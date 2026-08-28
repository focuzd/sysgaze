# Sysgaze Build Plan

## Summary

Build Sysgaze as a clean-room, zero-dependency Linux x86-64 system-call tracer for Hackathon Track A. It will launch or attach to processes, follow descendants, correctly handle signals and ptrace events, produce familiar `strace`-shaped output, and expose filtering, NDJSON, statistics, benchmarking, and an opt-in seccomp-BPF fast path.

The authoritative implementation kickoff is **2026-08-28 18:00 UTC / 23:30 IST**. Only planning and inspection occurred before kickoff; no project code was written or committed. The old `/home/focuzd/strace-clone` may inform tests and lessons learned, but no source or tables will be copied.

## Public Interface

- Build: `make` produces `build/sysgaze`; `make test`, `make bench`, and `make deps-proof` provide the corresponding verification.
- Launch: `sysgaze [OPTIONS] -- COMMAND [ARG...]`.
- Attach: `sysgaze [OPTIONS] -p PID`.
- Supported options:
  - `-p PID`: attach using `PTRACE_SEIZE`.
  - `-f, --follow`: follow fork, vfork, clone, and exec events.
  - `-e trace=EXPR`: syscall names and `%file`, `%process`, `%memory`, `%network`, `%signal`, `%ipc` classes; positive terms form the initial set and `!name`/`!%class` terms subtract from it.
  - `-s N`: maximum displayed string/buffer bytes; default 32.
  - `-o FILE`: redirect tracer output from stderr.
  - `-c`: suppress the event stream and print aggregate syscall statistics.
  - `--format=text|ndjson|json`: text and NDJSON for event streams; JSON is valid with `-c` for a finite summary document.
  - `--seccomp-bpf`: launch-mode-only acceleration requiring a non-empty syscall filter.
  - `-h`, `--version`.
- Unknown options, syscalls, classes, invalid combinations, and unsupported ABIs fail before tracing with exit status 2. Internal tracer failures return 1. Launched commands propagate their exit status or `128 + signal`.
- Text remains the default and resembles `strace`, including PID prefixes, errno names, signals, exits, and unfinished/resumed calls.
- NDJSON schema `sysgaze.trace/v1` emits metadata, syscall, signal, process-start, and process-exit records. Timestamps and 64-bit raw values use decimal or hexadecimal strings to avoid JSON precision loss.
- Stats aggregate calls, errors, elapsed syscall time, average time, and percentage by syscall across all followed tasks.

## Dependency-Driven Implementation Stages

### 1. Eligibility, build, and interfaces

- Record the verified start time and make the first implementation commit after kickoff.
- Establish the C23/GNU-Linux build with strict warnings, no third-party code, an OSI license, and a small C test harness.
- Define configuration, tracee state, syscall event, signal event, lifecycle event, output sink, decoder, and filter interfaces before implementing ptrace behavior.
- Add the CLI parser with `getopt_long`, filter resolution, validation, documented exit codes, and dynamic buffers with checked allocation.
- Gate: a warning-clean build and passing CLI/filter unit tests.

### 2. Single-process tracing core

- Launch through `fork`, `PTRACE_TRACEME`, a synchronization stop, and `execve`.
- Drive `waitpid(..., __WALL)` through an explicit per-TID state machine rather than global entry/exit counters.
- Use `PTRACE_O_TRACESYSGOOD`, `PTRACE_O_TRACEEXEC`, `PTRACE_O_EXITKILL` for launched tracees, and `PTRACE_GET_SYSCALL_INFO` for architecture, arguments, return values, and errno classification.
- Preserve a pending entry until its matching exit; handle interrupted and restarted syscalls without producing false completed calls.
- Gate: trace a deterministic fixture from exec through normal and signaled exit with correct command-status propagation.

### 3. Syscall metadata and safe decoding

- Create a new x86-64 syscall-name table from Linux UAPI definitions and test that all known native syscall numbers have names; unknown future numbers render as `syscall_<nr>`.
- Deeply decode common file, descriptor, process, memory, signal, and socket calls. Other calls retain accurate names, arity where known, and safe raw hexadecimal arguments.
- Support signed/unsigned integers, FDs, pointers, strings, byte buffers, enums, bitmasks, argv arrays, sockaddr values, and selected common structures.
- Read tracee memory primarily through `process_vm_readv`; partial reads, null pointers, races, and `EFAULT` render safely instead of terminating Sysgaze.
- Decode input buffers at entry and output buffers at exit, bounded by both `-s` and the successful return length.
- Gate: strings with escapes and embedded NULs, long/truncated buffers, unreadable pointers, unknown flags, successful results, and errno results all match golden output.

### 4. Attach, follow mode, and shutdown

- Validate an attached target as native x86-64, enumerate `/proc/PID/task`, seize each thread, interrupt it, and repeat enumeration until the task set stabilizes.
- Follow fork/vfork/clone through inherited ptrace options and maintain an open-addressed TID state table with safe insertion/removal.
- Track thread-group identity separately from TID so PID labels, clone events, exits, and summary aggregation remain correct.
- On SIGINT/SIGTERM, stop accepting new work, restore pending signal-delivery state, detach every attached tracee, and allow launched tracees to continue or terminate according to documented launch-mode behavior.
- Gate: attach to a cooperative multithreaded fixture, follow fork/thread/exec descendants, detach without killing an attached target, and leave no tracees stopped.

### 5. Signal and output correctness

- Distinguish syscall stops, ptrace event stops, signal-delivery stops, group stops, synthetic traps, continued tasks, normal exits, and signal deaths.
- Reinject only genuine delivery signals exactly once; never leak ptrace-generated `SIGTRAP` into the program.
- Build renderer-independent events first. The text renderer adds `--- SIG... ---`, `+++ exited ... +++`, and unfinished/resumed formatting when interleaving requires it.
- Add a manual JSON escaper and streaming NDJSON renderer. JSON summary output is generated directly without a serialization library.
- Gate: handled, ignored, blocking, stopping/continuing, and fatal signals preserve tracee behavior; NDJSON passes a test-only C JSON validator and round-trip field checks.

### 6. Filters and summary mode

- Apply one resolved syscall bitset consistently to collection, rendering, and statistics.
- Keep process-control ptrace events active even when their corresponding syscalls are filtered, so `-f` correctness is independent of display filters.
- Measure syscall duration with `CLOCK_MONOTONIC`; count completed calls and real syscall errors while excluding kernel restart pseudo-results.
- Produce deterministic text and JSON summaries with a stable tie-break order.
- Gate: explicit-name, class, mixed include/exclude, empty-result, and invalid filters behave identically in text, NDJSON, and summary modes.

### 7. Benchmark baseline and ptrace optimization

- Implement a C benchmark harness using `fork`, `execve`, `wait4`, `clock_gettime`, and `getrusage`; do not depend on `/usr/bin/time`, Python, awk, or system `strace`.
- Provide reproducible syscall-heavy, file-I/O, process-fanout, and thread-fanout workloads.
- Run five warmups and thirty measured iterations for native, unfiltered Sysgaze, filtered Sysgaze, and later seccomp mode. Report median, min/max, CPU time, event count, ptrace-call count, and overhead ratio.
- Reduce ptrace traffic by setting options once, relying on inherited child options, avoiding redundant register/event reads, and using one syscall-information request per required stop.
- Gate: optimization preserves byte-normalized output and event counts while publishing honest before/after measurements.

### 8. Raw seccomp-BPF fast path and scaling

- For launched commands with `--seccomp-bpf` and a filter, install a classic BPF program in the synchronized child using `PR_SET_NO_NEW_PRIVS` and the Linux `seccomp` syscall—no `libseccomp`.
- Validate `AUDIT_ARCH_X86_64`; return `SECCOMP_RET_TRACE` for selected syscalls and `SECCOMP_RET_ALLOW` for others.
- Handle selected entry events through `PTRACE_EVENT_SECCOMP`, request one exit stop, then return the task to `PTRACE_CONT`. The filter is inherited across fork and exec.
- Reject attach mode, unfiltered use, unsupported kernels, and incompatible ABIs with clear diagnostics; never silently fall back while claiming fast-path results.
- Gate: baseline-filtered and seccomp-filtered modes emit equivalent selected syscall events, preserve program results and signals, and show scaling results across 1, 2, 4, 8, and 16 workers.

### 9. Submission and demo hardening

- Write `README.md` with the problem, examples, supported platform, privilege/Yama limitations, unsupported compatibility flags, architecture boundaries, benchmarks, and honest differences from full `strace`.
- Write `STDLIB.md` with at least ten concrete substitutions: libc/POSIX/Linux APIs replacing CLI, collections, serialization, syscall decoding, libseccomp, process inspection, benchmarking, testing, buffering, and error-name helpers.
- Generate `deps-proof.txt` from the compiler/link command, source/include audit, and dynamic-library inspection, showing only permitted libc/platform components.
- Add `.zero-dep.toml` for Track A, release build instructions, demo fixtures, and a five-minute demo script covering build, dependency proof, launch, attach, follow mode, filters, NDJSON, stats, and measured fast-path performance.
- Attempt reproducible-build hardening only after all correctness gates pass.

## Test and Acceptance Plan

- Unit tests cover CLI parsing, filter algebra, dynamic buffers, escaping, flag decomposition including unknown bits, syscall lookup coverage, JSON writing, errno rendering, stats math, and tracee-state transitions.
- Integration fixtures cover normal execution, missing executables, open/read/write buffers, invalid addresses, blocking syscalls, syscall restarts, fork/vfork/clone/exec, multithreading, concurrent exits, handled and fatal signals, attach/detach, and output-file failures.
- Every stage ends with `make test`; tracing tests have timeouts and guaranteed cleanup. Permission-dependent attach tests skip with an explicit reason when Yama or container policy prevents them.
- `make check` additionally runs warning-clean builds and compiler sanitizers where ptrace interaction permits.
- Seccomp acceptance requires semantic parity with ordinary filtered tracing and a measurable report; no performance claim is made from a single run.
- Release acceptance requires a fresh-clone `make`, passing tests, a runnable artifact, an empty/absent dependency manifest, updated dependency proof, and successful execution on a native x86-64 Linux host.

## Assumptions and Cut Line

- The shipped target is native 64-bit x86-64 Linux; i386 compatibility and x32 syscall ABIs are detected and rejected.
- C library, POSIX, Linux UAPI headers, the C compiler, linker, Make, and formatter are permitted platform/toolchain components. There are no runtime packages or vendored sources.
- `-f` is explicit to preserve familiar `strace` behavior; without it, only the selected process/thread set is traced.
- NDJSON is the structured live-event format. Conventional JSON is intentionally limited to finite `-c` summary output.
- Seccomp-BPF is opt-in and never supported for already-running attached processes.
- If time runs short, protect stages 1–6, correctness tests, documentation, and honest baseline benchmarks. Reduce decoder breadth next, then omit seccomp acceleration and scaling polish rather than shipping signal, attach, or child-tracking behavior known to be incorrect.
