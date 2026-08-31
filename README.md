# Sysgaze

Sysgaze is a zero-dependency system-call tracer for native x86-64 Linux. It is
written from scratch in C23 for Track A of the Zero Dependency Hackathon and
links only to libc.

System-call tracing is useful when a program fails before its logs initialize,
hangs on an unexpected resource, opens the wrong file, or behaves differently
across machines. Sysgaze focuses on this daily debugging path with a small,
auditable implementation and no runtime package supply chain.

## Highlights

- Launch a command or attach to every thread of a running process.
- Follow fork, vfork, clone, and exec descendants with `-f`.
- Name every syscall in the installed x86-64 UAPI table and safely fall back to
  `syscall_N` for unknown future numbers.
- Deeply decode common file, descriptor, memory, process, signal, and socket
  arguments; safely bound all tracee-memory reads.
- Emit familiar text, streaming NDJSON, or deterministic text/JSON summaries.
- Filter by syscall name or `%file`, `%process`, `%memory`, `%network`,
  `%signal`, and `%ipc` classes.
- Preserve genuine signal delivery, syscall restarts, group stops, and command
  exit status.
- Optionally install a raw seccomp-BPF filter so unselected calls avoid ptrace
  stops—without `libseccomp`.
- Ship a C benchmark harness, dependency proof, sanitizer tests, and a
  byte-for-byte reproducible release target.

## Build

Requirements are a native x86-64 Linux host, a C23-capable GCC-compatible
compiler, GNU Make, libc/POSIX headers, and Linux UAPI headers. The tracing core
requires a kernel with `PTRACE_GET_SYSCALL_INFO` (Linux 5.3 or newer).

```sh
make
./build/sysgaze --version
```

`make` is the one-step build and produces `build/sysgaze`. For the normalized
release build:

```sh
make release
```

No package install, configure step, submodule, network service, or vendored
library is required.

The optional proof targets additionally use standard Linux development tools:
`readelf`, `sha256sum`, `cmp`, `cp`, and a POSIX shell. These verify the build;
none is executed or required by the Sysgaze runtime artifact.

## Quick start

```sh
# Launch a command
./build/sysgaze -- /bin/echo hello

# Select file-related calls
./build/sysgaze -e trace=%file -- command arg

# Follow processes and threads
./build/sysgaze -f -e trace=execve,clone,clone3,openat -- command arg

# Attach to an existing process
./build/sysgaze -p PID

# Stream machine-readable events
./build/sysgaze --format=ndjson -e trace=openat,read -- command arg

# Print aggregate statistics
./build/sysgaze -c -e trace=%file -- command arg
./build/sysgaze -c --format=json -- command arg

# Use the filtered seccomp fast path
./build/sysgaze --seccomp-bpf -e trace=getpid,openat -- command arg
```

## Command line

```text
Usage:
  sysgaze [OPTIONS] -- COMMAND [ARG...]
  sysgaze [OPTIONS] -p PID

Options:
  -p PID             attach to a running process
  -f, --follow       follow fork, vfork, clone, and exec
  -e trace=EXPR      select syscall names or %classes
  -s N               maximum displayed string/buffer bytes (default 32)
  -o FILE            write tracer output to FILE
  -c                 suppress events and print syscall statistics
      --format=FMT    text, ndjson, or json summary
      --seccomp-bpf   filtered launch-mode acceleration
  -h, --help         show help
      --version      show version
```

Positive filter terms form the initial set; `!name` and `!%class` subtract
from it. For example, `trace=%file,!read,!write` selects file-class calls other
than `read` and `write`. Unknown names, classes, malformed expressions, and
invalid mode combinations fail before tracing.

Text and NDJSON are event-stream formats. Conventional JSON is intentionally
limited to finite `-c` summaries; `-c --format=ndjson` and streaming
`--format=json` are rejected rather than emitting ambiguous documents.

## Output semantics

Text output resembles strace: syscall names and arguments, symbolic errno
results, `--- SIGNAL ---` records, lifecycle lines, and `<unfinished ...>` /
`<... resumed>` pairs when tasks interleave.

NDJSON uses schema `sysgaze.trace/v1` and emits metadata, syscall, signal,
process-start, and process-exit records. JSON summary mode uses
`sysgaze.summary/v1`. Raw arguments, results, durations, timestamps, and other
64-bit values that may exceed JSON's exact integer range are strings.

Summary mode reports calls, real errors, total syscall time, average time, and
percentage across all followed tasks. Kernel restart pseudo-errors are never
reported as user-visible failures. Rows sort deterministically by duration,
then syscall name and number.

## Exit status and shutdown

- CLI validation errors return `2`.
- Internal tracer failures return `1`.
- Launched commands propagate their exit status, or `128 + signal`.
- A missing launched executable returns `127`.

On `SIGINT` or `SIGTERM`, launch mode terminates and reaps its tracees. Attach
mode restores pending delivery signals, detaches all seized tasks, and leaves
the target running. Ptrace-generated traps are never injected into the target.

## Attach permissions

Attach mode is subject to the kernel's normal ptrace policy. The tracer and
target generally need the same UID, and Linux Yama `ptrace_scope`, dumpability,
containers, LSM policy, or missing `CAP_SYS_PTRACE` can still deny access.
Sysgaze reports the failed TID and suggests checking Yama rather than silently
tracing only part of a process.

The test fixture opts into tracing with `PR_SET_PTRACER`; arbitrary programs do
not. Launch mode normally needs no special privilege because the child requests
tracing itself.

## Seccomp-BPF mode

`--seccomp-bpf` is opt-in, launch-only, and requires a non-empty filter. The
synchronized child sets `PR_SET_NO_NEW_PRIVS` and installs a classic BPF program
through the Linux `seccomp` syscall. The program validates
`AUDIT_ARCH_X86_64`, rejects x32 calls, returns `SECCOMP_RET_TRACE` for selected
syscalls, and allows everything else.

Selected entries arrive as `PTRACE_EVENT_SECCOMP`; Sysgaze requests exactly one
exit stop and then returns the task to `PTRACE_CONT`. Filters are inherited by
forked processes, threads, and exec. `rt_sigreturn` is traced internally—but not
rendered unless selected—so interrupted/restarted syscall semantics remain
correct. Unsupported setup is an explicit error; there is no silent fallback.

## Correctness and tests

```sh
make test          # unit, CLI, ptrace, signal, JSON, filter, and parity tests
make check         # clean ASan/UBSan build and complete test suite
make bench-smoke   # compact one-sample Sysgaze/strace comparison and gate
```

The suite includes deterministic fixtures for decoding, unreadable memory,
syscall restarts, fatal and handled signals, stop/continue behavior, concurrent
threads, fork/clone/exec, attach/detach, summaries, and ordinary-versus-seccomp
event parity. Catalog tests require every known native x86-64 syscall to have
an exact 0–6 ABI arity and valid argument/result metadata. Ptrace commands must
run on a host that permits tracing.

## Benchmarks

The benchmark is a C program using `fork`, `execve`, `wait4`,
`clock_gettime(CLOCK_MONOTONIC)`, and `getrusage`. It runs five warmups and
thirty measured samples over syscall-heavy, file-I/O, process-fanout, and
thread-fanout workloads.

```sh
make bench          # native, full, filtered, and seccomp-filtered Sysgaze
make bench-compare  # additionally compare an installed system strace
make bench-scaling  # process/thread scaling at 1, 2, 4, 8, and 16 workers
```

Each row reports median/min/max wall time, median CPU time, overhead versus
native execution, exact selected-event count, and tracer-side ptrace calls.
Ordinary filtering saves decoding and rendering but cannot avoid entry/exit
stops; seccomp mode can.

On the recorded i3-1005G1 host, seccomp filtering reduced ptrace calls by 86%
and median time by 72% for the sparse file-I/O selection. It improved process
and thread fanout by 6% and 9%. The syscall-heavy workload selected almost every
call and improved only 1.6%, an expected break-even result. Full methods and
measurements are in [benchmarks/README.md](benchmarks/README.md),
[the strace comparison](benchmarks/results-2026-08-29.txt), and
[the seccomp/scaling run](benchmarks/results-2026-08-29-seccomp.txt).

## Zero-dependency and reproducibility proofs

```sh
make deps-proof
make repro-check
```

`make deps-proof` audits the release link command, source includes, vendored
directories, foreign manifests, and ELF `DT_NEEDED` entries. The committed
[deps-proof.txt](deps-proof.txt) shows that `libc.so.6` is the only dynamic
runtime dependency.

`make repro-check` performs two clean release builds with a fixed
`SOURCE_DATE_EPOCH` and compiler prefix maps in two different source
directories, compares every byte, and publishes both SHA-256 values in
[reproducible-build.txt](reproducible-build.txt).

[STDLIB.md](STDLIB.md) documents sixteen concrete package-to-platform
substitutions and the generated Linux UAPI metadata boundary. There is no C
runtime package manifest; absence is the correct empty manifest for C. Track
metadata is in [.zero-dep.toml](.zero-dep.toml).

## Scope and honest differences from full strace

Sysgaze is deliberately smaller than mature strace:

- Only native x86-64 Linux is supported. i386 compatibility, x32, non-Linux,
  and non-x86-64 targets are outside the build target or rejected.
- Every known syscall has a name and arity, but deep symbolic decoding covers a
  practical subset. Other calls retain accurate names and safe raw arguments.
- It does not implement strace's complete qualifier language, path filtering,
  stack traces, fault injection, syscall tampering, daemonization modes,
  personalities, or hundreds of compatibility flags.
- Structured schemas are project-specific and versioned; they are not strace
  JSON compatibility formats.
- Non-returning syscalls may appear as unfinished entries while lifecycle
  events carry the definitive process result.
- Ptrace changes scheduling and can be expensive. Results are local
  measurements, not universal performance guarantees.
- Seccomp mode accelerates selected tracing; it is not a security sandbox and
  does not block unselected calls.

These boundaries keep the state machine, signal delivery, cleanup, and output
behavior testable rather than imitating flags without their semantics.

## Design map

- `src/trace.c`: launch/attach, ptrace state machine, signals, raw seccomp-BPF.
- `src/decoder.c`: bounded tracee-memory reads and argument rendering.
- `src/output.c`: text, NDJSON, and JSON summary serialization.
- `src/filter.c`, `src/syscall_catalog.c`, `src/syscall_catalog.inc`: filters
  and the single canonical x86-64 descriptor table containing each syscall's
  number, name, ABI arity, classes, result kind, and argument kinds.
- `src/tracee_table.c`: open-addressed per-TID state storage.
- `src/stats.c`: checked aggregation and deterministic sorting.
- `benchmarks/`: C harness, workloads, methodology, and recorded results.
- `tests/`: C unit harness, JSON validator, integration scripts, and fixtures.

All implementation code was written during the event window beginning
2026-08-28 18:00 UTC.

## License

Sysgaze is available under the [MIT License](LICENSE).
