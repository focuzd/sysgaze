# Benchmark methodology

The benchmark runs four fixed workloads from `workload.c`:

- `syscall`: 2,000 direct `getpid` calls.
- `file`: 200 cycles of opening `/dev/zero` and `/dev/null`, one-byte read and
  write operations, closes, and one `getpid` marker.
- `process`: eight child processes making 100 `getpid` calls each.
- `thread`: eight threads making 100 `getpid` calls each.

Every mode receives five unrecorded warmups followed by thirty measurements.
Wall time is measured around `fork`/`execve`/`wait4` with the monotonic clock.
CPU time is the delta of `RUSAGE_CHILDREN`, so reaped descendants are included.
Output goes to a regular temporary file for both tracers, ensuring rendering
and write costs are measured rather than silently benchmarking summary mode.

The normal suite measures native, unfiltered Sysgaze, ordinarily filtered
Sysgaze, and seccomp-filtered Sysgaze. `make bench-compare` adds matched strace
modes. `make bench-scaling` runs process and thread workloads with 1, 2, 4, 8,
and 16 workers.

`make bench-smoke` uses one warmup and one measured sample to check event
counts and seccomp ptrace-call reduction. It prints a compact comparison of
seccomp-filtered Sysgaze and filtered strace when strace is installed. Its
single-sample timings are indicative only; use `make bench-compare` for the
full 30-sample measurement.

`events` means completed selected syscall events for Sysgaze. For strace it is
the number of syscall-entry records in the normalized text stream; strace may
include non-returning syscalls such as `exit_group`, so unfiltered totals can
differ slightly. The filtered `getpid` count is exact and is enforced on every
sample. `ptrace-calls` is Sysgaze's count of tracer-side ptrace API calls; the
tracee's initial `PTRACE_TRACEME` is deliberately excluded. Inspecting strace's
own ptrace traffic would require tracing the tracer and distort its timings, so
that column is reported as unavailable for strace.

For before/after checks, the current harness can also run a Stage 6 Sysgaze
binary. Older binaries do not emit internal metrics, so the harness normalizes
their text output for event counts and reports ptrace calls as unavailable.

Sysgaze sets ptrace options once on the initial task and relies on kernel option
inheritance for followed children. A regular syscall stop makes one
`PTRACE_GET_SYSCALL_INFO` request and no register request. Filtering skips
argument capture, timestamps, statistics, and rendering for unselected calls,
but normal `PTRACE_SYSCALL` mode necessarily retains entry and exit stops.
The seccomp mode installs a classic BPF program in the synchronized child. It
returns `SECCOMP_RET_TRACE` for selected calls and the internal `rt_sigreturn`
needed for restart tracking, and `SECCOMP_RET_ALLOW` otherwise. Selected entry
events use `PTRACE_EVENT_SECCOMP`, request one syscall exit stop, then return to
`PTRACE_CONT`.
