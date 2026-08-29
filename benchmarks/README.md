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
