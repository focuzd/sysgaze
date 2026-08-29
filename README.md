# Sysgaze

Sysgaze is a zero-dependency Linux x86-64 system-call tracer written in C23.

It can launch commands, attach to all threads in an existing process, follow
fork/clone/exec descendants, filter syscalls, and produce text or streaming
NDJSON output.

```sh
make
./build/sysgaze -e trace=openat,read -- command arg
./build/sysgaze -f --format=ndjson -- command arg
./build/sysgaze -p PID
./build/sysgaze -c -e trace=%file -- command arg
./build/sysgaze -c --format=json -- command arg
./build/sysgaze --seccomp-bpf -e trace=getpid -- command arg
```

The NDJSON stream uses schema `sysgaze.trace/v1`. It begins with a metadata
record and then emits syscall, signal, process-start, and process-exit records.
Raw syscall arguments, results, durations, and fault addresses that may exceed
JSON's exact integer range are represented as decimal or hexadecimal strings.

Text output identifies genuine signal-delivery stops by symbolic signal name.
Group stops and ptrace-generated traps are not reinjected as application
signals. Interleaved calls use `<unfinished ...>` and `<... resumed>` lines.

Summary mode (`-c`) suppresses the live event stream and aggregates completed
calls, real syscall errors, and monotonic elapsed time across every followed
task. Text is the default summary format; `--format=json` emits the finite
`sysgaze.summary/v1` document. Summary rows are ordered by elapsed time with a
stable syscall-name and number tie-break.

## Benchmarks

`make bench` runs the native C benchmark harness against four reproducible
workloads: syscall-heavy, file I/O, process fanout, and thread fanout. Each row
uses five warmups and thirty measured iterations and reports median/minimum/
maximum wall time, median CPU time, overhead relative to native execution,
completed selected syscall events, and tracer-side ptrace calls.

```sh
make bench
make bench-compare   # also run matched unfiltered/filtered system strace modes
make bench-scaling   # process/thread fanout at 1, 2, 4, 8, and 16 workers
```

The filtered case selects `getpid`, whose expected count is checked on every
measured run. This makes the output-normalization gate independent of dynamic
loader and thread-scheduling noise. Ordinary ptrace filtering still stops on
every syscall; it saves decoding and output work, but does not reduce ptrace
traffic. `--seccomp-bpf` installs a raw classic BPF filter and uses
`PTRACE_EVENT_SECCOMP` so unselected calls run without ptrace stops. It is
launch-only, requires a non-empty filter, and never silently falls back to the
ordinary tracing path.

The harness is itself C and uses `fork`, `execve`, `wait4`,
`clock_gettime(CLOCK_MONOTONIC)`, and `getrusage`. It does not invoke shell
timing or text-processing utilities. Set `SYSGAZE_BENCH_WARMUPS` and
`SYSGAZE_BENCH_ITERATIONS` only when a shorter diagnostic run is needed; the
published default remains 5/30. See [benchmarks/README.md](benchmarks/README.md)
for metric definitions and interpretation. The recorded Stage 8 run is in
[benchmarks/results-2026-08-29-seccomp.txt](benchmarks/results-2026-08-29-seccomp.txt).

## Shutdown behavior

When interrupted with `SIGINT` or `SIGTERM`, Sysgaze detaches processes opened
with `-p` and leaves them running. Processes started by Sysgaze are terminated
and reaped. The tracer exits with `128 + signal` in either mode.
