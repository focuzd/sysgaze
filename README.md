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
```

The NDJSON stream uses schema `sysgaze.trace/v1`. It begins with a metadata
record and then emits syscall, signal, process-start, and process-exit records.
Raw syscall arguments, results, durations, and fault addresses that may exceed
JSON's exact integer range are represented as decimal or hexadecimal strings.

Text output identifies genuine signal-delivery stops by symbolic signal name.
Group stops and ptrace-generated traps are not reinjected as application
signals. Interleaved calls use `<unfinished ...>` and `<... resumed>` lines.

## Shutdown behavior

When interrupted with `SIGINT` or `SIGTERM`, Sysgaze detaches processes opened
with `-p` and leaves them running. Processes started by Sysgaze are terminated
and reaped. The tracer exits with `128 + signal` in either mode.
