# Sysgaze

Sysgaze is a zero-dependency Linux x86-64 system-call tracer written in C23.

## Shutdown behavior

When interrupted with `SIGINT` or `SIGTERM`, Sysgaze detaches processes opened
with `-p` and leaves them running. Processes started by Sysgaze are terminated
and reaped. The tracer exits with `128 + signal` in either mode.
