#!/bin/sh
set -eu

program=$1
fixtures=$2
temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

set +e
"$program" -- "$fixtures/exit_fixture" >"$temporary_directory/exit.out" 2>"$temporary_directory/exit.trace"
status=$?
set -e
test "$status" -eq 7
test ! -s "$temporary_directory/exit.out"
grep -q '^execve(' "$temporary_directory/exit.trace"
grep -Eq '^getpid\(\) = [0-9]+$' "$temporary_directory/exit.trace"
grep -q '^+++ exited with 7 +++$' "$temporary_directory/exit.trace"
if grep -q '^syscall_' "$temporary_directory/exit.trace"; then
    echo "known x86-64 syscall rendered with a numeric fallback" >&2
    exit 1
fi

set +e
"$program" -- "$fixtures/signal_fixture" >"$temporary_directory/signal.out" 2>"$temporary_directory/signal.trace"
status=$?
set -e
test "$status" -eq 143
grep -q '^--- signal 15 ' "$temporary_directory/signal.trace"
grep -q '^+++ killed by signal 15 ' "$temporary_directory/signal.trace"

"$program" -e trace=read -- "$fixtures/restart_fixture" >"$temporary_directory/restart.out" 2>"$temporary_directory/restart.trace"
test ! -s "$temporary_directory/restart.out"
grep -Eq '^read\(.*\) = 1$' "$temporary_directory/restart.trace"
if grep -Eq 'errno\((512|513|514|516)\)' "$temporary_directory/restart.trace"; then
    echo "restart pseudo-error leaked into trace output" >&2
    exit 1
fi

set +e
"$program" -- /sysgaze/definitely-not-present >"$temporary_directory/missing.out" 2>"$temporary_directory/missing.trace"
status=$?
set -e
test "$status" -eq 127
grep -q "cannot execute '/sysgaze/definitely-not-present'" "$temporary_directory/missing.trace"
grep -q '^+++ exited with 127 +++$' "$temporary_directory/missing.trace"

set +e
"$program" -o "$temporary_directory/file.trace" -- "$fixtures/exit_fixture" >"$temporary_directory/file.out" 2>"$temporary_directory/file.err"
status=$?
set -e
test "$status" -eq 7
test ! -s "$temporary_directory/file.out"
test ! -s "$temporary_directory/file.err"
grep -q '^getpid(' "$temporary_directory/file.trace"

"$program" -s 4 -e trace=pipe2,write,read,openat,uname -- \
    "$fixtures/decode_fixture" >"$temporary_directory/decode.out" \
    2>"$temporary_directory/decode.trace"
test ! -s "$temporary_directory/decode.out"
grep -Eq '^pipe2\(\[[0-9]+, [0-9]+\], O_CLOEXEC\) = 0$' \
    "$temporary_directory/decode.trace"
grep -q '^write(.*"abcd"\.\.\., 8) = 8$' \
    "$temporary_directory/decode.trace"
grep -q '^read(.*"abcd"\.\.\., 8) = 8$' \
    "$temporary_directory/decode.trace"
grep -q '^openat(AT_FDCWD, "/sys"\.\.\., O_RDONLY) = -1 ENOENT ' \
    "$temporary_directory/decode.trace"
grep -q '^uname({sysname=' "$temporary_directory/decode.trace"
grep -q '^write(-1, 0x1, 4) = -1 EBADF ' "$temporary_directory/decode.trace"

echo "ok ptrace launch, syscall, restart, signal, status, and output behavior"
