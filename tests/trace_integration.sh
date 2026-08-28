#!/bin/sh
set -eu

program=$1
fixtures=$2
temporary_directory=$(mktemp -d)
target_pid=
tracer_pid=
cleanup() {
    if test -n "$tracer_pid"; then
        kill -KILL "$tracer_pid" 2>/dev/null || true
    fi
    if test -n "$target_pid"; then
        kill -KILL "$target_pid" 2>/dev/null || true
    fi
    rm -rf "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

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

set +e
"$program" -f -e trace=clone,clone3,execve,getpid,wait4 -- \
    "$fixtures/follow_fixture" >"$temporary_directory/follow.out" \
    2>"$temporary_directory/follow.trace"
status=$?
set -e
test "$status" -eq 5
test ! -s "$temporary_directory/follow.out"
test "$(grep -c '+++ spawned ' "$temporary_directory/follow.trace")" -ge 2
test "$(grep -c '] execve(' "$temporary_directory/follow.trace")" -ge 2
test "$(grep -c '] getpid() = ' "$temporary_directory/follow.trace")" -ge 2

"$program" -e trace=getpid -- "$fixtures/attach_fixture" \
    >"$temporary_directory/launch-shutdown.out" \
    2>"$temporary_directory/launch-shutdown.trace" &
tracer_pid=$!
launched_pid=
for unused in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 \
              21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
    launched_pid=$(sed -n 's/^getpid() = \([0-9][0-9]*\)$/\1/p' \
        "$temporary_directory/launch-shutdown.trace" | sed -n '1p')
    if test -n "$launched_pid"; then
        break
    fi
    if ! kill -0 "$tracer_pid" 2>/dev/null; then
        break
    fi
    sleep 0.025
done
test -n "$launched_pid"
target_pid=$launched_pid
kill -TERM "$tracer_pid"
set +e
wait "$tracer_pid"
status=$?
set -e
tracer_pid=
test "$status" -eq 143
if kill -0 "$target_pid" 2>/dev/null; then
    echo "launched target survived tracer shutdown" >&2
    exit 1
fi
target_pid=

"$fixtures/attach_fixture" >"$temporary_directory/attach.ready" \
    2>"$temporary_directory/attach.target.err" &
target_pid=$!
ready=false
for unused in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if grep -q '^ready$' "$temporary_directory/attach.ready"; then
        ready=true
        break
    fi
    sleep 0.02
done
test "$ready" = true

"$program" -e trace=getpid -p "$target_pid" \
    >"$temporary_directory/attach.out" \
    2>"$temporary_directory/attach.trace" &
tracer_pid=$!
attached=false
for unused in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 \
              21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
    if grep -q '] getpid() = ' "$temporary_directory/attach.trace"; then
        attached=true
        break
    fi
    if ! kill -0 "$tracer_pid" 2>/dev/null; then
        break
    fi
    sleep 0.025
done
test "$attached" = true
kill -INT "$tracer_pid"
set +e
wait "$tracer_pid"
status=$?
set -e
tracer_pid=
test "$status" -eq 130
kill -0 "$target_pid"
if grep -q '^State:[[:space:]]*[Tt]' "/proc/$target_pid/status"; then
    echo "attached target remained stopped after detach" >&2
    exit 1
fi
kill -TERM "$target_pid"
wait "$target_pid"
target_pid=
test ! -s "$temporary_directory/attach.target.err"

echo "ok launch, follow, attach/detach, syscall, signal, and status behavior"
