#!/bin/sh
set -eu

program=$1
fixtures=$2
validator=$3
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
grep -q '^--- SIGTERM ' "$temporary_directory/signal.trace"
grep -q '^+++ killed by SIGTERM ' "$temporary_directory/signal.trace"

"$program" -e trace=read -- "$fixtures/restart_fixture" >"$temporary_directory/restart.out" 2>"$temporary_directory/restart.trace"
test ! -s "$temporary_directory/restart.out"
grep -Eq '^(read\(.*\)|<\.\.\. read resumed>\)) = 1$' \
    "$temporary_directory/restart.trace"
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
"$program" -e trace=rt_sigaction,rt_sigprocmask,tgkill,wait4 -- \
    "$fixtures/signal_state_fixture" \
    >"$temporary_directory/signal-state.out" \
    2>"$temporary_directory/signal-state.trace"
status=$?
set -e
test "$status" -eq 143
test "$(grep -c '^--- SIGUSR1 ' "$temporary_directory/signal-state.trace")" -eq 1
test "$(grep -c '^--- SIGUSR2 ' "$temporary_directory/signal-state.trace")" -eq 1
test "$(grep -c '^--- SIGSTOP ' "$temporary_directory/signal-state.trace")" -eq 1
test "$(grep -c '^--- SIGCONT ' "$temporary_directory/signal-state.trace")" -eq 1
test "$(grep -c '^--- SIGTERM ' "$temporary_directory/signal-state.trace")" -eq 1
test "$(grep -c '^--- SIGTRAP ' "$temporary_directory/signal-state.trace")" -eq 1
if grep -q '^--- SIGTRAP .*si_addr' "$temporary_directory/signal-state.trace"; then
    echo "user-generated SIGTRAP rendered with a fault address" >&2
    exit 1
fi
grep -q '^wait4(.* <unfinished \.\.\.>$' \
    "$temporary_directory/signal-state.trace"
grep -q '^<\.\.\. wait4 resumed>) = ' \
    "$temporary_directory/signal-state.trace"

"$program" -f -e trace=read,getpid,write -- \
    "$fixtures/interleave_fixture" \
    >"$temporary_directory/interleave.out" \
    2>"$temporary_directory/interleave.trace"
test ! -s "$temporary_directory/interleave.out"
grep -q '] read(.* <unfinished \.\.\.>$' \
    "$temporary_directory/interleave.trace"
grep -q '] <\.\.\. read resumed>) = 1$' \
    "$temporary_directory/interleave.trace"

set +e
"$program" -e trace=mmap -- "$fixtures/fault_fixture" \
    >"$temporary_directory/fault.out" \
    2>"$temporary_directory/fault.trace"
status=$?
set -e
test "$status" -eq 139
grep -Eq '^--- SIGSEGV .*si_addr=0x[0-9a-f]+' \
    "$temporary_directory/fault.trace"
grep -q '^+++ killed by SIGSEGV +++$' "$temporary_directory/fault.trace"

set +e
"$program" --format=ndjson -e trace=execve,getpid -- \
    "$fixtures/exit_fixture" >"$temporary_directory/ndjson.out" \
    2>"$temporary_directory/events.ndjson"
status=$?
set -e
test "$status" -eq 7
test ! -s "$temporary_directory/ndjson.out"
"$validator" "$temporary_directory/events.ndjson"
grep -q 'execve(\\"build/tests/fixtures/exit_fixt' \
    "$temporary_directory/events.ndjson"

set +e
"$program" --format=ndjson -e trace=tgkill -- \
    "$fixtures/signal_state_fixture" \
    >"$temporary_directory/signal-ndjson.out" \
    2>"$temporary_directory/signal.ndjson"
status=$?
set -e
test "$status" -eq 143
"$validator" "$temporary_directory/signal.ndjson" syntax-only
grep -q '"type":"signal".*"name":"SIGSTOP"' \
    "$temporary_directory/signal.ndjson"
grep -q '"type":"process-exit".*"status":15.*"signaled":true' \
    "$temporary_directory/signal.ndjson"

"$program" -e trace=getpid,write -- "$fixtures/summary_fixture" \
    >"$temporary_directory/filter-text.out" \
    2>"$temporary_directory/filter-text.trace"
test "$(grep -c '^getpid() = ' "$temporary_directory/filter-text.trace")" -eq 3
test "$(grep -c '^write(' "$temporary_directory/filter-text.trace")" -eq 2

"$program" --format=ndjson -e trace=getpid,write -- \
    "$fixtures/summary_fixture" >"$temporary_directory/filter-ndjson.out" \
    2>"$temporary_directory/filter.ndjson"
"$validator" "$temporary_directory/filter.ndjson" syntax-only
test "$(grep -c '"type":"syscall"' \
    "$temporary_directory/filter.ndjson")" -eq 5

"$program" -c -e trace=getpid,write -- "$fixtures/summary_fixture" \
    >"$temporary_directory/summary.out" \
    2>"$temporary_directory/summary.txt"
test ! -s "$temporary_directory/summary.out"
grep -q '^% time.*syscall$' "$temporary_directory/summary.txt"
grep -Eq '[[:space:]]3[[:space:]]+0 getpid$' \
    "$temporary_directory/summary.txt"
grep -Eq '[[:space:]]2[[:space:]]+1 write$' \
    "$temporary_directory/summary.txt"
grep -Eq '[[:space:]]5[[:space:]]+1 total$' \
    "$temporary_directory/summary.txt"
if grep -qE '^(getpid|write)\(' "$temporary_directory/summary.txt"; then
    echo "event stream leaked into summary output" >&2
    exit 1
fi

"$program" -c --format=json -e trace=getpid,write -- \
    "$fixtures/summary_fixture" >"$temporary_directory/summary-json.out" \
    2>"$temporary_directory/summary.json"
test ! -s "$temporary_directory/summary-json.out"
"$validator" "$temporary_directory/summary.json" summary
grep -q '"total_calls":"5".*"total_errors":"1"' \
    "$temporary_directory/summary.json"
grep -q '"name":"getpid","calls":"3","errors":"0"' \
    "$temporary_directory/summary.json"
grep -q '"name":"write","calls":"2","errors":"1"' \
    "$temporary_directory/summary.json"
grep -q '"average_nanoseconds":"[0-9][0-9]*","percent":"[0-9][0-9]*\.[0-9][0-9]"' \
    "$temporary_directory/summary.json"

"$program" --seccomp-bpf -c --format=json -e trace=getpid,write -- \
    "$fixtures/summary_fixture" >"$temporary_directory/seccomp-summary.out" \
    2>"$temporary_directory/seccomp-summary.json"
test ! -s "$temporary_directory/seccomp-summary.out"
"$validator" "$temporary_directory/seccomp-summary.json" summary
grep -q '"total_calls":"5".*"total_errors":"1"' \
    "$temporary_directory/seccomp-summary.json"
grep -q '"name":"getpid","calls":"3","errors":"0"' \
    "$temporary_directory/seccomp-summary.json"
grep -q '"name":"write","calls":"2","errors":"1"' \
    "$temporary_directory/seccomp-summary.json"

"$program" --seccomp-bpf --format=ndjson -e trace=getpid -- \
    "$fixtures/summary_fixture" >"$temporary_directory/seccomp-ndjson.out" \
    2>"$temporary_directory/seccomp.ndjson"
"$validator" "$temporary_directory/seccomp.ndjson" syntax-only
test "$(grep -c '"type":"syscall"' \
    "$temporary_directory/seccomp.ndjson")" -eq 3
if grep -q '"name":"write"' "$temporary_directory/seccomp.ndjson"; then
    echo "unselected syscall leaked from seccomp fast path" >&2
    exit 1
fi

"$program" --seccomp-bpf -e trace=read -- "$fixtures/restart_fixture" \
    >"$temporary_directory/seccomp-restart.out" \
    2>"$temporary_directory/seccomp-restart.trace"
grep -Eq '^(read\(.*\)|<\.\.\. read resumed>\)) = 1$' \
    "$temporary_directory/seccomp-restart.trace"
if grep -Eq 'errno\((512|513|514|516)\)' \
    "$temporary_directory/seccomp-restart.trace"; then
    echo "restart pseudo-error leaked from seccomp fast path" >&2
    exit 1
fi

set +e
"$program" --seccomp-bpf -e trace=mmap -- "$fixtures/fault_fixture" \
    >"$temporary_directory/seccomp-fault.out" \
    2>"$temporary_directory/seccomp-fault.trace"
status=$?
set -e
test "$status" -eq 139
grep -Eq '^--- SIGSEGV .*si_addr=0x[0-9a-f]+' \
    "$temporary_directory/seccomp-fault.trace"

"$program" -c -e trace=getpid,!getpid -- "$fixtures/summary_fixture" \
    >"$temporary_directory/empty-summary.out" \
    2>"$temporary_directory/empty-summary.txt"
grep -Eq '[[:space:]]0[[:space:]]+0 total$' \
    "$temporary_directory/empty-summary.txt"
if grep -q ' getpid$' "$temporary_directory/empty-summary.txt"; then
    echo "empty-result filter produced a syscall summary row" >&2
    exit 1
fi

set +e
"$program" -c -e trace=%process,!getpid -- "$fixtures/exit_fixture" \
    >"$temporary_directory/class-summary.out" \
    2>"$temporary_directory/class-summary.txt"
status=$?
set -e
test "$status" -eq 7
grep -q ' execve$' "$temporary_directory/class-summary.txt"
if grep -q ' getpid$' "$temporary_directory/class-summary.txt"; then
    echo "excluded syscall appeared in class-filtered summary" >&2
    exit 1
fi

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

set +e
"$program" -f -c --format=json -e trace=getpid -- \
    "$fixtures/follow_fixture" >"$temporary_directory/follow-summary.out" \
    2>"$temporary_directory/follow-summary.json"
status=$?
set -e
test "$status" -eq 5
"$validator" "$temporary_directory/follow-summary.json" summary
grep -Eq '"name":"getpid","calls":"([2-9]|[1-9][0-9]+)"' \
    "$temporary_directory/follow-summary.json"
if grep -q '"type":"process-start"' \
    "$temporary_directory/follow-summary.json"; then
    echo "lifecycle event leaked into summary output" >&2
    exit 1
fi

set +e
"$program" -f --seccomp-bpf -c --format=json \
    -e trace=clone,clone3,execve,getpid,wait4 -- \
    "$fixtures/follow_fixture" \
    >"$temporary_directory/seccomp-follow-summary.out" \
    2>"$temporary_directory/seccomp-follow-summary.json"
status=$?
set -e
test "$status" -eq 5
"$validator" "$temporary_directory/seccomp-follow-summary.json" summary
grep -Eq '"name":"getpid","calls":"([2-9]|[1-9][0-9]+)"' \
    "$temporary_directory/seccomp-follow-summary.json"
grep -q '"name":"execve","calls":"' \
    "$temporary_directory/seccomp-follow-summary.json"

set +e
"$program" -f --format=ndjson -e trace=execve,getpid -- \
    "$fixtures/follow_fixture" >"$temporary_directory/follow-ndjson.out" \
    2>"$temporary_directory/follow.ndjson"
status=$?
set -e
test "$status" -eq 5
"$validator" "$temporary_directory/follow.ndjson" syntax-only
test "$(grep -c '"type":"process-start"' \
    "$temporary_directory/follow.ndjson")" -ge 2

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
calls_before_stop=$(grep -c '] getpid() = ' "$temporary_directory/attach.trace")
kill -STOP "$target_pid"
stopped=false
for unused in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if grep -q '^State:[[:space:]]*[Tt]' "/proc/$target_pid/status"; then
        stopped=true
        break
    fi
    sleep 0.025
done
test "$stopped" = true
kill -CONT "$target_pid"
continued=false
for unused in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 \
              21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
    calls_after_continue=$(grep -c '] getpid() = ' \
        "$temporary_directory/attach.trace")
    if test "$calls_after_continue" -gt "$calls_before_stop"; then
        continued=true
        break
    fi
    sleep 0.025
done
test "$continued" = true
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

echo "ok tracing, signals, filters, NDJSON, summaries, and status behavior"
