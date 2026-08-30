#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
temporary_directory=$(mktemp -d)
target_pid=
tracer_pid=

cleanup()
{
    if test -n "$tracer_pid"; then
        kill -KILL "$tracer_pid" 2>/dev/null || true
        wait "$tracer_pid" 2>/dev/null || true
    fi
    if test -n "$target_pid"; then
        kill -TERM "$target_pid" 2>/dev/null || true
        wait "$target_pid" 2>/dev/null || true
    fi
    rm -rf "$temporary_directory"
}

section()
{
    printf '\n=== %s ===\n' "$1"
}

trap cleanup EXIT HUP INT TERM
cd "$project_root"

section "1. One-command release build"
make release
./build/sysgaze --version

section "2. Empty manifest and ELF dependency proof"
sed -n '1,12p' .zero-dep.toml
make deps-proof

section "3. Launch mode and syscall filters"
./build/sysgaze -e trace=execve,write -- /bin/echo "hello from Sysgaze"

section "4. Follow a thread, child process, and exec"
make build/tests/fixtures/follow_fixture
set +e
./build/sysgaze -f -e trace=clone,clone3,execve,getpid,wait4 -- \
    ./build/tests/fixtures/follow_fixture
follow_status=$?
set -e
test "$follow_status" -eq 5

section "5. Streaming NDJSON"
./build/sysgaze --format=ndjson -e trace=execve,write -- \
    /bin/echo structured \
    2>"$temporary_directory/events.ndjson"
sed -n '1,5p' "$temporary_directory/events.ndjson"

section "6. Aggregate summary mode"
make build/tests/fixtures/summary_fixture
./build/sysgaze -c -e trace=getpid,write -- \
    ./build/tests/fixtures/summary_fixture

section "7. Attach to all threads, then detach safely"
make build/tests/fixtures/attach_fixture
./build/tests/fixtures/attach_fixture \
    >"$temporary_directory/attach-ready.txt" &
target_pid=$!
ready=false
for unused in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if grep -q '^ready$' "$temporary_directory/attach-ready.txt"; then
        ready=true
        break
    fi
    sleep 0.025
done
test "$ready" = true

./build/sysgaze -e trace=getpid -o "$temporary_directory/attach.trace" \
    -p "$target_pid" &
tracer_pid=$!
sleep 0.25
kill -INT "$tracer_pid"
set +e
wait "$tracer_pid"
attach_status=$?
set -e
tracer_pid=
test "$attach_status" -eq 130
kill -0 "$target_pid"
sed -n '1,6p' "$temporary_directory/attach.trace"
kill -TERM "$target_pid"
wait "$target_pid"
target_pid=

section "8. Seccomp fast-path measurement"
make build/bench/harness build/bench/workload
SYSGAZE_BENCH_WARMUPS=${SYSGAZE_DEMO_WARMUPS:-1} \
SYSGAZE_BENCH_ITERATIONS=${SYSGAZE_DEMO_ITERATIONS:-3} \
    ./build/bench/harness ./build/sysgaze ./build/bench/workload

section "9. Reproducible release receipt"
if test -f reproducible-build.txt; then
    cat reproducible-build.txt
else
    echo "Run 'make repro-check' to generate both byte-identical SHA-256 values."
fi

section "Demo complete"
echo "Sysgaze built, proved, traced, attached, summarized, and benchmarked."
