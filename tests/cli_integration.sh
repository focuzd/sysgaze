#!/bin/sh
set -eu

program=$1
temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

"$program" --help >"$temporary_directory/help.out" 2>"$temporary_directory/help.err"
test ! -s "$temporary_directory/help.err"
grep -q '^Usage:' "$temporary_directory/help.out"
grep -q -- '--seccomp-bpf' "$temporary_directory/help.out"

"$program" --version >"$temporary_directory/version.out" 2>"$temporary_directory/version.err"
test ! -s "$temporary_directory/version.err"
grep -q '^sysgaze ' "$temporary_directory/version.out"

set +e
"$program" --format=json -- /bin/true >"$temporary_directory/error.out" 2>"$temporary_directory/error.err"
status=$?
set -e
test "$status" -eq 2
test ! -s "$temporary_directory/error.out"
grep -q -- '--format=json is only valid with -c' "$temporary_directory/error.err"

set +e
"$program" -c --format=json -e trace=definitely_not_a_syscall -- /bin/true \
    >"$temporary_directory/filter-error.out" \
    2>"$temporary_directory/filter-error.err"
status=$?
set -e
test "$status" -eq 2
test ! -s "$temporary_directory/filter-error.out"
grep -q 'unknown syscall' "$temporary_directory/filter-error.err"

set +e
"$program" -c --format=ndjson -- /bin/true \
    >"$temporary_directory/summary-format.out" \
    2>"$temporary_directory/summary-format.err"
status=$?
set -e
test "$status" -eq 2
grep -q -- '--format=ndjson cannot be used with -c' \
    "$temporary_directory/summary-format.err"

"$program" -e trace=read -- /bin/true >"$temporary_directory/run.out" 2>"$temporary_directory/run.err"
test ! -s "$temporary_directory/run.out"
grep -q '^+++ exited with 0 +++$' "$temporary_directory/run.err"

echo "ok CLI process behavior"
