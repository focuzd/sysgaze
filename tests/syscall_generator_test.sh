#!/bin/sh
set -eu

generator=${1:-tools/generate_syscall_names.awk}
temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

valid_header=$temporary_directory/valid.h
invalid_header=$temporary_directory/invalid.h
output=$temporary_directory/output.inc

printf '%s\n' \
    '#define __NR_first 0' \
    '#define __NR_last 511' >"$valid_header"
printf '%s\n' \
    '#define __NR_first 0' \
    '#define __NR_out_of_range 512' >"$invalid_header"

awk -v syscall_limit=512 -f "$generator" "$valid_header" >"$output"
grep -q '^SYSCALL(0, first)$' "$output"
grep -q '^SYSCALL(511, last)$' "$output"

if awk -v syscall_limit=512 -f "$generator" "$invalid_header" \
        >/dev/null 2>&1; then
    echo "generator accepted a syscall at the exclusive limit" >&2
    exit 1
fi
if awk -f "$generator" "$valid_header" >/dev/null 2>&1; then
    echo "generator accepted a missing syscall_limit" >&2
    exit 1
fi

echo "ok syscall generator boundaries"
