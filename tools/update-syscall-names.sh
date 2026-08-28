#!/bin/sh
set -eu

header=${1:-/usr/include/x86_64-linux-gnu/asm/unistd_64.h}
output=${2:-src/syscall_names.inc}
temporary=$(mktemp)
trap 'rm -f "$temporary"' EXIT HUP INT TERM

awk -f tools/generate_syscall_names.awk "$header" >"$temporary"
chmod 0644 "$temporary"
mv "$temporary" "$output"
trap - EXIT HUP INT TERM
