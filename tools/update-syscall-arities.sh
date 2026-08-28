#!/bin/sh
set -eu

header=${1:-/usr/src/linux-headers-$(uname -r)/include/linux/syscalls.h}
output=${2:-src/syscall_arities.inc}
temporary=$(mktemp)
trap 'rm -f "$temporary"' EXIT HUP INT TERM

awk -v names_file=src/syscall_names.inc -f tools/generate_syscall_arities.awk \
    -v RS=';' "$header" >"$temporary"
chmod 0644 "$temporary"
mv "$temporary" "$output"
trap - EXIT HUP INT TERM
