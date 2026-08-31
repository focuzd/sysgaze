#!/bin/sh
set -eu

number_header=${1:-/usr/include/x86_64-linux-gnu/asm/unistd_64.h}
prototype_header=${2:-/usr/src/linux-headers-$(uname -r)/include/linux/syscalls.h}
output=${3:-src/syscall_catalog.inc}
syscall_limit=$(awk '
    $1 == "#define" && $2 == "SG_SYSCALL_LIMIT" {
        value = $3
        sub(/U$/, "", value)
        print value
        exit
    }
' include/sysgaze/filter.h)
if [ -z "$syscall_limit" ]; then
    echo "could not read SG_SYSCALL_LIMIT" >&2
    exit 1
fi
names=$(mktemp)
arities=$(mktemp)
temporary=$(mktemp)
trap 'rm -f "$names" "$arities" "$temporary"' EXIT HUP INT TERM

awk -v syscall_limit="$syscall_limit" \
    -f tools/generate_syscall_names.awk "$number_header" >"$names"
awk -v names_file="$names" -f tools/generate_syscall_arities.awk \
    -v RS=';' "$prototype_header" >"$arities"
awk -v arities_file="$arities" \
    -v overrides_file=tools/syscall_arity_overrides.inc \
    -v catalog_file="$output" -f tools/merge_syscall_catalog.awk \
    "$names" >"$temporary"
chmod 0644 "$temporary"
mv "$temporary" "$output"
trap - EXIT HUP INT TERM
