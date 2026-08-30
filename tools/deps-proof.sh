#!/bin/sh
set -eu

program=${1:-build/sysgaze}
compiler=${CC:-cc}
project_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$project_root"

if test ! -x "$program"; then
    echo "dependency proof: '$program' is not executable" >&2
    exit 1
fi

needed=$(readelf -d "$program" |
    sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')
if test "$needed" != "libc.so.6"; then
    echo "dependency proof: unexpected ELF dependencies: $needed" >&2
    exit 1
fi

if find . -path './.git' -prune -o -type d \
    \( -name vendor -o -name vendors -o -name third_party \
       -o -name third-party -o -name node_modules \) -print |
    grep -q .; then
    echo "dependency proof: vendored dependency directory found" >&2
    exit 1
fi

if find . -maxdepth 2 -type f \
    \( -name package.json -o -name requirements.txt -o -name Cargo.toml \
       -o -name go.mod -o -name pom.xml \) -print | grep -q .; then
    echo "dependency proof: foreign-language dependency manifest found" >&2
    exit 1
fi

echo "Sysgaze zero-dependency proof"
echo "=============================="
echo
echo "Artifact: build/sysgaze (ELF x86-64)"
echo "Compiler: $($compiler --version | sed -n '1p')"
echo "Dependency manifest: absent (C has no runtime package manifest)"
echo "Vendored dependency directories: none"
echo
echo "Representative compile command:"
make -Bn CC="$compiler" build/sysgaze |
    sed -n '/ -c src\/main.c /p' |
    sed "s|$project_root|.|g"
echo
echo "Link command:"
make -Bn CC="$compiler" build/sysgaze |
    sed -n '/ -o build\/sysgaze /p' |
    sed "s|$project_root|.|g"
echo
echo "ELF DT_NEEDED entries:"
readelf -d "$program" |
    sed -n 's/.*Shared library: \[\(.*\)\].*/  \1/p'
echo
echo "Unique source includes (local project headers and platform headers):"
grep -h '^#include [<"]' src/*.c include/sysgaze/*.h |
    sort -u |
    sed 's/^/  /'
echo
echo "Result: PASS — libc.so.6 is the only dynamic runtime dependency."
echo "Linux UAPI headers and syscalls are platform interfaces, not vendored code."
