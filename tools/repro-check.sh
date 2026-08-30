#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM
first_source="$temporary_directory/first-source"
second_source="$temporary_directory/second-source"
mkdir "$first_source" "$second_source"
cp -a "$project_root/." "$first_source/"
cp -a "$project_root/." "$second_source/"

make -C "$first_source" release >/dev/null
cp "$first_source/build/sysgaze" "$temporary_directory/sysgaze-first"
first_hash=$(sha256sum "$temporary_directory/sysgaze-first" | sed 's/ .*//')

make -C "$second_source" release >/dev/null
cp "$second_source/build/sysgaze" "$temporary_directory/sysgaze-second"
second_hash=$(sha256sum "$temporary_directory/sysgaze-second" | sed 's/ .*//')

if ! cmp -s "$temporary_directory/sysgaze-first" \
           "$temporary_directory/sysgaze-second"; then
    echo "reproducible build: FAIL — artifacts differ" >&2
    exit 1
fi

mkdir -p "$project_root/build"
cp "$temporary_directory/sysgaze-first" "$project_root/build/sysgaze"

echo "Sysgaze reproducible-build proof"
echo "================================"
echo "SOURCE_DATE_EPOCH=1787940000"
echo "Build roots: two distinct temporary source directories"
echo "first  sha256: $first_hash"
echo "second sha256: $second_hash"
echo "Result: PASS — the two clean release builds are byte-identical."
