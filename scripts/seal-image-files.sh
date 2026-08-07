#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib.sh"

directory=${1:-}
[ -n "$directory" ] && [ -d "$directory" ] || fail "usage: $0 IMAGE_DIR"

temporary="$directory/IMAGE_FILES.sha256.tmp"
: >"$temporary"
find "$directory" -maxdepth 1 -type f \( -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' \) -print |
	LC_ALL=C sort |
	while IFS= read -r archive; do
		printf '%s  %s\n' "$(sha256_file "$archive")" "$(basename "$archive")"
	done >"$temporary"
[ -s "$temporary" ] || {
	rm -f "$temporary"
	fail "no image archives found in $directory"
}
mv "$temporary" "$directory/IMAGE_FILES.sha256"
note "sealed image archive manifest: $directory/IMAGE_FILES.sha256"
