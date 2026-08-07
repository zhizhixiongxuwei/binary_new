#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib.sh"

require_command git
require_command tar
require_command zip

version=${1:-$(tr -d '\r\n' <"$PROJECT_ROOT/VERSION")}
output_directory=${2:-$PROJECT_ROOT/release}
case "$version" in
''|*[!A-Za-z0-9._-]*) fail "version contains unsafe characters" ;;
esac

git -C "$PROJECT_ROOT" rev-parse --verify HEAD >/dev/null 2>&1 ||
	fail "source repository has no commit to seal"
if [ -n "$(git -C "$PROJECT_ROOT" status --porcelain --untracked-files=normal)" ]; then
	fail "source repository must be clean before sealing"
fi

commit=$(git -C "$PROJECT_ROOT" rev-parse HEAD)
package_name="binaryscan-source-$version"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/binaryscan-source.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

git -C "$PROJECT_ROOT" archive --format=tar --prefix="$package_name/" HEAD |
	tar -xf - -C "$temporary"
package_root="$temporary/$package_name"
printf '%s\n' "$commit" >"$package_root/SOURCE_COMMIT"

(
	cd "$package_root"
	find . -type f ! -name MANIFEST.sha256 -print |
		LC_ALL=C sort |
		while IFS= read -r relative; do
			clean=${relative#./}
			printf '%s  %s\n' "$(sha256_file "$relative")" "$clean"
		done >MANIFEST.sha256
)

(cd "$package_root" && ./scripts/verify-source.sh)
mkdir -p "$output_directory"
archive="$output_directory/$package_name.zip"
rm -f "$archive" "$archive.sha256"
(cd "$temporary" && zip -X -q -r "$archive" "$package_name")
archive_hash=$(sha256_file "$archive")
printf '%s  %s\n' "$archive_hash" "$(basename "$archive")" >"$archive.sha256"

note "sealed source archive: $archive"
note "SHA-256: $archive_hash"
