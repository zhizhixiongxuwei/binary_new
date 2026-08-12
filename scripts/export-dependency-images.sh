#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib.sh"

directory=${1:-}
[ -n "$directory" ] || fail "usage: $0 OUTPUT_DIR"
require_command docker
verify_dependency_images
mkdir -p "$directory"
archive="$directory/binaryscan-dependency-images.tar"
docker save --output "$archive" \
	"$BINARYSCAN_BUILDER_IMAGE" \
	"$BINARYSCAN_MYSQL_IMAGE" \
	"$BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE" \
	"$BINARYSCAN_ARCHIVE_TOOLS_IMAGE" \
	"$BINARYSCAN_JAVA_RUNTIME_IMAGE" \
	"$BINARYSCAN_GHIDRA_RUNTIME_IMAGE" \
	"$BINARYSCAN_C_CHECKER_BUILDER_IMAGE" \
	"$BINARYSCAN_JAVA_CHECKER_BUILDER_IMAGE" \
	"$BINARYSCAN_C_CHECKER_JRE_IMAGE"
"$SCRIPT_DIR/seal-image-files.sh" "$directory"
note "dependency images exported separately from the source ZIP"
