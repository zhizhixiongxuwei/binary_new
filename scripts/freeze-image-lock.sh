#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib.sh"

require_command docker
load_settings
verify_dependency_images

image_id() {
	docker image inspect "$1" --format '{{.Id}}' 2>/dev/null ||
		fail "required image is not loaded: $1"
}

temporary="$PROJECT_ROOT/images.lock.env.tmp"
cat >"$temporary" <<EOF
# Frozen external images required for a network-isolated source build.
BINARYSCAN_PLATFORM=$BINARYSCAN_PLATFORM
BINARYSCAN_BUILDER_IMAGE=$BINARYSCAN_BUILDER_IMAGE
BINARYSCAN_BUILDER_IMAGE_ID=$(image_id "$BINARYSCAN_BUILDER_IMAGE")
BINARYSCAN_MYSQL_IMAGE=$BINARYSCAN_MYSQL_IMAGE
BINARYSCAN_MYSQL_IMAGE_ID=$(image_id "$BINARYSCAN_MYSQL_IMAGE")
BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE=$BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE
BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE_ID=$(image_id "$BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE")
BINARYSCAN_JAVA_RUNTIME_IMAGE=$BINARYSCAN_JAVA_RUNTIME_IMAGE
BINARYSCAN_JAVA_RUNTIME_IMAGE_ID=$(image_id "$BINARYSCAN_JAVA_RUNTIME_IMAGE")
BINARYSCAN_GHIDRA_RUNTIME_IMAGE=$BINARYSCAN_GHIDRA_RUNTIME_IMAGE
BINARYSCAN_GHIDRA_RUNTIME_IMAGE_ID=$(image_id "$BINARYSCAN_GHIDRA_RUNTIME_IMAGE")
EOF
mv "$temporary" "$PROJECT_ROOT/images.lock.env"
note "images.lock.env now contains immutable local image IDs"
note "review and commit it before creating the source ZIP"
