#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib.sh"

verify_source_manifest

inventory() {
	if [ -f "$PROJECT_ROOT/MANIFEST.sha256" ]; then
		sed -E 's/^[a-f0-9]{64}  //' "$PROJECT_ROOT/MANIFEST.sha256"
	elif command -v git >/dev/null 2>&1 &&
		git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
		git -C "$PROJECT_ROOT" ls-files
	else
		find "$PROJECT_ROOT" -type f \
			-not -path "$PROJECT_ROOT/.git/*" \
			-not -path "$PROJECT_ROOT/runtime/*" \
			-not -path "$PROJECT_ROOT/web/node_modules/*" \
			-not -path "$PROJECT_ROOT/web/dist/*" |
			sed "s#^$PROJECT_ROOT/##"
	fi
}

inventory | while IFS= read -r relative; do
	case "$relative" in
	runtime/*|*/node_modules/*|web/dist/*|*.tar|*.tar.gz|*.tgz|*.oci|*.iso|*/trivy.db|*/trivy-java.db|*.pem|*.key)
		fail "source package contains forbidden generated, image, database, or secret file: $relative"
		;;
	esac
done

note "source-only package policy passed"
