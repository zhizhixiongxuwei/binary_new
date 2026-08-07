#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

fail() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

note() {
	printf '%s\n' "$*"
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		fail "sha256sum or shasum is required"
	fi
}

load_settings() {
	[ -f "$PROJECT_ROOT/images.lock.env" ] || fail "images.lock.env is missing"
	set -a
	# shellcheck disable=SC1091
	. "$PROJECT_ROOT/images.lock.env"
	if [ -f "$PROJECT_ROOT/.env" ]; then
		# shellcheck disable=SC1091
		. "$PROJECT_ROOT/.env"
	fi
	set +a
}

compose() {
	docker compose \
		--project-directory "$PROJECT_ROOT" \
		--env-file "$PROJECT_ROOT/.env" \
		--file "$PROJECT_ROOT/compose.yaml" \
		"$@"
}

random_hex() {
	if command -v openssl >/dev/null 2>&1; then
		openssl rand -hex 32
	else
		od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
	fi
}

initialize_runtime() {
	umask 077
	if [ ! -f "$PROJECT_ROOT/.env" ]; then
		cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
		note "created .env from .env.example"
	fi
	mkdir -p "$PROJECT_ROOT/runtime/secrets"
	created_admin=false
	for name in mysql_root_password mysql_app_password initial_admin_password; do
		path="$PROJECT_ROOT/runtime/secrets/$name"
		if [ ! -s "$path" ]; then
			random_hex >"$path"
			chmod 600 "$path"
			if [ "$name" = initial_admin_password ]; then
				created_admin=true
			fi
		fi
	done
	if [ "$created_admin" = true ]; then
		note "initial administrator password: $(cat "$PROJECT_ROOT/runtime/secrets/initial_admin_password")"
		note "store this password securely; it is not included in the source package"
	fi
}

verify_image() {
	image=$1
	expected_id=${2:-}
	actual_id=$(docker image inspect "$image" --format '{{.Id}}' 2>/dev/null) ||
		fail "required image is not loaded: $image"
	labels=$(docker image inspect "$image" --format '{{json .Config.Labels}}' 2>/dev/null) ||
		fail "cannot inspect image labels: $image"
	case "$labels" in
	*com.binaryscan.installation-id*|*sigstore*|*signature_status*|*trust-key*)
		fail "image carries removed installation/signing metadata: $image"
		;;
	esac
	if [ -n "$expected_id" ] && [ "$actual_id" != "$expected_id" ]; then
		fail "image ID mismatch for $image: got $actual_id, want $expected_id"
	fi
	note "verified image $image ($actual_id)"
}

verify_dependency_images() {
	load_settings
	verify_image "$BINARYSCAN_BUILDER_IMAGE" "${BINARYSCAN_BUILDER_IMAGE_ID:-}"
	verify_image "$BINARYSCAN_MYSQL_IMAGE" "${BINARYSCAN_MYSQL_IMAGE_ID:-}"
	verify_image "$BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE" "${BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE_ID:-}"
	verify_image "$BINARYSCAN_JAVA_RUNTIME_IMAGE" "${BINARYSCAN_JAVA_RUNTIME_IMAGE_ID:-}"
	verify_image "$BINARYSCAN_GHIDRA_RUNTIME_IMAGE" "${BINARYSCAN_GHIDRA_RUNTIME_IMAGE_ID:-}"
}

verify_product_images() {
	load_settings
	verify_image "${BINARYSCAN_APP_IMAGE:-binaryscan/app:0.1.0}" ""
	verify_image "${BINARYSCAN_SCANNER_IMAGE:-binaryscan/scanner:0.1.0}" ""
	verify_image "${BINARYSCAN_JAVA_IMAGE:-binaryscan/java:0.1.0}" ""
	verify_image "${BINARYSCAN_GHIDRA_IMAGE:-binaryscan/ghidra:0.1.0}" ""
}

verify_source_manifest() {
	manifest="$PROJECT_ROOT/MANIFEST.sha256"
	[ -f "$manifest" ] || return 0
	while IFS='  ' read -r expected relative; do
		[ -n "$expected" ] || continue
		[ -n "$relative" ] || fail "invalid source manifest line"
		path="$PROJECT_ROOT/$relative"
		[ -f "$path" ] || fail "source manifest file is missing: $relative"
		actual=$(sha256_file "$path")
		[ "$actual" = "$expected" ] || fail "source hash mismatch: $relative"
	done <"$manifest"
	note "source manifest verified"
}
