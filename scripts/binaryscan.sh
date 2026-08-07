#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib.sh"

usage() {
	cat <<'EOF'
Usage: ./scripts/binaryscan.sh COMMAND [ARG]

Commands:
  doctor                 Check Docker, Compose, source hashes, and configuration
  init                   Create local secrets and .env (never packaged)
  import IMAGE_DIR       Verify and load Docker image tar files
  build                  Compile four product images fully offline
  up                     Start exactly five long-running services
  init-admin             Create the first administrator from the local secret
  deploy IMAGE_DIR       init + import + build + up + init-admin
  verify                 Run post-start service and bundle checks
  status                 Show service state
  logs [SERVICE]         Follow all logs or one service
  down                   Stop services without deleting data
EOF
}

doctor() {
	require_command docker
	docker info >/dev/null 2>&1 || fail "Docker Desktop engine is not running"
	docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
	initialize_runtime
	load_settings
	verify_source_manifest
	services=$(compose config --services)
	count=$(printf '%s\n' "$services" | awk 'NF {count++} END {print count+0}')
	[ "$count" -eq 5 ] || fail "compose service count is $count, want exactly 5"
	printf '%s\n' "$services"
	note "doctor check passed"
}

import_images() {
	directory=$1
	[ -d "$directory" ] || fail "image directory does not exist: $directory"
	if [ -f "$directory/IMAGE_FILES.sha256" ]; then
		(
			cd "$directory"
			while IFS='  ' read -r expected relative; do
				[ -n "$expected" ] || continue
				[ -f "$relative" ] || fail "image archive is missing: $relative"
				actual=$(sha256_file "$relative")
				[ "$actual" = "$expected" ] || fail "image archive hash mismatch: $relative"
			done <IMAGE_FILES.sha256
		)
		note "image archive hashes verified"
	fi
	find "$directory" -maxdepth 1 -type f \( -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' \) -print |
		LC_ALL=C sort |
		while IFS= read -r archive; do
			note "loading $(basename "$archive")"
			docker load --input "$archive"
		done
	verify_dependency_images
}

source_revision() {
	if [ -s "$PROJECT_ROOT/SOURCE_COMMIT" ]; then
		tr -d '\r\n' <"$PROJECT_ROOT/SOURCE_COMMIT"
	elif command -v git >/dev/null 2>&1 && git -C "$PROJECT_ROOT" rev-parse --verify HEAD >/dev/null 2>&1; then
		git -C "$PROJECT_ROOT" rev-parse HEAD
	else
		printf 'sealed-source'
	fi
}

source_manifest_hash() {
	if [ -f "$PROJECT_ROOT/MANIFEST.sha256" ]; then
		sha256_file "$PROJECT_ROOT/MANIFEST.sha256"
	else
		printf 'unsealed'
	fi
}

build_one() {
	name=$1
	dockerfile=$2
	tag=$3
	shift 3
	note "building $name as $tag"
	docker build \
		--pull=false \
		--network=none \
		--platform "$BINARYSCAN_PLATFORM" \
		--file "$PROJECT_ROOT/$dockerfile" \
		--tag "$tag" \
		--build-arg "BUILDER_IMAGE=$BINARYSCAN_BUILDER_IMAGE" \
		--build-arg "BINARYSCAN_VERSION=$version" \
		--build-arg "BINARYSCAN_REVISION=$revision" \
		--build-arg "BINARYSCAN_SOURCE_MANIFEST_SHA256=$manifest_hash" \
		"$@" \
		"$PROJECT_ROOT"
}

build_images() {
	require_command docker
	initialize_runtime
	verify_source_manifest
	verify_dependency_images
	load_settings
	version=$(tr -d '\r\n' <"$PROJECT_ROOT/VERSION")
	revision=$(source_revision)
	manifest_hash=$(source_manifest_hash)
	export version revision manifest_hash
	build_one app docker/app.Dockerfile "${BINARYSCAN_APP_IMAGE:-binaryscan/app:$version}"
	build_one scanner docker/scanner.Dockerfile "${BINARYSCAN_SCANNER_IMAGE:-binaryscan/scanner:$version}" \
		--build-arg "TRIVY_RUNTIME_DB_IMAGE=$BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE"
	build_one java docker/java.Dockerfile "${BINARYSCAN_JAVA_IMAGE:-binaryscan/java:$version}" \
		--build-arg "JAVA_RUNTIME_IMAGE=$BINARYSCAN_JAVA_RUNTIME_IMAGE"
	build_one ghidra docker/ghidra.Dockerfile "${BINARYSCAN_GHIDRA_IMAGE:-binaryscan/ghidra:$version}" \
		--build-arg "GHIDRA_RUNTIME_IMAGE=$BINARYSCAN_GHIDRA_RUNTIME_IMAGE"
	docker run --rm --network none \
		--entrypoint /usr/local/bin/binaryscan-bundle-check \
		"${BINARYSCAN_SCANNER_IMAGE:-binaryscan/scanner:$version}"
	note "offline product image build passed"
}

start_services() {
	initialize_runtime
	verify_product_images
	compose up --detach --wait
	note "BinaryScan is available at http://127.0.0.1:${BINARYSCAN_HTTP_PORT:-8080}"
}

initialize_admin() {
	initialize_runtime
	if [ -f "$PROJECT_ROOT/runtime/.admin-initialized" ]; then
		note "initial administrator was already created for this runtime directory"
		return 0
	fi
	compose exec --no-TTY app /usr/local/bin/binaryscan-maintenance \
		init-admin --username admin --display-name Administrator \
		--password-file /run/secrets/initial_admin_password
	: >"$PROJECT_ROOT/runtime/.admin-initialized"
	note "administrator created: admin"
}

verify_running() {
	verify_source_manifest
	compose ps
	compose exec --no-TTY app /usr/local/bin/binaryscan-maintenance healthcheck
	compose exec --no-TTY scanner /usr/local/bin/binaryscan-supervisor healthcheck scanner
	compose exec --no-TTY scanner /usr/local/bin/binaryscan-bundle-check
	compose exec --no-TTY java /usr/local/bin/binaryscan-worker healthcheck --role bytecode
	compose exec --no-TTY ghidra /usr/local/bin/binaryscan-worker healthcheck --role native
	note "runtime verification passed"
}

command=${1:-help}
case "$command" in
doctor)
	doctor
	;;
init)
	initialize_runtime
	;;
import)
	[ "$#" -eq 2 ] || fail "import requires IMAGE_DIR"
	import_images "$2"
	;;
build)
	[ "$#" -eq 1 ] || fail "build accepts no arguments"
	build_images
	;;
up)
	[ "$#" -eq 1 ] || fail "up accepts no arguments"
	start_services
	;;
init-admin)
	[ "$#" -eq 1 ] || fail "init-admin accepts no arguments"
	initialize_admin
	;;
deploy)
	[ "$#" -eq 2 ] || fail "deploy requires IMAGE_DIR"
	doctor
	import_images "$2"
	build_images
	start_services
	initialize_admin
	verify_running
	;;
verify)
	verify_running
	;;
status)
	initialize_runtime
	compose ps
	;;
logs)
	initialize_runtime
	if [ "$#" -eq 2 ]; then
		compose logs --follow "$2"
	elif [ "$#" -eq 1 ]; then
		compose logs --follow
	else
		fail "logs accepts at most one service name"
	fi
	;;
down)
	initialize_runtime
	compose down --remove-orphans
	;;
help|-h|--help)
	usage
	;;
*)
	usage >&2
	fail "unknown command: $command"
	;;
esac
