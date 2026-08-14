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
  build                  Compile six product images fully offline
  up                     Start exactly seven long-running services
  init-admin             Create the first administrator from the local secret
  deploy IMAGE_DIR       init + import + build + up + init-admin
  verify                 Run post-start service and bundle checks
  status                 Show service state
  logs [SERVICE]         Follow all logs or one service
  down                   Stop services without deleting data
  reset                  Stop services, delete all scan data, restart, and
                         re-create the administrator (asks for confirmation)
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
	[ "$count" -eq 8 ] || fail "compose service count is $count, want exactly 8"
	printf '%s\n' "$services"
	note "doctor check passed"
}

import_images() {
	directory=$1
	[ -d "$directory" ] || fail "image directory does not exist: $directory"
	manifest=$directory/IMAGE_FILES.sha256
	[ -f "$manifest" ] && [ ! -L "$manifest" ] ||
		fail "IMAGE_FILES.sha256 is missing or is not a regular file"
	manifest_names=
	while IFS= read -r line || [ -n "$line" ]; do
		[ -n "$line" ] || continue
		expected=${line%%  *}
		relative=${line#*  }
		[ "$line" = "$expected  $relative" ] || fail "invalid image hash manifest line: $line"
		[ "${#expected}" -eq 64 ] || fail "invalid image archive SHA-256: $expected"
		case "$expected" in *[!0-9a-f]*) fail "invalid image archive SHA-256: $expected" ;; esac
		case "$relative" in
		'' | *[!A-Za-z0-9._-]*) fail "invalid image archive name in manifest: $relative" ;;
		esac
		case "$relative" in *.tar | *.tar.gz | *.tgz) ;; *) fail "manifest entry is not an image archive: $relative" ;; esac
		case " $manifest_names " in *" $relative "*) fail "duplicate image archive in manifest: $relative" ;; esac
		manifest_names="$manifest_names $relative"
		archive=$directory/$relative
		[ -f "$archive" ] && [ ! -L "$archive" ] || fail "image archive is missing or unsafe: $relative"
		actual=$(sha256_file "$archive")
		[ "$actual" = "$expected" ] || fail "image archive hash mismatch: $relative"
	done <"$manifest"
	[ -n "$manifest_names" ] || fail "IMAGE_FILES.sha256 contains no image archives"
	find "$directory" -maxdepth 1 -type f \( -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' \) -print |
		LC_ALL=C sort |
		while IFS= read -r archive; do
			name=$(basename "$archive")
			case " $manifest_names " in *" $name "*) ;; *) fail "unlisted image archive: $name" ;; esac
			note "loading $name"
			docker load --input "$archive"
		done
	note "image archive hashes verified"
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

build_c_checker() {
	tag=${BINARYSCAN_C_CHECKER_IMAGE:-binaryscan/c-checker:$version}
	note "building c-checker as $tag"
	docker build \
		--pull=false \
		--network=none \
		--platform "$BINARYSCAN_PLATFORM" \
		--file "$PROJECT_ROOT/c-checker/Dockerfile" \
		--tag "$tag" \
		--build-arg "C_CHECKER_BUILDER_IMAGE=$BINARYSCAN_C_CHECKER_BUILDER_IMAGE" \
		--build-arg "C_CHECKER_JRE_IMAGE=$BINARYSCAN_C_CHECKER_JRE_IMAGE" \
		--build-arg "BINARYSCAN_VERSION=$version" \
		--build-arg "BINARYSCAN_REVISION=$revision" \
		--build-arg "BINARYSCAN_SOURCE_MANIFEST_SHA256=$manifest_hash" \
		"$PROJECT_ROOT/c-checker"
}

build_python_checker() {
	tag=${BINARYSCAN_PYTHON_CHECKER_IMAGE:-binaryscan/python-checker:$version}
	note "building python-checker as $tag"
	docker build \
		--pull=false \
		--network=none \
		--platform "$BINARYSCAN_PLATFORM" \
		--file "$PROJECT_ROOT/python-checker/Dockerfile" \
		--tag "$tag" \
		--build-arg "PYTHON_RUNTIME_IMAGE=$BINARYSCAN_PYTHON_RUNTIME_IMAGE" \
		--build-arg "BINARYSCAN_VERSION=$version" \
		--build-arg "BINARYSCAN_REVISION=$revision" \
		--build-arg "BINARYSCAN_SOURCE_MANIFEST_SHA256=$manifest_hash" \
		"$PROJECT_ROOT/python-checker"
}

build_java_checker() {
	tag=${BINARYSCAN_JAVA_CHECKER_IMAGE:-binaryscan/java-checker:$version}
	note "building java-checker as $tag"
	docker build \
		--pull=false \
		--network=none \
		--platform "$BINARYSCAN_PLATFORM" \
		--file "$PROJECT_ROOT/java-checker/Dockerfile" \
		--tag "$tag" \
		--build-arg "JAVA_CHECKER_BUILDER_IMAGE=$BINARYSCAN_JAVA_CHECKER_BUILDER_IMAGE" \
		--build-arg "JAVA_CHECKER_JRE_IMAGE=$BINARYSCAN_C_CHECKER_JRE_IMAGE" \
		--build-arg "BINARYSCAN_VERSION=$version" \
		--build-arg "BINARYSCAN_REVISION=$revision" \
		--build-arg "BINARYSCAN_SOURCE_MANIFEST_SHA256=$manifest_hash" \
		"$PROJECT_ROOT/java-checker"
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
		--build-arg "TRIVY_RUNTIME_DB_IMAGE=$BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE" \
		--build-arg "ARCHIVE_TOOLS_IMAGE=$BINARYSCAN_ARCHIVE_TOOLS_IMAGE"
	build_one java docker/java.Dockerfile "${BINARYSCAN_JAVA_IMAGE:-binaryscan/java:$version}" \
		--build-arg "JAVA_RUNTIME_IMAGE=$BINARYSCAN_JAVA_RUNTIME_IMAGE" \
		--build-arg "PYCDC_TOOLS_IMAGE=$BINARYSCAN_PYCDC_TOOLS_IMAGE"
	build_one ghidra docker/ghidra.Dockerfile "${BINARYSCAN_GHIDRA_IMAGE:-binaryscan/ghidra:$version}" \
		--build-arg "GHIDRA_RUNTIME_IMAGE=$BINARYSCAN_GHIDRA_RUNTIME_IMAGE"
	build_c_checker
	build_java_checker
	build_python_checker
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
	admin_marker=$BINARYSCAN_DATA_ROOT/.admin-initialized
	[ ! -L "$admin_marker" ] || fail "administrator marker must not be a symbolic link: $admin_marker"
	if [ -e "$admin_marker" ]; then
		[ -f "$admin_marker" ] || fail "administrator marker is not a regular file: $admin_marker"
		note "initial administrator was already created for this runtime directory"
		return 0
	fi
	compose exec --no-TTY app /usr/local/bin/binaryscan-maintenance \
		init-admin --username admin --display-name Administrator \
		--password-file /run/secrets/initial_admin_password
	if ! (set -C; : >"$admin_marker") 2>/dev/null; then
		[ ! -L "$admin_marker" ] && [ -f "$admin_marker" ] ||
			fail "could not create administrator marker safely: $admin_marker"
	fi
	note "administrator created: admin"
}

# reset_data_path removes exactly one allow-listed data-root entry. The list
# mirrors the compose bind mounts plus the administrator marker; nothing else
# under BINARYSCAN_DATA_ROOT is ever touched.
reset_data_path() {
	relative=$1
	case "$relative" in
	application | mysql | archive-sandbox | .admin-initialized) ;;
	*) fail "refusing to remove unexpected data path: $relative" ;;
	esac
	target=$BINARYSCAN_DATA_ROOT/$relative
	[ ! -L "$target" ] || fail "data path must not be a symbolic link: $target"
	if [ -e "$target" ]; then
		rm -rf -- "$target"
	fi
}

reset_runtime() {
	load_existing_runtime
	require_command docker
	probe=$BINARYSCAN_DATA_ROOT/.reset-write-probe
	[ ! -e "$probe" ] || fail "stale reset write probe exists: $probe"
	if ! (set -C; : >"$probe") 2>/dev/null; then
		fail "data root is not writable by the current user: $BINARYSCAN_DATA_ROOT"
	fi
	rm -f -- "$probe"
	cat <<EOF
This will permanently delete all BinaryScan data under:
  $BINARYSCAN_DATA_ROOT/application
  $BINARYSCAN_DATA_ROOT/mysql
  $BINARYSCAN_DATA_ROOT/archive-sandbox
  $BINARYSCAN_DATA_ROOT/.admin-initialized

Uploaded samples, scan tasks, results, and the administrator account will be
lost. Secrets under $PROJECT_ROOT/runtime/secrets are kept. Services will be
restarted afterwards and the initial administrator re-created.

Type RESET and press Enter to continue, or anything else to cancel:
EOF
	IFS= read -r answer || fail "reset confirmation could not be read"
	[ "$answer" = "RESET" ] || fail "reset cancelled"
	compose down --remove-orphans
	reset_data_path application
	reset_data_path mysql
	reset_data_path archive-sandbox
	reset_data_path .admin-initialized
	start_services
	initialize_admin
	note "runtime data was reset; administrator re-created as: admin"
}

verify_running() {
	verify_source_manifest
	compose ps
	compose exec --no-TTY app /usr/local/bin/binaryscan-maintenance healthcheck
	compose exec --no-TTY scanner /usr/local/bin/binaryscan-supervisor healthcheck scanner
	compose exec --no-TTY scanner /usr/local/bin/binaryscan-bundle-check
	compose exec --no-TTY java /usr/local/bin/binaryscan-worker healthcheck --role bytecode
	compose exec --no-TTY ghidra /usr/local/bin/binaryscan-worker healthcheck --role native
	compose exec --no-TTY c-checker /opt/binaryscan/bin/c-checker-healthcheck
	compose exec --no-TTY java-checker /opt/binaryscan/bin/java-checker-healthcheck
	compose exec --no-TTY python-checker python3 /opt/binaryscan/python-checker/healthcheck.py http://127.0.0.1:8080
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
	load_existing_runtime
	verify_running
	;;
status)
	load_existing_runtime
	compose ps
	;;
logs)
	load_existing_runtime
	if [ "$#" -eq 2 ]; then
		compose logs --follow "$2"
	elif [ "$#" -eq 1 ]; then
		compose logs --follow
	else
		fail "logs accepts at most one service name"
	fi
	;;
down)
	load_existing_runtime
	compose down --remove-orphans
	;;
reset)
	[ "$#" -eq 1 ] || fail "reset accepts no arguments"
	reset_runtime
	;;
help|-h|--help)
	usage
	;;
*)
	usage >&2
	fail "unknown command: $command"
	;;
esac
