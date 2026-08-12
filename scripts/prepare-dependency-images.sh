#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib.sh"

usage() {
	cat <<'EOF'
Usage: ./scripts/prepare-dependency-images.sh OUTPUT_DIR [TRIVY_CACHE_DIR]

Prepares the nine external dependency images, freezes their local image IDs, and
exports one offline image archive. When TRIVY_CACHE_DIR is omitted, Trivy 0.72.0
downloads the current primary and Java databases first.

Optional environment variables:
  BINARYSCAN_JAVA_SOURCE_IMAGE    Existing image containing the pinned JDK/tools
  BINARYSCAN_GHIDRA_SOURCE_IMAGE  Existing image containing Ghidra 12.1.2/JDK 21
  BINARYSCAN_CHECKER_MAVEN_IMAGE   Maven 3.9.11/JDK 17 image used to seed both checkers
EOF
}

ensure_image_loaded() {
	image=$1
	if docker image inspect "$image" >/dev/null 2>&1; then
		return 0
	fi
	note "pulling missing image $image"
	docker pull --platform "$BINARYSCAN_PLATFORM" "$image"
}

prepare_builder_caches() {
	go_source_cache=$(go env GOMODCACHE)
	[ -d "$go_source_cache" ] || fail "Go module cache does not exist: $go_source_cache"

	note "fetching and verifying locked Go modules on the preparation host"
	GOTOOLCHAIN=local go -C "$PROJECT_ROOT" mod download
	GOTOOLCHAIN=local go -C "$PROJECT_ROOT" mod verify

	go_build_cache=$build_root/go-mod-cache
	mkdir -p "$go_build_cache"
	GOTOOLCHAIN=local GOMODCACHE="$go_build_cache" \
		GOPROXY="file://$go_source_cache/cache/download" GOSUMDB=off \
		go -C "$PROJECT_ROOT" mod download
	GOTOOLCHAIN=local GOMODCACHE="$go_build_cache" GOPROXY=off GOSUMDB=off \
		go -C "$PROJECT_ROOT" mod verify

	note "fetching locked npm packages into a dedicated cache"
	npm_build_cache=$build_root/npm-cache
	npm_seed=$build_root/npm-seed
	mkdir -p "$npm_build_cache" "$npm_seed"
	cp "$PROJECT_ROOT/web/package.json" "$PROJECT_ROOT/web/package-lock.json" "$npm_seed/"
	(
		cd "$npm_seed"
		npm ci --ignore-scripts --no-audit --no-fund --cache "$npm_build_cache"
	)
	native_packages=$build_root/npm-linux-amd64-packages.txt
	node - "$PROJECT_ROOT/web/package-lock.json" >"$native_packages" <<'NODE'
const fs = require("node:fs");

const lock = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
for (const value of Object.values(lock.packages || {})) {
  const operatingSystems = value.os || [];
  const architectures = value.cpu || [];
  const cLibraries = value.libc || [];
  if (!value.optional || !operatingSystems.includes("linux") ||
      !architectures.includes("x64") ||
      (cLibraries.length > 0 && !cLibraries.includes("glibc"))) {
    continue;
  }
  if (typeof value.resolved !== "string" || !value.resolved.startsWith("https://")) {
    throw new Error("Linux amd64 optional package is missing an HTTPS resolved URL");
  }
  console.log(value.resolved);
}
NODE
	while IFS= read -r package_url; do
		[ -n "$package_url" ] || continue
		npm cache add "$package_url" --cache "$npm_build_cache"
	done <"$native_packages"
	rm -rf "$npm_seed/node_modules"
	(
		cd "$npm_seed"
		npm ci --offline --ignore-scripts --no-audit --no-fund \
			--cache "$npm_build_cache"
	)
	rm -rf "$npm_seed"
}

find_database_directory() {
	root=$1
	component=$2
	filename=$3
	direct=$root/$component
	if [ -f "$direct/metadata.json" ] && [ -f "$direct/$filename" ]; then
		printf '%s\n' "$direct"
		return 0
	fi
	found=
	for candidate in "$direct"/versions/*; do
		[ -d "$candidate" ] || continue
		[ -f "$candidate/metadata.json" ] || continue
		[ -f "$candidate/$filename" ] || continue
		[ -z "$found" ] || fail "multiple $component database versions found in $root"
		found=$candidate
	done
	[ -n "$found" ] || fail "$component database files are missing below $root"
	printf '%s\n' "$found"
}

download_databases() {
	destination=$1
	mkdir -p "$destination"
	note "downloading the current Trivy vulnerability database"
	docker run --rm --platform "$BINARYSCAN_PLATFORM" \
		--volume "$destination:/cache" \
		--entrypoint /usr/local/bin/trivy \
		aquasec/trivy:0.72.0 \
		--cache-dir /cache image --download-db-only --no-progress
	note "downloading the current Trivy Java database"
	docker run --rm --platform "$BINARYSCAN_PLATFORM" \
		--volume "$destination:/cache" \
		--entrypoint /usr/local/bin/trivy \
		aquasec/trivy:0.72.0 \
		--cache-dir /cache image --download-java-db-only --no-progress
}

[ "${1:-}" != "-h" ] && [ "${1:-}" != "--help" ] || {
	usage
	exit 0
}
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || {
	usage >&2
	exit 1
}

require_command docker
require_command go
require_command node
require_command npm
load_settings

ensure_image_loaded golang:1.25.0-bookworm
ensure_image_loaded node:22-bookworm-slim
ensure_image_loaded aquasec/trivy:0.72.0
ensure_image_loaded alpine:3.22.5
ensure_image_loaded "$BINARYSCAN_MYSQL_IMAGE"
c_checker_maven_source=${BINARYSCAN_CHECKER_MAVEN_IMAGE:-${BINARYSCAN_C_CHECKER_MAVEN_IMAGE:-maven:3.9.11-eclipse-temurin-17}}
ensure_image_loaded "$c_checker_maven_source"
ensure_image_loaded "$BINARYSCAN_C_CHECKER_JRE_IMAGE"

output_directory=$1
case "$output_directory" in
/*) ;;
*) output_directory=$PROJECT_ROOT/$output_directory ;;
esac
mkdir -p "$output_directory"

temporary_root=${TMPDIR:-/tmp}
temporary_root=${temporary_root%/}
build_root=$(mktemp -d "$temporary_root/binaryscan-dependencies.XXXXXX")
trap 'chmod -R u+rwX "$build_root" >/dev/null 2>&1 || true; rm -rf "$build_root"' EXIT HUP INT TERM

if [ "$#" -eq 2 ]; then
	trivy_cache=$2
	case "$trivy_cache" in
	/*) ;;
	*) trivy_cache=$PROJECT_ROOT/$trivy_cache ;;
	esac
	[ -d "$trivy_cache" ] || fail "Trivy cache directory does not exist: $trivy_cache"
else
	trivy_cache=$build_root/downloaded-trivy-cache
	download_databases "$trivy_cache"
fi

trivy_database=$(find_database_directory "$trivy_cache" db trivy.db)
java_database=$(find_database_directory "$trivy_cache" java-db trivy-java.db)

note "creating the fixed dual-database bundle manifest"
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go -C "$PROJECT_ROOT" run ./cmd/trivy-bundle \
	--trivy-dir "$trivy_database" \
	--java-dir "$java_database" \
	--output "$build_root/bundle.json" \
	--env-output "$build_root/bundle.env"
# shellcheck disable=SC1090
. "$build_root/bundle.env"
database_tag_version=$(printf '%s' "$TRIVY_DB_VERSION" | tr -d '.')
case "$BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE" in
*-db"$database_tag_version") ;;
*)
	fail "Trivy image tag does not match database version $TRIVY_DB_VERSION: $BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE"
	;;
esac

prepare_builder_caches

note "building $BINARYSCAN_ARCHIVE_TOOLS_IMAGE with pinned archive utilities"
docker build --pull=false --platform "$BINARYSCAN_PLATFORM" \
	--file "$PROJECT_ROOT/docker/archive-tools.Dockerfile" \
	--tag "$BINARYSCAN_ARCHIVE_TOOLS_IMAGE" \
	--build-arg ALPINE_IMAGE=alpine:3.22.5 \
	"$PROJECT_ROOT"

note "building $BINARYSCAN_C_CHECKER_BUILDER_IMAGE with the locked Maven dependency cache"
docker build --pull=false --platform "$BINARYSCAN_PLATFORM" \
	--file "$PROJECT_ROOT/c-checker/Dockerfile.builder" \
	--tag "$BINARYSCAN_C_CHECKER_BUILDER_IMAGE" \
	--build-arg "MAVEN_IMAGE=$c_checker_maven_source" \
	"$PROJECT_ROOT/c-checker"

note "building $BINARYSCAN_JAVA_CHECKER_BUILDER_IMAGE with the locked Maven dependency cache"
docker build --pull=false --platform "$BINARYSCAN_PLATFORM" \
	--file "$PROJECT_ROOT/java-checker/Dockerfile.builder" \
	--tag "$BINARYSCAN_JAVA_CHECKER_BUILDER_IMAGE" \
	--build-arg "MAVEN_IMAGE=$c_checker_maven_source" \
	"$PROJECT_ROOT/java-checker"

note "building $BINARYSCAN_BUILDER_IMAGE"
docker build --pull=false --network=none --platform "$BINARYSCAN_PLATFORM" \
	--file "$PROJECT_ROOT/docker/builder.Dockerfile" \
	--tag "$BINARYSCAN_BUILDER_IMAGE" \
	--build-arg GO_IMAGE=golang:1.25.0-bookworm \
	--build-arg NODE_IMAGE=node:22-bookworm-slim \
	--build-context "go-mod-cache=$go_build_cache" \
	--build-context "npm-cache=$npm_build_cache" \
	"$PROJECT_ROOT"

java_source=${BINARYSCAN_JAVA_SOURCE_IMAGE:-binaryscan/bytecode-worker:0.1.0}
docker image inspect "$java_source" >/dev/null 2>&1 ||
	fail "Java source image is not loaded: $java_source"
note "extracting the pinned Java tool runtime without old product metadata"
docker build --pull=false --network=none --platform "$BINARYSCAN_PLATFORM" \
	--file "$PROJECT_ROOT/docker/java-runtime.Dockerfile" \
	--tag "$BINARYSCAN_JAVA_RUNTIME_IMAGE" \
	--build-arg "SOURCE_IMAGE=$java_source" \
	"$PROJECT_ROOT"

ghidra_source=${BINARYSCAN_GHIDRA_SOURCE_IMAGE:-binaryscan/native-worker:0.1.0}
docker image inspect "$ghidra_source" >/dev/null 2>&1 ||
	fail "Ghidra source image is not loaded: $ghidra_source"
note "extracting the pinned Ghidra runtime without old product metadata"
docker build --pull=false --network=none --platform "$BINARYSCAN_PLATFORM" \
	--file "$PROJECT_ROOT/docker/ghidra-runtime.Dockerfile" \
	--tag "$BINARYSCAN_GHIDRA_RUNTIME_IMAGE" \
	--build-arg "SOURCE_IMAGE=$ghidra_source" \
	"$PROJECT_ROOT"

verify_image aquasec/trivy:0.72.0 ""
note "building $BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE with fixed read-only databases"
docker build --pull=false --network=none --platform "$BINARYSCAN_PLATFORM" \
	--file "$PROJECT_ROOT/docker/trivy-runtime-db.Dockerfile" \
	--tag "$BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE" \
	--build-arg TRIVY_IMAGE=aquasec/trivy:0.72.0 \
	--build-arg "TRIVY_DB_ID=$TRIVY_DB_ID" \
	--build-arg "TRIVY_JAVA_DB_ID=$TRIVY_JAVA_DB_ID" \
	--build-context "trivy-db=$trivy_database" \
	--build-context "trivy-java-db=$java_database" \
	"$build_root"

verify_image "$BINARYSCAN_MYSQL_IMAGE" ""
# The preparation step intentionally replaces locally built dependency images.
# Freeze their new identities before enforcing the immutable delivery lock.
verify_dependency_images_unlocked
"$SCRIPT_DIR/freeze-image-lock.sh"
unset BINARYSCAN_BUILDER_IMAGE_ID \
	BINARYSCAN_MYSQL_IMAGE_ID \
	BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE_ID \
	BINARYSCAN_ARCHIVE_TOOLS_IMAGE_ID \
	BINARYSCAN_JAVA_RUNTIME_IMAGE_ID \
	BINARYSCAN_GHIDRA_RUNTIME_IMAGE_ID \
	BINARYSCAN_C_CHECKER_BUILDER_IMAGE_ID \
	BINARYSCAN_JAVA_CHECKER_BUILDER_IMAGE_ID \
	BINARYSCAN_C_CHECKER_JRE_IMAGE_ID
"$SCRIPT_DIR/export-dependency-images.sh" "$output_directory"

note "dependency preparation complete"
note "offline archive: $output_directory/binaryscan-dependency-images.tar"
note "database bundle: $TRIVY_DB_VERSION ($BUNDLE_ID)"
