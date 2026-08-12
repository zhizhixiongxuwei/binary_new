#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
DEFAULT_INITIAL_ADMIN_PASSWORD=admin123456789

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

load_env_defaults() {
	file=$1
	[ -f "$file" ] || return 0
	carriage_return=$(printf '\r')
	while IFS= read -r line || [ -n "$line" ]; do
		line=${line%"$carriage_return"}
		case "$line" in
		'' | \#*) continue ;;
		esac
		case "$line" in
		*=*) ;;
		*) fail "invalid environment line in $file: $line" ;;
		esac
		name=${line%%=*}
		value=${line#*=}
		case "$name" in
		'' | [0-9]* | *[!A-Z0-9_]*) fail "invalid environment name in $file: $name" ;;
		esac
		eval "already_set=\${$name+x}"
		[ "$already_set" != x ] || continue
		case "$value" in
		\"*\") value=${value#\"}; value=${value%\"} ;;
		\'*\') value=${value#\'}; value=${value%\'} ;;
		\"* | \'*) fail "unterminated quoted value in $file: $name" ;;
		esac
		export "$name=$value"
	done <"$file"
}

load_compose_environment() {
	require_command docker
	env_file=$(compose_env_file)
	settings=$(docker compose \
		--project-directory "$PROJECT_ROOT" \
		--env-file "$env_file" \
		--file "$PROJECT_ROOT/compose.yaml" \
		config --environment) ||
		fail "could not parse .env with Docker Compose"
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
		BINARYSCAN_*=*) ;;
		*) continue ;;
		esac
		name=${line%%=*}
		value=${line#*=}
		case "$name" in
		BINARYSCAN_*[!A-Z0-9_]* | BINARYSCAN_) \
			fail "Docker Compose returned an invalid BinaryScan environment name: $name" ;;
		esac
		export "$name=$value"
	done <<EOF
$settings
EOF
}

compose_env_file() {
	if [ -f "$PROJECT_ROOT/.env" ]; then
		printf '%s\n' "$PROJECT_ROOT/.env"
	elif [ -f "$PROJECT_ROOT/.env.example" ]; then
		printf '%s\n' "$PROJECT_ROOT/.env.example"
	else
		fail ".env and .env.example are both missing"
	fi
}

load_settings() {
	[ -f "$PROJECT_ROOT/images.lock.env" ] || fail "images.lock.env is missing"
	# Let Compose own dotenv quoting, comments, duplicate keys, and process-env
	# precedence. Only immutable build-image defaults use the local parser.
	load_compose_environment
	load_env_defaults "$PROJECT_ROOT/images.lock.env"
}

compose() {
	env_file=$(compose_env_file)
	docker compose \
		--project-directory "$PROJECT_ROOT" \
		--env-file "$env_file" \
		--file "$PROJECT_ROOT/compose.yaml" \
		"$@"
}

linux_directory_allows_product_access() {
	directory=$1
	metadata=$(stat -c '%u %g %A' "$directory" 2>/dev/null) || return 1
	set -- $metadata
	owner_uid=$1
	owner_gid=$2
	permissions=$3

	if [ "$owner_uid" = 10001 ]; then
		read_permission=$(printf '%s' "$permissions" | cut -c 2)
		write_permission=$(printf '%s' "$permissions" | cut -c 3)
		execute_permission=$(printf '%s' "$permissions" | cut -c 4)
	elif [ "$owner_gid" = 10001 ]; then
		read_permission=$(printf '%s' "$permissions" | cut -c 5)
		write_permission=$(printf '%s' "$permissions" | cut -c 6)
		execute_permission=$(printf '%s' "$permissions" | cut -c 7)
	else
		read_permission=$(printf '%s' "$permissions" | cut -c 8)
		write_permission=$(printf '%s' "$permissions" | cut -c 9)
		execute_permission=$(printf '%s' "$permissions" | cut -c 10)
	fi

	[ "$read_permission" = r ] || return 1
	[ "$write_permission" = w ] || return 1
	case "$execute_permission" in
	x | s | t) return 0 ;;
	*) return 1 ;;
	esac
}

strip_trailing_slashes() {
	value=$1
	while [ "$value" != / ] && [ "${value%/}" != "$value" ]; do
		value=${value%/}
	done
	printf '%s\n' "$value"
}

assert_path_without_symlink_components() {
	candidate=$(strip_trailing_slashes "$1")
	system_name=$2
	while :; do
		if [ -L "$candidate" ]; then
			case "$system_name:$candidate" in
			Darwin:/tmp | Darwin:/var | Darwin:/etc) ;;
			*) fail "BINARYSCAN_DATA_ROOT must not contain a symbolic-link component: $candidate" ;;
			esac
		fi
		[ "$candidate" != / ] || break
		parent=$(dirname -- "$candidate")
		[ "$parent" != "$candidate" ] || break
		candidate=$parent
	done
}

prepare_data_directories() {
	configured_root=${BINARYSCAN_DATA_ROOT:-./runtime/data}
	case "/$configured_root/" in
	*/../* | *\\..\\* | *\\../* | */..\\*) \
		fail "BINARYSCAN_DATA_ROOT must not contain a parent-directory component" ;;
	esac
	system_name=$(uname -s 2>/dev/null || printf unknown)
	case "$system_name" in
	MSYS* | MINGW* | CYGWIN*)
		require_command cygpath
		case "$configured_root" in
		[A-Za-z]:[\\/]*) data_root=$(cygpath -u "$configured_root") ;;
		[A-Za-z]:*) fail "BINARYSCAN_DATA_ROOT must not be drive-relative: $configured_root" ;;
		*\\*) fail "use forward slashes for Git Bash BINARYSCAN_DATA_ROOT paths" ;;
		/*) data_root=$configured_root ;;
		*) data_root=$PROJECT_ROOT/$configured_root ;;
		esac
		;;
	*)
		case "$configured_root" in
		/*) data_root=$configured_root ;;
		*) data_root=$PROJECT_ROOT/$configured_root ;;
		esac
		;;
	esac
	data_root=$(strip_trailing_slashes "$data_root")
	case "/$data_root/" in
	*/../*) fail "BINARYSCAN_DATA_ROOT must not contain a parent-directory component" ;;
	esac
	case "$data_root" in
	*[!/]*) ;;
	*) fail "BINARYSCAN_DATA_ROOT must not be the filesystem root" ;;
	esac
	case "$system_name" in
	MSYS* | MINGW* | CYGWIN*)
		windows_root=$(cygpath -m "$data_root")
		case "$windows_root" in
		[A-Za-z]: | [A-Za-z]:/) fail "BINARYSCAN_DATA_ROOT must not be a drive root" ;;
		esac
		;;
	esac

	assert_path_without_symlink_components "$data_root" "$system_name"
	mkdir -p "$data_root"
	assert_path_without_symlink_components "$data_root" "$system_name"
	data_root=$(CDPATH= cd -- "$data_root" && pwd -P)
	case "$data_root" in
	*[!/]*) ;;
	*) fail "BINARYSCAN_DATA_ROOT must not be the filesystem root" ;;
	esac
	[ -r "$data_root" ] && [ -w "$data_root" ] && [ -x "$data_root" ] ||
		fail "data root must be readable, writable, and searchable by the current user: $data_root"

	for directory in \
		"$data_root/mysql" \
		"$data_root/archive-sandbox" \
		"$data_root/archive-sandbox/input" \
		"$data_root/archive-sandbox/output" \
		"$data_root/archive-sandbox/run" \
		"$data_root/application" \
		"$data_root/application/uploads" \
		"$data_root/application/repository" \
		"$data_root/application/repository/.staging" \
		"$data_root/application/repository/.staging/uploads" \
		"$data_root/application/task-work"; do
		[ ! -L "$directory" ] || fail "data directory must not be a symbolic link: $directory"
		mkdir -p "$directory"
		[ -d "$directory" ] || fail "data path is not a directory: $directory"
	done

	case "$system_name" in
	Darwin)
		[ -r "$data_root/mysql" ] && [ -w "$data_root/mysql" ] && [ -x "$data_root/mysql" ] ||
			fail "MySQL data directory is not fully accessible: $data_root/mysql"
		for directory in \
			"$data_root/archive-sandbox" \
			"$data_root/archive-sandbox/input" \
			"$data_root/archive-sandbox/output" \
			"$data_root/archive-sandbox/run" \
			"$data_root/application" \
			"$data_root/application/uploads" \
			"$data_root/application/repository" \
			"$data_root/application/repository/.staging" \
			"$data_root/application/repository/.staging/uploads" \
			"$data_root/application/task-work"; do
			[ -r "$directory" ] && [ -w "$directory" ] && [ -x "$directory" ] ||
				fail "application data directory is not fully accessible: $directory"
		done
		;;
	Linux)
		for directory in \
			"$data_root/archive-sandbox" \
			"$data_root/archive-sandbox/input" \
			"$data_root/archive-sandbox/output" \
			"$data_root/archive-sandbox/run" \
			"$data_root/application" \
			"$data_root/application/uploads" \
			"$data_root/application/repository" \
			"$data_root/application/repository/.staging" \
			"$data_root/application/repository/.staging/uploads" \
			"$data_root/application/task-work"; do
			linux_directory_allows_product_access "$directory" ||
				fail "application data directory must be readable, writable, and searchable by container UID/GID 10001 on Linux: $directory (see README data-directory permissions)"
		done
		;;
	*)
		[ -r "$data_root/mysql" ] && [ -w "$data_root/mysql" ] && [ -x "$data_root/mysql" ] ||
			fail "MySQL data directory is not fully accessible: $data_root/mysql"
		for directory in \
			"$data_root/archive-sandbox" \
			"$data_root/archive-sandbox/input" \
			"$data_root/archive-sandbox/output" \
			"$data_root/archive-sandbox/run" \
			"$data_root/application" \
			"$data_root/application/uploads" \
			"$data_root/application/repository" \
			"$data_root/application/repository/.staging" \
			"$data_root/application/repository/.staging/uploads" \
			"$data_root/application/task-work"; do
			[ -r "$directory" ] && [ -w "$directory" ] && [ -x "$directory" ] ||
				fail "application data directory is not fully accessible: $directory"
		done
		;;
	esac

	case "$system_name" in
	MSYS* | MINGW* | CYGWIN*) BINARYSCAN_DATA_ROOT=$(cygpath -m "$data_root") ;;
	*) BINARYSCAN_DATA_ROOT=$data_root ;;
	esac
	export BINARYSCAN_DATA_ROOT
	note "data root ready: $BINARYSCAN_DATA_ROOT"
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
	[ ! -L "$PROJECT_ROOT/.env" ] || fail ".env must not be a symbolic link"
	if [ -e "$PROJECT_ROOT/.env" ]; then
		[ -f "$PROJECT_ROOT/.env" ] || fail ".env is not a regular file"
	elif (set -C; cat "$PROJECT_ROOT/.env.example" >"$PROJECT_ROOT/.env") 2>/dev/null; then
		note "created .env from .env.example"
	else
		fail "could not create .env safely"
	fi
	for directory in "$PROJECT_ROOT/runtime" "$PROJECT_ROOT/runtime/secrets"; do
		[ ! -L "$directory" ] || fail "runtime directory must not be a symbolic link: $directory"
		if [ ! -e "$directory" ]; then
			mkdir "$directory" || fail "could not create runtime directory: $directory"
		fi
		[ -d "$directory" ] || fail "runtime path is not a directory: $directory"
	done
	created_admin=false
	for name in mysql_root_password mysql_app_password initial_admin_password; do
		path="$PROJECT_ROOT/runtime/secrets/$name"
		[ ! -L "$path" ] || fail "secret file must not be a symbolic link: $path"
		if [ -e "$path" ]; then
			[ -f "$path" ] && [ -s "$path" ] ||
				fail "existing secret must be a non-empty regular file: $path"
		elif [ "$name" = initial_admin_password ]; then
			if ! (
				set -C
				printf '%s\n' "$DEFAULT_INITIAL_ADMIN_PASSWORD" >"$path"
			) 2>/dev/null; then
				fail "could not create secret safely: $path"
			fi
			chmod 600 "$path"
			created_admin=true
		elif (set -C; random_hex >"$path") 2>/dev/null; then
			chmod 600 "$path"
		else
			fail "could not create secret safely: $path"
		fi
	done
	# Compose file-backed secrets retain host ownership on native Linux. The
	# private 0700 parent directories protect them on the host; 0644 lets the
	# fixed container UID 10001 read the individual read-only bind mounts.
	chmod 700 "$PROJECT_ROOT/runtime" "$PROJECT_ROOT/runtime/secrets"
	case "$(uname -s 2>/dev/null || printf unknown)" in
	Linux)
		chmod 644 \
			"$PROJECT_ROOT/runtime/secrets/mysql_root_password" \
			"$PROJECT_ROOT/runtime/secrets/mysql_app_password" \
			"$PROJECT_ROOT/runtime/secrets/initial_admin_password"
		;;
	*)
		chmod 600 \
			"$PROJECT_ROOT/runtime/secrets/mysql_root_password" \
			"$PROJECT_ROOT/runtime/secrets/mysql_app_password" \
			"$PROJECT_ROOT/runtime/secrets/initial_admin_password"
		;;
	esac
	if [ "$created_admin" = true ]; then
		note "default administrator credentials: admin / $DEFAULT_INITIAL_ADMIN_PASSWORD"
	fi
	load_settings
	prepare_data_directories
}

load_existing_runtime() {
	[ -f "$PROJECT_ROOT/.env" ] ||
		fail ".env is missing; run ./scripts/binaryscan.sh init first"
	load_settings
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

verify_locked_image() {
	image=$1
	expected_id=${2:-}
	[ -n "$expected_id" ] || fail "frozen image ID is missing for $image"
	verify_image "$image" "$expected_id"
}

verify_dependency_images() {
	load_settings
	verify_locked_image "$BINARYSCAN_BUILDER_IMAGE" "${BINARYSCAN_BUILDER_IMAGE_ID:-}"
	verify_locked_image "$BINARYSCAN_MYSQL_IMAGE" "${BINARYSCAN_MYSQL_IMAGE_ID:-}"
	verify_locked_image "$BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE" "${BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE_ID:-}"
	verify_locked_image "$BINARYSCAN_ARCHIVE_TOOLS_IMAGE" "${BINARYSCAN_ARCHIVE_TOOLS_IMAGE_ID:-}"
	verify_locked_image "$BINARYSCAN_JAVA_RUNTIME_IMAGE" "${BINARYSCAN_JAVA_RUNTIME_IMAGE_ID:-}"
	verify_locked_image "$BINARYSCAN_GHIDRA_RUNTIME_IMAGE" "${BINARYSCAN_GHIDRA_RUNTIME_IMAGE_ID:-}"
	verify_locked_image "$BINARYSCAN_C_CHECKER_BUILDER_IMAGE" "${BINARYSCAN_C_CHECKER_BUILDER_IMAGE_ID:-}"
	verify_locked_image "$BINARYSCAN_JAVA_CHECKER_BUILDER_IMAGE" "${BINARYSCAN_JAVA_CHECKER_BUILDER_IMAGE_ID:-}"
	verify_locked_image "$BINARYSCAN_C_CHECKER_JRE_IMAGE" "${BINARYSCAN_C_CHECKER_JRE_IMAGE_ID:-}"
}

verify_dependency_images_unlocked() {
	load_settings
	verify_image "$BINARYSCAN_BUILDER_IMAGE" ""
	verify_image "$BINARYSCAN_MYSQL_IMAGE" ""
	verify_image "$BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE" ""
	verify_image "$BINARYSCAN_ARCHIVE_TOOLS_IMAGE" ""
	verify_image "$BINARYSCAN_JAVA_RUNTIME_IMAGE" ""
	verify_image "$BINARYSCAN_GHIDRA_RUNTIME_IMAGE" ""
	verify_image "$BINARYSCAN_C_CHECKER_BUILDER_IMAGE" ""
	verify_image "$BINARYSCAN_JAVA_CHECKER_BUILDER_IMAGE" ""
	verify_image "$BINARYSCAN_C_CHECKER_JRE_IMAGE" ""
}

verify_product_images() {
	load_settings
	verify_image "${BINARYSCAN_APP_IMAGE:-binaryscan/app:0.1.0}" ""
	verify_image "${BINARYSCAN_SCANNER_IMAGE:-binaryscan/scanner:0.1.0}" ""
	verify_image "${BINARYSCAN_JAVA_IMAGE:-binaryscan/java:0.1.0}" ""
	verify_image "${BINARYSCAN_GHIDRA_IMAGE:-binaryscan/ghidra:0.1.0}" ""
	verify_image "${BINARYSCAN_C_CHECKER_IMAGE:-binaryscan/c-checker:0.1.0}" ""
	verify_image "${BINARYSCAN_JAVA_CHECKER_IMAGE:-binaryscan/java-checker:0.1.0}" ""
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
