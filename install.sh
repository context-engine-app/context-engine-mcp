#!/bin/sh

set -eu

# The public installer intentionally has no command-line options or production
# configuration. The test harness may suppress the final main call only.
readonly repository="context-engine-app/context-engine-mcp"
readonly minimum_version="0.2.0"
readonly latest_release_url="https://github.com/context-engine-app/context-engine-mcp/releases/latest"
readonly release_root="https://github.com/context-engine-app/context-engine-mcp/releases/download"

test_only="${CONTEXT_ENGINE_INSTALLER_TEST_ONLY:-0}"
installer_lock_acquired=0

fail() {
	printf 'Context Engine installer: %s\n' "$1" >&2
	exit 1
}

cleanup_working() {
	status=$?
	if [ "${cleanup_forced_status:-0}" -eq 1 ]; then
		status=1
		cleanup_forced_status=0
	fi
	if [ -n "${working:-}" ] && ! rm -rf -- "$working"; then
		printf 'Context Engine installer: cleanup failed: remove working directory\n' >&2
		status=1
	fi
	if [ "${installer_lock_acquired:-0}" -eq 1 ]; then
		if ! exec 9>&-; then
			printf 'Context Engine installer: cleanup failed: release installer lock\n' >&2
			status=1
		fi
		installer_lock_acquired=0
	fi
	trap - EXIT HUP INT TERM
	exit "$status"
}

cleanup_signal() {
	cleanup_forced_status=1
	cleanup_working
}

ce_curl() {
	curl --fail --silent --show-error --location --max-redirs 10 --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 60 --speed-time 30 --speed-limit 1 "$@"
}

validate_size() {
	validate_size_value=$1
	case "$validate_size_value" in
	'' | 0 | *[!0-9]*) return 1 ;;
	0*) return 1 ;;
	esac
	validate_size_length=${#validate_size_value}
	[ "$validate_size_length" -le 19 ] || return 1
	if [ "$validate_size_length" -eq 19 ]; then
		validate_size_maximum=9223372036854775807
		validate_size_index=1
		while [ "$validate_size_index" -le 19 ]; do
			validate_size_digit=$(printf '%s' "$validate_size_value" | cut -c "$validate_size_index")
			validate_size_max_digit=$(printf '%s' "$validate_size_maximum" | cut -c "$validate_size_index")
			if [ "$validate_size_digit" -lt "$validate_size_max_digit" ]; then
				break
			fi
			if [ "$validate_size_digit" -gt "$validate_size_max_digit" ]; then
				return 1
			fi
			validate_size_index=$((validate_size_index + 1))
		done
	fi
}

decimal_equal() {
	[ "$1" = "$2" ]
}

validate_payload_mode() {
	[ "$1" = 0755 ]
}

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum -- "$1" | awk '{ print $1 }'
	else
		shasum -a 256 -- "$1" | awk '{ print $1 }'
	fi
}

regular_file() {
	[ -f "$1" ] && [ ! -L "$1" ]
}

safe_path() {
	safe_path_value=$1
	if [ -e "$safe_path_value" ] || [ -L "$safe_path_value" ]; then
		regular_file "$safe_path_value"
	else
		return 0
	fi
}

curl_get() {
	curl_get_url=$1
	curl_get_out=$2
	shift 2
	canonical_release_request "$curl_get_url" || return 1
	curl_get_effective_file=$(mktemp "$curl_get_out.effective.XXXXXX") || return 1
	rm -f -- "$curl_get_out"
	curl_get_status=0
	(
		curl_get_file_limit=$(ulimit -f) || exit 1
		case "$curl_get_file_limit" in
		unlimited) ulimit -f 8192 || exit 1 ;;
		'' | *[!0-9]*) exit 1 ;;
		[0-9]*)
			if decimal_gt "$curl_get_file_limit" 8192; then ulimit -f 8192 || exit 1; fi
			;;
		esac
		ce_curl "$@" --output "$curl_get_out" --write-out '%{url_effective}' "$curl_get_url"
	) >"$curl_get_effective_file" || curl_get_status=$?
	curl_get_actual_size=0
	if [ -e "$curl_get_out" ]; then curl_get_actual_size=$(wc -c <"$curl_get_out" | tr -d '[:space:]'); fi
	if [ "$curl_get_status" -ne 0 ] || decimal_gt "$curl_get_actual_size" 4194304; then
		rm -f -- "$curl_get_out" "$curl_get_effective_file"
		return 1
	fi
	curl_get_effective=$(cat "$curl_get_effective_file")
	if ! acceptable_redirect "$curl_get_effective"; then
		rm -f -- "$curl_get_out" "$curl_get_effective_file"
		return 1
	fi
	rm -f -- "$curl_get_effective_file"
}

curl_effective() {
	url=$1
	shift
	ce_curl "$@" --output /dev/null --write-out '%{url_effective}' "$url"
}

acceptable_redirect() {
	effective=$1
	case "$effective" in
	https://*) return 0 ;;
	esac
	return 1
}

canonical_release_request() {
	request=$1
	case "$request" in
	https://github.com/context-engine-app/context-engine-mcp/releases/download/*) return 0 ;;
	esac
	return 1
}

discover_tag() {
	latest_url=$1
	effective=$(curl_effective "$latest_url") || fail "latest release lookup failed"
	case "$effective" in
	https://github.com/context-engine-app/context-engine-mcp/releases/tag/v*) ;;
	*) fail "latest release redirected outside the public product repository" ;;
	esac
	tag=$(printf '%s\n' "$effective" | sed -nE 's#^https://github\.com/context-engine-app/context-engine-mcp/releases/tag/(v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))$#\1#p')
	[ -n "$tag" ] || fail "latest release tag is not a stable semantic version"
	printf '%s\n' "$tag"
}

version_parts() {
	version=$1
	printf '%s\n' "$version" | sed -nE 's/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/\1 \2 \3/p'
}

decimal_gt() {
	decimal_gt_left=$1
	decimal_gt_right=$2
	case "$decimal_gt_left" in '' | 0* | *[!0-9]*) [ "$decimal_gt_left" = 0 ] || return 1 ;; esac
	case "$decimal_gt_right" in '' | 0* | *[!0-9]*) [ "$decimal_gt_right" = 0 ] || return 1 ;; esac
	[ "${#decimal_gt_left}" -gt "${#decimal_gt_right}" ] && return 0
	[ "${#decimal_gt_left}" -lt "${#decimal_gt_right}" ] && return 1
	decimal_gt_index=1
	while [ "$decimal_gt_index" -le "${#decimal_gt_left}" ]; do
		decimal_gt_left_digit=$(printf '%s' "$decimal_gt_left" | cut -c "$decimal_gt_index")
		decimal_gt_right_digit=$(printf '%s' "$decimal_gt_right" | cut -c "$decimal_gt_index")
		if [ "$decimal_gt_left_digit" -gt "$decimal_gt_right_digit" ]; then return 0; fi
		if [ "$decimal_gt_left_digit" -lt "$decimal_gt_right_digit" ]; then return 1; fi
		decimal_gt_index=$((decimal_gt_index + 1))
	done
	return 1
}

version_at_least() {
	version_at_least_left_parts=$(version_parts "$1")
	version_at_least_right_parts=$(version_parts "$2")
	[ -n "$version_at_least_left_parts" ] && [ -n "$version_at_least_right_parts" ] || return 1
	# Numeric components are intentionally small semantic-version fields in the
	# release contract; avoid shell arithmetic for untrusted byte counts.
	for version_at_least_component in 1 2 3; do
		version_at_least_left=$(printf '%s\n' "$version_at_least_left_parts" | cut -d' ' -f"$version_at_least_component")
		version_at_least_right=$(printf '%s\n' "$version_at_least_right_parts" | cut -d' ' -f"$version_at_least_component")
		version_at_least_left=${version_at_least_left#0}
		version_at_least_right=${version_at_least_right#0}
		version_at_least_left=${version_at_least_left:-0}
		version_at_least_right=${version_at_least_right:-0}
		if [ "${#version_at_least_left}" -gt "${#version_at_least_right}" ]; then return 0; fi
		if [ "${#version_at_least_left}" -lt "${#version_at_least_right}" ]; then return 1; fi
		if [ "$version_at_least_left" != "$version_at_least_right" ]; then
			decimal_gt "$version_at_least_left" "$version_at_least_right" && return 0
			return 1
		fi
	done
	return 0
}

json_string() {
	line=$1
	value=${line#*: }
	value=${value#\"}
	value=${value%\",}
	value=${value%\"}
	printf '%s\n' "$value"
}

# Extract the narrow release-manifest subset consumed by this script.  The
# release pipeline emits sorted two-space JSON; accepting only that shape keeps
# this dependency-free parser small and deterministic.
parse_manifest() {
	manifest=$1
	target=$2
	awk -v wanted_target="$target" '
	function fail(message) { print "manifest: " message > "/dev/stderr"; exit 1 }
	function scalar(line, value) {
		value=line; sub(/^[^:]+: /, "", value); sub(/,$/, "", value)
		if (value !~ /^"([^"\\]|\\.)*"$/) fail("manifest scalar must be a JSON string")
		sub(/^"/, "", value); sub(/"$/, "", value)
		return value
	}
	function rank(key) {
		if (section == "artifacts") {
			if (key == "architecture") return 1; if (key == "filename") return 2; if (key == "kind") return 3; if (key == "payload_id") return 4; if (key == "platform") return 5; if (key == "sha256") return 6; if (key == "size") return 7; if (key == "target") return 8; if (key == "url") return 9
		}
		if (section == "payloads") {
			if (key == "architecture") return 1; if (key == "executable_mode") return 2; if (key == "filename") return 3; if (key == "id") return 4; if (key == "license_mode") return 5; if (key == "platform") return 6; if (key == "sha256") return 7; if (key == "size") return 8; if (key == "target") return 9; if (key == "version_output") return 10
		}
		return 0
	}
	function field(key, value, current_rank) {
		value=scalar($0); if (seen[key]++) fail("duplicate " key)
		current_rank=rank(key); if (current_rank > 0 && current_rank <= last_rank) fail("non-canonical field order")
		if (current_rank > 0) last_rank=current_rank
		values[key]=value
	}
	BEGIN { section=""; object=0; selected=0; payload_selected=0; identity_order=0; }
	/^  "distribution_repository":/ { if (seen_repository++) fail("duplicate repository"); if (identity_order >= 1) fail("non-canonical identity order"); repository=scalar($0); identity_order=1; next }
	/^  "tag":/ { if (seen_tag++) fail("duplicate tag"); if (identity_order != 1) fail("non-canonical identity order"); tag=scalar($0); identity_order=2; next }
	/^  "version":/ { if (seen_version++) fail("duplicate version"); if (identity_order != 2) fail("non-canonical identity order"); version=scalar($0); identity_order=3; next }
	/^  "artifacts": \[/ { section="artifacts"; next }
	/^  "payloads": \[/ { section="payloads"; next }
	/^    \{/ {
		object=1; last_rank=0; delete values; delete seen; next
	}
	/^    \},?$/ {
		if (!object) next
		if (section == "artifacts" && values["kind"] == "archive" && values["target"] == wanted_target) {
			selected++; if (selected > 1) fail("duplicate archive target")
			artifact_payload=values["payload_id"]; artifact_filename=values["filename"]; artifact_target=values["target"]; artifact_url=values["url"]; artifact_sha=values["sha256"]; artifact_size=values["size"]
		}
		if (section == "payloads" && values["id"] == artifact_payload && values["target"] == wanted_target) {
			payload_selected++; if (payload_selected > 1) fail("duplicate payload")
			payload_id=values["id"]; payload_filename=values["filename"]; payload_target=values["target"]; payload_sha=values["sha256"]; payload_size=values["size"]; payload_mode=values["executable_mode"]; payload_version=values["version_output"]; payload_license=values["license_mode"]
		}
		object=0; next
	}
	object && /^      "(kind|payload_id|filename|target|url|sha256|size|id|platform|architecture|executable_mode|license_mode|version_output)":/ {
		key=$0; sub(/^      "/, "", key); sub(/".*/, "", key); field(key); next
	}
	END {
		if (repository == "" || tag == "" || version == "") fail("missing identity")
		if (repository != "context-engine-app/context-engine-mcp") fail("wrong repository")
		if (selected != 1 || payload_selected != 1) fail("target records are incomplete")
		for (key in values) { if (key == "") fail("invalid field") }
		if (artifact_filename == "" || artifact_target == "" || artifact_url == "" || artifact_sha == "" || artifact_size == "") fail("artifact fields are incomplete")
		if (payload_filename == "" || payload_target == "" || payload_sha == "" || payload_size == "" || payload_mode == "" || payload_version == "" || payload_license != "enforced") fail("payload fields are incomplete")
		printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", tag, version, artifact_filename, artifact_target, artifact_url, artifact_sha, artifact_size, payload_id, payload_filename, payload_sha, payload_size, payload_mode, payload_version
	}
' "$manifest"
}

parse_checksum() {
	checksums=$1
	filename=$2
	awk -v wanted="$filename" '
	$2 == wanted { count++; if (NF == 2 && $1 ~ /^[0-9a-f]{64}$/) { valid++; value=$1 } }
	END { if (count != 1 || valid != 1) exit 1; print value }
' "$checksums"
}

download_archive() {
	download_archive_url=$1
	download_archive_expected_size=$2
	download_archive_out=$3
	download_archive_header_file=$4
	canonical_release_request "$download_archive_url" || return 1
	# A final HEAD Content-Length is required before the GET.  The awk parser
	# counts only the final response block, so redirect headers cannot satisfy it.
	download_archive_effective=$(ce_curl --head --dump-header "$download_archive_header_file" --output /dev/null --write-out '%{url_effective}' "$download_archive_url") || return 1
	acceptable_redirect "$download_archive_effective" || return 1
	download_archive_head_size=$(awk '
	/^HTTP\// { count=0; value="" }
	/^[Cc]ontent-[Ll]ength:/ { count++; value=$2; sub(/\r$/, "", value) }
	END { if (count != 1) exit 1; print value }
	' "$download_archive_header_file") || return 1
	validate_size "$download_archive_head_size" || return 1
	decimal_equal "$download_archive_head_size" "$download_archive_expected_size" || return 1
	ce_curl --max-time 600 --max-filesize "$download_archive_expected_size" --output "$download_archive_out" "$download_archive_url" || return 1
	download_archive_actual=$(wc -c <"$download_archive_out" | tr -d '[:space:]')
	decimal_equal "$download_archive_actual" "$download_archive_expected_size"
}

safe_archive_member() {
	name=$1
	case "$name" in
	'' | . | .. | /* | ./* | ../* | */../* | */./* | */.. | */. | *//*) return 1 ;;
	esac
}

extract_archive() {
	extract_archive_path=$1
	extract_archive_filename=$2
	extract_archive_out=$3
	extract_archive_root=$4
	extract_archive_expected_mode=${5:-0755}
	extract_archive_listing="$extract_archive_root/listing"
	tar -tzf "$extract_archive_path" >"$extract_archive_listing" || return 1
	extract_archive_expected_count=$(awk -v wanted="$extract_archive_filename" '$0 == wanted { count++ } END { print count + 0 }' "$extract_archive_listing")
	[ "$extract_archive_expected_count" -eq 1 ] || return 1
	while IFS= read -r extract_archive_name; do
		safe_archive_member "$extract_archive_name" || return 1
		extract_archive_detail=$(tar -tvzf "$extract_archive_path" -- "$extract_archive_name") || return 1
		printf '%s\n' "$extract_archive_detail" | awk '
			NF == 0 { next }
			{ count++; if (substr($1, 1, 1) != "-") bad=1 }
			END { if (count == 0 || bad) exit 1 }
		' || return 1
		if [ "$extract_archive_name" = "$extract_archive_filename" ]; then
			extract_archive_permissions=$(printf '%s\n' "$extract_archive_detail" | awk 'NR == 1 { print substr($1, 2, 9) }')
			[ "$extract_archive_expected_mode" = 0755 ] && [ "$extract_archive_permissions" = rwxr-xr-x ] || return 1
		fi
	done <"$extract_archive_listing"
	tar -xzf "$extract_archive_path" -C "$extract_archive_root" -- "$extract_archive_filename" || return 1
	regular_file "$extract_archive_root/$extract_archive_filename" || return 1
	mv "$extract_archive_root/$extract_archive_filename" "$extract_archive_out"
}

run_version() {
	run_version_binary=$1
	run_version_expected=$2
	run_version_working=$3
	run_version_output="$run_version_working/version-output"
	"$run_version_binary" --version >"$run_version_output" 2>"$run_version_working/version-error" &
	run_version_pid=$!
	run_version_seconds=0
	while kill -0 "$run_version_pid" 2>/dev/null; do
		if [ "$run_version_seconds" -ge 10 ]; then
			kill -TERM "$run_version_pid" 2>/dev/null || true
			run_version_grace=0
			while kill -0 "$run_version_pid" 2>/dev/null && [ "$run_version_grace" -lt 2 ]; do
				sleep 1
				run_version_grace=$((run_version_grace + 1))
			done
			if kill -0 "$run_version_pid" 2>/dev/null; then
				kill -KILL "$run_version_pid" 2>/dev/null || true
				run_version_grace=0
				while kill -0 "$run_version_pid" 2>/dev/null && [ "$run_version_grace" -lt 2 ]; do
					sleep 1
					run_version_grace=$((run_version_grace + 1))
				done
			fi
			wait "$run_version_pid" 2>/dev/null || true
			return 1
		fi
		sleep 1
		run_version_seconds=$((run_version_seconds + 1))
	done
	wait "$run_version_pid" || return 1
	check_exact_version_output "$run_version_output" "$run_version_expected"
}

check_exact_version_output() {
	check_version_output=$1
	check_version_expected=$2
	printf '%s\n' "$check_version_expected" | cmp -s - "$check_version_output" || return 1
	if grep -F '(UNLICENSED DEV BUILD)' "$check_version_output" >/dev/null; then
		return 1
	fi
}

authorized_legacy_version() {
	authorized_legacy_binary=$1
	authorized_legacy_output=$(mktemp "${TMPDIR:-/tmp}/context-engine-version.XXXXXX") || return 1
	authorized_legacy_status=0
	"$authorized_legacy_binary" --version >"$authorized_legacy_output" 2>/dev/null || authorized_legacy_status=$?
	if [ "$authorized_legacy_status" -ne 0 ] || ! check_exact_version_output "$authorized_legacy_output" "context-engine 0.1.1"; then
		rm -f -- "$authorized_legacy_output" || true
		return 1
	fi
	rm -f -- "$authorized_legacy_output" || return 1
}

write_marker() {
	marker=$1
	(
		umask 077
		printf '{\n  "schema_version": 1,\n  "installation_method": "direct",\n  "distribution_repository": "%s"\n}\n' "$repository" >"$marker"
	)
}

entrypoint_parent() {
	entrypoint_parent_entrypoint=$1
	entrypoint_parent_value=${entrypoint_parent_entrypoint%/*}
	if [ "$entrypoint_parent_value" = "$entrypoint_parent_entrypoint" ]; then return 0; fi
	safe_directory_ancestors "$entrypoint_parent_value" || return 1
	if [ -e "$entrypoint_parent_value" ] || [ -L "$entrypoint_parent_value" ]; then
		[ -d "$entrypoint_parent_value" ] && [ ! -L "$entrypoint_parent_value" ] || return 1
		return 0
	fi
	entrypoint_parent_candidate=$entrypoint_parent_value
	while [ ! -e "$entrypoint_parent_candidate" ] && [ ! -L "$entrypoint_parent_candidate" ]; do
		entrypoint_parent_next=${entrypoint_parent_candidate%/*}
		if [ "$entrypoint_parent_next" = "$entrypoint_parent_candidate" ]; then entrypoint_parent_next=.; fi
		[ -n "$entrypoint_parent_next" ] || entrypoint_parent_next=/
		entrypoint_parent_candidate=$entrypoint_parent_next
	done
	[ -d "$entrypoint_parent_candidate" ] && [ ! -L "$entrypoint_parent_candidate" ] || return 1
	if [ "$entrypoint_parent_value" = /usr/local/bin ]; then
		sudo mkdir -m 0755 -- "$entrypoint_parent_value"
	else
		mkdir -m 0755 -- "$entrypoint_parent_value"
	fi
	[ -d "$entrypoint_parent_value" ] && [ ! -L "$entrypoint_parent_value" ]
}

safe_directory_ancestors() {
	safe_ancestors_path=$1
	case "$safe_ancestors_path" in
	'') return 1 ;;
	/*)
		safe_ancestors_current=/
		safe_ancestors_rest=${safe_ancestors_path#/}
		;;
	*)
		safe_ancestors_current=.
		safe_ancestors_rest=$safe_ancestors_path
		;;
	esac
	while [ -n "$safe_ancestors_rest" ]; do
		case "$safe_ancestors_rest" in
		*/*)
			safe_ancestors_component=${safe_ancestors_rest%%/*}
			safe_ancestors_rest=${safe_ancestors_rest#*/}
			;;
		*)
			safe_ancestors_component=$safe_ancestors_rest
			safe_ancestors_rest=
			;;
		esac
		[ -n "$safe_ancestors_component" ] || continue
		case "$safe_ancestors_component" in
		.) continue ;;
		..)
			return 1
			;;
		esac
		if [ "$safe_ancestors_current" = / ]; then safe_ancestors_current="/$safe_ancestors_component"; else safe_ancestors_current="$safe_ancestors_current/$safe_ancestors_component"; fi
		if [ -L "$safe_ancestors_current" ]; then
			return 1
		elif [ -e "$safe_ancestors_current" ] && [ ! -d "$safe_ancestors_current" ]; then
			return 1
		fi
	done
}

release_installer_lock() {
	if [ "${installer_lock_acquired:-0}" -eq 1 ]; then
		exec 9>&-
		installer_lock_acquired=0
	fi
}

acquire_installer_lock() {
	[ -n "${HOME:-}" ] || fail 'home directory is not set'
	case "$HOME" in
	/*) ;;
	*) fail 'home directory must be absolute' ;;
	esac
	installer_lock_os=$(uname -s) || fail 'cannot determine platform for installer lock'
	case "$installer_lock_os" in
	Darwin)
		command -v lockf >/dev/null 2>&1 || fail 'lockf is required to acquire the installer lock'
		;;
	Linux)
		command -v flock >/dev/null 2>&1 || fail 'flock is required to acquire the installer lock'
		;;
	*) fail 'unsupported platform for installer lock' ;;
	esac
	installer_lock_path="$HOME/.context-engine-installer.lock"
	safe_directory_ancestors "$HOME" || fail 'home directory is unsafe for installer lock'
	if [ -L "$installer_lock_path" ]; then
		fail 'installer lock path is a symlink'
	fi
	if [ -e "$installer_lock_path" ]; then
		[ -f "$installer_lock_path" ] || fail 'installer lock path is not a regular file'
	else
		if ! (
			umask 077
			set -C
			: >"$installer_lock_path"
		) 2>/dev/null; then
			if [ ! -e "$installer_lock_path" ] && [ ! -L "$installer_lock_path" ]; then
				fail 'cannot create installer lock file'
			fi
		fi
	fi
	[ -f "$installer_lock_path" ] && [ ! -L "$installer_lock_path" ] || fail 'installer lock path is not a regular file'
	installer_lock_size=$(wc -c <"$installer_lock_path" | tr -d '[:space:]')
	[ "$installer_lock_size" = 0 ] || fail 'installer lock file must be empty'
	if installer_lock_owner=$(stat -f '%u' "$installer_lock_path" 2>/dev/null) && case "$installer_lock_owner" in '' | *[!0-9]*) false ;; *) true ;; esac then :; else
		installer_lock_owner=$(stat -c '%u' -- "$installer_lock_path" 2>/dev/null) || fail 'cannot inspect installer lock owner'
	fi
	if installer_lock_mode=$(stat -f '%Lp' "$installer_lock_path" 2>/dev/null) && case "$installer_lock_mode" in '' | *[!0-9]*) false ;; *) true ;; esac then :; else
		installer_lock_mode=$(stat -c '%a' -- "$installer_lock_path" 2>/dev/null) || fail 'cannot inspect installer lock mode'
	fi
	[ "$installer_lock_owner" = "$(command id -u)" ] || fail 'installer lock file is not owned by the current user'
	[ "$installer_lock_mode" = 600 ] || fail 'installer lock file must have mode 0600'
	if ! exec 9<>"$installer_lock_path"; then
		fail 'cannot open installer lock file'
	fi
	case "$installer_lock_os" in
	Darwin)
		if ! lockf -s -t 0 9; then
			exec 9>&-
			fail 'another installer is already running'
		fi
		;;
	Linux)
		if ! flock -n 9; then
			exec 9>&-
			fail 'another installer is already running'
		fi
		;;
	esac
	installer_lock_acquired=1
}

entrypoint_repair_preflight() {
	entrypoint_preflight_entrypoint=$1
	entrypoint_preflight_parent=${entrypoint_preflight_entrypoint%/*}
	if [ "$entrypoint_preflight_parent" = "$entrypoint_preflight_entrypoint" ]; then return 0; fi
	safe_directory_ancestors "$entrypoint_preflight_parent" || return 1
	if [ -e "$entrypoint_preflight_parent" ] || [ -L "$entrypoint_preflight_parent" ]; then
		[ -d "$entrypoint_preflight_parent" ] && [ ! -L "$entrypoint_preflight_parent" ]
		return $?
	fi
	if [ "$entrypoint_preflight_parent" = /usr/local/bin ]; then
		[ -d /usr/local ] && [ ! -L /usr/local ] || return 1
		sudo test -d /usr/local
		return $?
	fi
	entrypoint_preflight_candidate=$entrypoint_preflight_parent
	while [ ! -e "$entrypoint_preflight_candidate" ] && [ ! -L "$entrypoint_preflight_candidate" ]; do
		entrypoint_preflight_next=${entrypoint_preflight_candidate%/*}
		if [ "$entrypoint_preflight_next" = "$entrypoint_preflight_candidate" ]; then entrypoint_preflight_next=.; fi
		[ -n "$entrypoint_preflight_next" ] || entrypoint_preflight_next=/
		entrypoint_preflight_candidate=$entrypoint_preflight_next
	done
	[ -d "$entrypoint_preflight_candidate" ] && [ ! -L "$entrypoint_preflight_candidate" ] && [ -w "$entrypoint_preflight_candidate" ]
}

remove_entrypoint_parent() {
	remove_entrypoint_parent_value=$1
	if [ "$remove_entrypoint_parent_value" = /usr/local/bin ]; then
		sudo rmdir -- "$remove_entrypoint_parent_value"
	else
		rmdir -- "$remove_entrypoint_parent_value"
	fi
}

remove_legacy_backup_container() {
	remove_backup_dir=$1
	if [ "$entrypoint" = /usr/local/bin/context-engine ]; then
		sudo rmdir -- "$remove_backup_dir"
	else
		rmdir -- "$remove_backup_dir"
	fi
}

repair_entrypoint() {
	repair_physical=$1
	repair_entrypoint_value=$2
	entrypoint_parent "$repair_entrypoint_value" || return 1
	if [ -L "$repair_entrypoint_value" ]; then
		[ "$(readlink "$repair_entrypoint_value")" = "$repair_physical" ] || return 1
		return 0
	fi
	[ ! -e "$repair_entrypoint_value" ] || return 1
	if ln -s "$repair_physical" "$repair_entrypoint_value"; then
		return 0
	fi
	if [ "$repair_entrypoint_value" = /usr/local/bin/context-engine ]; then
		sudo ln -s "$repair_physical" "$repair_entrypoint_value"
		return $?
	fi
	return 1
}

legacy_hash() {
	target=$1
	case "$target" in
	aarch64-apple-darwin) printf '%s\n' e271e9e8c14dfa759729978513148d05f11f9050e63a365338a63222c1faa144 ;;
	aarch64-unknown-linux-gnu) printf '%s\n' 41fc962f14a34fad23585152c2b5acd52db9569ce0474337f34d0261bf3cf84b ;;
	*) return 1 ;;
	esac
}

target_for_host() {
	os=$(uname -s)
	arch=$(uname -m)
	case "$os:$arch" in
	Darwin:arm64 | Darwin:aarch64) printf '%s\n' aarch64-apple-darwin ;;
	Darwin:x86_64 | Darwin:amd64) printf '%s\n' x86_64-apple-darwin ;;
	Linux:aarch64 | Linux:arm64) printf '%s\n' aarch64-unknown-linux-gnu ;;
	Linux:x86_64 | Linux:amd64) printf '%s\n' x86_64-unknown-linux-gnu ;;
	*) fail "unsupported platform: $os $arch" ;;
	esac
}

classify_entrypoint() {
	classify_target=$1
	classify_entrypoint_value=$2
	classify_parent=${classify_entrypoint_value%/*}
	if [ "$classify_parent" != "$classify_entrypoint_value" ]; then safe_directory_ancestors "$classify_parent" || return 1; fi
	if [ "$classify_parent" != "$classify_entrypoint_value" ] && { [ -e "$classify_parent" ] || [ -L "$classify_parent" ]; }; then
		[ -d "$classify_parent" ] && [ ! -L "$classify_parent" ] || return 1
	fi
	if [ ! -e "$classify_entrypoint_value" ] && [ ! -L "$classify_entrypoint_value" ]; then
		printf '%s\n' fresh
		return 0
	fi
	[ -L "$classify_entrypoint_value" ] && return 1
	[ "$classify_target" = aarch64-apple-darwin ] || [ "$classify_target" = aarch64-unknown-linux-gnu ] || return 1
	regular_file "$classify_entrypoint_value" || return 1
	classify_legacy_expected=$(legacy_hash "$classify_target") || return 1
	[ "$(sha256_file "$classify_entrypoint_value")" = "$classify_legacy_expected" ] || return 1
	authorized_legacy_version "$classify_entrypoint_value" || return 1
	printf '%s\n' legacy
}

install_fresh() {
	target=$1
	tag=$2
	version=$3
	archive_filename=$4
	archive_sha=$5
	archive_size=$6
	payload_filename=$7
	payload_sha=$8
	payload_size=$9
	payload_mode=${10}
	payload_version=${11}
	working=${12}
	root=${13}
	entrypoint=${14}
	transition=${15:-}
	newline=$(printf '\nX')
	newline=${newline%X}
	created_root_dirs=
	install_parent=${root%/*}
	case "$install_parent" in
	*"$newline"*) fail "installation parent contains an unsupported newline" ;;
	esac
	entrypoint_parent_path=${entrypoint%/*}
	legacy_backup=
	backup_dir=
	legacy_moved=0
	backup_created=0
	committed=0
	entrypoint_installed=0
	post_commit_cleanup_failed=0
	stage=
	entrypoint_parent_created=0
	cleanup_error=
	[ ! -e "$root" ] && [ ! -L "$root" ] || fail "installation directory already exists"
	safe_directory_ancestors "$install_parent" || fail "installation parent is unsafe"
	if [ -L "$install_parent" ] || { [ -e "$install_parent" ] && [ ! -d "$install_parent" ]; }; then
		fail "installation parent is unsafe"
	fi
	candidate=$install_parent
	while [ "$candidate" != / ] && [ ! -e "$candidate" ] && [ ! -L "$candidate" ]; do
		created_root_dirs="${created_root_dirs}${candidate}${newline}"
		next=${candidate%/*}
		if [ "$next" = "$candidate" ]; then next=.; fi
		[ -n "$next" ] || next=/
		candidate=$next
	done
	if [ -L "$candidate" ] || { [ -e "$candidate" ] && [ ! -d "$candidate" ]; }; then
		fail "installation parent is unsafe"
	fi
	if [ -z "$transition" ]; then
		if [ -e "$entrypoint" ] || [ -L "$entrypoint" ]; then transition=legacy; else transition=fresh; fi
	fi
	case "$transition" in
	fresh)
		[ ! -e "$entrypoint" ] && [ ! -L "$entrypoint" ] || fail "command entrypoint appeared during install"
		;;
	legacy)
		[ -e "$entrypoint" ] || [ -L "$entrypoint" ] || fail "legacy command entrypoint disappeared"
		[ ! -L "$entrypoint" ] || fail "legacy command entrypoint is a symlink"
		if [ "$target" != aarch64-apple-darwin ] && [ "$target" != aarch64-unknown-linux-gnu ]; then
			fail "existing command entrypoint is a conflict"
		fi
		regular_file "$entrypoint" || fail "legacy entrypoint is not a regular file"
		legacy_expected=$(legacy_hash "$target") || fail "legacy migration is unsupported for this target"
		[ "$(sha256_file "$entrypoint")" = "$legacy_expected" ] || fail "legacy executable hash is not authorized"
		authorized_legacy_version "$entrypoint" || fail "legacy executable version is not authorized"
		legacy_backup=planned
		;;
	*) fail "unknown installation transition" ;;
	esac
	cleanup_stage() {
		status=$?
		if [ "${cleanup_forced_status:-0}" -eq 1 ]; then
			status=1
			cleanup_forced_status=0
		fi
		if [ "$entrypoint_installed" -eq 1 ] && [ "$status" -ne 0 ]; then
			if [ -L "$entrypoint" ] && [ "$(readlink "$entrypoint")" = "$root/context-engine" ]; then
				if [ "$entrypoint" = /usr/local/bin/context-engine ]; then
					sudo rm -f -- "$entrypoint" || cleanup_error="${cleanup_error:+$cleanup_error; }remove failed command entrypoint"
				else
					rm -f -- "$entrypoint" || cleanup_error="${cleanup_error:+$cleanup_error; }remove failed command entrypoint"
				fi
				[ ! -e "$entrypoint" ] && [ ! -L "$entrypoint" ] && entrypoint_installed=0
			else
				cleanup_error="${cleanup_error:+$cleanup_error; }command entrypoint changed during recovery"
			fi
		fi
		if [ "$committed" -eq 1 ] && [ "$post_commit_cleanup_failed" -eq 0 ] && [ "$status" -ne 0 ]; then
			if [ -d "$root" ] && [ ! -L "$root" ] && ! rm -rf -- "$root"; then
				cleanup_error="${cleanup_error:+$cleanup_error; }remove promoted installation"
			fi
			committed=0
		fi
		if [ "$legacy_moved" -eq 1 ] && [ "$status" -ne 0 ]; then
			can_restore=1
			if [ -e "$entrypoint" ] || [ -L "$entrypoint" ]; then
				cleanup_error="${cleanup_error:+$cleanup_error; }command entrypoint changed during recovery"
				can_restore=0
			fi
			if [ "$can_restore" -eq 1 ] && regular_file "$legacy_backup"; then
				if [ "$entrypoint" = /usr/local/bin/context-engine ]; then
					if sudo mv -- "$legacy_backup" "$entrypoint"; then legacy_moved=0; else cleanup_error="${cleanup_error:+$cleanup_error; }restore legacy entrypoint"; fi
				else
					if mv -- "$legacy_backup" "$entrypoint"; then legacy_moved=0; else cleanup_error="${cleanup_error:+$cleanup_error; }restore legacy entrypoint"; fi
				fi
			elif [ "$can_restore" -eq 1 ]; then
				if [ -e "$legacy_backup" ] || [ -L "$legacy_backup" ]; then
					cleanup_error="${cleanup_error:+$cleanup_error; }legacy backup is unsafe"
				else
					cleanup_error="${cleanup_error:+$cleanup_error; }legacy backup disappeared"
				fi
			fi
		fi
		if [ -n "$stage" ]; then
			if ! rm -rf -- "$stage"; then cleanup_error="${cleanup_error:+$cleanup_error; }remove staging directory"; fi
			stage=
		fi
		if [ "$backup_created" -eq 1 ] && [ "$legacy_moved" -eq 0 ]; then
			if [ -d "$backup_dir" ] && [ ! -L "$backup_dir" ]; then
				if remove_legacy_backup_container "$backup_dir" 2>/dev/null; then
					backup_created=0
					backup_dir=
				else
					cleanup_error="${cleanup_error:+$cleanup_error; }remove legacy backup container"
				fi
			else
				cleanup_error="${cleanup_error:+$cleanup_error; }legacy backup container is unsafe"
			fi
		fi
		if [ "$entrypoint_parent_created" -eq 1 ] && [ -d "$entrypoint_parent_path" ] && [ ! -L "$entrypoint_parent_path" ]; then
			if ! remove_entrypoint_parent "$entrypoint_parent_path" 2>/dev/null; then
				cleanup_error="${cleanup_error:+$cleanup_error; }remove created entrypoint parent"
			fi
		fi
		if [ -n "$created_root_dirs" ]; then
			cleanup_created_root_dirs=$created_root_dirs
			while [ -n "$cleanup_created_root_dirs" ]; do
				case "$cleanup_created_root_dirs" in
				*"$newline"*)
					created_dir=${cleanup_created_root_dirs%%"$newline"*}
					cleanup_created_root_dirs=${cleanup_created_root_dirs#*"$newline"}
					;;
				*)
					created_dir=$cleanup_created_root_dirs
					cleanup_created_root_dirs=
					;;
				esac
				[ -n "$created_dir" ] || continue
				if [ -d "$created_dir" ] && [ ! -L "$created_dir" ] && ! rmdir -- "$created_dir" 2>/dev/null; then
					cleanup_error="${cleanup_error:+$cleanup_error; }remove created installation parent"
				fi
			done
		fi
		if [ -n "${working:-}" ]; then
			if ! rm -rf -- "$working"; then cleanup_error="${cleanup_error:+$cleanup_error; }remove working directory"; fi
			working=
		fi
		if [ "${installer_lock_acquired:-0}" -eq 1 ]; then
			if ! release_installer_lock; then
				cleanup_error="${cleanup_error:+$cleanup_error; }release installer lock"
				status=1
			fi
		fi
		if [ -n "$cleanup_error" ]; then
			printf 'Context Engine installer: recovery failed: %s\n' "$cleanup_error" >&2
			status=1
		fi
		trap - EXIT HUP INT TERM
		exit "$status"
	}
	cleanup_stage_signal() {
		cleanup_forced_status=1
		cleanup_stage
	}
	trap cleanup_stage EXIT
	trap cleanup_stage_signal HUP INT TERM
	if ! mkdir -p -- "$install_parent"; then fail "cannot create installation parent"; fi
	if [ "$entrypoint_parent_path" != "$entrypoint" ] && [ ! -e "$entrypoint_parent_path" ] && [ ! -L "$entrypoint_parent_path" ]; then
		entrypoint_parent_created=1
	fi
	if ! entrypoint_parent "$entrypoint"; then fail "command entrypoint parent is unsafe"; fi
	if [ "$transition" = legacy ]; then
		backup_pattern="$entrypoint_parent_path/.context-engine-legacy-backup.XXXXXX"
		if [ "$entrypoint" = /usr/local/bin/context-engine ]; then
			backup_dir=$(sudo mktemp -d "$backup_pattern") || fail "cannot create exclusive legacy backup container"
		else
			backup_dir=$(mktemp -d "$backup_pattern") || fail "cannot create exclusive legacy backup container"
		fi
		[ -d "$backup_dir" ] && [ ! -L "$backup_dir" ] || fail "legacy backup container is unsafe"
		case "$backup_dir" in
		"$entrypoint_parent_path"/.context-engine-legacy-backup.*) ;;
		*) fail "legacy backup container is outside the command parent" ;;
		esac
		backup_created=1
		legacy_backup="$backup_dir/context-engine"
		[ ! -e "$legacy_backup" ] && [ ! -L "$legacy_backup" ] || fail "legacy backup destination is not empty"
		[ "$(classify_entrypoint "$target" "$entrypoint")" = legacy ] || fail "legacy command entrypoint changed during install"
		if [ "$entrypoint" = /usr/local/bin/context-engine ]; then
			sudo mv -- "$entrypoint" "$legacy_backup" || fail "cannot stage legacy entrypoint"
		else
			mv -- "$entrypoint" "$legacy_backup" || fail "cannot stage legacy entrypoint"
		fi
		legacy_moved=1
	fi
	stage=$(mktemp -d "$install_parent/.context-engine-install.XXXXXX") || fail "cannot create staging directory"
	stage_name=${stage##*/}
	cp "$working/$payload_filename" "$stage/context-engine" || fail "cannot stage executable"
	chmod "$payload_mode" "$stage/context-engine" || fail "cannot set executable mode"
	write_marker "$stage/.context-engine-installation.json" || fail "cannot stage marker"
	[ ! -e "$root" ] || fail "installation directory appeared during install"
	mv -n "$stage" "$root" || fail "cannot promote installation directory"
	if [ -e "$stage" ] || [ -L "$stage" ]; then fail "installation directory appeared during install"; fi
	nested_stage="$root/$stage_name"
	if [ -e "$nested_stage" ] || [ -L "$nested_stage" ]; then
		if [ -d "$nested_stage" ] && [ ! -L "$nested_stage" ]; then stage=$nested_stage; else stage=; fi
		fail "installation directory appeared during install"
	fi
	stage=
	committed=1
	if ! repair_entrypoint "$root/context-engine" "$entrypoint"; then fail "cannot install command entrypoint"; fi
	entrypoint_installed=1
	if [ "$legacy_moved" -eq 1 ]; then
		regular_file "$legacy_backup" || fail "legacy backup is no longer a safe regular file"
		if [ "$entrypoint" = /usr/local/bin/context-engine ]; then
			sudo rm -f -- "$legacy_backup" || fail "cannot remove legacy backup"
		else
			rm -f -- "$legacy_backup" || fail "cannot remove legacy backup"
		fi
		legacy_moved=0
		if [ -d "$backup_dir" ] && [ ! -L "$backup_dir" ]; then
			if ! remove_legacy_backup_container "$backup_dir" 2>/dev/null; then
				backup_created=0
				post_commit_cleanup_failed=1
				entrypoint_installed=0
				legacy_moved=0
				entrypoint_parent_created=0
				created_root_dirs=
				printf 'Context Engine installer: post-commit cleanup failed: remove legacy backup container\n' >&2
				return 1
			fi
		else
			backup_created=0
			post_commit_cleanup_failed=1
			entrypoint_installed=0
			legacy_moved=0
			entrypoint_parent_created=0
			created_root_dirs=
			printf 'Context Engine installer: post-commit cleanup failed: legacy backup container is unsafe\n' >&2
			return 1
		fi
		backup_created=0
		backup_dir=
		legacy_backup=
	fi
	committed=0
	entrypoint_parent_created=0
	created_root_dirs=
	printf 'Context Engine %s installed for %s.\n' "$version" "$target"
}

marked_installation_valid() {
	marked_valid_root=$1
	marked_valid_entrypoint=$2
	marked_valid_marker="$marked_valid_root/.context-engine-installation.json"
	marked_valid_binary="$marked_valid_root/context-engine"
	regular_file "$marked_valid_marker" || return 1
	regular_file "$marked_valid_binary" || return 1
	[ "$(wc -l <"$marked_valid_marker" | tr -d '[:space:]')" = 5 ] || return 1
	marked_valid_marker_ok=$(awk '
	NR == 1 && $0 == "{" { next }
	NR == 2 && $0 == "  \"schema_version\": 1," { next }
	NR == 3 && $0 == "  \"installation_method\": \"direct\"," { next }
	NR == 4 && $0 == "  \"distribution_repository\": \"context-engine-app/context-engine-mcp\"" { next }
	NR == 5 && $0 == "}" { next }
	{ bad=1 }
	END { if (!bad && NR == 5) print "yes" }
	' "$marked_valid_marker")
	[ "$marked_valid_marker_ok" = yes ] || return 1
	[ -x "$marked_valid_binary" ] || return 1
	entrypoint_repair_preflight "$marked_valid_entrypoint" || return 1
	if [ -e "$marked_valid_entrypoint" ] || [ -L "$marked_valid_entrypoint" ]; then
		[ -L "$marked_valid_entrypoint" ] && [ "$(readlink "$marked_valid_entrypoint")" = "$marked_valid_binary" ] || return 1
	fi
	return 0
}

marked_reinstall() {
	root=$1
	entrypoint=$2
	marked_installation_valid "$root" "$entrypoint" || return 1
	marker="$root/.context-engine-installation.json"
	binary="$root/context-engine"
	"$binary" update || fail "direct updater failed"
	repair_entrypoint "$binary" "$entrypoint" || fail "updated binary but could not repair command entrypoint"
	printf '%s\n' 'Context Engine direct installation updated.'
}

main() {
	[ "$(id -u)" -ne 0 ] || fail 'do not run the direct installer as root'
	[ -n "${HOME:-}" ] || fail 'home directory is not set'
	case "$HOME" in
	/*) ;;
	*) fail 'home directory must be absolute' ;;
	esac
	target=$(target_for_host)
	root="$HOME/.local/lib/context-engine"
	entrypoint=/usr/local/bin/context-engine
	safe_directory_ancestors "${root%/*}" || fail 'installation parent is unsafe'
	if [ -d "$root" ] && [ ! -L "$root" ] && marked_installation_valid "$root" "$entrypoint"; then
		transition=marked
	elif [ -e "$root" ] || [ -L "$root" ]; then
		fail 'existing installation directory is not a valid marked direct installation'
	else
		transition=$(classify_entrypoint "$target" "$entrypoint") || fail 'existing command entrypoint is not an authorized legacy installation'
	fi
	acquire_installer_lock
	trap cleanup_working EXIT
	trap cleanup_signal HUP INT TERM
	safe_directory_ancestors "${root%/*}" || fail 'installation parent is unsafe'
	if [ -d "$root" ] && [ ! -L "$root" ] && marked_installation_valid "$root" "$entrypoint"; then
		marked_reinstall "$root" "$entrypoint"
		exit 0
	fi
	if [ -e "$root" ] || [ -L "$root" ]; then
		fail 'existing installation directory is not a valid marked direct installation'
	fi
	transition=$(classify_entrypoint "$target" "$entrypoint") || fail 'existing command entrypoint is not an authorized legacy installation'
	tag=$(discover_tag "$latest_release_url")
	version=${tag#v}
	version_at_least "$version" "$minimum_version" || fail "latest product release is older than $minimum_version"
	working=$(mktemp -d) || fail 'cannot create temporary directory'
	trap cleanup_working EXIT
	trap cleanup_signal HUP INT TERM
	base="$release_root/$tag"
	manifest="$working/release-manifest.json"
	checksums="$working/SHA256SUMS"
	curl_get "$base/release-manifest.json" "$manifest" --max-filesize 4194304 || fail 'manifest download failed'
	curl_get "$base/SHA256SUMS" "$checksums" --max-filesize 4194304 || fail 'checksum download failed'
	parsed=$(parse_manifest "$manifest" "$target") || fail 'release manifest does not contain a valid target record'
	tab=$(printf '\t')
	IFS="$tab" read -r manifest_tag manifest_version archive_filename archive_target archive_url archive_sha archive_size payload_id payload_filename payload_sha payload_size payload_mode payload_version <<EOF
$parsed
EOF
	[ "$manifest_tag" = "$tag" ] && [ "$manifest_version" = "$version" ] || fail 'manifest release identity mismatch'
	[ -n "$payload_id" ] || fail 'manifest payload linkage is missing'
	[ "$archive_target" = "$target" ] || fail 'manifest archive target mismatch'
	[ "$archive_url" = "$base/$archive_filename" ] || fail 'manifest archive URL is not canonical'
	[ "$archive_filename" = "context-engine-$target.tar.gz" ] || fail 'manifest archive filename is not canonical'
	validate_size "$archive_size" || fail 'manifest archive size is not a positive signed-64-bit decimal'
	validate_size "$payload_size" || fail 'manifest payload size is not a positive signed-64-bit decimal'
	case "$archive_sha:$payload_sha" in *[!0-9a-f:]*) fail 'manifest checksum is not lowercase SHA-256' ;; esac
	[ "${#archive_sha}" -eq 64 ] && [ "${#payload_sha}" -eq 64 ] || fail 'manifest checksum length is invalid'
	[ "$payload_filename" = context-engine ] || fail 'manifest payload filename is invalid'
	validate_payload_mode "$payload_mode" || fail 'manifest executable mode is not production mode'
	[ "$payload_version" = "context-engine $version" ] || fail 'manifest version output does not match release'
	checksum=$(parse_checksum "$checksums" "$archive_filename") || fail 'checksum record is missing or ambiguous'
	[ "$checksum" = "$archive_sha" ] || fail 'checksum record disagrees with manifest'
	archive="$working/$archive_filename"
	headers="$working/headers"
	download_archive "$archive_url" "$archive_size" "$archive" "$headers" || fail 'archive download framing or size is invalid'
	[ "$(sha256_file "$archive")" = "$archive_sha" ] || fail 'archive SHA-256 mismatch'
	extract_working="$working/extracted"
	mkdir -m 0700 -- "$extract_working" || fail 'cannot create archive extraction directory'
	staged="$working/context-engine"
	extract_archive "$archive" "$payload_filename" "$staged" "$extract_working" "$payload_mode" || fail 'archive layout or executable mode is unsafe'
	[ "$(wc -c <"$staged" | tr -d '[:space:]')" = "$payload_size" ] || fail 'payload size mismatch'
	[ "$(sha256_file "$staged")" = "$payload_sha" ] || fail 'payload SHA-256 mismatch'
	chmod "$payload_mode" "$staged" || fail 'cannot apply executable mode'
	run_version "$staged" "$payload_version" "$working" || fail 'staged binary failed exact version validation'
	install_fresh "$target" "$tag" "$version" "$archive_filename" "$archive_sha" "$archive_size" "$payload_filename" "$payload_sha" "$payload_size" "$payload_mode" "$payload_version" "$working" "$root" "$entrypoint" "$transition"
}

if [ "$test_only" != 1 ]; then
	main "$@"
fi
