#!/usr/bin/env bash
# StealthyPrivesc policy-bound dispatcher — authorized assessments only.
# This launcher may select an approved script fallback when the primary
# executable cannot start. It never disables or bypasses host controls.
#
# Fallback hosts are fixed enumerate-only reduced coverage. Only auth
# (via STEALTHY_AUTHORIZED) and --json / --format json are forwarded;
# binary flags such as --profile / --plugins are not applied to scripts.
# Missing interpreters are skipped. A launched host that is blocked
# (126/127/signal) stops the walk; the primary is never retried.
# Dispatcher banners are silent unless STEALTHY_DISPATCHER_VERBOSE=1.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$script_dir/stealthy-run.conf" ]]; then
  bundle_dir="$(cd "$script_dir/.." && pwd)"
  default_manifest="$script_dir/stealthy-run.conf"
else
  bundle_dir="$(cd "$script_dir/../.." && pwd)"
  default_manifest="$bundle_dir/scripts/stealthy-run.conf"
fi
manifest="${STEALTHY_MANIFEST:-$default_manifest}"

declare -A cfg=()
while IFS='=' read -r key value; do
  [[ -z "${key//[[:space:]]/}" || "${key:0:1}" == "#" ]] && continue
  key="${key//[[:space:]]/}"
  cfg["$key"]="${value%$'\r'}"
done < "$manifest"

require() {
  local key="$1"
  [[ -n "${cfg[$key]:-}" ]] || { echo "dispatcher: manifest missing $key" >&2; exit 78; }
}

require manifest_version
require authorization_ack
require allow_fallback
require roe_ref
require target_hostname
require operator_ack_required
[[ "${cfg[manifest_version]}" == "1" ]] || { echo "dispatcher: unsupported manifest version" >&2; exit 78; }
[[ "${cfg[authorization_ack]}" == "true" ]] || { echo "dispatcher: authorization_ack is not true" >&2; exit 78; }
[[ "${cfg[allow_fallback]}" == "true" ]] || { echo "dispatcher: fallback is not approved" >&2; exit 78; }
[[ "${cfg[operator_ack_required]}" == "true" ]] || { echo "dispatcher: operator acknowledgment is not required by the manifest" >&2; exit 78; }
[[ "${cfg[execution_mode]:-enumerate-only}" == "enumerate-only" ]] || {
  echo "dispatcher: only enumerate-only fallback mode is supported" >&2; exit 78;
}
bundle_mode="${cfg[bundle_mode]:-native-with-fallbacks}"
case "$bundle_mode" in
  native-with-fallbacks|script-only) ;;
  *) echo "dispatcher: unsupported bundle mode" >&2; exit 78 ;;
esac
if [[ "$bundle_mode" == "script-only" && -n "${cfg[primary_binary]:-}" ]]; then
  echo "dispatcher: script-only bundle must not declare a primary binary" >&2
  exit 78
fi

actual_host="$(cat /etc/hostname 2>/dev/null || hostname 2>/dev/null || true)"
expected_host="${cfg[target_hostname]}"
if [[ -z "$expected_host" || "$expected_host" == "AUTO" || "$expected_host" == "REQUIRED" || "$expected_host" == "SET_TARGET_HOSTNAME" ]]; then
  echo "dispatcher: explicit target_hostname is required" >&2
  exit 78
fi
if [[ "$actual_host" != "$expected_host" ]]; then
  echo "dispatcher: target hostname mismatch (expected ${cfg[target_hostname]}, got ${actual_host:-unknown})" >&2
  exit 78
fi
if [[ -n "${cfg[target_username]:-}" && "${cfg[target_username]}" != "AUTO" && "${USER:-}" != "${cfg[target_username]}" ]]; then
  echo "dispatcher: target username mismatch" >&2
  exit 78
fi

authorized_arg=false
for arg in "$@"; do
  [[ "$arg" == "--authorized" || "$arg" == "--i-understand-authorized-use-only" ]] && authorized_arg=true
done
if [[ "${STEALTHY_AUTHORIZED:-}" == "1" ]]; then
  authorized_arg=true
fi
if [[ "$authorized_arg" == false ]]; then
  echo "Authorization required: pass --authorized or set STEALTHY_AUTHORIZED=1" >&2
  exit 2
fi
export STEALTHY_AUTHORIZED=1

dispatcher_verbose=false
case "${STEALTHY_DISPATCHER_VERBOSE:-}" in
  1|true|TRUE|yes|YES) dispatcher_verbose=true ;;
esac
dispatcher_log() {
  if [[ "$dispatcher_verbose" == true ]]; then
    echo "dispatcher: $*" >&2
  fi
}

# True when /proc/self/mounts lists noexec on the longest prefix of $1.
mount_has_noexec() {
  local target="$1"
  local resolved=""
  if [[ -d "$target" ]]; then
    resolved="$(cd "$target" && pwd)" || return 1
  elif [[ -e "$target" ]]; then
    resolved="$(cd "$(dirname "$target")" && pwd)/$(basename "$target")" || return 1
  else
    return 1
  fi
  local mp opts best_opts="" best_len=-1
  while read -r _ mp _ opts _; do
    mp="${mp//\\040/ }"
    case "$resolved" in
      "$mp"|"$mp"/*)
        if [[ ${#mp} -gt $best_len ]]; then
          best_len=${#mp}
          best_opts="$opts"
        fi
        ;;
    esac
  done < /proc/self/mounts || true
  [[ "$best_opts" == *noexec* ]]
}

# Prints a short reason and returns 0 when a live endpoint sensor or noexec
# drop mount is observed. Process comm names only; no ps/systemctl.
detect_linux_sensor() {
  local path comm
  for path in /proc/[0-9]*/comm; do
    [[ -r "$path" ]] || continue
    comm=""
    IFS= read -r comm < "$path" || true
    comm="${comm%$'\r'}"
    case "$comm" in
      falcon-sensor|mdatp|wdavdaemon|elastic-agent|sentinelone-agent|s1-agent|cbagentd|cbdaemon|RepMgr|mfetpd|SophosHealth|savscand|symcfgd|rtvscand|tmdagent|ds_agent|kesl|ens|utl|bdagentd|cortex-xdr|traps_paned|cylancesvc|osqueryd|qualys-cloud-agent|tvmagent|ir_agent|taniumclient|fapolicyd)
        printf 'comm=%s' "$comm"
        return 0
        ;;
    esac
  done
  if mount_has_noexec "$1"; then
    printf 'mount-noexec'
    return 0
  fi
  return 1
}

fallback_banner() {
  local label="$1"
  case "${dispatch_reason:-blocked}" in
    script-only) dispatcher_log "script-only bundle; trying approved $label fallback" ;;
    script-first) dispatcher_log "script-first; trying approved $label fallback" ;;
    *) dispatcher_log "primary executable blocked; trying approved $label fallback" ;;
  esac
}

# Empty drop_dir (staged default) -> run the ELF in place, matching Windows.
# Avoids a second write+exec from $bundle_dir/.run-cache.
drop_dir_raw="${cfg[drop_dir]:-}"
drop_dir_raw="${drop_dir_raw#"${drop_dir_raw%%[![:space:]]*}"}"
drop_dir_raw="${drop_dir_raw%"${drop_dir_raw##*[![:space:]]}"}"
if [[ -z "$drop_dir_raw" ]]; then
  use_in_place=true
  drop_dir="$bundle_dir"
else
  use_in_place=false
  drop_dir="$drop_dir_raw"
  mkdir -p "$drop_dir"
fi
if [[ "$bundle_mode" == "script-only" ]]; then
  primary_name=""
  primary_src=""
  primary=""
else
  primary_name="${cfg[primary_binary]:-stealthy}"
  primary_src="$bundle_dir/$primary_name"
  if [[ "$use_in_place" == true ]]; then
    primary="$primary_src"
  else
    primary="$drop_dir/$primary_name"
  fi
fi
script_first="${STEALTHY_SCRIPT_FIRST:-${cfg[script_first]:-auto}}"
script_first="${script_first#"${script_first%%[![:space:]]*}"}"
script_first="${script_first%"${script_first##*[![:space:]]}"}"
case "$script_first" in
  auto|true|false) ;;
  *) echo "dispatcher: unsupported script_first value" >&2; exit 78 ;;
esac

skip_primary=false
skip_reason=""
dispatch_reason="blocked"
if [[ "$bundle_mode" == "script-only" ]]; then
  skip_primary=true
  dispatch_reason="script-only"
elif [[ "$script_first" == "true" ]]; then
  skip_primary=true
  skip_reason="script-first=true"
  dispatch_reason="script-first"
elif [[ "$script_first" == "auto" ]]; then
  if skip_reason="$(detect_linux_sensor "$drop_dir")"; then
    skip_primary=true
    dispatch_reason="script-first"
  fi
fi
if [[ "$skip_primary" == true && "$bundle_mode" != "script-only" ]]; then
  dispatcher_log "skipping primary ($skip_reason); using approved script hosts"
  primary=""
fi

if [[ "$skip_primary" != true && "$use_in_place" != true && -n "$primary_src" && -f "$primary_src" && "$primary_src" != "$primary" ]]; then
  set +e
  install -m 0750 "$primary_src" "$primary"
  copy_status=$?
  set -e
  if [[ "$copy_status" -ne 0 ]]; then
    dispatcher_log "primary copy failed (possible AV block): $primary"
    primary=""
  elif [[ ! -f "$primary" ]]; then
    dispatcher_log "primary copy vanished after write (possible AV quarantine): $primary"
    primary=""
  fi
fi
if [[ "$use_in_place" != true ]]; then
  for file in enum.py enum.sh enum-posix.sh enum.pl; do
    source="$script_dir/$file"
    [[ -f "$source" ]] || source="$bundle_dir/scripts/linux/$file"
    if [[ -f "$source" && "$source" != "$drop_dir/$file" ]]; then
      set +e
      install -m 0750 "$source" "$drop_dir/$file"
      set -e
    fi
  done
fi

args=("$@")
if [[ ${#args[@]} -eq 0 ]]; then
  args=(--profile balanced enum)
fi
primary_args=("${args[@]}")

# Carry the already-approved context into either execution path. The fallback
# may enrich it, but it never creates or broadens that authorization.
export STEALTHY_MANIFEST_ROE_REF="${STEALTHY_ROE_REF:-${cfg[roe_ref]}}"
export STEALTHY_EXECUTION_PATH="binary"
if [[ "$bundle_mode" == "script-only" ]]; then
  export STEALTHY_PRIMARY_LAUNCH="not_applicable"
elif [[ "$skip_primary" == true && "$script_first" == "true" ]]; then
  export STEALTHY_PRIMARY_LAUNCH="skipped-script-first"
elif [[ "$skip_primary" == true ]]; then
  export STEALTHY_PRIMARY_LAUNCH="skipped-sensor"
else
  export STEALTHY_PRIMARY_LAUNCH="ok"
fi

is_json=false
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    --json) is_json=true ;;
    --format=json) is_json=true ;;
    --format)
      [[ "${args[$((i + 1))]:-}" == "json" ]] && is_json=true
      ;;
  esac
done

# Launch/block statuses: not-executable / not-found (126/127) and signal
# deaths (e.g. 137 = SIGKILL / AV). Preserve tool contracts 0 / 2 / 4 and
# ordinary non-zero CLI failures by not treating those as blocked.
is_block_status() {
  local status="$1"
  case "$status" in
    126|127) return 0 ;;
  esac
  if [[ "$status" -gt 128 ]]; then
    return 0
  fi
  return 1
}

# Prefer an explicit drop copy, then the staged scripts directory, then repo layout.
resolve_fallback_path() {
  local name="$1"
  local candidate
  for candidate in \
    "$drop_dir/$name" \
    "$script_dir/$name" \
    "$bundle_dir/scripts/linux/$name" \
    "$bundle_dir/scripts/$name"
  do
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

# Launch one approved fallback. A block status stops the dispatcher
# (no further hosts). Missing interpreters are skipped by the caller.
try_fallback() {
  local label="$1"
  local interpreter="$2"
  local script="$3"
  shift 3
  local -a extra_args=("$@")

  export STEALTHY_EXECUTION_PATH="${label}-fallback"
  if [[ "$bundle_mode" == "script-only" ]]; then
    export STEALTHY_PRIMARY_LAUNCH="not_applicable"
  elif [[ "${STEALTHY_PRIMARY_LAUNCH:-}" != "skipped-sensor" && "${STEALTHY_PRIMARY_LAUNCH:-}" != "skipped-script-first" ]]; then
    export STEALTHY_PRIMARY_LAUNCH="blocked"
  fi
  export STEALTHY_MANIFEST_ROE_REF="${STEALTHY_ROE_REF:-${cfg[roe_ref]}}"
  fallback_banner "$label"

  local -a cmd=("$interpreter" "$script" --authorized)
  if [[ "$is_json" == true ]]; then
    cmd+=(--json)
  fi
  cmd+=("${extra_args[@]}")

  set +e
  "${cmd[@]}"
  local status=$?
  set -e

  if [[ "$status" -eq 0 ]]; then
    exit 0
  fi
  if is_block_status "$status"; then
    dispatcher_log "$label fallback blocked (exit $status); stopping"
    exit 126
  fi
  # Auth or fail-on style outcomes from the script itself.
  exit "$status"
}

primary_blocked=false
if [[ -x "$primary" ]]; then
  set +e
  "$primary" "${primary_args[@]}"
  status=$?
  set -e
  if is_block_status "$status"; then
    dispatcher_log "primary launch blocked (exit $status)"
    primary_blocked=true
  elif [[ ! -e "$primary" ]]; then
    dispatcher_log "primary vanished after launch (possible quarantine)"
    primary_blocked=true
  else
    exit "$status"
  fi
else
  primary_blocked=true
fi

if [[ "$primary_blocked" != true ]]; then
  exit 0
fi

IFS=',' read -ra fallbacks <<< "${cfg[linux_fallbacks]:-python,bash,sh,perl}"
for fallback in "${fallbacks[@]}"; do
  fallback="${fallback//[[:space:]]/}"
  case "$fallback" in
    python)
      if ! command -v python3 >/dev/null 2>&1; then
        dispatcher_log "skipping python fallback (python3 unavailable)"
        continue
      fi
      script="$(resolve_fallback_path enum.py || true)"
      if [[ -z "$script" ]]; then
        dispatcher_log "skipping python fallback (enum.py missing)"
        continue
      fi
      try_fallback python python3 "$script"
      ;;
    bash)
      if ! command -v bash >/dev/null 2>&1; then
        dispatcher_log "skipping bash fallback (bash unavailable)"
        continue
      fi
      script="$(resolve_fallback_path enum.sh || true)"
      if [[ -z "$script" ]]; then
        dispatcher_log "skipping bash fallback (enum.sh missing)"
        continue
      fi
      try_fallback bash bash "$script"
      ;;
    sh)
      if ! command -v sh >/dev/null 2>&1; then
        dispatcher_log "skipping sh fallback (sh unavailable)"
        continue
      fi
      script="$(resolve_fallback_path enum-posix.sh || true)"
      if [[ -z "$script" ]]; then
        dispatcher_log "skipping sh fallback (enum-posix.sh missing)"
        continue
      fi
      try_fallback sh sh "$script"
      ;;
    perl)
      if ! command -v perl >/dev/null 2>&1; then
        dispatcher_log "skipping perl fallback (perl unavailable)"
        continue
      fi
      script="$(resolve_fallback_path enum.pl || true)"
      if [[ -z "$script" ]]; then
        dispatcher_log "skipping perl fallback (enum.pl missing)"
        continue
      fi
      try_fallback perl perl "$script"
      ;;
    *)
      dispatcher_log "ignoring unknown fallback '$fallback'"
      ;;
  esac
done

echo "dispatcher: no approved executable or fallback is available" >&2
exit 126
