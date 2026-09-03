#!/usr/bin/env bash
# StealthyPrivesc policy-bound dispatcher — authorized assessments only.
# This launcher may select an approved script fallback when the primary
# executable cannot start. It never disables or bypasses host controls.
#
# Fallback hosts are fixed enumerate-only reduced coverage. Only auth
# (via STEALTHY_AUTHORIZED) and --json / --format json are forwarded;
# binary flags such as --profile / --plugins are not applied to scripts.
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

drop_dir="${cfg[drop_dir]:-$bundle_dir/.run-cache}"
mkdir -p "$drop_dir"
if [[ "$bundle_mode" == "script-only" ]]; then
  primary_name=""
  primary_src=""
  primary=""
else
  primary_name="${cfg[primary_binary]:-stealthy}"
  primary_src="$bundle_dir/$primary_name"
  primary="$drop_dir/$primary_name"
fi
if [[ -n "$primary_src" && -f "$primary_src" && "$primary_src" != "$primary" ]]; then
  install -m 0750 "$primary_src" "$primary"
fi
for file in enum.py enum.sh enum-posix.sh enum.pl; do
  source="$script_dir/$file"
  [[ -f "$source" ]] || source="$bundle_dir/scripts/linux/$file"
  [[ -f "$source" ]] && install -m 0750 "$source" "$drop_dir/$file"
done

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

# Returns 0 if the fallback should be treated as blocked (try next host).
# Non-block script failures are terminal for that host attempt only when
# status is not a block code — caller decides whether to continue.
try_fallback() {
  local label="$1"
  local interpreter="$2"
  local script="$3"
  shift 3
  local -a extra_args=("$@")

  export STEALTHY_EXECUTION_PATH="${label}-fallback"
  if [[ "$bundle_mode" == "script-only" ]]; then
    export STEALTHY_PRIMARY_LAUNCH="not_applicable"
  else
    export STEALTHY_PRIMARY_LAUNCH="blocked"
  fi
  export STEALTHY_MANIFEST_ROE_REF="${STEALTHY_ROE_REF:-${cfg[roe_ref]}}"
  if [[ "$bundle_mode" == "script-only" ]]; then
    echo "dispatcher: script-only bundle; trying approved $label fallback" >&2
  else
    echo "dispatcher: primary executable blocked; trying approved $label fallback" >&2
  fi

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
    echo "dispatcher: $label fallback blocked (exit $status); trying next host" >&2
    return 0
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
    echo "dispatcher: primary launch blocked (exit $status)" >&2
    primary_blocked=true
  elif [[ ! -e "$primary" ]]; then
    echo "dispatcher: primary vanished after launch (possible quarantine)" >&2
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
        echo "dispatcher: skipping python fallback (python3 unavailable)" >&2
        continue
      fi
      if [[ ! -f "$drop_dir/enum.py" ]]; then
        echo "dispatcher: skipping python fallback (enum.py missing)" >&2
        continue
      fi
      try_fallback python python3 "$drop_dir/enum.py"
      ;;
    bash)
      if ! command -v bash >/dev/null 2>&1; then
        echo "dispatcher: skipping bash fallback (bash unavailable)" >&2
        continue
      fi
      if [[ ! -f "$drop_dir/enum.sh" ]]; then
        echo "dispatcher: skipping bash fallback (enum.sh missing)" >&2
        continue
      fi
      try_fallback bash bash "$drop_dir/enum.sh"
      ;;
    sh)
      if ! command -v sh >/dev/null 2>&1; then
        echo "dispatcher: skipping sh fallback (sh unavailable)" >&2
        continue
      fi
      if [[ ! -f "$drop_dir/enum-posix.sh" ]]; then
        echo "dispatcher: skipping sh fallback (enum-posix.sh missing)" >&2
        continue
      fi
      try_fallback sh sh "$drop_dir/enum-posix.sh"
      ;;
    perl)
      if ! command -v perl >/dev/null 2>&1; then
        echo "dispatcher: skipping perl fallback (perl unavailable)" >&2
        continue
      fi
      if [[ ! -f "$drop_dir/enum.pl" ]]; then
        echo "dispatcher: skipping perl fallback (enum.pl missing)" >&2
        continue
      fi
      try_fallback perl perl "$drop_dir/enum.pl"
      ;;
    *)
      echo "dispatcher: ignoring unknown fallback '$fallback'" >&2
      ;;
  esac
done

echo "dispatcher: no approved executable or fallback is available" >&2
exit 126
