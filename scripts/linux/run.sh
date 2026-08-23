#!/usr/bin/env bash
# StealthyPrivesc policy-bound dispatcher — authorized assessments only.
# This launcher may select an approved script fallback when the primary
# executable cannot start. It never disables or bypasses host controls.
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

actual_host="$(cat /etc/hostname 2>/dev/null || hostname 2>/dev/null || true)"
expected_host="${cfg[target_hostname]}"
if [[ "$expected_host" != "AUTO" && "$actual_host" != "$expected_host" ]]; then
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
primary_name="${cfg[primary_binary]:-stealthy}"
primary_src="$bundle_dir/$primary_name"
primary="$drop_dir/$primary_name"
if [[ -f "$primary_src" && "$primary_src" != "$primary" ]]; then
  install -m 0750 "$primary_src" "$primary"
fi
for file in enum.py enum.sh; do
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
export STEALTHY_PRIMARY_LAUNCH="ok"

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

run_fallback() {
  local interpreter="$1"
  local script="$2"
  export STEALTHY_EXECUTION_PATH="$interpreter-fallback"
  export STEALTHY_PRIMARY_LAUNCH="blocked"
  export STEALTHY_MANIFEST_ROE_REF="${STEALTHY_ROE_REF:-${cfg[roe_ref]}}"
  echo "dispatcher: primary executable blocked; using approved $interpreter fallback" >&2
  if [[ "$is_json" == true ]]; then
    "$interpreter" "$script" --json
  else
    "$interpreter" "$script"
  fi
}

primary_blocked=false
if [[ -x "$primary" ]]; then
  set +e
  "$primary" "${primary_args[@]}"
  status=$?
  set -e
  case "$status" in
    126|127) primary_blocked=true ;;
    *) exit "$status" ;;
  esac
else
  primary_blocked=true
fi

if [[ "$primary_blocked" == true ]]; then
  IFS=',' read -ra fallbacks <<< "${cfg[linux_fallbacks]:-python,bash}"
  for fallback in "${fallbacks[@]}"; do
    case "$fallback" in
      python)
        if command -v python3 >/dev/null 2>&1 && [[ -f "$drop_dir/enum.py" ]]; then
          run_fallback python3 "$drop_dir/enum.py"
          exit $?
        fi ;;
      bash)
        if command -v bash >/dev/null 2>&1 && [[ -f "$drop_dir/enum.sh" ]]; then
          run_fallback bash "$drop_dir/enum.sh"
          exit $?
        fi ;;
      *) echo "dispatcher: ignoring unknown fallback '$fallback'" >&2 ;;
    esac
  done
  echo "dispatcher: no approved executable or fallback is available" >&2
  exit 126
fi
