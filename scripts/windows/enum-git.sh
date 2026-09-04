#!/usr/bin/env bash
# StealthyPrivesc Git-bash host fallback — authorized assessments only.
# Reduced file/env inventory for Git for Windows. No registry, WMI, or PE.
set -eu

authorized=false
want_json=false
for arg in "$@"; do
  case "$arg" in
    --authorized|--i-understand-authorized-use-only) authorized=true ;;
    --json) want_json=true ;;
  esac
done
if [[ "${STEALTHY_AUTHORIZED:-}" == "1" ]]; then
  authorized=true
fi
if [[ "$authorized" != true ]]; then
  echo "Authorization required: pass --authorized or set STEALTHY_AUTHORIZED=1" >&2
  exit 2
fi

username="${USERNAME:-${USER:-}}"
hostname="${COMPUTERNAME:-}"
arch="${PROCESSOR_ARCHITECTURE:-}"
execution_path="${STEALTHY_EXECUTION_PATH:-script}"
primary_launch="${STEALTHY_PRIMARY_LAUNCH:-not_applicable}"
roe_ref="${STEALTHY_MANIFEST_ROE_REF:-}"
started="$(date +%s 2>/dev/null || echo 0)"
run_id="$(printf '%x' "$started" 2>/dev/null || echo gitfallback000000000000)"
run_id="${run_id:0:24}"

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  printf '"%s"' "$s"
}

findings=""
finding_count=0
for path in \
  /c/Windows/Panther/Unattend.xml \
  /c/Windows/Panther/unattend.xml \
  /c/Windows/System32/sysprep/unattend.xml \
  /c/Windows/System32/config/RegBack/SAM
do
  if [[ -f "$path" ]]; then
    win_path="${path#/c/}"
    win_path="C:/${win_path}"
    finding_count=$((finding_count + 1))
    findings="${findings}{\"plugin\":\"windows.credentials\",\"kind\":\"credential\",\"severity\":\"medium\",\"title\":\"Sensitive file present: ${win_path}\",\"detail\":\"Presence only; contents were not read.\",\"recommendation\":\"Inspect and restrict access; remove stale unattended-install or SAM backup material.\",\"noisy\":false,\"leaves_artifacts\":false,\"object\":\"${win_path}\",\"condition\":\"sensitive-file-present\"},"
  fi
done
findings="${findings%,}"

if [[ "$want_json" == true ]]; then
  cat <<EOF
{"schema_version":"2","run_id":"${run_id}","started_at_unix":${started},"tool":"stealthy-script","version":"0.1.0","authorized_use_ack":true,"mode":"enumerate-only","execution_path":$(json_escape "$execution_path"),"primary_launch":$(json_escape "$primary_launch"),"roe_ref":$(json_escape "$roe_ref"),"profile":"script","coverage_mode":"script","capability_delta":["windows.privileges","windows.services","windows.scheduled_tasks","windows.always_install_elevated","windows.uac","windows.dll_hijack","windows.credentials","windows.admin_sessions","windows.env_path","windows.autoruns","windows.endpoint_controls","windows.app_control"],"os":{"family":"windows","os":"windows","arch":$(json_escape "$arch"),"version_hint":""},"identity":{"username":$(json_escape "$username"),"uid":null,"gid":null,"groups":[],"is_elevated":false,"elevation_source":"git-bash-env","token_context":"","hostname":$(json_escape "$hostname")},"findings":[${findings}],"assessments":[],"attack_paths":[],"triage_decisions":[],"plugins_run":["windows.credentials"],"coverage":[{"id":"windows.credentials","status":"ok","findings":${finding_count},"error":null,"duration_ms":0},{"id":"windows.privileges","status":"skipped","findings":0,"error":"Git-bash fallback does not enumerate token privileges","duration_ms":0}],"notes":["Git-bash fallback is file/env inventory only.","Native plugin equivalence is not claimed."]}
EOF
  exit 0
fi

echo "=== StealthyPrivesc Windows Git-bash enum ==="
echo "LEGAL: Authorized use only. Reduced, read-only fallback coverage."
echo "user=${username} host=${hostname} arch=${arch}"
if [[ "$finding_count" -eq 0 ]]; then
  echo "No credential-file presence findings."
else
  echo "FINDING count=${finding_count} (sensitive file presence only)"
fi
echo "Done. Enumeration only; native equivalence is not claimed."
