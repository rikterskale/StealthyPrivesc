#!/bin/sh
# StealthyPrivesc Linux POSIX sh fallback — authorized assessments only.
# Reduced coverage vs bash/python tiers. No bashisms; suitable for ash/dash.
# shellcheck shell=sh

authorized=false
json=false
for arg in "$@"; do
  case "$arg" in
    --authorized|--i-understand-authorized-use-only) authorized=true ;;
    --json) json=true ;;
  esac
done
if [ "${STEALTHY_AUTHORIZED:-}" = "1" ]; then
  authorized=true
fi
if [ "$authorized" != true ]; then
  echo "Authorization required: pass --authorized or set STEALTHY_AUTHORIZED=1" >&2
  exit 2
fi

hostname_val=$( (cat /etc/hostname 2>/dev/null || hostname 2>/dev/null) | head -n 1 )
hostname_val=${hostname_val:-unknown}
user_val=${USER:-unknown}

json_escape() {
  printf '%s' "$1" | awk 'BEGIN { ORS=""; first=1 }
    { if (!first) printf "\\n"; first=0;
      gsub(/\\/, "\\\\"); gsub(/"/, "\\\"");
      gsub(/\r/, "\\r"); gsub(/\t/, "\\t"); printf "%s", $0 }'
}

if [ "$json" = true ]; then
  exec_path=$(json_escape "${STEALTHY_EXECUTION_PATH:-sh-fallback}")
  primary_launch=$(json_escape "${STEALTHY_PRIMARY_LAUNCH:-not_applicable}")
  roe_ref=$(json_escape "${STEALTHY_MANIFEST_ROE_REF:-}")
  user_json=$(json_escape "$user_val")
  hostname_json=$(json_escape "$hostname_val")
  printf '%s' "{\"schema_version\":\"2\",\"tool\":\"stealthy-script\",\"coverage_mode\":\"script\",\"execution_path\":\"${exec_path}\",\"primary_launch\":\"${primary_launch}\",\"roe_ref\":\"${roe_ref}\",\"notes\":[\"posix sh fallback — reduced coverage\"],\"findings\":[],\"os\":{\"family\":\"unix\",\"os\":\"linux\",\"arch\":\"unknown\",\"version_hint\":\"linux\"},\"identity\":{\"username\":\"${user_json}\",\"uid\":null,\"gid\":null,\"groups\":[],\"is_elevated\":false,\"elevation_source\":\"posix-sh\",\"token_context\":\"\",\"hostname\":\"${hostname_json}\"},\"plugins_run\":[],\"coverage\":[],\"assessments\":[],\"attack_paths\":[],\"triage_decisions\":[],\"capability_delta\":[\"linux.app_control\",\"linux.systemd_cron\",\"linux.nfs\",\"linux.path_ld\",\"linux.services\",\"linux.wildcard_cron\"],\"mode\":\"enumerate-only\",\"profile\":\"script\",\"authorized_use_ack\":true,\"version\":\"0.1.0\",\"run_id\":\"posix-sh\",\"started_at_unix\":0}"
  echo
  exit 0
fi

echo "=== StealthyPrivesc Linux POSIX sh enum ==="
echo "LEGAL: Authorized use only."
echo

echo "[*] identity"
echo "uid=$(id -u 2>/dev/null || awk '/^Uid:/{print $2}' /proc/self/status 2>/dev/null)"
echo "user=${user_val}"
echo "hostname=${hostname_val}"
echo

echo "[*] sudoers readable fragments (no sudo -l by default)"
for f in /etc/sudoers /etc/sudoers.d/*; do
  [ -r "$f" ] || continue
  grep -E 'NOPASSWD|ALL=\(ALL' "$f" 2>/dev/null | sed "s|^|$f: |" || true
done
echo

echo "[*] interesting SUID (shallow)"
for d in /usr/bin /usr/sbin /bin /sbin; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 1 -perm -4000 -type f 2>/dev/null | head -n 50 || true
done
echo

echo "[*] interesting groups"
if [ -r /proc/self/status ] && [ -r /etc/group ]; then
  for g in docker lxd disk podman sudo wheel shadow; do
    gid=$(awk -F: -v n="$g" '$1==n{print $3; exit}' /etc/group 2>/dev/null || true)
    [ -n "${gid:-}" ] || continue
    if grep -E "^Groups:.*[[:space:]]${gid}([[:space:]]|$)" /proc/self/status >/dev/null 2>&1; then
      echo "FINDING: member of group $g"
    fi
  done
fi
echo

echo "[*] container sockets"
for s in /var/run/docker.sock /run/docker.sock \
         /var/run/podman/podman.sock /run/podman/podman.sock \
         /var/run/containerd/containerd.sock \
         /var/lib/lxd/unix.socket /var/snap/lxd/common/lxd/unix.socket; do
  [ -S "$s" ] || continue
  ls -l "$s" || true
  if [ -w "$s" ]; then
    echo "FINDING: container socket writable: $s"
  fi
done
echo

echo "[*] writable cron/systemd hints"
for p in /etc/crontab /etc/cron.d /etc/systemd/system; do
  [ -e "$p" ] || continue
  if [ -w "$p" ]; then
    echo "FINDING: writable $p"
  fi
done
echo

echo "[*] endpoint controls (AppArmor / SELinux / noexec)"
if [ -d /sys/module/apparmor ] || [ -d /sys/kernel/security/apparmor ]; then
  cur=$(cat /proc/self/attr/current 2>/dev/null || cat /proc/self/attr/apparmor/current 2>/dev/null || echo unreadable)
  echo "AppArmor current=${cur}"
  case "$cur" in
    *'(enforce)'*) echo "FINDING: AppArmor enforce profile active for this process" ;;
  esac
else
  echo "AppArmor module not evident"
fi
if [ -r /sys/fs/selinux/enforce ]; then
  echo "SELinux enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null)"
fi
if [ -r /proc/self/mountinfo ]; then
  for mp in /tmp /var/tmp /dev/shm "${HOME:-/nonexistent}"; do
    [ -n "$mp" ] || continue
    line=$(awk -v mp="$mp" '$5==mp {print; exit}' /proc/self/mountinfo 2>/dev/null || true)
    [ -n "$line" ] || continue
    case ",$line," in
      *,noexec,*) echo "FINDING: noexec mount on drop path $mp" ;;
    esac
  done
fi
echo "NOTE: if custom ELF is blocked, prefer enum.py / enum.sh / enum-posix.sh / enum.pl."
echo

echo "[*] shadow readability"
if [ -r /etc/shadow ]; then
  echo "FINDING: /etc/shadow readable"
else
  echo "/etc/shadow not readable (expected)"
fi

echo
echo "Done. Review findings manually — this script never auto-exploits."
