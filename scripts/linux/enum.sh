#!/usr/bin/env bash
# StealthyPrivesc Linux bash fallback — authorized assessments only.
set -euo pipefail

authorized=false
json=false
for arg in "$@"; do
  case "$arg" in
    --authorized|--i-understand-authorized-use-only) authorized=true ;;
    --json) json=true ;;
  esac
done
[[ "${STEALTHY_AUTHORIZED:-}" == "1" ]] && authorized=true
if [[ "$authorized" != true ]]; then
  echo "Authorization required: pass --authorized or set STEALTHY_AUTHORIZED=1" >&2
  exit 2
fi

if [[ "$json" == true ]]; then
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if command -v python3 >/dev/null 2>&1 && [[ -f "$here/enum.py" ]]; then
    exec python3 "$here/enum.py" --authorized --json
  fi
  echo '{"schema_version":"2","tool":"stealthy-script","coverage_mode":"script","notes":["bash --json requires python3 enum.py"],"findings":[],"os":{"family":"unix","os":"linux","arch":"unknown","version_hint":"linux"},"identity":{"username":"'"${USER:-unknown}"'","uid":null,"gid":null,"groups":[],"is_elevated":false,"elevation_source":"","token_context":"","hostname":"'"$(hostname 2>/dev/null || echo unknown)"'"},"plugins_run":[],"coverage":[],"assessments":[],"attack_paths":[],"triage_decisions":[],"capability_delta":[],"mode":"enumerate-only","profile":"script","authorized_use_ack":true,"version":"0.1.0","run_id":"bash-json","started_at_unix":0}' 
  exit 0
fi

set -euo pipefail

echo "=== StealthyPrivesc Linux shell enum ==="
echo "LEGAL: Authorized use only."
echo

echo "[*] identity"
echo "uid=$(id -u 2>/dev/null || cat /proc/self/status | awk '/^Uid:/{print $2}')"
echo "user=${USER:-unknown}"
echo "hostname=$(cat /etc/hostname 2>/dev/null || echo unknown)"
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
  # find is noisier than a pure shell walk but acceptable in script fallback
  find "$d" -maxdepth 1 -perm -4000 -type f 2>/dev/null | head -n 50 || true
done
echo

echo "[*] interesting groups"
if [ -r /proc/self/status ] && [ -r /etc/group ]; then
  # shellcheck disable=SC2013
  for g in docker lxd disk podman sudo wheel shadow; do
    gid=$(awk -F: -v n="$g" '$1==n{print $3; exit}' /etc/group || true)
    [ -n "${gid:-}" ] || continue
    if grep -E "^Groups:.*\b${gid}\b" /proc/self/status >/dev/null 2>&1; then
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

echo "[*] polkit paths"
for p in /etc/polkit-1/rules.d /etc/polkit-1/localauthority; do
  [ -e "$p" ] || continue
  if [ -w "$p" ]; then
    echo "FINDING: writable polkit path $p"
  fi
done
[ -e /usr/bin/pkexec ] && ls -l /usr/bin/pkexec || true
echo

echo "[*] writable cron/systemd/timer hints"
for p in /etc/crontab /etc/cron.d /etc/systemd/system; do
  [ -e "$p" ] || continue
  if [ -w "$p" ]; then
    echo "FINDING: writable $p"
  fi
done
find /etc/systemd/system -maxdepth 1 -name '*.timer' 2>/dev/null | head -n 20 || true
echo

echo "[*] passwd writability / mounts hint"
if [ -w /etc/passwd ]; then
  echo "FINDING: /etc/passwd writable"
fi
head -n 5 /proc/self/mountinfo 2>/dev/null || true
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
if [ -r /proc/sys/kernel/yama/ptrace_scope ]; then
  echo "yama.ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope)"
fi
echo "NOTE: if custom ELF is blocked, prefer this script or enum.py (approved fallback)."
echo

echo "[*] ssh keys (modes only)"
for d in "${HOME:-/nonexistent}/.ssh" /root/.ssh; do
  [ -d "$d" ] || continue
  ls -la "$d" 2>/dev/null | head -n 30 || true
  for k in id_rsa id_ed25519 id_ecdsa; do
    [ -r "$d/$k" ] && echo "FINDING: readable private key $d/$k"
  done
done
echo

echo "[*] kernel"
head -n 1 /proc/version 2>/dev/null || true
echo

echo "[*] shadow readability"
if [ -r /etc/shadow ]; then
  echo "FINDING: /etc/shadow readable"
else
  echo "/etc/shadow not readable (expected)"
fi

echo
echo "Done. Review findings manually — this script never auto-exploits."
