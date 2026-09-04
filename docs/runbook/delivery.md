# Get the kit onto a host

Operator-facing catalog for putting StealthyPrivesc on an **authorized** Linux
or Windows target. This page is the method chooser and copy-paste start.
The [full operator runbook](../operator-runbook.md) remains the detailed
recipe book for every transport variant.

Related: [Pre-flight](preflight.md) · [Build and package](build-and-package.md) ·
[Target operations](targets.md) · [CLI `stage` / `one-liners`](../cli-reference.md#stage--verify--one-liners)

## Two-machine model

| Machine | What happens here |
| --- | --- |
| Operator / build workstation | Install or build the tool, hash it, `stage` a drop bundle, copy the bundle |
| Target host | Receive the bundle over an already-approved channel, verify the hash, run `doctor`, then enumerate |

Do **not** treat the target as an install host. The published installers
(`scripts/install.sh`, `scripts/install.ps1`) are for the operator workstation
only. Running them on a target hits GitHub, writes a well-known path
(`$HOME/.local/bin/stealthy` or `%LOCALAPPDATA%\StealthyPrivesc\stealthy.exe`),
and is not an approved assessment drop.

`stealthy one-liners --os <linux\|windows> --transport <ssh\|scp\|http\|smb\|winrm>`
prints short placeholders. Replace host, path, and profile with the values from
the [pre-flight worksheet](preflight.md). The snippets are not authorization
and they do not create the bundle; run `stage` first.

## Do this on the operator box first

1. Complete [pre-flight](preflight.md) (ROE, hostname, account, transport, drop
   path, cleanup owner).
2. Obtain one reviewed artifact ([installation](../installation.md) or
   [build](build-and-package.md)). Record SHA-256, target triple, and revision.
3. Stage a drop bundle (next section). The staged directory is the unit you
   copy, not a lone binary.
4. Copy that directory with one method from the catalogs below.
5. Verify the remote hash, then follow [after the kit is on the host](#after-the-kit-is-on-the-host).

## Stage the drop bundle

`stage` does not require `--authorized`. It writes the binary (optional),
platform fallbacks, `scripts/run.sh` or `scripts/run.ps1`,
`scripts/stealthy-run.conf`, `SHA256SUMS`, and `OPERATOR.txt`.

The dispatcher binds `--target-hostname` to the target (`hostname` /
`/etc/hostname` on Linux, `%COMPUTERNAME%` on Windows). Use the real hostname
from pre-flight. `AUTO`, `REQUIRED`, and `SET_TARGET_HOSTNAME` are rejected.
Optional `--target-username` binds the run to that account.

Default `--name` is `cache-update`. Change it when ROE wants a bland basename.
Do not impersonate inbox Windows binaries.

### Native kit (binary plus fallbacks)

```bash
# Linux x86_64
./target/release/stealthy stage \
  --os linux --arch x86_64 \
  --target-hostname TARGET_HOSTNAME \
  --name cache-update \
  --out ./drop-linux \
  --binary ./target/release/stealthy

# Windows x64 (GNU cross-build from Linux)
./target/release/stealthy stage \
  --os windows --arch x86_64 \
  --target-hostname TARGET_HOSTNAME \
  --name cache-update \
  --out ./drop-windows \
  --binary ./target/x86_64-pc-windows-gnu/release/stealthy.exe
```

On a Windows operator box, `--binary` is `.\target\release\stealthy.exe` after
an MSVC release build.

Org Authenticode-sign the Windows PE **before** `--binary` if SmartScreen or
publisher policy is in play. This tool does not create certificates. Confirm
with `Get-AuthenticodeSignature` on the operator box (`Status` should be
`Valid`).

Record the digest from `./drop-linux/SHA256SUMS` or `./drop-windows/SHA256SUMS`.

### Script-only kit (no PE/ELF on disk)

Omit `--binary` when the custom executable is expected to be blocked
(`noexec`, WDAC/AppLocker, Defender quarantine of unsigned PEs):

```bash
./target/release/stealthy stage \
  --os linux --target-hostname TARGET_HOSTNAME --out ./drop-linux

./target/release/stealthy stage \
  --os windows --target-hostname TARGET_HOSTNAME --out ./drop-windows
```

That sets `bundle_mode=script-only`: no file is written under the primary
binary name, and `SHA256SUMS` lists the staged scripts. The dispatcher still
requires a fresh `--authorized` (or `STEALTHY_AUTHORIZED=1`) on the target.

### Verify the staged files locally

```bash
# Native kit
./target/release/stealthy verify \
  --path ./drop-linux/cache-update \
  --expect-sha256 "$(awk 'NR==1 {print $1}' ./drop-linux/SHA256SUMS)"

# Script-only: compare every path in SHA256SUMS before copy
```

## Choose a drop path

Always use the path named in the ROE. If the mount is `noexec` or the PE will
be scanned in `%TEMP%`, do not force a binary; use a script-only bundle.

| Platform | Prefer | Avoid |
| --- | --- | --- |
| Linux | `$HOME/.cache/<name>` or an already-approved tool directory | `/tmp` (often `noexec`, cleaned, monitored); world-writable dirs |
| Linux tmpfs | `/dev/shm/<name>` only when ROE allows (lost on reboot, often watched) | |
| Windows | `C:\Users\Public\Documents\<name>` or `%LOCALAPPDATA%\<name>` | `%TEMP%` / Downloads (Defender often quarantines a freshly written unsigned PE) |
| Windows admin share | `\\HOST\C$\Users\Public\Documents\<name>` | Dropping under `C:\Windows` or `ADMIN$` unless ROE requires it |

Staged manifests ship `drop_dir=` empty. Both `run.sh` and `run.ps1` then run
the primary **in place** (no copy into `.run-cache` or a second scan path).
Set `drop_dir` to an explicit directory only when the dispatcher should copy
the binary and fallback scripts there.

## Linux method catalog

Copy the **staged directory** (`drop-linux/.`) unless the method is
script-stdin-only. Full recipes: [runbook section 2](../operator-runbook.md#2-deploy-to-a-linux-target).

| Situation | Method | Runbook | Notes |
| --- | --- | --- | --- |
| Normal SSH file copy | SCP of staged bundle (preferred) | [2.1](../operator-runbook.md#21-scp-single-binary) | Use `scp -r ./drop-linux/.`; chmod 750 |
| Resume / retry-friendly | rsync over SSH | [2.2](../operator-runbook.md#22-rsync-over-ssh-resume-friendly) | Same for a full bundle |
| SCP unavailable, SSH works | SFTP batch | [2.3](../operator-runbook.md#23-sftp-batch) | `put` each staged file or a tarball |
| Bastion / jump host | SCP via ProxyJump | [2.4](../operator-runbook.md#24-scp--ssh-via-proxyjump-bastion) | `~/.ssh/config` `ProxyJump` |
| No SCP binary on PATH | SSH stdin pipe | [2.5](../operator-runbook.md#25-ssh-stdin-pipe-no-scp-binary-required-on-path) | `cat > file` of ELF or a tar stream |
| Target can pull HTTP(S) | Operator HTTP + curl/wget/python | [2.6](../operator-runbook.md#26-https-pull-on-target) | Bind the listener to the approved VPN address only |
| SSH file copy broken, raw TCP allowed | netcat / socat | [2.7](../operator-runbook.md#27-netcat--socat-raw-push) | Noisy / short-lived; ROE must allow the listener |
| Shared NFS/SMB/SSHFS | Mount copy | [2.8](../operator-runbook.md#28-shared-mount-nfs--smb--sshfs) | Copy then chmod on the target |
| Container / Kubernetes access | `docker cp` / `kubectl cp` | [2.9](../operator-runbook.md#29-container--kubernetes-adjacent-copy) | Confirm the container is in scope |
| Interactive / ticket / tiny channel | Base64 paste or split | [2.10](../operator-runbook.md#210-base64-paste--split-files-constrained-channels) | Prefer scripts over a multi-MB ELF |
| Many hosts or a release kit | Tarball / host loop | [2.11](../operator-runbook.md#211-scp-full-tarball--ansible-style-loop) | Still hash each host |
| ELF blocked, `noexec`, AppArmor | Script-only deploy | [2.12](../operator-runbook.md#212-script-only-deploy-no-custom-elf) | Dispatcher or stdin-fed `python3`/`bash`/`sh`/`perl` |
| After any binary drop | Verify hash and `--help` | [2.13](../operator-runbook.md#213-post-deploy-verify-linux) | Failed exec → 2.12; do not retry a quarantined hash |

Print a placeholder:

```bash
./target/release/stealthy one-liners --os linux --transport ssh
./target/release/stealthy one-liners --os linux --transport scp
./target/release/stealthy one-liners --os linux --transport http
./target/release/stealthy one-liners --os linux --transport smb
```

## Windows method catalog

Keep the PE out of `%TEMP%`. Full recipes: [runbook section 4](../operator-runbook.md#4-deploy-to-a-windows-target).

| Situation | Method | Runbook | Notes |
| --- | --- | --- | --- |
| Windows OpenSSH available | SCP of staged bundle (preferred from Linux) | [4.1](../operator-runbook.md#41-scp--openssh-on-windows) | Also zip + `Expand-Archive` |
| Domain workstation + admin share | SMB `Copy-Item` / `net use` / `smbclient` | [4.2](../operator-runbook.md#42-smb-admin-share--mapped-drive) | Admin share is loud; user share if it exists |
| WinRM enabled | `New-PSSession` + `Copy-Item -ToSession` | [4.3](../operator-runbook.md#43-winrm--powershell-remoting) | Prefer session copy of the whole bundle, not `C$` |
| Target can pull HTTP(S) | `Invoke-WebRequest` / `curl.exe` / BITS | [4.4](../operator-runbook.md#44-https--bits--curl-pull-on-target) | Avoid `certutil -urlcache` (common alert) |
| Interactive RDP | Drive redirect / `\\tsclient` / clipboard | [4.5](../operator-runbook.md#45-rdp-clipboard-drive-redirect-and-tsclient) | Clipboard is better for scripts than large PEs |
| Remote service create required | PsExec / PAExec (high noise) | [4.6](../operator-runbook.md#46-psexec-style-remote-create) | Stage via SMB first; execute only; ROE must allow service creation |
| Linux operator, Windows target | Impacket / Evil-WinRM | [4.7](../operator-runbook.md#47-linux-operator-windows-tooling-impacket--evil-winrm) | `smbclient.py`, `evil-winrm upload`; `psexec.py` is 4.6.4 |
| Text-only channel | Base64 / certutil / `FromBase64String` | [4.8](../operator-runbook.md#48-base64--certutil--powershell-decode) | Prefer scripts; `certutil -decode` is watched |
| Existing FTP/WebDAV | `curl.exe` / mapped WebDAV | [4.9](../operator-runbook.md#49-ftp--webdav-only-if-already-approved-infrastructure) | Only if that infrastructure is already in ROE |
| PE blocked (AppLocker/WDAC/AV) | Script-only deploy | [4.10](../operator-runbook.md#410-script-only-deploy-custom-exe-blocked) | Dispatcher `run.ps1` (`python → pwsh → powershell → git → jscript → msbuild`) |
| After any PE drop | `Get-FileHash` + `--help` | [4.11](../operator-runbook.md#411-post-deploy-verify-windows) | If the PE vanished, do not retry that hash; use 4.10 |

Print a placeholder:

```bash
./target/release/stealthy one-liners --os windows --transport ssh
./target/release/stealthy one-liners --os windows --transport scp
./target/release/stealthy one-liners --os windows --transport winrm
./target/release/stealthy one-liners --os windows --transport smb
./target/release/stealthy one-liners --os windows --transport http
```

## Preferred copy-paste (staged bundle)

Replace `TARGET`, hostnames, and drop paths with pre-flight values. After copy,
always [verify](#after-the-kit-is-on-the-host) before `--authorized enum`.

### Linux — SSH / SCP (default when you have a shell)

```bash
TARGET='user@10.0.0.20'
REMOTE='$HOME/.cache/cache-update'

ssh "$TARGET" "mkdir -p $REMOTE"
scp -r ./drop-linux/. "$TARGET:$REMOTE/"
ssh "$TARGET" "chmod 750 $REMOTE/cache-update $REMOTE/scripts/* 2>/dev/null || true"
ssh "$TARGET" "sha256sum $REMOTE/cache-update"
# compare to ./drop-linux/SHA256SUMS
```

rsync equivalent:

```bash
rsync -a ./drop-linux/ "$TARGET:$REMOTE/"
```

Tarball over SSH stdin when `scp` is missing:

```bash
tar -C ./drop-linux -czf - . | ssh "$TARGET" "mkdir -p $REMOTE && tar -C $REMOTE -xzf -"
```

### Windows — OpenSSH / SCP (from a Linux operator box)

```bash
TARGET='user@10.0.0.30'
REMOTE='C:/Users/Public/Documents/cache-update'
REMOTE_WIN='C:\Users\Public\Documents\cache-update'

ssh "$TARGET" "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '$REMOTE_WIN' | Out-Null\""
scp -r ./drop-windows/. "$TARGET:$REMOTE/"
ssh "$TARGET" "powershell -NoProfile -Command \"Get-FileHash '$REMOTE_WIN\\cache-update.exe' -Algorithm SHA256\""
```

### Windows — WinRM session copy (from a Windows operator box)

This is the WinRM path that does **not** require `C$`. Enable only if WinRM is
already in the ROE.

```powershell
$RemoteDir = 'C:\Users\Public\Documents\cache-update'
$s = New-PSSession -ComputerName TARGET -Credential (Get-Credential)
Invoke-Command -Session $s -ScriptBlock {
  param($Dir)
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
} -ArgumentList $RemoteDir
Copy-Item -ToSession $s -Path .\drop-windows\* -Destination $RemoteDir -Recurse -Force
Invoke-Command -Session $s -ScriptBlock {
  param($Dir)
  Get-FileHash (Join-Path $Dir 'cache-update.exe') -Algorithm SHA256
} -ArgumentList $RemoteDir
Remove-PSSession $s
```

### Windows — SMB admin share (noisy; needs admin)

```powershell
$Dir = '\\TARGET\C$\Users\Public\Documents\cache-update'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Copy-Item .\drop-windows\* $Dir -Recurse -Force
Get-FileHash "$Dir\cache-update.exe" -Algorithm SHA256
```

From Linux:

```bash
smbclient '//TARGET/C$' -U 'DOMAIN/user' -c \
  'mkdir Users\Public\Documents\cache-update; recurse ON; prompt OFF; cd Users\Public\Documents\cache-update; lcd drop-windows; mput *'
```

### HTTP(S) pull (both platforms)

Host the staged directory or a tarball/zip on an operator listener bound to the
approved address only ([Linux 2.6](../operator-runbook.md#26-https-pull-on-target),
[Windows 4.4](../operator-runbook.md#44-https--bits--curl-pull-on-target)).
Do not point the target at GitHub.

### Script-only (binary will not run)

Linux — copy the staged script-only bundle, or push scripts over stdin:

```bash
scp -r ./drop-linux/. "$TARGET:$REMOTE/"
ssh "$TARGET" "bash $REMOTE/scripts/run.sh --authorized enum"

# No disk scripts (last resort; command line still shows the interpreter)
ssh "$TARGET" 'STEALTHY_AUTHORIZED=1 python3 -' < ./drop-linux/scripts/enum.py
ssh "$TARGET" 'STEALTHY_AUTHORIZED=1 bash -s' < ./drop-linux/scripts/enum.sh
```

Windows:

```powershell
# After the script-only bundle is in $Dir:
& (Join-Path $Dir 'scripts\run.ps1') --authorized enum

# Direct hosts (troubleshooting)
powershell -NoProfile -File (Join-Path $Dir 'scripts\enum.ps1') -Authorized
cscript //nologo (Join-Path $Dir 'scripts\enum.js') --authorized
```

WinRM can run `enum.ps1` without a prior file drop:

```powershell
$s = New-PSSession -ComputerName TARGET -Credential (Get-Credential)
Invoke-Command -Session $s -FilePath .\scripts\windows\enum.ps1 -ArgumentList '-Authorized'
Remove-PSSession $s
```

## After the kit is on the host

Do not run `--auto-exploit` or `--allow-techniques` on the first drop.

| Step | Linux | Windows |
| --- | --- | --- |
| Integrity | `sha256sum` vs `SHA256SUMS` | `Get-FileHash -Algorithm SHA256` |
| Local health (no auth) | `./cache-update doctor` | `& $Bin doctor` |
| Plugins | `--authorized list-plugins` | same |
| First enum | `--authorized --profile quiet enum` | same |
| Binary blocked | `bash ./scripts/run.sh --authorized enum` | `.\scripts\run.ps1 --authorized enum` |

Linux:

```bash
cd "$HOME/.cache/cache-update"
sha256sum cache-update
./cache-update doctor
./cache-update --authorized list-plugins
./cache-update --authorized --profile quiet enum
```

If the ELF cannot start (`Permission denied`, `noexec`, exit 126/127/137), do
not retry that image. Use the dispatcher once:

```bash
bash ./scripts/run.sh --authorized enum
```

Windows:

```powershell
$Dir = 'C:\Users\Public\Documents\cache-update'
$Bin = Join-Path $Dir 'cache-update.exe'
Get-FileHash $Bin -Algorithm SHA256
& $Bin doctor
& $Bin --authorized list-plugins
& $Bin --authorized --profile quiet enum
```

If the PE is missing, quarantined, or blocked, do not copy it again. Run:

```powershell
& (Join-Path $Dir 'scripts\run.ps1') --authorized enum
```

Then continue with [target operations](targets.md) (coverage review, focused
plugins, evidence). Execution detail:
[Linux run](../operator-runbook.md#3-run-on-a-linux-target),
[Windows run](../operator-runbook.md#5-run-on-a-windows-target).

## Practical defaults

| Goal | Linux | Windows |
| --- | --- | --- |
| Normal SSH / WinRM / OpenSSH | Stage native kit, copy the folder, run the binary | Same; non-`TEMP` path; org-signed PE when required |
| Expect AV / WDAC / `noexec` | Script-only `stage`, copy `scripts/`, run `run.sh` | Script-only `stage`, run `run.ps1` or `enum.ps1` |
| No file copy, shell only | stdin-fed `python3` / `bash` / `sh` / `perl` | WinRM `-FilePath enum.ps1`, or a pasted `.ps1` |
| Many hosts | Tarball or rsync loop (2.11); hash per host | WinRM session loop or SMB copy; hash per host |

The authorization flag is an acknowledgment, not written permission. If a
method here conflicts with the ROE, stop and follow the ROE. Do not substitute
a noisier transport (netcat, PsExec, admin share) because it is faster.
