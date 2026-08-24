use anyhow::Result;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct SshKeysPlugin;

impl Plugin for SshKeysPlugin {
    fn id(&self) -> &'static str {
        "linux.ssh_keys"
    }
    fn name(&self) -> &'static str {
        "SSH key material"
    }
    fn description(&self) -> &'static str {
        "Find readable private keys and weak authorized_keys permissions (no key bytes printed)"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut roots: Vec<PathBuf> = Vec::new();
        if let Ok(home) = std::env::var("HOME") {
            roots.push(PathBuf::from(home).join(".ssh"));
        }
        roots.push(PathBuf::from("/root/.ssh"));
        // Shallow scan a few home dirs if readable
        if let Ok(rd) = fs::read_dir("/home") {
            for entry in rd.flatten().take(30) {
                if ctx.cancelled() {
                    break;
                }
                roots.push(entry.path().join(".ssh"));
            }
        }

        let key_names = [
            "id_rsa",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
            "id_xmss",
            "identity",
        ];

        for root in roots {
            if ctx.cancelled() {
                break;
            }
            if !root.is_dir() {
                continue;
            }
            for name in key_names {
                let p = root.join(name);
                check_private_key(&p, &mut findings);
            }
            let auth = root.join("authorized_keys");
            check_authorized_keys(&auth, &mut findings);
            let auth2 = root.join("authorized_keys2");
            check_authorized_keys(&auth2, &mut findings);
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No readable SSH private keys / weak authorized_keys found".into(),
                detail: "Scanned $HOME/.ssh, /root/.ssh, and /home/*/.ssh shallowly.".into(),
                recommendation: "Expand to application service accounts if in scope.".into(),
                noisy: false,
                leaves_artifacts: false,
                object: "ssh-key-search-roots".into(),
                condition: "no-readable-private-or-weak-authorized-keys".into(),
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn check_private_key(path: &Path, findings: &mut Vec<Finding>) {
    if !path.is_file() {
        return;
    }
    let Ok(meta) = fs::metadata(path) else {
        return;
    };
    let mode = meta.permissions().mode() & 0o777;
    // Readable by us?
    if fs::File::open(path).is_err() {
        return;
    }
    // Peek header only — never dump key material into findings or fully load the file.
    let mut header = [0u8; 64];
    let header_ok = fs::File::open(path)
        .ok()
        .and_then(|mut f| {
            use std::io::Read;
            let n = f.read(&mut header).ok()?;
            Some(header[..n].to_vec())
        })
        .map(|bytes| {
            let text = String::from_utf8_lossy(&bytes);
            text.contains("PRIVATE KEY") || text.starts_with("SSH ")
        })
        .unwrap_or(false);
    if !header_ok {
        return;
    }
    let weak = mode & 0o077 != 0;
    findings.push(Finding {
        plugin: "linux.ssh_keys".into(),
        kind: FindingKind::Credential,
        severity: if weak {
            Severity::High
        } else {
            Severity::Medium
        },
        title: format!("Readable SSH private key: {}", path.display()),
        detail: format!("mode={mode:o}; key bytes not displayed"),
        recommendation: "Useful for lateral movement under ROE. Do not exfiltrate beyond evidence rules."
            .into(),
        noisy: false,
        leaves_artifacts: false,
        object: path.display().to_string(),
        condition: if weak {
            "readable-private-key-weak-mode"
        } else {
            "readable-private-key"
        }
        .into(),
        ..Default::default()
    });
}

fn check_authorized_keys(path: &Path, findings: &mut Vec<Finding>) {
    if !path.is_file() {
        return;
    }
    let Ok(meta) = fs::metadata(path) else {
        return;
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        findings.push(Finding {
            plugin: "linux.ssh_keys".into(),
            kind: FindingKind::Misconfiguration,
            severity: Severity::High,
            title: format!("Writable authorized_keys: {}", path.display()),
            detail: format!("mode={mode:o}"),
            recommendation: "Group/world-writable authorized_keys enables SSH persistence/privesc if the account is valuable."
                .into(),
            noisy: false,
            leaves_artifacts: true,
            object: path.display().to_string(),
            condition: "authorized-keys-group-or-world-writable".into(),
            ..Default::default()
        });
    }
}
