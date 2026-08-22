use anyhow::Result;
use std::fs;
use std::path::Path;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct CredentialsPlugin;

impl Plugin for CredentialsPlugin {
    fn id(&self) -> &'static str {
        "linux.credentials"
    }
    fn name(&self) -> &'static str {
        "Readable shadow / backup credentials"
    }
    fn description(&self) -> &'static str {
        "Check readability of /etc/shadow and common credential backup files"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, _ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let candidates = [
            "/etc/shadow",
            "/etc/shadow-",
            "/etc/gshadow",
            "/etc/passwd.bak",
            "/etc/shadow.bak",
            "/var/backups/shadow.bak",
            "/var/backups/passwd.bak",
            "/etc/security/opasswd",
        ];

        for path in candidates {
            let p = Path::new(path);
            if !p.exists() {
                continue;
            }
            match fs::OpenOptions::new().read(true).open(p) {
                Ok(mut f) => {
                    use std::io::Read;
                    let mut buf = [0u8; 64];
                    let n = f.read(&mut buf).unwrap_or(0);
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Credential,
                        severity: if path.contains("shadow") {
                            Severity::Critical
                        } else {
                            Severity::High
                        },
                        title: format!("Readable credential-related file: {path}"),
                        detail: format!(
                            "Opened successfully; first bytes readable ({n} bytes sampled, not printed)."
                        ),
                        recommendation: "Readable shadow/backups often mean password-hash theft. Do not exfiltrate beyond ROE.".into(),
                        noisy: false,
                        leaves_artifacts: false,
                    });
                }
                Err(_) => {
                    // expected for /etc/shadow as non-root
                }
            }
        }

        // Home history / cloud creds — shallow, quiet.
        if let Ok(home) = std::env::var("HOME") {
            for rel in [
                ".aws/credentials",
                ".docker/config.json",
                ".netrc",
                ".git-credentials",
            ] {
                let p = Path::new(&home).join(rel);
                if p.is_file() {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Credential,
                        severity: Severity::Medium,
                        title: format!("Credential file in home: {}", p.display()),
                        detail: "File exists; contents not dumped by default.".into(),
                        recommendation: "Review for secrets useful for lateral movement under ROE."
                            .into(),
                        noisy: false,
                        leaves_artifacts: false,
                    });
                }
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No readable shadow/backup credential files".into(),
                detail: "Common paths were not readable to the current user.".into(),
                recommendation: "Continue with service config and sudo checks.".into(),
                noisy: false,
                leaves_artifacts: false,
            });
        }

        Ok(findings)
    }
}
