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

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
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
            if ctx.cancelled() {
                break;
            }
            let p = Path::new(path);
            if !p.exists() {
                continue;
            }
            match sample_readable_credential(p) {
                Some((n, severity)) => {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Credential,
                        severity,
                        title: format!("Readable credential-related file: {path}"),
                        detail: format!(
                            "Opened successfully; first bytes readable ({n} bytes sampled, not printed)."
                        ),
                        recommendation: "Readable shadow/backups often mean password-hash theft. Do not exfiltrate beyond ROE.".into(),
                        noisy: false,
                        leaves_artifacts: false,
                        object: path.into(),
                        condition: "credential-file-readable".into(),
                        mitre_techniques: vec!["T1003.008".into()],
                        technique_id: "readable-credential-file".into(),
                        ..Default::default()
                    });
                }
                None => {
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
                if ctx.cancelled() {
                    break;
                }
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
                        object: p.display().to_string(),
                        condition: "home-credential-file-present".into(),
                        technique_id: "credential-file".into(),
                        ..Default::default()
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
                object: "common-linux-credential-paths".into(),
                condition: "no-readable-credential-files".into(),
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn sample_readable_credential(path: &Path) -> Option<(usize, Severity)> {
    use std::io::Read;

    let mut file = fs::OpenOptions::new().read(true).open(path).ok()?;
    let mut sample = [0u8; 64];
    let bytes_read = file.read(&mut sample).ok()?;
    Some((bytes_read, credential_severity(path)))
}

fn credential_severity(path: &Path) -> Severity {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if name.starts_with("shadow") || name == "gshadow" || name == "opasswd" {
        Severity::Critical
    } else {
        Severity::High
    }
}

#[cfg(test)]
mod tests {
    use super::{credential_severity, sample_readable_credential};
    use crate::core::types::Severity;
    use std::path::Path;

    #[test]
    fn golden_shadow_fixture_is_sampled_without_returning_content() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/linux/shadow.golden");
        let (bytes_read, severity) = sample_readable_credential(&path).unwrap();
        assert!(bytes_read > 0 && bytes_read <= 64);
        assert_eq!(severity, Severity::Critical);
    }

    #[test]
    fn shadow_family_paths_are_critical() {
        assert_eq!(
            credential_severity(Path::new("/etc/shadow-")),
            Severity::Critical
        );
        assert_eq!(
            credential_severity(Path::new("/var/backups/passwd.bak")),
            Severity::High
        );
    }
}
