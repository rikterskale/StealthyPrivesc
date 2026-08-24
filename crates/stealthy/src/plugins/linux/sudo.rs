use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};
use crate::plugins::linux::util;
use anyhow::Result;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct SudoPlugin;

impl Plugin for SudoPlugin {
    fn id(&self) -> &'static str {
        "linux.sudo"
    }
    fn name(&self) -> &'static str {
        "Sudo rules"
    }
    fn description(&self) -> &'static str {
        "Enumerate sudo privileges (may invoke sudo -l; can be noisy/audited)"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Quiet profile skips all sudo binary helpers (version + -l).
        if !ctx.prefer_quiet {
            if let Ok(out) = crate::core::command::trusted_command("sudo")
                .args(["--version"])
                .output()
            {
                let text = String::from_utf8_lossy(&out.stdout);
                let line = text.lines().next().unwrap_or("").to_string();
                if !line.is_empty() {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Enumeration,
                        severity: Severity::Info,
                        title: "sudo version".into(),
                        detail: line.clone(),
                        recommendation:
                            "Compare against distro security tracker. No sudo CVE is auto-exploited."
                                .into(),
                        noisy: true,
                        leaves_artifacts: false,
                        object: "sudo".into(),
                        condition: "version-observed".into(),
                        ..Default::default()
                    });
                    if line.contains("1.8.") || line.contains("1.9.0") || line.contains("1.9.1") {
                        findings.push(Finding {
                            plugin: self.id().into(),
                            kind: FindingKind::Recommendation,
                            severity: Severity::Medium,
                            title: "sudo build may warrant CVE review (historical heap/Baron-class era)"
                                .into(),
                            detail: line,
                            recommendation: "Validate patch level offline. Do not run public sudo exploits on production."
                                .into(),
                            noisy: false,
                            leaves_artifacts: false,
                            object: "sudo".into(),
                            condition: "historical-version-review".into(),
                            ..Default::default()
                        });
                    }
                }
            }
        }

        // Quiet path: inspect sudoers fragments we can read without executing sudo.
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_default();
        let groups = util::current_group_names();
        for path in ["/etc/sudoers", "/etc/sudoers.d"] {
            if ctx.cancelled() {
                break;
            }
            collect_readable_sudoers(path, &username, &groups, &ctx.cancel, &mut findings);
        }

        // `sudo -l` is commonly audited — quiet/OPSEC profiles skip it entirely.
        if ctx.prefer_quiet {
            if findings.is_empty() {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Recommendation,
                    severity: Severity::Info,
                    title: "sudo helpers skipped (quiet profile)".into(),
                    detail:
                        "prefer_quiet/OPSEC profile avoids sudo --version and sudo -l; readable sudoers only."
                            .into(),
                    recommendation: "Re-run with --profile balanced|thorough if sudo helpers are in ROE."
                        .into(),
                    noisy: false,
                    leaves_artifacts: false,
                    object: "/etc/sudoers*".into(),
                    condition: "quiet-profile-helper-skipped".into(),
                    ..Default::default()
                });
            }
        } else if ctx.verbose || findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Recommendation,
                severity: Severity::Info,
                title: "sudo -l may generate audit events".into(),
                detail: "Invoking sudo -n -l talks to sudoers and is often logged.".into(),
                recommendation:
                    "Prefer readable /etc/sudoers* when possible; use sudo -l only if in-scope."
                        .into(),
                noisy: true,
                leaves_artifacts: false,
                object: "sudo:-n-l".into(),
                condition: "audited-helper-warning".into(),
                ..Default::default()
            });

            match crate::core::command::trusted_command("sudo")
                .args(["-n", "-l"])
                .output()
            {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let combined = format!("{stdout}{stderr}");
                    let gtfo = format_gtfobins_annotations(&combined);
                    if combined.contains("NOPASSWD") {
                        findings.push(Finding {
                            plugin: self.id().into(),
                            kind: FindingKind::Misconfiguration,
                            severity: Severity::High,
                            title: "NOPASSWD sudo rule(s) present".into(),
                            detail: append_annotation(truncate(&combined, 2000), &gtfo),
                            recommendation: "Review each NOPASSWD command for GTFOBins-style escalation paths. Do not auto-run them.".into(),
                            noisy: true,
                            leaves_artifacts: false,
                            object: "sudo:-n-l:nopasswd".into(),
                            condition: "sudo-nopasswd-rule-observed".into(),
                            mitre_techniques: vec!["T1548.003".into()],
                            technique_id: if gtfo.is_empty() { "sudo" } else { "gtfobins" }.into(),
                            ..Default::default()
                        });
                    } else if out.status.success() {
                        findings.push(Finding {
                            plugin: self.id().into(),
                            kind: FindingKind::Enumeration,
                            severity: Severity::Low,
                            title: "sudo -l succeeded".into(),
                            detail: append_annotation(truncate(&combined, 2000), &gtfo),
                            recommendation: "Manually review allowed commands for escalation primitives.".into(),
                            noisy: true,
                            leaves_artifacts: false,
                            object: "sudo:-n-l".into(),
                            condition: "sudo-rules-enumerated".into(),
                            mitre_techniques: vec!["T1548.003".into()],
                            technique_id: if gtfo.is_empty() { "sudo" } else { "gtfobins" }.into(),
                            ..Default::default()
                        });
                    } else if !combined.trim().is_empty() {
                        findings.push(Finding {
                            plugin: self.id().into(),
                            kind: FindingKind::Enumeration,
                            severity: Severity::Info,
                            title: "sudo -l did not succeed (expected without tickets)".into(),
                            detail: truncate(&combined, 500),
                            recommendation: "If password sudo is available interactively, re-check during an approved window.".into(),
                            noisy: true,
                            leaves_artifacts: false,
                            object: "sudo:-n-l".into(),
                            condition: "sudo-rules-unavailable".into(),
                            ..Default::default()
                        });
                    }
                }
                Err(e) => {
                    ctx.store.note(format!("sudo binary unavailable: {e}"));
                }
            }
        }

        Ok(findings)
    }
}

fn collect_readable_sudoers(
    path: &str,
    username: &str,
    groups: &[String],
    cancel: &Arc<AtomicBool>,
    findings: &mut Vec<Finding>,
) {
    if cancel.load(Ordering::SeqCst) {
        return;
    }
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };

    if meta.is_file() {
        if let Some(text) = read_text_bounded(Path::new(path), 1024 * 1024) {
            scan_sudoers_text(path, &text, username, groups, cancel, findings);
        }
        return;
    }

    if meta.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten().take(512) {
                if cancel.load(Ordering::SeqCst) {
                    return;
                }
                let p = entry.path();
                if p.is_file() {
                    if let Some(text) = read_text_bounded(&p, 1024 * 1024) {
                        scan_sudoers_text(
                            &p.to_string_lossy(),
                            &text,
                            username,
                            groups,
                            cancel,
                            findings,
                        );
                    }
                }
            }
        }
    }
}

fn read_text_bounded(path: &Path, max_bytes: u64) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.by_ref().take(max_bytes).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn scan_sudoers_text(
    path: &str,
    text: &str,
    username: &str,
    groups: &[String],
    cancel: &Arc<AtomicBool>,
    findings: &mut Vec<Finding>,
) {
    for line in text.lines() {
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let subject = trimmed.split_whitespace().next().unwrap_or("");
        if subject.is_empty() || !rule_applies_to_identity(subject, username, groups) {
            continue;
        }
        if trimmed.contains("NOPASSWD") {
            let gtfo = format_gtfobins_annotations(trimmed);
            findings.push(Finding {
                plugin: "linux.sudo".into(),
                kind: FindingKind::Misconfiguration,
                severity: Severity::High,
                title: format!("Readable NOPASSWD rule in {path}"),
                detail: append_annotation(trimmed.to_string(), &gtfo),
                recommendation: "Validate whether the allowed binary can be abused (GTFOBins). Escalate only with approval.".into(),
                noisy: false,
                leaves_artifacts: false,
                object: format!("{path}:{trimmed}"),
                condition: "sudo-nopasswd-rule-readable".into(),
                mitre_techniques: vec!["T1548.003".into()],
                technique_id: if gtfo.is_empty() { "sudo" } else { "gtfobins" }.into(),
                ..Default::default()
            });
        }
        if trimmed.contains("ALL=(ALL)") || trimmed.contains("ALL=(ALL:ALL)") {
            findings.push(Finding {
                plugin: "linux.sudo".into(),
                kind: FindingKind::Misconfiguration,
                severity: Severity::Critical,
                title: format!("Broad ALL sudo rule readable in {path}"),
                detail: trimmed.to_string(),
                recommendation:
                    "If this applies to the current user, full root via sudo is likely.".into(),
                noisy: false,
                leaves_artifacts: false,
                object: format!("{path}:{trimmed}"),
                condition: "sudo-broad-all-rule-readable".into(),
                mitre_techniques: vec!["T1548.003".into()],
                technique_id: "sudo".into(),
                ..Default::default()
            });
        }
    }
}

fn rule_applies_to_identity(subject: &str, username: &str, groups: &[String]) -> bool {
    subject.split(',').map(str::trim).any(|token| {
        token == "ALL"
            || (!username.is_empty() && token == username)
            || token
                .strip_prefix('%')
                .is_some_and(|group| groups.iter().any(|known| known == group))
            || token
                .strip_prefix('+')
                .is_some_and(|group| groups.iter().any(|known| known == group))
    })
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

fn append_annotation(mut detail: String, annotation: &str) -> String {
    if !annotation.is_empty() {
        detail.push('\n');
        detail.push_str(annotation);
    }
    detail
}

fn format_gtfobins_annotations(text: &str) -> String {
    let mut matches = Vec::new();
    for token in text.split(|character: char| {
        character.is_whitespace() || matches!(character, ',' | ':' | '=' | '(' | ')' | '!')
    }) {
        let binary = token
            .trim_matches(|character: char| character == '\'' || character == '"')
            .rsplit('/')
            .next()
            .unwrap_or("");
        let functions = match binary {
            "awk" => "shell,file-read,file-write,sudo",
            "bash" | "sh" | "env" | "find" | "make" | "nmap" | "perl" | "python" | "python3"
            | "ruby" | "systemctl" => "shell,sudo",
            "cp" | "mv" | "tar" | "zip" | "vi" | "vim" => "shell,file-read,file-write,sudo",
            "less" | "more" | "man" => "shell,file-read,sudo",
            _ => continue,
        };
        if !matches.iter().any(|(known, _)| *known == binary) {
            matches.push((binary, functions));
        }
    }
    matches
        .into_iter()
        .map(|(binary, functions)| {
            format!(
                "gtfobins.binary={binary} gtfobins.functions={functions} gtfobins.url=https://gtfobins.github.io/gtfobins/{binary}/ recommend_only=true"
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::{format_gtfobins_annotations, rule_applies_to_identity, scan_sudoers_text};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    #[test]
    fn matches_direct_user_and_group_rules() {
        let groups = vec!["wheel".to_string(), "dev".to_string()];
        assert!(rule_applies_to_identity("alice", "alice", &groups));
        assert!(rule_applies_to_identity("%wheel", "alice", &groups));
        assert!(rule_applies_to_identity("+dev", "alice", &groups));
        assert!(rule_applies_to_identity("ALL", "alice", &groups));
    }

    #[test]
    fn rejects_unrelated_subjects() {
        let groups = vec!["wheel".to_string()];
        assert!(!rule_applies_to_identity("bob", "alice", &groups));
        assert!(!rule_applies_to_identity("%sudo", "alice", &groups));
    }

    #[test]
    fn golden_sudoers_fixture_scopes_identity_and_annotates_gtfobins() {
        let fixture = include_str!("../../../tests/fixtures/linux/sudoers.golden");
        let mut findings = Vec::new();
        scan_sudoers_text(
            "/fixture/sudoers",
            fixture,
            "alice",
            &["wheel".into()],
            &Arc::new(AtomicBool::new(false)),
            &mut findings,
        );
        assert!(findings
            .iter()
            .any(|finding| finding.condition == "sudo-nopasswd-rule-readable"
                && finding.detail.contains("gtfobins.binary=find")
                && finding.technique_id == "gtfobins"));
        assert!(!findings
            .iter()
            .any(|finding| finding.detail.contains("bob ")));
        assert!(findings
            .iter()
            .all(|finding| !finding.object.is_empty() && !finding.condition.is_empty()));
    }

    #[test]
    fn annotations_never_include_unknown_commands() {
        assert!(format_gtfobins_annotations("/usr/bin/custom-tool --check").is_empty());
    }
}
