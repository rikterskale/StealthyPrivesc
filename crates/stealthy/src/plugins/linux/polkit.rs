use anyhow::Result;
use std::fs;
use std::path::Path;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};
use crate::exploit;
use crate::plugins::linux::util;

pub struct PolkitPlugin;

impl Plugin for PolkitPlugin {
    fn id(&self) -> &'static str {
        "linux.polkit"
    }
    fn name(&self) -> &'static str {
        "Polkit / pkexec"
    }
    fn description(&self) -> &'static str {
        "pkexec presence and writable polkit rules directories"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let euid = util::euid();
        let gids = util::current_gids();
        let pkexec_paths = [Path::new("/usr/bin/pkexec"), Path::new("/bin/pkexec")];
        let rule_dirs = [
            Path::new("/etc/polkit-1/rules.d"),
            Path::new("/etc/polkit-1/localauthority"),
            Path::new("/etc/polkit-1/localauthority/50-local.d"),
            Path::new("/usr/share/polkit-1/rules.d"),
        ];
        scan_paths(ctx, euid, &gids, &pkexec_paths, &rule_dirs)
    }
}

fn scan_paths(
    ctx: &mut PluginContext<'_>,
    euid: u32,
    gids: &[u32],
    pkexec_paths: &[&Path],
    rule_dirs: &[&Path],
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    for p in pkexec_paths {
        if ctx.cancelled() {
            break;
        }
        let cand = p.display();
        if p.is_file() {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::metadata(p)?;
            let suid = meta.mode() & 0o4000 != 0;
            findings.push(Finding {
                plugin: "linux.polkit".into(),
                kind: FindingKind::Enumeration,
                severity: if suid {
                    Severity::Info
                } else {
                    Severity::Low
                },
                title: format!("pkexec present: {cand}"),
                detail: format!("mode={:o} suid={suid}", meta.mode()),
                recommendation: "Review polkit rules; historical pkexec CVEs are kernel/tooling dependent — use --allow-techniques kernel-exploit when ROE permits."
                    .into(),
                noisy: false,
                leaves_artifacts: false,
                object: cand.to_string(),
                condition: if suid { "pkexec-suid-present" } else { "pkexec-present" }.into(),
                mitre_techniques: vec!["T1068".into()],
                technique_id: "polkit".into(),
                ..Default::default()
            });
        }
    }

    for dir in rule_dirs {
        if ctx.cancelled() {
            break;
        }
        let p = *dir;
        if !p.exists() {
            continue;
        }
        if let Ok(meta) = fs::metadata(p) {
            if util::is_writable_by_euid(&meta, euid, gids) {
                let candidate = Finding {
                    plugin: "linux.polkit".into(),
                    kind: FindingKind::Misconfiguration,
                    severity: Severity::Critical,
                    title: format!("Writable polkit path: {}", dir.display()),
                    detail: format!("path={}", dir.display()),
                    recommendation:
                        "Writable polkit rules can grant root actions to low-priv users.".into(),
                    noisy: false,
                    leaves_artifacts: false,
                    object: dir.display().to_string(),
                    condition: "writable-polkit-path".into(),
                    technique_id: "polkit-rule".into(),
                    ..Default::default()
                };
                let probe_allowed = ctx.probe_allowed_for(&candidate);
                findings.push(candidate);
                if probe_allowed && p.is_dir() {
                    if let Ok(true) = exploit::writable_probe(p) {
                        findings.push(Finding {
                            plugin: "linux.polkit".into(),
                            kind: FindingKind::ExploitAttempt,
                            severity: Severity::Critical,
                            title: format!("Confirmed writable polkit dir: {}", dir.display()),
                            detail: "Reversible marker write/delete succeeded.".into(),
                            recommendation: "Do not drop rules without explicit approval.".into(),
                            noisy: true,
                            leaves_artifacts: false,
                            object: dir.display().to_string(),
                            condition: "reversible-writable-probe-confirmed".into(),
                            ..Default::default()
                        });
                    }
                }
            }
        }
        // World-writable rule files inside
        if p.is_dir() {
            if let Ok(rd) = fs::read_dir(p) {
                for entry in rd.flatten().take(100) {
                    if ctx.cancelled() {
                        break;
                    }
                    if let Ok(meta) = entry.metadata() {
                        if util::is_writable_by_euid(&meta, euid, gids) {
                            findings.push(Finding {
                                plugin: "linux.polkit".into(),
                                kind: FindingKind::Misconfiguration,
                                severity: Severity::High,
                                title: format!("Writable polkit entry: {}", entry.path().display()),
                                detail: format!("path={}", entry.path().display()),
                                recommendation:
                                    "Inspect rule contents for overly broad allow actions.".into(),
                                noisy: false,
                                leaves_artifacts: false,
                                object: entry.path().display().to_string(),
                                condition: "writable-polkit-rule-entry".into(),
                                technique_id: "polkit-rule".into(),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        findings.push(Finding {
            plugin: "linux.polkit".into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Info,
            title: "No obvious polkit misconfigurations".into(),
            detail: "pkexec/rules paths checked.".into(),
            recommendation: "Review custom .rules files manually if present.".into(),
            noisy: false,
            leaves_artifacts: false,
            object: "common-polkit-paths".into(),
            condition: "no-polkit-misconfiguration".into(),
            ..Default::default()
        });
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::scan_paths;
    use crate::core::plugin::PluginContext;
    use crate::core::profile::EngagementProfile;
    use crate::core::store::EncryptedStore;
    use crate::exploit::TechniqueAllowlist;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn fixture_scan_covers_pkexec_rules_probes_and_cancellation() {
        let root = tempfile::tempdir().unwrap();
        let pkexec_suid = root.path().join("pkexec-suid");
        let pkexec_plain = root.path().join("pkexec-plain");
        std::fs::write(&pkexec_suid, b"fixture").unwrap();
        std::fs::write(&pkexec_plain, b"fixture").unwrap();
        std::fs::set_permissions(&pkexec_suid, std::fs::Permissions::from_mode(0o4755)).unwrap();
        std::fs::set_permissions(&pkexec_plain, std::fs::Permissions::from_mode(0o755)).unwrap();

        let rules = root.path().join("rules.d");
        std::fs::create_dir(&rules).unwrap();
        std::fs::set_permissions(&rules, std::fs::Permissions::from_mode(0o777)).unwrap();
        let rule = rules.join("fixture.rules");
        std::fs::write(&rule, b"fixture").unwrap();
        std::fs::set_permissions(&rule, std::fs::Permissions::from_mode(0o666)).unwrap();

        let euid = std::fs::metadata(&rules).unwrap().uid().saturating_add(1);
        let allow = TechniqueAllowlist::default();
        let mut store = EncryptedStore::new();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut context = PluginContext {
            verbose: false,
            auto_exploit: true,
            prefer_quiet: true,
            noise_budget: EngagementProfile::Ci.noise_budget(),
            allow_techniques: &allow,
            store: &mut store,
            approved_probe_ids: &[],
            artifact_path: None,
            control_assessment: None,
            cancel: cancel.clone(),
        };
        let findings = scan_paths(
            &mut context,
            euid,
            &[],
            &[pkexec_suid.as_path(), pkexec_plain.as_path()],
            &[rules.as_path()],
        )
        .unwrap();
        for condition in [
            "pkexec-suid-present",
            "pkexec-present",
            "writable-polkit-path",
            "reversible-writable-probe-confirmed",
            "writable-polkit-rule-entry",
        ] {
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.condition == condition),
                "missing {condition}: {findings:?}"
            );
        }

        cancel.store(true, Ordering::SeqCst);
        let findings = scan_paths(
            &mut context,
            euid,
            &[],
            &[pkexec_suid.as_path()],
            &[rules.as_path()],
        )
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].condition, "no-polkit-misconfiguration");
    }
}
