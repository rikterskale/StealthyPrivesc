use anyhow::Result;
use std::env;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};
use crate::exploit;

pub struct PathLdPlugin;

impl Plugin for PathLdPlugin {
    fn id(&self) -> &'static str {
        "linux.path_ld"
    }
    fn name(&self) -> &'static str {
        "Writable PATH / LD_* "
    }
    fn description(&self) -> &'static str {
        "Find writable PATH entries and risky LD_PRELOAD / LD_LIBRARY_PATH settings"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        if let Ok(path) = env::var("PATH") {
            for entry in path.split(':').filter(|s| !s.is_empty()) {
                if ctx.cancelled() {
                    break;
                }
                let p = Path::new(entry);
                if !p.exists() {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Misconfiguration,
                        severity: Severity::Medium,
                        title: format!("PATH entry missing (hijack candidate): {entry}"),
                        detail: "A missing PATH component can be created by the user if a parent dir is writable.".into(),
                        recommendation: "Check whether you can create this directory and plant a trojan binary name.".into(),
                        noisy: false,
                        leaves_artifacts: false,
                        object: entry.into(),
                        condition: "path-entry-missing".into(),
                        technique_id: "path-hijack".into(),
                        ..Default::default()
                    });
                    continue;
                }
                if let Ok(meta) = fs::metadata(p) {
                    let mode = meta.permissions().mode();
                    if mode & 0o002 != 0 {
                        let candidate = Finding {
                            plugin: self.id().into(),
                            kind: FindingKind::Misconfiguration,
                            severity: Severity::High,
                            title: format!("World-writable PATH entry: {entry}"),
                            detail: format!("mode={mode:o}"),
                            recommendation: "Binary planting in PATH is a classic privesc if privileged processes inherit PATH.".into(),
                            noisy: false,
                            leaves_artifacts: false,
                            object: entry.into(),
                            condition: "path-entry-world-writable".into(),
                            technique_id: "path-hijack".into(),
                            ..Default::default()
                        };
                        let probe_allowed = ctx.probe_allowed_for(&candidate);
                        findings.push(candidate);
                        if probe_allowed {
                            if let Ok(true) = exploit::writable_probe(p) {
                                findings.push(Finding {
                                    plugin: self.id().into(),
                                    kind: FindingKind::ExploitAttempt,
                                    severity: Severity::High,
                                    title: format!("Confirmed writable PATH dir: {entry}"),
                                    detail: "Reversible marker write/delete succeeded.".into(),
                                    recommendation:
                                        "Do not plant binaries unless explicitly authorized."
                                            .into(),
                                    noisy: true,
                                    leaves_artifacts: false,
                                    object: entry.into(),
                                    condition: "reversible-writable-probe-confirmed".into(),
                                    technique_id: "path-hijack".into(),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
        }

        for var in ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT"] {
            if ctx.cancelled() {
                break;
            }
            if let Ok(val) = env::var(var) {
                if !val.is_empty() {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Enumeration,
                        severity: Severity::Medium,
                        title: format!("{var} is set"),
                        detail: redacted_loader_detail(&val),
                        recommendation: "Inherited loader variables can redirect privileged dynamically linked programs.".into(),
                        noisy: false,
                        leaves_artifacts: false,
                        object: var.into(),
                        condition: "dynamic-loader-variable-set".into(),
                        technique_id: "dynamic-linker-hijack".into(),
                        ..Default::default()
                    });
                }
            }
        }

        // /etc/ld.so.preload readable?
        if let Some(text) = read_text_bounded(Path::new("/etc/ld.so.preload"), 1024 * 1024) {
            if !text.trim().is_empty() {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Enumeration,
                    severity: Severity::High,
                    title: "/etc/ld.so.preload is non-empty".into(),
                    detail: format!(
                        "{} non-empty loader configuration line(s); contents redacted.",
                        text.lines().filter(|line| !line.trim().is_empty()).count()
                    ),
                    recommendation: "If writable, this is a powerful persistence/privesc primitive — handle with extreme care.".into(),
                    noisy: false,
                    leaves_artifacts: false,
                    object: "/etc/ld.so.preload".into(),
                    condition: "loader-preload-config-nonempty".into(),
                    technique_id: "dynamic-linker-hijack".into(),
                    ..Default::default()
                });
            }
        }

        if let Ok(meta) = fs::metadata("/etc/ld.so.preload") {
            let mode = meta.permissions().mode();
            if mode & 0o002 != 0 {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Misconfiguration,
                    severity: Severity::Critical,
                    title: "/etc/ld.so.preload is world-writable".into(),
                    detail: format!("mode={mode:o}"),
                    recommendation: "Critical misconfiguration. Do not modify without explicit approval.".into(),
                    noisy: false,
                    leaves_artifacts: true,
                    object: "/etc/ld.so.preload".into(),
                    condition: "loader-preload-config-world-writable".into(),
                    technique_id: "dynamic-linker-hijack".into(),
                    ..Default::default()
                });
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No obvious PATH/LD issues".into(),
                detail: "PATH entries were not world-writable; LD_* unset or empty.".into(),
                recommendation:
                    "Still review sudo secure_path and systemd Environment= directives.".into(),
                noisy: false,
                leaves_artifacts: false,
                object: "PATH-and-dynamic-loader-environment".into(),
                condition: "no-obvious-path-loader-issue".into(),
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn read_text_bounded(path: &Path, max_bytes: u64) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.by_ref().take(max_bytes).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn redacted_loader_detail(value: &str) -> String {
    let entries = value.split(':').filter(|entry| !entry.is_empty()).count();
    format!("value_present=true entries={entries}; raw loader value redacted")
}

#[cfg(test)]
mod tests {
    use super::{read_text_bounded, redacted_loader_detail};

    #[test]
    fn loader_details_do_not_echo_environment_values() {
        let detail = redacted_loader_detail("/secret/token.so:/opt/private/lib");
        assert!(!detail.contains("secret"));
        assert!(detail.contains("entries=2"));
    }

    #[test]
    fn bounded_reader_is_limited_and_reports_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("preload");
        std::fs::write(&path, b"abcdef").unwrap();
        assert_eq!(read_text_bounded(&path, 3).as_deref(), Some("abc"));
        assert!(read_text_bounded(&dir.path().join("missing"), 3).is_none());
    }
}
