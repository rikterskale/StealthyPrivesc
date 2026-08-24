use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct DllHijackPlugin;

impl Plugin for DllHijackPlugin {
    fn id(&self) -> &'static str {
        "windows.dll_hijack"
    }
    fn name(&self) -> &'static str {
        "DLL hijack candidates"
    }
    fn description(&self) -> &'static str {
        "Look for writable directories in trusted search paths / application folders"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["windows"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut candidates: Vec<(PathBuf, Vec<&'static str>)> = Vec::new();
        if let Ok(sysroot) = std::env::var("SystemRoot") {
            add_candidate(&mut candidates, PathBuf::from(&sysroot), "system-root");
            add_candidate(
                &mut candidates,
                PathBuf::from(format!(r"{sysroot}\System32")),
                "system-search-directory",
            );
            add_candidate(
                &mut candidates,
                PathBuf::from(format!(r"{sysroot}\SysWOW64")),
                "system-search-directory",
            );
        }
        if let Ok(path) = std::env::var("PATH") {
            for part in path.split(';').filter(|s| !s.is_empty()).take(30) {
                add_candidate(&mut candidates, PathBuf::from(part), "process-path");
            }
        }
        if let Ok(cwd) = std::env::current_dir() {
            add_candidate(&mut candidates, cwd, "working-directory");
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                add_candidate(
                    &mut candidates,
                    parent.to_path_buf(),
                    "current-application-directory",
                );
            }
        }
        for (env_name, source) in [
            ("ProgramFiles", "application-root"),
            ("ProgramFiles(x86)", "application-root"),
            ("ProgramData", "shared-application-root"),
        ] {
            if let Ok(path) = std::env::var(env_name) {
                add_candidate(&mut candidates, PathBuf::from(path), source);
            }
        }

        let mut approved_probe_seen = false;
        for (dir, sources) in candidates {
            if ctx.cancelled() {
                break;
            }
            if !dir.is_dir() {
                continue;
            }
            let acl_state =
                super::acl::AclState::from_check(super::acl::is_writable_for_current_user(&dir));
            let source = sources.join(",");
            let candidate = Finding {
                plugin: self.id().into(),
                kind: if acl_state == super::acl::AclState::Writable {
                    FindingKind::Misconfiguration
                } else {
                    FindingKind::Enumeration
                },
                severity: if acl_state == super::acl::AclState::Writable {
                    Severity::High
                } else {
                    Severity::Info
                },
                title: format!("DLL search/app directory candidate: {}", dir.display()),
                detail: format!(
                    "source={source} directory_acl=current_token:{} prerequisite=privileged_application_searches_or_loads_from_directory",
                    acl_state.as_str()
                ),
                recommendation: if acl_state == super::acl::AclState::Writable {
                    "Identify a specific privileged application and its observed import/search behavior before treating this as exploitable; no DLL was created."
                        .into()
                } else {
                    "No writable condition was established. Application-specific import and SafeDllSearchMode analysis is still required."
                        .into()
                },
                noisy: false,
                leaves_artifacts: false,
                object: dir.display().to_string(),
                condition: format!("dll-search-directory-acl:{}", acl_state.as_str()),
                ..Default::default()
            };
            let probe_allowed = ctx.probe_allowed_for(&candidate);
            findings.push(candidate);
            approved_probe_seen |= probe_allowed;
            if probe_allowed && is_dir_writable(&dir) {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::ExploitAttempt,
                    severity: Severity::High,
                    title: format!(
                        "Confirmed writable DLL search/app directory: {}",
                        dir.display()
                    ),
                    detail: "Reversible marker write/delete succeeded.".into(),
                    recommendation: "Do not plant DLLs unless explicitly authorized.".into(),
                    noisy: true,
                    leaves_artifacts: false,
                    object: dir.display().to_string(),
                    condition: "writable-dll-search-directory-probe".into(),
                    ..Default::default()
                });
            }
        }

        if !approved_probe_seen {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Recommendation,
                severity: Severity::Info,
                title: "DLL write probes were not approved".into(),
                detail: "Read-only current-token ACL checks were used. Reversible marker probes remain finding-scoped and opt-in."
                    .into(),
                recommendation: "Use the read-only ACL result first; approve a specific finding only when a write confirmation is necessary under the ROE."
                    .into(),
                noisy: false,
                leaves_artifacts: false,
                object: "windows-dll-search-analysis".into(),
                condition: "write-probes-not-approved".into(),
                ..Default::default()
            });
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No writable trusted-path directories detected".into(),
                detail: "Checked SystemRoot, PATH entries, and Program Files roots.".into(),
                recommendation: "Per-app hijack analysis still required for thorough coverage."
                    .into(),
                noisy: false,
                leaves_artifacts: false,
                object: "windows-dll-search-analysis".into(),
                condition: "no-dll-search-directory-candidate".into(),
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn add_candidate(
    candidates: &mut Vec<(PathBuf, Vec<&'static str>)>,
    path: PathBuf,
    source: &'static str,
) {
    let key = path.to_string_lossy();
    if let Some((_, sources)) = candidates
        .iter_mut()
        .find(|(existing, _)| existing.to_string_lossy().eq_ignore_ascii_case(&key))
    {
        if !sources.contains(&source) {
            sources.push(source);
        }
    } else {
        candidates.push((path, vec![source]));
    }
}

fn is_dir_writable(dir: &Path) -> bool {
    crate::exploit::writable_probe(dir).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::add_candidate;
    use std::path::PathBuf;

    #[test]
    fn candidate_sources_are_deduplicated_case_insensitively() {
        let mut candidates = Vec::new();
        add_candidate(&mut candidates, PathBuf::from(r"C:\Tools"), "process-path");
        add_candidate(
            &mut candidates,
            PathBuf::from(r"c:\tools"),
            "working-directory",
        );
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].1, vec!["process-path", "working-directory"]);
    }
}
