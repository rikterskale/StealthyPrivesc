//! Enumerate Linux host controls that affect binary/script execution.
//!
//! Detection only: AppArmor, SELinux, noexec drop mounts, audit/Yama signals.
//! Does not disable or evade controls. When ROE permits, `--allow-techniques
//! endpoint-bypass` records alternate-path intent and approved-fixture
//! validation (see docs/techniques.md).

use anyhow::Result;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};
use crate::exploit::{self, TechniqueFamily};

pub struct EndpointControlsPlugin;

impl Plugin for EndpointControlsPlugin {
    fn id(&self) -> &'static str {
        "linux.endpoint_controls"
    }
    fn name(&self) -> &'static str {
        "Endpoint / execution controls"
    }
    fn description(&self) -> &'static str {
        "Report AppArmor, SELinux, noexec drop mounts, and related hardening signals"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut blocking = false;

        findings.extend(apparmor_findings(&mut blocking));
        findings.extend(selinux_findings());
        findings.extend(noexec_findings(&mut blocking, &ctx.cancel));
        findings.extend(hardening_signals());

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No Linux endpoint-control signals collected".into(),
                detail: "AppArmor/SELinux/noexec checks returned no readable evidence.".into(),
                recommendation: "Confirm /proc and securityfs access; use scripts/linux fallbacks if the binary cannot run.".into(),
                noisy: false,
                leaves_artifacts: false,
                object: "linux-endpoint-controls".into(),
                condition: "control-evidence-unavailable".into(),
                ..Default::default()
            });
        }

        if blocking {
            let tech = TechniqueFamily::EndpointBypass;
            let allowed = ctx.allow_techniques.allows(tech);
            let artifact = ctx.artifact_path.as_deref();
            let artifact_text = artifact.map(|p| p.display().to_string());
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Recommendation,
                severity: Severity::Medium,
                title: "Execution may be constrained by host controls".into(),
                detail: "One or more AppArmor-enforce or noexec conditions were observed on common drop paths.".into(),
                recommendation: exploit::endpoint_bypass_what_next(
                    allowed,
                    artifact_text.as_deref(),
                    false,
                ),
                noisy: false,
                leaves_artifacts: false,
                object: artifact_text
                    .clone()
                    .unwrap_or_else(|| "none".into()),
                condition: if allowed {
                    "endpoint-bypass-opted-in".into()
                } else {
                    "endpoint-bypass-available".into()
                },
                technique_id: tech.id().into(),
                ..Default::default()
            });
            if allowed || ctx.auto_exploit {
                findings.push(exploit::technique_status_with_artifact(
                    self.id(),
                    tech,
                    allowed,
                    artifact,
                ));
            }
        }

        Ok(findings)
    }
}

fn apparmor_findings(blocking: &mut bool) -> Vec<Finding> {
    let mut out = Vec::new();
    let module = Path::new("/sys/module/apparmor").is_dir()
        || Path::new("/sys/kernel/security/apparmor").is_dir();
    if !module {
        out.push(Finding {
            plugin: "linux.endpoint_controls".into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Info,
            title: "AppArmor module not evident".into(),
            detail: "Neither /sys/module/apparmor nor /sys/kernel/security/apparmor is present."
                .into(),
            recommendation: "Continue; record SELinux/noexec results separately.".into(),
            noisy: false,
            leaves_artifacts: false,
            object: "apparmor".into(),
            condition: "module-not-observed".into(),
            ..Default::default()
        });
        return out;
    }

    let profile = fs::read_to_string("/proc/self/attr/current")
        .or_else(|_| fs::read_to_string("/proc/self/attr/apparmor/current"))
        .unwrap_or_else(|_| "unreadable".into())
        .trim()
        .to_string();
    let enforce_like = profile.contains("(enforce)") || profile.ends_with(" (enforce)");
    if enforce_like {
        *blocking = true;
    }
    out.push(Finding {
        plugin: "linux.endpoint_controls".into(),
        kind: FindingKind::Enumeration,
        severity: if enforce_like {
            Severity::Medium
        } else {
            Severity::Low
        },
        title: format!("AppArmor present; current={profile}"),
        detail: "Read-only profile attribution for this process.".into(),
        recommendation: if enforce_like {
            "Enforcing profile may restrict custom binaries. Prefer scripts/linux fallbacks or ROE-approved packaging.".into()
        } else {
            "Record AppArmor mode in the engagement log.".into()
        },
        noisy: false,
        leaves_artifacts: false,
        object: "apparmor-current-profile".into(),
        condition: if enforce_like {
            "profile-enforcing"
        } else {
            "profile-present"
        }
        .into(),
        ..Default::default()
    });
    out
}

fn selinux_findings() -> Vec<Finding> {
    let mut out = Vec::new();
    let enforce_path = Path::new("/sys/fs/selinux/enforce");
    if !enforce_path.is_file() {
        return out;
    }
    let mode = fs::read_to_string(enforce_path)
        .unwrap_or_else(|_| "?".into())
        .trim()
        .to_string();
    let (title, severity) = match mode.as_str() {
        "1" => ("SELinux enforcing", Severity::Medium),
        "0" => ("SELinux permissive", Severity::Low),
        _ => ("SELinux enforce value present", Severity::Info),
    };
    out.push(Finding {
        plugin: "linux.endpoint_controls".into(),
        kind: FindingKind::Enumeration,
        severity,
        title: title.into(),
        detail: format!("/sys/fs/selinux/enforce={mode}"),
        recommendation:
            "SELinux policy can block unsigned drops; use approved script paths when constrained."
                .into(),
        noisy: false,
        leaves_artifacts: false,
        object: enforce_path.display().to_string(),
        condition: match mode.as_str() {
            "1" => "selinux-enforcing",
            "0" => "selinux-permissive",
            _ => "selinux-state-unreadable",
        }
        .into(),
        ..Default::default()
    });
    out
}

fn noexec_findings(blocking: &mut bool, cancel: &AtomicBool) -> Vec<Finding> {
    let mut out = Vec::new();
    let text = match fs::read_to_string("/proc/self/mountinfo") {
        Ok(t) => t,
        Err(_) => return out,
    };

    let watch = ["/tmp", "/var/tmp", "/dev/shm"];
    let mut home = std::env::var("HOME").ok();
    if let Ok(cwd) = std::env::current_dir() {
        home.get_or_insert_with(|| cwd.display().to_string());
    }

    for line in text.lines() {
        if cancel.load(Ordering::SeqCst) {
            break;
        }
        // mountinfo fields: ... mountpoint ... - fstype source superopts
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let mountpoint = parts[4];
        let lower = line.to_ascii_lowercase();
        let has_noexec = lower
            .split(|c: char| c == ',' || c.is_whitespace())
            .any(|t| t == "noexec");

        if !has_noexec {
            continue;
        }

        let relevant = watch
            .iter()
            .any(|p| mountpoint == *p || mountpoint.starts_with(&format!("{p}/")))
            || home.as_ref().is_some_and(|h| {
                mountpoint == h || h.starts_with(mountpoint) || mountpoint.starts_with(h)
            });

        if relevant {
            *blocking = true;
            out.push(Finding {
                plugin: "linux.endpoint_controls".into(),
                kind: FindingKind::Misconfiguration,
                severity: Severity::Medium,
                title: format!("noexec mount affects drop path: {mountpoint}"),
                detail: truncate(line, 280),
                recommendation: "Custom ELF drops on this mount will fail exec. Prefer script fallbacks (bash/python) or an approved executable mount.".into(),
                noisy: false,
                leaves_artifacts: false,
                object: mountpoint.into(),
                condition: "noexec-affects-drop-path".into(),
                ..Default::default()
            });
        }
    }

    if out.is_empty() {
        out.push(Finding {
            plugin: "linux.endpoint_controls".into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Info,
            title: "No noexec on common drop mounts".into(),
            detail: "Checked /tmp, /var/tmp, /dev/shm, and HOME/cwd against /proc/self/mountinfo."
                .into(),
            recommendation: "Still verify the intended drop path before writing a binary.".into(),
            noisy: false,
            leaves_artifacts: false,
            object: "common-drop-mounts".into(),
            condition: "no-noexec-observed".into(),
            ..Default::default()
        });
    }
    out
}

fn hardening_signals() -> Vec<Finding> {
    let mut out = Vec::new();
    if Path::new("/proc/sys/kernel/yama/ptrace_scope").is_file() {
        if let Ok(v) = fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
            let v = v.trim();
            out.push(Finding {
                plugin: "linux.endpoint_controls".into(),
                kind: FindingKind::Enumeration,
                severity: if v == "0" {
                    Severity::Info
                } else {
                    Severity::Low
                },
                title: format!("yama.ptrace_scope={v}"),
                detail: "Yama ptrace restrictions affect debugging and some tooling.".into(),
                recommendation: "Informational hardening signal; record for engagement context."
                    .into(),
                noisy: false,
                leaves_artifacts: false,
                object: "/proc/sys/kernel/yama/ptrace_scope".into(),
                condition: if v == "0" {
                    "ptrace-scope-unrestricted"
                } else {
                    "ptrace-scope-restricted"
                }
                .into(),
                ..Default::default()
            });
        }
    }
    if Path::new("/etc/audit/auditd.conf").is_file() || Path::new("/sbin/auditd").is_file() {
        out.push(Finding {
            plugin: "linux.endpoint_controls".into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Low,
            title: "auditd configuration or binary present".into(),
            detail: "Host appears to ship auditd; execution may generate audit events.".into(),
            recommendation: "Prefer low-noise reads; expect telemetry on helper spawns.".into(),
            noisy: false,
            leaves_artifacts: false,
            object: "auditd".into(),
            condition: "audit-service-present".into(),
            ..Default::default()
        });
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::truncate;

    #[test]
    fn truncate_short_unchanged() {
        assert_eq!(truncate("abc", 10), "abc");
    }
}
