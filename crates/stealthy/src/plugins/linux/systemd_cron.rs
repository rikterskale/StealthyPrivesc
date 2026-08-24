use anyhow::Result;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};
use crate::exploit;
use crate::plugins::linux::util;

pub struct SystemdCronPlugin;

impl Plugin for SystemdCronPlugin {
    fn id(&self) -> &'static str {
        "linux.systemd_cron"
    }
    fn name(&self) -> &'static str {
        "Writable systemd units / cron"
    }
    fn description(&self) -> &'static str {
        "Detect writable unit files and cron directories"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let euid = util::euid();
        let gids = util::current_gids();

        let unit_dirs = [
            "/etc/systemd/system",
            "/lib/systemd/system",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
        ];
        for dir in unit_dirs {
            if ctx.cancelled() {
                break;
            }
            check_writable_tree(
                dir,
                euid,
                &gids,
                "systemd unit path",
                &ctx.cancel,
                &mut findings,
            );
            scan_timers(dir, euid, &gids, &ctx.cancel, &mut findings);
        }

        if let Ok(home) = std::env::var("HOME") {
            for dir in [
                format!("{home}/.config/systemd/user"),
                format!("{home}/.local/share/systemd/user"),
            ] {
                if ctx.cancelled() {
                    break;
                }
                check_writable_tree(
                    &dir,
                    euid,
                    &gids,
                    "user systemd unit path",
                    &ctx.cancel,
                    &mut findings,
                );
                scan_timers(&dir, euid, &gids, &ctx.cancel, &mut findings);
            }
        }

        let cron_paths = [
            "/etc/crontab",
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/var/spool/cron/crontabs",
        ];
        for p in cron_paths {
            if ctx.cancelled() {
                break;
            }
            check_writable_tree(p, euid, &gids, "cron path", &ctx.cancel, &mut findings);
        }
        if let Ok(user) = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")) {
            check_writable_tree(
                &format!("/var/spool/cron/crontabs/{user}"),
                euid,
                &gids,
                "current-user crontab",
                &ctx.cancel,
                &mut findings,
            );
        }

        if ctx.auto_exploit {
            // Only probe directories we ourselves can write — reversible marker.
            for f in findings.clone() {
                if ctx.cancelled() {
                    break;
                }
                if ctx.probe_allowed_for(&f) && f.condition.starts_with("writable-") {
                    if let Some(path) = f.detail.strip_prefix("path=") {
                        let path = Path::new(path.trim());
                        if path.is_dir() {
                            match exploit::writable_probe(path) {
                                Ok(true) => findings.push(Finding {
                                    plugin: self.id().into(),
                                    kind: FindingKind::ExploitAttempt,
                                    severity: Severity::High,
                                    title: format!("Confirmed writable via probe: {}", path.display()),
                                    detail: "Created and deleted reversible writability marker successfully.".into(),
                                    recommendation: "Persistence via cron/systemd is noisy; obtain explicit approval first.".into(),
                                    noisy: true,
                                    leaves_artifacts: false,
                                    object: path.display().to_string(),
                                    condition: "reversible-writable-probe-confirmed".into(),
                                    ..Default::default()
                                }),
                                Ok(false) => {}
                                Err(e) => ctx.store.note(format!("probe failed on {}: {e}", path.display())),
                            }
                        }
                    }
                }
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No writable systemd/cron paths detected".into(),
                detail: "Checked common unit and cron locations for world/group write.".into(),
                recommendation: "Also review user crontab and timers with systemctl --user list-timers if in scope.".into(),
                noisy: false,
                leaves_artifacts: false,
                object: "common-systemd-and-cron-paths".into(),
                condition: "no-writable-scheduler-paths".into(),
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn scan_timers(
    dir: &str,
    euid: u32,
    gids: &[u32],
    cancel: &Arc<AtomicBool>,
    findings: &mut Vec<Finding>,
) {
    let p = Path::new(dir);
    if !p.is_dir() {
        return;
    }
    let Ok(rd) = fs::read_dir(p) else {
        return;
    };
    for entry in rd.flatten().take(300) {
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        let path = entry.path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.ends_with(".timer") {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if is_writable_by(&meta, euid, gids) {
                findings.push(Finding {
                    plugin: "linux.systemd_cron".into(),
                    kind: FindingKind::Misconfiguration,
                    severity: Severity::High,
                    title: format!("Writable systemd timer: {}", path.display()),
                    detail: format!("path={}", path.display()),
                    recommendation: "Writable timers can re-point OnCalendar/Unit to attacker-controlled services."
                        .into(),
                    noisy: false,
                    leaves_artifacts: false,
                    object: path.display().to_string(),
                    condition: "writable-systemd-timer".into(),
                    ..Default::default()
                });
            }
        }
        // Companion service unit next to timer
        if let Some(text) = read_text_bounded(&path, 256 * 1024) {
            for line in text.lines() {
                if cancel.load(Ordering::SeqCst) {
                    return;
                }
                let t = line.trim();
                if let Some(unit) = t.strip_prefix("Unit=") {
                    let unit = unit.trim();
                    let companion = Path::new(dir).join(unit);
                    if companion.is_file() {
                        if let Ok(meta) = fs::metadata(&companion) {
                            if is_writable_by(&meta, euid, gids) {
                                findings.push(Finding {
                                    plugin: "linux.systemd_cron".into(),
                                    kind: FindingKind::Misconfiguration,
                                    severity: Severity::High,
                                    title: format!(
                                        "Timer references writable unit: {}",
                                        companion.display()
                                    ),
                                    detail: format!("timer={} unit={unit}", path.display()),
                                    recommendation:
                                        "Modify/replace the unit only with ROE approval.".into(),
                                    noisy: false,
                                    leaves_artifacts: false,
                                    object: companion.display().to_string(),
                                    condition: "writable-timer-companion-unit".into(),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}

fn read_text_bounded(path: &Path, max_bytes: u64) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.by_ref().take(max_bytes).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn check_writable_tree(
    path: &str,
    euid: u32,
    gids: &[u32],
    label: &str,
    cancel: &Arc<AtomicBool>,
    findings: &mut Vec<Finding>,
) {
    if cancel.load(Ordering::SeqCst) {
        return;
    }
    let p = Path::new(path);
    let meta = match fs::metadata(p) {
        Ok(m) => m,
        Err(_) => return,
    };

    if is_writable_by(&meta, euid, gids) {
        findings.push(Finding {
            plugin: "linux.systemd_cron".into(),
            kind: FindingKind::Misconfiguration,
            severity: Severity::High,
            title: format!("Writable {label}"),
            detail: format!("path={path}"),
            recommendation: "Writable scheduled-task configuration often yields root at next run. Confirm ownership and timers carefully.".into(),
            noisy: false,
            leaves_artifacts: false,
            object: path.into(),
            condition: "writable-scheduler-root".into(),
            ..Default::default()
        });
    }

    if meta.is_dir() {
        if let Ok(rd) = fs::read_dir(p) {
            for entry in rd.flatten().take(200) {
                if cancel.load(Ordering::SeqCst) {
                    return;
                }
                if let Ok(m) = fs::symlink_metadata(entry.path()) {
                    if m.file_type().is_symlink() {
                        continue;
                    }
                    if is_writable_by(&m, euid, gids) {
                        findings.push(Finding {
                            plugin: "linux.systemd_cron".into(),
                            kind: FindingKind::Misconfiguration,
                            severity: Severity::High,
                            title: format!("Writable {label} entry"),
                            detail: format!("path={}", entry.path().display()),
                            recommendation: "Inspect unit/cron contents and ExecStart/command lines for injection.".into(),
                            noisy: false,
                            leaves_artifacts: false,
                            object: entry.path().display().to_string(),
                            condition: "writable-scheduler-entry".into(),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }
}

fn is_writable_by(meta: &fs::Metadata, euid: u32, gids: &[u32]) -> bool {
    util::is_writable_by_euid(meta, euid, gids)
}

#[cfg(test)]
mod tests {
    use super::{check_writable_tree, read_text_bounded, scan_timers};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    #[test]
    fn scheduler_helpers_report_writable_tree_timer_and_companion() {
        let dir = tempfile::tempdir().unwrap();
        let timer = dir.path().join("sample.timer");
        let service = dir.path().join("sample.service");
        std::fs::write(&timer, b"[Timer]\nUnit=sample.service\n").unwrap();
        std::fs::write(&service, b"[Service]\nExecStart=/bin/true\n").unwrap();
        std::fs::set_permissions(&timer, std::fs::Permissions::from_mode(0o666)).unwrap();
        std::fs::set_permissions(&service, std::fs::Permissions::from_mode(0o666)).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut findings = Vec::new();
        let euid = crate::plugins::linux::util::euid();
        scan_timers(
            &dir.path().to_string_lossy(),
            euid,
            &[],
            &cancel,
            &mut findings,
        );
        check_writable_tree(
            &dir.path().to_string_lossy(),
            euid,
            &[],
            "fixture",
            &cancel,
            &mut findings,
        );
        assert!(findings
            .iter()
            .any(|f| f.condition == "writable-systemd-timer"));
        assert!(findings
            .iter()
            .any(|f| f.condition == "writable-timer-companion-unit"));
        assert!(findings
            .iter()
            .any(|f| f.condition == "writable-scheduler-entry"));
        assert!(read_text_bounded(&timer, 8).unwrap().len() <= 8);

        cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        let before = findings.len();
        scan_timers(
            &dir.path().to_string_lossy(),
            euid,
            &[],
            &cancel,
            &mut findings,
        );
        assert_eq!(findings.len(), before);
    }
}
