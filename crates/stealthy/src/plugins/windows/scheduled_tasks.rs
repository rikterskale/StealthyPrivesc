use anyhow::Result;
use std::path::Path;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct ScheduledTasksPlugin;

impl Plugin for ScheduledTasksPlugin {
    fn id(&self) -> &'static str {
        "windows.scheduled_tasks"
    }
    fn name(&self) -> &'static str {
        "Scheduled tasks"
    }
    fn description(&self) -> &'static str {
        "Enumerate task XML plus task-file, action-file, and registry-backed task-object ACLs"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["windows"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let roots = [r"C:\Windows\System32\Tasks", r"C:\Windows\SysWOW64\Tasks"];
        let mut remaining = ctx.noise_budget.max_walk_entries;

        for root in roots {
            if ctx.cancelled() || remaining == 0 {
                break;
            }
            walk_tasks(
                Path::new(root),
                Path::new(root),
                3,
                &mut remaining,
                &mut findings,
                ctx,
            );
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No readable scheduled task XML findings".into(),
                detail: "Task store may be inaccessible without elevation.".into(),
                recommendation: "Use schtasks /query when process creation is acceptable.".into(),
                noisy: false,
                leaves_artifacts: false,
                object: "windows-task-file-store".into(),
                condition: "no-readable-task-finding".into(),
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn walk_tasks(
    root: &Path,
    dir: &Path,
    depth: u32,
    remaining: &mut usize,
    findings: &mut Vec<Finding>,
    ctx: &PluginContext<'_>,
) {
    if ctx.cancelled() || depth == 0 || *remaining == 0 || !dir.is_dir() {
        return;
    }
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        if ctx.cancelled() || *remaining == 0 {
            return;
        }
        *remaining -= 1;
        let path = entry.path();
        if path.is_dir() {
            walk_tasks(root, &path, depth - 1, remaining, findings, ctx);
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            let elevated = text.contains("<RunLevel>HighestAvailable</RunLevel>")
                || text.contains("S-1-5-18")
                || text.to_lowercase().contains("nt authority\\system");
            let user_context = text.contains("<UserId>") || text.contains("<Principal");
            let task_acl =
                super::acl::AclState::from_check(super::acl::is_writable_for_current_user(&path));
            let task_name = path
                .strip_prefix(root)
                .ok()
                .map(|relative| relative.to_string_lossy().replace('/', "\\"));
            let object_access = task_name
                .as_deref()
                .and_then(super::acl::task_object_access);
            let object_rights = object_access
                .as_ref()
                .map(|access| access.dangerous_rights())
                .unwrap_or_default();
            if elevated || user_context {
                findings.push(Finding {
                    plugin: "windows.scheduled_tasks".into(),
                    kind: FindingKind::Enumeration,
                    severity: if elevated {
                        Severity::Low
                    } else {
                        Severity::Info
                    },
                    title: format!("Scheduled task XML: {}", path.display()),
                    detail: format!(
                        "elevated_principal={elevated} user_context_present={user_context} task_file_acl=current_token:{} task_scheduler_object_dacl={}",
                        task_acl.as_str(),
                        if object_access.is_some() { "evaluated" } else { "unavailable" }
                    ),
                    recommendation: "Review writable task-file, action, and task-object findings below. Registry-backed task security and file ACL results are reported separately."
                        .into(),
                    noisy: false,
                    leaves_artifacts: false,
                    object: path.display().to_string(),
                    condition: if elevated {
                        "elevated-task-definition"
                    } else {
                        "task-principal-present"
                    }
                    .into(),
                    ..Default::default()
                });
            }
            if !object_rights.is_empty() {
                findings.push(Finding {
                    plugin: "windows.scheduled_tasks".into(),
                    kind: FindingKind::Misconfiguration,
                    severity: if elevated {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    title: format!("Current token can control scheduled-task security: {}", path.display()),
                    detail: format!(
                        "task_name={} task_scheduler_object_dacl=current_token:{}",
                        task_name.as_deref().unwrap_or("(unknown)"),
                        object_rights.join(",")
                    ),
                    recommendation: "Remove unnecessary task-object ownership, DACL, or delete rights from low-privilege principals. No task was changed."
                        .into(),
                    noisy: false,
                    leaves_artifacts: false,
                    object: format!("scheduled-task:{}", task_name.as_deref().unwrap_or("unknown")),
                    condition: "dangerous-task-object-dacl-right".into(),
                    ..Default::default()
                });
            }
            if task_acl == super::acl::AclState::Writable {
                findings.push(Finding {
                    plugin: "windows.scheduled_tasks".into(),
                    kind: FindingKind::Misconfiguration,
                    severity: if elevated {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    title: format!("Writable scheduled-task definition: {}", path.display()),
                    detail: format!(
                        "task_file_acl=current_token:writable task_scheduler_object_dacl={}",
                        if object_access.is_some() { "evaluated" } else { "unavailable" }
                    ),
                    recommendation: "Restrict the task definition file ACL and review the separately reported Task Scheduler object security. No task was changed."
                        .into(),
                    noisy: false,
                    leaves_artifacts: false,
                    object: path.display().to_string(),
                    condition: "writable-task-definition-file-acl".into(),
                    ..Default::default()
                });
            }
            for cmd in extract_commands(&text) {
                if ctx.cancelled() {
                    return;
                }
                let bin = strip_quotes_path(&cmd);
                let lolbas = super::lolbas_annotation(&cmd);
                if !bin.is_empty()
                    && std::path::Path::new(&bin).is_file()
                    && super::acl::is_writable_for_current_user(Path::new(&bin)).unwrap_or(false)
                {
                    findings.push(Finding {
                        plugin: "windows.scheduled_tasks".into(),
                        kind: FindingKind::Misconfiguration,
                        severity: if elevated {
                            Severity::Critical
                        } else {
                            Severity::High
                        },
                        title: format!("Writable task action binary: {bin}"),
                        detail: append_annotation(
                            format!("task={} command={cmd}", path.display()),
                            lolbas.as_deref(),
                        ),
                        recommendation: "High-priv tasks with writable actions are classic privesc — modify only with approval."
                            .into(),
                        noisy: false,
                        leaves_artifacts: true,
                        object: format!("task:{}|action:{bin}", path.display()),
                        condition: "writable-task-action-file-acl".into(),
                        technique_id: if lolbas.is_some() { "lolbas" } else { "task-action" }.into(),
                        ..Default::default()
                    });
                }
            }
        }
    }
}

fn append_annotation(mut detail: String, annotation: Option<&str>) -> String {
    if let Some(annotation) = annotation {
        detail.push_str("; ");
        detail.push_str(annotation);
    }
    detail
}

fn extract_commands(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<Command>") {
        rest = &rest[start + "<Command>".len()..];
        if let Some(end) = rest.find("</Command>") {
            let cmd = rest[..end].trim().to_string();
            if !cmd.is_empty() {
                out.push(cmd);
            }
            rest = &rest[end + "</Command>".len()..];
        } else {
            break;
        }
    }
    out
}

fn strip_quotes_path(cmd: &str) -> String {
    super::executable_path(cmd).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::extract_commands;

    #[test]
    fn extracts_multiple_task_actions() {
        let xml = r#"<Task><Actions><Exec><Command>C:\Tools\one.exe</Command></Exec><Exec><Command>"C:\Program Files\Two\two.exe"</Command></Exec></Actions></Task>"#;
        assert_eq!(
            extract_commands(xml),
            vec![
                r"C:\Tools\one.exe".to_string(),
                r#""C:\Program Files\Two\two.exe""#.to_string()
            ]
        );
    }
}
