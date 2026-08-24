use anyhow::Result;
use std::path::Path;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct ServicesPlugin;

impl Plugin for ServicesPlugin {
    fn id(&self) -> &'static str {
        "windows.services"
    }
    fn name(&self) -> &'static str {
        "Service misconfigurations"
    }
    fn description(&self) -> &'static str {
        "Read-only service path, binary ACL, and service-object DACL checks"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["windows"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (name, image_path, account) in
            list_service_image_paths(ctx.cancel.as_ref(), ctx.noise_budget.max_walk_entries)?
        {
            if ctx.cancelled() {
                break;
            }
            let service_object = format!("service:{name}");
            let lolbas = super::lolbas_annotation(&image_path);
            if is_unquoted_path(&image_path) {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Enumeration,
                    severity: Severity::Low,
                    title: format!("Unquoted service path: {name}"),
                    detail: append_annotation(
                        format!("account={account} image_path={image_path}"),
                        lolbas.as_deref(),
                    ),
                    recommendation: "An unquoted path is exploitable only when an intermediate plant location is writable; review the read-only ACL results below.".into(),
                    noisy: false,
                    leaves_artifacts: false,
                    object: service_object.clone(),
                    condition: "unquoted-service-image-path".into(),
                    technique_id: if lolbas.is_some() { "lolbas" } else { "service-path" }.into(),
                    ..Default::default()
                });

                if let Some(bin) = super::executable_path(&image_path) {
                    for (candidate_exe, parent) in unquoted_plant_candidates(&bin) {
                        if ctx.cancelled() {
                            break;
                        }
                        let acl_state = super::acl::AclState::from_check(
                            super::acl::is_writable_for_current_user(Path::new(&parent)),
                        );
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
                            title: format!("Unquoted service candidate ({name}): {candidate_exe}"),
                            detail: format!(
                                "account={account} candidate_executable={candidate_exe} parent_directory={parent} directory_acl=current_token:{}",
                                acl_state.as_str()
                            ),
                            recommendation: if acl_state == super::acl::AclState::Writable {
                                "Quote the service image path and restrict the intermediate directory ACL; no binary was planted."
                                    .into()
                            } else {
                                "Confirm group-specific rights if the current-token ACL check is unavailable; do not plant a binary without explicit approval."
                                    .into()
                            },
                            noisy: false,
                            leaves_artifacts: false,
                            object: format!("{service_object}|candidate:{candidate_exe}"),
                            condition: format!(
                                "unquoted-plant-directory-acl:{}",
                                acl_state.as_str()
                            ),
                            ..Default::default()
                        };
                        let probe_allowed = ctx.probe_allowed_for(&candidate);
                        findings.push(candidate);
                        if probe_allowed {
                            let p = std::path::Path::new(&parent);
                            if p.is_dir() {
                                if let Ok(true) = crate::exploit::writable_probe(p) {
                                    findings.push(Finding {
                                        plugin: self.id().into(),
                                        kind: FindingKind::ExploitAttempt,
                                        severity: Severity::Critical,
                                        title: format!(
                                            "Confirmed writable unquoted parent ({name}): {parent}"
                                        ),
                                        detail: "Reversible marker write/delete succeeded.".into(),
                                        recommendation: "Planting/replacing service binaries requires ROE approval (--allow-techniques service-replace)."
                                            .into(),
                                        noisy: true,
                                        leaves_artifacts: false,
                                        object: format!(
                                            "{service_object}|candidate:{candidate_exe}"
                                        ),
                                        condition: "writable-unquoted-plant-directory-probe"
                                            .into(),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }
            }

            if let Some(bin) = super::executable_path(&image_path) {
                if super::acl::AclState::from_check(super::acl::is_writable_for_current_user(
                    Path::new(&bin),
                )) == super::acl::AclState::Writable
                {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Misconfiguration,
                        severity: if is_high_priv_account(&account) {
                            Severity::Critical
                        } else {
                            Severity::High
                        },
                        title: format!("Writable service binary: {name}"),
                        detail: append_annotation(
                            format!("account={account} binary={bin} binary_acl=current_token:writable"),
                            lolbas.as_deref(),
                        ),
                        recommendation: "Replacing a service binary is high-impact and noisy — opt in with --allow-techniques service-replace when ROE permits.".into(),
                        noisy: false,
                        leaves_artifacts: true,
                        object: format!("{service_object}|binary:{bin}"),
                        condition: "writable-service-binary-acl".into(),
                        technique_id: if lolbas.is_some() { "lolbas" } else { "service-replace" }.into(),
                        ..Default::default()
                    });
                    let tech = crate::exploit::TechniqueFamily::ServiceReplace;
                    let allowed = ctx.allow_techniques.allows(tech);
                    if allowed || ctx.auto_exploit {
                        findings.push(crate::exploit::technique_status(self.id(), tech, allowed));
                    }
                }
            }

            if let Some(access) = super::acl::service_object_access(&name) {
                let rights = access.dangerous_rights();
                if !rights.is_empty() {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Misconfiguration,
                        severity: if is_high_priv_account(&account) {
                            Severity::Critical
                        } else {
                            Severity::High
                        },
                        title: format!("Current token can modify service object: {name}"),
                        detail: format!(
                            "account={account} service_object_dacl=current_token:{}",
                            rights.join(",")
                        ),
                        recommendation: "Remove unnecessary service-object change-config, ownership, DACL, or delete rights from low-privilege principals. No service state was changed."
                            .into(),
                        noisy: false,
                        leaves_artifacts: false,
                        object: service_object,
                        condition: "dangerous-service-object-dacl-right".into(),
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
                title: "No unquoted/writable service issues found in scan".into(),
                detail: "Enumerated service ImagePath values, file ACLs, and readable service-object DACLs. Services whose READ_CONTROL access was denied were not claimed as checked."
                    .into(),
                recommendation: "Review any inaccessible service objects from an approved administrative context if complete DACL coverage is required."
                    .into(),
                noisy: false,
                leaves_artifacts: false,
                object: "windows-service-control-manager".into(),
                condition: "no-service-risk-observed".into(),
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn is_high_priv_account(account: &str) -> bool {
    let account = account.to_ascii_lowercase();
    account.contains("localsystem")
        || account.contains(r"nt authority\system")
        || account == "system"
}

fn append_annotation(mut detail: String, annotation: Option<&str>) -> String {
    if let Some(annotation) = annotation {
        detail.push_str("; ");
        detail.push_str(annotation);
    }
    detail
}

/// Candidate executable names and parent directories Windows may consider for
/// an unquoted service image path. The intended executable itself is excluded.
fn unquoted_plant_candidates(bin: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let normalized = bin.replace('/', "\\");
    if !normalized.contains(' ') {
        return out;
    }
    for (index, character) in normalized.char_indices() {
        if !character.is_whitespace() {
            continue;
        }
        let prefix = normalized[..index].trim_end_matches('\\');
        if prefix.is_empty() {
            continue;
        }
        let candidate = format!("{prefix}.exe");
        if candidate.eq_ignore_ascii_case(&normalized) {
            continue;
        }
        if let Some(separator) = candidate.rfind('\\') {
            let raw_parent = &candidate[..separator];
            let parent = if raw_parent.ends_with(':') {
                format!("{raw_parent}\\")
            } else {
                raw_parent.to_string()
            };
            out.push((candidate, parent));
        }
    }
    out.sort_by(|left, right| left.0.cmp(&right.0));
    out.dedup_by(|left, right| left.0.eq_ignore_ascii_case(&right.0));
    out
}

fn is_unquoted_path(image: &str) -> bool {
    let trimmed = image.trim();
    if trimmed.starts_with('"') {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    [".exe", ".com", ".bat", ".cmd"]
        .iter()
        .filter_map(|extension| lower.find(extension))
        .min()
        .map(|end| trimmed[..end].chars().any(char::is_whitespace))
        .unwrap_or(false)
}

#[cfg(windows)]
fn list_service_image_paths(
    cancel: &std::sync::atomic::AtomicBool,
    max_entries: usize,
) -> Result<Vec<(String, String, String)>> {
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    let mut out = Vec::new();
    unsafe {
        let sub = to_wide(r"SYSTEM\CurrentControlSet\Services");
        let mut hkey = ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            anyhow::bail!("RegOpenKeyExW Services failed");
        }

        let mut index = 0u32;
        loop {
            if cancel.load(std::sync::atomic::Ordering::SeqCst) || index as usize >= max_entries {
                break;
            }
            let mut name_buf = vec![0u16; 256];
            let mut name_len = name_buf.len() as u32;
            let status = RegEnumKeyExW(
                hkey,
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if status != 0 {
                break;
            }
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let path_key = to_wide(&format!(r"SYSTEM\CurrentControlSet\Services\{name}"));
            let mut sk = ptr::null_mut();
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, path_key.as_ptr(), 0, KEY_READ, &mut sk) == 0 {
                if let Some(val) = reg_query_string(sk, "ImagePath") {
                    let account = reg_query_string(sk, "ObjectName")
                        .unwrap_or_else(|| "(service account unavailable)".into());
                    out.push((name, val, account));
                }
                RegCloseKey(sk);
            }
            index += 1;
            if index > 2000 {
                break;
            }
        }
        RegCloseKey(hkey);
    }
    Ok(out)
}

#[cfg(windows)]
fn reg_query_string(
    hkey: windows_sys::Win32::System::Registry::HKEY,
    name: &str,
) -> Option<String> {
    use std::ptr;
    use windows_sys::Win32::System::Registry::RegQueryValueExW;
    unsafe {
        let wname = to_wide(name);
        let mut ty = 0u32;
        let mut len = 0u32;
        if RegQueryValueExW(
            hkey,
            wname.as_ptr(),
            ptr::null_mut(),
            &mut ty,
            ptr::null_mut(),
            &mut len,
        ) != 0
        {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        if RegQueryValueExW(
            hkey,
            wname.as_ptr(),
            ptr::null_mut(),
            &mut ty,
            buf.as_mut_ptr(),
            &mut len,
        ) != 0
        {
            return None;
        }
        // REG_SZ / REG_EXPAND_SZ
        let u16s: Vec<u16> = buf
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|c| *c != 0)
            .collect();
        Some(String::from_utf16_lossy(&u16s))
    }
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(not(windows))]
fn list_service_image_paths(
    _cancel: &std::sync::atomic::AtomicBool,
    _max_entries: usize,
) -> Result<Vec<(String, String, String)>> {
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::{is_unquoted_path, unquoted_plant_candidates};
    use crate::plugins::windows::acl::AclState;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct ServiceAclFixture {
        image_path: String,
        acl_writable: Option<bool>,
        expected_unquoted: bool,
        expected_acl: String,
    }

    #[test]
    fn detects_unquoted_spaced_service_paths() {
        assert!(is_unquoted_path(
            r"C:\Program Files\Vendor\service.exe -k run"
        ));
        assert!(!is_unquoted_path(
            r#""C:\Program Files\Vendor\service.exe" -k run"#
        ));
        assert!(!is_unquoted_path(r"C:\Windows\System32\service.exe"));
    }

    #[test]
    fn derives_only_truncated_unquoted_executable_candidates() {
        assert_eq!(
            unquoted_plant_candidates(r"C:\Program Files\Acme Tools\service.exe"),
            vec![
                (
                    r"C:\Program Files\Acme.exe".into(),
                    r"C:\Program Files".into()
                ),
                (r"C:\Program.exe".into(), r"C:\".into()),
            ]
        );
    }

    #[test]
    fn golden_service_path_acl_interpretation() {
        let fixtures: Vec<ServiceAclFixture> = serde_json::from_str(include_str!(
            "../../../tests/fixtures/windows/service_path_acl_cases.json"
        ))
        .unwrap();
        for fixture in fixtures {
            assert_eq!(
                is_unquoted_path(&fixture.image_path),
                fixture.expected_unquoted,
                "{}",
                fixture.image_path
            );
            assert_eq!(
                AclState::from_check(fixture.acl_writable).as_str(),
                fixture.expected_acl
            );
        }
    }
}
