mod acl;
mod admin_sessions;
mod always_install_elevated;
mod app_control;
mod autoruns;
mod credentials;
mod dll_hijack;
mod endpoint_controls;
mod env_path;
mod privileges;
mod scheduled_tasks;
mod services;
mod uac;

use crate::core::plugin::Plugin;

/// Extract an executable path without truncating unquoted paths containing spaces.
pub(super) fn executable_path(command: &str) -> Option<String> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('"') {
        return rest.split('"').next().map(str::to_string);
    }
    let lower = trimmed.to_ascii_lowercase();
    let end = [".exe", ".com", ".bat", ".cmd"]
        .iter()
        .filter_map(|suffix| lower.find(suffix).map(|i| i + suffix.len()))
        .min();
    end.map(|i| trimmed[..i].to_string())
        .or_else(|| trimmed.split_whitespace().next().map(str::to_string))
}

/// Return a machine-readable, recommend-only LOLBAS annotation for a small
/// reviewed allowlist. This never turns the candidate into an executable
/// action and intentionally does not guess for unknown binaries.
pub(super) fn lolbas_annotation(command: &str) -> Option<String> {
    let path = executable_path(command)?;
    let binary = path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path.as_str())
        .trim()
        .to_ascii_lowercase();
    let (page, functions) = match binary.as_str() {
        "bitsadmin.exe" => ("Bitsadmin", "download,copy"),
        "certutil.exe" => ("Certutil", "download,encode,decode"),
        "cmstp.exe" => ("Cmstp", "execute"),
        "cscript.exe" => ("Cscript", "execute"),
        "forfiles.exe" => ("Forfiles", "execute"),
        "installutil.exe" => ("Installutil", "execute"),
        "msbuild.exe" => ("Msbuild", "execute"),
        "mshta.exe" => ("Mshta", "execute"),
        "msiexec.exe" => ("Msiexec", "execute"),
        "powershell.exe" => ("Powershell", "execute,download"),
        "regasm.exe" => ("Regasm", "execute"),
        "regsvcs.exe" => ("Regsvcs", "execute"),
        "regsvr32.exe" => ("Regsvr32", "execute,download"),
        "rundll32.exe" => ("Rundll32", "execute"),
        "wscript.exe" => ("Wscript", "execute"),
        _ => return None,
    };
    crate::core::opsec::lolbas_detail(&binary, page, functions)
}

pub fn plugins() -> Vec<&'static dyn Plugin> {
    vec![
        &app_control::AppControlPlugin,
        &privileges::PrivilegesPlugin,
        &services::ServicesPlugin,
        &scheduled_tasks::ScheduledTasksPlugin,
        &always_install_elevated::AlwaysInstallElevatedPlugin,
        &uac::UacPlugin,
        &dll_hijack::DllHijackPlugin,
        &credentials::CredentialsPlugin,
        &admin_sessions::AdminSessionsPlugin,
        &env_path::EnvPathPlugin,
        &autoruns::AutorunsPlugin,
        &endpoint_controls::EndpointControlsPlugin,
    ]
}

#[cfg(test)]
mod tests {
    use super::{executable_path, lolbas_annotation};

    #[test]
    fn preserves_spaces_in_unquoted_paths() {
        assert_eq!(
            executable_path(r"C:\Program Files\Vendor\service.exe -k run"),
            Some(r"C:\Program Files\Vendor\service.exe".into())
        );
        assert_eq!(
            executable_path(r#""C:\Program Files\Vendor\service.exe" -k run"#),
            Some(r"C:\Program Files\Vendor\service.exe".into())
        );
    }

    #[test]
    fn lolbas_annotations_are_allowlisted_and_recommend_only() {
        let annotation = lolbas_annotation(r#""C:\Windows\System32\certutil.exe" -urlcache"#)
            .expect("certutil is allowlisted");
        assert!(annotation.contains("lolbas.binary=certutil.exe"));
        assert!(annotation.contains("recommend_only=true"));
        assert!(lolbas_annotation(r"C:\Tools\ordinary.exe --check").is_none());
    }
}
