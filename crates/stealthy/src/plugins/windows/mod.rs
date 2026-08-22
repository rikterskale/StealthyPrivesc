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
    use super::executable_path;

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
}
