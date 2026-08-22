use crate::core::types::OsInfo;

/// Detect OS without spawning helper processes where possible.
pub fn detect() -> OsInfo {
    let family = std::env::consts::FAMILY.to_string();
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let version_hint = version_hint();

    OsInfo {
        family,
        os,
        arch,
        version_hint,
    }
}

#[cfg(target_os = "linux")]
fn version_hint() -> String {
    // Prefer /etc/os-release over `uname` to avoid an extra execve/audit event.
    if let Ok(text) = std::fs::read_to_string("/etc/os-release") {
        let mut pretty = None;
        let mut version = None;
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
                pretty = Some(v.trim_matches('"').to_string());
            }
            if let Some(v) = line.strip_prefix("VERSION_ID=") {
                version = Some(v.trim_matches('"').to_string());
            }
        }
        if let Some(p) = pretty {
            return p;
        }
        if let Some(v) = version {
            return v;
        }
    }
    std::fs::read_to_string("/proc/version")
        .unwrap_or_else(|_| "linux-unknown".into())
        .lines()
        .next()
        .unwrap_or("linux-unknown")
        .to_string()
}

#[cfg(target_os = "windows")]
fn version_hint() -> String {
    // Avoid cmd.exe / ver. Use env as a quiet hint; plugins deepen this later.
    std::env::var("OS").unwrap_or_else(|_| "Windows".into())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn version_hint() -> String {
    "unsupported".into()
}
