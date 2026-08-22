use crate::core::types::IdentityInfo;

/// Enumerate current identity with minimal process spawning.
pub fn current() -> IdentityInfo {
    #[cfg(target_os = "linux")]
    {
        linux_identity()
    }
    #[cfg(target_os = "windows")]
    {
        windows_identity()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        IdentityInfo {
            username: whoami_env(),
            uid: None,
            gid: None,
            groups: vec![],
            is_elevated: false,
            elevation_source: "unsupported".into(),
            token_context: "unknown".into(),
            hostname: hostname(),
        }
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

fn whoami_env() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

#[cfg(target_os = "linux")]
fn linux_identity() -> IdentityInfo {
    let uid = linux_geteuid();
    let gid = linux_getegid();
    let username = resolve_user(uid).unwrap_or_else(whoami_env);
    let groups = read_groups();
    let is_elevated = uid == 0;

    IdentityInfo {
        username,
        uid: Some(uid),
        gid: Some(gid),
        groups,
        is_elevated,
        elevation_source: "linux_euid".into(),
        token_context: format!("euid={uid} egid={}", linux_getegid()),
        hostname: hostname(),
    }
}

#[cfg(target_os = "linux")]
fn linux_geteuid() -> u32 {
    unsafe { libc_geteuid() }
}

#[cfg(target_os = "linux")]
fn linux_getegid() -> u32 {
    unsafe { libc_getegid() }
}

// Minimal libc bindings — avoids pulling the full `libc` crate for two calls.
#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn geteuid() -> u32;
    fn getegid() -> u32;
}

#[cfg(target_os = "linux")]
unsafe fn libc_geteuid() -> u32 {
    geteuid()
}

#[cfg(target_os = "linux")]
unsafe fn libc_getegid() -> u32 {
    getegid()
}

#[cfg(target_os = "linux")]
fn resolve_user(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 && parts[2].parse::<u32>().ok() == Some(uid) {
            return Some(parts[0].to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_groups() -> Vec<String> {
    // Prefer /proc/self/status for groups without spawning `id`.
    let mut gids = Vec::new();
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Groups:") {
                for tok in rest.split_whitespace() {
                    if let Ok(g) = tok.parse::<u32>() {
                        gids.push(g);
                    }
                }
            }
        }
    }

    let names = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let mut out = Vec::new();
    for gid in gids {
        let mut found = false;
        for line in names.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && parts[2].parse::<u32>().ok() == Some(gid) {
                out.push(parts[0].to_string());
                found = true;
                break;
            }
        }
        if !found {
            out.push(gid.to_string());
        }
    }
    out
}

#[cfg(target_os = "windows")]
fn windows_identity() -> IdentityInfo {
    let username = whoami_env();
    let is_elevated = windows_token_is_elevated().unwrap_or(false);

    IdentityInfo {
        username,
        uid: None,
        gid: None,
        groups: vec![],
        is_elevated,
        elevation_source: "windows_token_elevation".into(),
        token_context: if is_elevated {
            "token_is_elevated=true".into()
        } else {
            "token_is_elevated=false_or_unavailable".into()
        },
        hostname: hostname(),
    }
}

#[cfg(target_os = "windows")]
fn windows_token_is_elevated() -> Option<bool> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == FALSE {
            return None;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut TOKEN_ELEVATION as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        ) != FALSE;
        CloseHandle(token);
        ok.then_some(elevation.TokenIsElevated != 0)
    }
}
