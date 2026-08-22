use std::path::Path;

/// Best-effort ACL evaluation for an existing file.
///
/// Windows access checks are identity- and token-dependent. `icacls` gives us
/// a native, read-only view without creating a probe file; if it is unavailable
/// callers should treat the result as unknown rather than safe.
pub(super) fn is_writable_for_current_user(path: &Path) -> Option<bool> {
    #[cfg(windows)]
    {
        if let Some(result) = native_access_check(path) {
            return Some(result);
        }
        let output = std::process::Command::new("icacls")
            .arg(path)
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let username = std::env::var("USERNAME")
            .unwrap_or_default()
            .to_ascii_lowercase();
        for line in text.lines().skip(1) {
            let lower = line.to_ascii_lowercase();
            let principal = username.is_empty()
                || lower.contains(&username)
                || lower.contains("everyone")
                || lower.contains("authenticated users")
                || lower.contains("\u{5c}users:");
            if !principal {
                continue;
            }
            if ["(f)", "(m)", "(w)", "(wd)", "(ad)", "(wa)", "(dc)"]
                .iter()
                .any(|right| lower.contains(right))
            {
                return Some(true);
            }
        }
        Some(false)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}

#[cfg(windows)]
fn native_access_check(path: &Path) -> Option<bool> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, FALSE};
    use windows_sys::Win32::Security::Authorization::{
        AccessCheck, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GENERIC_MAPPING, PSECURITY_DESCRIPTOR, TOKEN_QUERY,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let name: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let status = GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        );
        if status != 0 || descriptor.is_null() {
            return None;
        }

        let mut token = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == FALSE {
            LocalFree(descriptor as _);
            return None;
        }
        let mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS,
        };
        let mut privileges = std::mem::zeroed();
        let mut privilege_len = std::mem::size_of_val(&privileges) as u32;
        let mut granted = 0u32;
        let mut allowed = FALSE;
        let ok = AccessCheck(
            descriptor,
            token,
            FILE_GENERIC_WRITE,
            &mapping,
            &mut privileges,
            &mut privilege_len,
            &mut granted,
            &mut allowed,
        ) != FALSE;
        CloseHandle(token);
        LocalFree(descriptor as _);
        ok.then_some(allowed != FALSE)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::native_access_check;
    use std::path::Path;

    #[test]
    fn native_acl_check_reports_missing_paths_as_unknown() {
        let path = Path::new(r"C:\__stealthy_acl_validation_missing__\target.bin");
        assert_eq!(native_access_check(path), None);
    }
}
