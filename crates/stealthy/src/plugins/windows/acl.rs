use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AclState {
    Writable,
    NotWritable,
    Unavailable,
}

impl AclState {
    pub(super) fn from_check(check: Option<bool>) -> Self {
        match check {
            Some(true) => Self::Writable,
            Some(false) => Self::NotWritable,
            None => Self::Unavailable,
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Writable => "writable",
            Self::NotWritable => "not_writable",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ServiceObjectAccess {
    pub(super) change_config: bool,
    pub(super) write_dac: bool,
    pub(super) write_owner: bool,
    pub(super) delete: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct TaskObjectAccess {
    pub(super) write_dac: bool,
    pub(super) write_owner: bool,
    pub(super) delete: bool,
}

impl TaskObjectAccess {
    pub(super) fn dangerous_rights(&self) -> Vec<&'static str> {
        let mut rights = Vec::new();
        if self.write_dac {
            rights.push("WRITE_DAC");
        }
        if self.write_owner {
            rights.push("WRITE_OWNER");
        }
        if self.delete {
            rights.push("DELETE");
        }
        rights
    }
}

impl ServiceObjectAccess {
    pub(super) fn dangerous_rights(&self) -> Vec<&'static str> {
        let mut rights = Vec::new();
        if self.change_config {
            rights.push("SERVICE_CHANGE_CONFIG");
        }
        if self.write_dac {
            rights.push("WRITE_DAC");
        }
        if self.write_owner {
            rights.push("WRITE_OWNER");
        }
        if self.delete {
            rights.push("DELETE");
        }
        rights
    }
}

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
        let output = crate::core::command::trusted_command("icacls")
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
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GENERIC_MAPPING, PSECURITY_DESCRIPTOR,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };

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

        let mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS,
        };
        let result = descriptor_access_check(descriptor, FILE_GENERIC_WRITE, &mapping);
        LocalFree(descriptor as _);
        result
    }
}

/// Read and evaluate the service object's DACL against the current token.
/// This opens the SCM and service with read-control rights only and never
/// changes service configuration or security.
#[cfg(windows)]
pub(super) fn service_object_access(service_name: &str) -> Option<ServiceObjectAccess> {
    use std::ptr;
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GENERIC_MAPPING, PSECURITY_DESCRIPTOR,
    };
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceObjectSecurity,
        SC_MANAGER_CONNECT, SERVICE_ALL_ACCESS, SERVICE_CHANGE_CONFIG,
        SERVICE_ENUMERATE_DEPENDENTS, SERVICE_INTERROGATE, SERVICE_PAUSE_CONTINUE,
        SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STOP,
        SERVICE_USER_DEFINED_CONTROL,
    };

    const DELETE_ACCESS: u32 = 0x0001_0000;
    const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
    const WRITE_DAC_ACCESS: u32 = 0x0004_0000;
    const WRITE_OWNER_ACCESS: u32 = 0x0008_0000;
    const STANDARD_RIGHTS_READ: u32 = READ_CONTROL_ACCESS;
    const STANDARD_RIGHTS_WRITE: u32 = READ_CONTROL_ACCESS;
    const STANDARD_RIGHTS_EXECUTE: u32 = READ_CONTROL_ACCESS;

    let service_name: Vec<u16> = service_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let manager = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return None;
        }
        let service = OpenServiceW(manager, service_name.as_ptr(), READ_CONTROL_ACCESS);
        if service.is_null() {
            CloseServiceHandle(manager);
            return None;
        }

        let mut needed = 0u32;
        QueryServiceObjectSecurity(
            service,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            0,
            &mut needed,
        );
        if needed == 0 {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return None;
        }
        let mut descriptor = vec![0u8; needed as usize];
        let ok = QueryServiceObjectSecurity(
            service,
            DACL_SECURITY_INFORMATION,
            descriptor.as_mut_ptr() as PSECURITY_DESCRIPTOR,
            needed,
            &mut needed,
        ) != 0;
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        if !ok {
            return None;
        }

        let mapping = GENERIC_MAPPING {
            GenericRead: STANDARD_RIGHTS_READ
                | SERVICE_QUERY_CONFIG
                | SERVICE_QUERY_STATUS
                | SERVICE_INTERROGATE
                | SERVICE_ENUMERATE_DEPENDENTS,
            GenericWrite: STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG,
            GenericExecute: STANDARD_RIGHTS_EXECUTE
                | SERVICE_START
                | SERVICE_STOP
                | SERVICE_PAUSE_CONTINUE
                | SERVICE_USER_DEFINED_CONTROL,
            GenericAll: SERVICE_ALL_ACCESS,
        };
        let descriptor = descriptor.as_mut_ptr() as PSECURITY_DESCRIPTOR;
        Some(ServiceObjectAccess {
            change_config: descriptor_access_check(descriptor, SERVICE_CHANGE_CONFIG, &mapping)?,
            write_dac: descriptor_access_check(descriptor, WRITE_DAC_ACCESS, &mapping)?,
            write_owner: descriptor_access_check(descriptor, WRITE_OWNER_ACCESS, &mapping)?,
            delete: descriptor_access_check(descriptor, DELETE_ACCESS, &mapping)?,
        })
    }
}

#[cfg(not(windows))]
pub(super) fn service_object_access(_service_name: &str) -> Option<ServiceObjectAccess> {
    None
}

/// Read the Task Scheduler's registry-backed security descriptor and evaluate
/// standard object-control rights against the current token. This is a
/// read-only best-effort check; it does not infer task-specific write/execute
/// rights when the descriptor is unavailable.
#[cfg(windows)]
pub(super) fn task_object_access(task_name: &str) -> Option<TaskObjectAccess> {
    use std::ptr;
    use windows_sys::Win32::Security::{GENERIC_MAPPING, PSECURITY_DESCRIPTOR};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_BINARY,
    };

    const DELETE_ACCESS: u32 = 0x0001_0000;
    const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
    const WRITE_DAC_ACCESS: u32 = 0x0004_0000;
    const WRITE_OWNER_ACCESS: u32 = 0x0008_0000;
    const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

    let normalized = task_name.trim_matches(['\\', '/']).replace('/', "\\");
    if normalized.is_empty() {
        return None;
    }
    let key_path = format!(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\{normalized}"
    );
    let key_path: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();
    let value_name: Vec<u16> = "SD".encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut key = ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return None;
        }
        let mut value_type = 0u32;
        let mut length = 0u32;
        let size_status = RegQueryValueExW(
            key,
            value_name.as_ptr(),
            ptr::null_mut(),
            &mut value_type,
            ptr::null_mut(),
            &mut length,
        );
        if size_status != 0 || value_type != REG_BINARY || length == 0 {
            RegCloseKey(key);
            return None;
        }
        let mut descriptor = vec![0u8; length as usize];
        let read_status = RegQueryValueExW(
            key,
            value_name.as_ptr(),
            ptr::null_mut(),
            &mut value_type,
            descriptor.as_mut_ptr(),
            &mut length,
        );
        RegCloseKey(key);
        if read_status != 0 {
            return None;
        }

        let mapping = GENERIC_MAPPING {
            GenericRead: READ_CONTROL_ACCESS,
            GenericWrite: READ_CONTROL_ACCESS | WRITE_DAC_ACCESS | WRITE_OWNER_ACCESS,
            GenericExecute: READ_CONTROL_ACCESS | SYNCHRONIZE_ACCESS,
            GenericAll: DELETE_ACCESS
                | READ_CONTROL_ACCESS
                | WRITE_DAC_ACCESS
                | WRITE_OWNER_ACCESS
                | SYNCHRONIZE_ACCESS,
        };
        let descriptor = descriptor.as_mut_ptr() as PSECURITY_DESCRIPTOR;
        Some(TaskObjectAccess {
            write_dac: descriptor_access_check(descriptor, WRITE_DAC_ACCESS, &mapping)?,
            write_owner: descriptor_access_check(descriptor, WRITE_OWNER_ACCESS, &mapping)?,
            delete: descriptor_access_check(descriptor, DELETE_ACCESS, &mapping)?,
        })
    }
}

#[cfg(not(windows))]
pub(super) fn task_object_access(_task_name: &str) -> Option<TaskObjectAccess> {
    None
}

#[cfg(windows)]
unsafe fn descriptor_access_check(
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    desired_access: u32,
    mapping: &windows_sys::Win32::Security::GENERIC_MAPPING,
) -> Option<bool> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE};
    use windows_sys::Win32::Security::{
        AccessCheck, DuplicateToken, SecurityImpersonation, PRIVILEGE_SET, TOKEN_DUPLICATE,
        TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut primary = ptr::null_mut();
    if OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_QUERY | TOKEN_DUPLICATE,
        &mut primary,
    ) == FALSE
    {
        return None;
    }
    let mut token = ptr::null_mut();
    let duplicated = DuplicateToken(primary, SecurityImpersonation, &mut token) != FALSE;
    CloseHandle(primary);
    if !duplicated {
        return None;
    }

    let mut privilege_buffer = [0usize; 128];
    let mut privilege_len = std::mem::size_of_val(&privilege_buffer) as u32;
    let mut granted = 0u32;
    let mut allowed = FALSE;
    let ok = AccessCheck(
        descriptor,
        token,
        desired_access,
        mapping,
        privilege_buffer.as_mut_ptr() as *mut PRIVILEGE_SET,
        &mut privilege_len,
        &mut granted,
        &mut allowed,
    ) != FALSE;
    CloseHandle(token);
    ok.then_some(allowed != FALSE)
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

#[cfg(test)]
mod portable_tests {
    use super::{AclState, ServiceObjectAccess, TaskObjectAccess};

    #[test]
    fn acl_state_preserves_unknown_results() {
        assert_eq!(AclState::from_check(Some(true)), AclState::Writable);
        assert_eq!(AclState::from_check(Some(false)), AclState::NotWritable);
        assert_eq!(AclState::from_check(None), AclState::Unavailable);
    }

    #[test]
    fn service_rights_report_only_observed_access() {
        let access = ServiceObjectAccess {
            change_config: true,
            write_owner: true,
            ..Default::default()
        };
        assert_eq!(
            access.dangerous_rights(),
            vec!["SERVICE_CHANGE_CONFIG", "WRITE_OWNER"]
        );
    }

    #[test]
    fn task_rights_report_only_observed_access() {
        let access = TaskObjectAccess {
            write_dac: true,
            delete: true,
            ..Default::default()
        };
        assert_eq!(access.dangerous_rights(), vec!["WRITE_DAC", "DELETE"]);
    }
}
