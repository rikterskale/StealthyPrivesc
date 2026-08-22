use std::fs;
use std::os::unix::fs::PermissionsExt;

/// True if the current process is in the named group (/etc/group + /proc/self/status).
pub fn user_in_group(name: &str) -> bool {
    let Some(gid) = group_gid(name) else {
        return false;
    };
    current_gids().contains(&gid)
}

pub fn group_gid(name: &str) -> Option<u32> {
    let group = fs::read_to_string("/etc/group").ok()?;
    for line in group.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 && parts[0] == name {
            return parts[2].parse().ok();
        }
    }
    None
}

pub fn current_gids() -> Vec<u32> {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return Vec::new();
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Groups:") {
            return rest
                .split_whitespace()
                .filter_map(|t| t.parse().ok())
                .collect();
        }
    }
    Vec::new()
}

pub fn current_group_names() -> Vec<String> {
    let gids = current_gids();
    let Ok(group) = fs::read_to_string("/etc/group") else {
        return gids.iter().map(|g| g.to_string()).collect();
    };
    let mut out = Vec::new();
    for gid in gids {
        let mut found = false;
        for line in group.lines() {
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

pub fn is_writable_by_euid(meta: &fs::Metadata, euid: u32, gids: &[u32]) -> bool {
    let mode = meta.permissions().mode();
    if euid == 0 {
        return false;
    }
    use std::os::unix::fs::MetadataExt;
    if meta.uid() == euid && mode & 0o200 != 0 {
        return true;
    }
    if gids.contains(&meta.gid()) && mode & 0o020 != 0 {
        return true;
    }
    mode & 0o002 != 0
}

#[cfg(test)]
mod tests {
    use super::is_writable_by_euid;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn recognizes_group_writable_files_for_member() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("group-writable");
        std::fs::write(&path, b"x").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o660);
        std::fs::set_permissions(&path, perms).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert!(is_writable_by_euid(&meta, meta.uid() + 1, &[meta.gid()]));
    }
}

pub fn euid() -> u32 {
    unsafe { geteuid() }
}

unsafe extern "C" {
    fn geteuid() -> u32;
}
