use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

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

/// Conservative effective-write check for an existing path.
///
/// This follows the target metadata and evaluates owner/group/other mode bits.
/// POSIX ACLs are intentionally reported as unknown until an ACL-aware backend
/// is available; callers should not treat a false result as proof of safety.
pub fn is_effectively_writable(path: &Path, euid: u32, gids: &[u32]) -> Option<bool> {
    let meta = fs::metadata(path).ok()?;
    if is_writable_by_euid(&meta, euid, gids) {
        return Some(true);
    }
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default();
    if let Some(acl) = read_acl(path) {
        return Some(acl_text_allows_write(
            &acl,
            &username,
            &current_group_names(),
        ));
    }
    Some(false)
}

fn read_acl(path: &Path) -> Option<String> {
    let output = std::process::Command::new("getfacl")
        .args(["--absolute-names", "-cp"])
        .arg(path)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn acl_text_allows_write(text: &str, username: &str, groups: &[String]) -> bool {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let mask_allows_write = lines
        .iter()
        .find_map(|line| {
            let (kind, rest) = line.split_once(':')?;
            let (name, perms) = rest.split_once(':')?;
            (kind == "mask" && name.is_empty()).then(|| perms.as_bytes().get(1) == Some(&b'w'))
        })
        .unwrap_or(true);
    for line in lines {
        let Some((kind, rest)) = line.split_once(':') else {
            continue;
        };
        let Some((name, perms)) = rest.split_once(':') else {
            continue;
        };
        if kind == "mask" {
            continue;
        }
        let matches = match kind {
            "user" if !name.is_empty() => name == username,
            "group" if !name.is_empty() => groups.iter().any(|group| group == name),
            "other" => true,
            _ => false,
        };
        if matches && perms.as_bytes().get(1) == Some(&b'w') {
            return kind == "other" || mask_allows_write;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{acl_text_allows_write, is_effectively_writable, is_writable_by_euid};
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

    #[test]
    fn effective_check_handles_existing_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("writable");
        std::fs::write(&path, b"x").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(is_effectively_writable(&path, meta.uid(), &[]), Some(true));
    }

    #[test]
    fn acl_parser_respects_named_groups_and_mask() {
        let acl = "user::rwx\ngroup::r-x\ngroup:deploy:rwx\nmask::r-x\nother::---\n";
        assert!(!acl_text_allows_write(acl, "alice", &["deploy".into()]));
        let acl = acl.replace("mask::r-x", "mask::rwx");
        assert!(acl_text_allows_write(&acl, "alice", &["deploy".into()]));
    }
}

pub fn euid() -> u32 {
    unsafe { geteuid() }
}

unsafe extern "C" {
    fn geteuid() -> u32;
}
