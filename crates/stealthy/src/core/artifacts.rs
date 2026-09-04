//! Run-scoped artifact ledger and cleanup helpers.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::output;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub run_id: String,
    pub kind: String,
    pub path: String,
    pub created_at_unix: u64,
    pub removable: bool,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArtifactLedger {
    pub schema_version: String,
    pub run_id: String,
    #[serde(default)]
    pub integrity: String,
    pub entries: Vec<ArtifactRecord>,
}

impl ArtifactLedger {
    pub fn new(run_id: impl Into<String>) -> Self {
        Self {
            schema_version: "1".into(),
            run_id: run_id.into(),
            integrity: String::new(),
            entries: Vec::new(),
        }
    }

    pub fn register(
        &mut self,
        kind: &str,
        path: impl AsRef<Path>,
        removable: bool,
        notes: impl Into<String>,
    ) {
        let created_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        self.entries.push(ArtifactRecord {
            run_id: self.run_id.clone(),
            kind: kind.into(),
            path: path.as_ref().display().to_string(),
            created_at_unix,
            removable,
            notes: notes.into(),
        });
    }
}

pub fn default_ledger_dir() -> PathBuf {
    PathBuf::from(".cache-run")
}

pub fn ledger_path(dir: &Path, run_id: &str) -> Result<PathBuf> {
    validate_run_id(run_id)?;
    Ok(dir.join(format!("{run_id}.json")))
}

pub fn save_ledger(dir: &Path, ledger: &ArtifactLedger) -> Result<PathBuf> {
    validate_run_id(&ledger.run_id)?;
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    restrict_dir_permissions(dir)?;
    let key = load_or_create_key(dir)?;
    let mut unsigned = ledger.clone();
    unsigned.schema_version = "2".into();
    unsigned.integrity.clear();
    let unsigned_body = serde_json::to_vec_pretty(&unsigned)?;
    unsigned.integrity = integrity_tag(&key, &unsigned_body);
    let body = serde_json::to_vec_pretty(&unsigned)?;
    let path = ledger_path(dir, &ledger.run_id)?;
    atomic_private_write(&path, &body)?;
    Ok(path)
}

/// Write sensitive JSON with restrictive permissions and crash-safe replacement.
pub fn write_private_atomic(path: &Path, body: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let suffix = rand::random::<u64>();
    let temp = parent.join(format!(
        ".{}.tmp-{suffix:016x}",
        path.file_name().unwrap().to_string_lossy()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .with_context(|| format!("create temporary private file {}", temp.display()))?;
    restrict_file_permissions(&file, &temp)?;
    file.write_all(body)?;
    file.sync_all()?;
    drop(file);
    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&temp, path).with_context(|| format!("replace private file {}", path.display()))?;
    Ok(())
}

pub fn load_ledger(dir: &Path, run_id: &str) -> Result<ArtifactLedger> {
    let path = ledger_path(dir, run_id)?;
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let ledger: ArtifactLedger = serde_json::from_str(&text)?;
    if ledger.run_id != run_id || ledger.integrity.is_empty() {
        bail!("ledger is missing a valid run identity or integrity tag");
    }
    if ledger
        .entries
        .iter()
        .any(|entry| entry.run_id != ledger.run_id)
    {
        bail!("ledger entry run identity does not match ledger");
    }
    let key = load_key(dir)?;
    let mut unsigned = ledger.clone();
    let expected = unsigned.integrity.clone();
    unsigned.integrity.clear();
    let body = serde_json::to_vec_pretty(&unsigned)?;
    if integrity_tag(&key, &body) != expected {
        bail!("ledger integrity verification failed");
    }
    Ok(ledger)
}

pub fn latest_run_id(dir: &Path) -> Result<String> {
    let mut best: Option<(u64, String)> = None;
    if !dir.exists() {
        bail!("no artifact ledger directory at {}", dir.display());
    }
    for ent in fs::read_dir(dir)? {
        let ent = ent?;
        let name = ent.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let meta = ent.metadata()?;
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let run_id = name.trim_end_matches(".json").to_string();
        if best.as_ref().map(|(t, _)| modified >= *t).unwrap_or(true) {
            best = Some((modified, run_id));
        }
    }
    best.map(|(_, id)| id)
        .ok_or_else(|| anyhow::anyhow!("no ledgers found in {}", dir.display()))
}

pub fn list_artifacts(dir: &Path, run_id: Option<&str>) -> Result<ArtifactLedger> {
    let id = match run_id {
        Some(id) => id.to_string(),
        None => latest_run_id(dir)?,
    };
    load_ledger(dir, &id)
}

pub fn cleanup(
    dir: &Path,
    run_id: Option<&str>,
    secure_delete: bool,
    remove_self: bool,
) -> Result<Vec<String>> {
    let ledger = list_artifacts(dir, run_id)?;
    let mut removed = Vec::new();
    for entry in &ledger.entries {
        if !entry.removable {
            continue;
        }
        let path = PathBuf::from(&entry.path);
        if fs::symlink_metadata(&path).is_err() {
            continue;
        }
        remove_recorded_path(&path, secure_delete)
            .with_context(|| format!("remove recorded artifact {}", path.display()))?;
        if fs::symlink_metadata(&path).is_err() {
            removed.push(entry.path.clone());
        }
    }
    // Remove ledger file itself after cleanup.
    let lp = ledger_path(dir, &ledger.run_id)?;
    fs::remove_file(&lp).with_context(|| format!("remove ledger {}", lp.display()))?;
    removed.push(lp.display().to_string());
    let has_other_ledgers = fs::read_dir(dir)?
        .flatten()
        .any(|entry| entry.file_name().to_string_lossy().ends_with(".json"));
    if !has_other_ledgers {
        let kp = key_path(dir);
        if kp.exists() {
            fs::remove_file(&kp).with_context(|| format!("remove ledger key {}", kp.display()))?;
            removed.push(kp.display().to_string());
        }
    }

    if remove_self {
        if let Ok(exe) = std::env::current_exe() {
            if secure_delete {
                let _ = output::secure_delete_hint(&exe);
            } else {
                let _ = fs::remove_file(&exe);
            }
            removed.push(exe.display().to_string());
        }
    }
    Ok(removed)
}

fn validate_run_id(run_id: &str) -> Result<()> {
    if run_id.is_empty()
        || run_id == "."
        || run_id == ".."
        || run_id
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':'))
    {
        bail!("run ID must be a safe filename component");
    }
    Ok(())
}

fn key_path(dir: &Path) -> PathBuf {
    dir.join(".ledger-key")
}

fn load_key(dir: &Path) -> Result<Vec<u8>> {
    let path = key_path(dir);
    let key = fs::read(&path).with_context(|| format!("read ledger key {}", path.display()))?;
    if key.len() != 32 {
        bail!("ledger key has an invalid length");
    }
    Ok(key)
}

fn load_or_create_key(dir: &Path) -> Result<Vec<u8>> {
    if let Ok(key) = load_key(dir) {
        return Ok(key);
    }
    let path = key_path(dir);
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            restrict_file_permissions(&file, &path)?;
            file.write_all(&key)?;
            file.sync_all()?;
            Ok(key.to_vec())
        }
        Err(_) => load_key(dir),
    }
}

fn integrity_tag(key: &[u8], body: &[u8]) -> String {
    // HMAC-SHA256 with the SHA-256 block size, kept local to avoid another dependency.
    let mut key_block = [0u8; 64];
    if key.len() > key_block.len() {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    for byte in &mut key_block {
        *byte ^= 0x36;
    }
    inner.update(key_block);
    inner.update(body);
    let inner_digest = inner.finalize();
    for byte in &mut key_block {
        *byte ^= 0x36 ^ 0x5c;
    }
    let mut outer = Sha256::new();
    outer.update(key_block);
    outer.update(inner_digest);
    hex::encode(outer.finalize())
}

fn atomic_private_write(path: &Path, body: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("ledger path has no parent"))?;
    let suffix = rand::random::<u64>();
    let temp = parent.join(format!(
        ".{}.tmp-{suffix:016x}",
        path.file_name().unwrap().to_string_lossy()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .with_context(|| format!("create temporary ledger {}", temp.display()))?;
    restrict_file_permissions(&file, &temp)?;
    file.write_all(body)?;
    file.sync_all()?;
    drop(file);
    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&temp, path).with_context(|| format!("replace ledger {}", path.display()))?;
    Ok(())
}

fn restrict_file_permissions(_file: &std::fs::File, _path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        _file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    {
        let sid = current_windows_sid()?;
        let grant = format!("*{sid}:(F)");
        let status = crate::core::command::trusted_command("icacls.exe")
            .arg(_path)
            .args(["/inheritance:r", "/grant:r", &grant])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .context("apply restrictive Windows private-file ACL")?;
        if !status.success() {
            bail!("icacls.exe failed to restrict private file");
        }
    }
    Ok(())
}

#[cfg(windows)]
fn current_windows_sid() -> Result<String> {
    use std::ffi::c_void;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            bail!("OpenProcessToken failed while resolving the current Windows SID");
        }
        let result = (|| {
            let mut byte_len = 0u32;
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut byte_len);
            if byte_len < std::mem::size_of::<TOKEN_USER>() as u32 {
                bail!("GetTokenInformation returned an invalid TokenUser size");
            }
            let words = byte_len as usize / std::mem::size_of::<usize>() + 1;
            let mut buffer = vec![0usize; words];
            if GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast::<c_void>(),
                byte_len,
                &mut byte_len,
            ) == 0
            {
                bail!("GetTokenInformation failed while resolving the current Windows SID");
            }
            let token_user = &*(buffer.as_ptr().cast::<TOKEN_USER>());
            let mut string_sid = ptr::null_mut();
            if ConvertSidToStringSidW(token_user.User.Sid, &mut string_sid) == 0 {
                bail!("ConvertSidToStringSidW failed for the current Windows token");
            }
            let mut len = 0usize;
            while len < 256 && *string_sid.add(len) != 0 {
                len += 1;
            }
            let sid = if len == 256 {
                Err(anyhow::anyhow!(
                    "current Windows SID string exceeded its bound"
                ))
            } else {
                String::from_utf16(std::slice::from_raw_parts(string_sid, len))
                    .context("current Windows SID was not valid UTF-16")
            };
            LocalFree(string_sid.cast());
            sid
        })();
        CloseHandle(token);
        result
    }
}

fn restrict_dir_permissions(_dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn remove_recorded_path(path: &Path, secure_delete: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        if secure_delete && !metadata.file_type().is_symlink() {
            output::secure_delete_hint(path)?;
        } else {
            fs::remove_file(path)?;
        }
        return Ok(());
    }

    // Detach the directory atomically before walking it. This prevents a
    // concurrent replacement of the recorded root from redirecting cleanup
    // outside the tree we are deleting.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let detached = parent.join(format!(".stealthy-cleanup-{}", hex::encode(nonce)));
    fs::rename(path, &detached)
        .with_context(|| format!("detach cleanup tree {}", path.display()))?;
    remove_detached_tree(&detached, secure_delete)
}

fn remove_detached_tree(path: &Path, secure_delete: bool) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let child = entry?.path();
        let metadata = fs::symlink_metadata(&child)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            if secure_delete && !metadata.file_type().is_symlink() {
                output::secure_delete_hint(&child)?;
            } else {
                fs::remove_file(&child)?;
            }
        } else {
            remove_detached_tree(&child, secure_delete)?;
        }
    }
    fs::remove_dir(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::write_private_atomic;
    use super::{cleanup, load_ledger, save_ledger, ArtifactLedger};

    #[test]
    fn ledgers_are_private_and_tamper_evident() {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = ArtifactLedger::new("run-1");
        ledger.register("test", dir.path().join("artifact"), true, "fixture");
        let path = save_ledger(dir.path(), &ledger).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert!(load_ledger(dir.path(), "run-1").is_ok());
        let mut body = std::fs::read_to_string(&path).unwrap();
        body = body.replace("fixture", "tampered");
        std::fs::write(&path, body).unwrap();
        assert!(load_ledger(dir.path(), "run-1").is_err());
    }

    #[test]
    fn ledger_path_rejects_traversal_ids() {
        assert!(super::ledger_path(std::path::Path::new("/tmp"), "../outside").is_err());
    }

    #[test]
    fn cleanup_is_recoverable_when_recorded_artifact_is_already_missing() {
        let dir = tempfile::tempdir().unwrap();
        let ledger_dir = dir.path().join("ledger");
        let missing = dir.path().join("already-removed");
        let mut ledger = ArtifactLedger::new("missing-artifact-run");
        ledger.register(
            "fixture",
            &missing,
            true,
            "fixture was removed before cleanup",
        );
        save_ledger(&ledger_dir, &ledger).unwrap();

        let removed = cleanup(&ledger_dir, Some("missing-artifact-run"), false, false).unwrap();
        assert!(removed
            .iter()
            .any(|path| path.ends_with("missing-artifact-run.json")));
        assert!(!ledger_dir.join("missing-artifact-run.json").exists());
        assert!(!ledger_dir.join(".ledger-key").exists());
    }

    #[test]
    fn missing_ledger_key_is_rejected_without_accepting_the_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = ArtifactLedger::new("missing-key-run");
        ledger.register("fixture", dir.path().join("fixture"), true, "fixture");
        save_ledger(dir.path(), &ledger).unwrap();
        std::fs::remove_file(dir.path().join(".ledger-key")).unwrap();
        assert!(load_ledger(dir.path(), "missing-key-run").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_does_not_follow_symlinked_children() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let ledger_dir = dir.path().join("ledger");
        let tree = dir.path().join("tree");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep.txt"), b"keep").unwrap();
        symlink(&outside, tree.join("link")).unwrap();

        let mut ledger = ArtifactLedger::new("symlink-run");
        ledger.register("tree", &tree, true, "fixture");
        save_ledger(&ledger_dir, &ledger).unwrap();
        super::cleanup(&ledger_dir, Some("symlink-run"), false, false).unwrap();

        assert!(!tree.exists());
        assert!(outside.join("keep.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_json_writer_restricts_permissions_and_replaces_atomically() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.json");
        write_private_atomic(&path, br#"{"ok":true}"#).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        write_private_atomic(&path, br#"{"ok":false}"#).unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "{\"ok\":false}");
    }
}
