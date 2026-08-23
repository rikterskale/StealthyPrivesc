//! Run-scoped artifact ledger and cleanup helpers.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

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
    pub entries: Vec<ArtifactRecord>,
}

impl ArtifactLedger {
    pub fn new(run_id: impl Into<String>) -> Self {
        Self {
            schema_version: "1".into(),
            run_id: run_id.into(),
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

pub fn ledger_path(dir: &Path, run_id: &str) -> PathBuf {
    dir.join(format!("{run_id}.json"))
}

pub fn save_ledger(dir: &Path, ledger: &ArtifactLedger) -> Result<PathBuf> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let path = ledger_path(dir, &ledger.run_id);
    let body = serde_json::to_string_pretty(ledger)?;
    fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

pub fn load_ledger(dir: &Path, run_id: &str) -> Result<ArtifactLedger> {
    let path = ledger_path(dir, run_id);
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
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
    let lp = ledger_path(dir, &ledger.run_id);
    fs::remove_file(&lp).with_context(|| format!("remove ledger {}", lp.display()))?;
    removed.push(lp.display().to_string());

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

    for entry in fs::read_dir(path)? {
        remove_recorded_path(&entry?.path(), secure_delete)?;
    }
    fs::remove_dir(path)?;
    Ok(())
}
