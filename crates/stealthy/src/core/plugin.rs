use anyhow::Result;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::core::store::EncryptedStore;
use crate::core::types::{ControlAssessment, Finding};
use crate::exploit::TechniqueAllowlist;

/// Runtime context passed to each plugin.
pub struct PluginContext<'a> {
    #[allow(dead_code)]
    pub verbose: bool,
    #[allow(dead_code)]
    pub auto_exploit: bool,
    /// When true, plugins should skip known-audited helpers (e.g. `sudo -l`, `getcap`).
    #[allow(dead_code)]
    pub prefer_quiet: bool,
    pub allow_techniques: &'a TechniqueAllowlist,
    #[allow(dead_code)]
    pub store: &'a mut EncryptedStore,
    /// Finding IDs approved for reversible probes (empty = legacy blanket auto_exploit).
    #[allow(dead_code)]
    pub approved_probe_ids: &'a [String],
    /// Optional artifact to assess. It is hashed/inspected, never executed.
    #[allow(dead_code)]
    pub artifact_path: Option<PathBuf>,
    /// Shared read-only control inventory for plugins that emit assessment findings.
    #[allow(dead_code)]
    pub control_assessment: Option<ControlAssessment>,
    /// Cooperative cancel flag set on plugin timeout or operator interrupt.
    #[allow(dead_code)]
    pub cancel: Arc<AtomicBool>,
}

impl PluginContext<'_> {
    #[allow(dead_code)]
    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }
}

/// Independent privilege-escalation check.
pub trait Plugin: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;

    /// Platforms this plugin targets (`linux`, `windows`).
    fn platforms(&self) -> &'static [&'static str];

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>>;
}

pub fn filter_plugins<'a>(
    all: &'a [&'a dyn Plugin],
    only: Option<&[String]>,
    skip: Option<&[String]>,
    os: &str,
) -> Vec<&'a dyn Plugin> {
    all.iter()
        .copied()
        .filter(|p| p.platforms().contains(&os))
        .filter(|p| {
            if let Some(only) = only {
                only.iter().any(|id| id == p.id())
            } else {
                true
            }
        })
        .filter(|p| {
            if let Some(skip) = skip {
                !skip.iter().any(|id| id == p.id())
            } else {
                true
            }
        })
        .collect()
}
