use anyhow::Result;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::core::profile::NoiseBudget;
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
    pub noise_budget: NoiseBudget,
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
    /// Return whether a reversible probe associated with `finding` is approved.
    /// An empty approval set preserves explicit `--auto-exploit` behavior; a
    /// non-empty set is finding-scoped and never falls back to blanket access.
    pub fn probe_allowed_for(&self, finding: &Finding) -> bool {
        if !self.auto_exploit {
            return false;
        }
        if self.approved_probe_ids.is_empty() {
            return true;
        }
        let finalized = crate::core::finalize::finalize_finding(finding.clone());
        self.approved_probe_ids
            .iter()
            .any(|id| id == &finalized.finding_id)
    }

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

#[cfg(test)]
mod tests {
    use super::{filter_plugins, Plugin, PluginContext};
    use crate::core::profile::NoiseBudget;
    use crate::core::store::EncryptedStore;
    use crate::core::types::Finding;
    use crate::exploit::TechniqueAllowlist;
    use anyhow::Result;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    struct FixturePlugin(&'static str, &'static [&'static str]);
    impl Plugin for FixturePlugin {
        fn id(&self) -> &'static str {
            self.0
        }
        fn name(&self) -> &'static str {
            self.0
        }
        fn description(&self) -> &'static str {
            "fixture"
        }
        fn platforms(&self) -> &'static [&'static str] {
            self.1
        }
        fn run(&self, _ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
            Ok(vec![])
        }
    }

    #[test]
    fn filtering_honors_platform_only_and_skip() {
        let linux = FixturePlugin("linux.one", &["linux"]);
        let windows = FixturePlugin("windows.one", &["windows"]);
        let all: [&dyn Plugin; 2] = [&linux, &windows];
        let only = vec!["linux.one".into(), "windows.one".into()];
        let skip = vec!["linux.one".into()];
        assert!(filter_plugins(&all, Some(&only), Some(&skip), "linux").is_empty());
        assert_eq!(
            filter_plugins(&all, None, None, "windows")[0].id(),
            "windows.one"
        );
    }

    #[test]
    fn probe_approval_is_exact_and_cancellation_is_observable() {
        let finding = crate::core::finalize::finalize_finding(Finding {
            plugin: "fixture".into(),
            object: "object".into(),
            condition: "condition".into(),
            ..Default::default()
        });
        let allow = TechniqueAllowlist::default();
        let mut store = EncryptedStore::new();
        let approved = vec![finding.finding_id.clone()];
        let cancel = Arc::new(AtomicBool::new(false));
        let context = PluginContext {
            verbose: false,
            auto_exploit: true,
            prefer_quiet: true,
            noise_budget: NoiseBudget {
                allow_external_helpers: false,
                max_walk_entries: 1,
                max_helper_records: 1,
            },
            allow_techniques: &allow,
            store: &mut store,
            approved_probe_ids: &approved,
            artifact_path: None,
            control_assessment: None,
            cancel: cancel.clone(),
        };
        assert!(context.probe_allowed_for(&finding));
        assert!(!context.probe_allowed_for(&Finding {
            plugin: "other".into(),
            ..Default::default()
        }));
        cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(context.cancelled());
    }
}
