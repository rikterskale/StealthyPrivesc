use crate::core::plugin::Plugin;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

/// All plugins compiled into this binary (OS-filtered at runtime too).
pub fn registry() -> Vec<&'static dyn Plugin> {
    let mut out: Vec<&'static dyn Plugin> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        out.extend(linux::plugins());
    }

    #[cfg(target_os = "windows")]
    {
        out.extend(windows::plugins());
    }

    out
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::registry;
    use crate::core::controls;
    use crate::core::plugin::PluginContext;
    use crate::core::profile::EngagementProfile;
    use crate::core::store::EncryptedStore;
    use crate::exploit::TechniqueAllowlist;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    #[test]
    fn every_registered_linux_plugin_runs_in_process() {
        let mut store = EncryptedStore::new();
        let allow = TechniqueAllowlist::default();
        let assessment = controls::collect("linux", None);
        let cancel = Arc::new(AtomicBool::new(false));
        let budget = EngagementProfile::Ci.noise_budget();
        for plugin in registry() {
            let mut context = PluginContext {
                verbose: false,
                auto_exploit: false,
                prefer_quiet: true,
                noise_budget: budget,
                allow_techniques: &allow,
                store: &mut store,
                approved_probe_ids: &[],
                artifact_path: None,
                control_assessment: Some(assessment.clone()),
                cancel: cancel.clone(),
            };
            plugin
                .run(&mut context)
                .unwrap_or_else(|error| panic!("{} failed: {error:#}", plugin.id()));
        }
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::registry;
    use crate::core::controls;
    use crate::core::plugin::PluginContext;
    use crate::core::profile::EngagementProfile;
    use crate::core::store::EncryptedStore;
    use crate::exploit::TechniqueAllowlist;
    use std::collections::BTreeSet;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    #[test]
    fn every_registered_windows_plugin_runs_and_has_unique_identity() {
        let plugins = registry();
        assert!(!plugins.is_empty());
        let mut ids = BTreeSet::new();
        let mut store = EncryptedStore::new();
        let allow = TechniqueAllowlist::default();
        let assessment = controls::collect("windows", None);
        let cancel = Arc::new(AtomicBool::new(false));
        let budget = EngagementProfile::Ci.noise_budget();
        for plugin in plugins {
            assert!(
                ids.insert(plugin.id()),
                "duplicate plugin ID: {}",
                plugin.id()
            );
            assert_eq!(plugin.platforms(), &["windows"]);
            assert!(!plugin.name().trim().is_empty());
            assert!(!plugin.description().trim().is_empty());
            let mut context = PluginContext {
                verbose: false,
                auto_exploit: false,
                prefer_quiet: true,
                noise_budget: budget,
                allow_techniques: &allow,
                store: &mut store,
                approved_probe_ids: &[],
                artifact_path: None,
                control_assessment: Some(assessment.clone()),
                cancel: cancel.clone(),
            };
            let findings = plugin
                .run(&mut context)
                .unwrap_or_else(|error| panic!("{} failed: {error:#}", plugin.id()));
            for finding in findings {
                assert_eq!(finding.plugin, plugin.id());
                assert!(!finding.title.trim().is_empty());
                assert!(!finding.recommendation.trim().is_empty());
            }
        }
    }
}
