use anyhow::Result;

use crate::core::store::EncryptedStore;
use crate::core::types::Finding;

/// Runtime context passed to each plugin.
pub struct PluginContext<'a> {
    #[allow(dead_code)]
    pub verbose: bool,
    #[allow(dead_code)]
    pub auto_exploit: bool,
    #[allow(dead_code)]
    pub store: &'a mut EncryptedStore,
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
