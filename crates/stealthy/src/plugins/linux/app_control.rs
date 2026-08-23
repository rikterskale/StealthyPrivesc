//! Structured Linux application-control and EDR-aware assessment.

use anyhow::Result;

use crate::core::controls;
use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::Finding;

pub struct AppControlPlugin;

impl Plugin for AppControlPlugin {
    fn id(&self) -> &'static str {
        "linux.app_control"
    }
    fn name(&self) -> &'static str {
        "Linux application-control assessment"
    }
    fn description(&self) -> &'static str {
        "Inventory fapolicyd, SELinux, AppArmor, IMA, fs-verity, mounts, audit sources, provenance, and telemetry expectations"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let assessment = ctx.control_assessment.clone().unwrap_or_else(|| {
            controls::collect_with(controls::CollectOptions {
                platform: "linux",
                artifact: ctx.artifact_path.as_deref(),
                quiet: ctx.prefer_quiet,
            })
        });
        Ok(controls::findings(&assessment, self.id()))
    }
}
