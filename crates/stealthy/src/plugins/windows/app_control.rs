//! Structured Windows application-control and EDR-aware assessment.

use anyhow::Result;

use crate::core::controls;
use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::Finding;

pub struct AppControlPlugin;

impl Plugin for AppControlPlugin {
    fn id(&self) -> &'static str {
        "windows.app_control"
    }
    fn name(&self) -> &'static str {
        "Windows application-control assessment"
    }
    fn description(&self) -> &'static str {
        "Inventory AppLocker, WDAC/CI, Smart App Control, UMCI, PowerShell policy, sensors, provenance, and telemetry expectations"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["windows"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let assessment = ctx.control_assessment.clone().unwrap_or_else(|| {
            controls::collect_with(controls::CollectOptions {
                platform: "windows",
                artifact: ctx.artifact_path.as_deref(),
                quiet: ctx.prefer_quiet,
            })
        });
        Ok(controls::findings(&assessment, self.id()))
    }
}
