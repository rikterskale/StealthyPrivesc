//! Normalize script-fallback JSON into a canonical RunReport.

use std::path::Path;

use anyhow::{Context, Result};

use crate::core::attack_path::{assign_path_ranks, build_attack_paths};
use crate::core::finalize::finalize_finding;
use crate::core::types::RunReport;

/// Plugin IDs typically missing from script fallbacks vs a full binary build.
pub fn script_capability_delta(os: &str) -> Vec<String> {
    match os {
        "windows" => vec![
            "windows.dll_hijack".into(),
            "windows.scheduled_tasks".into(),
            "windows.endpoint_controls".into(),
        ],
        _ => vec![
            "linux.wildcard_cron".into(),
            "linux.nfs".into(),
            "linux.polkit".into(),
            "linux.endpoint_controls".into(),
            "linux.kernel_cve".into(),
        ],
    }
}

pub fn ingest_path(path: &Path) -> Result<RunReport> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    ingest_json(&text)
}

pub fn ingest_json(text: &str) -> Result<RunReport> {
    let mut report: RunReport =
        serde_json::from_str(text).context("parse script/binary report JSON")?;
    report.schema_version = "2".into();
    if report.coverage_mode.is_empty() {
        report.coverage_mode = "script".into();
    }
    if report.capability_delta.is_empty() {
        report.capability_delta = script_capability_delta(&report.os.os);
    }
    report.findings = report.findings.into_iter().map(finalize_finding).collect();
    let paths = build_attack_paths(&report.findings);
    assign_path_ranks(&mut report.findings, &paths);
    report.attack_paths = paths;
    if report.tool.is_empty() {
        report.tool = "stealthy".into();
    }
    Ok(report)
}
