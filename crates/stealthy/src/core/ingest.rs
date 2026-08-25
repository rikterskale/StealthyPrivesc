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
            "windows.services".into(),
            "windows.scheduled_tasks".into(),
            "windows.always_install_elevated".into(),
            "windows.uac".into(),
            "windows.dll_hijack".into(),
            "windows.credentials".into(),
            "windows.admin_sessions".into(),
            "windows.env_path".into(),
            "windows.autoruns".into(),
            "windows.endpoint_controls".into(),
            "windows.app_control".into(),
        ],
        _ => vec![
            "linux.app_control".into(),
            "linux.systemd_cron".into(),
            "linux.nfs".into(),
            "linux.path_ld".into(),
            "linux.services".into(),
            "linux.wildcard_cron".into(),
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
    if report.coverage_mode.is_empty()
        || (report.coverage_mode == "native"
            && (report.tool.ends_with("-script")
                || report.profile == "script"
                || report.execution_path.contains("fallback")))
    {
        report.coverage_mode = "script".into();
    }
    if report.coverage_mode == "script" {
        let canonical = script_capability_delta(&report.os.os);
        if report.capability_delta != canonical {
            report.capability_delta = canonical;
        }
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

#[cfg(test)]
mod tests {
    use super::{ingest_json, script_capability_delta};

    #[test]
    fn normalizes_script_capability_delta_to_native_ids() {
        let mut report: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/script_report_min.json"))
                .unwrap();
        report["coverage_mode"] = serde_json::Value::String("script".into());
        report["os"]["os"] = serde_json::Value::String("linux".into());
        report["capability_delta"] = serde_json::json!(["linux.cron", "linux.kernel"]);
        let normalized = ingest_json(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(
            normalized.capability_delta,
            script_capability_delta("linux")
        );
    }

    #[test]
    fn legacy_windows_script_fixture_gets_schema_and_coverage_defaults() {
        let report = ingest_json(include_str!(
            "../../tests/fixtures/script_report_windows.json"
        ))
        .unwrap();
        assert_eq!(report.schema_version, "2");
        assert_eq!(report.coverage_mode, "script");
        assert_eq!(report.capability_delta, script_capability_delta("windows"));
        assert_eq!(report.tool, "stealthy-script");
        assert_eq!(report.notes, vec!["legacy fixture"]);
    }
}
