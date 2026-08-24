use std::collections::BTreeMap;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::core::types::{Finding, RunReport};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportDiff {
    pub schema_version: String,
    pub baseline_run_id: String,
    pub current_run_id: String,
    pub added: Vec<Finding>,
    pub removed: Vec<Finding>,
    pub changed: Vec<ChangedFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangedFinding {
    pub before: Finding,
    pub after: Finding,
}

pub fn compare(baseline: &RunReport, current: &RunReport) -> Result<ReportDiff> {
    let before = index(&baseline.findings)?;
    let after = index(&current.findings)?;
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for (key, finding) in &after {
        match before.get(key) {
            None => added.push((*finding).clone()),
            Some(previous) if *previous != *finding => changed.push(ChangedFinding {
                before: (*previous).clone(),
                after: (*finding).clone(),
            }),
            Some(_) => {}
        }
    }
    for (key, finding) in &before {
        if !after.contains_key(key) {
            removed.push((*finding).clone());
        }
    }
    added.sort_by(|a, b| a.title.cmp(&b.title));
    removed.sort_by(|a, b| a.title.cmp(&b.title));
    changed.sort_by(|a, b| a.after.title.cmp(&b.after.title));

    Ok(ReportDiff {
        schema_version: "1".into(),
        baseline_run_id: baseline.run_id.clone(),
        current_run_id: current.run_id.clone(),
        added,
        removed,
        changed,
    })
}

fn index(findings: &[Finding]) -> Result<BTreeMap<String, &Finding>> {
    let mut indexed = BTreeMap::new();
    for finding in findings {
        let id = key(finding);
        if indexed.insert(id.clone(), finding).is_some() {
            bail!("duplicate finding identity in report: {id}");
        }
    }
    Ok(indexed)
}

fn key(finding: &Finding) -> String {
    if !finding.finding_id.is_empty() {
        return finding.finding_id.clone();
    }
    crate::core::finalize::finalize_finding(finding.clone()).finding_id
}

#[cfg(test)]
mod tests {
    use super::compare;
    use crate::core::types::{Finding, FindingKind, RunReport};

    fn report(findings: Vec<Finding>, run_id: &str) -> RunReport {
        RunReport {
            schema_version: "1".into(),
            run_id: run_id.into(),
            started_at_unix: 0,
            tool: "test".into(),
            version: "0".into(),
            authorized_use_ack: true,
            mode: "enumerate-only".into(),
            execution_path: "binary".into(),
            primary_launch: "ok".into(),
            roe_ref: String::new(),
            os: crate::core::types::OsInfo {
                family: "unix".into(),
                os: "linux".into(),
                arch: "x86_64".into(),
                version_hint: "test".into(),
            },
            identity: crate::core::types::IdentityInfo {
                username: "u".into(),
                uid: Some(1),
                gid: Some(1),
                groups: vec![],
                is_elevated: false,
                elevation_source: "test".into(),
                token_context: "test".into(),
                hostname: "h".into(),
            },
            findings,
            assessments: vec![],
            attack_paths: vec![],
            triage_decisions: vec![],
            plugins_run: vec![],
            coverage: vec![],
            notes: vec![],
            profile: "balanced".into(),
            coverage_mode: "native".into(),
            capability_delta: vec![],
            control_assessment: None,
        }
    }

    fn finding(title: &str, detail: &str) -> Finding {
        Finding {
            plugin: "test".into(),
            kind: FindingKind::Enumeration,
            severity: crate::core::types::Severity::Info,
            title: title.into(),
            detail: detail.into(),
            recommendation: "review".into(),
            noisy: false,
            leaves_artifacts: false,
            object: title.into(),
            condition: "test-observation".into(),
            ..Default::default()
        }
    }

    #[test]
    fn compares_added_removed_and_changed_findings() {
        let baseline = report(vec![finding("same", "old"), finding("removed", "x")], "a");
        let current = report(vec![finding("same", "new"), finding("added", "x")], "b");
        let diff = compare(&baseline, &current).unwrap();
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.changed.len(), 1);
    }

    #[test]
    fn rejects_duplicate_finding_ids() {
        let mut first = finding("first", "x");
        first.finding_id = "duplicate".into();
        let mut second = finding("second", "y");
        second.finding_id = "duplicate".into();
        let baseline = report(vec![first, second], "a");
        let current = report(vec![], "b");
        let error = compare(&baseline, &current).unwrap_err();
        assert!(error.to_string().contains("duplicate finding identity"));
    }
}
