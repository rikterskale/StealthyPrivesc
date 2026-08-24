use crate::core::attack_path::{assign_path_ranks, build_attack_paths};
use crate::core::store::EncryptedStore;
use crate::core::types::{
    ControlAssessment, Finding, FindingAssessment, FindingKind, IdentityInfo, OsInfo,
    PluginCoverage, RunReport, TriageDecision,
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_report(
    run_id: &str,
    started_at_unix: u64,
    profile: &str,
    mode: &str,
    os_info: OsInfo,
    identity: IdentityInfo,
    mut findings: Vec<Finding>,
    plugins_run: Vec<String>,
    coverage: Vec<PluginCoverage>,
    notes: Vec<String>,
    triage_decisions: Vec<TriageDecision>,
    control_assessment: Option<ControlAssessment>,
) -> RunReport {
    let attack_paths = build_attack_paths(&findings);
    assign_path_ranks(&mut findings, &attack_paths);
    let assessments = findings
        .iter()
        .enumerate()
        .map(|(index, finding)| assess_finding(index, finding))
        .collect();
    RunReport {
        schema_version: "2".into(),
        run_id: run_id.into(),
        started_at_unix,
        tool: "stealthy".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        authorized_use_ack: true,
        mode: mode.into(),
        execution_path: "binary".into(),
        primary_launch: "ok".into(),
        roe_ref: std::env::var("STEALTHY_MANIFEST_ROE_REF").unwrap_or_default(),
        profile: profile.into(),
        coverage_mode: "native".into(),
        capability_delta: vec![],
        control_assessment,
        os: os_info,
        identity,
        findings,
        assessments,
        attack_paths,
        triage_decisions,
        plugins_run,
        coverage,
        notes,
    }
}

pub(crate) fn assess_finding(finding_index: usize, finding: &Finding) -> FindingAssessment {
    let (confidence, evidence_quality) = match finding.kind {
        FindingKind::ExploitAttempt => ("high", "direct_probe"),
        FindingKind::Misconfiguration | FindingKind::Credential => ("medium", "local_observation"),
        FindingKind::Enumeration => ("medium", "local_observation"),
        FindingKind::Recommendation => ("low", "heuristic"),
        FindingKind::Scaffold => ("low", "scaffold"),
    };
    let applicability = if matches!(
        finding.kind,
        FindingKind::Recommendation | FindingKind::Scaffold
    ) {
        "requires_validation"
    } else if finding.leaves_artifacts {
        "potentially_actionable"
    } else {
        "current_context"
    };
    FindingAssessment {
        finding_index,
        confidence: confidence.into(),
        applicability: applicability.into(),
        evidence_quality: evidence_quality.into(),
    }
}

pub(crate) fn with_operator_next_step(mut finding: Finding) -> Finding {
    if finding.needs_next_step() {
        finding.recommendation =
            "Validate this observation against the target and ROE before taking action; preserve evidence and document the stop condition.".into();
    }
    finding
}

pub(crate) fn store_into_parts(store: &EncryptedStore) -> (Vec<Finding>, Vec<String>) {
    (store.findings(), store.notes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::assess_finding;
    use crate::core::types::{Finding, FindingKind};

    #[test]
    fn scaffold_is_not_assessed_as_a_direct_probe() {
        let assessment = assess_finding(
            0,
            &Finding {
                kind: FindingKind::Scaffold,
                ..Default::default()
            },
        );
        assert_eq!(assessment.evidence_quality, "scaffold");
        assert_eq!(assessment.applicability, "requires_validation");
    }
}
