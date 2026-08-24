//! Finalize findings with stable IDs, catalog metadata, and scores.

use sha2::{Digest, Sha256};

use crate::core::catalog;
use crate::core::types::Finding;

/// Fill stable ID, MITRE, technique catalog, and scores when missing.
pub fn finalize_finding(mut finding: Finding) -> Finding {
    let (object, condition) = catalog::derive_object_condition(&finding);
    finding.object = object;
    finding.condition = condition;

    if finding.finding_id.is_empty() {
        finding.finding_id = fingerprint(
            &finding.plugin,
            &finding.object,
            &finding.condition,
            &format!("{:?}", finding.kind),
        );
    }

    if finding.mitre_techniques.is_empty() {
        finding.mitre_techniques = catalog::mitre_for_plugin(&finding.plugin)
            .iter()
            .map(|s| (*s).to_string())
            .collect();
    }

    finding.technique_id = catalog::technique_id_for(&finding);
    finding.exploitability = catalog::exploitability_for(&finding);
    finding.time_to_impact = catalog::time_to_impact_for(&finding);
    finding
}

fn fingerprint(plugin: &str, object: &str, condition: &str, kind: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plugin.as_bytes());
    hasher.update([0x1f]);
    hasher.update(object.as_bytes());
    hasher.update([0x1f]);
    hasher.update(condition.as_bytes());
    hasher.update([0x1f]);
    hasher.update(kind.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

#[cfg(test)]
mod tests {
    use super::finalize_finding;
    use crate::core::types::{Finding, FindingKind, Severity};

    #[test]
    fn assigns_stable_id_and_mitre() {
        let finding = finalize_finding(Finding {
            plugin: "linux.sudo".into(),
            kind: FindingKind::Misconfiguration,
            severity: Severity::High,
            title: "NOPASSWD sudo rule(s) present".into(),
            detail: "x".into(),
            recommendation: "review".into(),
            noisy: true,
            leaves_artifacts: false,
            object: "/etc/sudoers.d/example".into(),
            condition: "nopasswd-rule".into(),
            ..Default::default()
        });
        assert_eq!(finding.finding_id.len(), 16);
        assert!(finding.mitre_techniques.iter().any(|t| t == "T1548.003"));
        assert!(finding.exploitability > 0);
        let again = finalize_finding(Finding {
            plugin: "linux.sudo".into(),
            kind: FindingKind::Misconfiguration,
            severity: Severity::High,
            title: "Sudo rule permits passwordless execution".into(),
            detail: "different detail".into(),
            recommendation: "review".into(),
            noisy: true,
            leaves_artifacts: false,
            object: "/etc/sudoers.d/example".into(),
            condition: "nopasswd-rule".into(),
            ..Default::default()
        });
        assert_eq!(finding.finding_id, again.finding_id);
    }

    #[test]
    fn legacy_fallback_does_not_depend_on_title_wording() {
        let first = finalize_finding(Finding {
            plugin: "legacy.script".into(),
            title: "Original wording".into(),
            detail: "path=/tmp/example state=readable".into(),
            ..Default::default()
        });
        let second = finalize_finding(Finding {
            plugin: "legacy.script".into(),
            title: "Reworded title".into(),
            detail: "path=/tmp/example state=readable".into(),
            ..Default::default()
        });
        assert_eq!(first.finding_id, second.finding_id);
    }
}
