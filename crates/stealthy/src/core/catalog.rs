//! Internal technique catalog and default MITRE ATT&CK mappings.

use crate::core::types::{Finding, FindingKind, Severity};
use sha2::{Digest, Sha256};

/// Default MITRE technique IDs for a plugin.
pub fn mitre_for_plugin(plugin: &str) -> &'static [&'static str] {
    match plugin {
        "linux.sudo" => &["T1548.003"],
        "linux.suid" => &["T1548.001"],
        "linux.systemd_cron" => &["T1053.003", "T1543.002"],
        "linux.containers" => &["T1611"],
        "linux.groups" => &["T1068"],
        "linux.polkit" => &["T1548"],
        "linux.mounts" => &["T1548"],
        "linux.ssh_keys" => &["T1552.004"],
        "linux.path_ld" => &["T1574.006", "T1574.007"],
        "linux.kernel_cve" => &["T1068"],
        "linux.nfs" => &["T0840"],
        "linux.credentials" => &["T1552.001"],
        "linux.services" => &["T1543.002"],
        "linux.wildcard_cron" => &["T1053.003"],
        "linux.endpoint_controls" => &["T1562"],
        "linux.app_control" => &["T1480.001"],
        "windows.privileges" => &["T1134"],
        "windows.services" => &["T1543.003"],
        "windows.scheduled_tasks" => &["T1053.005"],
        "windows.always_install_elevated" => &["T1548"],
        "windows.uac" => &["T1548.002"],
        "windows.dll_hijack" => &["T1574.001"],
        "windows.credentials" => &["T1552.001"],
        "windows.admin_sessions" => &["T1078"],
        "windows.env_path" => &["T1574.007"],
        "windows.autoruns" => &["T1547.001"],
        "windows.endpoint_controls" => &["T1562"],
        "windows.app_control" => &["T1480.001"],
        "allow_techniques" | "auto_exploit" => &["T1068"],
        _ => &[],
    }
}

/// Internal catalog technique ID for a finding.
pub fn technique_id_for(finding: &Finding) -> String {
    if !finding.technique_id.is_empty() {
        return finding.technique_id.clone();
    }
    let cond = if finding.condition.is_empty() {
        "generic"
    } else {
        finding.condition.as_str()
    };
    format!("{}.{}", finding.plugin, cond)
}

/// Heuristic exploitability 0–100 when unset.
pub fn exploitability_for(finding: &Finding) -> u8 {
    if finding.exploitability > 0 {
        return finding.exploitability;
    }
    let base = match finding.severity {
        Severity::Critical => 90,
        Severity::High => 75,
        Severity::Medium => 50,
        Severity::Low => 25,
        Severity::Info => 10,
    };
    let kind_adj = match finding.kind {
        FindingKind::ExploitAttempt => 10i16,
        FindingKind::Misconfiguration | FindingKind::Credential => 5,
        FindingKind::Enumeration => 0,
        FindingKind::Recommendation => -15,
        FindingKind::Scaffold => -20,
    };
    let noisy_adj = if finding.noisy { -5 } else { 0 };
    ((base as i16) + kind_adj + noisy_adj).clamp(0, 100) as u8
}

pub fn time_to_impact_for(finding: &Finding) -> String {
    if !finding.time_to_impact.is_empty() {
        return finding.time_to_impact.clone();
    }
    match finding.severity {
        Severity::Critical | Severity::High => "minutes".into(),
        Severity::Medium => "hours".into(),
        Severity::Low | Severity::Info => "days".into(),
    }
}

/// Supply deterministic compatibility identities for legacy/ingested findings.
///
/// Native findings are expected to provide both fields. The fallback avoids
/// title-derived identities so wording-only title changes do not create drift.
pub fn derive_object_condition(finding: &Finding) -> (String, String) {
    let object = if finding.object.is_empty() {
        let digest = Sha256::digest(finding.detail.as_bytes());
        format!("legacy:{}:{}", finding.plugin, hex::encode(&digest[..8]))
    } else {
        finding.object.clone()
    };
    let condition = if finding.condition.is_empty() {
        format!("{:?}", finding.kind).to_ascii_lowercase()
    } else {
        finding.condition.clone()
    };
    (object, condition)
}

#[cfg(test)]
mod tests {
    use super::{
        derive_object_condition, exploitability_for, mitre_for_plugin, technique_id_for,
        time_to_impact_for,
    };
    use crate::core::types::{Finding, FindingKind, Severity};

    #[test]
    fn every_registered_plugin_has_a_catalog_mapping() {
        for plugin in crate::plugins::registry() {
            assert!(!mitre_for_plugin(plugin.id()).is_empty(), "{}", plugin.id());
        }
    }

    #[test]
    fn derived_catalog_fields_are_stable_and_bounded() {
        let finding = Finding {
            plugin: "linux.sudo".into(),
            kind: FindingKind::Misconfiguration,
            severity: Severity::Critical,
            noisy: true,
            title: "title".into(),
            detail: "detail".into(),
            ..Default::default()
        };
        assert!(technique_id_for(&finding).starts_with("linux.sudo."));
        assert!(exploitability_for(&finding) <= 100);
        assert!(!time_to_impact_for(&finding).is_empty());
        let first = derive_object_condition(&finding);
        let second = derive_object_condition(&finding);
        assert_eq!(first, second);
        assert!(first.0.starts_with("legacy:"));
    }
}
