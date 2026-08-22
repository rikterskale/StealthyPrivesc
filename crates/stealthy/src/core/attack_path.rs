//! Ranked attack-path synthesis from finalized findings.

use crate::core::types::{AttackPath, Finding, FindingKind, Severity};

/// Build ranked attack paths from actionable findings.
pub fn build_attack_paths(findings: &[Finding]) -> Vec<AttackPath> {
    let mut candidates: Vec<&Finding> = findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind,
                FindingKind::Misconfiguration
                    | FindingKind::Credential
                    | FindingKind::ExploitAttempt
            ) || (f.kind == FindingKind::Enumeration && f.severity.rank() >= Severity::High.rank())
        })
        .filter(|f| f.severity.rank() >= Severity::Medium.rank())
        .collect();

    candidates.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| b.exploitability.cmp(&a.exploitability))
            .then_with(|| a.plugin.cmp(&b.plugin))
    });

    let mut paths = Vec::new();
    let mut used = std::collections::BTreeSet::new();
    let mut rank = 1u32;

    // Group by plugin family for coherent paths.
    let mut by_plugin: std::collections::BTreeMap<&str, Vec<&Finding>> =
        std::collections::BTreeMap::new();
    for finding in &candidates {
        by_plugin
            .entry(finding.plugin.as_str())
            .or_default()
            .push(*finding);
    }

    let mut plugin_order: Vec<&str> = by_plugin.keys().copied().collect();
    plugin_order.sort_by(|a, b| {
        let sa = by_plugin[a]
            .iter()
            .map(|f| (f.severity.rank(), f.exploitability))
            .max()
            .unwrap_or((0, 0));
        let sb = by_plugin[b]
            .iter()
            .map(|f| (f.severity.rank(), f.exploitability))
            .max()
            .unwrap_or((0, 0));
        sb.cmp(&sa).then_with(|| a.cmp(b))
    });

    for plugin in plugin_order {
        let group = &by_plugin[plugin];
        let ids: Vec<String> = group
            .iter()
            .filter(|f| used.insert(f.finding_id.clone()))
            .map(|f| f.finding_id.clone())
            .collect();
        if ids.is_empty() {
            continue;
        }
        let top = group[0];
        let noise = if group.iter().any(|f| f.noisy) {
            "elevated"
        } else {
            "low"
        };
        paths.push(AttackPath {
            rank,
            title: format!("via {}", top.plugin),
            summary: format!(
                "{} actionable finding(s); top: {} (exploitability {})",
                ids.len(),
                top.title,
                top.exploitability
            ),
            finding_ids: ids,
            estimated_noise: noise.into(),
        });
        rank += 1;
        if paths.len() >= 8 {
            break;
        }
    }

    paths
}

/// Assign `attack_path_rank` onto findings referenced by paths.
pub fn assign_path_ranks(findings: &mut [Finding], paths: &[AttackPath]) {
    let mut map = std::collections::BTreeMap::new();
    for path in paths {
        for id in &path.finding_ids {
            map.entry(id.clone()).or_insert(path.rank);
        }
    }
    for finding in findings {
        if let Some(rank) = map.get(&finding.finding_id) {
            finding.attack_path_rank = Some(*rank);
        }
    }
}
