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
            .map(|finding| {
                if finding.finding_id.is_empty() {
                    crate::core::finalize::finalize_finding((*finding).clone()).finding_id
                } else {
                    finding.finding_id.clone()
                }
            })
            .filter(|id| used.insert(id.clone()))
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
        let id = if finding.finding_id.is_empty() {
            crate::core::finalize::finalize_finding(finding.clone()).finding_id
        } else {
            finding.finding_id.clone()
        };
        if let Some(rank) = map.get(&id) {
            finding.attack_path_rank = Some(*rank);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{assign_path_ranks, build_attack_paths};
    use crate::core::types::{Finding, FindingKind, Severity};

    fn finding(plugin: &str, object: &str, severity: Severity) -> Finding {
        Finding {
            plugin: plugin.into(),
            object: object.into(),
            condition: "writable".into(),
            kind: FindingKind::Misconfiguration,
            severity,
            exploitability: severity.rank() * 10,
            title: object.into(),
            ..Default::default()
        }
    }

    #[test]
    fn ranks_groups_and_assigns_ids_for_unfinalized_findings() {
        let mut findings = vec![
            finding("plugin.low", "one", Severity::Medium),
            finding("plugin.high", "two", Severity::Critical),
            finding("plugin.low", "three", Severity::High),
        ];
        let paths = build_attack_paths(&findings);
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].title, "via plugin.high");
        assert_eq!(paths[1].finding_ids.len(), 2);
        assert!(paths
            .iter()
            .all(|path| !path.finding_ids.contains(&String::new())));
        assign_path_ranks(&mut findings, &paths);
        assert!(findings
            .iter()
            .all(|finding| finding.attack_path_rank.is_some()));
    }

    #[test]
    fn excludes_non_actionable_findings_and_limits_paths() {
        let mut findings = (0..10)
            .map(|index| finding(&format!("plugin.{index}"), "target", Severity::High))
            .collect::<Vec<_>>();
        findings.push(Finding {
            plugin: "info".into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Info,
            ..Default::default()
        });
        assert_eq!(build_attack_paths(&findings).len(), 8);
    }
}
