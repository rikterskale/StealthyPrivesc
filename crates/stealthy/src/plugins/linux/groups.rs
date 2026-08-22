use anyhow::Result;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};
use crate::plugins::linux::util;

pub struct GroupsPlugin;

impl Plugin for GroupsPlugin {
    fn id(&self) -> &'static str {
        "linux.groups"
    }
    fn name(&self) -> &'static str {
        "Interesting group membership"
    }
    fn description(&self) -> &'static str {
        "Flag docker/lxd/disk and other root-adjacent group memberships"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, _ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let names = util::current_group_names();

        findings.push(Finding {
            plugin: self.id().into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Info,
            title: "Current groups".into(),
            detail: names.join(", "),
            recommendation:
                "Review memberships that map to block-device, container, or sudo access.".into(),
            noisy: false,
            leaves_artifacts: false,
            ..Default::default()
        });

        // (group, severity, note)
        let interesting: &[(&str, Severity, &str)] = &[
            (
                "docker",
                Severity::Critical,
                "Usually root-equivalent via docker API / privileged containers.",
            ),
            (
                "lxd",
                Severity::Critical,
                "LXD group members can often mount the host rootfs into a container.",
            ),
            (
                "disk",
                Severity::Critical,
                "Raw disk access can bypass file DACLs (e.g., debugfs on disks).",
            ),
            (
                "podman",
                Severity::High,
                "Podman socket/group access may allow container-based host compromise.",
            ),
            (
                "root",
                Severity::Critical,
                "Explicit root group membership.",
            ),
            (
                "sudo",
                Severity::Medium,
                "May allow passworded sudo — confirm with sudoers checks.",
            ),
            (
                "wheel",
                Severity::Medium,
                "Often maps to sudo/admin on RHEL-family systems.",
            ),
            (
                "adm",
                Severity::Low,
                "Often reads logs; useful recon, rarely direct root.",
            ),
            (
                "video",
                Severity::Low,
                "Sometimes useful for device/framebuffer abuse research.",
            ),
            (
                "shadow",
                Severity::High,
                "May read /etc/shadow depending on setup.",
            ),
        ];

        let mut hit = false;
        for (g, sev, note) in interesting {
            if names.iter().any(|n| n == g) {
                hit = true;
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Misconfiguration,
                    severity: *sev,
                    title: format!("Member of interesting group: {g}"),
                    detail: (*note).into(),
                    recommendation:
                        "Treat as a privilege boundary finding; exploit only with ROE approval."
                            .into(),
                    noisy: false,
                    leaves_artifacts: false,
                    ..Default::default()
                });
            }
        }

        if !hit {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No high-interest group memberships flagged".into(),
                detail: "Checked docker/lxd/disk/podman/sudo/wheel/shadow/adm/video.".into(),
                recommendation: "Still review custom enterprise groups.".into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }

        Ok(findings)
    }
}
