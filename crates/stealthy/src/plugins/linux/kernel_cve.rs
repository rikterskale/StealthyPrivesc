use anyhow::Result;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};
use crate::exploit;

pub struct KernelCvePlugin;

impl Plugin for KernelCvePlugin {
    fn id(&self) -> &'static str {
        "linux.kernel_cve"
    }
    fn name(&self) -> &'static str {
        "Kernel version vs known LPE CVEs (informational)"
    }
    fn description(&self) -> &'static str {
        "Report kernel version and map to well-known LPE CVE hints; execution via --allow-techniques kernel-exploit"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let version = std::fs::read_to_string("/proc/version")
            .unwrap_or_else(|_| "unknown".into())
            .lines()
            .next()
            .unwrap_or("unknown")
            .to_string();

        findings.push(Finding {
            plugin: self.id().into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Info,
            title: "Kernel version".into(),
            detail: version.clone(),
            recommendation: "Compare against current CVE feeds offline. Opt in with --allow-techniques kernel-exploit when ROE permits.".into(),
            noisy: false,
            leaves_artifacts: false,
        });

        // Very small static hint table — informational only.
        let hints: &[(&str, &str, &str)] = &[
            (
                "3.13",
                "CVE-2016-5195",
                "Dirty COW era kernels — historical",
            ),
            (
                "4.4",
                "CVE-2016-5195",
                "Dirty COW may apply depending on backports",
            ),
            (
                "5.8",
                "CVE-2021-22555",
                "Netfilter heap OOB — check distro backports",
            ),
            (
                "5.13",
                "CVE-2022-0847",
                "Dirty Pipe — verify patched status",
            ),
            ("6.2", "CVE-2023-0386", "OverlayFS — verify patched status"),
        ];

        for (needle, cve, note) in hints {
            if version.contains(needle) {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Recommendation,
                    severity: Severity::Medium,
                    title: format!("Possible historical interest: {cve}"),
                    detail: format!("{note}; kernel string matched '{needle}'"),
                    recommendation: "Validate with distro security tracker. Run exploits only with ROE approval (--allow-techniques kernel-exploit).".into(),
                    noisy: false,
                    leaves_artifacts: false,
                });
            }
        }

        let kernel = exploit::TechniqueFamily::KernelExploit;
        let allowed = ctx.allow_techniques.allows(kernel);
        if allowed || ctx.auto_exploit {
            findings.push(exploit::technique_status(self.id(), kernel, allowed));
        }

        Ok(findings)
    }
}
