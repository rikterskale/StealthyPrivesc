use anyhow::Result;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};
use crate::plugins::linux::util;

pub struct ContainersPlugin;

impl Plugin for ContainersPlugin {
    fn id(&self) -> &'static str {
        "linux.containers"
    }
    fn name(&self) -> &'static str {
        "Container sockets / groups"
    }
    fn description(&self) -> &'static str {
        "Docker/Podman/containerd/LXD sockets and group membership (replaces linux.docker)"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let sockets = [
            ("/var/run/docker.sock", "docker", Severity::Critical),
            ("/run/docker.sock", "docker", Severity::Critical),
            ("/var/run/podman/podman.sock", "podman", Severity::Critical),
            ("/run/podman/podman.sock", "podman", Severity::Critical),
            (
                "/var/run/containerd/containerd.sock",
                "containerd",
                Severity::High,
            ),
            (
                "/run/containerd/containerd.sock",
                "containerd",
                Severity::High,
            ),
            ("/var/lib/lxd/unix.socket", "lxd", Severity::Critical),
            (
                "/var/snap/lxd/common/lxd/unix.socket",
                "lxd",
                Severity::Critical,
            ),
        ];

        let mut any_sock = false;
        for (path, label, sev) in sockets {
            let p = Path::new(path);
            if !p.exists() {
                continue;
            }
            any_sock = true;
            if let Ok(meta) = std::fs::metadata(p) {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Enumeration,
                    severity: Severity::Info,
                    title: format!("{label} socket present"),
                    detail: format!(
                        "path={} mode={:o} uid={} gid={}",
                        p.display(),
                        meta.mode(),
                        meta.uid(),
                        meta.gid()
                    ),
                    recommendation: format!(
                        "RW access to {label} sockets is often host-root equivalent."
                    ),
                    noisy: false,
                    leaves_artifacts: false,
                });

                match std::fs::OpenOptions::new().read(true).write(true).open(p) {
                    Ok(_) => findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Misconfiguration,
                        severity: sev,
                        title: format!("Current user can open {label} socket RW"),
                        detail: path.into(),
                        recommendation: "Do not start privileged containers unless ROE allows."
                            .into(),
                        noisy: false,
                        leaves_artifacts: false,
                    }),
                    Err(e) if ctx.verbose => findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Enumeration,
                        severity: Severity::Info,
                        title: format!("{label} socket not RW-accessible"),
                        detail: e.to_string(),
                        recommendation: "Check group membership.".into(),
                        noisy: false,
                        leaves_artifacts: false,
                    }),
                    Err(_) => {}
                }
            }
        }

        if !any_sock {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No common container sockets found".into(),
                detail: "Checked docker/podman/containerd/lxd default unix sockets.".into(),
                recommendation: "Rootless podman sockets may live under $XDG_RUNTIME_DIR.".into(),
                noisy: false,
                leaves_artifacts: false,
            });
        }

        // Rootless podman under XDG_RUNTIME_DIR
        if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            let rootless = Path::new(&xdg).join("podman/podman.sock");
            if rootless.exists() {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Enumeration,
                    severity: Severity::Medium,
                    title: "Rootless podman socket present".into(),
                    detail: rootless.display().to_string(),
                    recommendation:
                        "Assess whether this user can escalate within/out of the rootless context."
                            .into(),
                    noisy: false,
                    leaves_artifacts: false,
                });
            }
        }

        for g in ["docker", "podman", "lxd"] {
            if util::user_in_group(g) {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Misconfiguration,
                    severity: Severity::Critical,
                    title: format!("Current user is in '{g}' group"),
                    detail: "Membership typically enables container API abuse toward host root."
                        .into(),
                    recommendation: "Confirm before any container-based demonstration.".into(),
                    noisy: false,
                    leaves_artifacts: false,
                });
            }
        }

        Ok(findings)
    }
}
