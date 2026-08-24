use anyhow::Result;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
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
            if ctx.cancelled() {
                break;
            }
            let p = Path::new(path);
            let Ok(link_meta) = std::fs::symlink_metadata(p) else {
                continue;
            };
            if link_meta.file_type().is_symlink() {
                continue;
            }
            if !link_meta.file_type().is_socket() {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Enumeration,
                    severity: Severity::Low,
                    title: format!("Expected {label} socket path is not a socket"),
                    detail: format!("path={path} symlink=false socket=false"),
                    recommendation: "Verify whether this is a stale or replaced runtime path; it was not opened.".into(),
                    noisy: false,
                    leaves_artifacts: false,
                    object: path.into(),
                    condition: "container-socket-path-non-socket".into(),
                    ..Default::default()
                });
                continue;
            }
            any_sock = true;
            if let Ok(meta) = std::fs::metadata(p) {
                let access = classify_socket_permissions(
                    meta.mode(),
                    meta.uid(),
                    meta.gid(),
                    util::euid(),
                    &util::current_gids(),
                );
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Enumeration,
                    severity: Severity::Info,
                    title: format!("{label} socket present"),
                    detail: format!(
                        "path={} mode={:o} uid={} gid={} permission_class={}",
                        p.display(),
                        meta.mode(),
                        meta.uid(),
                        meta.gid(),
                        access.as_str()
                    ),
                    recommendation: format!(
                        "RW access to {label} sockets is often host-root equivalent."
                    ),
                    noisy: false,
                    leaves_artifacts: false,
                    object: p.display().to_string(),
                    condition: "container-socket-present".into(),
                    ..Default::default()
                });

                let writable = util::is_effectively_writable_opts(
                    p,
                    util::euid(),
                    &util::current_gids(),
                    !ctx.prefer_quiet,
                )
                .unwrap_or(false);
                if writable {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Misconfiguration,
                        severity: sev,
                        title: format!("Current user can open {label} socket RW"),
                        detail: path.into(),
                        recommendation: "Do not start privileged containers unless ROE allows."
                            .into(),
                        noisy: false,
                        leaves_artifacts: false,
                        object: p.display().to_string(),
                        condition: "container-socket-current-user-writable".into(),
                        mitre_techniques: vec!["T1611".into()],
                        technique_id: "container-socket".into(),
                        ..Default::default()
                    });
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
                object: "common-container-socket-paths".into(),
                condition: "no-container-socket-observed".into(),
                ..Default::default()
            });
        }

        // Rootless podman under XDG_RUNTIME_DIR
        if !ctx.cancelled() {
            if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
                let rootless = Path::new(&xdg).join("podman/podman.sock");
                let rootless_is_socket =
                    std::fs::symlink_metadata(&rootless)
                        .ok()
                        .is_some_and(|meta| {
                            !meta.file_type().is_symlink() && meta.file_type().is_socket()
                        });
                if rootless_is_socket {
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
                        object: rootless.display().to_string(),
                        condition: "rootless-container-socket-present".into(),
                        ..Default::default()
                    });
                }
            }
        }

        for g in ["docker", "podman", "lxd"] {
            if ctx.cancelled() {
                break;
            }
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
                    object: format!("group:{g}"),
                    condition: "root-adjacent-container-group-membership".into(),
                    mitre_techniques: vec!["T1611".into()],
                    technique_id: "container-group".into(),
                    ..Default::default()
                });
            }
        }

        Ok(findings)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketPermission {
    OwnerWritable,
    GroupWritable,
    WorldWritable,
    Restricted,
}

impl SocketPermission {
    fn as_str(self) -> &'static str {
        match self {
            Self::OwnerWritable => "owner_writable",
            Self::GroupWritable => "group_writable",
            Self::WorldWritable => "world_writable",
            Self::Restricted => "restricted",
        }
    }
}

fn classify_socket_permissions(
    mode: u32,
    owner: u32,
    group: u32,
    euid: u32,
    gids: &[u32],
) -> SocketPermission {
    if euid != 0 && owner == euid && mode & 0o200 != 0 {
        SocketPermission::OwnerWritable
    } else if euid != 0 && gids.contains(&group) && mode & 0o020 != 0 {
        SocketPermission::GroupWritable
    } else if euid != 0 && mode & 0o002 != 0 {
        SocketPermission::WorldWritable
    } else {
        SocketPermission::Restricted
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_socket_permissions, SocketPermission};

    #[test]
    fn golden_docker_socket_modes_are_classified() {
        let fixture = include_str!("../../../tests/fixtures/linux/docker-sock-modes.golden");
        for line in fixture.lines().filter(|line| !line.starts_with('#')) {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.is_empty() {
                continue;
            }
            let mode = u32::from_str_radix(fields[1], 8).unwrap();
            let owner = fields[2].parse().unwrap();
            let group = fields[3].parse().unwrap();
            let euid = fields[4].parse().unwrap();
            let gids = fields[5]
                .split(',')
                .filter_map(|value| value.parse().ok())
                .collect::<Vec<_>>();
            let expected = match fields[6] {
                "owner_writable" => SocketPermission::OwnerWritable,
                "group_writable" => SocketPermission::GroupWritable,
                "world_writable" => SocketPermission::WorldWritable,
                "restricted" => SocketPermission::Restricted,
                value => panic!("unknown fixture class: {value}"),
            };
            assert_eq!(
                classify_socket_permissions(mode, owner, group, euid, &gids),
                expected,
                "fixture case {}",
                fields[0]
            );
        }
    }
}
