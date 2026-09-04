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

        let socket_paths =
            sockets.map(|(path, label, severity)| (Path::new(path), label, severity));
        let (socket_findings, any_sock) =
            scan_sockets(ctx, &socket_paths, util::euid(), &util::current_gids());
        findings.extend(socket_findings);

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
                if let Some(finding) = rootless_socket_finding(&rootless) {
                    findings.push(finding);
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

fn scan_sockets(
    ctx: &PluginContext<'_>,
    sockets: &[(&Path, &str, Severity)],
    euid: u32,
    gids: &[u32],
) -> (Vec<Finding>, bool) {
    let mut findings = Vec::new();
    let mut any_sock = false;
    for (path, label, severity) in sockets {
        if ctx.cancelled() {
            break;
        }
        let Ok(link_meta) = std::fs::symlink_metadata(path) else {
            continue;
        };
        if link_meta.file_type().is_symlink() {
            continue;
        }
        if !link_meta.file_type().is_socket() {
            findings.push(Finding {
                plugin: "linux.containers".into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Low,
                title: format!("Expected {label} socket path is not a socket"),
                detail: format!("path={} symlink=false socket=false", path.display()),
                recommendation:
                    "Verify whether this is a stale or replaced runtime path; it was not opened."
                        .into(),
                noisy: false,
                leaves_artifacts: false,
                object: path.display().to_string(),
                condition: "container-socket-path-non-socket".into(),
                ..Default::default()
            });
            continue;
        }
        any_sock = true;
        if let Ok(meta) = std::fs::metadata(path) {
            let access =
                classify_socket_permissions(meta.mode(), meta.uid(), meta.gid(), euid, gids);
            findings.push(Finding {
                plugin: "linux.containers".into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: format!("{label} socket present"),
                detail: format!(
                    "path={} mode={:o} uid={} gid={} permission_class={}",
                    path.display(),
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
                object: path.display().to_string(),
                condition: "container-socket-present".into(),
                ..Default::default()
            });
            if util::is_effectively_writable_opts(path, euid, gids, !ctx.prefer_quiet)
                .unwrap_or(false)
            {
                findings.push(Finding {
                    plugin: "linux.containers".into(),
                    kind: FindingKind::Misconfiguration,
                    severity: *severity,
                    title: format!("Current user can open {label} socket RW"),
                    detail: path.display().to_string(),
                    recommendation: "Do not start privileged containers unless ROE allows.".into(),
                    noisy: false,
                    leaves_artifacts: false,
                    object: path.display().to_string(),
                    condition: "container-socket-current-user-writable".into(),
                    mitre_techniques: vec!["T1611".into()],
                    technique_id: "container-socket".into(),
                    ..Default::default()
                });
            }
        }
    }
    (findings, any_sock)
}

fn rootless_socket_finding(path: &Path) -> Option<Finding> {
    let is_socket = std::fs::symlink_metadata(path)
        .ok()
        .is_some_and(|meta| !meta.file_type().is_symlink() && meta.file_type().is_socket());
    is_socket.then(|| Finding {
        plugin: "linux.containers".into(),
        kind: FindingKind::Enumeration,
        severity: Severity::Medium,
        title: "Rootless podman socket present".into(),
        detail: path.display().to_string(),
        recommendation: "Assess whether this user can escalate within/out of the rootless context."
            .into(),
        noisy: false,
        leaves_artifacts: false,
        object: path.display().to_string(),
        condition: "rootless-container-socket-present".into(),
        ..Default::default()
    })
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
    use super::{
        classify_socket_permissions, rootless_socket_finding, scan_sockets, SocketPermission,
    };
    use crate::core::plugin::PluginContext;
    use crate::core::profile::EngagementProfile;
    use crate::core::store::EncryptedStore;
    use crate::core::types::Severity;
    use crate::exploit::TechniqueAllowlist;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

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

    #[test]
    fn socket_fixture_scan_covers_types_access_rootless_and_cancellation() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("runtime.sock");
        let _listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
                ) =>
            {
                return;
            }
            Err(error) => panic!("bind Unix socket fixture: {error}"),
        };
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o777)).unwrap();
        let regular = root.path().join("stale.sock");
        std::fs::write(&regular, b"not a socket").unwrap();
        let linked = root.path().join("linked.sock");
        symlink(&socket, &linked).unwrap();
        let missing = root.path().join("missing.sock");

        let metadata = std::fs::metadata(&socket).unwrap();
        let euid = metadata.uid().saturating_add(1);
        let allow = TechniqueAllowlist::default();
        let mut store = EncryptedStore::new();
        let cancel = Arc::new(AtomicBool::new(false));
        let context = PluginContext {
            verbose: false,
            auto_exploit: false,
            prefer_quiet: true,
            noise_budget: EngagementProfile::Ci.noise_budget(),
            allow_techniques: &allow,
            store: &mut store,
            approved_probe_ids: &[],
            artifact_path: None,
            control_assessment: None,
            cancel: cancel.clone(),
        };
        let (findings, any_socket) = scan_sockets(
            &context,
            &[
                (socket.as_path(), "fixture", Severity::Critical),
                (regular.as_path(), "stale", Severity::High),
                (linked.as_path(), "linked", Severity::Low),
                (missing.as_path(), "missing", Severity::Low),
            ],
            euid,
            &[],
        );
        assert!(any_socket);
        assert!(findings
            .iter()
            .any(|finding| finding.condition == "container-socket-present"));
        assert!(findings.iter().any(|finding| {
            finding.condition == "container-socket-current-user-writable"
                && finding.severity == Severity::Critical
        }));
        assert!(findings
            .iter()
            .any(|finding| finding.condition == "container-socket-path-non-socket"));
        assert!(rootless_socket_finding(&socket).is_some());
        assert!(rootless_socket_finding(&regular).is_none());
        assert!(rootless_socket_finding(&linked).is_none());

        cancel.store(true, Ordering::SeqCst);
        let (findings, any_socket) = scan_sockets(
            &context,
            &[(socket.as_path(), "fixture", Severity::Critical)],
            euid,
            &[],
        );
        assert!(findings.is_empty());
        assert!(!any_socket);
    }
}
