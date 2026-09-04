use anyhow::Result;
use std::ffi::{c_char, c_void, CString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct SuidPlugin;

const DEFAULT_ROOTS: &[&str] = &["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"];
const QUIET_MAX_DEPTH: usize = 2;
const DEFAULT_MAX_DEPTH: usize = 4;
const QUIET_MAX_ENTRIES: usize = 8_000;
const DEFAULT_MAX_ENTRIES: usize = 25_000;
const HARD_MAX_DEPTH: usize = 16;
const HARD_MAX_ENTRIES: usize = 250_000;

#[derive(Debug, Clone)]
struct ScanPolicy {
    roots: Vec<PathBuf>,
    max_depth: usize,
    max_entries: usize,
    quiet: bool,
}

impl ScanPolicy {
    fn from_environment(quiet: bool, profile_entry_limit: usize) -> Self {
        let roots = std::env::var("STEALTHY_SUID_ROOTS")
            .ok()
            .map(|value| {
                value
                    .split(':')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
                    .filter(|path| path.is_absolute())
                    .collect::<Vec<_>>()
            })
            .filter(|roots| !roots.is_empty())
            .unwrap_or_else(|| DEFAULT_ROOTS.iter().map(PathBuf::from).collect());
        let default_depth = if quiet {
            QUIET_MAX_DEPTH
        } else {
            DEFAULT_MAX_DEPTH
        };
        let default_entries = if quiet {
            QUIET_MAX_ENTRIES
        } else {
            DEFAULT_MAX_ENTRIES
        };

        Self {
            roots,
            max_depth: bounded_env_usize(
                "STEALTHY_SUID_MAX_DEPTH",
                default_depth,
                1,
                HARD_MAX_DEPTH,
            ),
            max_entries: bounded_env_usize(
                "STEALTHY_SUID_MAX_ENTRIES",
                default_entries.min(profile_entry_limit),
                1,
                HARD_MAX_ENTRIES,
            )
            .min(profile_entry_limit.max(1)),
            quiet,
        }
    }
}

#[derive(Debug, Default)]
struct ScanStats {
    entries_seen: usize,
    roots_scanned: usize,
    limit_reached: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapabilitySet {
    permitted: u64,
    inheritable: u64,
    effective: bool,
    root_id: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
struct GtfoAnnotation {
    functions: &'static str,
}

impl Plugin for SuidPlugin {
    fn id(&self) -> &'static str {
        "linux.suid"
    }
    fn name(&self) -> &'static str {
        "SUID/SGID and capabilities"
    }
    fn description(&self) -> &'static str {
        "Find SUID/SGID binaries and file capabilities via bounded filesystem walks"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let policy =
            ScanPolicy::from_environment(ctx.prefer_quiet, ctx.noise_budget.max_walk_entries);
        let mut findings = Vec::new();
        let mut stats = ScanStats::default();

        for root in &policy.roots {
            if ctx.cancelled() || stats.limit_reached {
                break;
            }
            walk_root(root, &policy, &ctx.cancel, &mut stats, &mut |path, meta| {
                inspect_file(path, meta, &policy, &mut findings)
            });
        }

        if ctx.auto_exploit && !ctx.cancelled() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Recommendation,
                severity: Severity::Info,
                title: "SUID abuse not covered by reversible auto-exploit".into(),
                detail:
                    "SUID abuse is high-signal and often irreversible from a telemetry perspective."
                        .into(),
                recommendation:
                    "Exploit manually with ROE approval, or use a separately allowlisted technique family."
                        .into(),
                noisy: false,
                leaves_artifacts: false,
                object: "linux.suid:auto-exploit".into(),
                condition: "non-reversible-probe-unavailable".into(),
                ..Default::default()
            });
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No high-signal SUID/SGID/capability findings".into(),
                detail: format!(
                    "Bounded scan completed: roots_scanned={} entries_seen={} max_depth={} max_entries={} same_filesystem=true symlinks_followed=false quiet={} limit_reached={}",
                    stats.roots_scanned,
                    stats.entries_seen,
                    policy.max_depth,
                    policy.max_entries,
                    policy.quiet,
                    stats.limit_reached
                ),
                recommendation: "Adjust STEALTHY_SUID_ROOTS, STEALTHY_SUID_MAX_DEPTH, and STEALTHY_SUID_MAX_ENTRIES when broader enumeration is authorized.".into(),
                noisy: false,
                leaves_artifacts: false,
                object: policy_summary(&policy),
                condition: "bounded-scan-no-high-signal-findings".into(),
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn bounded_env_usize(name: &str, default: usize, min: usize, max: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default)
}

fn policy_summary(policy: &ScanPolicy) -> String {
    let roots = policy
        .roots
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(":");
    format!(
        "roots={roots};depth={};entries={}",
        policy.max_depth, policy.max_entries
    )
}

fn walk_root(
    root: &Path,
    policy: &ScanPolicy,
    cancel: &AtomicBool,
    stats: &mut ScanStats,
    inspect: &mut dyn FnMut(&Path, &std::fs::Metadata),
) {
    let Ok(root_meta) = std::fs::symlink_metadata(root) else {
        return;
    };
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return;
    }

    stats.roots_scanned += 1;
    let root_device = root_meta.dev();
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    while let Some((directory, depth)) = pending.pop() {
        if cancel.load(Ordering::SeqCst) || stats.entries_seen >= policy.max_entries {
            stats.limit_reached = stats.entries_seen >= policy.max_entries;
            return;
        }
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            if cancel.load(Ordering::SeqCst) || stats.entries_seen >= policy.max_entries {
                stats.limit_reached = stats.entries_seen >= policy.max_entries;
                return;
            }
            stats.entries_seen += 1;
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() || meta.dev() != root_device {
                continue;
            }
            if meta.is_file() {
                inspect(&path, &meta);
            } else if meta.is_dir() && depth < policy.max_depth {
                pending.push((path, depth + 1));
            }
        }
    }
}

fn inspect_file(
    path: &Path,
    meta: &std::fs::Metadata,
    policy: &ScanPolicy,
    findings: &mut Vec<Finding>,
) {
    let mode = meta.mode();
    let suid = mode & 0o4000 != 0;
    let sgid = mode & 0o2000 != 0;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let gtfo = gtfobins_annotation(name);

    if (suid || sgid) && (!policy.quiet || gtfo.is_some()) {
        #[cfg(not(feature = "opsec-string-strip"))]
        let condition = match (suid, sgid, gtfo.is_some()) {
            (true, true, true) => "suid-sgid-gtfobins-candidate",
            (true, false, true) => "suid-gtfobins-candidate",
            (false, true, true) => "sgid-gtfobins-candidate",
            (true, true, false) => "suid-sgid-set",
            (true, false, false) => "suid-set",
            (false, true, false) => "sgid-set",
            _ => "special-mode-set",
        };
        #[cfg(feature = "opsec-string-strip")]
        let condition = match (suid, sgid) {
            (true, true) => "suid-sgid-set",
            (true, false) => "suid-set",
            (false, true) => "sgid-set",
            _ => "special-mode-set",
        };
        let mut detail = format!("mode={mode:o} uid={} gid={}", meta.uid(), meta.gid());
        if let Some(annotation) = gtfo {
            if let Some(line) = crate::core::opsec::gtfobins_detail(name, annotation.functions) {
                detail.push_str("; ");
                detail.push_str(&line);
            }
        }
        findings.push(Finding {
            plugin: "linux.suid".into(),
            kind: FindingKind::Misconfiguration,
            severity: if gtfo.is_some() {
                Severity::High
            } else {
                Severity::Medium
            },
            title: format!(
                "{}{} binary: {}",
                if suid { "SUID " } else { "" },
                if sgid { "SGID" } else { "" },
                path.display()
            ),
            detail,
            #[cfg(not(feature = "opsec-string-strip"))]
            recommendation: "Review the documented GTFOBins technique manually; this annotation is recommend-only and never executes a payload.".into(),
            #[cfg(feature = "opsec-string-strip")]
            recommendation: "Review the binary's special mode and documented abuse potential offline. This tool does not execute a payload.".into(),
            noisy: false,
            leaves_artifacts: false,
            object: path.display().to_string(),
            condition: condition.into(),
            mitre_techniques: vec!["T1548.001".into()],
            technique_id: if gtfo.is_some() {
                crate::core::opsec::GTFO_TECHNIQUE
            } else {
                "set-id"
            }
            .into(),
            ..Default::default()
        });
    }

    let Some(capabilities) = read_file_capabilities(path) else {
        return;
    };
    let high_signal = capabilities.high_signal_names();
    if policy.quiet && high_signal.is_empty() {
        return;
    }
    findings.push(Finding {
        plugin: "linux.suid".into(),
        kind: FindingKind::Misconfiguration,
        severity: if high_signal.is_empty() {
            Severity::Medium
        } else {
            Severity::High
        },
        title: format!("File capabilities: {}", path.display()),
        detail: format!(
            "permitted=0x{:016x} inheritable=0x{:016x} effective={} root_id={} high_signal={}",
            capabilities.permitted,
            capabilities.inheritable,
            capabilities.effective,
            capabilities
                .root_id
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".into()),
            if high_signal.is_empty() {
                "none".into()
            } else {
                high_signal.join(",")
            }
        ),
        recommendation: "Review the capability set against the executable's intended role. Enumeration does not invoke the binary.".into(),
        noisy: false,
        leaves_artifacts: false,
        object: path.display().to_string(),
        condition: "linux-file-capabilities-present".into(),
        mitre_techniques: vec!["T1548.001".into()],
        technique_id: "linux-file-capabilities".into(),
        ..Default::default()
    });
}

impl CapabilitySet {
    fn high_signal_names(&self) -> Vec<&'static str> {
        const HIGH_SIGNAL: &[(u32, &str)] = &[
            (1, "CAP_DAC_OVERRIDE"),
            (6, "CAP_SETGID"),
            (7, "CAP_SETUID"),
            (12, "CAP_NET_ADMIN"),
            (16, "CAP_SYS_MODULE"),
            (17, "CAP_SYS_RAWIO"),
            (18, "CAP_SYS_CHROOT"),
            (19, "CAP_SYS_PTRACE"),
            (21, "CAP_SYS_ADMIN"),
            (31, "CAP_SETFCAP"),
        ];
        let combined = self.permitted | self.inheritable;
        HIGH_SIGNAL
            .iter()
            .filter_map(|(bit, name)| (combined & (1u64 << bit) != 0).then_some(*name))
            .collect()
    }
}

fn read_file_capabilities(path: &Path) -> Option<CapabilitySet> {
    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let name = b"security.capability\0";
    let mut bytes = [0u8; 24];
    let size = unsafe {
        getxattr(
            path.as_ptr(),
            name.as_ptr().cast(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if size < 12 {
        return None;
    }
    parse_capability_xattr(&bytes[..size as usize])
}

fn parse_capability_xattr(bytes: &[u8]) -> Option<CapabilitySet> {
    if bytes.len() < 12 {
        return None;
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let revision = magic & 0xff00_0000;
    let effective = magic & 0x0000_0001 != 0;
    let low_permitted = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as u64;
    let low_inheritable = u32::from_le_bytes(bytes[8..12].try_into().ok()?) as u64;
    let (permitted, inheritable) = match revision {
        0x0100_0000 => (low_permitted, low_inheritable),
        0x0200_0000 | 0x0300_0000 if bytes.len() >= 20 => (
            low_permitted | ((u32::from_le_bytes(bytes[12..16].try_into().ok()?) as u64) << 32),
            low_inheritable | ((u32::from_le_bytes(bytes[16..20].try_into().ok()?) as u64) << 32),
        ),
        _ => return None,
    };
    let root_id = if revision == 0x0300_0000 && bytes.len() >= 24 {
        Some(u32::from_le_bytes(bytes[20..24].try_into().ok()?))
    } else if revision == 0x0300_0000 {
        return None;
    } else {
        None
    };
    Some(CapabilitySet {
        permitted,
        inheritable,
        effective,
        root_id,
    })
}

fn gtfobins_annotation(binary: &str) -> Option<GtfoAnnotation> {
    let functions = match binary {
        "awk" => "shell,file-read,file-write,suid,sudo",
        "bash" | "sh" => "shell,suid,sudo",
        "cp" | "mv" => "file-read,file-write,suid,sudo",
        "env" => "shell,suid,sudo",
        "find" => "shell,suid,sudo",
        "less" | "more" | "man" => "shell,file-read,sudo",
        "make" => "shell,suid,sudo",
        "nmap" => "shell,suid,sudo",
        "perl" | "python" | "python3" | "ruby" => "shell,suid,sudo",
        "systemctl" => "shell,suid,sudo",
        "tar" | "zip" => "shell,file-read,file-write,suid,sudo",
        "vi" | "vim" => "shell,file-read,file-write,suid,sudo",
        _ => return None,
    };
    Some(GtfoAnnotation { functions })
}

unsafe extern "C" {
    fn getxattr(path: *const c_char, name: *const c_char, value: *mut c_void, size: usize)
        -> isize;
}

#[cfg(test)]
mod tests {
    use super::{gtfobins_annotation, parse_capability_xattr, walk_root, ScanPolicy, ScanStats};
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn parses_vfs_capability_revision_two() {
        let bytes = [
            0x01, 0x00, 0x00, 0x02, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let parsed = parse_capability_xattr(&bytes).unwrap();
        assert!(parsed.effective);
        assert_eq!(parsed.permitted, 0x82);
        assert_eq!(
            parsed.high_signal_names(),
            vec!["CAP_DAC_OVERRIDE", "CAP_SETUID"]
        );
    }

    #[test]
    fn gtfobins_annotations_are_allowlisted_and_recommend_only() {
        assert_eq!(
            gtfobins_annotation("find").map(|annotation| annotation.functions),
            Some("shell,suid,sudo")
        );
        assert!(gtfobins_annotation("ordinary-daemon").is_none());
    }

    #[test]
    fn bounded_walker_skips_symlinks_and_honors_cancellation() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("inside"), b"inside").unwrap();
        std::fs::write(outside.path().join("outside"), b"outside").unwrap();
        symlink(outside.path(), root.path().join("linked-outside")).unwrap();
        let policy = ScanPolicy {
            roots: vec![PathBuf::from(root.path())],
            max_depth: 3,
            max_entries: 10,
            quiet: false,
        };
        let cancel = AtomicBool::new(false);
        let mut stats = ScanStats::default();
        let mut observed = Vec::new();
        walk_root(root.path(), &policy, &cancel, &mut stats, &mut |path, _| {
            observed.push(path.to_path_buf())
        });
        assert_eq!(observed, vec![root.path().join("inside")]);

        cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        observed.clear();
        walk_root(
            root.path(),
            &policy,
            &cancel,
            &mut ScanStats::default(),
            &mut |path, _| observed.push(path.to_path_buf()),
        );
        assert!(observed.is_empty());
    }
}
