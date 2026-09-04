//! Read-only application-control, provenance, sensor, and telemetry assessment.
//!
//! This module intentionally predicts policy outcomes from observed state. It
//! never launches the inspected artifact, changes policy, disables protection,
//! or attempts to evade a control.

use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::core::types::{
    ArtifactAssessment, AuditSource, ControlAssessment, DeploymentGuidance, Finding, FindingKind,
    PolicyControl, SensorInventory, Severity, TelemetryExpectation, ValidationCase,
};

/// Options for live control / telemetry collection.
pub struct CollectOptions<'a> {
    pub platform: &'a str,
    pub artifact: Option<&'a Path>,
    /// Slim OPSEC mode: skip live audit tails, EDR process sweeps, and helper storms.
    pub quiet: bool,
}

/// Full live collection (used by `live-controls` and fixture validation).
pub fn collect(platform: &str, artifact: Option<&Path>) -> ControlAssessment {
    collect_with(CollectOptions {
        platform,
        artifact,
        quiet: false,
    })
}

pub fn collect_with(opts: CollectOptions<'_>) -> ControlAssessment {
    let collected_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let mut assessment = ControlAssessment {
        platform: opts.platform.to_string(),
        collection_mode: if opts.quiet {
            "live-read-only-quiet".into()
        } else {
            "live-read-only".into()
        },
        collected_at_unix,
        validation_cases: validation_cases_for(opts.platform),
        telemetry_expectations: telemetry_expectations(),
        approved_deployment: deployment_guidance(opts.platform),
        ..Default::default()
    };
    let (score, label) = exposure_score(&assessment.telemetry_expectations);
    assessment.detection_exposure = score;
    assessment.detection_exposure_label = label;

    if opts.platform == "linux" {
        collect_linux(&mut assessment, opts.quiet);
    } else if opts.platform == "windows" {
        collect_windows(&mut assessment, opts.quiet);
    } else {
        assessment
            .notes
            .push("Unsupported platform for control inventory".into());
    }

    assessment.artifact = opts
        .artifact
        .map(|path| inspect_artifact(path, opts.platform));
    if opts.quiet {
        assessment.notes.push(
            "Quiet collection: skipped live audit tails, EDR process sweeps, and helper inventory"
                .into(),
        );
        for source in &mut assessment.audit_sources {
            if source.available == "available" {
                source.last_event = "skipped-quiet".into();
                source.evidence.push("live_tail=skipped-quiet".into());
            }
        }
    } else {
        enrich_audit_sources(&mut assessment, opts.artifact);
    }
    let (score, label) = live_telemetry_score(&assessment.audit_sources);
    assessment.live_telemetry_score = score;
    assessment.live_telemetry_label = label;
    assessment
}

fn enrich_audit_sources(assessment: &mut ControlAssessment, artifact: Option<&Path>) {
    let artifact_anchors = artifact.map(|path| {
        (
            path.to_string_lossy().to_ascii_lowercase(),
            path.file_name()
                .map(|name| name.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default(),
        )
    });
    for source in &mut assessment.audit_sources {
        let Some(text) = read_live_audit_source(&source.source) else {
            continue;
        };
        let lower = text.to_ascii_lowercase();
        source.recent_events = text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()
            .min(u32::MAX as usize) as u32;
        source.recent_denials = [
            "deny",
            "denied",
            "block",
            "blocked",
            "avc",
            "apparmor",
            "codeintegrity",
        ]
        .iter()
        .map(|term| lower.matches(term).count())
        .sum::<usize>()
        .min(u32::MAX as usize) as u32;
        source.correlated_artifact_events = artifact_anchors
            .as_ref()
            .map(|(path_text, basename)| {
                let normalized = text.to_ascii_lowercase();
                normalized.matches(path_text).count()
                    + (!basename.is_empty() as usize) * normalized.matches(basename).count()
            })
            .unwrap_or_default()
            .min(u32::MAX as usize) as u32;
        source.last_event = text
            .lines()
            .find(|line| !line.trim().is_empty())
            .map(|line| compact_text(line, 512))
            .unwrap_or_else(|| "not_observed".into());
        source.snapshot_sha256 = digest_string(&text);
        source.evidence.push(format!(
            "recent_events={}; recent_denials={}; correlated_artifact_events={}",
            source.recent_events, source.recent_denials, source.correlated_artifact_events
        ));
    }
}

fn live_telemetry_score(sources: &[AuditSource]) -> (u8, String) {
    let total = sources.len().max(1);
    let available = sources
        .iter()
        .filter(|source| source.available == "available")
        .count();
    let active = sources
        .iter()
        .filter(|source| source.recent_events > 0)
        .count();
    let score = (((available * 60) / total) + ((active * 40) / total)).min(100) as u8;
    let label = match score {
        80..=100 => "live-high-telemetry",
        40..=79 => "live-partial-telemetry",
        _ => "live-low-telemetry",
    };
    (score, label.into())
}

pub fn findings(assessment: &ControlAssessment, plugin: &'static str) -> Vec<Finding> {
    let mut out = Vec::new();
    for policy in &assessment.policies {
        let severity = match policy.mode.as_str() {
            "enforce" | "block" => Severity::Medium,
            "audit" | "complain" => Severity::Low,
            _ => Severity::Info,
        };
        out.push(finding(
            plugin,
            &policy.name,
            "policy-state",
            FindingKind::Enumeration,
            severity,
            format!("{}: {}", policy.name, policy.state),
            format!(
                "mode={}; rules={}; evidence={}; impact={}",
                policy.mode,
                join(&policy.rules),
                join(&policy.evidence),
                policy.impact
            ),
            "Use the listed evidence to validate the expected allow/audit/block behavior; do not alter policy from this tool.",
        ));
    }

    for sensor in &assessment.sensors {
        let tamper_stop = sensor.tamper_protection.starts_with("enabled");
        out.push(finding(
            plugin,
            &sensor.product,
            "sensor-inventory",
            FindingKind::Enumeration,
            if tamper_stop { Severity::Medium } else { Severity::Low },
            format!("Sensor inventory: {}", sensor.product),
            format!(
                "identity={}; health={}; protection_mode={}; tamper_protection={}; policy_version={}; last_update={}; management_scope={}; special_group={}; log_retrieval={}; prevention_rules={}; evidence={}",
                sensor.identity,
                sensor.health,
                sensor.protection_mode,
                sensor.tamper_protection,
                sensor.policy_version,
                sensor.last_update,
                sensor.management_scope,
                sensor.special_group,
                sensor.log_retrieval,
                join(&sensor.prevention_rules),
                join(&sensor.evidence)
            ),
            if tamper_stop {
                "Tamper protection is present: record the state and stop; use the approved security-management workflow for changes."
            } else {
                "Record the sensor state and confirm centrally managed settings with the asset owner."
            },
        ));
    }

    for source in &assessment.audit_sources {
        out.push(finding(
            plugin,
            &source.source,
            "audit-source",
            FindingKind::Enumeration,
            if source.available == "available" {
                Severity::Low
            } else {
                Severity::Info
            },
            format!("Audit source: {} ({})", source.source, source.available),
            format!(
                "correlation={}; recent_events={}; recent_denials={}; correlated_artifact_events={}; last_event={}; snapshot_sha256={}; evidence={}",
                source.correlation,
                source.recent_events,
                source.recent_denials,
                source.correlated_artifact_events,
                source.last_event,
                source.snapshot_sha256,
                join(&source.evidence)
            ),
            "Correlate the validation timestamp, process identity, artifact hash, and policy result in the authorized log workflow.",
        ));
    }

    if let Some(artifact) = &assessment.artifact {
        let severity = match artifact.predicted_decision.as_str() {
            "block" => Severity::Medium,
            "audit" => Severity::Low,
            _ => Severity::Info,
        };
        out.push(finding(
            plugin,
            &artifact.path,
            "artifact-trust-prediction",
            FindingKind::Enumeration,
            severity,
            format!("Trust prediction: {}", artifact.predicted_decision),
            format!(
                "path={}; kind={}; sha256={}; package={}; origin={}; signer={}; publisher={}; product={}; file_version={}; original_filename={}; catalog_signature={}; timestamp={}; policy_rule={}; path_class={}; access_control={}; signature_status={}; integrity_status={}; mount_options={}; static_analysis={}; rationale={}; evidence={}",
                artifact.path,
                artifact.kind,
                artifact.sha256,
                artifact.package,
                artifact.origin,
                artifact.signer,
                artifact.publisher,
                artifact.product,
                artifact.file_version,
                artifact.original_filename,
                artifact.catalog_signature,
                artifact.timestamp,
                artifact.policy_rule,
                artifact.path_class,
                artifact.access_control,
                artifact.signature_status,
                artifact.integrity_status,
                artifact.mount_options,
                join(&artifact.static_analysis),
                artifact.rationale,
                join(&artifact.evidence)
            ),
            "Use an organization-approved signed/package deployment path and re-run this read-only assessment after authorization.",
        ));
    } else {
        out.push(finding(
            plugin,
            "none",
            "artifact-not-supplied",
            FindingKind::Recommendation,
            Severity::Info,
            "No artifact supplied for trust prediction".into(),
            "Policy and sensor inventory was collected; artifact hash, provenance, and predicted decision require --artifact PATH.".into(),
            "Supply a specific executable, script, library, or installer with --artifact PATH for provenance and pre-execution prediction.",
        ));
    }

    let exposures = assessment
        .telemetry_expectations
        .iter()
        .map(|e| format!("{}={}", e.behavior, e.exposure))
        .collect::<Vec<_>>();
    out.push(finding(
        plugin,
        plugin,
        "detection-exposure",
        FindingKind::Enumeration,
        Severity::Info,
        "Detection exposure / telemetry expectation".into(),
        format!(
            "detection_exposure={} ({}/100); {} behavior classes assessed: {}",
            assessment.detection_exposure_label,
            assessment.detection_exposure,
            assessment.telemetry_expectations.len(),
            exposures.join("; ")
        ),
        "Treat this as a preflight expectation, not a stealth score; correlate actual events after each approved validation.",
    ));

    out.push(finding(
        plugin,
        "validation-cases",
        "validation-cases-available",
        FindingKind::Recommendation,
        Severity::Info,
        format!("{} harmless validation cases available", assessment.validation_cases.len()),
        "Cases cover signed/unsigned artifacts, scope and integrity drift, interpreter and mount controls, domain transitions, package provenance, and policy mode differences. All cases are marked non-destructive and do not execute an artifact automatically.".into(),
        "Select one case, obtain explicit ROE approval, use a disposable test artifact, and compare the expected policy result with correlated audit events.",
    ));
    out
}

fn exposure_score(expectations: &[TelemetryExpectation]) -> (u8, String) {
    if expectations.is_empty() {
        return (0, "unknown".into());
    }
    let points: u32 = expectations
        .iter()
        .map(|expectation| match expectation.exposure.as_str() {
            "high" => 3,
            "moderate" => 2,
            "low" => 1,
            _ => 0,
        })
        .sum();
    let maximum = (expectations.len() * 3) as u32;
    let score = ((points * 100) / maximum).min(100) as u8;
    let label = match score {
        0..=33 => "low",
        34..=66 => "moderate",
        _ => "high",
    };
    (score, label.into())
}

#[allow(clippy::too_many_arguments)]
fn finding(
    plugin: &'static str,
    object: &str,
    condition: &str,
    kind: FindingKind,
    severity: Severity,
    title: String,
    detail: String,
    recommendation: &str,
) -> Finding {
    Finding {
        plugin: plugin.into(),
        kind,
        severity,
        title,
        detail,
        recommendation: recommendation.into(),
        noisy: false,
        leaves_artifacts: false,
        object: object.into(),
        condition: condition.into(),
        ..Default::default()
    }
}

fn join(values: &[String]) -> String {
    if values.is_empty() {
        "none".into()
    } else {
        values.join(" | ")
    }
}

fn collect_linux(assessment: &mut ControlAssessment, quiet: bool) {
    let apparmor = Path::new("/sys/module/apparmor").is_dir()
        || Path::new("/sys/kernel/security/apparmor").is_dir();
    let apparmor_mode = if apparmor {
        if fs::read_to_string("/proc/self/attr/current")
            .unwrap_or_default()
            .contains("enforce")
        {
            "enforce"
        } else {
            "complain-or-unknown"
        }
    } else {
        "unknown"
    };
    assessment.policies.push(policy(
        "AppArmor",
        "mandatory_access_control",
        if apparmor { "present" } else { "not_observed" },
        apparmor_mode,
        vec![
            "/sys/module/apparmor".into(),
            "/proc/self/attr/current".into(),
        ],
        "Profile transitions and denials can affect interpreters, libraries, and file access.",
    ));
    if let Ok(profiles) = fs::read_to_string("/sys/kernel/security/apparmor/profiles") {
        assessment.notes.push(format!(
            "AppArmor profiles visible={} current_context={}",
            profiles.lines().count(),
            fs::read_to_string("/proc/self/attr/current")
                .unwrap_or_else(|_| "unreadable".into())
                .trim()
        ));
    }

    let selinux = Path::new("/sys/fs/selinux/enforce").is_file();
    let selinux_mode = fs::read_to_string("/sys/fs/selinux/enforce")
        .unwrap_or_default()
        .trim()
        .to_string();
    assessment.policies.push(policy(
        "SELinux",
        "mandatory_access_control",
        if selinux { "present" } else { "not_observed" },
        if selinux_mode == "1" {
            "enforce"
        } else {
            "permissive-or-unknown"
        },
        vec![
            "/sys/fs/selinux/enforce".into(),
            "/proc/self/attr/current".into(),
        ],
        "SELinux type enforcement and domain transitions can deny execution or access.",
    ));
    assessment.notes.push(format!(
        "SELinux current_context={}",
        fs::read_to_string("/proc/self/attr/current")
            .unwrap_or_else(|_| "unreadable".into())
            .trim()
    ));

    let fapolicyd = Path::new("/etc/fapolicyd").is_dir()
        || Path::new("/usr/sbin/fapolicyd").is_file()
        || Path::new("/var/lib/fapolicyd").is_dir();
    let fapolicyd_config = fs::read_to_string("/etc/fapolicyd/fapolicyd.conf").unwrap_or_default();
    let fapolicyd_mode = if fapolicyd_config.lines().any(|line| {
        let line = line.trim().to_ascii_lowercase();
        line.starts_with("permissive") && line.contains('1')
    }) {
        "audit"
    } else if fapolicyd {
        "enforce-or-configured"
    } else {
        "unknown"
    };
    let fapolicyd_rules = count_regular_files("/etc/fapolicyd/rules.d");
    let fapolicyd_trust = fapolicyd_trust_summary();
    assessment.policies.push(policy(
        "fapolicyd",
        "application_trust",
        if fapolicyd { "present" } else { "not_observed" },
        fapolicyd_mode,
        vec![
            "/etc/fapolicyd".into(),
            "/var/lib/fapolicyd".into(),
            format!("rules.d_regular_files={fapolicyd_rules}"),
            format!("trust_entries={fapolicyd_trust}"),
        ],
        "Package ownership, rules, hashes, MIME types, and integrity settings can change the trust result.",
    ));

    let mountinfo = Path::new("/proc/self/mountinfo").is_file();
    assessment.policies.push(policy(
        "Mount restrictions",
        "mount_security",
        if mountinfo { "present" } else { "unknown" },
        "path-dependent",
        vec!["/proc/self/mountinfo".into()],
        "noexec, nosuid, and nodev can change execution, uid-transition, and device-access behavior.",
    ));

    for (name, path, impact) in [
        (
            "IMA appraisal",
            "/sys/kernel/security/ima",
            "IMA signatures or measurements may be required.",
        ),
        (
            "fs-verity",
            "/sys/fs/verity",
            "Verity-protected files may require immutable verified content.",
        ),
        (
            "kernel lockdown",
            "/sys/kernel/security/lockdown",
            "Lockdown can restrict kernel-facing validation paths.",
        ),
    ] {
        let present = Path::new(path).exists();
        assessment.policies.push(policy(
            name,
            "integrity_or_kernel",
            if present { "present" } else { "not_observed" },
            "unknown",
            vec![path.into()],
            impact,
        ));
    }
    if let Ok(ima_policy) = fs::read_to_string("/sys/kernel/security/ima/policy") {
        assessment.notes.push(format!(
            "IMA policy readable=true rules={}",
            ima_policy
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count()
        ));
    } else if Path::new("/sys/kernel/security/ima").exists() {
        assessment
            .notes
            .push("IMA policy present-but-unreadable".into());
    }

    let seccomp = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("Seccomp:"))
                .map(str::to_string)
        });
    assessment.policies.push(policy(
        "seccomp",
        "syscall_restriction",
        if seccomp.is_some() {
            "present"
        } else {
            "unknown"
        },
        "process-context",
        vec!["/proc/self/status (Seccomp)".into()],
        "The current process profile is evidence for this process only; containers may differ.",
    ));

    let auditd_present =
        Path::new("/etc/audit/auditd.conf").is_file() || Path::new("/sbin/auditd").is_file();
    let fapolicyd_health = if quiet {
        if fapolicyd {
            "installed-process-check-skipped-quiet"
        } else {
            "not_observed"
        }
    } else if process_named_present("fapolicyd") {
        "running"
    } else if fapolicyd {
        "installed-not-running-or-unreadable"
    } else {
        "not_observed"
    };
    assessment.sensors.push(SensorInventory {
        product: "fapolicyd".into(),
        identity: if fapolicyd {
            "filesystem-and-process-signal"
        } else {
            "not_observed"
        }
        .into(),
        health: fapolicyd_health.into(),
        protection_mode: fapolicyd_mode.into(),
        tamper_protection: "not_applicable".into(),
        policy_version: file_mtime("/etc/fapolicyd/fapolicyd.conf"),
        last_update: "not_collected".into(),
        management_scope: "local-config; central-management-unknown".into(),
        special_group: "not_applicable".into(),
        log_retrieval: if readable_file("/var/log/fapolicyd.log") {
            "available"
        } else {
            "not_observed"
        }
        .into(),
        prevention_rules: vec![
            format!("fapolicyd rules.d files={fapolicyd_rules}"),
            if quiet {
                "fapolicyd_rules=skipped-quiet".into()
            } else {
                fapolicyd_rule_summary()
            },
        ],
        evidence: vec![
            format!("rules.d_regular_files={fapolicyd_rules}"),
            "/etc/fapolicyd/fapolicyd.conf".into(),
        ],
    });
    let auditd_health = if quiet {
        if auditd_present {
            "installed-process-check-skipped-quiet"
        } else {
            "not_observed"
        }
    } else if process_named_present("auditd") {
        "running"
    } else if auditd_present {
        "installed-not-running-or-unreadable"
    } else {
        "not_observed"
    };
    assessment.sensors.push(SensorInventory {
        product: "auditd".into(),
        identity: if auditd_present {
            "configuration-or-binary-observed"
        } else {
            "not_observed"
        }
        .into(),
        health: auditd_health.into(),
        protection_mode: "audit".into(),
        tamper_protection: "not_applicable".into(),
        policy_version: file_mtime("/etc/audit/auditd.conf"),
        last_update: "not_collected".into(),
        management_scope: "local-config; central-management-unknown".into(),
        special_group: "not_applicable".into(),
        log_retrieval: if readable_file("/var/log/audit/audit.log") {
            "available"
        } else if Path::new("/var/log/audit/audit.log").exists() {
            "present-but-unreadable"
        } else {
            "not_observed"
        }
        .into(),
        prevention_rules: vec![if quiet {
            "audit_rules=skipped-quiet".into()
        } else {
            audit_rule_summary()
        }],
        evidence: vec![
            "/etc/audit/auditd.conf".into(),
            "/var/log/audit/audit.log".into(),
        ],
    });

    assessment.audit_sources.extend([
        audit_source(
            "/var/log/audit/audit.log",
            readable_file("/var/log/audit/audit.log"),
            "Correlate EXECVE, PATH, AVC, integrity, and policy records by timestamp and pid.",
        ),
        audit_source(
            "/var/log/syslog or journal",
            readable_file("/var/log/syslog") || Path::new("/run/systemd/journal").is_dir(),
            "Correlate service, interpreter, mount, and denial records with the validation id.",
        ),
    ]);

    if !quiet {
        if let Some(mdatp_health) = command_text("mdatp", &["health", "--output", "json"]) {
            assessment.sensors.push(SensorInventory {
                product: "Microsoft Defender for Endpoint (Linux)".into(),
                identity: "mdatp health command available".into(),
                health: "reported-by-mdatp".into(),
                protection_mode: "mdatp health output available".into(),
                tamper_protection: "not_exposed_by_local_health_command".into(),
                policy_version: "reported-by-mdatp-json".into(),
                last_update: "reported-by-mdatp-json".into(),
                management_scope: "organization metadata may be present in mdatp output".into(),
                special_group: "not_reported".into(),
                log_retrieval: if Path::new("/var/log/microsoft/mdatp").is_dir() {
                    "available"
                } else {
                    "not_observed"
                }
                .into(),
                prevention_rules: vec!["mdatp health JSON collected".into()],
                evidence: vec![format!(
                    "mdatp_health={}",
                    compact_text(&mdatp_health, 4096)
                )],
            });
        }

        for (name, product) in linux_sensor_processes() {
            if process_named_present(name) {
                assessment.sensors.push(SensorInventory {
                    product: product.into(),
                    identity: name.into(),
                    health: "process-running".into(),
                    protection_mode: "vendor-specific".into(),
                    tamper_protection: "vendor-specific".into(),
                    policy_version: "not_collected".into(),
                    last_update: "not_collected".into(),
                    management_scope: "vendor-specific".into(),
                    special_group: "not_reported".into(),
                    log_retrieval: "vendor-specific".into(),
                    prevention_rules: vec!["vendor-specific rule API not assumed".into()],
                    evidence: vec![format!("/proc process={name}")],
                });
            }
        }
    }

    assessment.notes.push(format!(
        "Current process seccomp evidence: {}",
        seccomp.unwrap_or_else(|| "unavailable".into())
    ));
    if !quiet {
        assessment
            .notes
            .push(format!("fapolicyd trust inventory: {fapolicyd_trust}"));
    }
    let package_summary = if quiet {
        "skipped-quiet".into()
    } else {
        package_database_summary()
    };
    assessment.policies.push(policy(
        "Package manager trust database",
        "package_provenance",
        if package_summary == "unavailable" || package_summary == "skipped-quiet" {
            "not_observed"
        } else {
            "present"
        },
        "read-only-verification",
        vec![package_summary],
        "Package ownership, installed-file verification, and repository metadata support provenance decisions.",
    ));
    assessment
        .notes
        .push(format!("mount inventory: {}", mount_summary()));
    assessment.notes.push(format!(
        "kernel module inventory: {}",
        kernel_module_summary()
    ));
    assessment.notes.push(format!(
        "namespace/container inventory: {}",
        namespace_summary()
    ));
}

#[cfg(windows)]
fn collect_windows(assessment: &mut ControlAssessment, quiet: bool) {
    let policies = [
        (
            "AppLocker",
            "application_control",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2",
        ),
        (
            "WDAC / Code Integrity",
            "application_control",
            r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy",
        ),
        (
            "Smart App Control / Device Guard",
            "application_control",
            r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
        ),
        (
            "PowerShell policy",
            "script_enforcement",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell",
        ),
        (
            "UMCI / user-mode code integrity",
            "user_mode_code_integrity",
            r"HKLM\SYSTEM\CurrentControlSet\Control\CI",
        ),
        (
            "Managed installer / ISG scope",
            "managed_installer_provenance",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\App Control",
        ),
        (
            "Dynamic code / .NET restriction signals",
            "dynamic_code_security",
            r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config",
        ),
        (
            "HVCI / memory integrity",
            "kernel_code_integrity",
            r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
        ),
        (
            "Vulnerable driver blocklist",
            "kernel_driver_policy",
            r"HKLM\SYSTEM\CurrentControlSet\Control\CI",
        ),
    ];
    for (name, family, key) in policies {
        let result = reg_query(key);
        let present = result.is_some();
        let mode = if result.as_deref().is_some_and(|text| text.contains("Audit")) {
            "audit"
        } else if present {
            "enforce-or-configured"
        } else {
            "unknown"
        };
        assessment.policies.push(policy(
            name,
            family,
            if present { "present" } else { "not_observed" },
            mode,
            vec![key.into()],
            "Policy collections may govern executables, DLLs, scripts, MSI, managed installer, UMCI, or kernel code.",
        ));
    }

    if quiet {
        for channel in [
            "Microsoft-Windows-CodeIntegrity/Operational",
            "Microsoft-Windows-AppLocker/EXE and DLL",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-Windows Defender/Operational",
        ] {
            assessment.audit_sources.push(audit_source(
                channel,
                false,
                "Correlate validation id, process lineage, signer/hash, policy rule, and result.",
            ));
        }
        assessment
            .notes
            .push("Quiet collection: skipped PowerShell/wevtutil sensor inventory".into());
        return;
    }

    let managed_installer = powershell_readonly(
        r#"$p=Get-MpPreference -ErrorAction SilentlyContinue; $keys=@('EnableManagedInstaller','ManagedInstallerEnabled','EnableISG','SmartAppControlState'); [ordered]@{keys=($keys|ForEach-Object {[ordered]@{name=$_;value=$p.$_}});app_control_registry=(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\App Control' -ErrorAction SilentlyContinue|ConvertTo-Json -Compress)}|ConvertTo-Json -Compress"#,
    );
    if let Some(policy) = assessment
        .policies
        .iter_mut()
        .find(|policy| policy.name == "Managed installer / ISG scope")
    {
        policy.evidence.push(snapshot_evidence(
            "managed_installer_effective",
            managed_installer.as_deref(),
        ));
        policy.rules = managed_installer
            .as_deref()
            .map(|text| vec![compact_text(text, 4096)])
            .unwrap_or_default();
    }

    let driver_inventory = powershell_readonly(
        "Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Select-Object Name,State,StartMode,PathName | ConvertTo-Json -Compress",
    );
    if let Some(policy) = assessment
        .policies
        .iter_mut()
        .find(|policy| policy.name == "HVCI / memory integrity")
    {
        policy.evidence.push(snapshot_evidence(
            "system_driver_inventory",
            driver_inventory.as_deref(),
        ));
        policy.rules = driver_inventory
            .as_deref()
            .map(|text| vec![format!("driver_inventory={}", compact_text(text, 4096))])
            .unwrap_or_default();
    }

    let app_locker_effective = powershell_readonly(
        "$p=Get-AppLockerPolicy -Effective -Xml -ErrorAction SilentlyContinue; if($null -ne $p){$p}",
    );
    let wdac_effective = command_text("CiTool.exe", &["-lp", "-json"]);
    if let Some(policy) = assessment
        .policies
        .iter_mut()
        .find(|p| p.name == "AppLocker")
    {
        policy.evidence.push(snapshot_evidence(
            "effective_xml",
            app_locker_effective.as_deref(),
        ));
        policy.rules = app_locker_effective
            .as_deref()
            .map(parse_applocker_rules)
            .unwrap_or_default();
    }
    if let Some(policy) = assessment
        .policies
        .iter_mut()
        .find(|p| p.name == "WDAC / Code Integrity")
    {
        policy
            .evidence
            .push(snapshot_evidence("CiTool", wdac_effective.as_deref()));
        policy.rules = wdac_effective
            .as_deref()
            .map(parse_wdac_rules)
            .unwrap_or_default();
    }

    let defender = reg_query(r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features");
    let defender_status = powershell_readonly(
        "$s=Get-MpComputerStatus -ErrorAction SilentlyContinue; if($null -ne $s){[ordered]@{AMServiceEnabled=$s.AMServiceEnabled;AntivirusEnabled=$s.AntivirusEnabled;RealTimeProtectionEnabled=$s.RealTimeProtectionEnabled;IsTamperProtected=$s.IsTamperProtected;AMProductVersion=$s.AMProductVersion;AMEngineVersion=$s.AMEngineVersion;AntivirusSignatureVersion=$s.AntivirusSignatureVersion;AntivirusSignatureLastUpdated=$s.AntivirusSignatureLastUpdated}|ConvertTo-Json -Compress}",
    );
    let status_field = |key: &str| json_field(defender_status.as_deref(), key);
    let tamper = status_field("IsTamperProtected")
        .or_else(|| reg_value(defender.as_deref(), "TamperProtection"))
        .map(|value| match value.to_ascii_lowercase().as_str() {
            "true" | "1" | "5" => "enabled".into(),
            "false" | "0" => "disabled".into(),
            _ => format!("observed:{value}"),
        })
        .unwrap_or_else(|| "unknown".into());
    let healthy = match (
        status_field("AMServiceEnabled"),
        status_field("AntivirusEnabled"),
        status_field("RealTimeProtectionEnabled"),
    ) {
        (Some(service), Some(av), Some(rt))
            if service == "true" && av == "true" && rt == "true" =>
        {
            "healthy"
        }
        (Some(_), Some(_), Some(_)) => "degraded-or-disabled",
        _ => "unknown",
    };
    let management =
        reg_query(r"HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status")
            .map(|text| {
                if reg_value(Some(text.as_str()), "OrgId").is_some() {
                    "centrally-managed-signal"
                } else {
                    "local-or-unknown"
                }
            })
            .unwrap_or("unknown");
    let special_group =
        reg_query(r"HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status")
            .and_then(|text| reg_value(Some(text.as_str()), "DeviceTag"))
            .unwrap_or_else(|| "not_reported".into());
    assessment.sensors.push(SensorInventory {
        product: "Microsoft Defender / EDR signals".into(),
        identity: if defender.is_some() {
            "registry_identity_observed".into()
        } else {
            "unknown".into()
        },
        health: healthy.into(),
        protection_mode: format!(
            "service={}; av={}; realtime={}",
            status_field("AMServiceEnabled").unwrap_or_else(|| "unknown".into()),
            status_field("AntivirusEnabled").unwrap_or_else(|| "unknown".into()),
            status_field("RealTimeProtectionEnabled").unwrap_or_else(|| "unknown".into())
        ),
        tamper_protection: tamper,
        policy_version: format!(
            "product={}; engine={}; signature={}",
            status_field("AMProductVersion").unwrap_or_else(|| "unknown".into()),
            status_field("AMEngineVersion").unwrap_or_else(|| "unknown".into()),
            status_field("AntivirusSignatureVersion").unwrap_or_else(|| "unknown".into())
        ),
        last_update: status_field("AntivirusSignatureLastUpdated")
            .unwrap_or_else(|| "unknown".into()),
        management_scope: management.into(),
        special_group,
        log_retrieval: "event-channel probe".into(),
        prevention_rules: assessment.policies.iter().map(|p| p.name.clone()).collect(),
        evidence: vec![
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features".into(),
            r"HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status".into(),
            snapshot_evidence("DefenderStatus", defender_status.as_deref()),
        ],
    });

    let defender_preferences = powershell_readonly(
        "$p=Get-MpPreference -ErrorAction SilentlyContinue; if($null -ne $p){[ordered]@{AttackSurfaceReductionRules_Ids=$p.AttackSurfaceReductionRules_Ids;AttackSurfaceReductionRules_Actions=$p.AttackSurfaceReductionRules_Actions;EnableNetworkProtection=$p.EnableNetworkProtection;EnableControlledFolderAccess=$p.EnableControlledFolderAccess;EnableScriptBlockLogging=$p.EnableScriptBlockLogging;EnablePowershellLogging=$p.EnablePowershellLogging;DisableRealtimeMonitoring=$p.DisableRealtimeMonitoring;PUAProtection=$p.PUAProtection;CloudBlockLevel=$p.CloudBlockLevel;EnableIOAVProtection=$p.EnableIOAVProtection;EnableBehaviorMonitoring=$p.EnableBehaviorMonitoring}|ConvertTo-Json -Compress}",
    );
    if let Some(preferences) = defender_preferences {
        if let Some(sensor) = assessment
            .sensors
            .iter_mut()
            .find(|sensor| sensor.product.starts_with("Microsoft Defender /"))
        {
            sensor.prevention_rules.push(format!(
                "DefenderPreferences={}",
                compact_text(&preferences, 4096)
            ));
            sensor.evidence.push(snapshot_evidence(
                "DefenderPreferences",
                Some(preferences.as_str()),
            ));
        }
    }

    if let Some(sense) = powershell_readonly(
        "$s=Get-Service -Name Sense -ErrorAction SilentlyContinue; if($null -ne $s){[ordered]@{Status=$s.Status.ToString();StartType=$s.StartType.ToString();Name=$s.Name}|ConvertTo-Json -Compress}",
    ) {
        assessment.sensors.push(SensorInventory {
            product: "Microsoft Defender for Endpoint Sense".into(),
            identity: "Sense service observed".into(),
            health: json_field(Some(sense.as_str()), "Status").unwrap_or_else(|| "unknown".into()),
            protection_mode: "endpoint-detection-and-response".into(),
            tamper_protection: "managed-by-Defender".into(),
            policy_version: "not_reported_by_service_query".into(),
            last_update: "not_reported_by_service_query".into(),
            management_scope: "organization-managed-signal".into(),
            special_group: "isolation-state-not-exposed-by-local-service-query".into(),
            log_retrieval: "event-channel probe".into(),
            prevention_rules: vec!["Defender preferences attached to primary sensor".into()],
            evidence: vec![format!("SenseService={sense}")],
        });
    }

    if let Some(security_center) = powershell_readonly(
        "$p=Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue; @($p)|Select-Object displayName,productState,pathToSignedProductExe|ConvertTo-Json -Compress",
    ) {
        assessment.sensors.push(SensorInventory {
            product: "Windows SecurityCenter antivirus providers".into(),
            identity: "SecurityCenter2 inventory".into(),
            health: "reported-by-provider-state".into(),
            protection_mode: "provider-specific".into(),
            tamper_protection: "provider-specific".into(),
            policy_version: "not_reported".into(),
            last_update: "not_reported".into(),
            management_scope: "provider-specific".into(),
            special_group: "not_reported".into(),
            log_retrieval: "provider-specific".into(),
            prevention_rules: vec!["provider-specific".into()],
            evidence: vec![format!(
                "SecurityCenter2={}",
                compact_text(&security_center, 4096)
            )],
        });
    }

    for sensor in windows_vendor_sensors() {
        assessment.sensors.push(sensor);
    }

    for channel in [
        "Microsoft-Windows-CodeIntegrity/Operational",
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
    ] {
        assessment.audit_sources.push(audit_source(
            channel,
            event_channel_available(channel),
            "Correlate validation id, process lineage, signer/hash, policy rule, and result.",
        ));
    }
}

#[cfg(windows)]
fn windows_vendor_sensors() -> Vec<SensorInventory> {
    let vendor_patterns = [
        "CrowdStrike",
        "Sentinel",
        "Carbon Black",
        "Cb Defense",
        "Cybereason",
        "Sophos",
        "Trend Micro",
        "McAfee",
        "Trellix",
        "Symantec",
        "Norton",
        "ESET",
        "Bitdefender",
        "Kaspersky",
        "Cylance",
        "Secureworks",
        "Cortex",
        "Palo Alto",
        "Elastic",
        "Tanium",
        "Rapid7",
        "Malwarebytes",
    ];
    let patterns = vendor_patterns.join("|");
    let services_text = powershell_readonly(&format!(
        "$pat='{patterns}'; Get-Service | Where-Object {{$_.DisplayName -match $pat -or $_.Name -match $pat}} | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress"
    ));
    let mut sensors = Vec::new();
    if let Some(text) = services_text {
        let parsed: Vec<serde_json::Value> = if text.trim_start().starts_with('[') {
            serde_json::from_str(&text).unwrap_or_default()
        } else {
            serde_json::from_str::<serde_json::Value>(&text)
                .map(|value| vec![value])
                .unwrap_or_default()
        };
        for service in parsed {
            let name = service
                .get("Name")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown")
                .to_string();
            let display = service
                .get("DisplayName")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown")
                .to_string();
            sensors.push(SensorInventory {
                product: display.clone(),
                identity: format!("service={name}"),
                health: service
                    .get("Status")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                protection_mode: "vendor-specific".into(),
                tamper_protection: "vendor-specific".into(),
                policy_version: "not_collected".into(),
                last_update: "not_collected".into(),
                management_scope: "vendor-specific".into(),
                special_group: "not_reported".into(),
                log_retrieval: "vendor-specific".into(),
                prevention_rules: vec!["vendor-specific rule API not assumed".into()],
                evidence: vec![format!("Get-Service match={display}")],
            });
        }
    }
    sensors
}

#[cfg(not(windows))]
fn collect_windows(_assessment: &mut ControlAssessment, _quiet: bool) {}

pub fn inspect_artifact(path: &Path, platform: &str) -> ArtifactAssessment {
    let mut artifact = ArtifactAssessment {
        path: path.display().to_string(),
        kind: file_kind(path),
        predicted_decision: "unknown".into(),
        rationale: "Insufficient evidence".into(),
        ..Default::default()
    };
    let Ok(meta) = fs::symlink_metadata(path) else {
        artifact.integrity_status = "missing-or-unreadable".into();
        artifact.rationale =
            "The supplied path could not be read; no execution was attempted.".into();
        return artifact;
    };
    artifact.size_bytes = meta.len();
    artifact.sha256 = sha256(path).unwrap_or_else(|| "unavailable".into());
    artifact.integrity_status = if artifact.sha256 == "unavailable" {
        "hash-unavailable".into()
    } else {
        "hash-collected".into()
    };
    artifact
        .evidence
        .push(format!("size_bytes={}", artifact.size_bytes));
    artifact.static_analysis = static_analysis(path, &artifact.kind);

    if platform == "linux" {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            artifact.owner = format!(
                "uid={} gid={} mode={:o}",
                meta.uid(),
                meta.gid(),
                meta.mode() & 0o7777
            );
            artifact.package =
                package_owner(path).unwrap_or_else(|| "manual-or-package-unknown".into());
            artifact.origin =
                if artifact.package.starts_with("dpkg:") || artifact.package.starts_with("rpm:") {
                    "package-database".into()
                } else {
                    "manual-or-unknown".into()
                };
            artifact.access_control = access_control(path);
            artifact.path_class = classify_access_control(path, &artifact.access_control);
            artifact.policy_rule = evaluate_effective_policy(path, platform);
            artifact.evidence.push(format!(
                "fapolicyd_trust_match={}",
                fapolicyd_trust_match(path)
            ));
            if Path::new("/sys/kernel/security/ima").exists() {
                if let Some(ima) = command_text(
                    "getfattr",
                    &[
                        "--only-values",
                        "-n",
                        "security.ima",
                        &path.display().to_string(),
                    ],
                ) {
                    artifact.integrity_status =
                        format!("hash-collected; ima-signature={}", ima.trim());
                    artifact.evidence.push("security.ima xattr readable".into());
                } else {
                    artifact
                        .evidence
                        .push("security.ima xattr not observed".into());
                }
            }
            if let Some(measurement) =
                command_text("fsverity", &["measure", &path.display().to_string()])
            {
                artifact.evidence.push(format!(
                    "fsverity_measure={}",
                    measurement.trim().replace('\n', " | ")
                ));
                artifact.integrity_status.push_str("; fsverity-measured");
            } else if Path::new("/sys/fs/verity").exists() {
                artifact
                    .evidence
                    .push("fsverity_measure=unavailable".into());
            }
            artifact.signature_status = if artifact.package.starts_with("rpm:") {
                command_text(
                    "rpm",
                    &[
                        "-q",
                        "--qf",
                        "%{SIGPGP:pgpsig}",
                        &path.display().to_string(),
                    ],
                )
                .map(|sig| format!("rpm-package-signature={}", sig.trim()))
                .unwrap_or_else(|| "rpm-signature-unavailable".into())
            } else if artifact.package.starts_with("dpkg:") {
                "debian-package-signature-not-collected".into()
            } else {
                "not_applicable".into()
            };
            artifact
                .evidence
                .push(format!("package_signature={}", artifact.signature_status));
            artifact.evidence.push(format!(
                "package_trust={}",
                package_trust_evidence(&artifact.package, path)
            ));
            artifact.mount_options = mount_options(path).unwrap_or_else(|| "unknown".into());
            let noexec = artifact.mount_options.split(',').any(|x| x == "noexec");
            let executable = meta.mode() & 0o111 != 0;
            artifact.predicted_decision = if noexec && executable {
                "block".into()
            } else if artifact.package.starts_with("dpkg:") || artifact.package.starts_with("rpm:")
            {
                "allow".into()
            } else {
                "audit".into()
            };
            artifact.rationale = if noexec && executable {
                "Executable permission is present but the containing mount reports noexec.".into()
            } else if artifact.package.starts_with("dpkg:") || artifact.package.starts_with("rpm:")
            {
                "Package ownership is evidence of provenance; the active trust rule and signature state still require confirmation.".into()
            } else {
                "No package ownership was observed; treat manually copied content as audit/unknown until approved.".into()
            };
            if let Some(cap) = command_text("getcap", &["-n", &path.display().to_string()]) {
                artifact
                    .evidence
                    .push(format!("file_capabilities={}", cap.trim()));
            }
        }
    } else if platform == "windows" {
        artifact.owner = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into());
        #[cfg(windows)]
        {
            let (
                status,
                signer,
                publisher,
                product,
                file_version,
                original_filename,
                origin,
                timestamp,
                chain_status,
            ) = authenticode(path);
            artifact.signature_status = status;
            artifact.signer = signer;
            artifact.publisher = publisher;
            artifact.product = product;
            artifact.file_version = file_version;
            artifact.original_filename = original_filename;
            artifact.origin = origin;
            artifact.timestamp = timestamp;
            artifact.catalog_signature = "not_collected".into();
            artifact
                .evidence
                .push(format!("signer_chain={chain_status}"));
            artifact.access_control = access_control(path);
            artifact.path_class = classify_access_control(path, &artifact.access_control);
            artifact.policy_rule = evaluate_effective_policy(path, platform);
            artifact.predicted_decision = if artifact.signature_status.eq_ignore_ascii_case("valid")
            {
                "allow".into()
            } else if artifact.signature_status.eq_ignore_ascii_case("notsigned") {
                "audit".into()
            } else {
                "unknown".into()
            };
            artifact.rationale = "Authenticode status is evidence only; publisher, product, version, path, hash, managed-installer, and ISG scope must be matched against the effective policy.".into();
        }
        #[cfg(not(windows))]
        {
            artifact.signature_status = "not_collected_non_windows".into();
            artifact.rationale = "Windows signature and effective policy require a Windows host; no execution was attempted.".into();
        }
    }
    artifact
}

/// Read-only driver/module compatibility evidence. This deliberately uses
/// signature and dry-run metadata commands only; it never loads a driver or
/// kernel module.
pub fn inspect_kernel_artifact(path: &Path, platform: &str) -> String {
    if platform == "linux" {
        let path_text = path.display().to_string();
        let info = command_text("modinfo", &[&path_text])
            .map(|text| compact_text(&text, 4096))
            .unwrap_or_else(|| "modinfo=unavailable".into());
        let name = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        let dry_run = if name.is_empty() {
            "modprobe_dry_run=not_attempted".into()
        } else {
            command_text("modprobe", &["--dry-run", "--verbose", name])
                .map(|text| format!("modprobe_dry_run={}", compact_text(&text, 2048)))
                .unwrap_or_else(|| "modprobe_dry_run=unavailable".into())
        };
        return format!("{info}; {dry_run}; lockdown={}", lockdown_state());
    }
    if platform == "windows" {
        #[cfg(windows)]
        {
            let path_text = path.to_string_lossy().into_owned();
            let signature = powershell_readonly_with_arg(
                "$s=Get-AuthenticodeSignature -LiteralPath $args[0]; [ordered]@{Status=$s.Status.ToString();Signer=[string]$s.SignerCertificate.Subject;Publisher=[string]$s.SignerCertificate.Issuer}|ConvertTo-Json -Compress",
                path,
            )
            .map(|text| format!("driver_signature={text}"))
            .unwrap_or_else(|| "driver_signature=unavailable".into());
            let hvci = powershell_readonly(
                "Get-ComputerInfo -Property DeviceGuard* -ErrorAction SilentlyContinue | ConvertTo-Json -Compress",
            )
            .map(|text| format!("hvci={}", compact_text(&text, 4096)))
            .unwrap_or_else(|| "hvci=unavailable".into());
            let _ = path_text;
            return format!("{signature}; {hvci}; load=not_attempted");
        }
        #[cfg(not(windows))]
        {
            return "windows_driver_validation=requires_windows_host".into();
        }
    }
    "kernel_artifact=unsupported_platform".into()
}

fn file_kind(path: &Path) -> String {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match ext.as_str() {
        "ps1" => "powershell_script",
        "msi" => "msi_installer",
        "bat" | "cmd" => "batch_script",
        "dll" => "dll",
        "so" => "shared_object",
        "py" | "pl" | "sh" => "interpreter_script",
        "sys" => "windows_driver",
        "ko" => "linux_kernel_module",
        "exe" | "com" => "windows_executable",
        _ => detect_header_kind(path),
    }
    .into()
}

fn static_analysis(path: &Path, kind: &str) -> Vec<String> {
    let Ok(file) = File::open(path) else {
        return vec!["static_read=unavailable".into()];
    };
    let mut bytes = Vec::new();
    if file.take(8 * 1024 * 1024).read_to_end(&mut bytes).is_err() {
        return vec!["static_read=failed".into()];
    }
    let mut findings = vec![format!("file_class={kind}")];
    if bytes.len() >= 2 && &bytes[..2] == b"MZ" {
        findings.push("format=PE/DOS".into());
        if bytes.len() >= 0x40 {
            let pe_offset =
                u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
            if pe_offset + 24 <= bytes.len() && &bytes[pe_offset..pe_offset + 4] == b"PE\0\0" {
                let machine = u16::from_le_bytes([bytes[pe_offset + 4], bytes[pe_offset + 5]]);
                let sections = u16::from_le_bytes([bytes[pe_offset + 6], bytes[pe_offset + 7]]);
                let optional_size =
                    u16::from_le_bytes([bytes[pe_offset + 20], bytes[pe_offset + 21]]) as usize;
                let optional = pe_offset + 24;
                findings.push(format!("pe_machine=0x{machine:04x}; sections={sections}"));
                if optional + optional_size <= bytes.len() && optional + 2 <= bytes.len() {
                    let magic = u16::from_le_bytes([bytes[optional], bytes[optional + 1]]);
                    let data_directory = if magic == 0x20b {
                        optional + 112
                    } else {
                        optional + 96
                    };
                    let cli_directory = data_directory + (14 * 8);
                    let managed = cli_directory + 8 <= bytes.len()
                        && u32::from_le_bytes([
                            bytes[cli_directory],
                            bytes[cli_directory + 1],
                            bytes[cli_directory + 2],
                            bytes[cli_directory + 3],
                        ]) != 0;
                    findings.push(format!("managed_code={managed}"));
                }
            } else {
                findings.push("pe_header=invalid".into());
            }
        }
        let lower = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
        for indicator in [
            "mscoree.dll",
            "clr.dll",
            "loadlibrary",
            "msi.dll",
            "customaction",
            "binarytable",
        ] {
            if lower.contains(indicator) {
                findings.push(format!("static_indicator={indicator}"));
            }
        }
    } else if bytes.len() >= 4 && &bytes[..4] == b"\x7fELF" {
        findings.push("format=ELF".into());
        if bytes.len() >= 20 {
            let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
            findings.push(format!("elf_machine=0x{machine:04x}"));
        }
        let lower = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
        for indicator in ["dlopen", "libpython", "libperl", "audit", "ima"] {
            if lower.contains(indicator) {
                findings.push(format!("static_indicator={indicator}"));
            }
        }
    } else if bytes.len() >= 8 && bytes[..8] == [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] {
        findings.push("format=OLE/CompoundFile".into());
        findings.push("installer_or_document_container=true".into());
    } else {
        findings.push("format=unrecognized_or_script".into());
    }
    findings
}

#[cfg(windows)]
fn parse_applocker_rules(xml: &str) -> Vec<String> {
    let mut rules = Vec::new();
    for fragment in xml.split('<').skip(1) {
        let tag = fragment.split('>').next().unwrap_or_default().trim();
        if tag.starts_with('/') || tag.starts_with('?') || tag.starts_with('!') {
            continue;
        }
        if tag.contains("Rule") || tag.contains("Publisher") || tag.contains("FilePublisher") {
            let compact = tag.split_whitespace().collect::<Vec<_>>().join(" ");
            if !compact.is_empty() {
                rules.push(compact_text(&compact, 2048));
            }
        }
    }
    rules.sort();
    rules.dedup();
    rules
}

#[cfg(windows)]
fn parse_wdac_rules(text: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return text
            .lines()
            .filter(|line| {
                let lower = line.to_ascii_lowercase();
                lower.contains("policy") || lower.contains("signing") || lower.contains("audit")
            })
            .take(128)
            .map(|line| compact_text(line, 2048))
            .collect();
    };
    let mut rules = Vec::new();
    collect_policy_json(&value, &mut rules);
    rules.sort();
    rules.dedup();
    rules
}

#[cfg(windows)]
fn collect_policy_json(value: &serde_json::Value, rules: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                let lower = key.to_ascii_lowercase();
                if lower.contains("policy")
                    || lower.contains("rule")
                    || lower.contains("sign")
                    || lower.contains("audit")
                    || lower.contains("enforce")
                {
                    if let Some(text) = value.as_str() {
                        rules.push(format!("{key}={}", compact_text(text, 1024)));
                    } else if !value.is_object() && !value.is_array() {
                        rules.push(format!("{key}={value}"));
                    }
                }
                collect_policy_json(value, rules);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_policy_json(value, rules);
            }
        }
        _ => {}
    }
}

#[cfg(unix)]
fn lockdown_state() -> String {
    fs::read_to_string("/sys/kernel/security/lockdown")
        .map(|text| text.trim().to_string())
        .unwrap_or_else(|_| "unavailable".into())
}

#[cfg(not(unix))]
fn lockdown_state() -> String {
    "not_linux".into()
}

fn path_class(path: &Path) -> String {
    let text = path.to_string_lossy().to_ascii_lowercase();
    if text.contains("/tmp/")
        || text.contains("/var/tmp/")
        || text.contains("/dev/shm/")
        || text.contains("\\temp\\")
        || text.contains("\\users\\public\\")
        || text.contains("\\appdata\\local\\temp\\")
    {
        "user-or-temporary".into()
    } else if text.contains("/usr/")
        || text.contains("/bin/")
        || text.contains("/sbin/")
        || text.contains("\\windows\\")
        || text.contains("\\program files\\")
    {
        "administrator-controlled-or-system".into()
    } else {
        "unclassified".into()
    }
}

fn classify_access_control(path: &Path, access_control: &str) -> String {
    let lower = access_control.to_ascii_lowercase();
    if lower.contains("windows_acl=") {
        let broad_write = ["everyone", "users", "authenticated users", "users:"]
            .iter()
            .any(|principal| {
                lower.contains(principal)
                    && ["modify", "write", "fullcontrol", ":f", ":m"]
                        .iter()
                        .any(|right| lower.contains(right))
            });
        if broad_write {
            return "user-writable-by-acl".into();
        }
        if lower.contains("administrators") && lower.contains("system") {
            return "administrator-controlled-by-acl".into();
        }
        return "acl-unclassified".into();
    }
    #[cfg(unix)]
    if let Ok(meta) = fs::symlink_metadata(path) {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode() & 0o7777;
        if mode & 0o002 != 0 || mode & 0o020 != 0 {
            return "user-writable-by-posix-mode".into();
        }
        if meta.uid() == 0 && mode & 0o022 == 0 {
            return "administrator-controlled-by-posix-mode".into();
        }
    }
    path_class(path)
}

fn detect_header_kind(path: &Path) -> &'static str {
    let Ok(mut file) = File::open(path) else {
        return "file";
    };
    let mut header = [0u8; 256];
    let count = file.read(&mut header).unwrap_or_default();
    if count >= 4 && &header[..4] == b"\x7fELF" {
        return "elf_executable";
    }
    if header[..count].starts_with(b"#!") {
        let line = String::from_utf8_lossy(&header[..count]).to_ascii_lowercase();
        if line.contains("python") {
            return "python_script";
        }
        if line.contains("perl") {
            return "perl_script";
        }
        if line.contains("sh") || line.contains("bash") {
            return "shell_script";
        }
        return "interpreter_script";
    }
    "file"
}

fn sha256(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Some(hex::encode(hasher.finalize()))
}

fn policy(
    name: &str,
    family: &str,
    state: &str,
    mode: &str,
    evidence: Vec<String>,
    impact: &str,
) -> PolicyControl {
    PolicyControl {
        name: name.into(),
        family: family.into(),
        state: state.into(),
        mode: mode.into(),
        rules: Vec::new(),
        evidence,
        impact: impact.into(),
    }
}

fn audit_source(source: &str, available: bool, correlation: &str) -> AuditSource {
    AuditSource {
        source: source.into(),
        available: if available {
            "available"
        } else {
            "not_observed"
        }
        .into(),
        correlation: correlation.into(),
        recent_events: 0,
        recent_denials: 0,
        correlated_artifact_events: 0,
        last_event: "not_collected".into(),
        snapshot_sha256: String::new(),
        evidence: vec![source.into()],
    }
}

fn telemetry_expectations() -> Vec<TelemetryExpectation> {
    [
        (
            "privileged process creation",
            "process lineage, signer, integrity level, command line",
            "high",
            "Read metadata and approved policy; do not launch the artifact.",
        ),
        (
            "service or scheduled-task validation",
            "configuration-object access and any modification attempt",
            "high",
            "Read service/task configuration only.",
        ),
        (
            "token or identity transition",
            "source/destination identities, privileges, session",
            "high",
            "Compare current token metadata; do not request a transition.",
        ),
        (
            "sensitive file access",
            "path, permissions, requesting process, result",
            "moderate",
            "Read only explicitly approved metadata paths.",
        ),
        (
            "SUID or file-capability validation",
            "executed inode, uid transition, capability set",
            "high",
            "Inspect mode/capability metadata; do not execute.",
        ),
        (
            "security-policy interaction",
            "policy lookup, denial, audit event, protected-setting alert",
            "high",
            "Read effective policy and correlate existing logs.",
        ),
        (
            "kernel interaction",
            "driver/module identity, signature, loading result",
            "high",
            "Inspect signing/lockdown state; do not load a module or driver.",
        ),
    ]
    .into_iter()
    .map(
        |(behavior, expected_telemetry, exposure, read_only_validation)| TelemetryExpectation {
            behavior: behavior.into(),
            expected_telemetry: expected_telemetry.into(),
            exposure: exposure.into(),
            read_only_validation: read_only_validation.into(),
        },
    )
    .collect()
}

pub fn validation_cases_for(platform: &str) -> Vec<ValidationCase> {
    let common = if platform == "windows" {
        vec![
            ("signed-vs-unsigned", "Compare an unsigned test build with an organization-signed build.", "two disposable artifacts; record hash, signer, publisher, and policy mode", "Different allow/audit/block outcomes by signer and policy scope."),
            ("publisher-scope", "Test trusted publisher with wrong product, filename, or version scope.", "same signer; vary only product metadata, name, and version", "Publisher trust does not imply unrestricted product/path/version trust."),
            ("hash-drift", "Change a hash-authorized artifact after authorization.", "copy and modify a disposable artifact; never use production software", "Changed hash is independently reported and policy result is correlated."),
            ("file-class-scope", "Compare executable, DLL, script, and MSI policy collections.", "one harmless artifact per file class", "Collection-specific decisions and events are recorded."),
            ("managed-installer-boundary", "Assess managed-installer provenance as a configuration boundary.", "review centrally managed provenance and audit events", "Record and stop if administrator or user trust assumptions are broader than intended."),
            ("dynamic-code", "Review .NET/plugin and PowerShell dynamic-code restrictions.", "use policy inspection and a signed vendor test fixture", "Restriction state is recorded without loading an unapproved plugin."),
            ("audit-vs-enforce", "Compare policy audit mode with enforcement using an approved fixture.", "policy-owner-approved test group and disposable artifact", "Audit logs an otherwise-blocked action; enforcement blocks it."),
            ("driver-hvci", "Review driver signing and memory-integrity compatibility.", "inventory only; no driver load", "Signature, HVCI, and blocklist state are correlated."),
            ("install-path-scope", "Compare user-writable and administrator-controlled installation paths.", "same approved fixture staged only in disposable test paths", "Path and managed-installer scope are recorded without changing ACLs or policy."),
            ("policy-drift", "Compare policy versions and effective settings across endpoints.", "export read-only policy metadata from the approved test group", "Drift in publisher, hash, path, audit, or enforcement scope is reported."),
            ("user-path-exec", "Validate default-rule enforcement by starting the benign probe from a user-writable path.", "suite-generated probe in a disposable user-writable directory; opt-in --execute", "AppLocker/WDAC block or audit events are correlated with the execution attempt."),
        ]
    } else {
        vec![
            (
                "package-vs-copy",
                "Compare package-installed and manually copied executables.",
                "same harmless program from package database and a copied fixture",
                "Package ownership and custom-copy trust differ where fapolicyd rules apply.",
            ),
            (
                "package-vs-custom-trust",
                "Compare package database trust with custom trust entries.",
                "read rules and package metadata; do not add trust entries",
                "Rule source and package provenance are recorded.",
            ),
            (
                "integrity-drift",
                "Assess hash or IMA drift for an approved fixture.",
                "hash before/after a disposable copy; no execution",
                "Drift is visible in evidence and predicted trust changes.",
            ),
            (
                "interpreter-script",
                "Review shell, Python, Perl, and shared-object loading restrictions.",
                "inspect shebang, interpreter policy, and library metadata",
                "Interpreter and library policy are correlated without execution.",
            ),
            (
                "mac-domain",
                "Review SELinux/AppArmor domain transitions and denials.",
                "read current profile/domain and existing audit logs",
                "Expected transition/denial event fields are documented.",
            ),
            (
                "mount-flags",
                "Assess noexec, nosuid, and nodev effects.",
                "read mountinfo for the intended test path",
                "Mount state contributes to the allow/audit/block prediction.",
            ),
            (
                "suid-capability",
                "Review SUID and file-capability behavior under policy.",
                "inspect inode mode and getcap output",
                "Expected uid/capability telemetry is recorded; no execution.",
            ),
            (
                "container-host",
                "Compare container and host policy views.",
                "collect separately inside and outside an authorized test container",
                "Policy scope and audit source differences are explicit.",
            ),
            (
                "kernel-lockdown",
                "Review module signing and lockdown compatibility.",
                "read lockdown and module-signing state",
                "No module load is attempted.",
            ),
        ]
    };
    common
        .into_iter()
        .map(
            |(id, objective, setup, expected_observation)| ValidationCase {
                id: id.into(),
                platform: platform.into(),
                objective: objective.into(),
                setup: setup.into(),
                expected_observation: expected_observation.into(),
                destructive: false,
                execute_artifact: false,
            },
        )
        .collect()
}

fn deployment_guidance(platform: &str) -> Vec<DeploymentGuidance> {
    if platform == "windows" {
        vec![
            DeploymentGuidance { channel: "organization-signed executable".into(), requirements: "Approved certificate chain, publisher/product/path/version scope, and hash recorded.".into(), verification: "Verify Authenticode, effective policy rule, and Code Integrity/AppLocker event.".into(), stop_condition: "Tamper protection or enforcement denies the artifact: record and stop.".into() },
            DeploymentGuidance { channel: "MSIX/MSI/software distribution".into(), requirements: "Use the organization-managed deployment channel and approved package identity.".into(), verification: "Correlate installer, policy, signer, and deployment provenance events.".into(), stop_condition: "Do not substitute a manually copied installer when managed provenance is required.".into() },
        ]
    } else {
        vec![
            DeploymentGuidance { channel: "signed RPM/DEB and approved repository".into(), requirements: "Repository/package signature and ownership are verified by the platform workflow.".into(), verification: "Record package owner, signature state, hash, capabilities, and active MAC profile.".into(), stop_condition: "fapolicyd, IMA, SELinux, AppArmor, or mount policy denies: record and stop.".into() },
            DeploymentGuidance { channel: "supplied SELinux/AppArmor profile".into(), requirements: "Profile is reviewed, signed/approved, and deployed by the security owner.".into(), verification: "Correlate profile/domain transition and audit denial/allow events.".into(), stop_condition: "Never weaken or replace a host profile from this tool.".into() },
        ]
    }
}

#[cfg(unix)]
fn count_regular_files(path: &str) -> usize {
    fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.path().is_file())
                .count()
        })
        .unwrap_or_default()
}

#[cfg(not(unix))]
fn count_regular_files(_path: &str) -> usize {
    0
}

#[cfg(unix)]
fn fapolicyd_trust_files() -> Vec<PathBuf> {
    ["/etc/fapolicyd/trust.d", "/var/lib/fapolicyd"]
        .into_iter()
        .flat_map(|directory| {
            fs::read_dir(directory)
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.is_file())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(not(unix))]
fn fapolicyd_trust_files() -> Vec<PathBuf> {
    Vec::new()
}

fn fapolicyd_trust_summary() -> String {
    let files = fapolicyd_trust_files();
    let lines = files
        .iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .map(|text| text.lines().filter(|line| !line.trim().is_empty()).count())
        .sum::<usize>();
    format!("files={}; nonempty_lines={lines}", files.len())
}

#[cfg(unix)]
fn fapolicyd_trust_match(path: &Path) -> String {
    let target = path.to_string_lossy();
    let hash = sha256(path).unwrap_or_default();
    for trust_file in fapolicyd_trust_files() {
        let Ok(text) = fs::read_to_string(&trust_file) else {
            continue;
        };
        if text.lines().any(|line| {
            line.contains(target.as_ref()) || (!hash.is_empty() && line.contains(&hash))
        }) {
            return format!("matched={}", trust_file.display());
        }
    }
    "not_matched".into()
}

fn fapolicyd_rule_summary() -> String {
    let files = ["/etc/fapolicyd/fapolicyd.conf", "/etc/fapolicyd/rules.d"];
    let mut entries = Vec::new();
    if let Ok(text) = fs::read_to_string(files[0]) {
        entries.extend(
            text.lines()
                .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
                .take(12)
                .map(|line| line.trim().to_string()),
        );
    }
    if let Ok(dir) = fs::read_dir(files[1]) {
        for entry in dir
            .flatten()
            .filter(|entry| entry.path().is_file())
            .take(12)
        {
            if let Ok(text) = fs::read_to_string(entry.path()) {
                entries.extend(
                    text.lines()
                        .filter(|line| {
                            !line.trim().is_empty() && !line.trim_start().starts_with('#')
                        })
                        .take(8)
                        .map(|line| {
                            format!("{}: {}", entry.file_name().to_string_lossy(), line.trim())
                        }),
                );
            }
        }
    }
    if entries.is_empty() {
        "fapolicyd_rules=unavailable".into()
    } else {
        format!("fapolicyd_rules={}", entries.join(" | "))
    }
}

fn audit_rule_summary() -> String {
    command_text("auditctl", &["-l"])
        .map(|text| format!("audit_rules={}", compact_text(&text, 4096)))
        .unwrap_or_else(|| "audit_rules=unavailable".into())
}

fn compact_text(text: &str, max_bytes: usize) -> String {
    let text = text.trim().replace('\n', " | ");
    if text.len() <= max_bytes {
        return text;
    }
    let start = text
        .char_indices()
        .find(|(index, _)| *index >= text.len().saturating_sub(max_bytes))
        .map(|(index, _)| index)
        .unwrap_or(0);
    text[start..].to_string()
}

fn package_database_summary() -> String {
    if let Some(text) = command_text("dpkg-query", &["-W", "-f=${binary:Package}\n"]) {
        return format!("dpkg_packages={}", text.lines().count());
    }
    if let Some(text) = command_text("rpm", &["-qa", "--qf", "%{NAME}\n"]) {
        return format!("rpm_packages={}", text.lines().count());
    }
    "unavailable".into()
}

fn mount_summary() -> String {
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        return "mountinfo=unavailable".into();
    };
    let mut noexec = 0usize;
    let mut nosuid = 0usize;
    let mut nodev = 0usize;
    for line in text.lines() {
        let options = line.split_whitespace().nth(5).unwrap_or_default();
        noexec += options.split(',').any(|value| value == "noexec") as usize;
        nosuid += options.split(',').any(|value| value == "nosuid") as usize;
        nodev += options.split(',').any(|value| value == "nodev") as usize;
    }
    format!(
        "mounts={}; noexec={noexec}; nosuid={nosuid}; nodev={nodev}",
        text.lines().count()
    )
}

fn kernel_module_summary() -> String {
    let modules = fs::read_to_string("/proc/modules")
        .map(|text| text.lines().count().to_string())
        .unwrap_or_else(|_| "unavailable".into());
    format!("loaded_modules={modules}; lockdown={}", lockdown_state())
}

fn namespace_summary() -> String {
    let mut values = Vec::new();
    for namespace in ["mnt", "pid", "user", "net", "uts"] {
        let current = fs::read_link(format!("/proc/self/ns/{namespace}"))
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "unavailable".into());
        let init = fs::read_link(format!("/proc/1/ns/{namespace}"))
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "unavailable".into());
        values.push(format!("{namespace}=self:{current},init:{init}"));
    }
    values.join(";")
}

fn readable_file(path: &str) -> bool {
    fs::File::open(path).is_ok()
}

fn file_mtime(path: &str) -> String {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|| "not_collected".into())
}

#[cfg(unix)]
fn process_named_present(name: &str) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        let file_name = entry.file_name();
        let Ok(pid) = file_name.to_string_lossy().parse::<u32>() else {
            return false;
        };
        let _ = pid;
        fs::read_to_string(entry.path().join("comm"))
            .map(|command| command.trim() == name)
            .unwrap_or(false)
    })
}

#[cfg(not(feature = "opsec-string-strip"))]
fn linux_sensor_processes() -> Vec<(&'static str, &'static str)> {
    vec![
        ("falcon-sensor", "CrowdStrike Falcon (Linux)"),
        ("sentinelone-agent", "SentinelOne Agent (Linux)"),
        ("s1-agent", "SentinelOne Agent (Linux)"),
        ("cbagentd", "Broadcom Carbon Black (Linux)"),
        ("cbdaemon", "Broadcom Carbon Black (Linux)"),
        ("RepMgr", "Trellix/McAfee Endpoint Security (Linux)"),
        ("mfetpd", "Trellix/McAfee Threat Prevention (Linux)"),
        ("SophosHealth", "Sophos Intercept X (Linux)"),
        ("savscand", "Sophos Anti-Virus (Linux)"),
        ("symcfgd", "Symantec/Broadcom Endpoint Protection (Linux)"),
        ("rtvscand", "Symantec/Broadcom AntiVirus (Linux)"),
        ("tmdagent", "Trend Micro Deep Security (Linux)"),
        ("ds_agent", "Trend Micro Deep Security (Linux)"),
        ("kesl", "Kaspersky Endpoint Security (Linux)"),
        ("ens", "ESET Server Security (Linux)"),
        ("utl", "ESET Server Security (Linux)"),
        ("bdagentd", "Bitdefender Endpoint Security (Linux)"),
        ("cortex-xdr", "Palo Alto Cortex XDR (Linux)"),
        ("traps_paned", "Palo Alto Cortex XDR (Linux)"),
        ("cylancesvc", "Secureworks Cylance (Linux)"),
        ("elastic-agent", "Elastic Defend/Agent (Linux)"),
        ("osqueryd", "osquery (fleet-managed detection)"),
        ("qualys-cloud-agent", "Qualys Cloud Agent (Linux)"),
        ("tvmagent", "Tenable VM Agent (Linux)"),
        ("ir_agent", "Rapid7 Insight Agent (Linux)"),
        ("taniumclient", "Tanium Client (Linux)"),
    ]
}

#[cfg(feature = "opsec-string-strip")]
fn linux_sensor_processes() -> Vec<(&'static str, &'static str)> {
    vec![
        ("falcon-sensor", "endpoint-sensor"),
        ("sentinelone-agent", "endpoint-sensor"),
        ("s1-agent", "endpoint-sensor"),
        ("cbagentd", "endpoint-sensor"),
        ("cbdaemon", "endpoint-sensor"),
        ("RepMgr", "endpoint-sensor"),
        ("mfetpd", "endpoint-sensor"),
        ("SophosHealth", "endpoint-sensor"),
        ("savscand", "endpoint-sensor"),
        ("symcfgd", "endpoint-sensor"),
        ("rtvscand", "endpoint-sensor"),
        ("tmdagent", "endpoint-sensor"),
        ("ds_agent", "endpoint-sensor"),
        ("kesl", "endpoint-sensor"),
        ("ens", "endpoint-sensor"),
        ("utl", "endpoint-sensor"),
        ("bdagentd", "endpoint-sensor"),
        ("cortex-xdr", "endpoint-sensor"),
        ("traps_paned", "endpoint-sensor"),
        ("cylancesvc", "endpoint-sensor"),
        ("elastic-agent", "endpoint-sensor"),
        ("osqueryd", "endpoint-sensor"),
        ("qualys-cloud-agent", "endpoint-sensor"),
        ("tvmagent", "endpoint-sensor"),
        ("ir_agent", "endpoint-sensor"),
        ("taniumclient", "endpoint-sensor"),
    ]
}

#[cfg(not(unix))]
fn process_named_present(_name: &str) -> bool {
    false
}

#[cfg(unix)]
fn package_owner(path: &Path) -> Option<String> {
    let text = command_text("dpkg-query", &["-S", &path.display().to_string()])
        .map(|s| format!("dpkg: {}", s.trim()))
        .or_else(|| {
            command_text("rpm", &["-qf", &path.display().to_string()])
                .map(|s| format!("rpm: {}", s.trim()))
        })?;
    Some(text)
}

#[cfg(unix)]
fn package_trust_evidence(package: &str, path: &Path) -> String {
    if let Some(name) = package
        .strip_prefix("dpkg:")
        .and_then(|value| value.split(':').next())
    {
        let status = command_text("dpkg-query", &["-W", "-f=${Status} ${Version}", name])
            .map(|text| format!("dpkg_status={}", text.trim()))
            .unwrap_or_else(|| "dpkg_status=unavailable".into());
        let repository = command_text("apt-cache", &["policy", name])
            .map(|text| format!("apt_policy={}", compact_text(&text, 2048)))
            .unwrap_or_else(|| "apt_policy=unavailable".into());
        let file_verify = command_text("debsums", &["-s", name])
            .map(|text| format!("debsums={}", compact_text(&text, 2048)))
            .unwrap_or_else(|| "debsums=unavailable".into());
        return format!(
            "{status}; {repository}; {file_verify}; path={}",
            path.display()
        );
    }
    if let Some(name) = package
        .strip_prefix("rpm:")
        .and_then(|value| value.split_whitespace().next())
    {
        let verify = command_text("rpm", &["-V", name])
            .map(|text| format!("rpm_verify={}", compact_text(&text, 2048)))
            .unwrap_or_else(|| "rpm_verify=unavailable".into());
        return verify;
    }
    "package_database=not_matched".into()
}

#[cfg(unix)]
fn mount_options(path: &Path) -> Option<String> {
    let text = fs::read_to_string("/proc/self/mountinfo").ok()?;
    let target = path.canonicalize().ok()?;
    let mut best: Option<(usize, String)> = None;
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let mountpoint = PathBuf::from(parts[4].replace("\\040", " "));
        if target.starts_with(&mountpoint) {
            let options = parts[5].to_string();
            if best
                .as_ref()
                .is_none_or(|(len, _)| mountpoint.as_os_str().len() > *len)
            {
                best = Some((mountpoint.as_os_str().len(), options));
            }
        }
    }
    best.map(|(_, options)| options)
}

fn command_text(program: &str, args: &[&str]) -> Option<String> {
    let output = crate::core::command::trusted_command(program)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(windows)]
fn read_live_audit_source(source: &str) -> Option<String> {
    command_text(
        "wevtutil.exe",
        &["qe", source, "/c:200", "/rd:true", "/f:RenderedXml"],
    )
}

#[cfg(unix)]
fn read_live_audit_source(source: &str) -> Option<String> {
    if source.contains("audit.log") {
        return fs::read_to_string("/var/log/audit/audit.log")
            .map(|text| tail_text(&text))
            .ok();
    }
    if source.contains("syslog") || source.contains("journal") {
        return command_text(
            "journalctl",
            &["--since", "15 minutes ago", "--no-pager", "-n", "500"],
        )
        .or_else(|| {
            fs::read_to_string("/var/log/syslog")
                .ok()
                .map(|text| tail_text(&text))
        });
    }
    None
}

#[cfg(not(any(unix, windows)))]
fn read_live_audit_source(_source: &str) -> Option<String> {
    None
}

#[cfg(unix)]
fn tail_text(text: &str) -> String {
    const MAX_BYTES: usize = 512 * 1024;
    if text.len() <= MAX_BYTES {
        return text.to_string();
    }
    let start = text
        .char_indices()
        .find(|(index, _)| *index >= text.len() - MAX_BYTES)
        .map(|(index, _)| index)
        .unwrap_or(0);
    text[start..].to_string()
}

fn digest_string(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

fn access_control(path: &Path) -> String {
    #[cfg(windows)]
    {
        if let Some(text) = powershell_readonly_with_arg(
            "$a=Get-Acl -LiteralPath $args[0]; [ordered]@{owner=[string]$a.Owner; access=(@($a.Access)|ForEach-Object {\"$($_.IdentityReference):$($_.FileSystemRights):$($_.AccessControlType):$($_.IsInherited)\"})} | ConvertTo-Json -Compress",
            path,
        ) {
            return format!("windows_acl={text}");
        }
        return "windows_acl=unavailable".into();
    }
    #[cfg(unix)]
    {
        if let Some(text) = command_text("getfacl", &["-cp", &path.display().to_string()]) {
            return format!("posix_acl={}", text.trim().replace('\n', " | "));
        }
        use std::os::unix::fs::MetadataExt;
        return fs::symlink_metadata(path)
            .map(|meta| {
                format!(
                    "mode={:o};uid={};gid={}",
                    meta.mode() & 0o7777,
                    meta.uid(),
                    meta.gid()
                )
            })
            .unwrap_or_else(|_| "posix_acl=unavailable".into());
    }
    #[allow(unreachable_code)]
    "access_control=unavailable".into()
}

fn evaluate_effective_policy(path: &Path, platform: &str) -> String {
    if platform == "linux" {
        if let Some(text) = command_text(
            "fapolicyd-cli",
            &["--check-trust", &path.display().to_string()],
        ) {
            return format!("fapolicyd_check_trust={}", text.trim().replace('\n', " | "));
        }
        return "fapolicyd_check_trust=unavailable; effective_fapolicyd_rule=unresolved".into();
    }
    if platform == "windows" {
        #[cfg(windows)]
        {
            if let Some(text) = powershell_readonly_with_arg(
                "$p=Get-AppLockerPolicy -Effective -ErrorAction Stop; Test-AppLockerPolicy -PolicyObject $p -Path $args[0] -User $env:USERNAME | ConvertTo-Json -Compress",
                path,
            ) {
                return format!("applocker_effective_test={}", text.trim());
            }
            return "applocker_effective_test=unavailable; wdac_rule=requires_CiTool_or_policy_export".into();
        }
        #[cfg(not(windows))]
        {
            return "windows_policy_test=requires_windows_host".into();
        }
    }
    "effective_policy=unsupported_platform".into()
}

#[cfg(windows)]
fn reg_query(key: &str) -> Option<String> {
    command_text("reg.exe", &["query", key]).filter(|text| !text.trim().is_empty())
}

#[cfg(windows)]
fn reg_value(text: Option<&str>, name: &str) -> Option<String> {
    text?.lines().find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        (fields.first().copied() == Some(name) && fields.len() >= 3).then(|| fields[2..].join(" "))
    })
}

#[cfg(windows)]
fn powershell_readonly(script: &str) -> Option<String> {
    command_text(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    )
    .filter(|text| !text.trim().is_empty())
}

#[cfg(windows)]
fn powershell_readonly_with_arg(script: &str, path: &Path) -> Option<String> {
    let path_text = path.to_string_lossy().into_owned();
    command_text(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
            path_text.as_str(),
        ],
    )
    .filter(|text| !text.trim().is_empty())
}

#[cfg(windows)]
fn json_field(text: Option<&str>, key: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text?).ok()?;
    let value = value.get(key)?;
    Some(match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        other => other.to_string(),
    })
}

#[cfg(windows)]
fn snapshot_evidence(name: &str, text: Option<&str>) -> String {
    match text {
        Some(text) => format!("{name}=available;sha256={}", digest_text(text)),
        None => format!("{name}=unavailable"),
    }
}

#[cfg(windows)]
fn digest_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(windows)]
fn event_channel_available(channel: &str) -> bool {
    command_text("wevtutil.exe", &["gl", channel]).is_some()
}

#[cfg(windows)]
fn authenticode(
    path: &Path,
) -> (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
) {
    let script = r#"$p=$args[0]; $s=Get-AuthenticodeSignature -LiteralPath $p; $i=Get-Item -LiteralPath $p; $v=$i.VersionInfo; $z=Get-Item -LiteralPath $p -Stream Zone.Identifier -ErrorAction SilentlyContinue; $chain='not_available'; if($null -ne $s.SignerCertificate){$chain=$s.SignerCertificate.Verify().ToString()}; [ordered]@{status=$s.Status.ToString(); signer=([string]$s.SignerCertificate.Subject); publisher=([string]$v.CompanyName); product=([string]$v.ProductName); file_version=([string]$v.FileVersion); original_filename=([string]$v.OriginalFilename); origin=if($null -ne $z){'downloaded-zone-identifier'}else{'local-or-unknown'}; timestamp=([string]$s.TimeStamperCertificate.Subject); chain=$chain} | ConvertTo-Json -Compress"#;
    let output = crate::core::command::trusted_command("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
            path.to_string_lossy().as_ref(),
        ])
        .output();
    let Some(output) = output.ok().filter(|o| o.status.success()) else {
        return (
            "not_collected".into(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            "unknown".into(),
            String::new(),
            "unknown".into(),
        );
    };
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_default();
    let get = |key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    (
        get("status").to_ascii_lowercase(),
        get("signer"),
        get("publisher"),
        get("product"),
        get("file_version"),
        get("original_filename"),
        get("origin"),
        get("timestamp"),
        get("chain"),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        classify_access_control, collect, compact_text, detect_header_kind, digest_string,
        exposure_score, file_kind, findings, inspect_artifact, path_class, static_analysis,
        validation_cases_for,
    };

    #[test]
    fn validation_cases_are_non_destructive_and_do_not_execute() {
        for platform in ["linux", "windows"] {
            let cases = validation_cases_for(platform);
            assert!(cases.len() >= 8);
            assert!(cases
                .iter()
                .all(|case| !case.destructive && !case.execute_artifact));
        }
    }

    #[test]
    fn collection_is_safe_without_an_artifact() {
        let assessment = collect("linux", None);
        assert_eq!(assessment.platform, "linux");
        assert!(assessment.artifact.is_none());
        assert!(!assessment.telemetry_expectations.is_empty());
    }

    #[test]
    fn collection_modes_and_findings_are_structured() {
        let quiet = super::collect_with(super::CollectOptions {
            platform: "linux",
            artifact: None,
            quiet: true,
        });
        let thorough = collect("linux", None);
        assert_eq!(quiet.collection_mode, "live-read-only-quiet");
        assert!(!findings(&quiet, "linux.app_control").is_empty());
        assert!(!findings(&thorough, "linux.endpoint_controls").is_empty());
        assert!(thorough.live_telemetry_score <= 100);
    }

    #[test]
    fn artifact_classification_and_policy_parsers_cover_safe_inputs() {
        let root = tempfile::tempdir().unwrap();
        let extensions = [
            "sh", "py", "pl", "so", "dll", "msi", "exe", "sys", "ko", "txt",
        ];
        for extension in extensions {
            let path = root.path().join(format!("fixture.{extension}"));
            std::fs::write(&path, format!("fixture {extension}\n")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
            }
            let assessment = inspect_artifact(&path, "linux");
            assert!(!assessment.kind.is_empty());
            assert!(!assessment.sha256.is_empty());
            assert!(!static_analysis(&path, &assessment.kind).is_empty());
        }
        let missing = inspect_artifact(&root.path().join("missing.exe"), "windows");
        assert_eq!(missing.integrity_status, "missing-or-unreadable");
        assert_eq!(file_kind(&root.path().join("fixture.msi")), "msi_installer");
        assert!(!path_class(&root.path().join("fixture.sh")).is_empty());
        let access =
            classify_access_control(&root.path().join("fixture.sh"), "owner=1000 mode=700");
        #[cfg(unix)]
        assert!(access.contains("user-writable"));
        #[cfg(not(unix))]
        assert!(!access.is_empty());
    }

    #[test]
    fn scoring_and_text_helpers_are_bounded() {
        let (_, label) = exposure_score(&[]);
        assert_eq!(label, "unknown");
        let (_, label) = exposure_score(&[super::TelemetryExpectation {
            behavior: "x".into(),
            expected_telemetry: "y".into(),
            exposure: "high".into(),
            read_only_validation: "none".into(),
        }]);
        assert!(["low", "moderate", "high"].contains(&label.as_str()));
        assert_eq!(compact_text("a\n\n b", 3), "  b");
        assert_eq!(digest_string("fixture").len(), 64);
    }

    #[test]
    fn static_analysis_covers_common_binary_headers_and_indicators() {
        let root = tempfile::tempdir().unwrap();
        let elf = root.path().join("sample");
        let mut elf_bytes = b"\x7fELF................dlopen libpython audit ima".to_vec();
        elf_bytes.resize(32, 0);
        elf_bytes[18] = 0x3e;
        std::fs::write(&elf, elf_bytes).unwrap();
        let elf_report = static_analysis(&elf, "elf_executable");
        assert!(elf_report.iter().any(|line| line == "format=ELF"));
        assert!(elf_report
            .iter()
            .any(|line| line.contains("static_indicator=dlopen")));

        let ole = root.path().join("sample.msi");
        std::fs::write(&ole, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).unwrap();
        assert!(static_analysis(&ole, "msi_installer")
            .iter()
            .any(|line| line.contains("OLE")));

        let invalid_pe = root.path().join("invalid.exe");
        let mut pe = vec![0u8; 80];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c] = 0x40;
        std::fs::write(&invalid_pe, pe).unwrap();
        assert!(static_analysis(&invalid_pe, "windows_executable")
            .iter()
            .any(|line| line.contains("pe_header=invalid")));
    }

    #[test]
    fn path_and_header_classification_covers_safe_variants() {
        let root = tempfile::tempdir().unwrap();
        let cases = [
            ("#!/usr/bin/python\n", "python_script"),
            ("#!/usr/bin/perl\n", "perl_script"),
            ("#!/bin/bash\n", "shell_script"),
            ("#!/usr/bin/custom\n", "interpreter_script"),
            ("plain text\n", "file"),
        ];
        for (index, (body, expected)) in cases.iter().enumerate() {
            let path = root.path().join(format!("header{index}"));
            std::fs::write(&path, body).unwrap();
            assert_eq!(detect_header_kind(&path), *expected);
        }
        assert_eq!(
            path_class(std::path::Path::new("/tmp/drop")),
            "user-or-temporary"
        );
        assert_eq!(
            path_class(std::path::Path::new("/usr/bin/tool")),
            "administrator-controlled-or-system"
        );
        assert_eq!(
            path_class(std::path::Path::new("/opt/tool")),
            "unclassified"
        );
        assert_eq!(
            classify_access_control(
                std::path::Path::new("/tmp/drop"),
                "windows_acl=Everyone:Modify"
            ),
            "user-writable-by-acl"
        );
        assert_eq!(
            classify_access_control(
                std::path::Path::new("/tmp/drop"),
                "windows_acl=Administrators;SYSTEM"
            ),
            "administrator-controlled-by-acl"
        );
    }

    #[test]
    fn public_assessment_paths_cover_platform_and_artifact_variants() {
        let windows = collect("windows", None);
        assert_eq!(windows.platform, "windows");
        assert!(!findings(&windows, "windows.app_control").is_empty());
        let unsupported = collect("plan9", None);
        assert_eq!(unsupported.platform, "plan9");
        assert!(!findings(&unsupported, "unknown.plugin").is_empty());

        let root = tempfile::tempdir().unwrap();
        let native = root.path().join("module.ko");
        std::fs::write(&native, b"not a real module").unwrap();
        assert!(super::inspect_kernel_artifact(&native, "linux").contains("lockdown="));
        let windows_driver = super::inspect_kernel_artifact(&native, "windows");
        #[cfg(not(windows))]
        assert_eq!(
            windows_driver,
            "windows_driver_validation=requires_windows_host"
        );
        #[cfg(windows)]
        assert!(
            windows_driver.contains("driver_signature=")
                && windows_driver.contains("load=not_attempted")
        );
        assert_eq!(
            super::inspect_kernel_artifact(&native, "other"),
            "kernel_artifact=unsupported_platform"
        );
        let missing = root.path().join("missing");
        assert_eq!(
            super::static_analysis(&missing, "unknown"),
            vec!["static_read=unavailable"]
        );
        assert_eq!(super::file_kind(&missing), "file");
    }
}
