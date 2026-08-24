//! Fixture-based, authorized application-control validation.
//!
//! The suite creates disposable fixtures, inspects them without loading them,
//! and optionally starts only the suite's own copied probe with `--execute`.
//! It never changes policy, ACLs, trust databases, certificates, mounts,
//! capabilities, SUID bits, or kernel state.

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::core::controls;
use crate::core::types::{
    ArtifactAssessment, ControlAssessment, ControlValidationReport, ValidationResult,
};

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub platform: String,
    pub case_filter: Option<String>,
    pub root: Option<PathBuf>,
    pub artifact: Option<PathBuf>,
    pub signed_artifact: Option<PathBuf>,
    pub baseline: Option<PathBuf>,
    pub execute: bool,
    pub keep_fixtures: bool,
}

struct Fixtures {
    root: PathBuf,
    base: PathBuf,
    comparison_base: PathBuf,
    unsigned: PathBuf,
    changed: PathBuf,
    shell: PathBuf,
    python: PathBuf,
    perl: PathBuf,
    powershell: PathBuf,
    batch: PathBuf,
    library: PathBuf,
    installer: PathBuf,
    user_path: PathBuf,
    admin_path: PathBuf,
}

#[derive(Debug, Default)]
struct EventSnapshot {
    sources: BTreeMap<String, String>,
}

pub fn run(options: &Options) -> Result<ControlValidationReport> {
    let started_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let assessment = controls::collect(&options.platform, options.artifact.as_deref());
    if let Some(sensor) = assessment
        .sensors
        .iter()
        .find(|sensor| sensor.tamper_protection.starts_with("enabled"))
        .cloned()
    {
        return Ok(ControlValidationReport {
            schema_version: "1".into(),
            tool: "stealthy".into(),
            platform: options.platform.clone(),
            started_at_unix,
            case_filter: options.case_filter.clone().unwrap_or_else(|| "all".into()),
            execute_requested: options.execute,
            fixtures_cleaned: true,
            assessment,
            results: vec![ValidationResult {
                case_id: "tamper-protection-stop".into(),
                status: "record_and_stop".into(),
                executed: false,
                fixture_root: String::new(),
                observations: vec![format!("sensor={} tamper_protection={}", sensor.product, sensor.tamper_protection)],
                evidence: sensor.evidence.clone(),
                expected_telemetry: vec!["protected-setting alert and security-management event".into()],
                telemetry_score: 0,
                telemetry_label: "not_measured_record_and_stop".into(),
                observed_telemetry: Vec::new(),
                event_correlation: Vec::new(),
                stop_reason: "Tamper protection is present. No fixture was created and no alternate validation method was attempted.".into(),
            }],
            notes: vec!["Record and stop: use the approved security-management workflow for any authorized change.".into()],
        });
    }
    let (root, owned_root) = fixture_root(options)?;
    let fixtures = prepare_fixtures(&root, options.artifact.as_deref())?;
    let selected = controls::validation_cases_for(&options.platform)
        .into_iter()
        .filter(|case| {
            options.case_filter.as_deref().is_none_or(|filter| {
                case.id == filter
                    || (filter == "hash-drift" && case.id == "integrity-drift")
                    || (filter == "integrity-drift" && case.id == "hash-drift")
            })
        })
        .collect::<Vec<_>>();

    let mut results = Vec::new();
    for case in selected {
        let before = capture_event_snapshot(&assessment);
        let mut result = run_case(&case.id, options, &assessment, &fixtures)?;
        let after = capture_event_snapshot(&assessment);
        let (observed, correlation) = correlate_events(
            &before,
            &after,
            &[fixtures.root.display().to_string(), case.id.clone()],
        );
        let (score, label) = measured_telemetry_score(&assessment, &observed, &correlation);
        result.telemetry_score = score;
        result.telemetry_label = label;
        result.observed_telemetry = observed;
        result.event_correlation = correlation;
        results.push(result);
    }

    let mut notes = vec![
        "Fixtures are disposable and were never used to change host policy, trust databases, ACLs, mounts, capabilities, certificates, or kernel state.".into(),
        "A result of observed means evidence was collected; it does not mean the effective policy allowed or blocked an artifact unless that result is explicitly recorded.".into(),
    ];
    if let Some(baseline) = &options.baseline {
        let baseline_assessment = load_baseline(baseline)?;
        let drift = compare_policy_drift(&baseline_assessment, &assessment);
        notes.push(format!("Policy drift comparison: {drift}"));
    }
    if options.execute {
        notes.push("--execute was requested; only the suite-generated copied probe may be started, with --help, and the exit result is recorded.".into());
    }

    let fixtures_cleaned = owned_root && !options.keep_fixtures;
    let report = ControlValidationReport {
        schema_version: "1".into(),
        tool: "stealthy".into(),
        platform: options.platform.clone(),
        started_at_unix,
        case_filter: options.case_filter.clone().unwrap_or_else(|| "all".into()),
        execute_requested: options.execute,
        fixtures_cleaned,
        assessment,
        results,
        notes,
    };

    if fixtures_cleaned {
        fs::remove_dir_all(&root)
            .with_context(|| format!("clean generated fixture root {}", root.display()))?;
    }
    Ok(report)
}

fn capture_event_snapshot(assessment: &ControlAssessment) -> EventSnapshot {
    let mut snapshot = EventSnapshot::default();
    for source in &assessment.audit_sources {
        if source.available != "available" {
            continue;
        }
        if let Some(text) = read_event_source(&source.source) {
            snapshot.sources.insert(source.source.clone(), text);
        }
    }
    snapshot
}

#[cfg(windows)]
fn read_event_source(source: &str) -> Option<String> {
    Command::new("wevtutil.exe")
        .args(["qe", source, "/c:100", "/rd:true", "/f:RenderedXml"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(unix)]
fn read_event_source(source: &str) -> Option<String> {
    if source.contains("audit.log") {
        return fs::read_to_string("/var/log/audit/audit.log")
            .ok()
            .map(|text| tail_text(&text));
    }
    if source.contains("syslog") || source.contains("journal") {
        return Command::new("journalctl")
            .args(["--since", "5 minutes ago", "--no-pager", "-n", "200"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .or_else(|| {
                fs::read_to_string("/var/log/syslog")
                    .ok()
                    .map(|text| tail_text(&text))
            });
    }
    None
}

#[cfg(not(any(unix, windows)))]
fn read_event_source(_source: &str) -> Option<String> {
    None
}

#[cfg(unix)]
fn tail_text(text: &str) -> String {
    const MAX_BYTES: usize = 256 * 1024;
    if text.len() <= MAX_BYTES {
        text.to_string()
    } else {
        let start = text
            .char_indices()
            .find(|(index, _)| *index >= text.len() - MAX_BYTES)
            .map(|(index, _)| index)
            .unwrap_or(0);
        text[start..].to_string()
    }
}

fn correlate_events(
    before: &EventSnapshot,
    after: &EventSnapshot,
    anchors: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut observed = Vec::new();
    let mut correlation = Vec::new();
    for (source, after_text) in &after.sources {
        let before_text = before
            .sources
            .get(source)
            .map(String::as_str)
            .unwrap_or_default();
        let before_hash = digest_text(before_text);
        let after_hash = digest_text(after_text);
        if before_hash == after_hash {
            observed.push(format!("{source}: unchanged; sha256={after_hash}"));
            continue;
        }
        observed.push(format!(
            "{source}: changed; before_sha256={before_hash}; after_sha256={after_hash}"
        ));
        let lower = after_text.to_ascii_lowercase();
        let anchor_hits = anchors
            .iter()
            .filter(|anchor| lower.contains(&anchor.to_ascii_lowercase()))
            .count();
        let denial_hits = ["deny", "block", "audit", "avc", "apparmor", "codeintegrity"]
            .iter()
            .map(|term| lower.matches(term).count())
            .sum::<usize>();
        correlation.push(format!(
            "{source}: anchor_hits={anchor_hits}; policy_signal_hits={denial_hits}"
        ));
    }
    if after.sources.is_empty() {
        observed.push(
            "no readable audit/event source was available for before/after comparison".into(),
        );
    }
    (observed, correlation)
}

fn measured_telemetry_score(
    assessment: &ControlAssessment,
    observed: &[String],
    correlation: &[String],
) -> (u8, String) {
    let available = assessment
        .audit_sources
        .iter()
        .filter(|source| source.available == "available")
        .count();
    let expected = assessment.audit_sources.len().max(1);
    let source_score = ((available * 60) / expected).min(60);
    let changed = observed
        .iter()
        .filter(|entry| entry.contains(": changed;"))
        .count();
    let correlation_score = if correlation.is_empty() {
        0
    } else {
        (changed * 40).min(40)
    };
    let score = (source_score + correlation_score).min(100) as u8;
    let label = match score {
        80..=100 => "measured-high-telemetry",
        40..=79 => "measured-partial-telemetry",
        _ => "measured-low-telemetry",
    };
    (score, label.into())
}

fn digest_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

fn fixture_root(options: &Options) -> Result<(PathBuf, bool)> {
    if let Some(root) = &options.root {
        fs::create_dir_all(root)
            .with_context(|| format!("create fixture root {}", root.display()))?;
        return Ok((root.clone(), false));
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!(
        "stealthy-control-tests-{}-{}",
        std::process::id(),
        nonce
    ));
    fs::create_dir_all(&root)?;
    Ok((root, true))
}

fn prepare_fixtures(root: &Path, source: Option<&Path>) -> Result<Fixtures> {
    fs::create_dir_all(root)?;
    let base = root.join(if cfg!(windows) { "probe.exe" } else { "probe" });
    let probe_source = std::env::current_exe().unwrap_or_else(|_| root.join("missing-source"));
    copy_or_placeholder(&probe_source, &base)?;
    make_executable(&base)?;

    let comparison_base = root.join(if cfg!(windows) {
        "comparison-base.exe"
    } else {
        "comparison-base"
    });
    copy_or_placeholder(source.unwrap_or(&probe_source), &comparison_base)?;
    make_executable(&comparison_base)?;

    let unsigned = root.join(if cfg!(windows) {
        "unsigned.exe"
    } else {
        "unsigned"
    });
    copy_or_placeholder(&comparison_base, &unsigned)?;
    make_executable(&unsigned)?;
    let changed = root.join(if cfg!(windows) {
        "hash-drift.exe"
    } else {
        "hash-drift"
    });
    copy_or_placeholder(&comparison_base, &changed)?;
    OpenOptions::new()
        .append(true)
        .open(&changed)
        .and_then(|mut f| f.write_all(b"\nfixture-hash-drift\n"))?;
    make_executable(&changed)?;

    let shell = root.join("trusted-interpreter.sh");
    let python = root.join("trusted-interpreter.py");
    let perl = root.join("trusted-interpreter.pl");
    let powershell = root.join("trusted-interpreter.ps1");
    let batch = root.join("trusted-interpreter.cmd");
    write_fixture(&shell, b"#!/bin/sh\nexit 0\n")?;
    write_fixture(&python, b"#!/usr/bin/env python3\nprint('control-test')\n")?;
    write_fixture(&perl, b"#!/usr/bin/perl\nprint \"control-test\\n\";\n")?;
    write_fixture(&powershell, b"Write-Output 'control-test'\n")?;
    write_fixture(&batch, b"@echo off\nexit /b 0\n")?;

    let library = root.join(if cfg!(windows) {
        "plugin.dll"
    } else {
        "plugin.so"
    });
    let installer = root.join("package.msi");
    write_fixture(
        &library,
        b"disposable library metadata fixture; never loaded\n",
    )?;
    write_fixture(
        &installer,
        b"disposable installer metadata fixture; never installed\n",
    )?;

    let user_path = root.join("user-writable");
    let admin_path = root.join("administrator-controlled");
    fs::create_dir_all(&user_path)?;
    fs::create_dir_all(&admin_path)?;
    set_mode(&user_path, 0o700)?;
    set_mode(&admin_path, 0o755)?;
    configure_windows_acl_fixtures(&user_path, &admin_path);

    Ok(Fixtures {
        root: root.to_path_buf(),
        base,
        comparison_base,
        unsigned,
        changed,
        shell,
        python,
        perl,
        powershell,
        batch,
        library,
        installer,
        user_path,
        admin_path,
    })
}

fn run_case(
    case_id: &str,
    options: &Options,
    assessment: &ControlAssessment,
    fixtures: &Fixtures,
) -> Result<ValidationResult> {
    let mut result = ValidationResult {
        case_id: case_id.into(),
        status: "observed".into(),
        executed: false,
        fixture_root: fixtures.root.display().to_string(),
        expected_telemetry: expected_telemetry(case_id),
        ..Default::default()
    };

    match case_id {
        "signed-vs-unsigned" => {
            result
                .observations
                .push(describe(controls::inspect_artifact(
                    &fixtures.unsigned,
                    &options.platform,
                )));
            if let Some(signed) = &options.signed_artifact {
                result
                    .observations
                    .push(describe(controls::inspect_artifact(
                        signed,
                        &options.platform,
                    )));
                result
                    .evidence
                    .push(format!("signed_fixture={}", signed.display()));
            } else {
                result.status = "requires_signed_fixture".into();
                result.stop_reason = "Provide --signed-artifact from the approved organization signing workflow; the harness does not create certificates or alter a certificate store.".into();
            }
        }
        "publisher-scope" => {
            let Some(signed) = &options.signed_artifact else {
                result.status = "requires_signed_fixture".into();
                result.stop_reason = "No organization-signed artifact was supplied.".into();
                return Ok(result);
            };
            let signed_info = controls::inspect_artifact(signed, &options.platform);
            result.observations.push(describe(signed_info));
            result.observations.push("Product, original filename, and version are collected for comparison; effective publisher/path/version rule matching remains policy-owner evidence.".into());
        }
        "hash-drift" | "integrity-drift" => {
            let before = controls::inspect_artifact(&fixtures.comparison_base, &options.platform);
            let after = controls::inspect_artifact(&fixtures.changed, &options.platform);
            result
                .observations
                .push(format!("before_sha256={}", before.sha256));
            result
                .observations
                .push(format!("after_sha256={}", after.sha256));
            result.status = if !before.sha256.is_empty() && before.sha256 != after.sha256 {
                "observed_drift".into()
            } else {
                "inconclusive".into()
            };
        }
        "file-class-scope" => {
            for path in [
                &fixtures.base,
                &fixtures.library,
                &fixtures.powershell,
                &fixtures.installer,
            ] {
                let info = controls::inspect_artifact(path, &options.platform);
                result
                    .observations
                    .push(format!("{} => {}", path.display(), info.kind));
                result.evidence.push(path.display().to_string());
            }
        }
        "install-path-scope" => {
            result
                .observations
                .push(path_observation(&fixtures.user_path, &options.platform));
            result
                .observations
                .push(path_observation(&fixtures.admin_path, &options.platform));
            result.observations.push("The generated administrator-controlled fixture receives an explicit Windows ACL when icacls is available; the resulting ACL is read back into the evidence.".into());
        }
        "dynamic-code" => {
            for path in [
                &fixtures.powershell,
                &fixtures.library,
                &fixtures.shell,
                &fixtures.python,
                &fixtures.perl,
            ] {
                result.observations.push(format!(
                    "{} => {}",
                    path.display(),
                    controls::inspect_artifact(path, &options.platform).kind
                ));
            }
            result.observations.push("Plugin/shared-library loading was not attempted; policy and file-class evidence only.".into());
        }
        "interpreter-script" => {
            for path in [
                &fixtures.shell,
                &fixtures.python,
                &fixtures.perl,
                &fixtures.powershell,
                &fixtures.batch,
            ] {
                result.observations.push(format!(
                    "{} => {}",
                    path.display(),
                    controls::inspect_artifact(path, &options.platform).kind
                ));
            }
            if options.execute {
                let executions = execute_interpreters(&fixtures.root, fixtures);
                result.executed = !executions.is_empty();
                result.observations.extend(executions);
                result.status = "observed_interpreter_execution".into();
            } else {
                result.status = "ready_for_explicit_interpreter_probe".into();
                result.stop_reason = "Re-run with --execute to start only the generated scripts through trusted interpreters.".into();
            }
        }
        "audit-vs-enforce" => {
            if options.execute {
                let (status, detail) = execute_probe(&fixtures.base, &fixtures.root)?;
                result.executed = true;
                result.observations.push(detail);
                result.status = status;
            } else {
                result.status = "ready_for_explicit_probe".into();
                result.stop_reason =
                    "Re-run with --execute to start only the generated benign probe with --help."
                        .into();
            }
            result.observations.push(policy_modes(assessment));
        }
        "managed-installer-boundary" => {
            result
                .observations
                .push(policy_summary(assessment, "managed_installer_provenance"));
            result.observations.push("Managed-installer trust is assessed as a configuration boundary; no trust entry or installer provenance was changed.".into());
            if assessment
                .sensors
                .iter()
                .any(|s| s.tamper_protection.starts_with("enabled"))
            {
                result.status = "record_and_stop".into();
                result.stop_reason = "Tamper protection evidence is present.".into();
            }
        }
        "driver-hvci" | "kernel-lockdown" => {
            result
                .observations
                .push(policy_summary(assessment, "integrity_or_kernel"));
            if let Some(artifact) = &options.artifact {
                result.observations.push(format!(
                    "kernel_artifact={}",
                    controls::inspect_kernel_artifact(artifact, &options.platform)
                ));
                result.evidence.push(artifact.display().to_string());
            } else {
                result.observations.push(
                    "No driver/module supplied; provide --artifact with an approved test artifact for signature and dry-run compatibility evidence.".into(),
                );
            }
            result.observations.push(
                "Signature and dry-run compatibility metadata are collected; no driver, module, or kernel policy is loaded.".into(),
            );
        }
        "mount-flags" => {
            result.observations.push(format!(
                "fixture_mount={}",
                controls::inspect_artifact(&fixtures.base, &options.platform).mount_options
            ));
            result
                .observations
                .push("noexec/nosuid/nodev effects were assessed from mount metadata only.".into());
            if options.execute {
                let probe = execute_mount_namespace_probe(&fixtures.base, &fixtures.root);
                result.executed = probe.is_some();
                if let Some(probe) = probe {
                    result.observations.push(probe);
                    result.status = "observed_mount_namespace_probe".into();
                } else {
                    result.status = "mount_namespace_probe_unavailable".into();
                    result.stop_reason = "The host did not permit an isolated mount namespace or does not provide unshare/mount; no host mount was changed.".into();
                }
            } else {
                result.status = "ready_for_explicit_mount_probe".into();
                result.stop_reason = "Re-run with --execute to attempt only an isolated noexec/nosuid/nodev mount namespace probe.".into();
            }
        }
        "suid-capability" => {
            let inspected = options.artifact.as_deref().unwrap_or(&fixtures.base);
            let info = controls::inspect_artifact(inspected, &options.platform);
            result.observations.push(format!(
                "owner_mode={}; evidence={}",
                info.owner,
                info.evidence.join(" | ")
            ));
            result.observations.push(
                "No SUID bit or file capability was added and the fixture was not executed.".into(),
            );
        }
        "package-vs-copy" => {
            let package_path = if Path::new("/bin/sh").exists() {
                PathBuf::from("/bin/sh")
            } else {
                fixtures.base.clone()
            };
            result.observations.push(format!(
                "package_candidate={}",
                describe(controls::inspect_artifact(&package_path, &options.platform))
            ));
            let manual_copy = options
                .artifact
                .as_deref()
                .unwrap_or(&fixtures.comparison_base);
            result.observations.push(format!(
                "manual_copy={}",
                describe(controls::inspect_artifact(manual_copy, &options.platform))
            ));
        }
        "package-vs-custom-trust" => {
            result
                .observations
                .push(policy_summary(assessment, "application_trust"));
            result.observations.push("Package database and custom trust entries were inspected read-only; no trust entry was added.".into());
        }
        "mac-domain" => {
            result
                .observations
                .push(read_text_observation("/proc/self/attr/current"));
            result
                .observations
                .push(policy_summary(assessment, "mandatory_access_control"));
            if options.execute {
                let probes = execute_mac_probes(&fixtures.base, &fixtures.root);
                result.executed = !probes.is_empty();
                result.observations.extend(probes);
                result.status = if result.executed {
                    "observed_mac_probe".into()
                } else {
                    "mac_probe_unavailable".into()
                };
            } else {
                result.status = "ready_for_explicit_mac_probe".into();
                result.stop_reason = "Re-run with --execute to run only the generated probe under the current MAC context/profile when the host exposes a supported launcher.".into();
            }
        }
        "container-host" => {
            result
                .observations
                .push(read_text_observation("/proc/1/cgroup"));
            result.observations.push(format!(
                "dockerenv_present={}; containerenv_present={}",
                Path::new("/.dockerenv").exists(),
                Path::new("/run/.containerenv").exists()
            ));
            result.observations.push("Host and container policy differences require separate authorized runs; no container boundary was crossed.".into());
            if let Some(baseline) = &options.baseline {
                let baseline = load_baseline(baseline)?;
                result.observations.push(format!(
                    "paired_policy_comparison={}",
                    compare_policy_drift(&baseline, assessment)
                ));
            } else {
                result.stop_reason = "Provide --baseline from the paired host or container run to compare policy, sensor, and audit scope.".into();
            }
        }
        "policy-drift" => {
            if let Some(path) = &options.baseline {
                let baseline = load_baseline(path)?;
                result
                    .observations
                    .push(compare_policy_drift(&baseline, assessment));
            } else {
                result.status = "requires_baseline".into();
                result.stop_reason =
                    "Provide --baseline with a prior JSON control assessment or report.".into();
            }
        }
        "user-path-exec" => {
            let staged = fixtures.user_path.join(
                fixtures
                    .base
                    .file_name()
                    .unwrap_or_else(|| std::ffi::OsStr::new("probe")),
            );
            copy_or_placeholder(&fixtures.base, &staged)?;
            make_executable(&staged)?;
            result
                .observations
                .push(format!("staged_path={}", staged.display()));
            result
                .observations
                .push(path_observation(&fixtures.user_path, &options.platform));
            if options.execute {
                let (status, detail) = execute_probe(&staged, &fixtures.root)?;
                result.executed = true;
                result.observations.push(detail);
                result.status = status;
            } else {
                result.status = "ready_for_explicit_probe".into();
                result.stop_reason = "Re-run with --execute to start only the benign probe from the disposable user-writable path.".into();
            }
        }
        _ => {
            result.status = "unsupported_case".into();
        }
    }
    Ok(result)
}

fn expected_telemetry(case_id: &str) -> Vec<String> {
    match case_id {
        "audit-vs-enforce" | "signed-vs-unsigned" | "publisher-scope" | "hash-drift"
        | "integrity-drift" | "file-class-scope" | "dynamic-code" => vec![
            "process lineage, signer/hash, integrity level, command line, policy rule, and result"
                .into(),
        ],
        "install-path-scope"
        | "package-vs-copy"
        | "package-vs-custom-trust"
        | "mount-flags"
        | "suid-capability" => {
            vec!["path, permissions, provenance, requesting process, and result".into()]
        }
        "driver-hvci" | "kernel-lockdown" => {
            vec!["driver/module identity, signature, lockdown state, and loading result".into()]
        }
        "container-host" => vec!["host/container identity, policy scope, and audit source".into()],
        "user-path-exec" => {
            vec![
                "process creation, path, policy rule, block/audit decision, and parent lineage"
                    .into(),
            ]
        }
        _ => vec![
            "policy lookup, audit/denial, protected-setting alert, and validation result".into(),
        ],
    }
}

fn describe(info: ArtifactAssessment) -> String {
    format!("path={}; kind={}; sha256={}; origin={}; signer={}; publisher={}; product={}; version={}; signature={}; decision={}; rule={}; access_control={}; static_analysis={}", info.path, info.kind, info.sha256, info.origin, info.signer, info.publisher, info.product, info.file_version, info.signature_status, info.predicted_decision, info.policy_rule, info.access_control, info.static_analysis.join(" | "))
}

fn path_observation(path: &Path, platform: &str) -> String {
    let meta = fs::metadata(path);
    match meta {
        Ok(meta) => {
            let acl = controls::inspect_artifact(path, platform).access_control;
            format!(
                "{} exists=true readonly={} size={} access_control={}",
                path.display(),
                meta.permissions().readonly(),
                meta.len(),
                acl
            )
        }
        Err(error) => format!("{} unreadable={error}", path.display()),
    }
}

fn policy_summary(assessment: &ControlAssessment, family: &str) -> String {
    assessment
        .policies
        .iter()
        .filter(|p| {
            p.family == family
                || p.name
                    .to_ascii_lowercase()
                    .contains(&family.replace('_', " "))
        })
        .map(|p| format!("{}={}/{}", p.name, p.state, p.mode))
        .collect::<Vec<_>>()
        .join("; ")
}

fn policy_modes(assessment: &ControlAssessment) -> String {
    assessment
        .policies
        .iter()
        .filter(|p| p.mode == "audit" || p.mode.contains("enforce"))
        .map(|p| format!("{}={}", p.name, p.mode))
        .collect::<Vec<_>>()
        .join("; ")
}

fn read_text_observation(path: &str) -> String {
    match fs::read_to_string(path) {
        Ok(text) => format!("{}={}", path, text.trim()),
        Err(error) => format!("{} unavailable={error}", path),
    }
}

fn execute_probe(path: &Path, root: &Path) -> Result<(String, String)> {
    let output = Command::new(path)
        .arg("--help")
        .current_dir(root)
        .output()
        .with_context(|| format!("start generated benign probe {}", path.display()))?;
    let detail = format!(
        "probe={} exit_code={:?} stdout_bytes={} stderr_bytes={}",
        path.display(),
        output.status.code(),
        output.stdout.len(),
        output.stderr.len()
    );
    if output.status.success() {
        Ok(("observed_execution".into(), detail))
    } else {
        Ok(("blocked_or_failed_execution".into(), detail))
    }
}

fn execute_interpreters(root: &Path, fixtures: &Fixtures) -> Vec<String> {
    #[cfg(unix)]
    let commands = vec![
        ("sh", vec![fixtures.shell.as_path()]),
        ("python3", vec![fixtures.python.as_path()]),
        ("perl", vec![fixtures.perl.as_path()]),
    ];
    #[cfg(windows)]
    let commands = vec![
        ("powershell.exe", vec![fixtures.powershell.as_path()]),
        ("cmd.exe", vec![fixtures.batch.as_path()]),
    ];

    commands
        .into_iter()
        .map(|(program, args)| {
            let output = Command::new(program).args(args).current_dir(root).output();
            match output {
                Ok(output) => format!(
                    "interpreter={} exit_code={:?} stdout_bytes={} stderr_bytes={}",
                    program,
                    output.status.code(),
                    output.stdout.len(),
                    output.stderr.len()
                ),
                Err(error) => format!("interpreter={} unavailable={error}", program),
            }
        })
        .collect()
}

#[cfg(unix)]
fn execute_mac_probes(probe: &Path, root: &Path) -> Vec<String> {
    let mut results = Vec::new();
    let path_text = probe.display().to_string();
    if let Ok(output) = Command::new("runcon")
        .args(["--current", path_text.as_str(), "--help"])
        .current_dir(root)
        .output()
    {
        results.push(format!(
            "selinux_runcon_current exit_code={:?} stdout_bytes={} stderr_bytes={}",
            output.status.code(),
            output.stdout.len(),
            output.stderr.len()
        ));
    }
    if let Ok(context) = fs::read_to_string("/proc/self/attr/current") {
        let profile = context.split_whitespace().next().unwrap_or_default();
        if !profile.is_empty() && profile != "unconfined" && profile != "unconfined//null" {
            if let Ok(output) = Command::new("aa-exec")
                .args(["-p", profile, "--", path_text.as_str(), "--help"])
                .current_dir(root)
                .output()
            {
                results.push(format!(
                    "apparmor_aa_exec profile={} exit_code={:?} stdout_bytes={} stderr_bytes={}",
                    profile,
                    output.status.code(),
                    output.stdout.len(),
                    output.stderr.len()
                ));
            }
        }
    }
    results
}

#[cfg(not(unix))]
fn execute_mac_probes(_probe: &Path, _root: &Path) -> Vec<String> {
    Vec::new()
}

#[cfg(unix)]
fn execute_mount_namespace_probe(probe: &Path, root: &Path) -> Option<String> {
    let path_text = probe.display().to_string();
    let script = "set -eu; d=$(mktemp -d); trap 'umount \"$d\" 2>/dev/null || true; rmdir \"$d\" 2>/dev/null || true' EXIT; mount -t tmpfs -o noexec,nosuid,nodev stealthy-test \"$d\"; cp \"$1\" \"$d/probe\"; chmod 700 \"$d/probe\"; \"$d/probe\" --help";
    let output = Command::new("unshare")
        .args([
            "--mount",
            "--propagation",
            "private",
            "sh",
            "-c",
            script,
            "stealthy-mount-probe",
            path_text.as_str(),
        ])
        .current_dir(root)
        .output()
        .ok()?;
    Some(format!(
        "isolated_mount_probe exit_code={:?} success={} stdout_bytes={} stderr_bytes={}",
        output.status.code(),
        output.status.success(),
        output.stdout.len(),
        output.stderr.len()
    ))
}

#[cfg(not(unix))]
fn execute_mount_namespace_probe(_probe: &Path, _root: &Path) -> Option<String> {
    None
}

fn load_baseline(path: &Path) -> Result<ControlAssessment> {
    let value: serde_json::Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    if let Some(assessment) = value.get("control_assessment") {
        Ok(serde_json::from_value(assessment.clone())?)
    } else if let Some(assessment) = value.get("assessment") {
        Ok(serde_json::from_value(assessment.clone())?)
    } else {
        Ok(serde_json::from_value(value)?)
    }
}

fn compare_policy_drift(before: &ControlAssessment, after: &ControlAssessment) -> String {
    let old = before
        .policies
        .iter()
        .map(|p| (p.name.clone(), p))
        .collect::<BTreeMap<_, _>>();
    let mut changes = Vec::new();
    for current in &after.policies {
        match old.get(&current.name) {
            Some(previous)
                if previous.state == current.state
                    && previous.mode == current.mode
                    && previous.rules == current.rules
                    && previous.evidence == current.evidence => {}
            Some(previous) => changes.push(format!(
                "{}: {}/{} -> {}/{} (evidence changed={})",
                current.name,
                previous.state,
                previous.mode,
                current.state,
                current.mode,
                previous.evidence != current.evidence || previous.rules != current.rules
            )),
            None => changes.push(format!("{}: added", current.name)),
        }
    }
    if before.platform != after.platform {
        changes.push(format!(
            "platform: {} -> {}",
            before.platform, after.platform
        ));
    }
    for current in &after.sensors {
        let previous = before
            .sensors
            .iter()
            .find(|sensor| sensor.product == current.product);
        if let Some(previous) = previous {
            if previous.health != current.health
                || previous.protection_mode != current.protection_mode
                || previous.policy_version != current.policy_version
                || previous.management_scope != current.management_scope
                || previous.prevention_rules != current.prevention_rules
                || previous.evidence != current.evidence
            {
                changes.push(format!(
                    "sensor {} changed health/mode/version/scope",
                    current.product
                ));
            }
        } else {
            changes.push(format!("sensor {}: added", current.product));
        }
    }
    for current in &after.audit_sources {
        let previous = before
            .audit_sources
            .iter()
            .find(|source| source.source == current.source);
        if let Some(previous) = previous {
            if previous.available != current.available || previous.evidence != current.evidence {
                changes.push(format!(
                    "audit source {} availability/evidence changed",
                    current.source
                ));
            }
        } else {
            changes.push(format!("audit source {}: added", current.source));
        }
    }
    if before.detection_exposure != after.detection_exposure {
        changes.push(format!(
            "detection_exposure: {} -> {}",
            before.detection_exposure, after.detection_exposure
        ));
    }
    if changes.is_empty() {
        "no policy state/mode drift observed".into()
    } else {
        format!("drift_detected: {}", changes.join("; "))
    }
}

fn copy_or_placeholder(source: &Path, target: &Path) -> Result<()> {
    if source.is_file() {
        fs::copy(source, target)
            .with_context(|| format!("copy {} to {}", source.display(), target.display()))?;
    } else {
        write_fixture(target, b"disposable control-test placeholder\n")?;
    }
    Ok(())
}

fn write_fixture(path: &Path, body: &[u8]) -> Result<()> {
    fs::write(path, body)?;
    set_mode(path, 0o700)
}

fn make_executable(path: &Path) -> Result<()> {
    set_mode(path, 0o700)
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(mode);
        fs::set_permissions(path, permissions)?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

#[cfg(windows)]
fn configure_windows_acl_fixtures(user_path: &Path, admin_path: &Path) {
    let user_text = user_path.display().to_string();
    let _ = Command::new("icacls")
        .args([user_text.as_str(), "/inheritance:e"])
        .output();
    let admin_text = admin_path.display().to_string();
    let _ = Command::new("icacls")
        .args([
            admin_text.as_str(),
            "/inheritance:r",
            "/grant:r",
            "SYSTEM:(OI)(CI)F",
            "/grant:r",
            "BUILTIN\\Administrators:(OI)(CI)F",
            "/grant:r",
            "BUILTIN\\Users:(OI)(CI)RX",
        ])
        .output();
}

#[cfg(not(windows))]
fn configure_windows_acl_fixtures(_user_path: &Path, _admin_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::{run, Options};

    #[test]
    fn suite_creates_and_cleans_only_generated_fixtures() {
        let report = run(&Options {
            platform: "linux".into(),
            case_filter: Some("hash-drift".into()),
            ..Default::default()
        })
        .unwrap();
        assert!(report.fixtures_cleaned);
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].status, "observed_drift");
    }

    #[test]
    fn every_linux_case_is_safe_without_execution() {
        let cases = crate::core::controls::validation_cases_for("linux");
        for case in cases {
            let report = run(&Options {
                platform: "linux".into(),
                case_filter: Some(case.id.to_string()),
                ..Default::default()
            })
            .unwrap();
            assert_eq!(report.results.len(), 1, "case {}", case.id);
            assert!(!report.results[0].executed, "case {}", case.id);
            assert!(report.fixtures_cleaned, "case {}", case.id);
        }
    }

    #[test]
    fn explicit_execution_remains_fixture_scoped() {
        let report = run(&Options {
            platform: "linux".into(),
            case_filter: Some("interpreter-script".into()),
            execute: true,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(report.results.len(), 1);
        assert!(report.results[0].executed);
        assert!(report.results[0]
            .observations
            .iter()
            .any(|entry| entry.contains("interpreter=")));
    }

    #[test]
    fn explicit_execution_covers_each_safe_linux_case() {
        for case in crate::core::controls::validation_cases_for("linux") {
            let report = run(&Options {
                platform: "linux".into(),
                case_filter: Some(case.id.to_string()),
                execute: true,
                ..Default::default()
            })
            .unwrap();
            assert_eq!(report.results.len(), 1, "case {}", case.id);
            assert!(report.fixtures_cleaned, "case {}", case.id);
        }
    }

    #[test]
    fn baseline_drift_and_fixture_retention_are_reported() {
        let root = tempfile::tempdir().unwrap();
        let baseline = root.path().join("baseline.json");
        let baseline_report = crate::core::controls::collect("linux", None);
        std::fs::write(&baseline, serde_json::to_vec(&baseline_report).unwrap()).unwrap();
        let fixture_root = root.path().join("fixtures");
        let report = run(&Options {
            platform: "linux".into(),
            case_filter: Some("policy-drift".into()),
            root: Some(fixture_root.clone()),
            baseline: Some(baseline),
            keep_fixtures: true,
            ..Default::default()
        })
        .unwrap();
        assert!(!report.fixtures_cleaned);
        assert!(fixture_root.is_dir());
        assert!(report
            .notes
            .iter()
            .any(|note| note.contains("Policy drift")));
        std::fs::remove_dir_all(fixture_root).unwrap();
    }
}
