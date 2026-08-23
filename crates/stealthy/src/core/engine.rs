use anyhow::{bail, Result};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::cli::{Cli, CliOverrides, OutputMode, ReportFormat};
use crate::core::artifacts::{self, ArtifactLedger};
use crate::core::attack_path::{assign_path_ranks, build_attack_paths};
use crate::core::controls;
use crate::core::evasion::{self, low_and_slow};
use crate::core::finalize::finalize_finding;
use crate::core::identity;
use crate::core::os;
use crate::core::output::{self, OutputOptions};
use crate::core::plugin::{filter_plugins, PluginContext};
use crate::core::profile::EngagementProfile;
use crate::core::store::EncryptedStore;
use crate::core::term;
use crate::core::triage;
use crate::core::types::{
    ControlAssessment, Finding, FindingAssessment, FindingKind, PluginCoverage, RunReport,
    Severity, TriageDecision,
};
use crate::exploit::TechniqueAllowlist;
use crate::plugins;

pub struct Engine {
    quiet: bool,
    verbose: bool,
    delay_ms: u64,
    plugin_timeout_ms: u64,
    profile: EngagementProfile,
    prefer_quiet: bool,
    auto_exploit: bool,
    allow_techniques: TechniqueAllowlist,
    only: Option<Vec<String>>,
    skip: Option<Vec<String>>,
    output: OutputOptions,
    fail_on: Option<Severity>,
    checkpoint: Option<PathBuf>,
    resume_from: Option<PathBuf>,
    ledger_dir: PathBuf,
    triage: bool,
    triage_out: Option<PathBuf>,
    approve_file: Option<PathBuf>,
    artifact: Option<PathBuf>,
}

pub struct EngineOutcome {
    pub fail_on_triggered: bool,
    #[allow(dead_code)]
    pub run_id: String,
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub fn from_cli(
        cli: &Cli,
        overrides: &CliOverrides,
        auto_exploit: bool,
        allow_techniques: TechniqueAllowlist,
        only: Option<Vec<String>>,
        skip: Option<Vec<String>>,
        checkpoint: Option<PathBuf>,
        resume_from: Option<PathBuf>,
        triage: bool,
        triage_out: Option<PathBuf>,
        approve_file: Option<PathBuf>,
    ) -> Result<Self> {
        let profile = cli.profile;
        let mut quiet = cli.quiet || profile.force_quiet_console();
        let mut verbose = cli.verbose || profile.force_verbose();
        if quiet {
            verbose = false;
        }
        let delay_ms = if overrides.delay_ms_set {
            cli.delay_ms
        } else {
            profile.default_delay_ms()
        };
        let plugin_timeout_ms = if overrides.plugin_timeout_ms_set {
            cli.plugin_timeout_ms
        } else {
            profile.default_plugin_timeout_ms()
        };
        let mut format = cli.format;
        if profile.force_json() && !overrides.format_set {
            format = ReportFormat::Json;
            quiet = true;
        }

        Ok(Self {
            quiet,
            verbose,
            delay_ms,
            plugin_timeout_ms,
            profile,
            prefer_quiet: profile.prefer_quiet(),
            auto_exploit,
            allow_techniques,
            only,
            skip,
            fail_on: cli.fail_on.map(|m| m.to_severity()),
            checkpoint,
            resume_from,
            ledger_dir: cli
                .ledger_dir
                .clone()
                .unwrap_or_else(artifacts::default_ledger_dir),
            triage,
            triage_out,
            approve_file,
            artifact: cli.artifact.clone(),
            output: OutputOptions {
                mode: cli.output,
                path: cli.output_path.clone(),
                plaintext_file: cli.plaintext_file,
                also_markdown: cli.also_markdown,
                exfil_url: cli.exfil_url.clone(),
                quiet,
                format,
                min_severity: cli.min_severity.to_severity(),
                verbose,
                run_id: String::new(),
                ledger_dir: cli
                    .ledger_dir
                    .clone()
                    .unwrap_or_else(artifacts::default_ledger_dir),
            },
        })
    }

    pub fn run(&mut self) -> Result<EngineOutcome> {
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_flag = cancel.clone();
        let _ = ctrlc::set_handler(move || {
            cancel_flag.store(true, Ordering::SeqCst);
        });

        let os_info = os::detect();
        let ident = identity::current();
        let started_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();

        let mut prior: Option<RunReport> = None;
        if let Some(path) = &self.resume_from {
            let text = std::fs::read_to_string(path)?;
            prior = Some(serde_json::from_str(&text)?);
        }

        let run_id = prior
            .as_ref()
            .map(|r| r.run_id.clone())
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| {
                let mut run_entropy = [0u8; 12];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut run_entropy);
                hex::encode(run_entropy)
            });
        self.output.run_id = run_id.clone();

        let mut store = EncryptedStore::new();
        let mut plugins_run = Vec::new();
        let mut coverage = Vec::new();
        let mut triage_decisions: Vec<TriageDecision> = Vec::new();
        let mut control_assessment = prior
            .as_ref()
            .and_then(|report| report.control_assessment.clone());

        if let Some(report) = &prior {
            for finding in &report.findings {
                store.push(finding.clone());
            }
            for note in &report.notes {
                store.note(note.clone());
            }
            coverage.extend(report.coverage.clone());
            plugins_run.extend(report.plugins_run.clone());
            triage_decisions.extend(report.triage_decisions.clone());
            store.note(format!("Resumed from checkpoint; run_id={run_id}"));
        }

        for note in evasion::evasion_notes() {
            store.note(note);
        }
        store.note(format!(
            "Profile {} — {}",
            self.profile.as_str(),
            self.profile.description()
        ));

        if ident.is_elevated {
            store.note(
                "Already elevated — enumeration still useful for lateral/persistence review.",
            );
        }

        // Triage pass-1 forces enumerate-only; probes happen after decisions.
        let mut effective_auto_exploit = self.auto_exploit && !self.triage;
        let mut approved_probe_ids: Vec<String> = Vec::new();

        if let Some(path) = &self.approve_file {
            let file = triage::load_approve_file(path)?;
            triage_decisions = file.decisions.clone();
            approved_probe_ids = triage::probe_ids(&file.decisions);
            if !approved_probe_ids.is_empty() {
                effective_auto_exploit = true;
                store.note(format!(
                    "Triage approve-file enabled reversible probes for {} finding_id(s)",
                    approved_probe_ids.len()
                ));
            } else {
                store.note("Triage approve-file loaded with no probe actions");
            }
        }

        if effective_auto_exploit {
            store.note(
                "AUTO-EXPLOIT enabled: low-noise reversible verifications run. High-impact families still require --allow-techniques.",
            );
        }

        if !self.allow_techniques.is_empty() {
            let note = if self
                .allow_techniques
                .allows(crate::exploit::TechniqueFamily::EndpointBypass)
            {
                format!(
                    "ALLOW-TECHNIQUES enabled: {} (endpoint-bypass wires What's next / next_command to live-controls --artifact and controls --execute; other families remain scaffold)",
                    self.allow_techniques.ids().join(", ")
                )
            } else {
                format!(
                    "ALLOW-TECHNIQUES enabled (scaffold): {}",
                    self.allow_techniques.ids().join(", ")
                )
            };
            store.note(note);
            for technique in crate::exploit::TechniqueFamily::ALL {
                if self.allow_techniques.allows(*technique) {
                    store.push(finalize_finding(
                        crate::exploit::technique_status_with_artifact(
                            "allow_techniques",
                            *technique,
                            true,
                            self.artifact.as_deref(),
                        ),
                    ));
                }
            }
        }

        let registry = plugins::registry();
        let available: Vec<&str> = registry
            .iter()
            .filter(|plugin| plugin.platforms().contains(&os_info.os.as_str()))
            .map(|plugin| plugin.id())
            .collect();
        let mut unknown = Vec::new();
        for requested in self.only.iter().chain(self.skip.iter()).flatten() {
            if !available.contains(&requested.as_str()) {
                unknown.push(requested.as_str());
            }
        }
        unknown.sort_unstable();
        unknown.dedup();
        if !unknown.is_empty() {
            bail!(
                "unknown plugin ID(s) for {}: {}. Use `--authorized list-plugins` to inspect this build",
                os_info.os,
                unknown.join(", ")
            );
        }
        let selected = filter_plugins(
            &registry,
            self.only.as_deref(),
            self.skip.as_deref(),
            &os_info.os,
        );

        let done_ok: std::collections::BTreeSet<String> = coverage
            .iter()
            .filter(|c| c.status == "ok")
            .map(|c| c.id.clone())
            .collect();

        let selected: Vec<_> = selected
            .into_iter()
            .filter(|p| !done_ok.contains(p.id()))
            .collect();

        let needs_app_control = selected
            .iter()
            .any(|plugin| matches!(plugin.id(), "linux.app_control" | "windows.app_control"));
        if needs_app_control {
            if control_assessment.is_none() {
                control_assessment = Some(controls::collect_with(controls::CollectOptions {
                    platform: &os_info.os,
                    artifact: self.artifact.as_deref(),
                    quiet: self.prefer_quiet,
                }));
                store.note(if self.prefer_quiet {
                    "control_assessment collected (quiet/slim; app_control selected)"
                } else {
                    "control_assessment collected (app_control selected)"
                });
            }
        } else if control_assessment.is_none() {
            store.note("control_assessment skipped (app_control not selected)");
        }

        if selected.is_empty() {
            store.note(format!(
                "No plugins selected for os={} — check --plugins / build target / resume coverage.",
                os_info.os
            ));
            if !self.quiet {
                eprintln!(
                    "{} No plugins matched. Try `stealthy --authorized list-plugins`",
                    term::warn("[!]")
                );
            }
        } else if !self.quiet {
            eprintln!(
                "{} {} · {}@{} · {} plugin(s) · profile={}",
                term::bold("[*]"),
                term::cyan(&os_info.os),
                ident.username,
                ident.hostname,
                selected.len(),
                self.profile.as_str()
            );
        }

        let total = selected.len();
        let mut cancelled = false;

        for (idx, plugin) in selected.iter().enumerate() {
            if cancel.load(Ordering::SeqCst) {
                cancelled = true;
                coverage.push(PluginCoverage {
                    id: plugin.id().to_string(),
                    status: "cancelled".into(),
                    findings: 0,
                    error: Some("interrupted".into()),
                    duration_ms: 0,
                });
                for rest in selected.iter().skip(idx + 1) {
                    coverage.push(PluginCoverage {
                        id: rest.id().to_string(),
                        status: "cancelled".into(),
                        findings: 0,
                        error: Some("interrupted".into()),
                        duration_ms: 0,
                    });
                }
                break;
            }

            let plugin_started = Instant::now();
            if !self.quiet {
                eprintln!(
                    "{} [{:>2}/{}] {}",
                    term::dim("[*]"),
                    idx + 1,
                    total,
                    plugin.id()
                );
            }
            low_and_slow(self.delay_ms);

            let outcome = self.run_one_plugin(
                plugin.id(),
                effective_auto_exploit,
                &approved_probe_ids,
                control_assessment.as_ref(),
                cancel.clone(),
            );

            match outcome {
                PluginOutcome::Ok(findings) => {
                    let findings = findings
                        .into_iter()
                        .map(with_operator_next_step)
                        .map(finalize_finding)
                        .collect::<Vec<_>>();
                    let n = findings.len();
                    let max = findings
                        .iter()
                        .map(|f| f.severity)
                        .max()
                        .unwrap_or(Severity::Info);
                    for f in findings {
                        if self.verbose && !self.quiet {
                            eprintln!(
                                "    {} {} {} ({})",
                                term::severity_tag(f.severity),
                                term::dim("+"),
                                f.title,
                                term::dim(&f.finding_id)
                            );
                        }
                        store.push(f);
                    }
                    if !self.quiet && n > 0 {
                        eprintln!(
                            "    {} {} finding(s) · max {}",
                            term::dim("↳"),
                            n,
                            term::severity_tag(max)
                        );
                    }
                    plugins_run.push(plugin.id().to_string());
                    coverage.push(PluginCoverage {
                        id: plugin.id().to_string(),
                        status: "ok".into(),
                        findings: n,
                        error: None,
                        duration_ms: plugin_started.elapsed().as_millis(),
                    });
                }
                PluginOutcome::Err(error) => {
                    store.note(format!("plugin {} error: {error}", plugin.id()));
                    coverage.push(PluginCoverage {
                        id: plugin.id().to_string(),
                        status: "error".into(),
                        findings: 0,
                        error: Some(error.clone()),
                        duration_ms: plugin_started.elapsed().as_millis(),
                    });
                    if !self.quiet {
                        eprintln!("    {} plugin failed: {error}", term::err("[!]"));
                    }
                }
                PluginOutcome::Timeout => {
                    store.note(format!(
                        "plugin {} timed out after {}ms",
                        plugin.id(),
                        self.plugin_timeout_ms
                    ));
                    coverage.push(PluginCoverage {
                        id: plugin.id().to_string(),
                        status: "timeout".into(),
                        findings: 0,
                        error: Some(format!("timeout after {}ms", self.plugin_timeout_ms)),
                        duration_ms: plugin_started.elapsed().as_millis(),
                    });
                    if !self.quiet {
                        eprintln!(
                            "    {} plugin timed out after {}ms",
                            term::warn("[!]"),
                            self.plugin_timeout_ms
                        );
                    }
                }
            }

            if let Some(path) = &self.checkpoint {
                let (findings, notes) = store_into_parts(&store);
                let partial = build_report(
                    &run_id,
                    started_at_unix,
                    self.profile.as_str(),
                    mode_label(
                        effective_auto_exploit,
                        self.allow_techniques.is_empty(),
                        self.triage,
                    ),
                    os_info.clone(),
                    ident.clone(),
                    findings,
                    plugins_run.clone(),
                    coverage.clone(),
                    notes,
                    triage_decisions.clone(),
                    control_assessment.clone(),
                );
                if let Ok(body) = serde_json::to_string_pretty(&partial) {
                    let _ = std::fs::write(path, body);
                    let mut ledger = ArtifactLedger::new(&run_id);
                    ledger.register("checkpoint", path, true, "partial run checkpoint");
                    let _ = artifacts::save_ledger(&self.ledger_dir, &ledger);
                }
            }
        }

        if cancelled {
            store.note("Run cancelled by operator signal; partial results retained.");
        }

        // Post-enum triage: write stub and/or prompt.
        if self.triage {
            let (findings_now, _) = store_into_parts(&store);
            if let Some(path) = &self.triage_out {
                triage::write_triage_stub(path, &run_id, &findings_now)?;
                if !self.quiet {
                    eprintln!(
                        "{} wrote triage stub {}",
                        term::ok("[triage]"),
                        path.display()
                    );
                }
            }
            if self.approve_file.is_none() {
                let prompted = triage::prompt_tty(&run_id, &findings_now)?;
                if !prompted.decisions.is_empty() {
                    triage_decisions = prompted.decisions;
                    approved_probe_ids = triage::probe_ids(&triage_decisions);
                    if !approved_probe_ids.is_empty() {
                        store.note(format!(
                            "TTY triage approved {} probe(s); re-run with --approve-file or --auto-exploit to execute probes",
                            approved_probe_ids.len()
                        ));
                    }
                }
            }
        }

        let mode = mode_label(
            effective_auto_exploit,
            self.allow_techniques.is_empty(),
            self.triage,
        );
        let (mut findings, notes) = store_into_parts(&store);
        let attack_paths = build_attack_paths(&findings);
        assign_path_ranks(&mut findings, &attack_paths);
        let assessments = findings
            .iter()
            .enumerate()
            .map(|(finding_index, finding)| assess_finding(finding_index, finding))
            .collect();

        let report = RunReport {
            schema_version: "2".into(),
            run_id: run_id.clone(),
            started_at_unix,
            tool: "stealthy".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            authorized_use_ack: true,
            mode: mode.into(),
            execution_path: "binary".into(),
            primary_launch: "ok".into(),
            roe_ref: std::env::var("STEALTHY_MANIFEST_ROE_REF").unwrap_or_default(),
            profile: self.profile.as_str().into(),
            coverage_mode: "binary".into(),
            capability_delta: vec![],
            control_assessment,
            os: os_info,
            identity: ident,
            findings,
            assessments,
            attack_paths,
            triage_decisions,
            plugins_run,
            coverage,
            notes,
        };

        // Persist final checkpoint if requested.
        if let Some(path) = &self.checkpoint {
            if let Ok(body) = serde_json::to_string_pretty(&report) {
                let _ = std::fs::write(path, body);
            }
        }

        let emitted = output::emit(&report, &store, &self.output)?;

        // Update ledger for file outputs.
        let mut ledger = ArtifactLedger::new(&run_id);
        if self.output.mode == OutputMode::File {
            if let Some(path) = &self.output.path {
                let kind = if self.output.plaintext_file {
                    "json"
                } else {
                    "seal"
                };
                ledger.register(kind, path, true, "enum output");
                if self.output.also_markdown {
                    ledger.register(
                        "markdown",
                        PathBuf::from(format!("{}.md", path.display())),
                        true,
                        "markdown sidecar",
                    );
                }
            }
        }
        if let Some(path) = &self.checkpoint {
            ledger.register("checkpoint", path, true, "checkpoint");
        }
        let _ = artifacts::save_ledger(&self.ledger_dir, &ledger);

        if self.verbose && self.output.mode == OutputMode::Memory && !self.quiet {
            eprintln!(
                "{} seal key (hex): {}",
                term::dim("[memory]"),
                store.key_hex()
            );
        }

        let fail_on_triggered = self
            .fail_on
            .map(|min| emitted.max_severity.rank() >= min.rank())
            .unwrap_or(false);

        if fail_on_triggered && !self.quiet {
            eprintln!(
                "{} --fail-on triggered (max severity {})",
                term::err("[!]"),
                term::severity_tag(emitted.max_severity)
            );
        }

        let _ = store;
        Ok(EngineOutcome {
            fail_on_triggered,
            run_id,
        })
    }

    fn run_one_plugin(
        &self,
        plugin_id: &str,
        auto_exploit: bool,
        approved_probe_ids: &[String],
        control_assessment: Option<&ControlAssessment>,
        cancel: Arc<AtomicBool>,
    ) -> PluginOutcome {
        let timeout = self.plugin_timeout_ms;
        if timeout == 0 {
            return match run_plugin_blocking(
                plugin_id,
                self.verbose,
                auto_exploit,
                self.prefer_quiet,
                &self.allow_techniques,
                approved_probe_ids,
                self.artifact.clone(),
                control_assessment.cloned(),
                cancel,
            ) {
                Ok(f) => PluginOutcome::Ok(f),
                Err(e) => PluginOutcome::Err(format!("{e:#}")),
            };
        }

        let (tx, rx) = mpsc::channel();
        let verbose = self.verbose;
        let prefer_quiet = self.prefer_quiet;
        let allow = self.allow_techniques.clone();
        let approved = approved_probe_ids.to_vec();
        let artifact = self.artifact.clone();
        let control_assessment = control_assessment.cloned();
        let id = plugin_id.to_string();
        let worker_cancel = cancel.clone();
        std::thread::spawn(move || {
            let result = run_plugin_blocking(
                &id,
                verbose,
                auto_exploit,
                prefer_quiet,
                &allow,
                &approved,
                artifact,
                control_assessment,
                worker_cancel,
            );
            let _ = tx.send(result);
        });

        match rx.recv_timeout(Duration::from_millis(timeout)) {
            Ok(Ok(findings)) => PluginOutcome::Ok(findings),
            Ok(Err(e)) => PluginOutcome::Err(format!("{e:#}")),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                cancel.store(true, Ordering::SeqCst);
                PluginOutcome::Timeout
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                PluginOutcome::Err("plugin thread disconnected".into())
            }
        }
    }
}

enum PluginOutcome {
    Ok(Vec<Finding>),
    Err(String),
    Timeout,
}

#[allow(clippy::too_many_arguments)]
fn run_plugin_blocking(
    plugin_id: &str,
    verbose: bool,
    auto_exploit: bool,
    prefer_quiet: bool,
    allow_techniques: &TechniqueAllowlist,
    approved_probe_ids: &[String],
    artifact_path: Option<PathBuf>,
    control_assessment: Option<ControlAssessment>,
    cancel: Arc<AtomicBool>,
) -> Result<Vec<Finding>> {
    let registry = plugins::registry();
    let plugin = registry
        .iter()
        .find(|p| p.id() == plugin_id)
        .ok_or_else(|| anyhow::anyhow!("plugin not found: {plugin_id}"))?;
    let mut local_store = EncryptedStore::new();
    let mut ctx = PluginContext {
        verbose,
        auto_exploit,
        prefer_quiet,
        allow_techniques,
        store: &mut local_store,
        approved_probe_ids,
        artifact_path,
        control_assessment,
        cancel,
    };
    plugin.run(&mut ctx)
}

fn mode_label(auto_exploit: bool, allow_empty: bool, triage: bool) -> &'static str {
    match (auto_exploit, allow_empty, triage) {
        (_, _, true) => "enumerate+triage",
        (true, false, _) => "enumerate+auto-exploit+allow-techniques",
        (true, true, _) => "enumerate+limited-auto-exploit",
        (false, false, _) => "enumerate+allow-techniques",
        (false, true, _) => "enumerate-only",
    }
}

#[allow(clippy::too_many_arguments)]
fn build_report(
    run_id: &str,
    started_at_unix: u64,
    profile: &str,
    mode: &str,
    os_info: crate::core::types::OsInfo,
    ident: crate::core::types::IdentityInfo,
    mut findings: Vec<Finding>,
    plugins_run: Vec<String>,
    coverage: Vec<PluginCoverage>,
    notes: Vec<String>,
    triage_decisions: Vec<TriageDecision>,
    control_assessment: Option<ControlAssessment>,
) -> RunReport {
    let attack_paths = build_attack_paths(&findings);
    assign_path_ranks(&mut findings, &attack_paths);
    let assessments = findings
        .iter()
        .enumerate()
        .map(|(i, f)| assess_finding(i, f))
        .collect();
    RunReport {
        schema_version: "2".into(),
        run_id: run_id.into(),
        started_at_unix,
        tool: "stealthy".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        authorized_use_ack: true,
        mode: mode.into(),
        execution_path: "binary".into(),
        primary_launch: "ok".into(),
        roe_ref: std::env::var("STEALTHY_MANIFEST_ROE_REF").unwrap_or_default(),
        profile: profile.into(),
        coverage_mode: "binary".into(),
        capability_delta: vec![],
        control_assessment,
        os: os_info,
        identity: ident,
        findings,
        assessments,
        attack_paths,
        triage_decisions,
        plugins_run,
        coverage,
        notes,
    }
}

fn assess_finding(finding_index: usize, finding: &Finding) -> FindingAssessment {
    let (confidence, evidence_quality) = match finding.kind {
        FindingKind::ExploitAttempt => ("high", "direct_probe"),
        FindingKind::Misconfiguration | FindingKind::Credential => ("medium", "local_observation"),
        FindingKind::Enumeration => ("medium", "local_observation"),
        FindingKind::Recommendation => ("low", "heuristic"),
    };
    let applicability = if matches!(finding.kind, FindingKind::Recommendation) {
        "requires_validation"
    } else if finding.leaves_artifacts {
        "potentially_actionable"
    } else {
        "current_context"
    };
    FindingAssessment {
        finding_index,
        confidence: confidence.into(),
        applicability: applicability.into(),
        evidence_quality: evidence_quality.into(),
    }
}

fn with_operator_next_step(mut finding: Finding) -> Finding {
    if finding.needs_next_step() {
        finding.recommendation =
            "Validate this observation against the target and ROE before taking action; preserve evidence and document the stop condition.".into();
    }
    finding
}

fn store_into_parts(store: &EncryptedStore) -> (Vec<Finding>, Vec<String>) {
    (store.findings(), store.notes().to_vec())
}
