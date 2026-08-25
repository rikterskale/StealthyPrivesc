use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::cli::{Cli, CliOverrides, OutputMode, ReportFormat, ScanPreset};
use crate::core::artifacts::{self, ArtifactLedger};
use crate::core::attack_path::{assign_path_ranks, build_attack_paths};
use crate::core::controls;
use crate::core::evasion::{self, low_and_slow};
use crate::core::finalize::finalize_finding;
use crate::core::identity;
use crate::core::os;
use crate::core::output::{self, OutputOptions};
use crate::core::plugin::filter_plugins;
use crate::core::plugin_worker::{self, PluginOutcome, PluginWorkerRequest};
use crate::core::profile::{EngagementProfile, NoiseBudget};
use crate::core::reporting::{
    assess_finding, build_report, store_into_parts, with_operator_next_step,
};
use crate::core::store::EncryptedStore;
use crate::core::term;
use crate::core::triage;
use crate::core::types::{ControlAssessment, PluginCoverage, RunReport, Severity, TriageDecision};
use crate::exploit::TechniqueAllowlist;
use crate::plugins;

pub struct Engine {
    quiet: bool,
    verbose: bool,
    delay_ms: u64,
    plugin_timeout_ms: u64,
    max_scan_seconds: u64,
    max_findings: usize,
    max_report_bytes: usize,
    profile: EngagementProfile,
    prefer_quiet: bool,
    noise_budget: NoiseBudget,
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
    pub report: RunReport,
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
        let profile = match cli.preset {
            Some(ScanPreset::Quick) => crate::core::profile::EngagementProfile::Quiet,
            Some(ScanPreset::Standard) => crate::core::profile::EngagementProfile::Balanced,
            Some(ScanPreset::Deep) => crate::core::profile::EngagementProfile::Thorough,
            None => cli.profile,
        };
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
        match cli.output {
            OutputMode::Memory => {
                if cli.plaintext_file {
                    bail!("--plaintext-file requires --output=file");
                }
                if cli.also_markdown {
                    bail!("--also-markdown requires --output=file");
                }
            }
            OutputMode::File if cli.output_path.is_none() => {
                bail!("--output=file requires --output-path");
            }
            OutputMode::Remote if cli.exfil_url.is_none() => {
                bail!("--output=remote requires --exfil-url");
            }
            OutputMode::File | OutputMode::Remote => {}
        }
        let encrypted_output = (cli.output == OutputMode::File && !cli.plaintext_file)
            || cli.output == OutputMode::Remote;
        if encrypted_output && cli.key_output_path.is_none() {
            bail!(
                "encrypted output requires --key-output-path (or STEALTHY_KEY_OUTPUT_PATH); keys are never printed to stderr"
            );
        }
        if cli.output_path.is_some() && cli.output_path == cli.key_output_path {
            bail!("--key-output-path must differ from --output-path");
        }

        Ok(Self {
            quiet,
            verbose,
            delay_ms,
            plugin_timeout_ms,
            max_scan_seconds: cli.max_scan_seconds,
            max_findings: cli.max_findings,
            max_report_bytes: cli.max_report_bytes,
            profile,
            prefer_quiet: profile.prefer_quiet(),
            noise_budget: profile.noise_budget(),
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
                key_output_path: cli.key_output_path.clone(),
                plaintext_file: cli.plaintext_file,
                also_markdown: cli.also_markdown,
                exfil_url: cli.exfil_url.clone(),
                quiet,
                summary: cli.summary,
                progress_json: cli.progress_json,
                format,
                min_severity: cli.min_severity.to_severity(),
                run_id: String::new(),
                ledger_dir: cli
                    .ledger_dir
                    .clone()
                    .unwrap_or_else(artifacts::default_ledger_dir),
            },
        })
    }

    pub fn run(&mut self) -> Result<EngineOutcome> {
        let run_started = Instant::now();
        let scan_deadline = (self.max_scan_seconds != 0)
            .then(|| run_started + std::time::Duration::from_secs(self.max_scan_seconds));
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

        let approved_file = self
            .approve_file
            .as_ref()
            .map(|path| triage::load_approve_file(path))
            .transpose()?;
        if approved_file.is_some() && prior.is_none() {
            bail!("--approve-file requires a checkpoint from the same triage run");
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

        if let Some(file) = &approved_file {
            if file.run_id != run_id {
                anyhow::bail!(
                    "approval file run_id {} does not match current run_id {}",
                    file.run_id,
                    run_id
                );
            }
            triage_decisions = file.decisions.clone();
            let prior_findings = prior
                .as_ref()
                .map(|report| report.findings.as_slice())
                .unwrap_or(&[]);
            approved_probe_ids = triage::validate_probe_ids(&file.decisions, prior_findings)?;
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
            let suggestions = unknown
                .iter()
                .filter_map(|wanted| {
                    available
                        .iter()
                        .copied()
                        .find(|candidate| {
                            candidate.contains(wanted)
                                || wanted.contains(candidate)
                                || candidate
                                    .split('.')
                                    .next_back()
                                    .is_some_and(|name| wanted.contains(name))
                        })
                        .map(|candidate| format!("{wanted} -> {candidate}"))
                })
                .collect::<Vec<_>>();
            let hint = if suggestions.is_empty() {
                "Use `stealthy --authorized list-plugins` to inspect this build.".into()
            } else {
                format!("Suggestions: {}", suggestions.join(", "))
            };
            bail!(
                "unknown plugin ID(s) for {}: {}. {}",
                os_info.os,
                unknown.join(", "),
                hint
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

        let approved_plugins: std::collections::BTreeSet<String> = prior
            .as_ref()
            .map(|report| {
                report
                    .findings
                    .iter()
                    .filter(|finding| approved_probe_ids.contains(&finding.finding_id))
                    .map(|finding| finding.plugin.clone())
                    .collect()
            })
            .unwrap_or_default();
        let selected: Vec<_> = selected
            .into_iter()
            .filter(|p| {
                !done_ok.contains(p.id())
                    || (self.approve_file.is_some() && approved_plugins.contains(p.id()))
            })
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
            if scan_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                cancelled = true;
                store.note(format!(
                    "Run stopped at max_scan_seconds={} before plugin {}",
                    self.max_scan_seconds,
                    plugin.id()
                ));
                for rest in selected.iter().skip(idx) {
                    coverage.push(PluginCoverage {
                        id: rest.id().to_string(),
                        status: "cancelled".into(),
                        findings: 0,
                        error: Some("scan duration limit".into()),
                        duration_ms: 0,
                    });
                }
                break;
            }
            if cancel.load(Ordering::SeqCst) {
                cancelled = true;
                if self.output.progress_json {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "event": "scan_cancelled",
                            "plugin": plugin.id(),
                            "index": idx + 1,
                            "total": total,
                            "resume": self.checkpoint.as_ref().map(|path| path.display().to_string())
                        })
                    );
                }
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
            if self.output.progress_json {
                eprintln!(
                    "{}",
                    serde_json::json!({"event":"plugin_started", "plugin":plugin.id(), "index":idx + 1, "total":total})
                );
            }
            if !self.quiet {
                let elapsed = run_started.elapsed().as_secs();
                let completed = idx;
                let eta = if completed > 0 {
                    let average = run_started.elapsed().as_secs_f64() / completed as f64;
                    format!(
                        " · eta≈{}s",
                        (average * (total - completed) as f64).round() as u64
                    )
                } else {
                    String::new()
                };
                eprintln!(
                    "{} [{:>2}/{}] {} · elapsed={}s{}",
                    term::dim("[*]"),
                    idx + 1,
                    total,
                    plugin.id(),
                    elapsed,
                    eta
                );
            }
            low_and_slow(self.delay_ms);

            let plugin_timeout_ms = scan_deadline
                .map(|deadline| {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    let remaining_ms = remaining.as_millis().min(u64::MAX as u128) as u64;
                    if self.plugin_timeout_ms == 0 {
                        remaining_ms.max(1)
                    } else {
                        self.plugin_timeout_ms.min(remaining_ms.max(1))
                    }
                })
                .unwrap_or(self.plugin_timeout_ms);

            let outcome = self.run_one_plugin(
                plugin.id(),
                effective_auto_exploit,
                &approved_probe_ids,
                control_assessment.as_ref(),
                cancel.clone(),
                plugin_timeout_ms,
            );

            match outcome {
                PluginOutcome::Completed(result) => {
                    for note in result.notes {
                        store.note(format!("{}: {note}", plugin.id()));
                    }
                    if let Some(error) = result.error {
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
                    } else {
                        let mut findings = result
                            .findings
                            .into_iter()
                            .map(with_operator_next_step)
                            .map(finalize_finding)
                            .collect::<Vec<_>>();
                        let remaining = self.max_findings.saturating_sub(store.findings().len());
                        if findings.len() > remaining {
                            findings.truncate(remaining);
                            store.note(format!(
                                "Finding limit reached at max_findings={}; plugin {} results were truncated",
                                self.max_findings,
                                plugin.id()
                            ));
                        }
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
                }
                PluginOutcome::Error(error) => {
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
            if self.output.progress_json {
                eprintln!(
                    "{}",
                    serde_json::json!({"event":"plugin_finished", "plugin":plugin.id(), "index":idx + 1, "total":total, "elapsed_ms":plugin_started.elapsed().as_millis()})
                );
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
                    if let Err(error) = artifacts::write_private_atomic(path, body.as_bytes()) {
                        store.note(format!("Checkpoint persistence failed: {error}"));
                    }
                    let mut ledger = ArtifactLedger::new(&run_id);
                    ledger.register("checkpoint", path, true, "partial run checkpoint");
                    if let Err(error) = artifacts::save_ledger(&self.ledger_dir, &ledger) {
                        store.note(format!("Artifact ledger persistence failed: {error}"));
                    }
                } else {
                    store.note(
                        "Checkpoint serialization failed; partial checkpoint was not written",
                    );
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
            min_severity: self.output.min_severity.as_str().into(),
            selected_plugins: plugins_run.clone(),
            skipped_plugins: self.skip.clone().unwrap_or_default(),
            coverage_mode: "native".into(),
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

        let report_size = serde_json::to_vec(&report)?.len();
        if self.max_report_bytes != 0 && report_size > self.max_report_bytes {
            anyhow::bail!(
                "report size {} bytes exceeds --max-report-bytes limit of {}",
                report_size,
                self.max_report_bytes
            );
        }

        // Persist final checkpoint if requested.
        if let Some(path) = &self.checkpoint {
            if let Ok(body) = serde_json::to_string_pretty(&report) {
                artifacts::write_private_atomic(path, body.as_bytes())
                    .with_context(|| format!("write checkpoint {}", path.display()))?;
            } else {
                anyhow::bail!("serialize final checkpoint");
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
        if self.output.mode != OutputMode::Memory {
            if let Some(key_path) = &self.output.key_output_path {
                ledger.register("report-key", key_path, true, "sealed report key");
            }
        }
        if let Some(path) = &self.checkpoint {
            ledger.register("checkpoint", path, true, "checkpoint");
        }
        if !ledger.entries.is_empty() {
            artifacts::save_ledger(&self.ledger_dir, &ledger).context("persist artifact ledger")?;
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
            report,
        })
    }

    fn run_one_plugin(
        &self,
        plugin_id: &str,
        auto_exploit: bool,
        approved_probe_ids: &[String],
        control_assessment: Option<&ControlAssessment>,
        cancel: Arc<AtomicBool>,
        plugin_timeout_ms: u64,
    ) -> PluginOutcome {
        let request = PluginWorkerRequest {
            plugin: plugin_id.into(),
            verbose: self.verbose,
            auto_exploit,
            prefer_quiet: self.prefer_quiet,
            noise_budget: self.noise_budget,
            allow_techniques: self
                .allow_techniques
                .ids()
                .into_iter()
                .map(str::to_string)
                .collect(),
            approved_probe_ids: approved_probe_ids.to_vec(),
            artifact_path: self.artifact.clone(),
            control_assessment: control_assessment.cloned(),
        };
        plugin_worker::run_with_timeout(request, plugin_timeout_ms, cancel)
    }
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
