//! StealthyPrivesc — modular privilege-escalation enumerator for authorized assessments.
//!
//! LEGAL: Use only on systems you are explicitly authorized to assess in writing.
//! Unauthorized use is illegal. Default mode is quiet enumeration + recommendations only.

mod cli;
mod core;
mod exploit;
mod plugins;

use anyhow::{Context, Result};
use clap::Parser;

use crate::cli::{Cli, CliOverrides, Commands, ReportFormat};
use crate::core::artifacts;
use crate::core::control_tests;
use crate::core::delivery;
use crate::core::engine::Engine;
use crate::core::ingest;
use crate::core::output;
use crate::core::store::EncryptedStore;
use crate::core::term;
use crate::core::ux;

fn main() {
    if let Err(error) = run_main() {
        eprintln!("error: {error:#}");
        print_recovery_hint(&error.to_string());
        std::process::exit(1);
    }
}

fn run_main() -> Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    let overrides = CliOverrides {
        delay_ms_set: arg_was_set(&argv, "--delay-ms"),
        plugin_timeout_ms_set: arg_was_set(&argv, "--plugin-timeout-ms"),
        format_set: arg_was_set(&argv, "--format"),
    };
    let mut cli = Cli::parse();
    term::init(cli.no_color);

    // Local UX / operator-workstation commands never need the auth gate.
    let needs_auth = !matches!(
        &cli.command,
        Some(Commands::Disclaimer)
            | Some(Commands::Guide)
            | Some(Commands::Doctor { .. })
            | Some(Commands::Quickstart)
            | Some(Commands::Demo { .. })
            | Some(Commands::SecurityLab { .. })
            | Some(Commands::ExplainPlugin { .. })
            | Some(Commands::PluginPicker)
            | Some(Commands::Completions { .. })
            | Some(Commands::ExplainFinding { .. })
            | Some(Commands::HtmlReport { .. })
            | Some(Commands::CoverageCompare { .. })
            | Some(Commands::Presets)
            | Some(Commands::Playbook { .. })
            | Some(Commands::Disposition { .. })
            | Some(Commands::Report { .. })
            | Some(Commands::Diff { .. })
            | Some(Commands::Ingest { .. })
            | Some(Commands::Artifacts { .. })
            | Some(Commands::Cleanup { .. })
            | Some(Commands::Stage { .. })
            | Some(Commands::Verify { .. })
            | Some(Commands::OneLiners { .. })
    );

    if needs_auth && !cli.i_understand_authorized_use_only {
        print_auth_required();
        std::process::exit(2);
    }

    let command = cli.command.take().unwrap_or(Commands::Enum {
        auto_exploit: false,
        allow_techniques: None,
        confirm_evasion: false,
        plugins: None,
        skip: None,
        triage: false,
        triage_out: None,
        approve_file: None,
        save_baseline: None,
        compare_with: None,
    });

    match command {
        Commands::Disclaimer => {
            print_disclaimer();
            Ok(())
        }
        Commands::Guide => {
            print_guide();
            Ok(())
        }
        Commands::Doctor { json } => print_doctor(json),
        Commands::Quickstart => ux::quickstart(&cli, &overrides),
        Commands::Demo { html } => ux::demo(html),
        Commands::SecurityLab { root } => ux::security_lab(root),
        Commands::ExplainPlugin { id } => ux::explain_plugin(&id),
        Commands::PluginPicker => ux::plugin_picker(),
        Commands::Completions { shell } => ux::completions(shell),
        Commands::ExplainFinding { id, report } => ux::explain_finding(&id, report.as_deref()),
        Commands::HtmlReport { input } => ux::html_report(&input),
        Commands::CoverageCompare { native, fallback } => ux::coverage_compare(&native, &fallback),
        Commands::Disposition {
            report,
            finding_id,
            status,
            out,
            reason,
        } => ux::disposition(&report, &finding_id, status, &reason, out.as_deref()),
        Commands::Presets => ux::presets(),
        Commands::Playbook { id } => ux::playbook(&id),
        Commands::Controls {
            case,
            root,
            signed_artifact,
            baseline,
            execute,
            keep_fixtures,
        } => {
            #[cfg(feature = "enum-only")]
            if execute {
                anyhow::bail!("the enum-only build disables executable fixture probes");
            }
            print_control_validation(
                &cli,
                case,
                root,
                signed_artifact,
                baseline,
                execute,
                keep_fixtures,
            )
        }
        Commands::LiveControls => print_live_controls(&cli),
        Commands::Report {
            input,
            key_hex,
            key_file,
            format,
        } => print_report(&input, key_hex.as_deref(), key_file.as_deref(), format),
        Commands::Diff {
            baseline,
            current,
            format,
        } => print_diff(&baseline, &current, format),
        Commands::Ingest { input, format } => print_ingest(&input, format),
        Commands::ListPlugins { tsv } => {
            print_plugins(tsv);
            Ok(())
        }
        Commands::Artifacts {
            run_id,
            latest,
            json,
        } => {
            let id = if latest { None } else { run_id };
            print_artifacts(cli.ledger_dir.as_deref(), id, json)
        }
        Commands::Cleanup {
            run_id,
            latest,
            secure_delete,
            remove_self,
        } => run_cleanup(
            cli.ledger_dir.as_deref(),
            run_id,
            latest,
            secure_delete,
            remove_self,
        ),
        Commands::Stage {
            os,
            arch,
            name,
            out,
            binary,
            target_hostname,
            target_username,
        } => run_stage(
            &os,
            &arch,
            &name,
            &out,
            binary.as_deref(),
            &target_hostname,
            target_username.as_deref(),
            cli.ledger_dir.as_deref(),
        ),
        Commands::Verify {
            path,
            ssh,
            expect_sha256,
        } => run_verify(path.as_deref(), ssh.as_deref(), &expect_sha256),
        Commands::OneLiners { os, transport } => {
            print!("{}", delivery::one_liners(&os, &transport));
            Ok(())
        }
        Commands::PluginWorker { plugin } => run_plugin_worker(&plugin),
        Commands::Resume {
            checkpoint,
            auto_exploit,
            allow_techniques,
            confirm_evasion,
            plugins: only,
            skip,
        } => run_enum(
            &cli,
            &overrides,
            auto_exploit,
            allow_techniques,
            only,
            skip,
            cli.checkpoint.clone().or(Some(checkpoint.clone())),
            Some(checkpoint),
            false,
            None,
            None,
            confirm_evasion,
            None,
            None,
        ),
        Commands::Enum {
            auto_exploit,
            allow_techniques,
            confirm_evasion,
            plugins: only,
            skip,
            triage,
            triage_out,
            approve_file,
            save_baseline,
            compare_with,
        } => run_enum(
            &cli,
            &overrides,
            auto_exploit,
            allow_techniques,
            only,
            skip,
            cli.checkpoint.clone(),
            None,
            triage,
            triage_out,
            approve_file,
            confirm_evasion,
            save_baseline,
            compare_with,
        ),
    }
}

fn print_recovery_hint(message: &str) {
    let lower = message.to_ascii_lowercase();
    let hint = if lower.contains("no such file")
        && (lower.contains("python") || lower.contains("bash") || lower.contains("powershell"))
    {
        Some("Interpreter missing or blocked. Verify it with `command -v python3 bash sh perl` (Linux) or `Get-Command powershell` (Windows), then rerun the staged dispatcher.")
    } else if lower.contains("permission denied")
        && (lower.contains("ledger") || lower.contains("cache"))
    {
        Some("Ledger is not writable. Choose a writable location: `stealthy --ledger-dir ./stealthy-ledger --authorized scan`.")
    } else if lower.contains("key") && (lower.contains("path") || lower.contains("file")) {
        Some("Key path is unavailable. Create a protected destination and retry with `--key-output-path ./report.key`.")
    } else if lower.contains("126") || lower.contains("blocked") {
        Some("The primary binary was blocked. Use the staged fallback: `bash ./scripts/run.sh --authorized scan` (Linux) or `& .\\scripts\\run.ps1 --authorized scan` (PowerShell).")
    } else if lower.contains("timeout") || lower.contains("partial") || lower.contains("cancel") {
        Some("The scan was partial. Preserve the report, inspect coverage errors, then rerun the affected plugin with `--plugins ID`.")
    } else {
        None
    };
    if let Some(hint) = hint {
        eprintln!("Recovery: {hint}");
    }
}

fn run_plugin_worker(plugin: &str) -> Result<()> {
    use std::io::Read;

    let mut body = String::new();
    std::io::stdin().read_to_string(&mut body)?;
    let request: crate::core::plugin_worker::PluginWorkerRequest = serde_json::from_str(&body)?;
    if request.plugin != plugin {
        anyhow::bail!("plugin worker request mismatch");
    }
    let result = crate::core::plugin_worker::run_plugin_worker(request)?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_enum(
    cli: &Cli,
    overrides: &CliOverrides,
    auto_exploit: bool,
    allow_techniques: Option<Vec<String>>,
    only: Option<Vec<String>>,
    skip: Option<Vec<String>>,
    checkpoint: Option<std::path::PathBuf>,
    resume_from: Option<std::path::PathBuf>,
    triage: bool,
    triage_out: Option<std::path::PathBuf>,
    approve_file: Option<std::path::PathBuf>,
    confirm_evasion: bool,
    save_baseline: Option<std::path::PathBuf>,
    compare_with: Option<std::path::PathBuf>,
) -> Result<()> {
    let approval_resume = if approve_file.is_some() {
        Some(checkpoint.clone().ok_or_else(|| {
            anyhow::anyhow!("--approve-file requires --checkpoint from the triage run")
        })?)
    } else {
        resume_from
    };
    let allow =
        crate::exploit::TechniqueAllowlist::from_ids(allow_techniques.as_deref().unwrap_or(&[]))?;
    #[cfg(feature = "enum-only")]
    if auto_exploit || !allow.is_empty() {
        anyhow::bail!(
            "the enum-only build disables --auto-exploit and every --allow-techniques family"
        );
    }
    if allow.contains_evasion_family() && !(cli.confirm_evasion || confirm_evasion) {
        anyhow::bail!(
            "evasion technique families require --confirm-evasion in addition to --allow-techniques"
        );
    }
    let evasion_confirmed = cli.confirm_evasion || confirm_evasion;
    let mut engine = Engine::from_cli(
        cli,
        overrides,
        auto_exploit,
        allow,
        evasion_confirmed,
        only,
        skip,
        checkpoint,
        approval_resume,
        triage,
        triage_out,
        approve_file,
    )?;
    let outcome = engine.run()?;
    if let Some(path) = save_baseline {
        let body = serde_json::to_vec_pretty(&outcome.report)?;
        artifacts::write_private_atomic(&path, &body)
            .with_context(|| format!("write baseline {}", path.display()))?;
        println!("saved baseline {}", path.display());
    }
    if let Some(path) = compare_with {
        let baseline = crate::core::ingest::ingest_path(&path)?;
        let diff = crate::core::diff::compare(&baseline, &outcome.report)?;
        println!(
            "baseline comparison: {} added, {} removed, {} changed",
            diff.added.len(),
            diff.removed.len(),
            diff.changed.len()
        );
    }
    if outcome.fail_on_triggered {
        std::process::exit(4);
    }
    Ok(())
}

fn print_ingest(path: &std::path::Path, format: ReportFormat) -> Result<()> {
    let report = ingest::ingest_path(path)?;
    let findings = report.findings.iter().collect::<Vec<_>>();
    match format {
        ReportFormat::Json => println!("{}", output::render_json(&report, &findings)?),
        ReportFormat::Sarif => println!("{}", output::render_sarif(&report, &findings)),
        ReportFormat::Markdown | ReportFormat::Human => {
            print!(
                "{}",
                output::render_markdown(&report, &findings, findings.len())
            );
        }
    }
    Ok(())
}

fn print_control_validation(
    cli: &Cli,
    case: Option<String>,
    root: Option<std::path::PathBuf>,
    signed_artifact: Option<std::path::PathBuf>,
    baseline: Option<std::path::PathBuf>,
    execute: bool,
    keep_fixtures: bool,
) -> Result<()> {
    let report = control_tests::run(&control_tests::Options {
        platform: crate::core::os::detect().os,
        case_filter: case,
        root,
        artifact: cli.artifact.clone(),
        signed_artifact,
        baseline,
        execute,
        keep_fixtures,
    })?;
    match cli.format {
        ReportFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        ReportFormat::Markdown | ReportFormat::Human => print_control_validation_markdown(&report),
        ReportFormat::Sarif => anyhow::bail!(
            "SARIF is not supported for control validation reports; use --format json or markdown"
        ),
    }
    Ok(())
}

fn print_control_validation_markdown(report: &crate::core::types::ControlValidationReport) {
    println!(
        "# {} application-control validation\n",
        crate::core::opsec::BRAND
    );
    println!("- Platform: `{}`", report.platform);
    println!("- Cases: `{}`", report.case_filter);
    println!("- Execute requested: `{}`", report.execute_requested);
    println!(
        "- Detection exposure: `{}` ({}/100)",
        report.assessment.detection_exposure_label, report.assessment.detection_exposure
    );
    println!("\n## Results\n");
    println!("| Case | Status | Executed | Telemetry | Observations |");
    println!("| --- | --- | ---: | --- | --- |");
    for result in &report.results {
        println!(
            "| `{}` | `{}` | {} | `{}` ({}/100) | {} |",
            result.case_id,
            result.status,
            result.executed,
            result.telemetry_label,
            result.telemetry_score,
            result.observations.join("<br>").replace('|', "\\|")
        );
    }
    if !report.notes.is_empty() {
        println!("\n## Notes\n");
        for note in &report.notes {
            println!("- {note}");
        }
    }
}

fn print_live_controls(cli: &Cli) -> Result<()> {
    let platform = crate::core::os::detect().os;
    let assessment = crate::core::controls::collect(&platform, cli.artifact.as_deref());
    match cli.format {
        ReportFormat::Json => println!("{}", serde_json::to_string_pretty(&assessment)?),
        ReportFormat::Markdown | ReportFormat::Human => {
            println!("# {} live control collection\n", crate::core::opsec::BRAND);
            println!("- Platform: {}", assessment.platform);
            println!("- Collection mode: {}", assessment.collection_mode);
            println!(
                "- Live telemetry: {} ({}/100)",
                assessment.live_telemetry_label, assessment.live_telemetry_score
            );
            println!("\n## Policies\n");
            println!("| Policy | State | Mode | Rules |\n| --- | --- | --- | --- |");
            for policy in &assessment.policies {
                println!(
                    "| {} | {} | {} | {} |",
                    policy.name,
                    policy.state,
                    policy.mode,
                    policy.rules.join("<br>").replace('|', "\\|")
                );
            }
            println!("\n## Sensors\n");
            println!("| Product | Health | Protection | Tamper | Logs |\n| --- | --- | --- | --- | --- |");
            for sensor in &assessment.sensors {
                println!(
                    "| {} | {} | {} | {} | {} |",
                    sensor.product,
                    sensor.health,
                    sensor.protection_mode,
                    sensor.tamper_protection,
                    sensor.log_retrieval
                );
            }
            println!("\n## Audit sources\n");
            println!("| Source | Availability | Recent events | Denials | Artifact matches | Snapshot |\n| --- | --- | ---: | ---: | ---: | --- |");
            for source in &assessment.audit_sources {
                println!(
                    "| {} | {} | {} | {} | {} | {} |",
                    source.source,
                    source.available,
                    source.recent_events,
                    source.recent_denials,
                    source.correlated_artifact_events,
                    source.snapshot_sha256
                );
            }
            if let Some(artifact) = &assessment.artifact {
                println!("\n## Artifact\n");
                println!("- Path: {}", artifact.path);
                println!("- Decision prediction: {}", artifact.predicted_decision);
                println!("- Policy evidence: {}", artifact.policy_rule);
                println!("- Access control: {}", artifact.access_control);
                println!("- Static analysis: {}", artifact.static_analysis.join("; "));
            }
        }
        ReportFormat::Sarif => anyhow::bail!(
            "SARIF is not supported for live control collections; use --format json or markdown"
        ),
    }
    Ok(())
}

fn print_artifacts(
    ledger_dir: Option<&std::path::Path>,
    run_id: Option<String>,
    json: bool,
) -> Result<()> {
    let dir = ledger_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(artifacts::default_ledger_dir);
    let ledger = artifacts::list_artifacts(&dir, run_id.as_deref())?;
    if json {
        println!("{}", serde_json::to_string_pretty(&ledger)?);
    } else {
        println!("run_id={}", ledger.run_id);
        for entry in &ledger.entries {
            println!(
                "  [{}] {} removable={} {}",
                entry.kind, entry.path, entry.removable, entry.notes
            );
        }
    }
    Ok(())
}

fn run_cleanup(
    ledger_dir: Option<&std::path::Path>,
    run_id: Option<String>,
    latest: bool,
    secure_delete: bool,
    remove_self: bool,
) -> Result<()> {
    let dir = ledger_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(artifacts::default_ledger_dir);
    let id = if latest { None } else { run_id };
    let removed = artifacts::cleanup(&dir, id.as_deref(), secure_delete, remove_self)?;
    for path in removed {
        println!("removed {path}");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_stage(
    os: &str,
    arch: &str,
    name: &str,
    out: &std::path::Path,
    binary: Option<&std::path::Path>,
    target_hostname: &str,
    target_username: Option<&str>,
    ledger_dir: Option<&std::path::Path>,
) -> Result<()> {
    if target_hostname.trim().is_empty() {
        anyhow::bail!("--target-hostname is required for staged bundles");
    }
    let mut entropy = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut entropy);
    let run_id = format!("stage-{}", hex::encode(entropy));
    let ledger_dir = ledger_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(artifacts::default_ledger_dir);
    let staged = delivery::stage(delivery::StageOptions {
        os,
        arch,
        name,
        out_dir: out,
        binary,
        target_hostname,
        target_username,
        run_id: &run_id,
        ledger_dir: &ledger_dir,
    })?;
    println!("staged bundle at {}", staged.display());
    println!("run_id={run_id}");
    Ok(())
}

fn run_verify(
    path: Option<&std::path::Path>,
    ssh: Option<&str>,
    expect_sha256: &str,
) -> Result<()> {
    match (path, ssh) {
        (Some(path), None) => {
            delivery::verify_local(path, expect_sha256)?;
            println!("ok {}", path.display());
        }
        (Some(path), Some(ssh_target)) => {
            delivery::verify_ssh(ssh_target, &path.display().to_string(), expect_sha256)?;
            println!("ok {ssh_target}:{}", path.display());
        }
        (None, Some(_)) => anyhow::bail!("--ssh requires --path for the remote file path"),
        (None, None) => anyhow::bail!("provide --path (and optional --ssh)"),
    }
    Ok(())
}

fn print_doctor(json: bool) -> Result<()> {
    let os = crate::core::os::detect();
    let plugin_count = plugins::registry().len();
    let cwd = std::env::current_dir().ok();
    let cwd_ok = cwd.as_ref().is_some_and(|p| p.is_dir());
    let cwd_readonly = cwd
        .as_ref()
        .and_then(|path| std::fs::metadata(path).ok())
        .is_some_and(|metadata| metadata.permissions().readonly());
    let supported = matches!(os.os.as_str(), "linux" | "windows");
    let fallback_tools: Vec<&str> = if os.os == "linux" {
        vec!["python3", "bash", "sh", "perl"]
    } else if os.os == "windows" {
        vec!["powershell", "cscript"]
    } else {
        Vec::new()
    };
    let available_fallback_tools: Vec<&str> = fallback_tools
        .iter()
        .copied()
        .filter(|tool| command_available(tool))
        .collect();
    let fallback_count = available_fallback_tools.len();
    let blocking = !supported || plugin_count == 0 || !cwd_ok || cwd_readonly;
    let readiness = if blocking {
        "blocked"
    } else if fallback_count == 0 {
        "ready_with_warnings"
    } else {
        "ready"
    };
    let healthy = !blocking;
    let mut recommendations = Vec::new();
    if !supported {
        recommendations.push("run a supported Linux or Windows build on the target OS");
    }
    if plugin_count == 0 {
        recommendations
            .push("install a native build with compiled plugins or use an approved fallback");
    }
    if !cwd_ok {
        recommendations.push("rerun from a readable working directory or set --ledger-dir");
    }
    if cwd_readonly {
        recommendations
            .push("choose a writable working directory or set --ledger-dir to a writable path");
    }
    if fallback_count == 0 && supported {
        recommendations.push("install at least one approved fallback host for recovery coverage");
    }
    let checks = serde_json::json!({
        "supported_os": supported,
        "plugins_available": plugin_count > 0,
        "working_directory": cwd_ok,
        "working_directory_writable": cwd_ok && !cwd_readonly,
        "fallback_available": fallback_count > 0,
    });
    let check_details = serde_json::json!({
        "supported_os": {"status": if supported { "pass" } else { "block" }, "severity": if supported { "info" } else { "critical" }, "message": format!("{} {}", os.os, os.arch), "remediation": "Use a supported native build on Linux or Windows."},
        "plugins_available": {"status": if plugin_count > 0 { "pass" } else { "block" }, "severity": if plugin_count > 0 { "info" } else { "critical" }, "message": format!("{} compiled plugin(s)", plugin_count), "remediation": "Install or build a target-specific binary with plugins."},
        "working_directory": {"status": if cwd_ok { "pass" } else { "block" }, "severity": if cwd_ok { "info" } else { "high" }, "message": cwd.as_ref().map(|path| path.display().to_string()).unwrap_or_else(|| "unavailable".into()), "remediation": "Run from a readable directory or set --ledger-dir."},
        "working_directory_writable": {"status": if cwd_ok && !cwd_readonly { "pass" } else { "block" }, "severity": if cwd_ok && !cwd_readonly { "info" } else { "high" }, "message": if cwd_readonly { "directory is read-only" } else { "directory metadata is writable" }, "remediation": "Choose a writable working directory or ledger destination."},
        "fallback_available": {"status": if fallback_count > 0 { "pass" } else { "warn" }, "severity": if fallback_count > 0 { "info" } else { "medium" }, "message": format!("{fallback_count}/{} approved fallback host(s) available", fallback_tools.len()), "remediation": "Install an approved interpreter fallback for recovery coverage."},
    });
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": "1",
                "healthy": healthy,
                "readiness": readiness,
                "blocking": blocking,
                "os": os,
                "plugins": plugin_count,
                "fallback_hosts_available": fallback_count,
                "fallback_tools": {
                    "required": fallback_tools,
                    "available": available_fallback_tools,
                },
                "current_directory": cwd.map(|p| p.display().to_string()),
                "checks": checks,
                "check_details": check_details,
                "recommendations": recommendations,
            })
        );
    } else {
        println!(
            "{}",
            term::bold(&format!("{} doctor", crate::core::opsec::BRAND))
        );
        println!("  {} OS: {} ({})", check(supported), os.os, os.arch);
        println!(
            "  {} Plugins compiled: {}",
            check(plugin_count > 0),
            plugin_count
        );
        println!(
            "  {} Working directory: {}",
            check(cwd_ok),
            cwd.map(|p| p.display().to_string())
                .unwrap_or_else(|| "unavailable".into())
        );
        println!(
            "  {} Script fallback hosts available: {}/{}",
            check(fallback_count > 0),
            fallback_count,
            fallback_tools.len()
        );
        println!();
        println!(
            "{}",
            match readiness {
                "ready" => term::ok("READY — safe to continue to an authorized scan."),
                "ready_with_warnings" => term::warn(
                    "READY WITH WARNINGS — native scan is available; recovery coverage is limited."
                ),
                _ => term::err("BLOCKED — resolve the blocking checks before scanning."),
            }
        );
        if !recommendations.is_empty() {
            println!("\n{}", term::bold("Recommended next steps"));
            for (index, recommendation) in recommendations.iter().enumerate() {
                println!("  {}. {}", index + 1, recommendation);
            }
        }
    }
    if healthy {
        Ok(())
    } else {
        std::process::exit(3)
    }
}

fn command_available(command: &str) -> bool {
    let output = if cfg!(windows) {
        std::process::Command::new("where").arg(command).output()
    } else {
        std::process::Command::new("sh")
            .args(["-c", "command -v \"$1\"", "doctor", command])
            .output()
    };
    output
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn check(ok: bool) -> String {
    if ok {
        term::ok("[ok]")
    } else {
        term::err("[!!]")
    }
}

fn arg_was_set(argv: &[String], option: &str) -> bool {
    argv.iter()
        .any(|arg| arg == option || arg.starts_with(&format!("{option}=")))
}

fn print_report(
    path: &std::path::Path,
    key_hex: Option<&str>,
    key_file: Option<&std::path::Path>,
    format: ReportFormat,
) -> Result<()> {
    use zeroize::Zeroizing;

    let key = match (key_hex, key_file) {
        (Some(key), None) => Zeroizing::new(key.trim().to_string()),
        (None, Some(key_path)) => Zeroizing::new(
            std::fs::read_to_string(key_path)
                .with_context(|| format!("read report key {}", key_path.display()))?
                .trim()
                .to_string(),
        ),
        (None, None) => anyhow::bail!(
            "report requires --key-file, --key-hex, STEALTHY_KEY_FILE, or STEALTHY_KEY_HEX"
        ),
        (Some(_), Some(_)) => anyhow::bail!("provide only one report key source"),
    };
    let sealed = std::fs::read_to_string(path)?;
    let report = EncryptedStore::open_sealed_report(&sealed, &key)?;
    let findings = report.findings.iter().collect::<Vec<_>>();
    match format {
        ReportFormat::Json => println!("{}", output::render_json(&report, &findings)?),
        ReportFormat::Sarif => println!("{}", output::render_sarif(&report, &findings)),
        ReportFormat::Markdown | ReportFormat::Human => {
            print!(
                "{}",
                output::render_markdown(&report, &findings, findings.len())
            );
        }
    }
    Ok(())
}

fn print_diff(
    baseline_path: &std::path::Path,
    current_path: &std::path::Path,
    format: ReportFormat,
) -> Result<()> {
    let baseline: crate::core::types::RunReport =
        serde_json::from_str(&std::fs::read_to_string(baseline_path)?)?;
    let current: crate::core::types::RunReport =
        serde_json::from_str(&std::fs::read_to_string(current_path)?)?;
    let diff = crate::core::diff::compare(&baseline, &current)?;
    match format {
        ReportFormat::Json => println!("{}", serde_json::to_string_pretty(&diff)?),
        ReportFormat::Markdown | ReportFormat::Human => {
            println!("# {} report diff\n", crate::core::opsec::BRAND);
            println!("- Baseline: {}", diff.baseline_run_id);
            println!("- Current: {}\n", diff.current_run_id);
            println!(
                "| Added | Removed | Changed |\n| ---: | ---: | ---: |\n| {} | {} | {} |\n",
                diff.added.len(),
                diff.removed.len(),
                diff.changed.len()
            );
            if diff.identity_changed
                || diff.plugin_set_changed
                || diff.coverage_changed
                || diff.profile_changed
                || diff.severity_filter_changed
            {
                println!("## Comparison warnings\n");
                if diff.identity_changed {
                    println!("- Host identity or OS context changed.");
                }
                if diff.plugin_set_changed {
                    println!("- The completed plugin set changed.");
                }
                if diff.coverage_changed {
                    println!("- Coverage status or fallback capability changed.");
                }
                if diff.profile_changed {
                    println!("- Engagement profile changed.");
                }
                if diff.severity_filter_changed {
                    println!("- Minimum severity filter changed; finding counts are not directly comparable.");
                }
                println!();
            }
            for finding in &diff.added {
                println!("- Added: {} — {}", finding.title, finding.detail);
            }
            for finding in &diff.removed {
                println!("- Removed: {} — {}", finding.title, finding.detail);
            }
            for finding in &diff.changed {
                println!("- Changed: {}", finding.after.title);
            }
        }
        ReportFormat::Sarif => anyhow::bail!("SARIF is not supported for report diffs"),
    }
    Ok(())
}

fn print_auth_required() {
    eprintln!("{}", term::err("━".repeat(60).as_str()));
    eprintln!("{}", term::err("Authorization required"));
    eprintln!("{}", term::err("━".repeat(60).as_str()));
    eprintln!();
    eprintln!(
        "This tool is for {} only.",
        term::bold("authorized assessments")
    );
    eprintln!("Refusing to run without an explicit acknowledgment.");
    eprintln!();
    eprintln!("{}", term::bold("Next steps"));
    eprintln!("  1. Confirm written ROE covers this host");
    eprintln!(
        "  2. Re-run with {} or {}",
        term::cyan("--authorized"),
        term::cyan("STEALTHY_AUTHORIZED=1")
    );
    eprintln!(
        "  3. Read {} first if you are new here",
        term::cyan("stealthy guide")
    );
    eprintln!();
    eprintln!("  {} enum", term::ok("stealthy --authorized"));
    eprintln!("  {}", term::dim("stealthy disclaimer"));
    eprintln!();
}

fn print_plugins(tsv: bool) {
    let list = plugins::registry();
    if list.is_empty() {
        println!("{}", term::warn("No plugins compiled for this OS build."));
        return;
    }
    if tsv {
        for p in &list {
            println!("{}\t{}\t{}", p.id(), p.name(), p.description());
        }
        return;
    }

    let id_w = list.iter().map(|p| p.id().len()).max().unwrap_or(8).max(8);
    let name_w = list
        .iter()
        .map(|p| p.name().len())
        .max()
        .unwrap_or(8)
        .max(8);

    println!(
        "{}  {} plugins available on this build\n",
        term::bold("Plugins"),
        list.len()
    );
    println!(
        "  {}  {}  {}",
        term::bold(&format!("{:id_w$}", "ID")),
        term::bold(&format!("{:name_w$}", "NAME")),
        term::bold("DESCRIPTION")
    );
    println!(
        "  {}  {}  {}",
        term::dim(&"-".repeat(id_w)),
        term::dim(&"-".repeat(name_w)),
        term::dim(&"-".repeat(24))
    );
    for p in &list {
        let id = format!("{:id_w$}", p.id());
        let name = format!("{:name_w$}", p.name());
        println!(
            "  {}  {}  {}",
            term::cyan(&id),
            name,
            term::dim(p.description())
        );
    }
    println!();
    println!(
        "{}",
        term::dim("Tip: stealthy --authorized enum --plugins id1,id2")
    );
}

fn print_guide() {
    println!(
        "{}",
        term::bold(&format!("{} — operator guide", crate::core::opsec::BRAND))
    );
    println!();
    println!("{}", term::bold("1. Legal boundary"));
    println!("   Authorized engagements only. Read: stealthy disclaimer");
    println!();
    println!("{}", term::bold("2. Check readiness"));
    println!("   {}", term::cyan("stealthy doctor"));
    println!(
        "   {}",
        term::dim("Safe local checks; no host enumeration.")
    );
    println!();
    println!("{}", term::bold("3. Acknowledge authorization"));
    println!("   {}", term::cyan("stealthy --authorized enum"));
    println!("   {}", term::dim("# or: export STEALTHY_AUTHORIZED=1"));
    println!();
    println!("{}", term::bold("4. Discover plugins for this OS"));
    println!("   {}", term::cyan("stealthy --authorized list-plugins"));
    println!();
    println!("{}", term::bold("5. First safe enumeration (memory-only)"));
    println!("   {}", term::cyan("stealthy --authorized scan"));
    println!(
        "   {}",
        term::dim("Findings stay in memory. Nothing written to disk.")
    );
    println!();
    println!("{}", term::bold("5. Focus the noise"));
    println!(
        "   {}",
        term::cyan("stealthy --authorized --profile quiet enum --min-severity high")
    );
    println!(
        "   {}",
        term::cyan("stealthy --authorized enum --plugins linux.sudo,linux.groups")
    );
    println!();
    println!("{}", term::bold("6. Evidence (optional)"));
    println!(
        "   {}",
        term::cyan(
            "stealthy --authorized --output file --output-path ./findings.seal --also-markdown enum"
        )
    );
    println!(
        "   {}",
        term::cyan("stealthy --authorized --format markdown enum > report.md")
    );
    println!();
    println!("{}", term::bold("7. Operator extras"));
    println!(
        "   {}",
        term::cyan("stealthy --authorized enum --triage --triage-out decisions.json")
    );
    println!(
        "   {}",
        term::cyan("stealthy stage --os linux --target-hostname target-a --out ./drop --binary ./target/release/stealthy")
    );
    println!(
        "   {}",
        term::cyan("stealthy cleanup --latest --secure-delete")
    );
    println!();
    println!("{}", term::bold("8. Automation exit codes"));
    println!("   0  success");
    println!("   2  missing --authorized");
    println!("   4  --fail-on severity threshold hit");
    println!();
    println!("{}", term::bold("Safety defaults"));
    println!("   · Enumerate + recommend");
    println!("   · --auto-exploit = reversible probes");
    println!("   · --allow-techniques = high-impact families (ROE opt-in)");
    println!("   · --profile quiet|balanced|thorough|ci (quiet/balanced run plugins in-process)");
    println!();
    println!(
        "{}",
        term::dim("Full deploy steps: docs/runbook/delivery.md and docs/operator-runbook.md")
    );
}

fn print_disclaimer() {
    println!(
        "================================================================\n\
         {} — AUTHORIZED USE ONLY\n\
         ================================================================",
        crate::core::opsec::BRAND
    );
    println!(
        r#"
This software is intended exclusively for:
  • Authorized red team engagements
  • Internal security assessments
  • Defensive research with explicit written permission

You MUST have documented authorization before using this tool
against any system. Unauthorized privilege escalation, evasion,
or reconnaissance is illegal and unethical.

Default posture: enumeration + recommendations only.
Auto-exploitation (--auto-exploit) is opt-in for reversible probes.
High-impact families require --allow-techniques when ROE permits.

The operators of this project assume no liability for misuse.
================================================================"#
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    #[test]
    fn local_rendering_and_diagnostics_paths_are_exercised() {
        assert!(arg_was_set(
            &["stealthy".into(), "--format=json".into()],
            "--format"
        ));
        assert!(!arg_was_set(&["stealthy".into()], "--format"));
        assert!(!check(false).is_empty());
        assert!(!check(true).is_empty());
        print_recovery_hint("python: no such file or directory");
        print_recovery_hint("permission denied writing ledger cache");
        print_recovery_hint("key path unavailable");
        print_recovery_hint("primary blocked with status 126");
        print_recovery_hint("scan timeout partial cancel");
        print_recovery_hint("ordinary error");
        print_auth_required();
        print_guide();
        print_disclaimer();
        print_plugins(true);
        print_plugins(false);
        print_doctor(true).unwrap();
        print_doctor(false).unwrap();
    }

    #[test]
    fn offline_report_commands_cover_all_supported_formats() {
        let path = fixture("script_report_min.json");
        print_ingest(&path, ReportFormat::Json).unwrap();
        print_ingest(&path, ReportFormat::Markdown).unwrap();
        print_ingest(&path, ReportFormat::Human).unwrap();
        print_ingest(&path, ReportFormat::Sarif).unwrap();
        print_diff(&path, &path, ReportFormat::Json).unwrap();
        print_diff(&path, &path, ReportFormat::Markdown).unwrap();
        assert!(print_diff(&path, &path, ReportFormat::Sarif).is_err());
        let empty_ledger = tempfile::tempdir().unwrap();
        assert!(print_artifacts(Some(empty_ledger.path()), None, true).is_err());
        assert!(run_cleanup(Some(empty_ledger.path()), None, true, false, false).is_err());
    }

    #[test]
    fn safe_control_and_verify_paths_are_exercised() {
        let cli = Cli::parse_from(["stealthy", "--authorized", "controls"]);
        print_control_validation(
            &cli,
            Some("hash-drift".into()),
            None,
            None,
            None,
            false,
            false,
        )
        .unwrap();
        print_live_controls(&cli).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("verify");
        std::fs::write(&file, b"verify").unwrap();
        let hash = crate::core::delivery::sha256_file(&file).unwrap();
        run_verify(Some(&file), None, &hash).unwrap();
        assert!(run_verify(None, None, &hash).is_err());
    }
}
