//! StealthyPrivesc — modular privilege-escalation enumerator for authorized assessments.
//!
//! LEGAL: Use only on systems you are explicitly authorized to assess in writing.
//! Unauthorized use is illegal. Default mode is quiet enumeration + recommendations only.

mod cli;
mod core;
mod exploit;
mod plugins;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, CliOverrides, Commands, ReportFormat};
use crate::core::artifacts;
use crate::core::delivery;
use crate::core::engine::Engine;
use crate::core::ingest;
use crate::core::output;
use crate::core::store::EncryptedStore;
use crate::core::term;

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    let overrides = CliOverrides {
        delay_ms_set: argv.iter().any(|a| a == "--delay-ms"),
        plugin_timeout_ms_set: argv.iter().any(|a| a == "--plugin-timeout-ms"),
        format_set: argv.iter().any(|a| a == "--format"),
    };
    let mut cli = Cli::parse();
    term::init(cli.no_color);

    // Local UX / operator-workstation commands never need the auth gate.
    let needs_auth = !matches!(
        &cli.command,
        Some(Commands::Disclaimer)
            | Some(Commands::Guide)
            | Some(Commands::Doctor { .. })
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
        plugins: None,
        skip: None,
        triage: false,
        triage_out: None,
        approve_file: None,
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
        Commands::Report {
            input,
            key_hex,
            format,
        } => print_report(&input, &key_hex, format),
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
        } => run_stage(
            &os,
            &arch,
            &name,
            &out,
            binary.as_deref(),
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
        Commands::Resume {
            checkpoint,
            auto_exploit,
            allow_techniques,
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
        ),
        Commands::Enum {
            auto_exploit,
            allow_techniques,
            plugins: only,
            skip,
            triage,
            triage_out,
            approve_file,
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
        ),
    }
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
) -> Result<()> {
    let allow =
        crate::exploit::TechniqueAllowlist::from_ids(allow_techniques.as_deref().unwrap_or(&[]))?;
    let mut engine = Engine::from_cli(
        cli,
        overrides,
        auto_exploit,
        allow,
        only,
        skip,
        checkpoint,
        resume_from,
        triage,
        triage_out,
        approve_file,
    )?;
    let outcome = engine.run()?;
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

fn run_stage(
    os: &str,
    arch: &str,
    name: &str,
    out: &std::path::Path,
    binary: Option<&std::path::Path>,
    ledger_dir: Option<&std::path::Path>,
) -> Result<()> {
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
    let supported = matches!(os.os.as_str(), "linux" | "windows");
    let healthy = supported && plugin_count > 0 && cwd_ok;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": "1",
                "healthy": healthy,
                "os": os,
                "plugins": plugin_count,
                "current_directory": cwd.map(|p| p.display().to_string()),
                "checks": {
                    "supported_os": supported,
                    "plugins_available": plugin_count > 0,
                    "working_directory": cwd_ok,
                }
            })
        );
    } else {
        println!("{}", term::bold("StealthyPrivesc doctor"));
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
        println!();
        println!(
            "{}",
            if healthy {
                term::ok("Ready for an authorized scan.")
            } else {
                term::err("Action required before scanning.")
            }
        );
    }
    if healthy {
        Ok(())
    } else {
        std::process::exit(3)
    }
}

fn check(ok: bool) -> String {
    if ok {
        term::ok("[ok]")
    } else {
        term::err("[!!]")
    }
}

fn print_report(path: &std::path::Path, key_hex: &str, format: ReportFormat) -> Result<()> {
    let sealed = std::fs::read_to_string(path)?;
    let report = EncryptedStore::open_sealed_report(&sealed, key_hex)?;
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
    let diff = crate::core::diff::compare(&baseline, &current);
    match format {
        ReportFormat::Json => println!("{}", serde_json::to_string_pretty(&diff)?),
        ReportFormat::Markdown | ReportFormat::Human => {
            println!("# StealthyPrivesc report diff\n");
            println!("- Baseline: {}", diff.baseline_run_id);
            println!("- Current: {}\n", diff.current_run_id);
            println!(
                "| Added | Removed | Changed |\n| ---: | ---: | ---: |\n| {} | {} | {} |\n",
                diff.added.len(),
                diff.removed.len(),
                diff.changed.len()
            );
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
    println!("{}", term::bold("StealthyPrivesc — operator guide"));
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
        term::cyan("stealthy stage --os linux --out ./drop --binary ./target/release/stealthy")
    );
    println!("   {}", term::cyan("stealthy cleanup --latest --secure-delete"));
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
    println!("   · --profile quiet|balanced|thorough|ci");
    println!();
    println!(
        "{}",
        term::dim("Full deploy steps: docs/operator-runbook.md")
    );
}

fn print_disclaimer() {
    println!(
        r#"================================================================
StealthyPrivesc — AUTHORIZED USE ONLY
================================================================

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
