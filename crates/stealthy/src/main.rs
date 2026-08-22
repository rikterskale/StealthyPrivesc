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

use crate::cli::{Cli, Commands, ReportFormat};
use crate::core::engine::Engine;
use crate::core::output;
use crate::core::store::EncryptedStore;
use crate::core::term;

fn main() -> Result<()> {
    let mut cli = Cli::parse();
    term::init(cli.no_color);

    // Local UX commands never need the auth gate. Bare `--help` is handled by clap.
    let needs_auth = !matches!(
        &cli.command,
        Some(Commands::Disclaimer)
            | Some(Commands::Guide)
            | Some(Commands::Doctor { .. })
            | Some(Commands::Report { .. })
    );

    if needs_auth && !cli.i_understand_authorized_use_only {
        print_auth_required();
        std::process::exit(2);
    }

    let command = cli.command.take().unwrap_or(Commands::Enum {
        auto_exploit: false,
        plugins: None,
        skip: None,
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
        Commands::ListPlugins { tsv } => {
            print_plugins(tsv);
            Ok(())
        }
        Commands::Enum {
            auto_exploit,
            plugins: only,
            skip,
        } => {
            let mut engine = Engine::from_cli(&cli, auto_exploit, only, skip)?;
            let outcome = engine.run()?;
            if outcome.fail_on_triggered {
                std::process::exit(4);
            }
            Ok(())
        }
    }
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
        ReportFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
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
        term::cyan("stealthy --authorized enum --min-severity high")
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
    println!("{}", term::bold("7. Automation exit codes"));
    println!("   0  success");
    println!("   2  missing --authorized");
    println!("   4  --fail-on severity threshold hit");
    println!();
    println!("{}", term::bold("Safety defaults"));
    println!("   · Enumerate + recommend");
    println!("   · --auto-exploit = reversible probes only");
    println!("   · Kernel exploits blocked");
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
Auto-exploitation is opt-in, limited to low-noise reversible
techniques, and never includes kernel exploits in this build.

The operators of this project assume no liability for misuse.
================================================================"#
    );
}
