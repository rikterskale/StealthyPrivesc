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

use crate::cli::{Cli, Commands};
use crate::core::engine::Engine;
use crate::core::term;

fn main() -> Result<()> {
    let mut cli = Cli::parse();
    term::init(cli.no_color);

    // Guide + disclaimer never need the auth gate. Bare `--help` is handled by clap.
    let needs_auth = !matches!(
        &cli.command,
        Some(Commands::Disclaimer) | Some(Commands::Guide)
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
    println!("{}", term::bold("2. Acknowledge authorization"));
    println!("   {}", term::cyan("stealthy --authorized enum"));
    println!("   {}", term::dim("# or: export STEALTHY_AUTHORIZED=1"));
    println!();
    println!("{}", term::bold("3. Discover plugins for this OS"));
    println!("   {}", term::cyan("stealthy --authorized list-plugins"));
    println!();
    println!("{}", term::bold("4. First safe enumeration (memory-only)"));
    println!("   {}", term::cyan("stealthy --authorized enum"));
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
