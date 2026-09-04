//! Beginner-facing, offline UX built on the canonical report and plugin contracts.

use anyhow::{Context, Result};
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

use crate::cli::{Cli, CliOverrides, CompletionShell, DispositionStatus};
use crate::core::types::{Finding, RunReport};
use crate::core::{ingest, output};
use crate::plugins;

pub fn quickstart(cli: &Cli, overrides: &CliOverrides) -> Result<()> {
    println!("{} quickstart\n", crate::core::opsec::BRAND);
    println!("1. Doctor checks local readiness (no host enumeration).\n");
    let _ = crate::core::os::detect();
    println!("2. Authorization: only assess systems covered by written ROE. Use --authorized or STEALTHY_AUTHORIZED=1.");
    println!(
        "3. Plugins compiled for this build: {}",
        plugins::registry().len()
    );
    for p in plugins::registry().iter().take(8) {
        println!("   - {}: {}", p.id(), p.name());
    }
    println!("\nSafe scan: enumerate + recommend, memory-only, no exploitation.");
    if cli.i_understand_authorized_use_only {
        let effective_profile = match cli.preset {
            Some(crate::cli::ScanPreset::Quick) => "quiet",
            Some(crate::cli::ScanPreset::Standard) => "balanced",
            Some(crate::cli::ScanPreset::Deep) => "thorough",
            None => cli.profile.as_str(),
        };
        println!("Authorization acknowledged.\n  OS: {}\n  Plugins: {}\n  Profile: {}\n  Output: memory-only\n  Mode: enumerate-only\n", crate::core::os::detect().os, plugins::registry().len(), effective_profile);
        if io::stdin().is_terminal() {
            println!("Start this safe scan? [y/N]");
            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                println!("Cancelled before host enumeration.");
                return Ok(());
            }
        }
        println!("Starting the safe scan.\n");
        let mut engine = crate::core::engine::Engine::from_cli(
            cli,
            overrides,
            false,
            crate::exploit::TechniqueAllowlist::from_ids(&[])?,
            false,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
        )?;
        engine.run()?;
    } else {
        println!("Run next: stealthy --authorized scan");
    }
    Ok(())
}

fn demo_report() -> Result<RunReport> {
    ingest::ingest_json(include_str!("../../tests/fixtures/script_report_min.json"))
}

pub fn demo(html: bool) -> Result<()> {
    let report = demo_report()?;
    let refs: Vec<&Finding> = report.findings.iter().collect();
    if html {
        println!("{}", output::render_html(&report, &refs));
    } else {
        println!("{}", output::render_markdown(&report, &refs, refs.len()));
    }
    Ok(())
}

pub fn html_report(path: &Path) -> Result<()> {
    let report = ingest::ingest_path(path)?;
    let refs: Vec<&Finding> = report.findings.iter().collect();
    println!("{}", output::render_html(&report, &refs));
    Ok(())
}

pub fn explain_plugin(id: &str) -> Result<()> {
    let p = plugins::registry()
        .into_iter()
        .find(|p| p.id() == id)
        .ok_or_else(|| anyhow::anyhow!("unknown plugin ID '{id}'; run stealthy list-plugins"))?;
    let category = if id.contains("credential") || id.contains("ssh") {
        "credentials"
    } else if id.contains("service") || id.contains("cron") || id.contains("task") {
        "persistence/services"
    } else if id.contains("container") {
        "containers"
    } else if id.contains("endpoint") || id.contains("app_control") {
        "endpoint controls"
    } else {
        "privilege and configuration"
    };
    println!("{} — {}\n\nCategory: {category}\nPrerequisites: runs on {} and reads only the sources available to the current account.\nData source: OS-native files, commands, or APIs selected by the plugin.\nLimitations: permissions, platform policy, and missing tools can reduce coverage; inspect coverage errors.\nNoise: low by default; profile and external-helper settings can change this.\nFallback coverage: script dispatchers provide reduced coverage; compare with `stealthy coverage-compare`.\n\n{}", p.id(), p.name(), p.platforms().join(", "), p.description());
    Ok(())
}

pub fn plugin_picker() -> Result<()> {
    println!("Plugin picker (copy the IDs you want into --plugins ID1,ID2):\n");
    let groups: &[(&str, &[&str])] = &[
        ("credentials", &["credential", "ssh"]),
        (
            "services / persistence",
            &["service", "cron", "task", "autorun"],
        ),
        ("containers", &["container"]),
        ("endpoint controls", &["endpoint", "app_control"]),
        (
            "privilege / configuration",
            &["sudo", "suid", "uac", "privilege", "mount", "path"],
        ),
    ];
    for (name, needles) in groups {
        println!("{name}:");
        for p in plugins::registry()
            .iter()
            .filter(|p| needles.iter().any(|n| p.id().contains(n)))
        {
            println!("  {} — {}", p.id(), p.name());
        }
    }
    if io::stdin().is_terminal() && io::stdout().is_terminal() {
        println!("\nEnter comma-separated plugin IDs, or press Enter to cancel:");
        let mut selection = String::new();
        io::stdin().read_line(&mut selection)?;
        let ids = selection
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .collect::<Vec<_>>();
        if !ids.is_empty() {
            println!(
                "\nRun: stealthy --authorized enum --plugins {}",
                ids.join(",")
            );
        } else {
            println!("No plugins selected.");
        }
    } else {
        println!("\nNon-interactive mode: copy IDs into `--plugins ID1,ID2`.");
    }
    Ok(())
}

pub fn presets() -> Result<()> {
    println!("Scan presets (all remain enumerate-only):\n  quick    ~10–30s, low noise, high-signal checks\n  standard ~30–120s, balanced coverage and noise\n  deep     2–10m, fullest native coverage, highest noise\n\nCommands:\n  stealthy --authorized --preset quick scan\n  stealthy --authorized --preset standard scan\n  stealthy --authorized --preset deep scan\n\nProfiles are lower-level controls; presets select a profile plus beginner-friendly intent.");
    Ok(())
}

pub fn playbook(id: &str) -> Result<()> {
    let plugin = id.split(':').next().unwrap_or(id);
    let name = plugins::registry()
        .into_iter()
        .find(|p| p.id() == plugin)
        .map(|p| p.name())
        .unwrap_or("finding");
    println!("Remediation playbook — {name} ({id})\n\n1. Verify safely\n  Re-run the focused read-only check with --plugins {plugin}. Preserve the JSON report and confirm the object, account, and permissions.\n\n2. Recommended fix\n  Apply the platform owner's approved least-privilege change: remove unnecessary elevation, restrict write access, rotate exposed secrets, or update the affected package/service. Do not apply an unreviewed command from this report.\n\n3. Rollback\n  Record the original value, owner, mode/ACL, and package version before changing it; restore that exact approved state if the service or workflow regresses.\n\n4. Post-fix recheck\n  Run `stealthy --authorized scan --plugins {plugin}` and compare it with the saved baseline using `stealthy diff BASELINE CURRENT`. Mark the disposition only after coverage is healthy.");
    Ok(())
}

pub fn security_lab(root: Option<PathBuf>) -> Result<()> {
    let root = root.unwrap_or_else(|| {
        std::env::temp_dir().join(format!("stealthy-lab-{}", std::process::id()))
    });
    std::fs::create_dir_all(&root).with_context(|| format!("create lab {}", root.display()))?;
    std::fs::write(root.join("README.txt"), "Disposable learning fixtures. They are inert text files, not exploits.\n\nlinux.sudo: inspect sudoers-style text.\nlinux.services: inspect service definitions.\nlinux.credentials: identify credential-shaped filenames.\nlinux.containers: inspect socket-style permissions.\n")?;
    std::fs::write(
        root.join("sudoers.example"),
        "alice ALL=(ALL) NOPASSWD: ALL\n",
    )?;
    std::fs::write(
        root.join("service.example"),
        "[Service]\nUser=root\nExecStart=/tmp/example\n",
    )?;
    std::fs::write(
        root.join("credentials.example"),
        "password=REDACTED-FIXTURE\n",
    )?;
    println!("Security lab created at {}\nIt is disposable and inert. Review README.txt, then remove it when finished.", root.display());
    Ok(())
}

pub fn explain_finding(id: &str, path: Option<&Path>) -> Result<()> {
    let report = match path {
        Some(p) => ingest::ingest_path(p)?,
        None => demo_report()?,
    };
    let f = report
        .findings
        .iter()
        .find(|f| f.finding_id == id || id == f.plugin || id == f.title)
        .ok_or_else(|| anyhow::anyhow!("finding '{id}' was not found; use a report finding_id"))?;
    println!("Why did I get this finding?\n\n{} ({})\n\n{}\n\nPlain English: {} observed `{}` in `{}`. That matters because it may affect the current user's path to higher privilege.\n\nConfidence: derived from the report's assessment metadata when available.\nSafe next step: {}\nVerify with: {}\n\nSource: {}", f.title, f.finding_id, f.detail, f.plugin, f.condition, f.object, f.recommendation, f.next_command(), path.map(|p| p.display().to_string()).unwrap_or_else(|| "bundled demo report (use --report for a real finding)".into()));
    Ok(())
}

pub fn coverage_compare(native: &Path, fallback: &Path) -> Result<()> {
    let n = ingest::ingest_path(native)?;
    let f = ingest::ingest_path(fallback)?;
    println!("Coverage comparison\nNative mode: {} plugins / {} findings\nFallback mode: {} plugins / {} findings", n.plugins_run.len(), n.findings.len(), f.plugins_run.len(), f.findings.len());
    println!("\nFallback could not collect:");
    for id in &f.capability_delta {
        println!("  - {id}");
    }
    println!("\nInterpretation: missing fallback plugins are coverage gaps, not clean results.");
    Ok(())
}

pub fn disposition(
    path: &Path,
    id: &str,
    status: DispositionStatus,
    reason: &str,
    out: Option<&Path>,
) -> Result<()> {
    let mut value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let finding_exists = value["findings"].as_array().is_some_and(|findings| {
        findings
            .iter()
            .any(|finding| finding["finding_id"].as_str() == Some(id))
    });
    if !finding_exists {
        anyhow::bail!(
            "finding '{id}' was not found in {}; use a report finding_id",
            path.display()
        );
    }
    let previous_status = value["dispositions"].as_array().and_then(|items| {
        items.iter().rev().find_map(|item| {
            (item["finding_id"].as_str() == Some(id))
                .then(|| item["status"].as_str().map(str::to_owned))
                .flatten()
        })
    });
    let operator = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into());
    let mut entry = serde_json::json!({
        "finding_id": id,
        "status": status,
        "reason": reason,
        "recorded_at_unix": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default(),
        "operator": operator
    });
    if let Some(previous) = previous_status {
        entry["previous_status"] = serde_json::json!(previous);
    }
    value["dispositions"]
        .as_array_mut()
        .map(|a| a.push(entry.clone()))
        .unwrap_or_else(|| value["dispositions"] = serde_json::json!([entry]));
    let destination = out
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("{}.dispositions.json", path.display())));
    if destination == path {
        anyhow::bail!("disposition output must not overwrite the original report; use --out");
    }
    value["disposition_source"] = serde_json::json!(path.display().to_string());
    std::fs::write(&destination, serde_json::to_string_pretty(&value)?)?;
    println!(
        "Recorded {} for {} in {}",
        serde_json::to_value(status)?.as_str().unwrap_or("status"),
        id,
        destination.display()
    );
    Ok(())
}

pub fn completions(shell: CompletionShell) -> Result<()> {
    let commands = "disclaimer guide doctor quickstart demo security-lab explain-plugin plugin-picker completions explain-finding html-report coverage-compare disposition presets playbook controls live-controls report diff ingest list-plugins artifacts cleanup stage verify one-liners resume enum scan";
    let flags = "--authorized --profile --preset --quiet --verbose --summary --progress-json --no-color --delay-ms --plugin-timeout-ms --max-scan-seconds --max-findings --max-report-bytes --format --min-severity --fail-on --output --output-path --key-output-path --plaintext-file --also-markdown --checkpoint --plugins --skip --auto-exploit --allow-techniques --triage --triage-out --approve-file";
    let ids = plugins::registry()
        .iter()
        .map(|p| p.id())
        .collect::<Vec<_>>()
        .join(" ");
    let words = format!("{commands} {flags} {ids}");
    let body = match shell {
        CompletionShell::Bash => format!("# stealthy bash completion\n_stealthy() {{ COMPREPLY=( $(compgen -W '{words}' -- \"${{COMP_WORDS[COMP_CWORD]}}\") ); }}\ncomplete -F _stealthy stealthy\n"),
        CompletionShell::Zsh => format!("#compdef stealthy\n_arguments '*: :(({words}))'\n"),
        CompletionShell::Fish => format!("complete -c stealthy -f -a '{words}'\n"),
        CompletionShell::Powershell => format!("Register-ArgumentCompleter -Native -CommandName stealthy -ScriptBlock {{ param($wordToComplete) '{words}'.Split() | Where-Object {{ $_ -like \"$wordToComplete*\" }} }}\n"),
    };
    print!("{body}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn offline_helpers_cover_all_formats_and_files() {
        let report = demo_report().unwrap();
        let refs: Vec<&Finding> = report.findings.iter().collect();
        assert!(output::render_html(&report, &refs)
            .contains(&format!("{} report", crate::core::opsec::BRAND)));
        assert!(output::render_markdown(&report, &refs, refs.len()).contains("## Findings"));

        let path =
            std::env::temp_dir().join(format!("stealthy-ux-test-{}.json", std::process::id()));
        std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
        html_report(&path).unwrap();
        coverage_compare(&path, &path).unwrap();
        let id = report.findings[0].finding_id.clone();
        explain_finding(&id, Some(&path)).unwrap();
        disposition(
            &path,
            &id,
            DispositionStatus::NeedsReview,
            "initial review",
            None,
        )
        .unwrap();
        let disposition_path = PathBuf::from(format!("{}.dispositions.json", path.display()));
        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&disposition_path).unwrap()).unwrap();
        assert_eq!(updated["dispositions"][0]["finding_id"], id);
        let rejected = path.with_extension("rejected.json");
        let error = disposition(
            &path,
            "missing-id",
            DispositionStatus::Fixed,
            "invalid",
            Some(&rejected),
        )
        .unwrap_err();
        assert!(error.to_string().contains("was not found"));
        assert!(!rejected.exists());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(disposition_path).unwrap();
    }

    #[test]
    fn operator_helpers_cover_safe_paths() {
        #[cfg(target_os = "linux")]
        let plugin_id = "linux.sudo";
        #[cfg(target_os = "windows")]
        let plugin_id = "windows.services";
        explain_plugin(plugin_id).unwrap();
        plugin_picker().unwrap();
        presets().unwrap();
        playbook(plugin_id).unwrap();
        for shell in [
            CompletionShell::Bash,
            CompletionShell::Zsh,
            CompletionShell::Fish,
            CompletionShell::Powershell,
        ] {
            completions(shell).unwrap();
        }
        let root = tempfile::tempdir().unwrap();
        security_lab(Some(root.path().join("lab"))).unwrap();
        assert!(root.path().join("lab/README.txt").is_file());
    }

    #[test]
    fn quickstart_without_acknowledgment_stays_off_host() {
        let cli = Cli::parse_from(["stealthy", "quickstart"]);
        quickstart(&cli, &CliOverrides::default()).unwrap();
    }
}
