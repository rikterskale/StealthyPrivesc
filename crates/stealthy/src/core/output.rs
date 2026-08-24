use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::Path;

use crate::cli::{OutputMode, ReportFormat};
use crate::core::store::EncryptedStore;
use crate::core::term;
use crate::core::types::{Finding, RunReport, Severity};

pub struct OutputOptions {
    pub mode: OutputMode,
    pub path: Option<std::path::PathBuf>,
    pub key_output_path: Option<std::path::PathBuf>,
    pub plaintext_file: bool,
    pub also_markdown: bool,
    pub exfil_url: Option<String>,
    pub quiet: bool,
    pub format: ReportFormat,
    pub min_severity: Severity,
    #[allow(dead_code)]
    pub run_id: String,
    #[allow(dead_code)]
    pub ledger_dir: std::path::PathBuf,
}

pub struct EmitResult {
    /// Highest severity among findings that passed the display filter (Info if none).
    pub max_severity: Severity,
}

pub fn emit(
    report: &RunReport,
    store: &EncryptedStore,
    opts: &OutputOptions,
) -> Result<EmitResult> {
    if ((opts.mode == OutputMode::File && !opts.plaintext_file) || opts.mode == OutputMode::Remote)
        && opts.key_output_path.is_none()
    {
        bail!(
            "encrypted output requires --key-output-path (or STEALTHY_KEY_OUTPUT_PATH); keys are never printed to stderr"
        );
    }
    let filtered = filter_findings(&report.findings, opts.min_severity);
    let max_severity = filtered
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);
    let shown = filtered.len();
    let total = report.findings.len();

    // Machine formats always go to stdout (even with -q). Human report respects quiet.
    match opts.format {
        ReportFormat::Human => {
            if !opts.quiet {
                print_human(report, &filtered, total);
            }
        }
        ReportFormat::Json => {
            let mut view = report.clone();
            view.findings = filtered.iter().map(|f| (*f).clone()).collect();
            println!("{}", render_json(&view, &filtered)?);
        }
        ReportFormat::Markdown => {
            print!("{}", render_markdown(report, &filtered, total));
        }
        ReportFormat::Sarif => {
            println!("{}", render_sarif(report, &filtered));
        }
    }

    match opts.mode {
        OutputMode::Memory => {
            if opts.plaintext_file {
                anyhow::bail!("--plaintext-file requires --output=file");
            }
            if opts.also_markdown {
                anyhow::bail!("--also-markdown requires --output=file");
            }
            if !opts.quiet && matches!(opts.format, ReportFormat::Human) {
                eprintln!(
                    "\n{} {} finding(s) in memory ({} shown) · nothing written to disk",
                    term::dim("[memory]"),
                    total,
                    shown
                );
            }
        }
        OutputMode::File => {
            let path = opts
                .path
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("--output=file requires --output-path"))?;
            write_file(report, store, path, opts.plaintext_file)?;
            if !opts.plaintext_file {
                let key_path = opts.key_output_path.as_ref().expect("validated key path");
                if key_path == path {
                    bail!("--key-output-path must differ from --output-path");
                }
                write_sensitive_file(key_path, store.key_hex().as_bytes())?;
            }
            if !opts.quiet {
                eprintln!("{} wrote {}", term::ok("[file]"), path.display());
                if !opts.plaintext_file {
                    let key_path = opts.key_output_path.as_ref().expect("validated key path");
                    eprintln!(
                        "{} wrote protected report key {}",
                        term::warn("[key]"),
                        key_path.display()
                    );
                }
            }
            if opts.also_markdown {
                let md_path = std::path::PathBuf::from(format!("{}.md", path.display()));
                let md = render_markdown(report, &filtered, total);
                let mut md_file = std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(&md_path)
                    .with_context(|| format!("write {}", md_path.display()))?;
                restrict_file_permissions(&md_file, &md_path)?;
                md_file.write_all(md.as_bytes())?;
                if !opts.quiet {
                    eprintln!("{} wrote {}", term::ok("[file]"), md_path.display());
                }
            }
        }
        OutputMode::Remote => {
            let url = opts
                .exfil_url
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("--output=remote requires --exfil-url"))?;
            let sealed = store.seal_report(report)?;
            let key_path = opts.key_output_path.as_ref().expect("validated key path");
            write_sensitive_file(key_path, store.key_hex().as_bytes())?;
            if !opts.quiet {
                eprintln!(
                    "{}\n  target: {}\n  POST body (base64 nonce||ciphertext):\n{}",
                    term::warn("[remote] HTTPS exfil is operator-driven in v1 (no silent client)"),
                    url,
                    sealed
                );
                eprintln!(
                    "{} wrote protected report key {}",
                    term::warn("[key]"),
                    key_path.display()
                );
            }
        }
    }

    let _ = (shown, total);
    Ok(EmitResult { max_severity })
}

/// Render a JSON report with derived operator guidance fields.
///
/// `recommendation` remains unchanged for compatibility. The derived fields
/// make the human-facing contract available to automation as well.
pub fn render_json(report: &RunReport, findings: &[&Finding]) -> Result<String> {
    let mut view = serde_json::to_value(report)?;
    if let Some(serialized_findings) = view
        .get_mut("findings")
        .and_then(serde_json::Value::as_array_mut)
    {
        for (serialized, finding) in serialized_findings.iter_mut().zip(findings) {
            serialized["what_next"] = serde_json::json!(finding.what_next());
            serialized["next_command"] = serde_json::json!(finding.next_command());
        }
    }
    Ok(serde_json::to_string_pretty(&view)?)
}

fn filter_findings(findings: &[Finding], min: Severity) -> Vec<&Finding> {
    let mut v: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity.rank() >= min.rank())
        .collect();
    v.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| a.plugin.cmp(&b.plugin))
            .then_with(|| a.title.cmp(&b.title))
    });
    v
}

fn count_by_severity(findings: &[&Finding]) -> [usize; 5] {
    let mut c = [0usize; 5];
    for f in findings {
        c[f.severity.rank() as usize] += 1;
    }
    c
}

fn print_human(report: &RunReport, findings: &[&Finding], total: usize) {
    let counts = count_by_severity(findings);
    let bar = "─".repeat(64);

    println!("{}", term::bold(&bar));
    println!(
        "{}  {}",
        term::bold("StealthyPrivesc"),
        term::dim(&format!("v{}", report.version))
    );
    println!("{}", term::bold(&bar));

    let elev = if report.identity.is_elevated {
        term::warn("elevated")
    } else {
        term::ok("user")
    };
    println!(
        "  {}  {}@{}  [{}]  {}/{}",
        term::cyan(&report.os.os),
        term::bold(&report.identity.username),
        report.identity.hostname,
        elev,
        report.os.arch,
        term::dim(&report.os.version_hint)
    );
    println!(
        "  mode={}  profile={}  plugins_run={}",
        report.mode,
        if report.profile.is_empty() {
            "balanced"
        } else {
            &report.profile
        },
        report.plugins_run.len()
    );
    println!();

    // Severity summary strip
    println!("{}", term::bold("Summary"));
    println!(
        "  {} {}  {} {}  {} {}  {} {}  {} {}   total {} (showing {})",
        term::severity_tag(Severity::Critical),
        counts[4],
        term::severity_tag(Severity::High),
        counts[3],
        term::severity_tag(Severity::Medium),
        counts[2],
        term::severity_tag(Severity::Low),
        counts[1],
        term::severity_tag(Severity::Info),
        counts[0],
        total,
        findings.len()
    );
    println!();

    if !report.attack_paths.is_empty() {
        println!("{}", term::bold("Attack paths"));
        for path in &report.attack_paths {
            println!(
                "  {}. {} — {} (noise={})",
                path.rank, path.title, path.summary, path.estimated_noise
            );
            println!(
                "       {}",
                term::dim(&format!("findings: {}", path.finding_ids.join(", ")))
            );
        }
        println!();
    }

    if findings.is_empty() {
        println!(
            "  {}",
            term::ok("No findings at or above the selected severity filter.")
        );
        println!();
    } else {
        println!("{}", term::bold("Findings"));
        println!("{}", term::dim("  (sorted by severity · highest first)"));
        println!();
        for (i, f) in findings.iter().enumerate() {
            print_finding(i + 1, f);
        }
    }

    if !report.notes.is_empty() {
        println!("{}", term::bold("Notes"));
        for n in &report.notes {
            println!("  {} {}", term::dim("·"), n);
        }
        println!();
    }

    if !report.coverage.is_empty() {
        println!("{}", term::bold("Coverage"));
        for coverage in &report.coverage {
            let detail = coverage
                .error
                .as_deref()
                .map(|e| format!(": {e}"))
                .unwrap_or_default();
            println!(
                "  {} {} · {} finding(s){}",
                if coverage.status == "ok" {
                    term::ok("[ok]")
                } else {
                    term::err("[error]")
                },
                coverage.id,
                coverage.findings,
                detail
            );
        }
        println!();
    }

    println!("{}", term::dim(&bar));
    println!(
        "{}",
        term::dim(
            "Authorized use only · high-impact techniques require --allow-techniques · prefer --authorized enum",
        )
    );
}

fn print_finding(idx: usize, f: &Finding) {
    println!(
        "  {}  {}  {}  {}",
        term::dim(&format!("{idx:>3}.")),
        term::severity_tag(f.severity),
        term::cyan(&f.plugin),
        term::bold(&f.title)
    );
    if !f.finding_id.is_empty() {
        println!(
            "       {} {}  exploitability={}  tti={}",
            term::dim("id"),
            f.finding_id,
            f.exploitability,
            if f.time_to_impact.is_empty() {
                "unknown"
            } else {
                &f.time_to_impact
            }
        );
    }
    if !f.mitre_techniques.is_empty() {
        println!(
            "       {} {}",
            term::dim("MITRE"),
            f.mitre_techniques.join(", ")
        );
    }
    println!("       {}", f.detail);
    println!(
        "       {} {} {}",
        term::green("→"),
        term::bold("What's next:"),
        f.what_next()
    );
    println!("       {} {}", term::dim("Command:"), f.next_command());
    let mut tags = Vec::new();
    if f.noisy {
        tags.push(term::warn("noisy"));
    }
    if f.leaves_artifacts {
        tags.push(term::warn("artifacts"));
    }
    tags.push(term::dim(&format!("{:?}", f.kind).to_ascii_lowercase()));
    if !tags.is_empty() {
        println!("       {}", tags.join("  "));
    }
    println!();
}

pub fn render_markdown(report: &RunReport, findings: &[&Finding], total: usize) -> String {
    let counts = count_by_severity(findings);
    let mut out = String::new();
    out.push_str(&format!(
        "# StealthyPrivesc report\n\n\
         - **Version:** {}\n\
         - **Schema:** {}\n\
         - **Run ID:** `{}`\n\
         - **Started (Unix):** {}\n\
         - **Host:** `{}`\n\
         - **User:** `{}` (elevated={})\n\
         - **OS:** {} / {} ({})\n\
         - **Mode:** {}\n\
         - **Execution path:** {}\n\
         - **Primary launch:** {}\n\
         - **ROE reference:** `{}`\n\
         - **Profile:** {}\n\
         - **Coverage mode:** {}\n\
         - **Plugins run:** {}\n\
         - **Findings:** {} total, {} shown\n\n",
        report.version,
        report.schema_version,
        report.run_id,
        report.started_at_unix,
        report.identity.hostname,
        report.identity.username,
        report.identity.is_elevated,
        report.os.os,
        report.os.arch,
        report.os.version_hint,
        report.mode,
        if report.execution_path.is_empty() {
            "binary"
        } else {
            &report.execution_path
        },
        if report.primary_launch.is_empty() {
            "not_applicable"
        } else {
            &report.primary_launch
        },
        report.roe_ref,
        if report.profile.is_empty() {
            "balanced"
        } else {
            &report.profile
        },
        if report.coverage_mode.is_empty() {
            "binary"
        } else {
            &report.coverage_mode
        },
        report.plugins_run.join(", "),
        total,
        findings.len()
    ));
    if !report.attack_paths.is_empty() {
        out.push_str("## Attack paths\n\n");
        for path in &report.attack_paths {
            out.push_str(&format!(
                "{}. **{}** — {} _(noise: {})_\n  - findings: `{}`\n",
                path.rank,
                path.title,
                path.summary,
                path.estimated_noise,
                path.finding_ids.join("`, `")
            ));
        }
        out.push('\n');
    }
    if let Some(controls) = &report.control_assessment {
        out.push_str("## Application-control and telemetry assessment\n\n");
        out.push_str(&format!(
            "- Platform: `{}`\n- Collection mode: `{}`\n- Policies observed: {}\n- Sensors inventoried: {}\n- Audit sources: {}\n- Validation cases: {}\n- Telemetry behavior classes: {}\n",
            controls.platform,
            controls.collection_mode,
            controls.policies.len(),
            controls.sensors.len(),
            controls.audit_sources.len(),
            controls.validation_cases.len(),
            controls.telemetry_expectations.len()
        ));
        out.push_str(&format!(
            "- Detection exposure: `{}` ({}/100 expected-telemetry score)\n",
            controls.detection_exposure_label, controls.detection_exposure
        ));
        out.push_str(&format!(
            "- Live telemetry: `{}` ({}/100; recent event collection)\n",
            controls.live_telemetry_label, controls.live_telemetry_score
        ));
        if let Some(artifact) = &controls.artifact {
            out.push_str(&format!(
                "- Artifact: `{}` — predicted decision `{}`; sha256 `{}`; origin `{}`; signer `{}`; publisher `{}`; product `{}`; version `{}`; policy rule `{}`; path class `{}`; access control `{}`; static analysis `{}`\n",
                artifact.path,
                artifact.predicted_decision,
                artifact.sha256,
                artifact.origin,
                artifact.signer,
                artifact.publisher,
                artifact.product,
                artifact.file_version,
                artifact.policy_rule,
                artifact.path_class,
                artifact.access_control,
                artifact.static_analysis.join(" | ")
            ));
        }
        out.push_str(
            "- Detection exposure is an expected-telemetry label, not a stealth score.\n\n",
        );
    }
    out.push_str("## Severity summary\n\n");
    out.push_str("| Critical | High | Medium | Low | Info |\n| --- | --- | --- | --- | --- |\n");
    out.push_str(&format!(
        "| {} | {} | {} | {} | {} |\n\n",
        counts[4], counts[3], counts[2], counts[1], counts[0]
    ));
    out.push_str("## Findings\n\n");
    if findings.is_empty() {
        out.push_str("_No findings at selected severity._\n\n");
    }
    for (i, f) in findings.iter().enumerate() {
        out.push_str(&format!(
            "### {}. [{}] {} (`{}`)\n\n\
             - **finding_id:** `{}`\n\
             - **MITRE:** {}\n\
             - **technique_id:** `{}`\n\
             - **exploitability:** {}\n\
             - **time_to_impact:** {}\n\n\
             {}\n\n\
             **What's next:** {}\n\n\
             **Command:** `{}`\n\n\
             - kind: `{:?}`\n\
             - noisy: {}\n\
             - leaves_artifacts: {}\n\n",
            i + 1,
            f.severity.as_str().to_ascii_uppercase(),
            f.title,
            f.plugin,
            f.finding_id,
            if f.mitre_techniques.is_empty() {
                "_none_".into()
            } else {
                f.mitre_techniques
                    .iter()
                    .map(|t| format!("`{t}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            f.technique_id,
            f.exploitability,
            if f.time_to_impact.is_empty() {
                "unknown"
            } else {
                &f.time_to_impact
            },
            f.detail,
            f.what_next(),
            f.next_command(),
            f.kind,
            f.noisy,
            f.leaves_artifacts
        ));
    }
    if !report.notes.is_empty() {
        out.push_str("## Notes\n\n");
        for n in &report.notes {
            out.push_str(&format!("- {n}\n"));
        }
        out.push('\n');
    }
    if !report.coverage.is_empty() {
        out.push_str("## Plugin coverage\n\n| Plugin | Status | Findings | Duration (ms) | Error |\n| --- | --- | ---: | ---: | --- |\n");
        for coverage in &report.coverage {
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} |\n",
                coverage.id,
                coverage.status,
                coverage.findings,
                coverage.duration_ms,
                coverage.error.as_deref().unwrap_or("").replace('|', "\\|")
            ));
        }
        out.push('\n');
    }
    out.push_str(
        "---\n_Authorized assessments only. High-impact techniques require --allow-techniques._\n",
    );
    out
}

pub fn render_sarif(report: &RunReport, findings: &[&Finding]) -> String {
    let results = findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "ruleId": finding.plugin,
                "level": match finding.severity {
                    Severity::Critical | Severity::High => "error",
                    Severity::Medium => "warning",
                    Severity::Low | Severity::Info => "note",
                },
                "message": { "text": format!("{}: {}", finding.title, finding.detail) },
                "properties": {
                    "severity": finding.severity.as_str(),
                    "kind": format!("{:?}", finding.kind).to_ascii_lowercase(),
                    "recommendation": finding.what_next(),
                    "what_next": finding.what_next(),
                    "next_command": finding.next_command(),
                    "noisy": finding.noisy,
                    "leaves_artifacts": finding.leaves_artifacts,
                    "finding_id": finding.finding_id,
                    "mitre_techniques": finding.mitre_techniques,
                    "technique_id": finding.technique_id,
                    "exploitability": finding.exploitability,
                }
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": report.tool,
                "version": report.version,
                "informationUri": "https://github.com/rikterskale/StealthyPrivesc"
            }},
            "properties": {
                "run_id": report.run_id,
                "started_at_unix": report.started_at_unix,
                "coverage": report.coverage
            },
            "results": results
        }]
    })
    .to_string()
}

fn write_file(
    report: &RunReport,
    store: &EncryptedStore,
    path: &Path,
    plaintext: bool,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create output directory {}", parent.display()))?;
        }
    }

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    restrict_file_permissions(&f, path)?;

    if plaintext {
        let findings = report.findings.iter().collect::<Vec<_>>();
        let json = render_json(report, &findings)?.into_bytes();
        f.write_all(&json)?;
    } else {
        let sealed = store.seal_report(report)?;
        f.write_all(sealed.as_bytes())?;
    }
    f.flush()?;
    Ok(())
}

fn write_sensitive_file(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create key directory {}", parent.display()))?;
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .with_context(|| format!("create protected key file {}", path.display()))?;
    restrict_file_permissions(&file, path)?;
    file.write_all(contents)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn restrict_file_permissions(_file: &std::fs::File, _path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        _file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    {
        let whoami = crate::core::command::trusted_command("whoami.exe")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .context("resolve current Windows SID for output ACL")?;
        if !whoami.status.success() {
            bail!("whoami.exe could not resolve the current Windows SID");
        }
        let text = String::from_utf8_lossy(&whoami.stdout);
        let sid = text
            .split(',')
            .nth(1)
            .map(|value| value.trim().trim_matches('"'))
            .filter(|value| value.starts_with("S-1-"))
            .ok_or_else(|| anyhow::anyhow!("could not parse current Windows SID"))?;
        let grant = format!("*{sid}:(F)");
        let status = crate::core::command::trusted_command("icacls.exe")
            .arg(_path)
            .args(["/inheritance:r", "/grant:r", &grant])
            .status()
            .context("apply restrictive Windows output ACL")?;
        if !status.success() {
            bail!("icacls.exe failed to restrict output to the current Windows SID");
        }
    }
    Ok(())
}

/// Best-effort overwrite then unlink. Not a guarantee against forensic recovery.
pub fn secure_delete_hint(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("path does not exist");
    }
    let len = std::fs::metadata(path)?.len();
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
        let chunk = vec![0u8; 4096];
        let mut remaining = len;
        while remaining > 0 {
            let n = remaining.min(chunk.len() as u64) as usize;
            f.write_all(&chunk[..n])?;
            remaining -= n as u64;
        }
        f.flush()?;
    }
    std::fs::remove_file(path)?;
    Ok(())
}
