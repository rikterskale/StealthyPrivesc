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
    pub plaintext_file: bool,
    pub also_markdown: bool,
    pub exfil_url: Option<String>,
    pub quiet: bool,
    pub format: ReportFormat,
    pub min_severity: Severity,
    pub verbose: bool,
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
            println!("{}", serde_json::to_string_pretty(&view)?);
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
                    "\n{} {} finding(s) in memory ({} shown) · seal key prefix {}",
                    term::dim("[memory]"),
                    total,
                    shown,
                    term::cyan(&store.key_hex()[..16.min(store.key_hex().len())])
                );
                eprintln!(
                    "{} Full key with -v · nothing written to disk by default",
                    term::dim("[memory]")
                );
            }
        }
        OutputMode::File => {
            let path = opts
                .path
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("--output=file requires --output-path"))?;
            write_file(report, store, path, opts.plaintext_file)?;
            if !opts.quiet {
                eprintln!("{} wrote {}", term::ok("[file]"), path.display());
                if !opts.plaintext_file && opts.verbose {
                    eprintln!(
                        "{} decrypt key (hex): {}\n{} treat this key as sensitive",
                        term::warn("[file]"),
                        store.key_hex(),
                        term::warn("[warn]")
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
                restrict_file_permissions(&md_file)?;
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
            if !opts.quiet {
                eprintln!(
                    "{}\n  target: {}\n  POST body (base64 nonce||ciphertext):\n{}",
                    term::warn("[remote] HTTPS exfil is operator-driven in v1 (no silent client)"),
                    url,
                    sealed
                );
                if opts.verbose {
                    eprintln!("  decrypt key (sensitive): {}", store.key_hex());
                } else {
                    eprintln!(
                        "{} decrypt key suppressed; use --verbose only with secure handling",
                        term::warn("[remote]")
                    );
                }
            }
        }
    }

    let _ = (shown, total);
    Ok(EmitResult { max_severity })
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
        "  mode={}  plugins_run={}",
        report.mode,
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
        term::dim("Authorized use only · kernel exploits disabled · prefer --authorized enum")
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
    println!("       {}", f.detail);
    println!("       {} {}", term::green("→"), f.recommendation);
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
        report.plugins_run.join(", "),
        total,
        findings.len()
    ));
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
             {}\n\n\
             **Recommendation:** {}\n\n\
             - kind: `{:?}`\n\
             - noisy: {}\n\
             - leaves_artifacts: {}\n\n",
            i + 1,
            f.severity.as_str().to_ascii_uppercase(),
            f.title,
            f.plugin,
            f.detail,
            f.recommendation,
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
    out.push_str("---\n_Authorized assessments only. Kernel exploits disabled in this build._\n");
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
                    "recommendation": finding.recommendation,
                    "noisy": finding.noisy,
                    "leaves_artifacts": finding.leaves_artifacts,
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
    restrict_file_permissions(&f)?;

    if plaintext {
        let json = serde_json::to_vec_pretty(report)?;
        f.write_all(&json)?;
    } else {
        let sealed = store.seal_report(report)?;
        f.write_all(sealed.as_bytes())?;
    }
    f.flush()?;
    Ok(())
}

fn restrict_file_permissions(_file: &std::fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        _file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Best-effort overwrite then unlink. Not a guarantee against forensic recovery.
#[allow(dead_code)]
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
