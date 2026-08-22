use clap::{Parser, Subcommand, ValueEnum};

/// StealthyPrivesc — modular privilege-escalation enumerator for authorized assessments.
///
/// Default posture: quiet enumeration + recommendations. High-impact techniques require
/// explicit `--allow-techniques` opt-in when ROE permits.
#[derive(Debug, Parser)]
#[command(name = "stealthy")]
#[command(version, about, long_about = LONG_ABOUT)]
#[command(propagate_version = true)]
#[command(after_help = AFTER_HELP)]
#[command(arg_required_else_help = false)]
pub struct Cli {
    /// Required acknowledgment that use is limited to authorized assessments.
    /// Alias: --authorized. Env: STEALTHY_AUTHORIZED=1
    #[arg(
        long = "i-understand-authorized-use-only",
        visible_alias = "authorized",
        global = true,
        env = "STEALTHY_AUTHORIZED"
    )]
    pub i_understand_authorized_use_only: bool,

    /// Reduce console noise (still stores findings in memory).
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Extra diagnostic output (may be noisier on-host).
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Disable ANSI colors (also honors NO_COLOR).
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Randomized low-and-slow delay budget in milliseconds between checks (0 = off).
    #[arg(long, global = true, default_value_t = 50)]
    pub delay_ms: u64,

    /// Console / file report shape.
    #[arg(long, global = true, value_enum, default_value_t = ReportFormat::Human)]
    pub format: ReportFormat,

    /// Only show findings at or above this severity (human format).
    #[arg(long, global = true, value_enum, default_value_t = MinSeverity::Info)]
    pub min_severity: MinSeverity,

    /// Exit non-zero if any finding reaches this severity (after filters).
    #[arg(long, global = true, value_enum)]
    pub fail_on: Option<MinSeverity>,

    /// Where findings are emitted after the run.
    #[arg(long, global = true, value_enum, default_value_t = OutputMode::Memory)]
    pub output: OutputMode,

    /// Path used when --output=file (encrypted blob) or plaintext JSON if --plaintext-file.
    #[arg(long, global = true)]
    pub output_path: Option<std::path::PathBuf>,

    /// Write plaintext JSON instead of encrypted blob (still requires explicit --output=file).
    #[arg(long, global = true)]
    pub plaintext_file: bool,

    /// Also write a Markdown evidence report next to --output-path (adds .md).
    #[arg(long, global = true)]
    pub also_markdown: bool,

    /// Optional HTTPS C2 URL for encrypted exfil (operator-configured; off by default).
    #[arg(long, global = true, env = "STEALTHY_EXFIL_URL")]
    pub exfil_url: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Print the legal / ethical disclaimer.
    Disclaimer,

    /// First-run operator guide (safe; no host enumeration).
    Guide,

    /// Check platform, plugin, permissions, and output prerequisites.
    Doctor {
        /// Emit a compact JSON diagnostic document.
        #[arg(long)]
        json: bool,
    },

    /// Decode an encrypted report using its operator-held hex key.
    Report {
        /// Sealed report path.
        input: std::path::PathBuf,
        /// Hex key printed when the report was created with --verbose.
        #[arg(long)]
        key_hex: String,
        /// Report format to print.
        #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
        format: ReportFormat,
    },

    /// Compare two plaintext JSON reports offline.
    Diff {
        /// Baseline JSON report.
        baseline: std::path::PathBuf,
        /// Current JSON report.
        current: std::path::PathBuf,
        /// Output format for the comparison.
        #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
        format: ReportFormat,
    },

    /// List compiled-in plugin IDs for this build/OS.
    #[command(visible_alias = "plugins")]
    ListPlugins {
        /// Machine-readable TSV (id\\tname\\tdescription).
        #[arg(long)]
        tsv: bool,
    },

    /// Enumerate privilege-escalation opportunities (default).
    #[command(visible_alias = "scan")]
    Enum {
        /// Opt-in: attempt low-noise, reversible verification actions.
        #[arg(long)]
        auto_exploit: bool,

        /// Opt-in high-impact technique families when ROE permits.
        /// Known IDs: persistence, host-crash, potato, kernel-exploit,
        /// service-replace, msi, credential-dump, endpoint-bypass.
        /// Scaffolded in this revision (flags accepted; payloads land later).
        #[arg(long, value_delimiter = ',')]
        allow_techniques: Option<Vec<String>>,

        /// Comma-separated plugin IDs to run (default: all for this OS).
        #[arg(long, value_delimiter = ',')]
        plugins: Option<Vec<String>>,

        /// Comma-separated plugin IDs to skip.
        #[arg(long, value_delimiter = ',')]
        skip: Option<Vec<String>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputMode {
    /// Keep results encrypted in memory only (default; nothing written to disk).
    Memory,
    /// Write an encrypted blob (or plaintext JSON with --plaintext-file) to --output-path.
    File,
    /// Attempt optional HTTPS POST of encrypted findings to --exfil-url.
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    /// Colorized operator report with severity summary (default).
    Human,
    /// Pretty JSON on stdout (still honors --output for sealed file/remote).
    Json,
    /// Markdown report on stdout.
    Markdown,
    /// SARIF 2.1.0 for GitHub code-scanning-compatible consumers.
    Sarif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MinSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl MinSeverity {
    pub fn to_severity(self) -> crate::core::types::Severity {
        match self {
            MinSeverity::Info => crate::core::types::Severity::Info,
            MinSeverity::Low => crate::core::types::Severity::Low,
            MinSeverity::Medium => crate::core::types::Severity::Medium,
            MinSeverity::High => crate::core::types::Severity::High,
            MinSeverity::Critical => crate::core::types::Severity::Critical,
        }
    }
}

const LONG_ABOUT: &str = "\
StealthyPrivesc is a modular privilege-escalation enumerator for authorized \
red team and internal assessments only.

Default mode enumerates and recommends. Auto-exploitation is opt-in for \
reversible probes. High-impact families (kernel exploits, persistence, Potato, \
MSI, credential dump, service replace, host-crash, endpoint bypass) require \
explicit --allow-techniques when ROE permits.

Pass --authorized (or set STEALTHY_AUTHORIZED=1) before any host action.";

const AFTER_HELP: &str = "\
Examples:
  stealthy guide
  stealthy --authorized disclaimer
  stealthy --authorized list-plugins
  stealthy --authorized enum
  stealthy --authorized -q enum --plugins linux.sudo,linux.groups
  stealthy --authorized enum --min-severity high
  stealthy --authorized enum --auto-exploit
  stealthy --authorized enum --allow-techniques kernel-exploit,potato
  stealthy --authorized --format json scan
  stealthy --authorized --format sarif -q scan > findings.sarif
  stealthy --authorized --output file --output-path /tmp/f.seal enum
  stealthy --authorized enum --fail-on critical
  stealthy diff baseline.json current.json
  stealthy doctor

Docs: README.md  ·  docs/operator-runbook.md  ·  docs/techniques.md
";
