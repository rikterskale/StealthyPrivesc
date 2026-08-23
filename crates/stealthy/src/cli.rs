use clap::{builder::BoolishValueParser, ArgAction, Parser, Subcommand, ValueEnum};

use crate::core::profile::EngagementProfile;

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
        env = "STEALTHY_AUTHORIZED",
        value_parser = BoolishValueParser::new(),
        action = ArgAction::SetTrue
    )]
    pub i_understand_authorized_use_only: bool,

    /// Named OPSEC / engagement profile (explicit flags override).
    #[arg(long, global = true, value_enum, default_value_t = EngagementProfile::Balanced)]
    pub profile: EngagementProfile,

    /// Reduce console noise (still stores findings in memory).
    #[arg(short, long, global = true, action = ArgAction::SetTrue)]
    pub quiet: bool,

    /// Extra diagnostic output (may be noisier on-host).
    #[arg(short, long, global = true, action = ArgAction::SetTrue)]
    pub verbose: bool,

    /// Disable ANSI colors (also honors NO_COLOR).
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Randomized low-and-slow delay budget in milliseconds between checks (0 = off).
    #[arg(long, global = true, default_value_t = 50)]
    pub delay_ms: u64,

    /// Per-plugin timeout in milliseconds (0 = disabled).
    #[arg(long, global = true, default_value_t = 120_000)]
    pub plugin_timeout_ms: u64,

    /// Artifact ledger directory (default: .cache-run).
    #[arg(long, global = true)]
    pub ledger_dir: Option<std::path::PathBuf>,

    /// Read-only artifact for hash, provenance, signer, mount, and trust prediction.
    /// The artifact is never executed or modified.
    #[arg(long, global = true)]
    pub artifact: Option<std::path::PathBuf>,

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

    /// Write/update a plaintext JSON checkpoint during the run.
    #[arg(long, global = true)]
    pub checkpoint: Option<std::path::PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Flags that must be resolved after parse with occurrence tracking.
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    pub delay_ms_set: bool,
    pub plugin_timeout_ms_set: bool,
    pub format_set: bool,
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

    /// Run disposable, read-only application-control validation cases.
    #[command(visible_alias = "validate-controls")]
    Controls {
        /// Run one case ID instead of the complete platform suite.
        #[arg(long)]
        case: Option<String>,
        /// Preserve fixtures under this directory for operator review.
        #[arg(long)]
        root: Option<std::path::PathBuf>,
        /// Optional organization-signed artifact for Windows signer/scope cases.
        #[arg(long)]
        signed_artifact: Option<std::path::PathBuf>,
        /// Prior JSON report or control assessment for policy-drift comparison.
        #[arg(long)]
        baseline: Option<std::path::PathBuf>,
        /// Start only the suite-generated benign probe with --help.
        #[arg(long)]
        execute: bool,
        /// Keep automatically generated temporary fixtures instead of cleaning them.
        #[arg(long)]
        keep_fixtures: bool,
    },

    /// Collect live application-control, provenance, sensor, and audit state without fixtures.
    #[command(visible_alias = "collect-controls")]
    LiveControls,

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

    /// Normalize a script-fallback JSON report into schema v2.
    Ingest {
        /// Script or partial JSON report path.
        input: std::path::PathBuf,
        /// Output format.
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

    /// List artifact ledger entries for a run.
    Artifacts {
        /// Run ID (default: latest ledger).
        #[arg(long)]
        run_id: Option<String>,
        /// Use the most recently written ledger.
        #[arg(long)]
        latest: bool,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },

    /// Remove removable artifacts recorded in the ledger.
    Cleanup {
        /// Run ID (default: latest ledger).
        #[arg(long)]
        run_id: Option<String>,
        /// Use latest ledger.
        #[arg(long)]
        latest: bool,
        /// Overwrite then unlink when possible.
        #[arg(long)]
        secure_delete: bool,
        /// Also attempt to remove this binary.
        #[arg(long)]
        remove_self: bool,
    },

    /// Package a drop bundle for an approved transport.
    Stage {
        /// Target OS family.
        #[arg(long, value_parser = ["linux", "windows"])]
        os: String,
        /// Target architecture.
        #[arg(long, default_value = "x86_64", value_parser = ["x86_64", "aarch64"])]
        arch: String,
        /// Drop / binary basename.
        #[arg(long, default_value = "cache-update")]
        name: String,
        /// Output directory.
        #[arg(long)]
        out: std::path::PathBuf,
        /// Optional real binary to copy into the bundle.
        #[arg(long)]
        binary: Option<std::path::PathBuf>,
    },

    /// Verify a local or remote artifact hash.
    Verify {
        /// Local path to verify.
        #[arg(long)]
        path: Option<std::path::PathBuf>,
        /// SSH target (user@host) for remote verify.
        #[arg(long)]
        ssh: Option<String>,
        /// Expected SHA-256 hex digest.
        #[arg(long)]
        expect_sha256: String,
    },

    /// Print copy-paste transport one-liners (no execution).
    OneLiners {
        #[arg(long, value_parser = ["linux", "windows"])]
        os: String,
        #[arg(long, value_parser = ["ssh", "scp", "http", "smb", "winrm"])]
        transport: String,
    },

    /// Private per-plugin worker used to enforce process-level timeouts.
    #[command(name = "__plugin-worker", hide = true)]
    PluginWorker {
        #[arg(long)]
        plugin: String,
    },

    /// Resume an interrupted run from a checkpoint JSON file.
    Resume {
        /// Checkpoint path from a prior `--checkpoint` run.
        #[arg(long)]
        checkpoint: std::path::PathBuf,
        /// Opt-in: attempt low-noise, reversible verification actions.
        #[arg(long)]
        auto_exploit: bool,
        /// Opt-in high-impact technique families when ROE permits.
        #[arg(long, value_delimiter = ',')]
        allow_techniques: Option<Vec<String>>,
        /// Comma-separated plugin IDs to run (default: all for this OS).
        #[arg(long, value_delimiter = ',')]
        plugins: Option<Vec<String>>,
        /// Comma-separated plugin IDs to skip.
        #[arg(long, value_delimiter = ',')]
        skip: Option<Vec<String>>,
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
        /// Most families are scaffold-only in this revision. `endpoint-bypass`
        /// means alternate-path + approved-fixture validation only (AMSI/ETW/EDR
        /// disable and quarantine tamper are Planned separate families). See
        /// docs/techniques.md.
        #[arg(long, value_delimiter = ',')]
        allow_techniques: Option<Vec<String>>,

        /// Comma-separated plugin IDs to run (default: all for this OS).
        #[arg(long, value_delimiter = ',')]
        plugins: Option<Vec<String>>,

        /// Comma-separated plugin IDs to skip.
        #[arg(long, value_delimiter = ',')]
        skip: Option<Vec<String>>,

        /// Enumerate then open triage (TTY prompts and/or --triage-out stub).
        #[arg(long)]
        triage: bool,

        /// Write a triage decisions stub JSON for offline editing.
        #[arg(long)]
        triage_out: Option<std::path::PathBuf>,

        /// Apply triage decisions; `probe` actions enable reversible probes.
        #[arg(long)]
        approve_file: Option<std::path::PathBuf>,
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
MSI, credential dump, service replace, host-crash, endpoint-bypass) require \
explicit --allow-techniques when ROE permits. endpoint-bypass means \
alternate-path + approved-fixture validation only (never AMSI/ETW/EDR disable).

Pass --authorized (or set STEALTHY_AUTHORIZED=1) before any host action.";

const AFTER_HELP: &str = "\
Examples:
  stealthy guide
  stealthy --authorized --profile quiet enum
  stealthy --authorized --profile ci enum --plugins linux.kernel_cve
  stealthy --authorized enum --triage --triage-out decisions.json
  stealthy --authorized enum --approve-file decisions.json
  stealthy --authorized --checkpoint /tmp/run.json enum
  stealthy --authorized resume --checkpoint /tmp/run.json
  stealthy stage --os linux --arch x86_64 --out ./drop --binary ./target/release/stealthy
  stealthy verify --path ./drop/cache-update --expect-sha256 HEX
  stealthy one-liners --os linux --transport ssh
  stealthy ingest script-report.json
  stealthy artifacts --latest
  stealthy cleanup --latest --secure-delete

Docs: README.md  ·  docs/operator-runbook.md  ·  docs/techniques.md
";
