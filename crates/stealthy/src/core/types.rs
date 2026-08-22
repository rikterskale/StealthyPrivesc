use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Enumeration,
    Misconfiguration,
    Credential,
    Recommendation,
    ExploitAttempt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub plugin: String,
    pub kind: FindingKind,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// Operator-facing remediation / next-step guidance (no automatic exploit).
    pub recommendation: String,
    /// True when acting on this finding may generate EDR/audit noise or artifacts.
    pub noisy: bool,
    /// True when exploitation could leave persistent artifacts.
    pub leaves_artifacts: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub username: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub groups: Vec<String>,
    pub is_elevated: bool,
    /// How elevation was determined (for example, a Linux euid or Windows token query).
    #[serde(default)]
    pub elevation_source: String,
    /// Additional token context when the platform exposes it.
    #[serde(default)]
    pub token_context: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub family: String,
    pub os: String,
    pub arch: String,
    pub version_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub schema_version: String,
    #[serde(default)]
    pub run_id: String,
    #[serde(default)]
    pub started_at_unix: u64,
    pub tool: String,
    pub version: String,
    pub authorized_use_ack: bool,
    pub mode: String,
    pub os: OsInfo,
    pub identity: IdentityInfo,
    pub findings: Vec<Finding>,
    /// Machine-readable assessment metadata aligned by finding index.
    #[serde(default)]
    pub assessments: Vec<FindingAssessment>,
    pub plugins_run: Vec<String>,
    pub coverage: Vec<PluginCoverage>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingAssessment {
    pub finding_index: usize,
    pub confidence: String,
    pub applicability: String,
    pub evidence_quality: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCoverage {
    pub id: String,
    pub status: String,
    pub findings: usize,
    pub error: Option<String>,
    #[serde(default)]
    pub duration_ms: u128,
}
