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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub tool: String,
    pub version: String,
    pub authorized_use_ack: bool,
    pub mode: String,
    pub os: OsInfo,
    pub identity: IdentityInfo,
    pub findings: Vec<Finding>,
    pub plugins_run: Vec<String>,
    pub notes: Vec<String>,
}
