use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    #[default]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    #[default]
    Enumeration,
    Misconfiguration,
    Credential,
    Recommendation,
    /// An allowlisted capability or workflow that is present but does not
    /// execute a probe or payload in this build.
    Scaffold,
    ExploitAttempt,
}

impl FindingKind {
    /// Whether a finding describes an observed result rather than a suggestion
    /// to run or review another check.
    pub fn is_positive(self) -> bool {
        !matches!(self, Self::Recommendation | Self::Scaffold)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub plugin: String,
    pub kind: FindingKind,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// Operator-facing "what's next" guidance (no automatic exploit).
    pub recommendation: String,
    /// True when acting on this finding may generate EDR/audit noise or artifacts.
    pub noisy: bool,
    /// True when exploitation could leave persistent artifacts.
    pub leaves_artifacts: bool,
    /// Stable fingerprint across runs (schema v2).
    #[serde(default)]
    pub finding_id: String,
    /// Observed object (path, privilege name, rule, …).
    #[serde(default)]
    pub object: String,
    /// Short condition key for fingerprinting.
    #[serde(default)]
    pub condition: String,
    /// Heuristic exploitability score 0–100.
    #[serde(default)]
    pub exploitability: u8,
    /// Rough operator time-to-impact hint.
    #[serde(default)]
    pub time_to_impact: String,
    /// Rank within the run's attack-path list, when assigned.
    #[serde(default)]
    pub attack_path_rank: Option<u32>,
    /// MITRE ATT&CK technique IDs.
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
    /// Internal technique catalog ID.
    #[serde(default)]
    pub technique_id: String,
}

impl Default for Finding {
    fn default() -> Self {
        Self {
            plugin: String::new(),
            kind: FindingKind::Enumeration,
            severity: Severity::Info,
            title: String::new(),
            detail: String::new(),
            recommendation: String::new(),
            noisy: false,
            leaves_artifacts: false,
            finding_id: String::new(),
            object: String::new(),
            condition: String::new(),
            exploitability: 0,
            time_to_impact: String::new(),
            attack_path_rank: None,
            mitre_techniques: Vec::new(),
            technique_id: String::new(),
        }
    }
}

impl Finding {
    /// Return the operator action associated with this finding.
    ///
    /// `recommendation` remains the serialized field name for report
    /// compatibility; the human-facing contract is explicitly "What's next".
    pub fn what_next(&self) -> &str {
        &self.recommendation
    }

    /// Return a concrete, read-only follow-up command for the operator.
    ///
    /// These commands validate or collect context for a finding. They do not
    /// perform privilege escalation, write persistence, or modify the host.
    #[cfg(feature = "opsec-string-strip")]
    pub fn next_command(&self) -> String {
        "Consult the approved operator runbook for a read-only validation command.".into()
    }

    #[cfg(not(feature = "opsec-string-strip"))]
    pub fn next_command(&self) -> String {
        if self.technique_id == "endpoint-bypass" || self.condition.starts_with("endpoint-bypass") {
            let allowed =
                self.condition == "endpoint-bypass-opted-in" || self.title.contains("opted in");
            let artifact =
                (!self.object.is_empty() && self.object != "none").then_some(self.object.as_str());
            let windows = self.plugin.contains("windows");
            return crate::exploit::endpoint_bypass_next_command(allowed, artifact, windows);
        }
        let command = match self.plugin.as_str() {
            "linux.sudo" => "sudo -n -l",
            "linux.suid" => {
                "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -ls 2>/dev/null"
            }
            "linux.systemd_cron" => {
                "systemctl list-timers --all; find /etc/cron* -maxdepth 2 -type f -writable -print 2>/dev/null"
            }
            "linux.containers" => {
                "id; stat -c '%A %U:%G %n' /run/docker.sock /run/podman/podman.sock 2>/dev/null"
            }
            "linux.groups" => "id; getent group",
            "linux.polkit" => "pkaction --verbose 2>/dev/null",
            "linux.mounts" => {
                "findmnt -o TARGET,FSTYPE,OPTIONS; test -w /etc/passwd && echo '/etc/passwd writable'"
            }
            "linux.ssh_keys" => {
                "find \"$HOME/.ssh\" -maxdepth 2 -type f \\( -name 'id_*' -o -name authorized_keys \\) -readable -print 2>/dev/null"
            }
            "linux.path_ld" => "printf '%s\\n' \"$PATH\"; env | grep -E '^(LD_|PATH=)'",
            "linux.kernel_cve" => "uname -a; cat /etc/os-release",
            "linux.nfs" => "findmnt -t nfs,nfs4 -o TARGET,OPTIONS; cat /etc/exports 2>/dev/null",
            "linux.credentials" => {
                "find /etc /var/backups -maxdepth 3 -type f -readable \\( -name shadow -o -name '*passwd*' -o -name '*.bak' \\) -print 2>/dev/null"
            }
            "linux.services" => {
                "systemctl list-unit-files --type=service --no-pager; find /etc/systemd /etc/init.d -type f -writable -print 2>/dev/null"
            }
            "linux.wildcard_cron" => {
                "grep -RInE '(^|[[:space:]])(tar|chown|chmod|rsync|cp|mv)[[:space:]].*\\*' /etc/cron* /var/spool/cron 2>/dev/null"
            }
            "linux.endpoint_controls" => {
                "findmnt -o TARGET,OPTIONS; command -v aa-status >/dev/null && aa-status; command -v getenforce >/dev/null && getenforce"
            }
            "linux.app_control" => {
                "stealthy --authorized enum --plugins linux.app_control --artifact /approved/test/artifact"
            }
            "windows.privileges" => "whoami /priv",
            "windows.services" => {
                "Get-CimInstance Win32_Service | Select-Object Name,StartName,PathName,State"
            }
            "windows.scheduled_tasks" => "schtasks.exe /query /fo LIST /v",
            "windows.always_install_elevated" => {
                "reg.exe query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated & reg.exe query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"
            }
            "windows.uac" => {
                "reg.exe query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
            }
            "windows.dll_hijack" => "Get-Process | Select-Object Id,ProcessName,Path",
            "windows.credentials" => {
                "Get-ChildItem C:\\Windows\\Panther,C:\\Windows\\System32\\sysprep -Recurse -File -ErrorAction SilentlyContinue"
            }
            "windows.admin_sessions" => "whoami /groups & quser",
            "windows.env_path" => {
                "$env:Path -split ';'; [Environment]::GetEnvironmentVariable('Path','Machine')"
            }
            "windows.autoruns" => {
                "reg.exe query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run & reg.exe query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            }
            "windows.endpoint_controls" => {
                "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue; reg.exe query HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy"
            }
            "windows.app_control" => {
                "stealthy --authorized enum --plugins windows.app_control --artifact C:\\approved\\test\\artifact.exe"
            }
            "allow_techniques" => {
                if self.technique_id == "endpoint-bypass"
                    || self.condition.starts_with("endpoint-bypass")
                    || self.title.contains("endpoint-bypass")
                {
                    let allowed = self.condition == "endpoint-bypass-opted-in"
                        || self.title.contains("opted in");
                    let artifact = (!self.object.is_empty() && self.object != "none")
                        .then_some(self.object.as_str());
                    return crate::exploit::endpoint_bypass_next_command(allowed, artifact, false);
                }
                return self
                    .recommendation
                    .split("--allow-techniques")
                    .nth(1)
                    .and_then(|rest| rest.split_whitespace().next())
                    .map(|id| {
                        format!(
                            "stealthy --authorized --format json enum --allow-techniques {id}"
                        )
                    })
                    .unwrap_or_else(|| {
                        "Review the approved technique in the ROE; no payload command is available in this build.".into()
                    });
            }
            _ => {
                return format!(
                    "stealthy --authorized --format json enum --plugins {}",
                    self.plugin
                )
            }
        };
        command.into()
    }

    /// Keep plugins from silently producing positive findings without an
    /// operator hand-off. The engine supplies a safe fallback if a future
    /// plugin forgets to populate the field.
    pub fn needs_next_step(&self) -> bool {
        self.kind.is_positive() && self.what_next().trim().is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsInfo {
    pub family: String,
    pub os: String,
    pub arch: String,
    pub version_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub rank: u32,
    pub title: String,
    pub summary: String,
    pub finding_ids: Vec<String>,
    pub estimated_noise: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageDecision {
    pub finding_id: String,
    pub action: String,
}

/// Read-only inventory of controls that can affect code execution.
///
/// These records deliberately describe observed state and expected evidence.
/// They do not contain bypass instructions or execute the inspected artifact.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ControlAssessment {
    pub platform: String,
    #[serde(default)]
    pub collection_mode: String,
    #[serde(default)]
    pub collected_at_unix: u64,
    #[serde(default)]
    pub artifact: Option<ArtifactAssessment>,
    #[serde(default)]
    pub policies: Vec<PolicyControl>,
    #[serde(default)]
    pub sensors: Vec<SensorInventory>,
    #[serde(default)]
    pub audit_sources: Vec<AuditSource>,
    #[serde(default)]
    pub telemetry_expectations: Vec<TelemetryExpectation>,
    #[serde(default)]
    pub live_telemetry_score: u8,
    #[serde(default)]
    pub live_telemetry_label: String,
    /// 0-100 preflight expectation based on behavior classes, not a stealth score.
    #[serde(default)]
    pub detection_exposure: u8,
    #[serde(default)]
    pub detection_exposure_label: String,
    #[serde(default)]
    pub validation_cases: Vec<ValidationCase>,
    #[serde(default)]
    pub approved_deployment: Vec<DeploymentGuidance>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidationResult {
    pub case_id: String,
    pub status: String,
    pub executed: bool,
    pub fixture_root: String,
    #[serde(default)]
    pub observations: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub expected_telemetry: Vec<String>,
    /// Measured coverage of the expected telemetry sources for this case.
    #[serde(default)]
    pub telemetry_score: u8,
    #[serde(default)]
    pub telemetry_label: String,
    #[serde(default)]
    pub observed_telemetry: Vec<String>,
    #[serde(default)]
    pub event_correlation: Vec<String>,
    #[serde(default)]
    pub stop_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ControlValidationReport {
    pub schema_version: String,
    pub tool: String,
    pub platform: String,
    pub started_at_unix: u64,
    pub case_filter: String,
    pub execute_requested: bool,
    pub fixtures_cleaned: bool,
    pub assessment: ControlAssessment,
    pub results: Vec<ValidationResult>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyControl {
    pub name: String,
    pub family: String,
    pub state: String,
    pub mode: String,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
    pub impact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArtifactAssessment {
    pub path: String,
    pub kind: String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub package: String,
    #[serde(default)]
    pub signer: String,
    #[serde(default)]
    pub signature_status: String,
    #[serde(default)]
    pub integrity_status: String,
    #[serde(default)]
    pub mount_options: String,
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub publisher: String,
    #[serde(default)]
    pub product: String,
    #[serde(default)]
    pub file_version: String,
    #[serde(default)]
    pub original_filename: String,
    #[serde(default)]
    pub catalog_signature: String,
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub policy_rule: String,
    #[serde(default)]
    pub path_class: String,
    #[serde(default)]
    pub access_control: String,
    #[serde(default)]
    pub static_analysis: Vec<String>,
    pub predicted_decision: String,
    pub rationale: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SensorInventory {
    pub product: String,
    pub identity: String,
    pub health: String,
    pub protection_mode: String,
    pub tamper_protection: String,
    pub policy_version: String,
    pub last_update: String,
    pub management_scope: String,
    pub special_group: String,
    pub log_retrieval: String,
    #[serde(default)]
    pub prevention_rules: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditSource {
    pub source: String,
    pub available: String,
    pub correlation: String,
    #[serde(default)]
    pub recent_events: u32,
    #[serde(default)]
    pub recent_denials: u32,
    #[serde(default)]
    pub correlated_artifact_events: u32,
    #[serde(default)]
    pub last_event: String,
    #[serde(default)]
    pub snapshot_sha256: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelemetryExpectation {
    pub behavior: String,
    pub expected_telemetry: String,
    pub exposure: String,
    pub read_only_validation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidationCase {
    pub id: String,
    pub platform: String,
    pub objective: String,
    pub setup: String,
    pub expected_observation: String,
    pub destructive: bool,
    pub execute_artifact: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeploymentGuidance {
    pub channel: String,
    pub requirements: String,
    pub verification: String,
    pub stop_condition: String,
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
    /// Execution path used to collect this report (`binary` or a named fallback).
    #[serde(default)]
    pub execution_path: String,
    /// Primary executable launch outcome (`not_applicable`, `ok`, or `blocked`).
    #[serde(default)]
    pub primary_launch: String,
    /// ROE/reference carried by an approved dispatcher manifest, when present.
    #[serde(default)]
    pub roe_ref: String,
    /// Engagement / OPSEC profile used for this run.
    #[serde(default)]
    pub profile: String,
    /// `native` for the Rust engine or `script` for a fallback report.
    #[serde(default = "default_coverage_mode")]
    pub coverage_mode: String,
    /// Plugin IDs missing relative to a full binary run (script mode).
    #[serde(default)]
    pub capability_delta: Vec<String>,
    /// Structured, read-only policy and telemetry assessment.
    #[serde(default)]
    pub control_assessment: Option<ControlAssessment>,
    pub os: OsInfo,
    pub identity: IdentityInfo,
    pub findings: Vec<Finding>,
    /// Machine-readable assessment metadata aligned by finding index.
    #[serde(default)]
    pub assessments: Vec<FindingAssessment>,
    /// Ranked operator attack paths derived from findings.
    #[serde(default)]
    pub attack_paths: Vec<AttackPath>,
    /// Recorded triage decisions for this run, when present.
    #[serde(default)]
    pub triage_decisions: Vec<TriageDecision>,
    pub plugins_run: Vec<String>,
    pub coverage: Vec<PluginCoverage>,
    pub notes: Vec<String>,
}

fn default_coverage_mode() -> String {
    "native".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingAssessment {
    pub finding_index: usize,
    pub confidence: String,
    pub applicability: String,
    pub evidence_quality: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginCoverage {
    pub id: String,
    pub status: String,
    pub findings: usize,
    pub error: Option<String>,
    #[serde(default)]
    pub duration_ms: u128,
}
