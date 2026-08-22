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

impl FindingKind {
    /// Whether a finding describes an observed result rather than a suggestion
    /// to run or review another check.
    pub fn is_positive(self) -> bool {
        !matches!(self, Self::Recommendation)
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
    pub fn next_command(&self) -> String {
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
            "allow_techniques" => {
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
                    .unwrap_or_else(|| "Review the approved technique in the ROE; no payload command is available in this build.".into());
            }
            _ => return format!(
                "stealthy --authorized --format json enum --plugins {}",
                self.plugin
            ),
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
