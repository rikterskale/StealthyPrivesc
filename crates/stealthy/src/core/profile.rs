//! Named engagement / OPSEC profiles.

use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum EngagementProfile {
    Quiet,
    #[default]
    Balanced,
    Thorough,
    Ci,
}

impl EngagementProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quiet => "quiet",
            Self::Balanced => "balanced",
            Self::Thorough => "thorough",
            Self::Ci => "ci",
        }
    }

    pub fn default_delay_ms(self) -> u64 {
        match self {
            Self::Quiet => 250,
            Self::Balanced => 50,
            Self::Thorough | Self::Ci => 0,
        }
    }

    pub fn default_plugin_timeout_ms(self) -> u64 {
        match self {
            Self::Quiet | Self::Balanced => 120_000,
            Self::Thorough | Self::Ci => 60_000,
        }
    }

    pub fn prefer_quiet(self) -> bool {
        matches!(self, Self::Quiet)
    }

    pub fn force_quiet_console(self) -> bool {
        matches!(self, Self::Ci)
    }

    pub fn force_json(self) -> bool {
        matches!(self, Self::Ci)
    }

    pub fn force_verbose(self) -> bool {
        matches!(self, Self::Thorough)
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Quiet => {
                "Low-noise reads; skip sudo helpers/getcap/getfacl; slim control collect; higher delay"
            }
            Self::Balanced => "Default enumerate posture",
            Self::Thorough => "Full plugin set, no delay, verbose progress",
            Self::Ci => "Quiet JSON automation posture",
        }
    }
}
