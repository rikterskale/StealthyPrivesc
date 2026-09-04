//! Named engagement / OPSEC profiles.

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoiseBudget {
    pub allow_external_helpers: bool,
    pub max_walk_entries: usize,
    pub max_helper_records: usize,
}

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

    /// Per-plugin worker timeout. `0` runs plugins in-process (no
    /// `__plugin-worker` child). Quiet and balanced default to in-process so a
    /// normal enum does not spawn one extra process per plugin.
    pub fn default_plugin_timeout_ms(self) -> u64 {
        match self {
            Self::Quiet | Self::Balanced => 0,
            Self::Thorough | Self::Ci => 60_000,
        }
    }

    pub fn prefer_quiet(self) -> bool {
        !matches!(self, Self::Thorough)
    }

    pub fn noise_budget(self) -> NoiseBudget {
        match self {
            Self::Quiet => NoiseBudget {
                allow_external_helpers: false,
                max_walk_entries: 2_000,
                max_helper_records: 50,
            },
            Self::Balanced => NoiseBudget {
                allow_external_helpers: false,
                max_walk_entries: 10_000,
                max_helper_records: 200,
            },
            Self::Thorough => NoiseBudget {
                allow_external_helpers: true,
                max_walk_entries: 100_000,
                max_helper_records: 2_000,
            },
            Self::Ci => NoiseBudget {
                allow_external_helpers: false,
                max_walk_entries: 5_000,
                max_helper_records: 100,
            },
        }
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
                "Low-noise reads; skip sudo helpers/getcap/getfacl; slim control collect; higher delay; in-process plugins"
            }
            Self::Balanced => {
                "High-signal read-only checks; in-process plugins; external helper scans require the thorough profile"
            }
            Self::Thorough => {
                "Full plugin set, no delay, verbose progress; isolated plugin workers"
            }
            Self::Ci => "Quiet JSON automation posture; isolated plugin workers",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EngagementProfile;

    #[test]
    fn quiet_and_balanced_default_to_in_process_plugins() {
        assert_eq!(EngagementProfile::Quiet.default_plugin_timeout_ms(), 0);
        assert_eq!(EngagementProfile::Balanced.default_plugin_timeout_ms(), 0);
        assert_eq!(EngagementProfile::default().default_plugin_timeout_ms(), 0);
    }

    #[test]
    fn thorough_and_ci_keep_isolated_workers() {
        assert_eq!(
            EngagementProfile::Thorough.default_plugin_timeout_ms(),
            60_000
        );
        assert_eq!(EngagementProfile::Ci.default_plugin_timeout_ms(), 60_000);
    }
}
