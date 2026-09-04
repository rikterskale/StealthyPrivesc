use rand::Rng;
use std::thread;
use std::time::Duration;

/// Low-and-slow helper: sleep a randomized fraction of `budget_ms`.
///
/// WARNING: Excessive delays can still look anomalous if the process holds
/// unusual handles; keep budgets small by default.
pub fn low_and_slow(budget_ms: u64) {
    if budget_ms == 0 {
        return;
    }
    let mut rng = rand::thread_rng();
    let jitter = rng.gen_range(0..=budget_ms);
    if jitter > 0 {
        thread::sleep(Duration::from_millis(jitter));
    }
}

/// Operator-facing note: string literals in this binary are not heavily obfuscated
/// in v1 (readability > extreme obfuscation per project constraints). Release
/// builds should still strip symbols (`strip = true` in Cargo.toml).
pub fn evasion_notes() -> Vec<String> {
    vec![
        "Prefer /proc and direct file reads over spawning ps/ss/id where possible.".into(),
        "Avoid cmd.exe /c and powershell.exe child processes for simple identity queries.".into(),
        "control_assessment runs only when linux.app_control / windows.app_control is selected."
            .into(),
        "Use --profile quiet to skip sudo helpers, getcap/getfacl, and slim control collection."
            .into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::{evasion_notes, low_and_slow};

    #[test]
    fn zero_budget_returns_immediately_and_notes_are_actionable() {
        let started = std::time::Instant::now();
        low_and_slow(0);
        assert!(started.elapsed() < std::time::Duration::from_millis(50));
        let notes = evasion_notes();
        assert!(!notes.is_empty());
        assert!(notes.iter().all(|note| !note.trim().is_empty()));
        assert!(notes.iter().any(|note| note.contains("--profile quiet")));
    }
}
