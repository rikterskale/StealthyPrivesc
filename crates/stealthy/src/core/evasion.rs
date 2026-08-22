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
        "Default mode never patches AMSI/ETW; that remains an explicit operator choice in script paths.".into(),
        "Avoid cmd.exe /c and powershell.exe child processes for simple identity queries.".into(),
        "Kernel exploits are disabled in this build.".into(),
    ]
}
