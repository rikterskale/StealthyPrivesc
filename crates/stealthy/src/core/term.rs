//! Lightweight terminal styling (no extra crate). Honors NO_COLOR and --no-color.

use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::core::types::Severity;

static COLOR: AtomicBool = AtomicBool::new(false);

pub fn init(force_off: bool) {
    let no_env = std::env::var_os("NO_COLOR").is_some();
    let on = !force_off && !no_env && std::io::stderr().is_terminal();
    // Prefer stdout for report colors when stdout is a TTY.
    let out_on = !force_off && !no_env && std::io::stdout().is_terminal();
    COLOR.store(on || out_on, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    COLOR.load(Ordering::Relaxed)
}

pub fn paint(code: &str, text: &str) -> String {
    if enabled() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn bold(text: &str) -> String {
    paint("1", text)
}

pub fn dim(text: &str) -> String {
    paint("2", text)
}

pub fn red(text: &str) -> String {
    paint("31", text)
}

pub fn green(text: &str) -> String {
    paint("32", text)
}

pub fn yellow(text: &str) -> String {
    paint("33", text)
}

pub fn cyan(text: &str) -> String {
    paint("36", text)
}

pub fn severity_tag(sev: Severity) -> String {
    let label = format!("{:>8}", sev.as_str().to_ascii_uppercase());
    match sev {
        Severity::Critical => paint("1;37;41", &label),
        Severity::High => paint("1;31", &label),
        Severity::Medium => paint("1;33", &label),
        Severity::Low => paint("1;34", &label),
        Severity::Info => paint("1;90", &label),
    }
}

pub fn ok(text: &str) -> String {
    green(text)
}

pub fn warn(text: &str) -> String {
    yellow(text)
}

pub fn err(text: &str) -> String {
    red(text)
}

#[cfg(test)]
mod tests {
    use crate::core::types::Severity;

    #[test]
    fn forced_no_color_keeps_all_helpers_plain() {
        super::init(true);
        assert!(!super::enabled());
        for rendered in [
            super::bold("x"),
            super::dim("x"),
            super::red("x"),
            super::green("x"),
            super::yellow("x"),
            super::cyan("x"),
            super::ok("x"),
            super::warn("x"),
            super::err("x"),
        ] {
            assert_eq!(rendered, "x");
        }
        assert_eq!(super::severity_tag(Severity::High), "    HIGH");
    }
}
