use crate::core::plugin::Plugin;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

/// All plugins compiled into this binary (OS-filtered at runtime too).
pub fn registry() -> Vec<&'static dyn Plugin> {
    let mut out: Vec<&'static dyn Plugin> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        out.extend(linux::plugins());
    }

    #[cfg(target_os = "windows")]
    {
        out.extend(windows::plugins());
    }

    out
}
