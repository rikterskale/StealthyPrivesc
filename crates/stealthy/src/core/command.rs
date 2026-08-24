//! Process-launch helpers with a fixed, system-only command search path.

use std::process::Command;

#[cfg(unix)]
const TRUSTED_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
#[cfg(windows)]
const TRUSTED_PATH: &str = r"C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem";

pub fn trusted_command(program: &str) -> Command {
    let mut command = Command::new(program);
    command.env("PATH", TRUSTED_PATH);
    command
}
