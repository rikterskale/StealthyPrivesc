use std::process::Command;

fn stealthy() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stealthy"))
}

#[test]
fn refuses_host_commands_without_authorization() {
    let output = stealthy().arg("list-plugins").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Authorization required"));
}

#[test]
fn guide_is_available_without_authorization() {
    let output = stealthy().arg("guide").output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("operator guide"));
}

#[test]
fn authorized_plugin_listing_is_machine_readable() {
    let output = stealthy()
        .args(["--authorized", "list-plugins", "--tsv"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.lines().all(|line| line.split('\t').count() == 3));
    assert!(!stdout.trim().is_empty());
}

#[test]
fn encrypted_file_output_does_not_print_the_key_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("findings.seal");
    let output = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "--output",
            "file",
            "--output-path",
            path.to_str().unwrap(),
            "enum",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(path.is_file());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("decrypt key"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
