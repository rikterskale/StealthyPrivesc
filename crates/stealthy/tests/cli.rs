use std::process::Command;

fn smoke_plugin() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows.uac"
    } else {
        "linux.kernel_cve"
    }
}

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

#[test]
fn doctor_json_reports_schema_and_checks() {
    let output = stealthy().args(["doctor", "--json"]).output().unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], "1");
    assert!(value["checks"].is_object());
}

#[test]
fn sarif_output_is_valid_sarif_21() {
    let output = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "--format",
            "sarif",
            "scan",
            "--plugins",
            smoke_plugin(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["version"], "2.1.0");
    assert!(value["runs"].is_array());
}

#[test]
fn json_report_contains_identity_and_assessment_metadata() {
    let output = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "--format",
            "json",
            "enum",
            "--plugins",
            smoke_plugin(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value["identity"]["elevation_source"].is_string());
    assert!(value["assessments"].is_array());
    assert_eq!(
        value["assessments"].as_array().unwrap().len(),
        value["findings"].as_array().unwrap().len()
    );
}

#[test]
fn diff_command_compares_offline_json_reports() {
    let dir = tempfile::tempdir().unwrap();
    let baseline_path = dir.path().join("baseline.json");
    let current_path = dir.path().join("current.json");
    for path in [&baseline_path, &current_path] {
        let output = stealthy()
            .args([
                "--authorized",
                "--quiet",
                "--format",
                "json",
                "enum",
                "--plugins",
                smoke_plugin(),
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        std::fs::write(path, output.stdout).unwrap();
    }
    let output = stealthy()
        .args([
            "diff",
            baseline_path.to_str().unwrap(),
            current_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["added"].as_array().unwrap().len(), 0);
    assert_eq!(value["removed"].as_array().unwrap().len(), 0);
    assert_eq!(value["changed"].as_array().unwrap().len(), 0);
}

#[test]
fn unknown_plugin_ids_fail_with_actionable_error() {
    let output = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "enum",
            "--plugins",
            "not.a.real.plugin",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown plugin ID"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("list-plugins"));
}
