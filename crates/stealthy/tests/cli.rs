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
fn human_findings_label_the_operator_next_step() {
    let output = stealthy()
        .args([
            "--authorized",
            "--no-color",
            "enum",
            "--plugins",
            smoke_plugin(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("What's next:"),
        "missing next-step label in:\n{stdout}"
    );
    assert!(
        stdout.contains("Command:"),
        "missing next-step command in:\n{stdout}"
    );
}

#[test]
fn json_findings_have_next_step_guidance() {
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
    for finding in value["findings"].as_array().unwrap() {
        if finding["kind"] != "recommendation" {
            assert!(
                !finding["recommendation"]
                    .as_str()
                    .unwrap_or_default()
                    .trim()
                    .is_empty(),
                "positive finding has no next step: {finding}"
            );
        }
        assert!(finding["what_next"].is_string());
        assert!(finding["next_command"].is_string());
    }
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

#[test]
fn unknown_allow_techniques_ids_fail() {
    let output = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "enum",
            "--allow-techniques",
            "not-a-real-technique",
            "--plugins",
            smoke_plugin(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("unknown --allow-techniques"));
}

#[test]
fn endpoint_controls_plugin_is_registered() {
    let output = stealthy()
        .args(["--authorized", "list-plugins", "--tsv"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = if cfg!(target_os = "windows") {
        "windows.endpoint_controls"
    } else {
        "linux.endpoint_controls"
    };
    assert!(
        stdout.lines().any(|line| line.starts_with(expected)),
        "missing {expected} in:\n{stdout}"
    );
}

#[test]
fn allow_techniques_records_scaffold_findings() {
    let output = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "--format",
            "json",
            "enum",
            "--allow-techniques",
            "kernel-exploit,potato",
            "--plugins",
            smoke_plugin(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["mode"], "enumerate+allow-techniques");
    let notes = value["notes"].as_array().unwrap();
    assert!(notes.iter().any(|n| n
        .as_str()
        .unwrap_or_default()
        .contains("ALLOW-TECHNIQUES enabled")));
    let findings = value["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| {
        f["plugin"] == "allow_techniques"
            && f["title"]
                .as_str()
                .unwrap_or_default()
                .contains("Kernel exploit execution opted in")
    }));
}

#[test]
fn profile_ci_emits_json_with_finding_ids_and_attack_paths() {
    let output = stealthy()
        .args([
            "--authorized",
            "--profile",
            "ci",
            "enum",
            "--plugins",
            smoke_plugin(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], "2");
    assert_eq!(value["profile"], "ci");
    assert!(value["attack_paths"].is_array());
    for finding in value["findings"].as_array().unwrap() {
        assert!(finding["finding_id"].as_str().unwrap().len() == 16);
        assert!(finding["mitre_techniques"].is_array());
    }
}

#[test]
fn ingest_enriches_script_fixture() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/script_report_min.json"
    );
    let output = stealthy()
        .args(["ingest", fixture, "--format", "json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["coverage_mode"], "script");
    let findings = value["findings"].as_array().unwrap();
    assert!(!findings.is_empty());
    assert_eq!(findings[0]["finding_id"].as_str().unwrap().len(), 16);
    assert!(findings[0]["mitre_techniques"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t == "T1548.003"));
}

#[test]
fn stage_and_verify_local_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("drop");
    let bin = dir.path().join("fakebin");
    std::fs::write(&bin, b"stealthy-fake").unwrap();
    let output = stealthy()
        .args([
            "stage",
            "--os",
            "linux",
            "--arch",
            "x86_64",
            "--name",
            "cache-update",
            "--out",
            out.to_str().unwrap(),
            "--binary",
            bin.to_str().unwrap(),
            "--ledger-dir",
            dir.path().join("ledger").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let staged = out.join("cache-update");
    assert!(staged.is_file());
    let sums = std::fs::read_to_string(out.join("SHA256SUMS")).unwrap();
    let expect = sums.split_whitespace().next().unwrap();
    let verify = stealthy()
        .args([
            "verify",
            "--path",
            staged.to_str().unwrap(),
            "--expect-sha256",
            expect,
        ])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn one_liners_print_snippets() {
    let output = stealthy()
        .args(["one-liners", "--os", "linux", "--transport", "ssh"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("scp"));
}

#[test]
fn triage_out_writes_decisions_stub() {
    let dir = tempfile::tempdir().unwrap();
    let decisions = dir.path().join("decisions.json");
    let output = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "--format",
            "json",
            "enum",
            "--plugins",
            smoke_plugin(),
            "--triage",
            "--triage-out",
            decisions.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(decisions.is_file());
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&decisions).unwrap()).unwrap();
    assert_eq!(value["schema_version"], "1");
    assert!(value["decisions"].is_array());
}

#[test]
fn checkpoint_and_resume_skips_completed_plugin() {
    let dir = tempfile::tempdir().unwrap();
    let checkpoint = dir.path().join("cp.json");
    let first = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "--format",
            "json",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
            "--plugin-timeout-ms",
            "60000",
            "enum",
            "--plugins",
            smoke_plugin(),
        ])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(checkpoint.is_file());
    let resume = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "--format",
            "json",
            "resume",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
            "--plugins",
            smoke_plugin(),
        ])
        .output()
        .unwrap();
    assert!(
        resume.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&resume.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&resume.stdout).unwrap();
    // coverage should still list the plugin as ok from prior or current
    let coverage = value["coverage"].as_array().unwrap();
    assert!(coverage
        .iter()
        .any(|c| c["id"] == smoke_plugin() && c["status"] == "ok"));
}
