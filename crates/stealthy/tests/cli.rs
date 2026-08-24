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

fn stealthy_in(dir: &std::path::Path) -> Command {
    let mut command = stealthy();
    command.current_dir(dir);
    command
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
    let key_path = dir.path().join("findings.key");
    let output = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "--output",
            "file",
            "--output-path",
            path.to_str().unwrap(),
            "--key-output-path",
            key_path.to_str().unwrap(),
            "enum",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(path.is_file());
    assert!(key_path.is_file());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("decrypt key"));
    let reopened = stealthy()
        .args([
            "report",
            path.to_str().unwrap(),
            "--key-file",
            key_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(reopened.status.success());
    let report: serde_json::Value = serde_json::from_slice(&reopened.stdout).unwrap();
    assert_eq!(report["schema_version"], "2");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let key_mode = std::fs::metadata(key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_mode, 0o600);
    }
}

#[test]
fn encrypted_file_output_requires_protected_key_sink() {
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
            "--plugins",
            smoke_plugin(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--key-output-path"));
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
fn application_control_assessment_is_registered_and_structured() {
    let output = stealthy()
        .args(["--authorized", "list-plugins", "--tsv"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = if cfg!(target_os = "windows") {
        "windows.app_control"
    } else {
        "linux.app_control"
    };
    assert!(stdout.lines().any(|line| line.starts_with(expected)));
}

#[test]
fn control_assessment_skipped_when_app_control_not_selected() {
    let plugin = if cfg!(target_os = "windows") {
        "windows.uac"
    } else {
        "linux.groups"
    };
    let output = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "--format",
            "json",
            "enum",
            "--plugins",
            plugin,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        value["control_assessment"].is_null(),
        "expected null control_assessment, got {}",
        value["control_assessment"]
    );
    let notes = value["notes"].as_array().cloned().unwrap_or_default();
    assert!(
        notes.iter().any(|note| {
            note.as_str()
                .unwrap_or_default()
                .contains("control_assessment skipped")
        }),
        "missing skip note in {notes:?}"
    );
}

#[test]
fn application_control_report_has_read_only_artifact_and_telemetry_data() {
    let artifact = std::env::current_exe().unwrap();
    let plugin = if cfg!(target_os = "windows") {
        "windows.app_control"
    } else {
        "linux.app_control"
    };
    let output = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "--format",
            "json",
            "enum",
            "--plugins",
            plugin,
            "--artifact",
            artifact.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let assessment = &value["control_assessment"];
    assert!(assessment["policies"].as_array().unwrap().len() >= 4);
    assert!(
        assessment["telemetry_expectations"]
            .as_array()
            .unwrap()
            .len()
            >= 7
    );
    assert!(assessment["detection_exposure"].as_u64().unwrap() > 0);
    assert!(assessment["detection_exposure_label"].is_string());
    assert!(assessment["validation_cases"]
        .as_array()
        .unwrap()
        .iter()
        .all(|case| { case["destructive"] == false && case["execute_artifact"] == false }));
    assert_eq!(assessment["artifact"]["sha256"].as_str().unwrap().len(), 64);
    assert!(assessment["artifact"]["predicted_decision"].is_string());
}

#[test]
fn controls_command_runs_fixture_validation_without_execution() {
    let output = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "--format",
            "json",
            "controls",
            "--case",
            if cfg!(target_os = "windows") {
                "hash-drift"
            } else {
                "integrity-drift"
            },
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["execute_requested"], false);
    assert_eq!(value["fixtures_cleaned"], true);
    assert_eq!(value["results"].as_array().unwrap().len(), 1);
    assert!(value["results"][0]["observations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|observation| observation.as_str().unwrap_or_default().contains("sha256")));
    assert!(value["results"][0]["telemetry_label"]
        .as_str()
        .unwrap_or_default()
        .starts_with("measured-"));
}

#[test]
fn live_controls_collects_host_state_without_fixtures() {
    let output = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "--format",
            "json",
            "live-controls",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["collection_mode"], "live-read-only");
    assert!(value["policies"].as_array().is_some());
    assert!(value["audit_sources"].as_array().is_some());
    assert!(value["live_telemetry_label"]
        .as_str()
        .unwrap_or_default()
        .starts_with("live-"));
}

#[cfg(not(feature = "enum-only"))]
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
            && f["kind"] == "scaffold"
            && f["title"]
                .as_str()
                .unwrap_or_default()
                .contains("Kernel exploit execution opted in")
    }));
}

#[cfg(not(feature = "enum-only"))]
#[test]
fn endpoint_bypass_wires_next_command_to_validation() {
    let artifact = tempfile::NamedTempFile::new().unwrap();
    let artifact_path = artifact.path().display().to_string();
    let output = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "--format",
            "json",
            "--artifact",
            &artifact_path,
            "enum",
            "--allow-techniques",
            "endpoint-bypass",
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
    let notes = value["notes"].as_array().unwrap();
    assert!(notes.iter().any(|n| n
        .as_str()
        .unwrap_or_default()
        .contains("endpoint-bypass wires")));
    let findings = value["findings"].as_array().unwrap();
    let bypass = findings
        .iter()
        .find(|f| {
            f["plugin"] == "allow_techniques"
                && f["technique_id"].as_str() == Some("endpoint-bypass")
        })
        .expect("endpoint-bypass allow_techniques finding");
    assert_eq!(bypass["object"].as_str(), Some(artifact_path.as_str()));
    let next = bypass["next_command"].as_str().unwrap_or_default();
    assert!(
        next.contains("live-controls") && next.contains(&artifact_path),
        "next_command={next}"
    );
    let what_next = bypass["what_next"].as_str().unwrap_or_default();
    assert!(what_next.contains("controls --execute"));
    assert!(
        what_next.contains("Never disable")
            || what_next.contains("never disable")
            || what_next.contains("Never disable/unhook")
    );
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
fn equals_form_global_overrides_are_honored() {
    let output = stealthy()
        .args([
            "--authorized",
            "--profile=ci",
            "--format=markdown",
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
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("# StealthyPrivesc report"));
    assert!(stdout.contains("Profile:** ci"));
}

#[test]
fn memory_only_run_does_not_create_artifact_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let output = stealthy_in(dir.path())
        .args([
            "--authorized",
            "--quiet",
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
    assert!(!dir.path().join(".cache-run").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn linux_direct_fallbacks_require_authorization() {
    let scripts = [
        ("bash", "scripts/linux/enum.sh"),
        ("python3", "scripts/linux/enum.py"),
        ("sh", "scripts/linux/enum-posix.sh"),
        ("perl", "scripts/linux/enum.pl"),
    ];
    for (interpreter, script) in scripts {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(script);
        if !path.is_file() {
            continue;
        }
        let Ok(output) = std::process::Command::new(interpreter)
            .arg(&path)
            .arg("--json")
            .env_remove("STEALTHY_AUTHORIZED")
            .output()
        else {
            continue;
        };
        assert_eq!(output.status.code(), Some(2), "{interpreter} {script}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("Authorization required"));
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
    let dispatcher = out.join("scripts/run.sh");
    assert!(dispatcher.is_file());
    let manifest = std::fs::read_to_string(out.join("scripts/stealthy-run.conf")).unwrap();
    assert!(manifest.contains("authorization_ack=true"));
    assert!(manifest.contains("operator_ack_required=true"));
    assert!(manifest.contains("primary_binary=cache-update"));
    assert!(manifest.contains("linux_fallbacks=python,bash,sh,perl"));
    assert!(out.join("scripts/enum-posix.sh").is_file());
    assert!(out.join("scripts/enum.pl").is_file());
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

#[cfg(unix)]
#[test]
fn stage_output_must_be_empty() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("drop");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("preexisting.txt"), b"keep me").unwrap();
    let bin = dir.path().join("fakebin");
    std::fs::write(&bin, b"stealthy-fake").unwrap();
    let output = stealthy()
        .args([
            "stage",
            "--os",
            "linux",
            "--out",
            out.to_str().unwrap(),
            "--binary",
            bin.to_str().unwrap(),
            "--ledger-dir",
            dir.path().join("ledger").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must be empty"));
    assert!(out.join("preexisting.txt").is_file());
}

#[cfg(unix)]
#[test]
fn staged_dispatcher_requires_fresh_authorization() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("drop");
    let bin = dir.path().join("fakebin");
    std::fs::write(&bin, b"#!/bin/sh\nexit 0\n").unwrap();
    let mut perms = std::fs::metadata(&bin).unwrap().permissions();
    perms.set_mode(0o750);
    std::fs::set_permissions(&bin, perms).unwrap();
    let ledger = dir.path().join("ledger");
    let stage = stealthy()
        .args([
            "stage",
            "--os",
            "linux",
            "--out",
            out.to_str().unwrap(),
            "--binary",
            bin.to_str().unwrap(),
            "--ledger-dir",
            ledger.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(stage.status.success());
    let dispatcher = out.join("scripts/run.sh");
    let output = std::process::Command::new("bash")
        .arg(dispatcher)
        .env_remove("STEALTHY_AUTHORIZED")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Authorization required"));
}

#[cfg(unix)]
#[test]
fn stage_windows_manifest_lists_script_hosts() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("drop");
    let bin = dir.path().join("fakebin.exe");
    std::fs::write(&bin, b"MZ-fake").unwrap();
    let output = stealthy()
        .args([
            "stage",
            "--os",
            "windows",
            "--arch",
            "x86_64",
            "--name",
            "stealthy",
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
    let manifest = std::fs::read_to_string(out.join("scripts/stealthy-run.conf")).unwrap();
    assert!(manifest.contains("windows_fallbacks=powershell,jscript,msbuild"));
    assert!(out.join("scripts/run.ps1").is_file());
    assert!(out.join("scripts/enum.ps1").is_file());
    assert!(out.join("scripts/enum.js").is_file());
    assert!(out.join("scripts/EnumTasks.csproj").is_file());
}

#[cfg(unix)]
#[test]
fn dispatcher_falls_back_when_primary_exits_126() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("drop");
    let bin = dir.path().join("fakebin");
    std::fs::write(&bin, b"#!/bin/sh\nexit 126\n").unwrap();
    let mut perms = std::fs::metadata(&bin).unwrap().permissions();
    perms.set_mode(0o750);
    std::fs::set_permissions(&bin, perms).unwrap();
    let ledger = dir.path().join("ledger");
    let stage = stealthy()
        .args([
            "stage",
            "--os",
            "linux",
            "--out",
            out.to_str().unwrap(),
            "--binary",
            bin.to_str().unwrap(),
            "--ledger-dir",
            ledger.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(stage.status.success());

    let output = std::process::Command::new("bash")
        .arg(out.join("scripts/run.sh"))
        .arg("--authorized")
        .arg("--json")
        .env("STEALTHY_AUTHORIZED", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stderr={stderr}\nstdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(stderr.contains("primary launch blocked"));
    assert!(
        stderr.contains("trying approved python fallback")
            || stderr.contains("trying approved bash fallback")
            || stderr.contains("trying approved sh fallback")
            || stderr.contains("trying approved perl fallback"),
        "stderr={stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"coverage_mode\"") || stdout.contains("schema_version"),
        "stdout={stdout}"
    );
}

#[cfg(unix)]
#[test]
fn dispatcher_chains_past_blocked_first_fallback() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("drop");
    let bin = dir.path().join("fakebin");
    std::fs::write(&bin, b"#!/bin/sh\nexit 126\n").unwrap();
    let mut perms = std::fs::metadata(&bin).unwrap().permissions();
    perms.set_mode(0o750);
    std::fs::set_permissions(&bin, perms).unwrap();
    let ledger = dir.path().join("ledger");
    let stage = stealthy()
        .args([
            "stage",
            "--os",
            "linux",
            "--out",
            out.to_str().unwrap(),
            "--binary",
            bin.to_str().unwrap(),
            "--ledger-dir",
            ledger.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(stage.status.success());

    // Force python tier to look available but blocked so the chain continues.
    std::fs::write(
        out.join("scripts/enum.py"),
        "#!/usr/bin/env python3\nimport sys\nsys.exit(126)\n",
    )
    .unwrap();
    let mut py_perms = std::fs::metadata(out.join("scripts/enum.py"))
        .unwrap()
        .permissions();
    py_perms.set_mode(0o750);
    std::fs::set_permissions(out.join("scripts/enum.py"), py_perms).unwrap();

    let conf = out.join("scripts/stealthy-run.conf");
    let mut manifest = std::fs::read_to_string(&conf).unwrap();
    manifest = manifest
        .lines()
        .map(|line| {
            if line.starts_with("linux_fallbacks=") {
                "linux_fallbacks=python,bash".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    if !manifest.ends_with('\n') {
        manifest.push('\n');
    }
    std::fs::write(&conf, manifest).unwrap();

    let output = std::process::Command::new("bash")
        .arg(out.join("scripts/run.sh"))
        .arg("--authorized")
        .env("STEALTHY_AUTHORIZED", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stderr={stderr}\nstdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("trying approved python fallback"),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains("python fallback blocked") && stderr.contains("trying next host"),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains("trying approved bash fallback"),
        "stderr={stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("StealthyPrivesc Linux shell enum") || stdout.contains("LEGAL"),
        "stdout={stdout}"
    );
}

#[cfg(unix)]
#[test]
fn dispatcher_falls_back_on_signal_death() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("drop");
    let bin = dir.path().join("fakebin");
    // 137 = 128 + SIGKILL — treated as primary blocked.
    std::fs::write(&bin, b"#!/bin/sh\nkill -9 $$\n").unwrap();
    let mut perms = std::fs::metadata(&bin).unwrap().permissions();
    perms.set_mode(0o750);
    std::fs::set_permissions(&bin, perms).unwrap();
    let ledger = dir.path().join("ledger");
    let stage = stealthy()
        .args([
            "stage",
            "--os",
            "linux",
            "--out",
            out.to_str().unwrap(),
            "--binary",
            bin.to_str().unwrap(),
            "--ledger-dir",
            ledger.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(stage.status.success());

    let output = std::process::Command::new("bash")
        .arg(out.join("scripts/run.sh"))
        .arg("--authorized")
        .arg("--json")
        .env("STEALTHY_AUTHORIZED", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stderr={stderr}\nstdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(stderr.contains("primary launch blocked"), "stderr={stderr}");
}

#[cfg(unix)]
#[test]
fn cleanup_removes_staged_directory_recursively() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("drop");
    let bin = dir.path().join("fakebin");
    std::fs::write(&bin, b"stealthy-fake").unwrap();
    let ledger = dir.path().join("ledger");
    let stage = stealthy()
        .args([
            "stage",
            "--os",
            "linux",
            "--out",
            out.to_str().unwrap(),
            "--binary",
            bin.to_str().unwrap(),
            "--ledger-dir",
            ledger.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(stage.status.success());
    assert!(out.is_dir());
    let cleanup = stealthy()
        .args([
            "--ledger-dir",
            ledger.to_str().unwrap(),
            "cleanup",
            "--latest",
        ])
        .output()
        .unwrap();
    assert!(
        cleanup.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&cleanup.stderr)
    );
    assert!(!out.exists());
    assert!(!ledger.exists() || std::fs::read_dir(&ledger).unwrap().next().is_none());
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
fn approval_file_requires_same_run_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let decisions = dir.path().join("decisions.json");
    std::fs::write(
        &decisions,
        r#"{"schema_version":"1","run_id":"not-a-checkpoint-run","decisions":[]}"#,
    )
    .unwrap();
    let output = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "--format",
            "json",
            "enum",
            "--approve-file",
            decisions.to_str().unwrap(),
            "--plugins",
            smoke_plugin(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires --checkpoint"));
}

#[cfg(all(unix, not(feature = "enum-only")))]
#[test]
fn auto_exploit_probes_each_reversible_candidate() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    std::fs::create_dir_all(&first).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::fs::set_permissions(&second, std::fs::Permissions::from_mode(0o777)).unwrap();
    let path_value = format!("{}:{}", first.display(), second.display());

    let output = stealthy()
        .env("PATH", path_value)
        .args([
            "--authorized",
            "--quiet",
            "--format",
            "json",
            "--plugin-timeout-ms",
            "0",
            "enum",
            "--auto-exploit",
            "--plugins",
            "linux.path_ld",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let confirmed = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["kind"] == "exploit_attempt")
        .collect::<Vec<_>>();
    assert_eq!(confirmed.len(), 2, "findings={}", report["findings"]);
}

#[cfg(all(unix, not(feature = "enum-only")))]
#[test]
fn approve_file_probes_only_the_selected_finding() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    std::fs::create_dir_all(&first).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::fs::set_permissions(&second, std::fs::Permissions::from_mode(0o777)).unwrap();
    let path_value = format!("{}:{}", first.display(), second.display());
    let checkpoint = dir.path().join("checkpoint.json");

    let baseline = stealthy()
        .env("PATH", &path_value)
        .args([
            "--authorized",
            "--quiet",
            "--format",
            "json",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
            "--plugin-timeout-ms",
            "0",
            "enum",
            "--plugins",
            "linux.path_ld",
        ])
        .output()
        .unwrap();
    assert!(baseline.status.success());
    let prior: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&checkpoint).unwrap()).unwrap();
    let candidates = prior["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| {
            finding["plugin"] == "linux.path_ld"
                && finding["title"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("World-writable PATH entry")
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 2);
    assert_ne!(candidates[0]["finding_id"], candidates[1]["finding_id"]);
    let approved = candidates
        .iter()
        .find(|finding| finding["object"] == first.to_string_lossy().as_ref())
        .unwrap();
    let decisions = dir.path().join("decisions.json");
    std::fs::write(
        &decisions,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "1",
            "run_id": prior["run_id"],
            "decisions": [{
                "finding_id": approved["finding_id"],
                "action": "probe"
            }]
        }))
        .unwrap(),
    )
    .unwrap();

    let resumed = stealthy()
        .env("PATH", &path_value)
        .args([
            "--authorized",
            "--quiet",
            "--format",
            "json",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
            "--plugin-timeout-ms",
            "0",
            "enum",
            "--approve-file",
            decisions.to_str().unwrap(),
            "--plugins",
            "linux.path_ld",
        ])
        .output()
        .unwrap();
    assert!(
        resumed.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&resumed.stdout).unwrap();
    let confirmed = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["kind"] == "exploit_attempt")
        .collect::<Vec<_>>();
    assert_eq!(confirmed.len(), 1, "findings={}", report["findings"]);
    assert_eq!(confirmed[0]["object"], first.to_string_lossy().as_ref());
}

#[cfg(feature = "enum-only")]
#[test]
fn enum_only_build_rejects_probe_flags() {
    let output = stealthy()
        .args([
            "--authorized",
            "--quiet",
            "enum",
            "--auto-exploit",
            "--plugins",
            smoke_plugin(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("enum-only"));
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
