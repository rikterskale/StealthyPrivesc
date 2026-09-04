//! Operator triage decisions for stepwise probe approval.

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::core::types::{Finding, TriageDecision};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageFile {
    pub schema_version: String,
    #[serde(default)]
    pub run_id: String,
    pub decisions: Vec<TriageDecision>,
}

impl TriageFile {
    pub fn empty(run_id: impl Into<String>) -> Self {
        Self {
            schema_version: "1".into(),
            run_id: run_id.into(),
            decisions: Vec::new(),
        }
    }
}

pub fn load_approve_file(path: &Path) -> Result<TriageFile> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read approve file {}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

pub fn write_triage_template(path: &Path, run_id: &str, findings: &[Finding]) -> Result<()> {
    let mut file = TriageFile::empty(run_id);
    for finding in findings.iter().take(12) {
        if finding.severity.rank() < crate::core::types::Severity::Medium.rank() {
            continue;
        }
        file.decisions.push(TriageDecision {
            finding_id: finding.finding_id.clone(),
            action: "defer".into(),
        });
    }
    let body = serde_json::to_string_pretty(&file)?;
    crate::core::artifacts::write_private_atomic(path, body.as_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Prompt on a TTY for each candidate; non-TTY returns empty decisions.
pub fn prompt_tty(run_id: &str, findings: &[Finding]) -> Result<TriageFile> {
    if !io::stdin().is_terminal() {
        return Ok(TriageFile::empty(run_id));
    }
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    prompt_with_io(run_id, findings, &mut stdin.lock(), &mut stdout)
}

fn prompt_with_io<R: BufRead, W: Write>(
    run_id: &str,
    findings: &[Finding],
    input: &mut R,
    output: &mut W,
) -> Result<TriageFile> {
    let mut file = TriageFile::empty(run_id);
    for finding in findings.iter().filter(|f| {
        f.severity.rank() >= crate::core::types::Severity::Medium.rank() && f.kind.is_positive()
    }) {
        writeln!(
            output,
            "\n[{}] {} — {}\n  action? [y=probe, v=validate, n=defer, d=out_of_scope, s=skip]",
            finding.severity.as_str(),
            finding.finding_id,
            finding.title
        )?;
        output.flush()?;
        let mut line = String::new();
        input.read_line(&mut line)?;
        let action = match line.trim().to_ascii_lowercase().as_str() {
            "y" | "probe" => "probe",
            "v" | "validate" => "validate",
            "d" | "out_of_scope" => "out_of_scope",
            "s" | "skip" => continue,
            _ => "defer",
        };
        file.decisions.push(TriageDecision {
            finding_id: finding.finding_id.clone(),
            action: action.into(),
        });
    }
    Ok(file)
}

pub fn probe_ids(decisions: &[TriageDecision]) -> Vec<String> {
    decisions
        .iter()
        .filter(|d| d.action == "probe")
        .map(|d| d.finding_id.clone())
        .collect()
}

pub fn validate_probe_ids(
    decisions: &[TriageDecision],
    findings: &[Finding],
) -> Result<Vec<String>> {
    let known: std::collections::BTreeSet<&str> = findings
        .iter()
        .map(|finding| finding.finding_id.as_str())
        .collect();
    let ids = probe_ids(decisions);
    let unknown: Vec<&str> = ids
        .iter()
        .map(String::as_str)
        .filter(|id| !known.contains(id))
        .collect();
    if !unknown.is_empty() {
        anyhow::bail!(
            "approval file contains unknown probe finding_id(s): {}",
            unknown.join(", ")
        );
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use std::io::{self, BufRead, Cursor, Read, Write};

    use super::{
        load_approve_file, probe_ids, prompt_with_io, validate_probe_ids, write_triage_template,
    };
    use crate::core::types::{Finding, FindingKind, Severity, TriageDecision};

    #[test]
    fn rejects_probe_ids_not_present_in_checkpoint_findings() {
        let findings = vec![Finding {
            finding_id: "known-id".into(),
            plugin: "linux.path_ld".into(),
            kind: FindingKind::Misconfiguration,
            severity: Severity::High,
            ..Default::default()
        }];
        let decisions = vec![TriageDecision {
            finding_id: "unknown-id".into(),
            action: "probe".into(),
        }];
        assert!(validate_probe_ids(&decisions, &findings).is_err());
    }

    #[test]
    fn triage_template_round_trips_only_actionable_findings() {
        let findings = vec![
            Finding {
                finding_id: "low".into(),
                plugin: "linux.sudo".into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Low,
                ..Default::default()
            },
            Finding {
                finding_id: "high".into(),
                plugin: "linux.sudo".into(),
                kind: FindingKind::Misconfiguration,
                severity: Severity::High,
                ..Default::default()
            },
        ];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approve.json");
        write_triage_template(&path, "run-1", &findings).unwrap();
        let loaded = load_approve_file(&path).unwrap();
        assert_eq!(loaded.run_id, "run-1");
        assert_eq!(loaded.decisions.len(), 1);
        assert!(probe_ids(&loaded.decisions).is_empty());
    }

    fn candidate(id: &str) -> Finding {
        Finding {
            finding_id: id.into(),
            title: format!("candidate {id}"),
            plugin: "linux.sudo".into(),
            kind: FindingKind::Misconfiguration,
            severity: Severity::High,
            ..Default::default()
        }
    }

    #[test]
    fn interactive_triage_maps_every_choice_and_alias() {
        let findings: Vec<Finding> = (0..10)
            .map(|index| candidate(&format!("f{index}")))
            .collect();
        let mut input = Cursor::new(
            b"y\nprobe\nv\nvalidate\nd\nout_of_scope\ns\nskip\nn\nunrecognized\n".to_vec(),
        );
        let mut output = Vec::new();

        let file = prompt_with_io("run-interactive", &findings, &mut input, &mut output).unwrap();

        assert_eq!(file.schema_version, "1");
        assert_eq!(file.run_id, "run-interactive");
        assert_eq!(
            file.decisions
                .iter()
                .map(|decision| (decision.finding_id.as_str(), decision.action.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("f0", "probe"),
                ("f1", "probe"),
                ("f2", "validate"),
                ("f3", "validate"),
                ("f4", "out_of_scope"),
                ("f5", "out_of_scope"),
                ("f8", "defer"),
                ("f9", "defer"),
            ]
        );
        let prompts = String::from_utf8(output).unwrap();
        assert_eq!(prompts.matches("action?").count(), findings.len());
    }

    #[test]
    fn interactive_triage_filters_non_candidates_and_accepts_case_and_whitespace() {
        let mut low = candidate("low");
        low.severity = Severity::Low;
        let mut non_positive = candidate("recommendation");
        non_positive.kind = FindingKind::Recommendation;
        let findings = vec![low, non_positive, candidate("eligible")];
        let mut input = Cursor::new(b"  PROBE  \n".to_vec());
        let mut output = Vec::new();

        let file = prompt_with_io("run-filter", &findings, &mut input, &mut output).unwrap();

        assert_eq!(file.decisions.len(), 1);
        assert_eq!(file.decisions[0].finding_id, "eligible");
        assert_eq!(file.decisions[0].action, "probe");
        let prompts = String::from_utf8(output).unwrap();
        assert!(prompts.contains("eligible"));
        assert!(!prompts.contains("candidate low"));
        assert!(!prompts.contains("candidate recommendation"));
    }

    #[test]
    fn interactive_triage_treats_eof_as_defer() {
        let mut input = Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();

        let file = prompt_with_io("run-eof", &[candidate("eof")], &mut input, &mut output).unwrap();

        assert_eq!(file.decisions.len(), 1);
        assert_eq!(file.decisions[0].action, "defer");
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("fixture read failure"))
        }
    }

    impl BufRead for FailingReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::other("fixture read failure"))
        }

        fn consume(&mut self, _amount: usize) {}
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("fixture write failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn interactive_triage_propagates_input_and_output_errors() {
        let findings = [candidate("error")];
        let mut input = FailingReader;
        let mut output = Vec::new();
        assert!(prompt_with_io("run-read-error", &findings, &mut input, &mut output).is_err());

        let mut input = Cursor::new(b"y\n".to_vec());
        let mut output = FailingWriter;
        assert!(prompt_with_io("run-write-error", &findings, &mut input, &mut output).is_err());
    }
}
