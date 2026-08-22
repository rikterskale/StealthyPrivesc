use anyhow::Result;

use crate::cli::{Cli, OutputMode};
use crate::core::evasion::{self, low_and_slow};
use crate::core::identity;
use crate::core::os;
use crate::core::output::{self, OutputOptions};
use crate::core::plugin::{filter_plugins, PluginContext};
use crate::core::store::EncryptedStore;
use crate::core::term;
use crate::core::types::{PluginCoverage, RunReport, Severity};
use crate::plugins;

pub struct Engine {
    quiet: bool,
    verbose: bool,
    delay_ms: u64,
    auto_exploit: bool,
    only: Option<Vec<String>>,
    skip: Option<Vec<String>>,
    output: OutputOptions,
    fail_on: Option<Severity>,
}

pub struct EngineOutcome {
    pub fail_on_triggered: bool,
}

impl Engine {
    pub fn from_cli(
        cli: &Cli,
        auto_exploit: bool,
        only: Option<Vec<String>>,
        skip: Option<Vec<String>>,
    ) -> Result<Self> {
        Ok(Self {
            quiet: cli.quiet,
            verbose: cli.verbose,
            delay_ms: cli.delay_ms,
            auto_exploit,
            only,
            skip,
            fail_on: cli.fail_on.map(|m| m.to_severity()),
            output: OutputOptions {
                mode: cli.output,
                path: cli.output_path.clone(),
                plaintext_file: cli.plaintext_file,
                also_markdown: cli.also_markdown,
                exfil_url: cli.exfil_url.clone(),
                quiet: cli.quiet,
                format: cli.format,
                min_severity: cli.min_severity.to_severity(),
                verbose: cli.verbose,
            },
        })
    }

    pub fn run(&mut self) -> Result<EngineOutcome> {
        let os_info = os::detect();
        let ident = identity::current();
        let mut store = EncryptedStore::new();

        for note in evasion::evasion_notes() {
            store.note(note);
        }

        if ident.is_elevated {
            store.note(
                "Already elevated — enumeration still useful for lateral/persistence review.",
            );
        }

        if self.auto_exploit {
            store.note(
                "AUTO-EXPLOIT enabled: only low-noise reversible verifications run; kernel exploits disabled.",
            );
        }

        let registry = plugins::registry();
        let selected = filter_plugins(
            &registry,
            self.only.as_deref(),
            self.skip.as_deref(),
            &os_info.os,
        );

        if selected.is_empty() {
            store.note(format!(
                "No plugins selected for os={} — check --plugins / build target.",
                os_info.os
            ));
            if !self.quiet {
                eprintln!(
                    "{} No plugins matched. Try `stealthy --authorized list-plugins`",
                    term::warn("[!]")
                );
            }
        } else if !self.quiet {
            eprintln!(
                "{} {} · {}@{} · {} plugin(s)",
                term::bold("[*]"),
                term::cyan(&os_info.os),
                ident.username,
                ident.hostname,
                selected.len()
            );
        }

        let mut plugins_run = Vec::new();
        let mut coverage = Vec::new();
        let total = selected.len();

        for (idx, plugin) in selected.iter().enumerate() {
            if !self.quiet {
                eprintln!(
                    "{} [{:>2}/{}] {}",
                    term::dim("[*]"),
                    idx + 1,
                    total,
                    plugin.id()
                );
            }
            low_and_slow(self.delay_ms);

            let mut ctx = PluginContext {
                verbose: self.verbose,
                auto_exploit: self.auto_exploit,
                store: &mut store,
            };

            match plugin.run(&mut ctx) {
                Ok(findings) => {
                    let n = findings.len();
                    let max = findings
                        .iter()
                        .map(|f| f.severity)
                        .max()
                        .unwrap_or(Severity::Info);
                    for f in findings {
                        if self.verbose && !self.quiet {
                            eprintln!(
                                "    {} {} {}",
                                term::severity_tag(f.severity),
                                term::dim("+"),
                                f.title
                            );
                        }
                        store.push(f);
                    }
                    if !self.quiet && n > 0 {
                        eprintln!(
                            "    {} {} finding(s) · max {}",
                            term::dim("↳"),
                            n,
                            term::severity_tag(max)
                        );
                    }
                    plugins_run.push(plugin.id().to_string());
                    coverage.push(PluginCoverage {
                        id: plugin.id().to_string(),
                        status: "ok".into(),
                        findings: n,
                        error: None,
                    });
                }
                Err(e) => {
                    let error = format!("{e:#}");
                    store.note(format!("plugin {} error: {error}", plugin.id()));
                    coverage.push(PluginCoverage {
                        id: plugin.id().to_string(),
                        status: "error".into(),
                        findings: 0,
                        error: Some(error.clone()),
                    });
                    if !self.quiet {
                        eprintln!("    {} plugin failed: {error}", term::err("[!]"));
                    }
                }
            }
        }

        let mode = if self.auto_exploit {
            "enumerate+limited-auto-exploit"
        } else {
            "enumerate-only"
        };

        let (findings, notes) = store_into_parts(&store);
        let report = RunReport {
            schema_version: "1".into(),
            tool: "stealthy".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            authorized_use_ack: true,
            mode: mode.into(),
            os: os_info,
            identity: ident,
            findings,
            plugins_run,
            coverage,
            notes,
        };

        let emitted = output::emit(&report, &store, &self.output)?;

        if self.verbose && self.output.mode == OutputMode::Memory && !self.quiet {
            eprintln!(
                "{} seal key (hex): {}",
                term::dim("[memory]"),
                store.key_hex()
            );
        }

        let fail_on_triggered = self
            .fail_on
            .map(|min| emitted.max_severity.rank() >= min.rank())
            .unwrap_or(false);

        if fail_on_triggered && !self.quiet {
            eprintln!(
                "{} --fail-on triggered (max severity {})",
                term::err("[!]"),
                term::severity_tag(emitted.max_severity)
            );
        }

        let _ = store;
        let _ = emitted.max_severity;
        Ok(EngineOutcome { fail_on_triggered })
    }
}

fn store_into_parts(store: &EncryptedStore) -> (Vec<crate::core::types::Finding>, Vec<String>) {
    (store.findings().to_vec(), store.notes().to_vec())
}
