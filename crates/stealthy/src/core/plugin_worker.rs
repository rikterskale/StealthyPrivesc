use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::profile::NoiseBudget;
use crate::core::store::EncryptedStore;
use crate::core::types::{ControlAssessment, Finding};
use crate::exploit::TechniqueAllowlist;
use crate::plugins;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PluginWorkerRequest {
    pub plugin: String,
    pub verbose: bool,
    pub auto_exploit: bool,
    pub prefer_quiet: bool,
    pub noise_budget: NoiseBudget,
    pub allow_techniques: Vec<String>,
    pub approved_probe_ids: Vec<String>,
    pub artifact_path: Option<PathBuf>,
    pub control_assessment: Option<ControlAssessment>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct PluginWorkerResult {
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
    pub error: Option<String>,
}

pub(crate) enum PluginOutcome {
    Completed(PluginWorkerResult),
    Error(String),
    Timeout,
}

pub(crate) fn run_plugin_worker(request: PluginWorkerRequest) -> Result<PluginWorkerResult> {
    let allow = TechniqueAllowlist::from_ids(&request.allow_techniques)?;
    Ok(run_plugin_blocking(
        &request.plugin,
        request.verbose,
        request.auto_exploit,
        request.prefer_quiet,
        request.noise_budget,
        &allow,
        &request.approved_probe_ids,
        request.artifact_path,
        request.control_assessment,
        Arc::new(AtomicBool::new(false)),
    ))
}

pub(crate) fn run_with_timeout(
    request: PluginWorkerRequest,
    timeout_ms: u64,
    cancel: Arc<AtomicBool>,
) -> PluginOutcome {
    if timeout_ms == 0 {
        let allow = match TechniqueAllowlist::from_ids(&request.allow_techniques) {
            Ok(allow) => allow,
            Err(error) => return PluginOutcome::Error(format!("{error:#}")),
        };
        return PluginOutcome::Completed(run_plugin_blocking(
            &request.plugin,
            request.verbose,
            request.auto_exploit,
            request.prefer_quiet,
            request.noise_budget,
            &allow,
            &request.approved_probe_ids,
            request.artifact_path,
            request.control_assessment,
            cancel,
        ));
    }

    let plugin_id = request.plugin.clone();
    let mut child = match std::env::current_exe()
        .context("locate plugin worker executable")
        .and_then(|exe| {
            let mut command = Command::new(exe);
            command
                .args([
                    "--authorized",
                    "--quiet",
                    "__plugin-worker",
                    "--plugin",
                    &plugin_id,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            #[cfg(unix)]
            unsafe {
                command.pre_exec(|| {
                    if setsid() == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            command.spawn().context("spawn isolated plugin worker")
        }) {
        Ok(child) => child,
        Err(error) => return PluginOutcome::Error(format!("{error:#}")),
    };

    if let Some(mut stdin) = child.stdin.take() {
        match serde_json::to_vec(&request) {
            Ok(body) => {
                if let Err(error) = stdin.write_all(&body) {
                    terminate_worker(&mut child);
                    return PluginOutcome::Error(format!("write plugin worker request: {error}"));
                }
            }
            Err(error) => {
                terminate_worker(&mut child);
                return PluginOutcome::Error(format!("serialize plugin worker request: {error}"));
            }
        }
    }

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if cancel.load(Ordering::SeqCst) || Instant::now() >= deadline {
            cancel.store(true, Ordering::SeqCst);
            terminate_worker(&mut child);
            return PluginOutcome::Timeout;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut pipe) = child.stdout.take() {
                    let _ = pipe.read_to_end(&mut stdout);
                }
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_end(&mut stderr);
                }
                if !status.success() {
                    return PluginOutcome::Error(format!(
                        "plugin worker failed: {}",
                        String::from_utf8_lossy(&stderr)
                    ));
                }
                return match serde_json::from_slice::<PluginWorkerResult>(&stdout) {
                    Ok(result) => PluginOutcome::Completed(result),
                    Err(error) => {
                        PluginOutcome::Error(format!("parse plugin worker output: {error}"))
                    }
                };
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                terminate_worker(&mut child);
                return PluginOutcome::Error(format!("poll plugin worker: {error}"));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_plugin_blocking(
    plugin_id: &str,
    verbose: bool,
    auto_exploit: bool,
    prefer_quiet: bool,
    noise_budget: NoiseBudget,
    allow_techniques: &TechniqueAllowlist,
    approved_probe_ids: &[String],
    artifact_path: Option<PathBuf>,
    control_assessment: Option<ControlAssessment>,
    cancel: Arc<AtomicBool>,
) -> PluginWorkerResult {
    let registry = plugins::registry();
    let Some(plugin) = registry.iter().find(|plugin| plugin.id() == plugin_id) else {
        return PluginWorkerResult {
            error: Some(format!("plugin not found: {plugin_id}")),
            ..Default::default()
        };
    };
    run_plugin_instance(
        *plugin,
        verbose,
        auto_exploit,
        prefer_quiet,
        noise_budget,
        allow_techniques,
        approved_probe_ids,
        artifact_path,
        control_assessment,
        cancel,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_plugin_instance(
    plugin: &dyn Plugin,
    verbose: bool,
    auto_exploit: bool,
    prefer_quiet: bool,
    noise_budget: NoiseBudget,
    allow_techniques: &TechniqueAllowlist,
    approved_probe_ids: &[String],
    artifact_path: Option<PathBuf>,
    control_assessment: Option<ControlAssessment>,
    cancel: Arc<AtomicBool>,
) -> PluginWorkerResult {
    let mut local_store = EncryptedStore::new();
    let mut context = PluginContext {
        verbose,
        auto_exploit,
        prefer_quiet,
        noise_budget,
        allow_techniques,
        store: &mut local_store,
        approved_probe_ids,
        artifact_path,
        control_assessment,
        cancel,
    };
    let execution = plugin.run(&mut context);
    let notes = local_store.notes().to_vec();
    match execution {
        Ok(findings) => PluginWorkerResult {
            findings,
            notes,
            error: None,
        },
        Err(error) => PluginWorkerResult {
            findings: Vec::new(),
            notes,
            error: Some(format!("{error:#}")),
        },
    }
}

fn terminate_worker(child: &mut Child) {
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(child.id()) {
        unsafe {
            let _ = kill(-pid, 9);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
    fn setsid() -> i32;
}

#[cfg(test)]
mod tests {
    use super::{run_plugin_instance, PluginWorkerResult};
    use crate::core::plugin::{Plugin, PluginContext};
    use crate::core::profile::NoiseBudget;
    use crate::core::types::Finding;
    use crate::exploit::TechniqueAllowlist;
    use anyhow::Result;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    struct NotePlugin;

    impl Plugin for NotePlugin {
        fn id(&self) -> &'static str {
            "test.notes"
        }
        fn name(&self) -> &'static str {
            "notes"
        }
        fn description(&self) -> &'static str {
            "notes"
        }
        fn platforms(&self) -> &'static [&'static str] {
            &["test"]
        }
        fn run(&self, context: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
            context.store.note("worker-owned note");
            Ok(Vec::new())
        }
    }

    #[test]
    fn worker_envelope_preserves_notes() {
        let result = PluginWorkerResult {
            notes: vec!["plugin note".into()],
            ..Default::default()
        };
        let encoded = serde_json::to_vec(&result).unwrap();
        let decoded: PluginWorkerResult = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.notes, vec!["plugin note"]);
    }

    #[test]
    fn plugin_store_notes_are_returned_in_worker_result() {
        let result = run_plugin_instance(
            &NotePlugin,
            false,
            false,
            true,
            NoiseBudget {
                allow_external_helpers: false,
                max_walk_entries: 10,
                max_helper_records: 10,
            },
            &TechniqueAllowlist::default(),
            &[],
            None,
            None,
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(result.notes, vec!["worker-owned note"]);
        assert!(result.error.is_none());
    }
}
