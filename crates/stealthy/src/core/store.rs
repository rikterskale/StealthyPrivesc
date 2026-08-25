use anyhow::{anyhow, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use zeroize::Zeroize;

use crate::core::types::{Finding, RunReport};

/// Encrypted in-memory result store.
///
/// Findings are sealed with ChaCha20-Poly1305 while resident in this store.
/// Transient decrypted views are produced only when reading or emitting.
/// The ephemeral key is zeroized on drop.
pub struct EncryptedStore {
    sealed_findings: Vec<String>,
    notes: Vec<String>,
    key: [u8; 32],
}

impl EncryptedStore {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self {
            sealed_findings: Vec::new(),
            notes: Vec::new(),
            key,
        }
    }

    pub fn push(&mut self, finding: Finding) {
        match serde_json::to_vec(&finding)
            .ok()
            .and_then(|bytes| self.seal_bytes(&bytes).ok())
        {
            Some(sealed) => self.sealed_findings.push(sealed),
            None => {
                // Extremely unlikely; keep a note rather than storing plaintext.
                self.notes
                    .push("failed to seal a finding into the encrypted store".into());
            }
        }
    }

    pub fn note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// Decrypt a temporary owned snapshot of sealed findings.
    pub fn findings(&self) -> Vec<Finding> {
        self.sealed_findings
            .iter()
            .filter_map(|sealed| self.open_bytes(sealed).ok())
            .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
            .collect()
    }

    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// Seal an arbitrary report into `nonce || ciphertext` (base64).
    pub fn seal_report(&self, report: &RunReport) -> Result<String> {
        let plaintext = serde_json::to_vec(report).context("serialize report")?;
        self.seal_bytes(&plaintext)
    }

    /// Decode and authenticate a sealed report using an operator-supplied key.
    pub fn open_sealed_report(sealed: &str, key_hex: &str) -> Result<RunReport> {
        let key = hex::decode(key_hex).context("decode hex key")?;
        if key.len() != 32 {
            return Err(anyhow!("report key must contain exactly 32 bytes"));
        }
        let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sealed)
            .context("decode sealed report")?;
        if raw.len() < 12 {
            return Err(anyhow!("sealed report is shorter than a nonce"));
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&raw[..12]), &raw[12..])
            .map_err(|_| anyhow!("sealed report authentication failed"))?;
        serde_json::from_slice(&plaintext).context("parse sealed report")
    }

    pub fn seal_bytes(&self, plaintext: &[u8]) -> Result<String> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| anyhow!("encryption failed"))?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &out,
        ))
    }

    fn open_bytes(&self, sealed: &str) -> Result<Vec<u8>> {
        let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sealed)
            .context("decode sealed payload")?;
        if raw.len() < 12 {
            return Err(anyhow!("sealed payload is shorter than a nonce"));
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        cipher
            .decrypt(Nonce::from_slice(&raw[..12]), &raw[12..])
            .map_err(|_| anyhow!("sealed payload authentication failed"))
    }

    /// Export the raw key as hex for operator-side decryption of sealed blobs.
    /// WARNING: treat this like a credential; do not write to disk casually.
    pub fn key_hex(&self) -> String {
        hex::encode(self.key)
    }
}

impl Default for EncryptedStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EncryptedStore {
    fn drop(&mut self) {
        self.key.zeroize();
        self.sealed_findings.clear();
        self.notes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{
        FindingKind, IdentityInfo, OsInfo, PluginCoverage, RunReport, Severity,
    };

    #[test]
    fn seal_roundtrip_shape() {
        let store = EncryptedStore::new();
        let sealed = store.seal_bytes(b"test-payload").unwrap();
        let raw =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sealed).unwrap();
        assert!(raw.len() > 12);
    }

    #[test]
    fn seal_roundtrip_recovers_plaintext_and_rejects_tampering() {
        let store = EncryptedStore::new();
        let sealed = store.seal_bytes(b"test-payload").unwrap();
        assert_eq!(store.open_bytes(&sealed).unwrap(), b"test-payload");

        let mut raw =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sealed).unwrap();
        *raw.last_mut().unwrap() ^= 1;
        let tampered = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw);
        assert!(store.open_bytes(&tampered).is_err());
    }

    #[test]
    fn seals_large_payload_without_truncation() {
        let store = EncryptedStore::new();
        let payload = vec![b'x'; 1024 * 1024];
        let sealed = store.seal_bytes(&payload).unwrap();
        assert_eq!(store.open_bytes(&sealed).unwrap(), payload);
    }

    #[test]
    fn sealed_report_can_be_reopened_with_operator_key() {
        let store = EncryptedStore::new();
        let report = RunReport {
            schema_version: "1".into(),
            run_id: "test-run".into(),
            started_at_unix: 0,
            tool: "stealthy".into(),
            version: "0.1.0".into(),
            authorized_use_ack: true,
            mode: "enumerate-only".into(),
            execution_path: "binary".into(),
            primary_launch: "ok".into(),
            roe_ref: String::new(),
            os: OsInfo {
                family: "unix".into(),
                os: "linux".into(),
                arch: "x86_64".into(),
                version_hint: "test".into(),
            },
            identity: IdentityInfo {
                username: "tester".into(),
                uid: Some(1000),
                gid: Some(1000),
                groups: vec![],
                is_elevated: false,
                elevation_source: "test".into(),
                token_context: "test".into(),
                hostname: "host".into(),
            },
            findings: vec![],
            assessments: vec![],
            attack_paths: vec![],
            triage_decisions: vec![],
            plugins_run: vec![],
            coverage: vec![PluginCoverage {
                id: "test".into(),
                status: "ok".into(),
                findings: 0,
                error: None,
                duration_ms: 0,
            }],
            notes: vec![],
            profile: "balanced".into(),
            coverage_mode: "native".into(),
            capability_delta: vec![],
            control_assessment: None,
        };
        let sealed = store.seal_report(&report).unwrap();
        let reopened = EncryptedStore::open_sealed_report(&sealed, &store.key_hex()).unwrap();
        assert_eq!(reopened.schema_version, "1");
        assert_eq!(reopened.coverage[0].status, "ok");
    }

    #[test]
    fn stores_findings_sealed_at_rest() {
        let mut store = EncryptedStore::new();
        store.push(Finding {
            plugin: "t".into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Info,
            title: "t".into(),
            detail: "d".into(),
            recommendation: "r".into(),
            noisy: false,
            leaves_artifacts: false,
            ..Default::default()
        });
        assert_eq!(store.findings().len(), 1);
        assert_eq!(store.findings()[0].title, "t");
        assert_eq!(store.sealed_findings.len(), 1);
        assert!(!store.sealed_findings[0].contains("\"title\":\"t\""));
    }
}
