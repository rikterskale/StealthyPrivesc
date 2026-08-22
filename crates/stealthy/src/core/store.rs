use anyhow::{anyhow, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use zeroize::Zeroize;

use crate::core::types::{Finding, RunReport};

/// Encrypted in-memory result store.
///
/// Findings are held as plaintext `Finding` values for operator convenience during
/// the run, then sealed with ChaCha20-Poly1305 when exporting. The ephemeral key
/// is zeroized on drop.
pub struct EncryptedStore {
    findings: Vec<Finding>,
    notes: Vec<String>,
    key: [u8; 32],
}

impl EncryptedStore {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self {
            findings: Vec::new(),
            notes: Vec::new(),
            key,
        }
    }

    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// Seal an arbitrary report into `nonce || ciphertext` (base64).
    pub fn seal_report(&self, report: &RunReport) -> Result<String> {
        let plaintext = serde_json::to_vec(report).context("serialize report")?;
        self.seal_bytes(&plaintext)
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

    /// Test-only opener used to verify authenticated encryption behavior.
    #[cfg(test)]
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{FindingKind, Severity};

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
    fn stores_findings() {
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
        });
        assert_eq!(store.findings().len(), 1);
    }
}
