//! Signed blocklist manifest.
//!
//! The signature covers a fixed line-oriented encoding of every manifest
//! field (not the JSON text), so formatting or key order can never change
//! what was signed.

use gg_crypto::{digest_eq_hex, sha256_hex, verify_any, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const FORMAT: u32 = 1;
const DOMAIN_TAG: &str = "gg-blocklist-manifest-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u32,
    /// Stable list identifier, e.g. `gambling`. `[a-z0-9_-]{1,64}`.
    pub list_id: String,
    /// Monotonically increasing. Clients never activate a lower or equal one.
    pub version: u64,
    /// Seconds since the Unix epoch at which the list was built.
    pub generated_at: u64,
    /// Lowercase hex SHA-256 of the payload bytes.
    pub sha256: String,
    /// Payload length in bytes.
    pub size: u64,
    /// Number of valid rules in the payload, as counted by the publisher.
    pub rule_count: u64,
    /// Lowercase hex Ed25519 signature over [`Manifest::signed_message`].
    pub signature: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("manifest is not valid JSON for format {FORMAT}: {0}")]
    Parse(String),
    #[error("unsupported manifest format {0}")]
    Format(u32),
    #[error("invalid list id")]
    ListId,
    #[error("signature does not verify against any trusted key")]
    Signature,
    #[error("payload size {actual} does not match manifest size {expected}")]
    Size { expected: u64, actual: u64 },
    #[error("payload hash does not match manifest")]
    Hash,
}

fn valid_list_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        serde_json::from_slice(bytes).map_err(|e| ManifestError::Parse(e.to_string()))
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("manifest serializes")
    }

    pub fn signed_message(&self) -> Vec<u8> {
        format!(
            "{DOMAIN_TAG}\nformat={}\nlist_id={}\nversion={}\ngenerated_at={}\nsha256={}\nsize={}\nrule_count={}\n",
            self.format,
            self.list_id,
            self.version,
            self.generated_at,
            self.sha256.to_ascii_lowercase(),
            self.size,
            self.rule_count
        )
        .into_bytes()
    }

    /// Check format and signature only. Cheap; done before downloading the
    /// payload so an unsigned or stale manifest costs nothing further.
    pub fn verify_signature(&self, keys: &[PublicKey]) -> Result<(), ManifestError> {
        if self.format != FORMAT {
            return Err(ManifestError::Format(self.format));
        }
        if !valid_list_id(&self.list_id) {
            return Err(ManifestError::ListId);
        }
        verify_any(keys, &self.signed_message(), &self.signature)
            .map_err(|_| ManifestError::Signature)
    }

    /// Full check: signature, then payload size and hash.
    pub fn verify(&self, keys: &[PublicKey], payload: &[u8]) -> Result<(), ManifestError> {
        self.verify_signature(keys)?;
        if payload.len() as u64 != self.size {
            return Err(ManifestError::Size {
                expected: self.size,
                actual: payload.len() as u64,
            });
        }
        if !digest_eq_hex(&sha256_hex(payload), &self.sha256) {
            return Err(ManifestError::Hash);
        }
        Ok(())
    }

    /// Build and sign a manifest for `payload`. Publisher side only.
    pub fn sign(
        key: &SecretKey,
        list_id: &str,
        version: u64,
        generated_at: u64,
        payload: &[u8],
        rule_count: u64,
    ) -> Result<Self, ManifestError> {
        if !valid_list_id(list_id) {
            return Err(ManifestError::ListId);
        }
        let mut m = Manifest {
            format: FORMAT,
            list_id: list_id.to_owned(),
            version,
            generated_at,
            sha256: sha256_hex(payload),
            size: payload.len() as u64,
            rule_count,
            signature: String::new(),
        };
        m.signature = key.sign_hex(&m.signed_message());
        Ok(m)
    }
}
