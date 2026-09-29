//! Cryptographic primitives used for signed blocklist distribution.
//!
//! Ed25519 (RFC 8032) with strict verification, SHA-256 for payload
//! integrity. Keys and signatures travel as lowercase hex.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid hex encoding")]
    Hex,
    #[error("wrong length: expected {expected} bytes, got {actual}")]
    Length { expected: usize, actual: usize },
    #[error("invalid public key")]
    PublicKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("operating system random source unavailable")]
    Random,
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// Constant-time comparison of two hex digests (case-insensitive).
pub fn digest_eq_hex(a: &str, b: &str) -> bool {
    let (Ok(x), Ok(y)) = (hex::decode(a.trim()), hex::decode(b.trim())) else {
        return false;
    };
    x.len() == y.len() && x.iter().zip(&y).fold(0u8, |acc, (p, q)| acc | (p ^ q)) == 0
}

fn fixed<const N: usize>(text: &str) -> Result<[u8; N], CryptoError> {
    let bytes = hex::decode(text.trim()).map_err(|_| CryptoError::Hex)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Length {
            expected: N,
            actual: bytes.len(),
        })
}

/// A pinned Ed25519 public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    pub fn from_hex(text: &str) -> Result<Self, CryptoError> {
        let bytes = fixed::<32>(text)?;
        VerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| CryptoError::PublicKey)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_bytes())
    }

    /// Strict verification: rejects non-canonical and small-order encodings.
    pub fn verify(&self, message: &[u8], signature_hex: &str) -> Result<(), CryptoError> {
        let sig = Signature::from_bytes(&fixed::<64>(signature_hex)?);
        self.0
            .verify_strict(message, &sig)
            .map_err(|_| CryptoError::BadSignature)
    }
}

/// Verify against a set of trusted keys; succeeds if any key verifies.
/// Multiple keys allow rotation without a flag day.
pub fn verify_any(
    keys: &[PublicKey],
    message: &[u8],
    signature_hex: &str,
) -> Result<(), CryptoError> {
    if keys
        .iter()
        .any(|k| k.verify(message, signature_hex).is_ok())
    {
        Ok(())
    } else {
        Err(CryptoError::BadSignature)
    }
}

/// Offline signing key. Only the publishing tool ever holds one.
pub struct SecretKey(SigningKey);

impl SecretKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| CryptoError::Random)?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    pub fn from_hex(text: &str) -> Result<Self, CryptoError> {
        let seed = Zeroizing::new(fixed::<32>(text)?);
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.0.to_bytes()))
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    pub fn sign_hex(&self, message: &[u8]) -> String {
        hex::encode(self.0.sign(message).to_bytes())
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn rfc8032_test_vector_1() {
        // RFC 8032 §7.1, TEST 1 (empty message).
        let sk =
            SecretKey::from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        assert_eq!(
            sk.public().to_hex(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(
            sk.sign_hex(b""),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn sign_verify_and_tamper() {
        let sk = SecretKey::generate().unwrap();
        let pk = sk.public();
        let sig = sk.sign_hex(b"payload");
        assert!(pk.verify(b"payload", &sig).is_ok());
        assert_eq!(pk.verify(b"payloaD", &sig), Err(CryptoError::BadSignature));
        let mut bad = sig.clone().into_bytes();
        bad[0] = if bad[0] == b'0' { b'1' } else { b'0' };
        assert!(pk
            .verify(b"payload", std::str::from_utf8(&bad).unwrap())
            .is_err());
        assert!(matches!(pk.verify(b"payload", "zz"), Err(CryptoError::Hex)));
        assert!(matches!(
            pk.verify(b"payload", "00"),
            Err(CryptoError::Length { .. })
        ));
    }

    #[test]
    fn verify_any_supports_rotation() {
        let old = SecretKey::generate().unwrap();
        let new = SecretKey::generate().unwrap();
        let other = SecretKey::generate().unwrap();
        let trusted = [old.public(), new.public()];
        assert!(verify_any(&trusted, b"m", &new.sign_hex(b"m")).is_ok());
        assert!(verify_any(&trusted, b"m", &other.sign_hex(b"m")).is_err());
        assert!(verify_any(&[], b"m", &new.sign_hex(b"m")).is_err());
    }

    #[test]
    fn key_hex_round_trip_and_redacted_debug() {
        let sk = SecretKey::generate().unwrap();
        let again = SecretKey::from_hex(&sk.to_hex()).unwrap();
        assert_eq!(again.public(), sk.public());
        assert_eq!(
            PublicKey::from_hex(&sk.public().to_hex()).unwrap(),
            sk.public()
        );
        assert_eq!(format!("{sk:?}"), "SecretKey(<redacted>)");
    }

    #[test]
    fn digest_comparison() {
        let d = sha256_hex(b"x");
        assert!(digest_eq_hex(&d, &d.to_uppercase()));
        assert!(!digest_eq_hex(&d, &sha256_hex(b"y")));
        assert!(!digest_eq_hex(&d, "not-hex"));
        assert!(!digest_eq_hex(&d, &d[..62]));
    }
}
