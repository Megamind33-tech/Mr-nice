//! Domain normalization.
//!
//! Every domain entering the engine — from a blocklist, a user rule, or an
//! intercepted DNS query — passes through [`normalize_domain`] so that
//! `WWW.Betting-Site.COM.`, `www.betting-site.com` and IDN/punycode variants
//! compare identically.

use std::fmt;

use thiserror::Error;

/// Maximum length of a full domain name in presentation form (RFC 1035).
pub const MAX_DOMAIN_LEN: usize = 253;
/// Maximum length of a single label (RFC 1035).
pub const MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("domain is empty")]
    Empty,
    #[error("domain exceeds {MAX_DOMAIN_LEN} characters")]
    TooLong,
    #[error("label is empty (consecutive or leading dots)")]
    EmptyLabel,
    #[error("label exceeds {MAX_LABEL_LEN} characters")]
    LabelTooLong,
    #[error("invalid character in domain")]
    InvalidCharacter,
    #[error("label may not start or end with a hyphen")]
    HyphenPosition,
    #[error("IDN conversion failed")]
    Idna,
}

/// A validated, normalized domain in lowercase ASCII (punycode) form without
/// a trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Domain(String);

impl Domain {
    pub fn parse(input: &str) -> Result<Self, DomainError> {
        normalize_domain(input).map(Domain)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Labels from most specific to least specific (`a.b.com` → `a`, `b`, `com`).
    pub fn labels(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.0.split('.')
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Normalize a domain name to lowercase ASCII (punycode), strip a single
/// trailing root dot, and validate label syntax.
pub fn normalize_domain(input: &str) -> Result<String, DomainError> {
    let trimmed = input.trim();
    let trimmed = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return Err(DomainError::Empty);
    }

    let ascii = if trimmed.is_ascii() {
        trimmed.to_ascii_lowercase()
    } else {
        idna::domain_to_ascii(trimmed).map_err(|_| DomainError::Idna)?
    };

    validate_ascii_domain(&ascii)?;
    Ok(ascii)
}

fn validate_ascii_domain(domain: &str) -> Result<(), DomainError> {
    if domain.is_empty() {
        return Err(DomainError::Empty);
    }
    if domain.len() > MAX_DOMAIN_LEN {
        return Err(DomainError::TooLong);
    }
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(DomainError::EmptyLabel);
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(DomainError::LabelTooLong);
        }
        // Underscore is permitted because it appears in real DNS names
        // (e.g. SRV/service labels) and must not cause a lookup to escape
        // matching by failing validation.
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(DomainError::InvalidCharacter);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DomainError::HyphenPosition);
        }
    }
    Ok(())
}
