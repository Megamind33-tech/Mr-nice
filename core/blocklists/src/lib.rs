//! Gambling Guard blocklist distribution.
//!
//! - [`Manifest`]: signed description of a list version.
//! - [`BlocklistProvider`]: untrusted transport (file, HTTP).
//! - [`BlocklistRepository`]: verified local cache with rollback slot.
//! - [`BlocklistUpdater`]: the only path by which a list becomes active.
//! - [`RuleCompiler`]: payload → matcher.

pub mod bundled;
pub mod compiler;
pub mod manifest;
pub mod provider;
pub mod repository;
pub mod updater;

pub use compiler::{CompiledList, RuleCompiler};
pub use manifest::{Manifest, ManifestError};
pub use provider::{from_source, BlocklistProvider, FileProvider, HttpProvider, ProviderError};
pub use repository::{BlocklistRepository, Slot, VerifiedList};
pub use updater::{BlocklistUpdater, UpdateOutcome, UpdatePolicy};

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error("payload is not UTF-8")]
    Encoding,
    #[error("list id {0} does not match expected list")]
    WrongList(String),
    #[error("version {offered} is not newer than current {current}")]
    NotNewer { offered: u64, current: u64 },
    #[error("manifest declares {manifest} rules but payload has {actual}")]
    RuleCountMismatch { manifest: u64, actual: u64 },
    #[error("only {0} valid rules")]
    TooFewRules(usize),
    #[error("{0} invalid lines exceed tolerance")]
    TooManyErrors(usize),
    #[error("list shrank from {from} to {to} rules")]
    Shrunk { from: u64, to: u64 },
    #[error("declared payload size {0} exceeds limit")]
    TooLarge(u64),
}
