//! Gambling Guard shared rules engine.
//!
//! Platform-independent: no networking, no filesystem, no OS APIs. Native
//! platform layers (Windows service, Android VpnService) feed it normalized
//! domain names and act on the returned [`Verdict`].

pub mod category;
pub mod domain;
pub mod list;
pub mod matcher;
pub mod rule;

pub use category::Category;
pub use domain::{normalize_domain, Domain, DomainError};
pub use list::{parse_list, ParsedList};
pub use matcher::{MatchDetail, RuleMatcher, Verdict};
pub use rule::{Action, Rule, RuleId, Scope};
