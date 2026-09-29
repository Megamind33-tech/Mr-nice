//! Rule syntax.
//!
//! | Syntax              | Meaning                                         |
//! |---------------------|-------------------------------------------------|
//! | `example.com`       | `example.com` **and** every subdomain           |
//! | `*.example.com`     | subdomains of `example.com` only, not the apex  |
//! | `=example.com`      | exactly `example.com`, no subdomains            |
//! | `@@<any of above>`  | allow (exception) rule with the same scope      |
//!
//! Blank lines and lines starting with `#` are ignored by the list parser.

use std::fmt;

use thiserror::Error;

use crate::category::Category;
use crate::domain::{Domain, DomainError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Block,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// The domain itself and all subdomains.
    DomainAndSubdomains,
    /// Subdomains only.
    SubdomainsOnly,
    /// Only the exact domain.
    Exact,
}

/// Stable identifier of a rule within a compiled rule set. Used for
/// statistics without having to record the visited domain itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleId(pub u32);

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "R{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub domain: Domain,
    pub scope: Scope,
    pub action: Action,
    pub category: Category,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuleParseError {
    #[error("invalid domain in rule: {0}")]
    Domain(#[from] DomainError),
    #[error("wildcard is only supported as a leading `*.` label")]
    UnsupportedWildcard,
}

impl Rule {
    pub fn parse(text: &str, category: Category) -> Result<Self, RuleParseError> {
        let text = text.trim();
        let (action, rest) = match text.strip_prefix("@@") {
            Some(r) => (Action::Allow, r),
            None => (Action::Block, text),
        };
        let (scope, rest) = if let Some(r) = rest.strip_prefix("*.") {
            (Scope::SubdomainsOnly, r)
        } else if let Some(r) = rest.strip_prefix('=') {
            (Scope::Exact, r)
        } else {
            (Scope::DomainAndSubdomains, rest)
        };
        if rest.contains('*') {
            return Err(RuleParseError::UnsupportedWildcard);
        }
        Ok(Rule {
            domain: Domain::parse(rest)?,
            scope,
            action,
            category,
        })
    }
}
