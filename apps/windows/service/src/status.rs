//! Protection health, computed only by the service from component state.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectionHealth {
    Protected,
    PartiallyProtected,
    ActionRequired,
    Disabled,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Components {
    /// Local filter is listening on every configured address.
    pub dns_listener: bool,
    /// Every active adapter's DNS points at the local filter.
    pub dns_takeover: bool,
    /// WFP filters that block DNS bypass are installed.
    pub bypass_filters: bool,
    /// Rule set compiled with at least one rule and no unreadable list.
    pub rules_loaded: bool,
    /// A verified gambling blocklist is active and within its maximum age.
    pub blocklist_fresh: bool,
}

impl Components {
    pub fn health(&self) -> ProtectionHealth {
        match *self {
            Components {
                dns_listener: false,
                ..
            } => ProtectionHealth::Error,
            Components {
                dns_takeover: false,
                ..
            } => ProtectionHealth::ActionRequired,
            Components {
                bypass_filters: true,
                rules_loaded: true,
                blocklist_fresh: true,
                ..
            } => ProtectionHealth::Protected,
            _ => ProtectionHealth::PartiallyProtected,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    pub health: ProtectionHealth,
    pub components: Components,
    pub blocklist: Option<crate::blocklist::BlocklistStatus>,
    pub rule_count: usize,
    pub upstreams: Vec<String>,
    pub queries: u64,
    pub blocked: u64,
    pub forwarded: u64,
    pub upstream_failures: u64,
    pub service_pid: u32,
    /// Seconds since the Unix epoch at which this report was written.
    pub updated_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(listener: bool, takeover: bool, filters: bool, rules: bool) -> Components {
        Components {
            dns_listener: listener,
            dns_takeover: takeover,
            bypass_filters: filters,
            rules_loaded: rules,
            blocklist_fresh: true,
        }
    }

    #[test]
    fn stale_blocklist_is_partial_protection() {
        let stale = Components {
            blocklist_fresh: false,
            ..c(true, true, true, true)
        };
        assert_eq!(stale.health(), ProtectionHealth::PartiallyProtected);
    }

    #[test]
    fn protected_only_when_everything_is_up() {
        assert_eq!(
            c(true, true, true, true).health(),
            ProtectionHealth::Protected
        );
        assert_eq!(
            c(true, true, false, true).health(),
            ProtectionHealth::PartiallyProtected
        );
        assert_eq!(
            c(true, true, true, false).health(),
            ProtectionHealth::PartiallyProtected
        );
        assert_eq!(
            c(true, false, true, true).health(),
            ProtectionHealth::ActionRequired
        );
        assert_eq!(c(false, true, true, true).health(), ProtectionHealth::Error);
        assert_eq!(Components::default().health(), ProtectionHealth::Error);
    }
}
