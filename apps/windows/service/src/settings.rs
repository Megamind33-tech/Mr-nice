//! Versioned service settings (`settings.json`).
//!
//! Unreadable or invalid settings never disable protection. The service logs
//! the problem and runs with defaults, which always include filtering.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use gg_dns_filter::BlockResponse;
use serde::{Deserialize, Serialize};

pub const CURRENT_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BlockMode {
    #[default]
    Sinkhole,
    Nxdomain,
}

impl From<BlockMode> for BlockResponse {
    fn from(m: BlockMode) -> Self {
        match m {
            BlockMode::Sinkhole => BlockResponse::Sinkhole,
            BlockMode::Nxdomain => BlockResponse::NxDomain,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkSettings {
    /// Where the local filter listens. The OS resolver is pointed here.
    pub listen: Vec<SocketAddr>,
    /// Explicit upstream resolvers. Empty = use resolvers captured from the
    /// adapters at takeover, then `fallback_upstreams`.
    pub upstreams: Vec<SocketAddr>,
    pub fallback_upstreams: Vec<SocketAddr>,
    /// Public DNS-over-HTTPS resolver addresses blocked on port 443.
    pub doh_resolver_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtectionSettings {
    pub block_mode: BlockMode,
    /// On a clean service stop, remove WFP filters and restore DNS. When
    /// false, a stopped service leaves DNS pointed at loopback with outbound
    /// DNS blocked, so name resolution fails closed until it restarts.
    pub restore_network_on_stop: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PrivacySettings {
    /// Record blocked hostnames in the local log. Off by default: only the
    /// rule ID and category are logged.
    pub log_blocked_domains: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceSettings {
    pub schema_version: u32,
    pub protection: ProtectionSettings,
    pub network: NetworkSettings,
    pub privacy: PrivacySettings,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            listen: vec![
                "127.0.0.1:53".parse().expect("valid literal"),
                "[::1]:53".parse().expect("valid literal"),
            ],
            upstreams: Vec::new(),
            fallback_upstreams: vec![
                "9.9.9.9:53".parse().expect("valid literal"),
                "1.1.1.1:53".parse().expect("valid literal"),
            ],
            doh_resolver_ips: default_doh_ips(),
        }
    }
}

impl Default for ProtectionSettings {
    fn default() -> Self {
        Self {
            block_mode: BlockMode::Sinkhole,
            restore_network_on_stop: true,
        }
    }
}

impl Default for ServiceSettings {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA,
            protection: ProtectionSettings::default(),
            network: NetworkSettings::default(),
            privacy: PrivacySettings::default(),
        }
    }
}

/// Well-known public resolvers that serve DoH/DoT. Partial by nature; see
/// docs/THREAT_MODEL.md.
fn default_doh_ips() -> Vec<IpAddr> {
    [
        // Google
        "8.8.8.8",
        "8.8.4.4",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        // Cloudflare (incl. family filters)
        "1.1.1.1",
        "1.0.0.1",
        "1.1.1.2",
        "1.0.0.2",
        "1.1.1.3",
        "1.0.0.3",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        // Quad9
        "9.9.9.9",
        "149.112.112.112",
        "9.9.9.11",
        "149.112.112.11",
        "2620:fe::fe",
        "2620:fe::9",
        // OpenDNS
        "208.67.222.222",
        "208.67.220.220",
        "2620:119:35::35",
        "2620:119:53::53",
        // AdGuard
        "94.140.14.14",
        "94.140.15.15",
    ]
    .iter()
    .map(|s| s.parse().expect("valid literal"))
    .collect()
}

#[derive(Debug)]
pub enum LoadOutcome {
    Loaded(ServiceSettings),
    Migrated {
        settings: ServiceSettings,
        from: u32,
    },
    Missing(ServiceSettings),
    Invalid {
        settings: ServiceSettings,
        reason: String,
    },
}

impl LoadOutcome {
    pub fn settings(&self) -> &ServiceSettings {
        match self {
            LoadOutcome::Loaded(s)
            | LoadOutcome::Missing(s)
            | LoadOutcome::Migrated { settings: s, .. }
            | LoadOutcome::Invalid { settings: s, .. } => s,
        }
    }
}

pub fn parse(text: &str) -> LoadOutcome {
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            return LoadOutcome::Invalid {
                settings: ServiceSettings::default(),
                reason: e.to_string(),
            }
        }
    };
    let from = value
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    if from > CURRENT_SCHEMA {
        return LoadOutcome::Invalid {
            settings: ServiceSettings::default(),
            reason: format!("schema {from} is newer than supported {CURRENT_SCHEMA}"),
        };
    }
    let migrated = migrate(value, from);
    match serde_json::from_value::<ServiceSettings>(migrated) {
        Ok(mut s) => {
            s.schema_version = CURRENT_SCHEMA;
            if from == CURRENT_SCHEMA {
                LoadOutcome::Loaded(s)
            } else {
                LoadOutcome::Migrated { settings: s, from }
            }
        }
        Err(e) => LoadOutcome::Invalid {
            settings: ServiceSettings::default(),
            reason: e.to_string(),
        },
    }
}

/// Apply schema migrations in order. Each step takes version N to N+1.
fn migrate(mut value: serde_json::Value, from: u32) -> serde_json::Value {
    if from < 1 {
        // v0 (pre-release prototype): flat `upstreams` and `block_mode` keys.
        if let Some(obj) = value.as_object_mut() {
            let upstreams = obj.remove("upstreams");
            let block_mode = obj.remove("block_mode");
            let network = obj
                .entry("network")
                .or_insert_with(|| serde_json::json!({}));
            if let (Some(u), Some(n)) = (upstreams, network.as_object_mut()) {
                n.insert("upstreams".into(), u);
            }
            let protection = obj
                .entry("protection")
                .or_insert_with(|| serde_json::json!({}));
            if let (Some(b), Some(p)) = (block_mode, protection.as_object_mut()) {
                p.insert("block_mode".into(), b);
            }
        }
    }
    value
}

pub fn load(path: &Path) -> LoadOutcome {
    match std::fs::read_to_string(path) {
        Ok(text) => parse(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            LoadOutcome::Missing(ServiceSettings::default())
        }
        Err(e) => LoadOutcome::Invalid {
            settings: ServiceSettings::default(),
            reason: e.to_string(),
        },
    }
}

pub fn save(path: &Path, settings: &ServiceSettings) -> std::io::Result<()> {
    let text = serde_json::to_string_pretty(settings).map_err(std::io::Error::other)?;
    crate::fsutil::write_atomic(path, text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_round_trip() {
        let s = ServiceSettings::default();
        let text = serde_json::to_string(&s).unwrap();
        assert!(matches!(parse(&text), LoadOutcome::Loaded(p) if p == s));
    }

    #[test]
    fn missing_fields_take_defaults() {
        let out = parse(r#"{"schema_version":1,"privacy":{"log_blocked_domains":true}}"#);
        let s = out.settings();
        assert!(s.privacy.log_blocked_domains);
        assert_eq!(s.network, NetworkSettings::default());
    }

    #[test]
    fn migrates_v0_flat_layout() {
        let out = parse(r#"{"upstreams":["192.0.2.1:53"],"block_mode":"nxdomain"}"#);
        match out {
            LoadOutcome::Migrated { settings, from } => {
                assert_eq!(from, 0);
                assert_eq!(settings.schema_version, CURRENT_SCHEMA);
                assert_eq!(
                    settings.network.upstreams,
                    vec!["192.0.2.1:53".parse().unwrap()]
                );
                assert_eq!(settings.protection.block_mode, BlockMode::Nxdomain);
            }
            other => panic!("expected migration, got {other:?}"),
        }
    }

    #[test]
    fn corrupt_or_future_settings_fall_back_to_protective_defaults() {
        for text in [
            "{not json",
            r#"{"schema_version":99}"#,
            r#"{"schema_version":1,"network":{"listen":"x"}}"#,
        ] {
            let out = parse(text);
            assert!(matches!(out, LoadOutcome::Invalid { .. }), "{text}");
            assert_eq!(out.settings(), &ServiceSettings::default());
        }
    }
}
