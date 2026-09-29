//! Service runtime shared by the Windows service and console mode.
//!
//! Order on start: bind listeners → compile rules → take over system DNS and
//! install bypass filters. Filtering is therefore live before the OS is
//! pointed at it. On a clean stop, the system integration is removed only if
//! settings allow; otherwise resolution fails closed until restart.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gg_dns_filter::{run_tcp, run_udp, BlockEvent, BlockSink, FilterConfig, FilterEngine};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;

use crate::rules_store::{Fingerprint, RulesStore};
use crate::settings::ServiceSettings;
use crate::status::{Components, StatusReport};

const RULE_POLL: Duration = Duration::from_secs(3);
const REASSERT_EVERY: Duration = Duration::from_secs(15);

/// OS-specific enforcement around the filter: redirect system DNS to it and
/// block ways around it.
pub trait SystemIntegration: Send {
    /// Resolvers the system was using before takeover (excluding loopback).
    fn discover_upstreams(&mut self) -> Vec<SocketAddr>;
    /// Point system DNS at the local filter. Called repeatedly; must be
    /// idempotent. Returns whether every active adapter is covered.
    fn ensure_dns_takeover(&mut self) -> bool;
    /// Install bypass-prevention filters. Idempotent. Returns whether they
    /// are present.
    fn ensure_bypass_filters(&mut self) -> bool;
    /// Called after the rule set changes so cached answers are dropped.
    fn flush_dns_cache(&mut self) {}
    /// Undo DNS takeover and remove filters.
    fn remove(&mut self);
}

/// Console/testing integration that changes nothing on the system. Health
/// is reported honestly as ACTION_REQUIRED because no takeover happens.
pub struct NoSystemIntegration;

impl SystemIntegration for NoSystemIntegration {
    fn discover_upstreams(&mut self) -> Vec<SocketAddr> {
        Vec::new()
    }
    fn ensure_dns_takeover(&mut self) -> bool {
        false
    }
    fn ensure_bypass_filters(&mut self) -> bool {
        false
    }
    fn remove(&mut self) {}
}

struct LogSink {
    log_domains: bool,
}

impl BlockSink for LogSink {
    fn on_block(&self, e: &BlockEvent<'_>) {
        if self.log_domains {
            tracing::info!(event = "BLOCK_EVENT", rule = %e.rule, category = %e.category, qtype = e.qtype, domain = e.name);
        } else {
            tracing::info!(event = "BLOCK_EVENT", rule = %e.rule, category = %e.category, qtype = e.qtype);
        }
    }
}

pub struct RuntimeConfig {
    pub settings: ServiceSettings,
    pub rules_dir: PathBuf,
    pub status_path: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("no DNS listener could be started")]
    NoListener,
}

pub async fn run(
    config: RuntimeConfig,
    mut integration: Box<dyn SystemIntegration>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), RuntimeError> {
    let settings = &config.settings;
    let store = RulesStore::new(&config.rules_dir);

    // 1. Listeners first, so nothing is redirected to a dead port.
    let mut bound = Vec::new();
    let mut listen_ok = true;
    for addr in &settings.network.listen {
        match (UdpSocket::bind(addr).await, TcpListener::bind(addr).await) {
            (Ok(u), Ok(t)) => bound.push((*addr, u, t)),
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(event = "FILTER_FAILURE", %addr, error = %e, "listener bind failed");
                listen_ok = false;
            }
        }
    }
    if bound.is_empty() {
        return Err(RuntimeError::NoListener);
    }
    let listen_addrs: Vec<SocketAddr> = bound.iter().map(|(a, _, _)| *a).collect();

    // 2. Rules.
    let compiled = store.compile();
    let mut rules_ok = compiled.unreadable.is_empty() && !compiled.matcher.is_empty();
    log_ruleset(&compiled);
    let mut fingerprint: Fingerprint = compiled.fingerprint;

    let filter_config = FilterConfig {
        block_response: settings.protection.block_mode.into(),
        listen_addrs: listen_addrs.clone(),
        ..FilterConfig::default()
    };
    let sink = Arc::new(LogSink {
        log_domains: settings.privacy.log_blocked_domains,
    });
    let engine = FilterEngine::new(filter_config, compiled.matcher, Vec::new(), Some(sink));

    let mut tasks = Vec::new();
    for (addr, udp, tcp) in bound {
        tasks.push(tokio::spawn(run_udp(engine.clone(), udp)));
        tasks.push(tokio::spawn(run_tcp(engine.clone(), tcp)));
        tracing::info!(event = "FILTER_INSTALL", %addr, "DNS filter listening");
    }

    // 3. Upstreams, captured before takeover changes adapter settings.
    let upstreams = choose_upstreams(settings, integration.discover_upstreams());
    engine.set_upstreams(upstreams);

    // 4. System integration.
    let mut components = Components {
        dns_listener: listen_ok,
        rules_loaded: rules_ok,
        bypass_filters: integration.ensure_bypass_filters(),
        dns_takeover: integration.ensure_dns_takeover(),
    };
    integration.flush_dns_cache();
    tracing::info!(event = "SERVICE_START", health = ?components.health(), ?components);

    let mut last_reassert = Instant::now();
    let mut tick = tokio::time::interval(RULE_POLL);
    loop {
        write_status(&config, &engine, components);
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => break,
        }

        let fp = store.fingerprint();
        if fp != fingerprint {
            let compiled = store.compile();
            log_ruleset(&compiled);
            rules_ok = compiled.unreadable.is_empty() && !compiled.matcher.is_empty();
            fingerprint = compiled.fingerprint;
            engine.replace_rules(compiled.matcher);
            integration.flush_dns_cache();
            components.rules_loaded = rules_ok;
        }

        if last_reassert.elapsed() >= REASSERT_EVERY {
            last_reassert = Instant::now();
            let before = components;
            components.bypass_filters = integration.ensure_bypass_filters();
            components.dns_takeover = integration.ensure_dns_takeover();
            if components != before {
                tracing::warn!(event = "TAMPER_OR_NETWORK_CHANGE", ?before, after = ?components, health = ?components.health());
            }
        }
    }

    tracing::info!(
        event = "SERVICE_STOP",
        restore = settings.protection.restore_network_on_stop
    );
    if settings.protection.restore_network_on_stop {
        integration.remove();
    }
    for t in tasks {
        t.abort();
    }
    Ok(())
}

fn choose_upstreams(settings: &ServiceSettings, discovered: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let net = &settings.network;
    let chosen = if !net.upstreams.is_empty() {
        net.upstreams.clone()
    } else if !discovered.is_empty() {
        discovered
    } else {
        net.fallback_upstreams.clone()
    };
    tracing::info!(upstreams = ?chosen, "upstream resolvers selected");
    chosen
}

fn log_ruleset(c: &crate::rules_store::Compiled) {
    tracing::info!(
        event = "RULESET_UPDATE",
        rules = c.matcher.len(),
        files = c.files,
        line_errors = c.line_errors,
        unreadable = c.unreadable.len()
    );
}

fn write_status(config: &RuntimeConfig, engine: &FilterEngine, components: Components) {
    let Some(path) = &config.status_path else {
        return;
    };
    let s = engine.stats();
    let report = StatusReport {
        health: components.health(),
        components,
        rule_count: engine.rules().len(),
        upstreams: engine.upstreams().iter().map(|u| u.to_string()).collect(),
        queries: s.queries,
        blocked: s.blocked,
        forwarded: s.forwarded,
        upstream_failures: s.upstream_failures,
        service_pid: std::process::id(),
        updated_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    };
    if let Ok(text) = serde_json::to_string_pretty(&report) {
        if let Err(e) = crate::fsutil::write_atomic(path, text.as_bytes()) {
            tracing::debug!(error = %e, "status write failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_precedence() {
        let mut s = ServiceSettings::default();
        let d: SocketAddr = "192.0.2.53:53".parse().unwrap();
        assert_eq!(choose_upstreams(&s, vec![d]), vec![d]);
        assert_eq!(choose_upstreams(&s, vec![]), s.network.fallback_upstreams);
        let explicit: SocketAddr = "198.51.100.1:53".parse().unwrap();
        s.network.upstreams = vec![explicit];
        assert_eq!(choose_upstreams(&s, vec![d]), vec![explicit]);
    }
}
