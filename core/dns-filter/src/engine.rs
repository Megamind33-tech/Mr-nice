//! Filtering decision and upstream forwarding.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use gg_rules_engine::{Category, Domain, RuleId, RuleMatcher, Verdict};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::message::{
    bare_error_response, blocked_response, error_response, parse_query, read_id,
    summarize_response, BlockResponse, ParseError, Query, Rcode,
};

#[derive(Debug, Clone)]
pub struct FilterConfig {
    pub block_response: BlockResponse,
    pub upstream_timeout: Duration,
    /// Addresses this filter listens on. Upstreams equal to one of these are
    /// ignored so a misconfiguration cannot create a forwarding loop.
    pub listen_addrs: Vec<SocketAddr>,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            block_response: BlockResponse::Sinkhole,
            upstream_timeout: Duration::from_secs(3),
            listen_addrs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Block {
        rule: RuleId,
        category: Category,
    },
    Forward,
    /// Name cannot be a valid hostname; refuse rather than forward, so
    /// oddly-encoded names can never slip past matching.
    Refuse,
}

/// Emitted for every blocked query. The sink decides what (if anything) to
/// record; the engine never persists names itself.
#[derive(Debug, Clone)]
pub struct BlockEvent<'a> {
    pub rule: RuleId,
    pub category: &'a Category,
    pub qtype: u16,
    pub name: &'a str,
}

pub trait BlockSink: Send + Sync {
    fn on_block(&self, event: &BlockEvent<'_>);
}

#[derive(Debug, Default)]
pub struct Stats {
    pub queries: AtomicU64,
    pub blocked: AtomicU64,
    pub forwarded: AtomicU64,
    pub refused: AtomicU64,
    pub malformed: AtomicU64,
    pub upstream_failures: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatsSnapshot {
    pub queries: u64,
    pub blocked: u64,
    pub forwarded: u64,
    pub refused: u64,
    pub malformed: u64,
    pub upstream_failures: u64,
}

impl Stats {
    pub fn snapshot(&self) -> StatsSnapshot {
        let l = |c: &AtomicU64| c.load(Ordering::Relaxed);
        StatsSnapshot {
            queries: l(&self.queries),
            blocked: l(&self.blocked),
            forwarded: l(&self.forwarded),
            refused: l(&self.refused),
            malformed: l(&self.malformed),
            upstream_failures: l(&self.upstream_failures),
        }
    }
}

fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

pub struct FilterEngine {
    rules: RwLock<Arc<RuleMatcher>>,
    upstreams: RwLock<Arc<Vec<SocketAddr>>>,
    config: FilterConfig,
    stats: Stats,
    sink: Option<Arc<dyn BlockSink>>,
}

impl FilterEngine {
    pub fn new(
        config: FilterConfig,
        rules: RuleMatcher,
        upstreams: Vec<SocketAddr>,
        sink: Option<Arc<dyn BlockSink>>,
    ) -> Arc<Self> {
        let engine = Arc::new(Self {
            rules: RwLock::new(Arc::new(rules)),
            upstreams: RwLock::new(Arc::new(Vec::new())),
            config,
            stats: Stats::default(),
            sink,
        });
        engine.set_upstreams(upstreams);
        engine
    }

    /// Atomically swap in a new compiled rule set. In-flight queries finish
    /// against the set they started with.
    pub fn replace_rules(&self, rules: RuleMatcher) {
        *self.rules.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(rules);
    }

    pub fn rules(&self) -> Arc<RuleMatcher> {
        self.rules.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_upstreams(&self, upstreams: Vec<SocketAddr>) {
        let filtered: Vec<_> = upstreams
            .into_iter()
            .filter(|u| !self.config.listen_addrs.contains(u))
            .collect();
        *self.upstreams.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(filtered);
    }

    pub fn upstreams(&self) -> Arc<Vec<SocketAddr>> {
        self.upstreams
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    pub fn decide(&self, query: &Query<'_>) -> Decision {
        let Some(name) = query.name.as_deref() else {
            return Decision::Refuse;
        };
        if name.is_empty() {
            // Root-zone queries (priming) carry no hostname to classify.
            return Decision::Forward;
        }
        let Ok(domain) = Domain::parse(name) else {
            return Decision::Refuse;
        };
        match self.rules().verdict(&domain) {
            Verdict::Block { rule, category } => Decision::Block { rule, category },
            Verdict::Allow => Decision::Forward,
        }
    }

    /// Handle one DNS message. `None` means drop silently (not even a header
    /// to reply to, or the input was itself a response).
    pub async fn handle(&self, packet: &[u8], transport: Transport) -> Option<Vec<u8>> {
        bump(&self.stats.queries);
        let query = match parse_query(packet) {
            Ok(q) => q,
            Err(ParseError::TooShort | ParseError::NotAQuery) => {
                bump(&self.stats.malformed);
                return None;
            }
            Err(ParseError::UnsupportedOpcode) => {
                bump(&self.stats.malformed);
                return Some(bare_error_response(read_id(packet)?, Rcode::NotImp));
            }
            Err(ParseError::Malformed | ParseError::QuestionCount) => {
                bump(&self.stats.malformed);
                return Some(bare_error_response(read_id(packet)?, Rcode::FormErr));
            }
        };

        match self.decide(&query) {
            Decision::Block { rule, category } => {
                bump(&self.stats.blocked);
                if let Some(sink) = &self.sink {
                    sink.on_block(&BlockEvent {
                        rule,
                        category: &category,
                        qtype: query.qtype,
                        name: query.name.as_deref().unwrap_or_default(),
                    });
                }
                Some(blocked_response(&query, self.config.block_response))
            }
            Decision::Refuse => {
                bump(&self.stats.refused);
                Some(error_response(&query, Rcode::Refused))
            }
            Decision::Forward => match self.forward(packet, query.id, transport).await {
                Some(resp) => {
                    bump(&self.stats.forwarded);
                    Some(resp)
                }
                None => {
                    bump(&self.stats.upstream_failures);
                    Some(error_response(&query, Rcode::ServFail))
                }
            },
        }
    }

    async fn forward(&self, packet: &[u8], id: u16, transport: Transport) -> Option<Vec<u8>> {
        for upstream in self.upstreams().iter() {
            let result = match transport {
                Transport::Udp => {
                    forward_udp(packet, id, *upstream, self.config.upstream_timeout).await
                }
                Transport::Tcp => {
                    forward_tcp(packet, id, *upstream, self.config.upstream_timeout).await
                }
            };
            match result {
                Ok(resp) => return Some(resp),
                Err(e) => tracing::debug!(%upstream, error = %e, "upstream attempt failed"),
            }
        }
        None
    }
}

fn unspecified_for(addr: &SocketAddr) -> SocketAddr {
    let ip = match addr.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    SocketAddr::new(ip, 0)
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "upstream timed out")
}

async fn forward_udp(
    packet: &[u8],
    id: u16,
    upstream: SocketAddr,
    limit: Duration,
) -> io::Result<Vec<u8>> {
    // Fresh socket per query: random source port, and `connect` makes the OS
    // discard datagrams from any address other than the upstream.
    let sock = UdpSocket::bind(unspecified_for(&upstream)).await?;
    sock.connect(upstream).await?;
    sock.send(packet).await?;
    let mut buf = vec![0u8; 65_535];
    timeout(limit, async {
        loop {
            let n = sock.recv(&mut buf).await?;
            // Ignore stray datagrams that are not the matching response.
            if summarize_response(&buf[..n]).is_some_and(|s| s.id == id) {
                return Ok(buf[..n].to_vec());
            }
        }
    })
    .await
    .map_err(|_| timed_out())?
}

async fn forward_tcp(
    packet: &[u8],
    id: u16,
    upstream: SocketAddr,
    limit: Duration,
) -> io::Result<Vec<u8>> {
    timeout(limit, async {
        let mut stream = TcpStream::connect(upstream).await?;
        let len = u16::try_from(packet.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "query too large"))?;
        let mut framed = Vec::with_capacity(packet.len() + 2);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(packet);
        stream.write_all(&framed).await?;
        let resp_len = stream.read_u16().await? as usize;
        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp).await?;
        if summarize_response(&resp).is_some_and(|s| s.id == id) {
            Ok(resp)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mismatched upstream response",
            ))
        }
    })
    .await
    .map_err(|_| timed_out())?
}
