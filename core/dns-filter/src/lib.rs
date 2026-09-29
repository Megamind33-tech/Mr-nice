//! Gambling Guard local filtering DNS resolver.
//!
//! Platform services point the OS resolver at this server. Each query is
//! classified with `gg-rules-engine`. Blocked names get a synthesized answer;
//! everything else is relayed to the upstream resolvers unchanged.
//!
//! This crate performs no OS configuration. Redirecting system DNS and
//! preventing DNS bypass (WFP on Windows, VpnService on Android) belong to
//! the platform layers.

pub mod engine;
pub mod message;
pub mod server;

pub use engine::{
    BlockEvent, BlockSink, Decision, FilterConfig, FilterEngine, StatsSnapshot, Transport,
};
pub use message::BlockResponse;
pub use server::{run_tcp, run_udp};
