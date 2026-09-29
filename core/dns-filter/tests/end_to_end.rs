//! Runs the real UDP/TCP listeners on loopback against a fake upstream.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gg_dns_filter::message::{build_query, summarize_response, ResponseSummary, TYPE_A, TYPE_AAAA};
use gg_dns_filter::{run_tcp, run_udp, BlockEvent, BlockSink, FilterConfig, FilterEngine};
use gg_rules_engine::{Category, Rule, RuleMatcher};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const UPSTREAM_IP: [u8; 4] = [203, 0, 113, 7];

/// Upstream that answers every A query with 203.0.113.7.
async fn fake_upstream() -> SocketAddr {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
            udp.send_to(&answer(&buf[..n]), peer).await.unwrap();
        }
    });
    tokio::spawn(async move {
        loop {
            let (mut s, _) = tcp.accept().await.unwrap();
            let len = s.read_u16().await.unwrap() as usize;
            let mut q = vec![0; len];
            s.read_exact(&mut q).await.unwrap();
            let a = answer(&q);
            s.write_u16(a.len() as u16).await.unwrap();
            s.write_all(&a).await.unwrap();
        }
    });
    addr
}

fn answer(q: &[u8]) -> Vec<u8> {
    let mut r = q.to_vec();
    r[2] |= 0x80; // QR
    r[3] |= 0x80; // RA
    r[7] = 1; // ANCOUNT
    r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    r.extend_from_slice(&UPSTREAM_IP);
    r
}

#[derive(Default)]
struct RecordingSink(Mutex<Vec<String>>);
impl BlockSink for RecordingSink {
    fn on_block(&self, e: &BlockEvent<'_>) {
        self.0
            .lock()
            .unwrap()
            .push(format!("{}:{}", e.rule, e.category));
    }
}

fn rules(list: &[&str]) -> RuleMatcher {
    RuleMatcher::from_rules(
        list.iter()
            .map(|l| Rule::parse(l, Category::OnlineCasino).unwrap()),
    )
}

struct Harness {
    engine: Arc<FilterEngine>,
    addr: SocketAddr,
    sink: Arc<RecordingSink>,
}

async fn start(list: &[&str], upstreams: Vec<SocketAddr>) -> Harness {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).await.unwrap();
    let sink = Arc::new(RecordingSink::default());
    let config = FilterConfig {
        upstream_timeout: Duration::from_millis(500),
        listen_addrs: vec![addr],
        ..Default::default()
    };
    let engine = FilterEngine::new(config, rules(list), upstreams, Some(sink.clone()));
    tokio::spawn(run_udp(engine.clone(), udp));
    tokio::spawn(run_tcp(engine.clone(), tcp));
    Harness { engine, addr, sink }
}

async fn udp_ask(server: SocketAddr, name: &str, qtype: u16) -> ResponseSummary {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&build_query(0x1234, name, qtype), server)
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf))
        .await
        .expect("filter did not answer")
        .unwrap();
    summarize_response(&buf[..n]).unwrap()
}

async fn tcp_ask(server: SocketAddr, name: &str, qtype: u16) -> ResponseSummary {
    let mut s = TcpStream::connect(server).await.unwrap();
    let q = build_query(0x4321, name, qtype);
    s.write_u16(q.len() as u16).await.unwrap();
    s.write_all(&q).await.unwrap();
    let len = s.read_u16().await.unwrap() as usize;
    let mut r = vec![0; len];
    s.read_exact(&mut r).await.unwrap();
    summarize_response(&r).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn blocked_domain_is_sinkholed_over_udp_and_tcp() {
    let h = start(&["gambling-test.local"], vec![fake_upstream().await]).await;
    for name in ["gambling-test.local", "WWW.Gambling-Test.LOCAL."] {
        let r = udp_ask(h.addr, name, TYPE_A).await;
        assert_eq!(r.first_rdata.as_deref(), Some(&[0u8; 4][..]), "{name}");
        let r = tcp_ask(h.addr, name, TYPE_A).await;
        assert_eq!(r.first_rdata.as_deref(), Some(&[0u8; 4][..]), "{name}");
    }
    let r = udp_ask(h.addr, "gambling-test.local", TYPE_AAAA).await;
    assert_eq!(r.first_rdata.as_deref(), Some(&[0u8; 16][..]));
    assert_eq!(h.engine.stats().blocked, 5);
    assert_eq!(h.sink.0.lock().unwrap().len(), 5);
    assert_eq!(h.sink.0.lock().unwrap()[0], "R0:online_casino");
}

#[tokio::test(flavor = "multi_thread")]
async fn allowed_domain_is_forwarded() {
    let h = start(&["gambling-test.local"], vec![fake_upstream().await]).await;
    let r = udp_ask(h.addr, "news.example", TYPE_A).await;
    assert_eq!(r.id, 0x1234);
    assert_eq!(r.first_rdata.as_deref(), Some(&UPSTREAM_IP[..]));
    let r = tcp_ask(h.addr, "news.example", TYPE_A).await;
    assert_eq!(r.first_rdata.as_deref(), Some(&UPSTREAM_IP[..]));
    assert_eq!(h.engine.stats().forwarded, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn removing_rule_restores_access_without_restart() {
    let h = start(&["gambling-test.local"], vec![fake_upstream().await]).await;
    let r = udp_ask(h.addr, "gambling-test.local", TYPE_A).await;
    assert_eq!(r.first_rdata.as_deref(), Some(&[0u8; 4][..]));

    h.engine.replace_rules(rules(&[]));
    let r = udp_ask(h.addr, "gambling-test.local", TYPE_A).await;
    assert_eq!(r.first_rdata.as_deref(), Some(&UPSTREAM_IP[..]));

    h.engine.replace_rules(rules(&["gambling-test.local"]));
    let r = udp_ask(h.addr, "gambling-test.local", TYPE_A).await;
    assert_eq!(r.first_rdata.as_deref(), Some(&[0u8; 4][..]));
}

#[tokio::test(flavor = "multi_thread")]
async fn blocking_works_with_no_upstream_at_all() {
    // Filtering must not depend on network availability.
    let h = start(&["gambling-test.local"], vec![]).await;
    let r = udp_ask(h.addr, "gambling-test.local", TYPE_A).await;
    assert_eq!(r.first_rdata.as_deref(), Some(&[0u8; 4][..]));
    let r = udp_ask(h.addr, "news.example", TYPE_A).await;
    assert_eq!(r.rcode, 2, "SERVFAIL when no upstream is reachable");
}

#[tokio::test(flavor = "multi_thread")]
async fn dead_upstream_falls_back_to_next() {
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap(); // bound, never answers
    let h = start(&[], vec![dead.local_addr().unwrap(), fake_upstream().await]).await;
    let r = udp_ask(h.addr, "news.example", TYPE_A).await;
    assert_eq!(r.first_rdata.as_deref(), Some(&UPSTREAM_IP[..]));
}

#[tokio::test(flavor = "multi_thread")]
async fn self_referencing_upstream_is_ignored() {
    let h = start(&[], vec![]).await;
    h.engine.set_upstreams(vec![h.addr]);
    assert!(h.engine.upstreams().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_input_does_not_kill_server() {
    let h = start(&["gambling-test.local"], vec![fake_upstream().await]).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for junk in [&[1u8, 2, 3][..], &[0xAB; 40][..], &[0u8; 12][..]] {
        sock.send_to(junk, h.addr).await.unwrap();
    }
    let r = udp_ask(h.addr, "gambling-test.local", TYPE_A).await;
    assert_eq!(r.first_rdata.as_deref(), Some(&[0u8; 4][..]));
    assert!(h.engine.stats().malformed >= 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn firefox_doh_canary_gets_nxdomain() {
    let h = start(&[], vec![fake_upstream().await]).await;
    let r = udp_ask(h.addr, "use-application-dns.net", TYPE_A).await;
    assert_eq!((r.rcode, r.answer_count), (3, 0));
    // Subdomains are not the canary and are forwarded normally.
    let r = udp_ask(h.addr, "x.use-application-dns.net", TYPE_A).await;
    assert_eq!(r.first_rdata.as_deref(), Some(&UPSTREAM_IP[..]));
}
