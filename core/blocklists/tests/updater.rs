use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;

use gg_blocklist::*;
use gg_crypto::{PublicKey, SecretKey};

fn payload(n: usize, tag: &str) -> String {
    let mut s = String::from("[online_casino]\n");
    for i in 0..n {
        s.push_str(&format!("casino{i}-{tag}.test\n"));
    }
    s
}

fn signed(key: &SecretKey, version: u64, body: &str) -> (Manifest, String) {
    let count = RuleCompiler::compile(body).rule_count as u64;
    let m = Manifest::sign(
        key,
        "gambling",
        version,
        1_790_000_000 + version,
        body.as_bytes(),
        count,
    )
    .unwrap();
    (m, body.to_owned())
}

fn publish(dir: &Path, m: &Manifest, body: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("manifest.json"), m.to_json()).unwrap();
    std::fs::write(dir.join("payload.txt"), body).unwrap();
}

struct Env {
    _tmp: tempfile::TempDir,
    src: std::path::PathBuf,
    repo: BlocklistRepository,
    repo_root: std::path::PathBuf,
    key: SecretKey,
    keys: Vec<PublicKey>,
    policy: UpdatePolicy,
}

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let repo_root = tmp.path().join("repo");
    let key = SecretKey::generate().unwrap();
    let keys = vec![key.public()];
    Env {
        repo: BlocklistRepository::new(&repo_root),
        repo_root,
        src,
        _tmp: tmp,
        key,
        keys,
        policy: UpdatePolicy::default(),
    }
}

impl Env {
    fn updater(&self) -> BlocklistUpdater<'_> {
        BlocklistUpdater {
            keys: &self.keys,
            policy: &self.policy,
            repo: &self.repo,
        }
    }
    fn run(&self) -> UpdateOutcome {
        let p: Vec<Box<dyn BlocklistProvider>> = vec![Box::new(FileProvider::new(&self.src))];
        self.updater().update(&p)
    }
    fn active_version(&self) -> Option<u64> {
        self.repo
            .load(Slot::Active, &self.keys)
            .map(|l| l.manifest.version)
    }
    fn install(&self, version: u64, body: &str) {
        let (m, b) = signed(&self.key, version, body);
        publish(&self.src, &m, &b);
        assert!(matches!(self.run(), UpdateOutcome::Updated { .. }));
    }
}

fn failed_with(outcome: UpdateOutcome, needle: &str) {
    match outcome {
        UpdateOutcome::Failed { errors } => {
            assert!(
                errors.iter().any(|(_, e)| e.contains(needle)),
                "{errors:?} lacks {needle:?}"
            )
        }
        other => panic!("expected failure containing {needle:?}, got {other:?}"),
    }
}

#[test]
fn valid_signed_list_is_activated() {
    let e = env();
    let (m, b) = signed(&e.key, 1, &payload(100, "a"));
    publish(&e.src, &m, &b);
    assert_eq!(e.run(), UpdateOutcome::Updated { from: None, to: 1 });
    let active = e.repo.load(Slot::Active, &e.keys).unwrap();
    let compiled = RuleCompiler::compile(&active.payload);
    assert!(compiled
        .matcher
        .check("www.casino42-a.test")
        .unwrap()
        .is_blocked());
}

#[test]
fn same_version_is_up_to_date_and_older_is_rejected() {
    let e = env();
    e.install(5, &payload(100, "a"));
    assert_eq!(e.run(), UpdateOutcome::UpToDate { version: 5 });
    let (m, b) = signed(&e.key, 4, &payload(100, "old"));
    publish(&e.src, &m, &b);
    failed_with(e.run(), "not newer");
    assert_eq!(e.active_version(), Some(5));
}

#[test]
fn tampered_payload_keeps_current_list() {
    let e = env();
    e.install(1, &payload(100, "a"));
    let (m, _) = signed(&e.key, 2, &payload(100, "b"));
    publish(&e.src, &m, &payload(100, "B"));
    failed_with(e.run(), "hash");
    assert_eq!(e.active_version(), Some(1));
}

#[test]
fn truncated_payload_is_rejected() {
    let e = env();
    let body = payload(100, "a");
    let (m, _) = signed(&e.key, 1, &body);
    publish(&e.src, &m, &body[..body.len() - 5]);
    failed_with(e.run(), "size");
    assert_eq!(e.active_version(), None);
}

#[test]
fn untrusted_key_is_rejected() {
    let e = env();
    let attacker = SecretKey::generate().unwrap();
    let (m, b) = signed(&attacker, 99, &payload(100, "evil"));
    publish(&e.src, &m, &b);
    failed_with(e.run(), "signature");
    assert_eq!(e.active_version(), None);
}

#[test]
fn edited_manifest_field_breaks_signature() {
    let e = env();
    let (mut m, b) = signed(&e.key, 1, &payload(100, "a"));
    m.version = 1000;
    publish(&e.src, &m, &b);
    failed_with(e.run(), "signature");
}

#[test]
fn unknown_manifest_fields_are_rejected() {
    let e = env();
    let (m, b) = signed(&e.key, 1, &payload(100, "a"));
    let mut v: serde_json::Value = serde_json::from_str(&m.to_json()).unwrap();
    v["disable_protection"] = true.into();
    std::fs::create_dir_all(&e.src).unwrap();
    std::fs::write(e.src.join("manifest.json"), v.to_string()).unwrap();
    std::fs::write(e.src.join("payload.txt"), b).unwrap();
    failed_with(e.run(), "unknown field");
}

#[test]
fn signed_but_nearly_empty_list_cannot_disable_blocking() {
    let e = env();
    let (m, b) = signed(&e.key, 1, &payload(3, "tiny"));
    publish(&e.src, &m, &b);
    failed_with(e.run(), "only 3 valid rules");

    e.install(2, &payload(200, "full"));
    let (m, b) = signed(&e.key, 3, &payload(60, "shrunk"));
    publish(&e.src, &m, &b);
    failed_with(e.run(), "shrank");
    assert_eq!(e.active_version(), Some(2));
}

#[test]
fn rule_count_mismatch_and_garbage_are_rejected() {
    let e = env();
    let body = payload(100, "a");
    let m = Manifest::sign(&e.key, "gambling", 1, 1, body.as_bytes(), 500).unwrap();
    publish(&e.src, &m, &body);
    failed_with(e.run(), "declares 500");

    let mut junk = payload(100, "j");
    for i in 0..10 {
        junk.push_str(&format!("bad..{i}\n"));
    }
    let (m, b) = signed(&e.key, 2, &junk);
    publish(&e.src, &m, &b);
    failed_with(e.run(), "invalid lines");
}

#[test]
fn wrong_list_id_is_rejected() {
    let e = env();
    let body = payload(100, "a");
    let m = Manifest::sign(&e.key, "adult", 1, 1, body.as_bytes(), 100).unwrap();
    publish(&e.src, &m, &body);
    failed_with(e.run(), "does not match expected list");
}

#[test]
fn corrupted_active_falls_back_to_previous() {
    let e = env();
    e.install(1, &payload(100, "a"));
    e.install(2, &payload(100, "b"));
    let active_payload = e.repo_root.join("active/payload.txt");
    let mut text = std::fs::read_to_string(&active_payload).unwrap();
    text.push_str("injected.test\n");
    std::fs::write(&active_payload, text).unwrap();
    let (slot, list) = e.repo.load_best(&e.keys).unwrap();
    assert_eq!((slot, list.manifest.version), (Slot::Previous, 1));
}

#[test]
fn source_failover_uses_next_provider() {
    let e = env();
    let good = e._tmp.path().join("good");
    let (m, b) = signed(&e.key, 1, &payload(100, "a"));
    publish(&good, &m, &b);
    let providers: Vec<Box<dyn BlocklistProvider>> = vec![
        Box::new(FileProvider::new(e._tmp.path().join("missing"))),
        Box::new(FileProvider::new(&good)),
    ];
    assert_eq!(
        e.updater().update(&providers),
        UpdateOutcome::Updated { from: None, to: 1 }
    );
}

#[test]
fn bundled_seed_first_run_upgrade_and_rejection() {
    let e = env();
    let (m1, b1) = signed(&e.key, 1, &payload(100, "seed"));
    let j1 = m1.to_json();
    let u = e.updater();
    assert_eq!(
        u.load_or_seed(Some((j1.as_bytes(), b1.as_bytes())))
            .unwrap()
            .manifest
            .version,
        1
    );
    assert_eq!(e.active_version(), Some(1), "seed cached");

    let (m3, b3) = signed(&e.key, 3, &payload(120, "newer"));
    let j3 = m3.to_json();
    assert_eq!(
        u.load_or_seed(Some((j3.as_bytes(), b3.as_bytes())))
            .unwrap()
            .manifest
            .version,
        3
    );

    // Older bundle does not replace newer stored list.
    assert_eq!(
        u.load_or_seed(Some((j1.as_bytes(), b1.as_bytes())))
            .unwrap()
            .manifest
            .version,
        3
    );

    // Tampered bundle is ignored; stored list still served.
    assert_eq!(
        u.load_or_seed(Some((j3.as_bytes(), b"tampered")))
            .unwrap()
            .manifest
            .version,
        3
    );
}

#[test]
fn no_seed_and_no_store_yields_none() {
    let e = env();
    assert!(e.updater().load_or_seed(None).is_none());
}

/// Minimal HTTP/1.1 server returning fixed bodies for two paths.
fn serve(manifest: String, body: String, requests: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(requests) {
            let mut s = stream.unwrap();
            let mut buf = [0u8; 2048];
            let n = s.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            let content = if req.starts_with("GET /lists/manifest.json") {
                &manifest
            } else if req.starts_with("GET /lists/payload.txt") {
                &body
            } else {
                ""
            };
            let status = if content.is_empty() {
                "404 Not Found"
            } else {
                "200 OK"
            };
            write!(
                s,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{content}",
                content.len()
            )
            .unwrap();
        }
    });
    format!("http://{addr}/lists/")
}

#[test]
fn http_provider_end_to_end() {
    let e = env();
    let (m, b) = signed(&e.key, 7, &payload(100, "http"));
    let url = serve(m.to_json(), b, 2);
    let providers = vec![from_source(&url).unwrap()];
    assert_eq!(
        e.updater().update(&providers),
        UpdateOutcome::Updated { from: None, to: 7 }
    );
}

#[test]
fn http_size_limits_are_enforced() {
    let e = env();
    let (m, b) = signed(&e.key, 1, &payload(100, "big"));
    let url = serve(m.to_json(), b, 2);
    let p = from_source(&url).unwrap();
    assert!(matches!(
        p.fetch_manifest(10),
        Err(ProviderError::TooLarge(10))
    ));
}

#[test]
fn declared_oversize_payload_is_not_downloaded() {
    let mut e = env();
    e.policy.max_payload_bytes = 100;
    let (m, b) = signed(&e.key, 1, &payload(100, "a"));
    publish(&e.src, &m, &b);
    failed_with(e.run(), "exceeds limit");
}

#[test]
fn unsupported_source_scheme() {
    assert!(from_source("ftp://example.com/list").is_err());
}
