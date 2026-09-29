//! Publisher tool: generate keys, sign and verify blocklist bundles.
//!
//! ```text
//! gg-blocklist-tool keygen <secret-key-file>
//! gg-blocklist-tool sign --key <secret-key-file> --list-id gambling \
//!     --version <n> --payload <payload.txt> --out <manifest.json> [--generated-at <unix>]
//! gg-blocklist-tool verify --pubkey <hex> --manifest <manifest.json> --payload <payload.txt>
//! ```
//!
//! The secret key file must stay offline. Only the public key is shipped.

use std::collections::HashMap;
use std::process::ExitCode;

use gg_blocklist::{Manifest, RuleCompiler, UpdatePolicy};
use gg_crypto::{PublicKey, SecretKey};

fn flags(args: &[String]) -> HashMap<&str, &str> {
    args.chunks(2)
        .filter_map(|c| match c {
            [k, v] => k.strip_prefix("--").map(|k| (k, v.as_str())),
            _ => None,
        })
        .collect()
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("error: {msg}");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let Some(path) = args.get(1) else {
                return fail("missing key file path");
            };
            if std::path::Path::new(path).exists() {
                return fail("refusing to overwrite existing key file");
            }
            let key = match SecretKey::generate() {
                Ok(k) => k,
                Err(e) => return fail(e),
            };
            if let Err(e) = std::fs::write(path, key.to_hex().as_bytes()) {
                return fail(e);
            }
            println!("{}", key.public().to_hex());
            ExitCode::SUCCESS
        }
        Some("sign") => {
            let f = flags(&args[1..]);
            let (Some(k), Some(v), Some(p), Some(o)) = (
                f.get("key"),
                f.get("version"),
                f.get("payload"),
                f.get("out"),
            ) else {
                return fail("sign needs --key --version --payload --out");
            };
            let list_id = f.get("list-id").copied().unwrap_or("gambling");
            let Ok(version) = v.parse::<u64>() else {
                return fail("bad --version");
            };
            let generated_at = match f.get("generated-at") {
                Some(t) => match t.parse() {
                    Ok(t) => t,
                    Err(_) => return fail("bad --generated-at"),
                },
                None => std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            };
            let key = match std::fs::read_to_string(k).map(|t| SecretKey::from_hex(&t)) {
                Ok(Ok(key)) => key,
                Ok(Err(e)) => return fail(e),
                Err(e) => return fail(e),
            };
            let payload = match std::fs::read(p) {
                Ok(b) => b,
                Err(e) => return fail(e),
            };
            let Ok(text) = std::str::from_utf8(&payload) else {
                return fail("payload not UTF-8");
            };
            let compiled = RuleCompiler::compile(text);
            if compiled.error_lines > 0 {
                return fail(format!(
                    "{} invalid lines; fix before signing",
                    compiled.error_lines
                ));
            }
            let m = match Manifest::sign(
                &key,
                list_id,
                version,
                generated_at,
                &payload,
                compiled.rule_count as u64,
            ) {
                Ok(m) => m,
                Err(e) => return fail(e),
            };
            if let Err(e) = std::fs::write(o, m.to_json() + "\n") {
                return fail(e);
            }
            println!(
                "signed {list_id} v{version}: {} rules, sha256 {}",
                m.rule_count, m.sha256
            );
            ExitCode::SUCCESS
        }
        Some("verify") => {
            let f = flags(&args[1..]);
            let (Some(k), Some(m), Some(p)) =
                (f.get("pubkey"), f.get("manifest"), f.get("payload"))
            else {
                return fail("verify needs --pubkey --manifest --payload");
            };
            let key = match PublicKey::from_hex(k) {
                Ok(k) => k,
                Err(e) => return fail(e),
            };
            let (Ok(mb), Ok(pb)) = (std::fs::read(m), std::fs::read(p)) else {
                return fail("cannot read manifest or payload");
            };
            let list = match gg_blocklist::VerifiedList::verify(&[key], &mb, &pb) {
                Ok(l) => l,
                Err(e) => return fail(e),
            };
            let policy = UpdatePolicy {
                list_id: list.manifest.list_id.clone(),
                ..UpdatePolicy::default()
            };
            let repo = gg_blocklist::BlocklistRepository::new(
                std::env::temp_dir().join("gg-verify-unused"),
            );
            let keys = [PublicKey::from_hex(k).expect("already parsed")];
            let updater = gg_blocklist::BlocklistUpdater {
                keys: &keys,
                policy: &policy,
                repo: &repo,
            };
            match updater.accept(&list, None) {
                Ok(()) => {
                    println!(
                        "OK {} v{} ({} rules)",
                        list.manifest.list_id, list.manifest.version, list.manifest.rule_count
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => fail(format!("signature valid but list would be rejected: {e}")),
            }
        }
        _ => {
            eprintln!("usage: gg-blocklist-tool keygen <file> | sign ... | verify ...");
            ExitCode::from(2)
        }
    }
}
