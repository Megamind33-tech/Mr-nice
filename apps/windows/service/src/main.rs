//! Gambling Guard service core (platform-independent parts).
//!
//! The Windows system-integration layer is not included in this crate yet.
//! `console` runs the local DNS filter with no system changes, for testing.

mod blocklist;
mod fsutil;
mod paths;
mod rules_store;
mod runtime;
mod settings;
mod status;

use std::net::SocketAddr;

use tokio::sync::watch;

fn usage() -> ! {
    eprintln!("usage: gambling-guard-service console [--listen ADDR]... | rules add|remove DOMAIN | rules list | blocklist status|update | status");
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let paths = paths::DataPaths::resolve();
    let store = rules_store::RulesStore::new(paths.rules_dir());
    match args.first().map(String::as_str) {
        Some("console") => console(&args[1..], &paths),
        Some("rules") => match (args.get(1).map(String::as_str), args.get(2)) {
            (Some("add"), Some(d)) => report(store.add_user_domain(d), "added", "already present"),
            (Some("remove"), Some(d)) => {
                report(store.remove_user_domain(d), "removed", "not present")
            }
            (Some("list"), None) => {
                for d in store.user_domains().unwrap_or_default() {
                    println!("{d}");
                }
            }
            _ => usage(),
        },
        Some("blocklist") => blocklist_cmd(args.get(1).map(String::as_str), &paths),
        Some("status") => match std::fs::read_to_string(paths.status()) {
            Ok(t) => println!("{t}"),
            Err(e) => {
                eprintln!("no status available: {e}");
                std::process::exit(1)
            }
        },
        _ => usage(),
    }
}

fn report(r: Result<bool, rules_store::StoreError>, yes: &str, no: &str) {
    match r {
        Ok(true) => println!("{yes}"),
        Ok(false) => println!("{no}"),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1)
        }
    }
}

fn console(args: &[String], paths: &paths::DataPaths) {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let loaded = settings::load(&paths.settings());
    match &loaded {
        settings::LoadOutcome::Migrated { from, .. } => {
            tracing::info!(from, "settings migrated to current schema")
        }
        settings::LoadOutcome::Invalid { reason, .. } => {
            tracing::warn!(%reason, "settings invalid; using protective defaults")
        }
        settings::LoadOutcome::Missing(defaults) => {
            if let Err(e) = std::fs::create_dir_all(&paths.root)
                .and_then(|_| settings::save(&paths.settings(), defaults))
            {
                tracing::warn!(error = %e, "could not write default settings");
            }
        }
        settings::LoadOutcome::Loaded(_) => {}
    }
    let mut settings = loaded.settings().clone();
    let mut listen = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match (a.as_str(), it.next()) {
            ("--listen", Some(v)) => {
                listen.push(v.parse::<SocketAddr>().unwrap_or_else(|_| usage()))
            }
            _ => usage(),
        }
    }
    if !listen.is_empty() {
        settings.network.listen = listen;
    }
    let store = rules_store::RulesStore::new(paths.rules_dir());
    if let Err(e) = store.ensure_layout() {
        eprintln!("cannot create rules directory: {e}");
        std::process::exit(1)
    }
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = tx.send(true);
        });
        let cfg = runtime::RuntimeConfig {
            settings,
            rules_dir: paths.rules_dir(),
            blocklist_dir: paths.blocklist_dir(),
            status_path: Some(paths.status()),
        };
        if let Err(e) = runtime::run(cfg, Box::new(runtime::NoSystemIntegration), rx).await {
            eprintln!("error: {e}");
            std::process::exit(1)
        }
    });
}

fn blocklist_cmd(sub: Option<&str>, paths: &paths::DataPaths) {
    let settings = settings::load(&paths.settings()).settings().clone();
    let mut manager = blocklist::BlocklistManager::new(paths.blocklist_dir(), settings.blocklist);
    match sub {
        Some("status") => {}
        Some("update") => {
            let outcome = manager.job().run();
            println!("{outcome:?}");
            manager.reload();
            if matches!(outcome, gg_blocklist::UpdateOutcome::Failed { .. }) {
                print_blocklist(&manager);
                std::process::exit(1);
            }
        }
        _ => usage(),
    }
    print_blocklist(&manager);
}

fn print_blocklist(manager: &blocklist::BlocklistManager) {
    match manager.status(blocklist::now_unix()) {
        Some(s) => println!(
            "{}",
            serde_json::to_string_pretty(&s).expect("status serializes")
        ),
        None => println!("no verified blocklist available"),
    }
}
