//! On-disk rule lists.
//!
//! `<data>/rules/*.txt` are compiled together in file-name order. `user.txt`
//! holds rules added from the CLI. A list that fails to read is skipped and
//! reported, so one damaged file cannot empty the whole rule set.

use std::path::PathBuf;
use std::time::SystemTime;

use gg_rules_engine::{parse_list, Category, Domain, RuleMatcher};

pub const USER_LIST: &str = "user.txt";
pub const BYPASS_LIST: &str = "10-dns-bypass.txt";

/// Resolver hostnames used for DNS-over-HTTPS/TLS. Sinkholing them stops a
/// browser configured with one of these providers from bootstrapping DoH.
pub const DNS_BYPASS_LIST: &str = "\
# Managed by Gambling Guard. Known encrypted-DNS resolver hostnames.
# Blocking them prevents browsers bypassing the local filter with DoH.
[dns_bypass]
dns.google
dns.google.com
cloudflare-dns.com
one.one.one.one
dns.quad9.net
dns9.quad9.net
dns10.quad9.net
dns11.quad9.net
doh.opendns.com
doh.familyshield.opendns.com
dns.nextdns.io
dns.adguard.com
dns.adguard-dns.com
doh.cleanbrowsing.org
doh.mullvad.net
dns.mullvad.net
dns.controld.com
freedns.controld.com
doh.dns.sb
";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fingerprint(Vec<(PathBuf, u64, Option<SystemTime>)>);

#[derive(Debug)]
pub struct Compiled {
    pub matcher: RuleMatcher,
    pub fingerprint: Fingerprint,
    pub files: usize,
    pub line_errors: usize,
    pub unreadable: Vec<PathBuf>,
}

pub struct RulesStore {
    dir: PathBuf,
}

impl RulesStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Create the directory and managed lists if absent.
    pub fn ensure_layout(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let bypass = self.dir.join(BYPASS_LIST);
        crate::fsutil::write_atomic(&bypass, DNS_BYPASS_LIST.as_bytes())?;
        let user = self.dir.join(USER_LIST);
        if !user.exists() {
            crate::fsutil::write_atomic(
                &user,
                b"# User-added rules. One per line.\n[user_defined]\n",
            )?;
        }
        Ok(())
    }

    fn list_files(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&self.dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.extension().is_some_and(|x| x == "txt"))
                    .collect()
            })
            .unwrap_or_default();
        files.sort();
        files
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint(
            self.list_files()
                .into_iter()
                .map(|p| {
                    let meta = std::fs::metadata(&p).ok();
                    let len = meta.as_ref().map_or(0, |m| m.len());
                    let mtime = meta.and_then(|m| m.modified().ok());
                    (p, len, mtime)
                })
                .collect(),
        )
    }

    /// Compile the on-disk lists plus an already-verified blocklist payload.
    pub fn compile_with(&self, blocklist: Option<&str>) -> Compiled {
        let fingerprint = self.fingerprint();
        let mut rules = Vec::new();
        if let Some(text) = blocklist {
            rules.extend(parse_list(text, Category::Other("uncategorized".into())).rules);
        }
        let mut line_errors = 0;
        let mut unreadable = Vec::new();
        let files = self.list_files();
        for path in &files {
            match std::fs::read_to_string(path) {
                Ok(text) => {
                    let parsed = parse_list(&text, Category::UserDefined);
                    line_errors += parsed.errors.len();
                    rules.extend(parsed.rules);
                }
                Err(_) => unreadable.push(path.clone()),
            }
        }
        Compiled {
            matcher: RuleMatcher::from_rules(rules),
            fingerprint,
            files: files.len(),
            line_errors,
            unreadable,
        }
    }

    fn user_path(&self) -> PathBuf {
        self.dir.join(USER_LIST)
    }

    fn read_user(&self) -> std::io::Result<Vec<String>> {
        match std::fs::read_to_string(self.user_path()) {
            Ok(t) => Ok(t.lines().map(str::to_owned).collect()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(vec!["[user_defined]".to_owned()])
            }
            Err(e) => Err(e),
        }
    }

    fn write_user(&self, lines: &[String]) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let mut text = lines.join("\n");
        text.push('\n');
        crate::fsutil::write_atomic(&self.user_path(), text.as_bytes())
    }

    /// Add a domain (and its subdomains) to the user list. Returns false if
    /// it was already present.
    pub fn add_user_domain(&self, raw: &str) -> Result<bool, StoreError> {
        let domain = Domain::parse(raw)?;
        let mut lines = self.read_user()?;
        if lines.iter().any(|l| l.trim() == domain.as_str()) {
            return Ok(false);
        }
        lines.push(domain.as_str().to_owned());
        self.write_user(&lines)?;
        Ok(true)
    }

    /// Remove a domain from the user list. Returns false if it was absent.
    pub fn remove_user_domain(&self, raw: &str) -> Result<bool, StoreError> {
        let domain = Domain::parse(raw)?;
        let lines = self.read_user()?;
        let kept: Vec<String> = lines
            .iter()
            .filter(|l| l.trim() != domain.as_str())
            .cloned()
            .collect();
        if kept.len() == lines.len() {
            return Ok(false);
        }
        self.write_user(&kept)?;
        Ok(true)
    }

    pub fn user_domains(&self) -> std::io::Result<Vec<String>> {
        Ok(self
            .read_user()?
            .into_iter()
            .map(|l| l.split('#').next().unwrap_or("").trim().to_owned())
            .filter(|l| !l.is_empty() && !l.starts_with('['))
            .collect())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("invalid domain: {0}")]
    Domain(#[from] gg_rules_engine::DomainError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(c: &Compiled, d: &str) -> bool {
        c.matcher.check(d).unwrap().is_blocked()
    }

    #[test]
    fn add_remove_round_trip_changes_verdict_and_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let store = RulesStore::new(dir.path().join("rules"));
        store.ensure_layout().unwrap();
        let before = store.compile_with(None);
        assert!(!blocked(&before, "example-gambling-domain.com"));
        assert!(blocked(&before, "dns.google"), "bypass list active");

        assert!(store
            .add_user_domain("EXAMPLE-Gambling-Domain.com.")
            .unwrap());
        assert!(!store
            .add_user_domain("example-gambling-domain.com")
            .unwrap());
        let added = store.compile_with(None);
        assert_ne!(added.fingerprint, before.fingerprint);
        assert!(blocked(&added, "www.example-gambling-domain.com"));
        assert_eq!(
            store.user_domains().unwrap(),
            vec!["example-gambling-domain.com"]
        );

        assert!(store
            .remove_user_domain("example-gambling-domain.com")
            .unwrap());
        assert!(!store
            .remove_user_domain("example-gambling-domain.com")
            .unwrap());
        assert!(!blocked(
            &store.compile_with(None),
            "example-gambling-domain.com"
        ));
    }

    #[test]
    fn rejects_invalid_domains() {
        let dir = tempfile::tempdir().unwrap();
        let store = RulesStore::new(dir.path());
        assert!(store.add_user_domain("not a domain").is_err());
        assert!(store.add_user_domain("").is_err());
    }

    #[test]
    fn bad_lines_do_not_drop_other_rules() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "good.test\nbad..line\n").unwrap();
        std::fs::write(dir.path().join("b.txt"), "other.test\n").unwrap();
        std::fs::write(dir.path().join("ignored.json"), "casino.test\n").unwrap();
        let c = RulesStore::new(dir.path()).compile_with(None);
        assert_eq!((c.files, c.line_errors), (2, 1));
        assert!(blocked(&c, "good.test"));
        assert!(blocked(&c, "other.test"));
        assert!(!blocked(&c, "casino.test"));
    }

    #[test]
    fn missing_directory_compiles_to_empty_set() {
        let c = RulesStore::new("/nonexistent/gg-rules").compile_with(None);
        assert!(c.matcher.is_empty());
    }
}
