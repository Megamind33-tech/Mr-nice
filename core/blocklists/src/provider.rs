//! BlocklistProvider: where manifests and payloads come from.
//!
//! Providers are untrusted transport. Everything they return is verified by
//! the updater before use.

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

pub const MANIFEST_FILE: &str = "manifest.json";
pub const PAYLOAD_FILE: &str = "payload.txt";

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(String),
    #[error("response exceeds {0} bytes")]
    TooLarge(usize),
    #[error("unsupported source: {0}")]
    Unsupported(String),
}

pub trait BlocklistProvider: Send + Sync {
    fn describe(&self) -> String;
    fn fetch_manifest(&self, limit: usize) -> Result<Vec<u8>, ProviderError>;
    fn fetch_payload(&self, limit: usize) -> Result<Vec<u8>, ProviderError>;
}

fn read_limited(mut r: impl Read, limit: usize) -> Result<Vec<u8>, ProviderError> {
    let mut buf = Vec::new();
    r.by_ref().take(limit as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() > limit {
        return Err(ProviderError::TooLarge(limit));
    }
    Ok(buf)
}

/// Directory containing `manifest.json` and `payload.txt` (e.g. a USB stick
/// or a bundle shipped with the installer).
pub struct FileProvider {
    dir: PathBuf,
}

impl FileProvider {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

impl BlocklistProvider for FileProvider {
    fn describe(&self) -> String {
        format!("file:{}", self.dir.display())
    }
    fn fetch_manifest(&self, limit: usize) -> Result<Vec<u8>, ProviderError> {
        read_limited(std::fs::File::open(self.dir.join(MANIFEST_FILE))?, limit)
    }
    fn fetch_payload(&self, limit: usize) -> Result<Vec<u8>, ProviderError> {
        read_limited(std::fs::File::open(self.dir.join(PAYLOAD_FILE))?, limit)
    }
}

/// `https://host/path/` serving `manifest.json` and `payload.txt`.
pub struct HttpProvider {
    base: String,
    agent: ureq::Agent,
}

impl HttpProvider {
    pub fn new(base: &str) -> Self {
        let mut base = base.trim_end_matches('/').to_owned();
        base.push('/');
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .redirects(3)
            .build();
        Self { base, agent }
    }

    fn get(&self, file: &str, limit: usize) -> Result<Vec<u8>, ProviderError> {
        let url = format!("{}{}", self.base, file);
        let resp = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| ProviderError::Http(e.to_string()))?;
        read_limited(resp.into_reader(), limit)
    }
}

impl BlocklistProvider for HttpProvider {
    fn describe(&self) -> String {
        self.base.clone()
    }
    fn fetch_manifest(&self, limit: usize) -> Result<Vec<u8>, ProviderError> {
        self.get(MANIFEST_FILE, limit)
    }
    fn fetch_payload(&self, limit: usize) -> Result<Vec<u8>, ProviderError> {
        self.get(PAYLOAD_FILE, limit)
    }
}

/// Build a provider from a settings string: `https://…`, `http://…`, or a
/// filesystem path.
pub fn from_source(source: &str) -> Result<Box<dyn BlocklistProvider>, ProviderError> {
    let s = source.trim();
    if s.starts_with("https://") || s.starts_with("http://") {
        Ok(Box::new(HttpProvider::new(s)))
    } else if s.contains("://") {
        Err(ProviderError::Unsupported(s.to_owned()))
    } else {
        Ok(Box::new(FileProvider::new(s)))
    }
}
