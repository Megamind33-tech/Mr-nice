//! Keeps the gambling blocklist current for the service.
//!
//! The bundled list guarantees protection on first run and offline. Remote
//! updates run on a blocking thread and only replace the list through
//! `BlocklistUpdater`, which keeps the current list on any failure.

use std::path::PathBuf;
use std::time::SystemTime;

use gg_blocklist::bundled::{GAMBLING_MANIFEST, GAMBLING_PAYLOAD};
use gg_blocklist::{
    from_source, BlocklistProvider, BlocklistRepository, BlocklistUpdater, UpdateOutcome,
    UpdatePolicy, VerifiedList,
};
use gg_crypto::PublicKey;
use serde::{Deserialize, Serialize};

use crate::settings::BlocklistSettings;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocklistStatus {
    pub version: u64,
    pub generated_at: u64,
    pub rule_count: u64,
    pub fresh: bool,
    pub last_update: Option<String>,
}

/// Everything an update needs, cloneable onto a blocking thread.
#[derive(Clone)]
pub struct UpdateJob {
    root: PathBuf,
    keys: Vec<PublicKey>,
    policy: UpdatePolicy,
    sources: Vec<String>,
}

impl UpdateJob {
    pub fn run(&self) -> UpdateOutcome {
        let repo = BlocklistRepository::new(&self.root);
        let mut providers: Vec<Box<dyn BlocklistProvider>> = Vec::new();
        let mut errors = Vec::new();
        for s in &self.sources {
            match from_source(s) {
                Ok(p) => providers.push(p),
                Err(e) => errors.push((s.clone(), e.to_string())),
            }
        }
        if providers.is_empty() {
            if errors.is_empty() {
                errors.push(("settings".into(), "no update sources configured".into()));
            }
            return UpdateOutcome::Failed { errors };
        }
        let updater = BlocklistUpdater {
            keys: &self.keys,
            policy: &self.policy,
            repo: &repo,
        };
        updater.update(&providers)
    }
}

pub struct BlocklistManager {
    settings: BlocklistSettings,
    job: UpdateJob,
    active: Option<VerifiedList>,
    stamp: Option<SystemTime>,
    last_update: Option<String>,
}

pub fn parse_keys(hex_keys: &[String]) -> Vec<PublicKey> {
    hex_keys
        .iter()
        .filter_map(|k| match PublicKey::from_hex(k) {
            Ok(key) => Some(key),
            Err(e) => {
                tracing::error!(error = %e, "ignoring invalid trusted blocklist key");
                None
            }
        })
        .collect()
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl BlocklistManager {
    pub fn new(root: PathBuf, settings: BlocklistSettings) -> Self {
        let job = UpdateJob {
            root,
            keys: parse_keys(&settings.trusted_keys),
            policy: UpdatePolicy::default(),
            sources: settings.sources.clone(),
        };
        let mut m = Self {
            settings,
            job,
            active: None,
            stamp: None,
            last_update: None,
        };
        m.reload();
        m
    }

    fn repo(&self) -> BlocklistRepository {
        BlocklistRepository::new(&self.job.root)
    }

    /// Load the best verified list (stored or bundled).
    pub fn reload(&mut self) {
        let repo = self.repo();
        let updater = BlocklistUpdater {
            keys: &self.job.keys,
            policy: &self.job.policy,
            repo: &repo,
        };
        let bundled = Some((GAMBLING_MANIFEST.as_bytes(), GAMBLING_PAYLOAD.as_bytes()));
        self.active = updater.load_or_seed(bundled);
        self.stamp = repo.active_stamp();
        match &self.active {
            Some(l) => tracing::info!(
                event = "RULESET_UPDATE",
                list = %l.manifest.list_id,
                version = l.manifest.version,
                rules = l.manifest.rule_count
            ),
            None => tracing::error!(
                event = "FILTER_FAILURE",
                "no verified gambling blocklist available"
            ),
        }
    }

    /// True if another process changed the stored list since last load.
    pub fn changed_on_disk(&self) -> bool {
        self.repo().active_stamp() != self.stamp
    }

    pub fn payload(&self) -> Option<&str> {
        self.active.as_ref().map(|l| l.payload.as_str())
    }

    pub fn is_fresh(&self, now: u64) -> bool {
        self.active.as_ref().is_some_and(|l| {
            now.saturating_sub(l.manifest.generated_at) <= self.settings.max_age_days * 86_400
        })
    }

    pub fn update_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.settings.update_interval_hours.max(1) * 3600)
    }

    pub fn has_sources(&self) -> bool {
        !self.settings.sources.is_empty()
    }

    pub fn job(&self) -> UpdateJob {
        self.job.clone()
    }

    pub fn record(&mut self, outcome: &UpdateOutcome) {
        self.last_update = Some(match outcome {
            UpdateOutcome::Updated { from, to } => format!("updated {from:?} -> {to}"),
            UpdateOutcome::UpToDate { version } => format!("up to date at {version}"),
            UpdateOutcome::Failed { errors } => format!("failed: {errors:?}"),
        });
    }

    pub fn status(&self, now: u64) -> Option<BlocklistStatus> {
        self.active.as_ref().map(|l| BlocklistStatus {
            version: l.manifest.version,
            generated_at: l.manifest.generated_at,
            rule_count: l.manifest.rule_count,
            fresh: self.is_fresh(now),
            last_update: self.last_update.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_run_uses_bundled_list_and_caches_it() {
        let dir = tempfile::tempdir().unwrap();
        let m = BlocklistManager::new(dir.path().to_path_buf(), BlocklistSettings::default());
        let st = m.status(now_unix()).expect("bundled list loaded");
        assert!(st.rule_count >= 50);
        assert!(dir.path().join("active/manifest.json").exists());
        assert!(!m.changed_on_disk());
    }

    #[test]
    fn untrusted_keys_mean_no_list_rather_than_unverified_list() {
        let dir = tempfile::tempdir().unwrap();
        let settings = BlocklistSettings {
            trusted_keys: vec!["00".repeat(32), "garbage".into()],
            ..BlocklistSettings::default()
        };
        let m = BlocklistManager::new(dir.path().to_path_buf(), settings);
        assert!(m.payload().is_none());
        assert!(!m.is_fresh(now_unix()));
    }

    #[test]
    fn freshness_follows_max_age() {
        let dir = tempfile::tempdir().unwrap();
        let m = BlocklistManager::new(dir.path().to_path_buf(), BlocklistSettings::default());
        let generated = m.status(0).unwrap().generated_at;
        assert!(m.is_fresh(generated + 29 * 86_400));
        assert!(!m.is_fresh(generated + 31 * 86_400));
    }

    #[test]
    fn update_without_sources_fails_and_keeps_list() {
        let dir = tempfile::tempdir().unwrap();
        let m = BlocklistManager::new(dir.path().to_path_buf(), BlocklistSettings::default());
        assert!(matches!(m.job().run(), UpdateOutcome::Failed { .. }));
        assert!(m.payload().is_some());
    }
}
