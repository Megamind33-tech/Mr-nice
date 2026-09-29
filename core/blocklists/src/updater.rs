//! BlocklistUpdater: fetch → verify → sanity-check → promote.
//!
//! Invariant: nothing reaches the active slot unless its signature, hash,
//! version and content checks all pass. Any failure keeps the current list.

use gg_crypto::PublicKey;

use crate::compiler::RuleCompiler;
use crate::manifest::Manifest;
use crate::provider::BlocklistProvider;
use crate::repository::{BlocklistRepository, VerifiedList};
use crate::UpdateError;

#[derive(Debug, Clone)]
pub struct UpdatePolicy {
    pub list_id: String,
    pub max_manifest_bytes: usize,
    pub max_payload_bytes: usize,
    /// Reject lists with fewer valid rules than this.
    pub min_rules: usize,
    /// Reject a new list smaller than this fraction of the current one.
    /// Guards against a truncated-but-signed list silently weakening
    /// protection.
    pub min_ratio_of_current: f64,
    /// Reject lists where more than this fraction of rule lines are invalid.
    pub max_error_ratio: f64,
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        Self {
            list_id: "gambling".into(),
            max_manifest_bytes: 64 * 1024,
            max_payload_bytes: 32 * 1024 * 1024,
            min_rules: 50,
            min_ratio_of_current: 0.5,
            max_error_ratio: 0.01,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    Updated {
        from: Option<u64>,
        to: u64,
    },
    UpToDate {
        version: u64,
    },
    /// Every source failed; the current list stays active.
    Failed {
        errors: Vec<(String, String)>,
    },
}

pub struct BlocklistUpdater<'a> {
    pub keys: &'a [PublicKey],
    pub policy: &'a UpdatePolicy,
    pub repo: &'a BlocklistRepository,
}

impl BlocklistUpdater<'_> {
    /// Acceptance checks shared by remote updates and bundled lists.
    pub fn accept(
        &self,
        list: &VerifiedList,
        current: Option<&VerifiedList>,
    ) -> Result<(), UpdateError> {
        let m = &list.manifest;
        if m.list_id != self.policy.list_id {
            return Err(UpdateError::WrongList(m.list_id.clone()));
        }
        if let Some(cur) = current {
            if m.version <= cur.manifest.version {
                return Err(UpdateError::NotNewer {
                    offered: m.version,
                    current: cur.manifest.version,
                });
            }
        }
        let compiled = RuleCompiler::compile(&list.payload);
        if compiled.rule_count as u64 != m.rule_count {
            return Err(UpdateError::RuleCountMismatch {
                manifest: m.rule_count,
                actual: compiled.rule_count as u64,
            });
        }
        if compiled.rule_count < self.policy.min_rules {
            return Err(UpdateError::TooFewRules(compiled.rule_count));
        }
        let lines = compiled.rule_count + compiled.error_lines;
        if compiled.error_lines as f64 > self.policy.max_error_ratio * lines as f64 {
            return Err(UpdateError::TooManyErrors(compiled.error_lines));
        }
        if let Some(cur) = current {
            let floor = cur.manifest.rule_count as f64 * self.policy.min_ratio_of_current;
            if (compiled.rule_count as f64) < floor {
                return Err(UpdateError::Shrunk {
                    from: cur.manifest.rule_count,
                    to: compiled.rule_count as u64,
                });
            }
        }
        Ok(())
    }

    fn try_source(
        &self,
        provider: &dyn BlocklistProvider,
        current: Option<&VerifiedList>,
    ) -> Result<Option<VerifiedList>, UpdateError> {
        let manifest_bytes = provider.fetch_manifest(self.policy.max_manifest_bytes)?;
        let manifest = Manifest::parse(&manifest_bytes)?;
        manifest.verify_signature(self.keys)?;
        if let Some(cur) = current {
            if manifest.version == cur.manifest.version {
                return Ok(None);
            }
        }
        if manifest.size as usize > self.policy.max_payload_bytes {
            return Err(UpdateError::TooLarge(manifest.size));
        }
        let payload = provider.fetch_payload(self.policy.max_payload_bytes)?;
        let list = VerifiedList::verify(self.keys, &manifest_bytes, &payload)?;
        self.accept(&list, current)?;
        Ok(Some(list))
    }

    /// Try each source in order until one yields an acceptable newer list.
    pub fn update(&self, providers: &[Box<dyn BlocklistProvider>]) -> UpdateOutcome {
        let current = self.repo.load_best(self.keys).map(|(_, l)| l);
        let mut errors = Vec::new();
        for p in providers {
            match self.try_source(p.as_ref(), current.as_ref()) {
                Ok(Some(list)) => {
                    let to = list.manifest.version;
                    if let Err(e) = self.repo.promote(&list) {
                        errors.push((p.describe(), format!("store failed: {e}")));
                        continue;
                    }
                    tracing::info!(event = "RULESET_UPDATE", source = %p.describe(), version = to, rules = list.manifest.rule_count);
                    return UpdateOutcome::Updated {
                        from: current.map(|c| c.manifest.version),
                        to,
                    };
                }
                Ok(None) => {
                    let version = current.as_ref().map_or(0, |c| c.manifest.version);
                    return UpdateOutcome::UpToDate { version };
                }
                Err(e) => {
                    tracing::warn!(event = "RULESET_REJECTED", source = %p.describe(), error = %e);
                    errors.push((p.describe(), e.to_string()));
                }
            }
        }
        UpdateOutcome::Failed { errors }
    }

    /// Best list available offline: stored active/previous, or the bundled
    /// list if it verifies and is newer (e.g. first run, or an app upgrade
    /// that ships a newer list). A newer bundled list is promoted.
    pub fn load_or_seed(&self, bundled: Option<(&[u8], &[u8])>) -> Option<VerifiedList> {
        let stored = self.repo.load_best(self.keys).map(|(_, l)| l);
        let seed = bundled.and_then(|(m, p)| match VerifiedList::verify(self.keys, m, p) {
            Ok(l) => Some(l),
            Err(e) => {
                tracing::error!(event = "RULESET_REJECTED", source = "bundled", error = %e);
                None
            }
        });
        match (stored, seed) {
            (Some(s), Some(b)) if b.manifest.version > s.manifest.version => {
                if self.accept(&b, Some(&s)).is_ok() {
                    let _ = self.repo.promote(&b);
                    Some(b)
                } else {
                    Some(s)
                }
            }
            (Some(s), _) => Some(s),
            (None, Some(b)) => {
                if self.accept(&b, None).is_ok() {
                    if let Err(e) = self.repo.promote(&b) {
                        tracing::warn!(error = %e, "could not cache bundled blocklist");
                    }
                    Some(b)
                } else {
                    None
                }
            }
            (None, None) => None,
        }
    }
}
