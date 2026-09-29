//! BlocklistRepository: verified on-disk cache with one-step rollback.
//!
//! ```text
//! <root>/active/{manifest.json,payload.txt}    in use
//! <root>/previous/{manifest.json,payload.txt}  last good list before active
//! <root>/staging/                              write area, never read
//! ```
//!
//! Every load re-verifies signature and hash, so a list modified on disk is
//! detected and skipped rather than trusted because it is local.

use std::path::{Path, PathBuf};

use gg_crypto::PublicKey;

use crate::manifest::Manifest;
use crate::provider::{MANIFEST_FILE, PAYLOAD_FILE};

/// A list whose manifest signature and payload hash have been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedList {
    pub manifest: Manifest,
    pub payload: String,
}

impl VerifiedList {
    pub fn verify(
        keys: &[PublicKey],
        manifest_bytes: &[u8],
        payload: &[u8],
    ) -> Result<Self, crate::UpdateError> {
        let manifest = Manifest::parse(manifest_bytes)?;
        manifest.verify(keys, payload)?;
        let payload =
            String::from_utf8(payload.to_vec()).map_err(|_| crate::UpdateError::Encoding)?;
        Ok(Self { manifest, payload })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    Active,
    Previous,
}

pub struct BlocklistRepository {
    root: PathBuf,
}

impl BlocklistRepository {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn read_slot(&self, dir: &Path, keys: &[PublicKey]) -> Option<VerifiedList> {
        let m = std::fs::read(dir.join(MANIFEST_FILE)).ok()?;
        let p = std::fs::read(dir.join(PAYLOAD_FILE)).ok()?;
        match VerifiedList::verify(keys, &m, &p) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(event = "RULESET_REJECTED", slot = %dir.display(), error = %e, "stored blocklist failed verification");
                None
            }
        }
    }

    pub fn load(&self, slot: Slot, keys: &[PublicKey]) -> Option<VerifiedList> {
        let name = match slot {
            Slot::Active => "active",
            Slot::Previous => "previous",
        };
        self.read_slot(&self.dir(name), keys)
    }

    /// Newest list that still verifies: active, else previous.
    pub fn load_best(&self, keys: &[PublicKey]) -> Option<(Slot, VerifiedList)> {
        self.load(Slot::Active, keys)
            .map(|l| (Slot::Active, l))
            .or_else(|| self.load(Slot::Previous, keys).map(|l| (Slot::Previous, l)))
    }

    /// Store `list` as active; the old active becomes previous. The new list
    /// is fully written and synced in staging before any rename happens, so
    /// an interruption leaves either the old or the new set in place.
    pub fn promote(&self, list: &VerifiedList) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        let staging = self.dir("staging");
        let active = self.dir("active");
        let previous = self.dir("previous");
        if staging.exists() {
            std::fs::remove_dir_all(&staging)?;
        }
        std::fs::create_dir_all(&staging)?;
        write_synced(&staging.join(PAYLOAD_FILE), list.payload.as_bytes())?;
        write_synced(
            &staging.join(MANIFEST_FILE),
            list.manifest.to_json().as_bytes(),
        )?;

        if active.exists() {
            if previous.exists() {
                std::fs::remove_dir_all(&previous)?;
            }
            std::fs::rename(&active, &previous)?;
        }
        std::fs::rename(&staging, &active)
    }
}

fn write_synced(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)?;
    f.write_all(data)?;
    f.sync_all()
}
