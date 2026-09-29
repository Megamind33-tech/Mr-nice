//! Signed gambling list compiled into the binary, so protection exists on
//! first run and offline. It passes the same verification as a download.

/// Ed25519 public key that signed the bundled list. This is a development
/// key; production releases must pin their own offline release key(s).
pub const DEV_SIGNING_KEY: &str = include_str!("../../../packages/blocklists/keys/dev-signing.pub");
pub const GAMBLING_MANIFEST: &str =
    include_str!("../../../packages/blocklists/gambling/manifest.json");
pub const GAMBLING_PAYLOAD: &str =
    include_str!("../../../packages/blocklists/gambling/payload.txt");
