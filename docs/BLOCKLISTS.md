# Blocklists

Status: **BUILT and tested** (`core/crypto`, `core/blocklists`, service integration).

## Flow

```
publisher (offline key)                 client (service)
  payload.txt ──sign──► manifest.json     BlocklistProvider (file / HTTP) — untrusted
                                                │
                                                ▼
                                   manifest signature (pinned Ed25519 keys)
                                                │ reject → keep current list
                                                ▼
                                   version > current?  (rollback prevention)
                                                ▼
                                   download payload (size-capped)
                                                ▼
                                   size + SHA-256 match manifest
                                                ▼
                                   content policy: ≥50 rules, ≤1% bad lines,
                                   rule_count matches, not <50% of current list
                                                ▼
                                   BlocklistRepository.promote (staging → active,
                                   old active → previous)
```

Any failure at any step keeps the currently active list. Bad remote data can
never empty or disable protection.

## Manifest

```json
{
  "format": 1,
  "list_id": "gambling",
  "version": 2,
  "generated_at": 1790709480,
  "sha256": "…",
  "size": 1812,
  "rule_count": 101,
  "signature": "…"
}
```

The Ed25519 signature covers a fixed line encoding of every field
(`gg-blocklist-manifest-v1\nformat=…\nlist_id=…\n…`), not the JSON text.
Unknown JSON fields are rejected.

## Local storage

`%ProgramData%\GamblingGuard\blocklists\gambling\{active,previous,staging}\`.
Every load re-verifies signature and hash. A list edited on disk is skipped
and the previous slot is used instead.

## Bundled list

`packages/blocklists/gambling/` is compiled into the service binary. It gives
protection on first run and offline, and passes the same verification as a
download. It is a **representative seed of 100 well-known operators** across
all 14 categories. It is not a complete gambling database.

## Keys

> ⚠️ `packages/blocklists/keys/dev-signing.pub` is a **development key**. Its
> private half was never committed and no longer exists. Before any release:

```sh
cargo run -p gg-blocklist --bin gg-blocklist-tool -- keygen release.key   # prints public key; keep release.key offline
cargo run -p gg-blocklist --bin gg-blocklist-tool -- sign --key release.key --version 2 \
    --payload packages/blocklists/gambling/payload.txt --out packages/blocklists/gambling/manifest.json
```

Then replace `dev-signing.pub` with the printed key. `trusted_keys` in
settings accepts several keys, so a new key can be added before the old one
is retired.

## Service commands

```sh
gambling-guard-service blocklist status
gambling-guard-service blocklist update     # uses settings.blocklist.sources
```

Settings (`settings.json`, schema 2):

```json
"blocklist": {
  "sources": ["https://lists.example.org/gambling/"],
  "update_interval_hours": 12,
  "trusted_keys": ["<hex>"],
  "max_age_days": 30
}
```

There is **no hosted update server yet**. `sources` is empty by default, so
only the bundled list is used. It becomes stale after `max_age_days`, and
health then reports `PARTIALLY_PROTECTED`.

## Known limitations
- Freshness uses the local clock. Moving the clock back makes a stale list
  look fresh. That affects the health display only, never blocking. Trusted
  time comes in Milestone 3.
- A server can withhold updates (freeze attack). Staleness reporting is the
  mitigation.
- Anyone holding a trusted signing key can publish any list. Key custody is
  an operational requirement.
