# Bypass Test Matrix

No platform enforcement exists yet, so every row is **NOT YET SUPPORTED / NOT TESTED**. Rows are updated only from recorded test evidence.

| Vector | Windows | Android | Evidence |
|---|---|---|---|
| Incognito / private mode | NOT TESTED | NOT TESTED | — |
| New browser | NOT TESTED | NOT TESTED | — |
| Different system DNS | NOT TESTED | NOT TESTED | — |
| Third-party VPN | NOT TESTED | NOT TESTED | — |
| Proxy | NOT TESTED | NOT TESTED | — |
| Browser DoH | NOT TESTED | NOT TESTED | — |
| Android Private DNS | NOT TESTED | NOT TESTED | — |
| IPv6 | NOT TESTED | NOT TESTED | — |
| Direct IP | NOT TESTED | NOT TESTED | — |
| QUIC / HTTP3 | NOT TESTED | NOT TESTED | — |
| Restart | NOT TESTED | NOT TESTED | — |
| Safe mode | NOT TESTED | NOT TESTED | — |
| Service termination | NOT TESTED | NOT TESTED | — |
| Clock manipulation | NOT TESTED | NOT TESTED | — |
| Config modification | NOT TESTED | NOT TESTED | — |
| App downgrade | NOT TESTED | NOT TESTED | — |
| Blocklist rollback | BLOCKED (list layer) | BLOCKED (list layer, shared core) | `core/blocklists/tests/updater.rs`: older and equal versions rejected; live run 2026-09-29 kept v2 when a tampered v3 was offered |
