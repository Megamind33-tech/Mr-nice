# Testing

## Unit tests — core (`cargo test`)
| Area | File | Status |
|---|---|---|
| Case, trailing dot, whitespace normalization | `tests/normalization.rs` | PASS |
| IDN → punycode, punycode passthrough | `tests/normalization.rs` | PASS |
| Malformed names, length limits | `tests/normalization.rs` | PASS |
| Apex+subdomain, `*.`, `=` scopes | `tests/matching.rs` | PASS |
| No substring/suffix false positives (`alphabet.com` vs `bet.com`) | `tests/matching.rs` | PASS |
| Allow/block precedence and ties | `tests/matching.rs` | PASS |
| List parsing with categories, comments, bad lines | `tests/matching.rs` | PASS |
| 50k-rule set lookup correctness | `tests/matching.rs` | PASS |

| DNS wire parsing: truncation, compression pointers, bad counts, opcodes | `core/dns-filter/tests/message.rs` | PASS |
| Sinkhole A/AAAA, NODATA for other types, NXDOMAIN mode, 0x20 case echo | `core/dns-filter/tests/message.rs` | PASS |
| Real UDP+TCP listeners: block, forward, live rule removal restores access | `core/dns-filter/tests/end_to_end.rs` | PASS |
| Blocking with no upstream reachable; dead-upstream fallback; loop guard | `core/dns-filter/tests/end_to_end.rs` | PASS |
| Firefox DoH canary answered NXDOMAIN | `core/dns-filter/tests/end_to_end.rs` | PASS |
| Settings: defaults, v0→v1 migration, corrupt/future files fall back to defaults | `apps/windows/service/src/settings.rs` | PASS |
| Rule store: add/remove, normalization, damaged list isolation | `apps/windows/service/src/rules_store.rs` | PASS |
| Health: PROTECTED only when all components are up | `apps/windows/service/src/status.rs` | PASS |

Manual run (Linux container, 2026-09-29), `console --listen 127.0.0.1:5353`:
- rule added → `www.example-gambling-domain.com` answered `A 0.0.0.0`
- `dns.google` answered `A 0.0.0.0` (DoH bypass list)
- `use-application-dns.net` answered NXDOMAIN
- rule removed → the query was forwarded upstream; the real answer was NXDOMAIN because the name does not exist
- `status` reported `ACTION_REQUIRED` (correct: no system DNS redirection in console mode)

Not yet covered, because the code does not exist yet: config migration, commitment timing, signature verification.

## Integration tests
Windows (Chrome/Edge/Firefox, reboot, reconnect, DNS change) and Android (Chrome, second browser, Wi-Fi/mobile, restart, background, lock): **NOT YET RUN**. They need the platform layers and real devices or VMs.
