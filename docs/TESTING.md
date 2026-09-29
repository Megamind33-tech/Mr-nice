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

Not yet covered, because the code does not exist yet: config migration, commitment timing, signature verification.

## Integration tests
Windows (Chrome/Edge/Firefox, reboot, reconnect, DNS change) and Android (Chrome, second browser, Wi-Fi/mobile, restart, background, lock): **NOT YET RUN**. They need the platform layers and real devices or VMs.
