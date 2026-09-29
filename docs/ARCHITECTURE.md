# Gambling Guard — Architecture

Status legend: **BUILT** (in repo, tests pass) · **DESIGNED** (specified here, no code yet) · **UNKNOWN — REQUIRES VERIFICATION**.

## 1. Principle

Enforcement sits in the operating system's network path, never in a browser.
The UI controls a privileged component. The UI is **not** the security boundary.

```
 any app / any browser / private mode / WebView / PWA
                    │
          OS network stack
                    │
   ┌────────────────▼─────────────────┐
   │  Platform interception (native)  │  Windows: service + WFP
   │                                  │  Android: VpnService
   └────────────────┬─────────────────┘
                    │ normalized domain name
   ┌────────────────▼─────────────────┐
   │  gg-rules-engine (Rust, shared)  │  BUILT
   └────────────────┬─────────────────┘
                    │ Verdict: Allow | Block{rule, category}
                    ▼
               ALLOW / BLOCK
```

## 2. Repository layout

| Path | Contents | Status |
|---|---|---|
| `core/rules-engine` | Domain normalization, rule parsing, trie matcher, list parser | **BUILT** |
| `core/classification` | Category metadata beyond the enum (display names, grouping) | DESIGNED |
| `core/blocklists` | Signed manifest format, `BlocklistProvider/Repository/Updater`, `RuleCompiler` | DESIGNED |
| `core/crypto` | Ed25519 manifest verification, hashing helpers | DESIGNED |
| `apps/windows/service` | Windows service: local DNS filter, WFP policy, IPC server | DESIGNED |
| `apps/windows/ui` | Unprivileged UI, IPC client | DESIGNED |
| `apps/windows/installer` | MSI with service registration and recovery options | DESIGNED |
| `apps/android/app` | Kotlin, Compose, `VpnService`, core via JNI | DESIGNED |
| `backend/*` | NestJS + PostgreSQL: accounts, partners, manifests, recovery | DESIGNED — not needed for blocking |
| `packages/contracts` | IPC and API schemas shared across clients | DESIGNED |
| `packages/test-data` | Fixture lists, manifests | DESIGNED |

## 3. Shared core: `gg-rules-engine` (BUILT)

No I/O and no OS APIs. It compiles for `x86_64-unknown-linux-gnu` (tested) and passes `cargo check` for `x86_64-pc-windows-msvc`. Android targets are not yet verified.

### Normalization (`domain.rs`)
- Trim whitespace. Strip one trailing root dot.
- Convert non-ASCII input to punycode with UTS-46 (`idna` crate). Lowercase ASCII input.
- Validate: total length ≤ 253 characters, labels 1–63 characters from `[a-z0-9-_]`, no leading or trailing hyphen.
- Result: `Domain`, a newtype that can only exist once validated.

### Rule syntax (`rule.rs`)
| Syntax | Scope |
|---|---|
| `example.com` | the domain and every subdomain |
| `*.example.com` | subdomains only |
| `=example.com` | the exact host only |
| `@@…` | allow (exception) with the same scope |

A `*` anywhere else is rejected, so there is no glob or substring matching.

### Matching (`matcher.rs`)
The trie is keyed by labels in reverse order. Lookup costs O(number of labels) and does not depend on the size of the list.
Precedence:
1. The deepest matching node wins.
2. At the same node, `Exact` beats `DomainAndSubdomains`, which beats `SubdomainsOnly`.
3. At an exact tie, **Block beats Allow**.

Rule sets are immutable once compiled. Removing a rule means compiling a new set and swapping it in atomically.

### Categories (`category.rs`)
There are 14 gambling categories plus `user_defined`. An unknown category ID in a newer list becomes `Other(id)` instead of failing the load, so an older client keeps enforcing a newer list.

## 4. Windows (DESIGNED — no code yet)

```
GamblingGuard.UI (user) ──named pipe, ACL'd + caller SID check──► GamblingGuard.Service (LocalSystem)
                                                                  ├─ DNS filter  (127.0.0.1:53 / [::1]:53)
                                                                  ├─ WFP policy  (user-mode FwpmEngineOpen0 / FwpmFilterAdd0)
                                                                  ├─ Rules engine (gg-rules-engine)
                                                                  ├─ Blocklist updater (signed manifests)
                                                                  ├─ Commitment engine
                                                                  └─ Event log
```

Smallest real blocking proof, as planned:
1. The service runs a local DNS resolver. Blocked names get a synthesized `0.0.0.0` / `::` answer, or NXDOMAIN. Other queries are forwarded upstream.
2. The service sets each active adapter's DNS to the loopback resolver.
3. User-mode WFP filters in the service's own sublayer (no kernel driver):
   - block outbound UDP/TCP 53 and TCP 853 from every process except the service;
   - block known public DoH resolver IPs on 443 (UDP and TCP). This list is partial by nature; see the threat model.
4. Filters are added as persistent, so they apply at boot before the service starts. The service removes them only when policy allows.

Exact WFP layer identifiers and the app-ID condition for excluding the service's own traffic must be checked against Microsoft documentation during implementation: **UNKNOWN — REQUIRES VERIFICATION**.

## 5. Android (DESIGNED — no code yet)

`VpnService` claims DNS by advertising a virtual DNS server address inside the tunnel. Only DNS packets are routed into the TUN interface. Queries go through the rules engine over JNI. Allowed queries are forwarded through a `protect()`ed socket.
Always-on VPN plus "Block connections without VPN" is recommended to the user, but only the user or a Device Owner can turn it on.
Private DNS (DoT) bypasses this design unless it is switched off; a Device Owner can enforce that. The limitation will be recorded in `BYPASS_TEST_MATRIX.md`.

## 6. Failure behavior

| Failure | Behavior |
|---|---|
| UI crash | Service keeps filtering (process separation) |
| Backend down | Local list continues; no backend call on the blocking path |
| Update invalid | Current list kept; new list activated only after signature and parse checks |
| Stats failure | Stats are best-effort and off the verdict path |

## 7. Protection health

`PROTECTED` is shown only when the service reports that DNS takeover and WFP filters are both installed. Other states: `PARTIALLY_PROTECTED` (e.g. stale list), `ACTION_REQUIRED` (e.g. VPN off), `DISABLED`, `ERROR`. The UI never computes this itself.
