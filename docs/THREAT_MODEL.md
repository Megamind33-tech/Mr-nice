# Gambling Guard — Threat Model

Gambling Guard is **voluntary** self-protection. It raises the cost of an impulsive bypass. It does **not** defend against a determined device owner with full administrative or physical control. The operating system does not give that guarantee to any application, and we will not claim it.

## Assets
1. Enforcement state: installed filters, DNS takeover, VPN.
2. Active rule set and its integrity.
3. Commitment state (lock window, cooling-off) and the trusted time it depends on.
4. Recovery and partner secrets (stored only as Argon2id hashes).
5. User privacy: visited domains must never leave the device by default.

## Threat actors and boundaries

| Actor | Capability | In scope? | Primary mitigations |
|---|---|---|---|
| Casual user (impulse bypass) | New browser, incognito, change DNS, close the app | **Yes, primary** | System-level filtering; DNS/DoT egress blocked; UI is not the boundary; commitment cooling-off |
| Local standard user | Everything above, no admin | **Yes** | Service runs as LocalSystem; config ACL'd to SYSTEM/Admins; IPC validates commands and checks policy |
| Local administrator | Stop services, delete WFP filters, boot Safe Mode, uninstall | **Partially** | Commitment gating inside our own uninstaller; tamper detection and logging; persistent WFP filters. **An admin can always remove protection**, which is by design (recovery must exist) |
| Malware on device | Arbitrary code | Out of scope as an adversary. We only ensure our IPC cannot be abused to escalate privilege | No arbitrary-command IPC; strict command schema |
| Network attacker | MITM on update traffic | **Yes** | Ed25519-signed manifests; TLS; hash checks; rollback prevention by version |
| Malicious or compromised update server | Serves chosen payloads | **Yes** | Offline signing key, not held by the server; clients pin the public key; monotonically increasing versions; invalid data never replaces the working list |
| Remote attacker targeting recovery | Tries to trigger unlock | **Yes** | Recovery needs code + account auth + a 72-hour delay, with notification and audit trail |

## Known structural limitations (never hide these)

1. **DNS-based filtering does not see direct-IP access.** An IP typed straight into the browser skips name resolution. Blocking CDN ranges would hit legitimate sites, so it is not done by default.
2. **DoH to unknown endpoints.** DoH is ordinary HTTPS on port 443. We block known public DoH resolver IPs, and Chromium and Firefox policy keys can disable browser DoH. An unknown or self-hosted DoH endpoint remains a bypass. Status: PARTIALLY MITIGATED.
3. **Third-party VPN or proxy apps.** Traffic tunnelled out of the device skips local DNS. Windows: partially mitigated by blocking known VPN endpoints. Android: only one VPN can be active, so starting another disconnects ours; Always-on plus lockdown and Device Owner mode help. Status: PARTIALLY MITIGATED / OS LIMITATION.
4. **Cached DNS answers** can persist briefly after a rule is added. We flush the OS cache when rules change; browsers keep their own caches for a short time.
5. **Safe Mode / alternate OS boot on Windows**: the service may not run. Persistent WFP filters survive a normal reboot. Whether they are enforced in Safe Mode is **UNKNOWN — REQUIRES VERIFICATION**.
6. **Android consumer mode**: the user can uninstall the app or revoke VPN consent. Stronger control needs Device Owner provisioning.
7. **Clock manipulation**: see `COMMITMENT_MODE.md` (to be written in milestone 3). Local time is only trusted to move forward relative to the last trusted time seen.

## Explicit non-goals
Kernel rootkits, hidden persistence, sabotaging uninstall or Windows recovery, blocking factory reset, TLS interception, installing root certificates, uploading browsing history.
