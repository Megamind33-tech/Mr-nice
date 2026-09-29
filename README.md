# Gambling Guard

Voluntary, system-level gambling-site blocking for Windows and Android (iOS later).
Enforcement runs in the OS network path, not in a browser extension.

**Current state:** the shared rules engine (`core/rules-engine`) is built and unit-tested.
The local filtering DNS resolver (`core/dns-filter`) and the service core (`apps/windows/service`) are built and tested on Linux.
OS integration (redirecting system DNS, WFP bypass filters, Windows service host, Android VpnService) is **not implemented**.
Nothing blocks traffic system-wide on any device yet.

- Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- Build: [docs/BUILD.md](docs/BUILD.md) · Testing: [docs/TESTING.md](docs/TESTING.md)
- Bypass matrix: [docs/BYPASS_TEST_MATRIX.md](docs/BYPASS_TEST_MATRIX.md)
