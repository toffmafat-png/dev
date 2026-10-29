# NOVA X — Dark Web, Tor Network & Advanced Internet Intelligence (§165)

NOVA X integrates configurable privacy-network routing, Tor SOCKS5h connectivity, legitimate v3 `.onion` service inspection, 11-category multi-source OSINT search, a 12-step epistemic research assistant, defensive threat-intelligence correlation, and a quarantine-first download/file-analysis pipeline directly into NOVA X's existing native Kali Linux desktop app (`nova-x`), `PlatformService`, `ToolRegistry`, `AutonomyPolicy`, `KnowledgeStore`, `SharedMemorySystem`, and FastAPI service.

## Architecture & Subsystems (`nova/privacy_intel/`)

1. **`TorIntegrationManager` (§165.1, §165.8)**
   - Detects Kali Linux `tor`, `torsocks`, and official Tor Browser (`torbrowser-launcher` / user bundle) binaries, `systemctl is-active tor` state, and live RFC 1928 SOCKS5 reachability.
   - Prefers official Tor Browser for interactive browsing (`launch_tor_browser`).
   - Uses native RFC 1928 **`SOCKS5h` (`ATYP=0x03`)** remote hostname resolution so `.onion` queries never leak to local DNS resolvers, with distinct `IsolateSOCKSAuth` stream-isolation tokens per session.
   - Exposes the 6-component **Privacy-Aware Network Dashboard** (`tor_browser`, `automated_research_client`, `proxy_aware_integrations`, `ordinary_ai_providers`, `direct_internet_access`, `local_only_operations`) with explicit anonymity limitation disclosures.
   - Enforces an immediate Tor kill-switch when `tor_enabled=False` and **never** silently modifies `/etc/resolv.conf`, iptables/nftables, or system-wide proxy settings.

2. **`OnionServiceBrowser` (§165.2)**
   - Validates v3 `.onion` hostnames against Tor `rend-spec-v3` (56 base32 chars + 32-byte Ed25519 public key + 2-byte `SHA3-256(".onion checksum" || pubkey || 0x03)` checksum + version `0x03`), rejecting retired 16-char v2 addresses.
   - Verifies `.onion` mirrors against independently documented official references (`verify_against_official_reference`), maintains provenance-tagged bookmarks, flags broken/outdated `.onion` links, and reports `401`/`403` authentication gates without attempting to bypass access controls or CAPTCHAs.
   - Keeps ordinary website requests (`fetch_ordinary_website`) completely isolated on direct HTTP/HTTPS transport.

3. **`UnifiedSearchOrchestrator` (§165.3) & `DarkWebResearchAssistant` (§165.4)**
   - Pluggable source adapters across 11 categories (`public_web`, `official_docs`, `code_repositories`, `academic_sources`, `security_advisories`, `public_breach_notices`, `public_blockchain`, `public_onion_services`, `privacy_network_search`, `user_supplied_archives`, `authorized_threat_intel`) with minimum-sufficient source selection (§165.11).
   - Records `sources_consulted`, `sources_skipped`, `query_limitations`, and `retrieval_errors` in SQLite (`internet_search_runs`) — never claiming a single engine indexes the dark web and never fabricating hits.
   - Runs a 12-step research workflow separating `observations`, `claims`, `hypotheses`, and `verified_facts`, flagging contradictions and probable scams, enforcing `MULTI_MODEL_AGREEMENT_IS_PROOF = False`, and indexing structured reports into `KnowledgeStore` and `SharedMemorySystem`.

4. **`ThreatIntelligenceAnalyzer` (§165.5), `OrganizationalExposureMonitor` (§165.6) & `SecureDownloadAndAnalysisPipeline` (§165.7)**
   - Strictly separates `external_report` claims from `verified_local_observation` telemetry, correlates supplied host logs and package versions against CVEs/IOCs, scans authorized paths for leaked secrets, minimizes PII on sight, refuses stolen-credential collection/use, and never declares an organization breached from an unverified post.
   - Quarantines untrusted downloads inside `0700` directories with `0400` non-executable permissions (`auto_executed=False`), enforces size caps, computes SHA-256/SHA-512 hashes, detects magic-byte MIME spoofing, blocks Zip-Slip/symlink/bomb archives prior to optional isolated extraction, checks detached GPG signatures and ClamAV when installed, states malware-scanning limitations honestly, and extracts static text/indicators without loading remote resources.

5. **`OptionalOnionHostingHelper` (§165.9) & `AutonomousResearchMonitor` (§165.10)**
   - Keeps optional private onion-service hosting disabled until `onion_hosting_enabled=True`, blocks exposing NOVA admin ports (`8000`, `7860`, `22`) or non-loopback binds, verifies `0700` `HiddenServiceDir` permissions, and isolates service keys in `0600` `ProtectedCredentialVault` storage redacted from logs and reports.
   - Persists scoped, rate-limited recurring research monitors in SQLite (`research_monitors`) across restarts while honestly reporting `continuous_monitoring_active` based on actual background worker state.

## CLI & Verification

```bash
# Inspect Kali Tor & Privacy Network Dashboard
nova-x tor --dashboard

# Run unified multi-source OSINT search or full 12-step research report
nova-x osint "CVE-2026-4242 advisory" --research

# Run the live 15-check §165.13 acceptance suite
python -m nova.privacy_intel.acceptance
```
