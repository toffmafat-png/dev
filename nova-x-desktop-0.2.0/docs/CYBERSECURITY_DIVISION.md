# DEV — Autonomous Cybersecurity, Vulnerability Research, and Security Engineering Division (§201–§220)

This subsystem integrates a discipline-grounded, scope-governed cybersecurity research, vulnerability validation, defensive engineering, and continuous improvement division directly into DEV's **single unified native Kali Linux architecture** (`PlatformService.cyber_division`, `DesktopRuntime.cyber_division`, `ToolRegistry`, `nova-x cyber`, `NovaWindow`, and `/api/cyber/*`).

## Architectural Principles & Truthful Boundaries (§201, §202 & §220)

1. **Single Native Kali Architecture:** All security capabilities share DEV's local SQLite WAL persistence (`nova/db.py`), hardware/driver discovery (`nova/kali_intel/` & `nova/system_access/`), `ToolRegistry`, `AutonomyPolicy`, `KnowledgeStore`, and `HybridCloudIntelligenceService` specialist reasoning—never operating as an isolated chatbot.
2. **Evidence-Grounded Honesty:** DEV never claims to be "the world's best security system" without independently measurable proof, never treats unverified scanner alerts or model hypotheses as confirmed vulnerabilities without empirical evidence, and never claims wireless/hardware features solely because a CLI binary exists on disk (`honest_capability_statement()`).
3. **Local Execution Authority:** Frontier cloud AI models (when configured) act strictly as analytical specialists (code review, advisory correlation, remediation drafting); target scope authorization, rate limits, and execution permissions remain 100% enforced by DEV's local security engine.

## Section-by-Section Architecture

| Section | Module / Class | Verified Capabilities & Safety Controls |
| --- | --- | --- |
| **§201–§202** | `CybersecurityEngineeringDivision` (`service.py`) | Models 16 architectural domains and executes the 14-step assessment workflow (`objective -> environment -> scope -> tools -> docs -> plan -> specialists -> permitted execution -> actual evidence -> validation -> contextual severity -> remediation -> authorized retest -> professional Markdown/JSON report`). |
| **§203** | `SecurityScopeRegistry` (`scope_and_surface.py`) | Centralized scope registry across 10 asset categories (`local_vm`, `owned_computer`, `authorized_network_range`, `development_environment`, `test_application`, `owned_domain`, `registered_server`, `authorized_cloud_account`, `bug_bounty_asset`, `vulnerable_training_environment`). Enforces standing minimal-intervention rules for 11 routine activities, explicit exclusions, expiration timestamps, protocol allowlists, per-minute rate limits, `partition_targets_by_scope()`, and hard blocks against tool/model/plugin/downloaded-instruction self-expansion. |
| **§204** | `AttackSurfaceManager` (`scope_and_surface.py`) | Tracks 14 attack-surface dimensions correlated to registered scopes with SHA-256 surface fingerprinting so unchanged assets never trigger duplicate alerts. |
| **§205 & §216** | `VulnerabilityDiscoveryAndLifecycleEngine` (`assessment_and_code_sec.py`) | Covers 22 vulnerability categories across 7 epistemic states (`potential_vulnerability`, `tool_generated_alert`, `reproducible_security_defect`, `confirmed_vulnerability`, `false_positive`, `previously_fixed_vulnerability`, `requires_further_investigation`). Computes contextual priority scores (exposure, mitigations, confidence, verified repro) and enforces `Discovered -> Investigating -> Confirmed -> Prioritized -> Remediating -> Retesting -> Resolved / Accepted Risk` with hard blocks against unverified closures. |
| **§206** | `NetworkSecurityWorkspace` (`assessment_and_code_sec.py`) | Truthfully inventories installed network utilities (`nmap`, `tshark`, `tcpdump`, `wireshark`, `ss`, `ip`, `openssl`, `nft`, etc.), parses binary `libpcap` `.pcap` captures passively without root, and runs scope-gated network posture reviews. |
| **§207** | `WebAndApiSecurityLab` (`assessment_and_code_sec.py`) | Non-destructively inspects HTTP security headers, wildcard/credentialed CORS, session cookie flags (`HttpOnly`, `SameSite`), exposed administrative routes, and OpenAPI schemas—sending `0` destructive payloads and extracting `0` real user records. |
| **§208** | `SourceCodeSecurityEngineer` (`assessment_and_code_sec.py`) | Performs Python AST SAST, false-positive filtering (parameterized SQL & mock test fixtures), `requirements.txt` SCA, `Dockerfile` posture checks, and the 10-step automated remediation workflow preserving `.orig.bak` backups and running isolated `unittest` regression checks. |
| **§209 & §213** | `SecurityKnowledgeAndResearchWorkbench` (`research_forensics_wireless.py`) | Indexes CVE/CWE/CVSS/OWASP/MITRE ATT&CK/NIST defensive advisories with pre-ingest disk/size budget checks (`check_storage_budget_before_ingest`), enforces 8 epistemic fields, analyzes patch diffs, and refuses weaponized exploit or credential-theft requests. |
| **§210** | `ReverseEngineeringAndForensicsLab` (`research_forensics_wireless.py`) | Performs strictly non-executing static inspection (`ELF`, `PE`, `APK/ZIP`, `PDF`, `SQLite3`, scripts), computing SHA-256/SHA-512 hashes, structural headers, printable strings, and signature matches while verifying bit-for-bit preservation of original evidence. |
| **§211** | `WirelessAndHardwareSecurityLab` (`research_forensics_wireless.py`) | Correlates `/sys/class/net/*/wireless`, `/sys/class/bluetooth`, `/sys/bus/usb`, kernel drivers, and `iw list` hardware monitor support without conflating CLI presence with physical adapter support. |
| **§212** | `IncidentResponseAssistant` (`research_forensics_wireless.py`) | Builds chronological incident timelines, separates `confirmed_evidence` from `suspected_activity`, preserves `0400` read-only SHA-256 forensic copies, generates a 6-phase IR checklist, and never auto-deletes files or kills processes without policy authorization. |
| **§214** | `AutonomousSecurityToolFactory` (`factory_purple_automation.py`) | Executes all 14 tool-development steps across 17 defensive utility categories: prefers mature installed tools first, blocks offensive/evasion intents and unsafe AST calls, runs isolated unit tests, versions with rollback, and wraps registered tools inside `SecurityScopeRegistry` + `AutonomyPolicy` so generated tools can never bypass authorization. |
| **§215, §217, §218 & §219** | `AutonomousPurpleTeamCoordinator`, `ContinuousSecurityAutomationEngine`, `CybersecurityExpertTutor`, `SelfImprovingSecurityIntelligence` (`factory_purple_automation.py`) | Lab-bounded purple-team detection gap closure; CPU/RAM/disk-bounded recurring assessments that auto-pause on expired scopes or invalid credentials; adaptive 17-discipline tutor driven by demonstrated scores; and benchmarked detector refinement with immutable scope/auth/audit guardrails. |

## Verification

Run the 18-check controlled acceptance suite directly:

```bash
python -m nova.cyber_division.acceptance
```
