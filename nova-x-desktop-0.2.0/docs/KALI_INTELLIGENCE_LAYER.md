# DEV — Advanced Kali Linux Intelligence, Application Mastery & Universal Software Integration (§181–§200)

## Architectural Principle

The **Kali Intelligence Layer** (`nova/kali_intel/`) is embedded directly inside DEV's single existing local-OS + frontier-cloud gateway architecture (`PlatformService.kali_intel`, `ToolRegistry`, `Database` SQLite WAL, `KnowledgeStore`, `AutonomyPolicy`, `HybridCloudIntelligenceService`, FastAPI `/api/kali/*`, `nova-x kali` CLI, and the native Qt `NovaWindow` desktop shell). No competing planner, duplicate database, or parallel orchestrator is introduced.

---

## Subsystem Map (§181–§200)

| Section | Module & Class | Capabilities & Enforced Guardrails |
|---|---|---|
| **§181** | `system_model.py` (`KaliSystemKnowledgeModel`) | Live inspection of all **21** host dimensions (`/etc/os-release`, kernel/arch, DE, `.desktop` apps, `$PATH` utilities, Kali tools, `dpkg` dependencies, APT repositories, kernel modules, hardware/drivers, services, non-secret env vars, network interfaces, system configs, dev toolchains, redacted logs, user permissions, disk/RAM, virtualization, containers, policies). Auto-refreshes when `/var/lib/dpkg/status` fingerprint changes. Explicitly distinguishes `installed`, `available`, `configured`, `running`, `functional`, and `unavailable`. |
| **§182** | `tool_and_doc_engine.py` (`KaliToolIntelligenceEngine`) | Reference catalogue aligned with `https://www.kali.org/tools/all-tools/` combined with live `$PATH`/`dpkg` inspection. Builds verified **20-field tool profiles** and supports multi-attribute + problem-first search (`"I want to inspect network traffic"`) without ever assuming uninstalled Kali tools are present. |
| **§183** | `tool_and_doc_engine.py` (`IntelligentToolSelectorAndExecutor`) | **13-step** discovery, `--help`/`man` option verification, tool comparison, permission check, execution, and real stdout/stderr verification. Rejects invented CLI flags (`rejected_unverified_cli_option`) and gates mutating commands behind explicit approval. |
| **§184 & §191** | `tool_and_doc_engine.py` (`AutomaticDocumentationEngine`) | **5-tier authority hierarchy** (`P1` local `man`/`--help`/README -> `P2` official Kali docs/metadata -> `P3` upstream docs -> `P4` Kali Training / *Kali Linux Revealed* pointers -> `P5` non-authoritative community notes). Incremental SHA-256 deduplicated indexing into SQLite (`kali_knowledge_documents`) + FTS `KnowledgeStore` with version, date, license, and reliability metadata. |
| **§185 & §197** | `community_and_research.py` (`KaliCommunityForumIntelligence`, `TechnicalResearchVerifier`) | Safe read-only forum troubleshooting synthesis (`AUTO_EXECUTE_FORUM_COMMANDS = False`, `AUTO_PUBLISH_ONLINE = False`). Detects destructive commands (`rm -rf`, `dd of=/dev/`, `curl \| sh`), flags outdated Kali advice (`apt-key add`, `--break-system-packages`, legacy codenames), prepares secret-redacted support drafts, and reconciles multi-source version/date conflicts. |
| **§186 & §196** | `universal_apps_and_chaining.py` (`UniversalApplicationRegistry`) | Dynamic discovery across **13 channels** (`.desktop`, `$PATH`, `apt`/`dpkg`, `flatpak`, `snap`, Python packages, Node `package.json`, config dirs, processes, D-Bus, AT-SPI, local APIs). Builds **15-field application profiles**, applies the **6-tier integration hierarchy** (`1_official_api_or_plugin` -> `6_desktop_gui_automation`), and answers live capability queries honestly. |
| **§187 & §198** | `universal_apps_and_chaining.py` (`MultiAppWorkflowAndChainEngine`) | Coordinates multi-tool pipelines under **one central `tasks` record** (`LAUNCH_EQUALS_COMPLETION = False`), validating input/output format compatibility, SHA-256 deduplication, fallback tool recovery, per-stage output verification, and anti-overwrite export protection. |
| **§188 & §189** | `cyber_labs_and_education.py` (`CybersecurityKnowledgeBase`, `AutonomousCyberLabManager`) | Connects **25 cybersecurity domains** to actually installed tools with 8 technical facets. Enforces authorized-target boundaries (`POSSESSION_IMPLIES_PERMISSION = False`) and runs CPU/RAM/disk/network-isolation preflight checks before provisioning isolated labs with snapshots and restore points. |
| **§190** | `system_model.py` (`KaliPackageIntelligence`) | Multi-ecosystem package/dependency inspection (`apt`, `dpkg`, `pip`/`venv`, `npm`, `git`, `docker`/`podman`). Blocks indiscriminate massive metapackage installs (`kali-linux-everything`, `kali-tools-all`) on low-spec hosts and forbids silent repository replacement. |
| **§192** | `cyber_labs_and_education.py` (`KaliTrainingAcademy`) | **11 Kali Training tracks** across `beginner`/`intermediate`/`advanced` depth: practical host-checked exercises, line-by-line command breakdowns, flashcards, quiz grading with wrong-answer analysis, roadmap tracking, and strict attribution separating official pointers from DEV-generated explanations. |
| **§193** | `cyber_labs_and_education.py` (`KaliTroubleshootingEngine`) | **13-step** machine-specific diagnostic playbooks across **19 Kali failure domains**, executing safe read-only probes before proposing minimal, proportionate repairs. |
| **§194** | `universal_apps_and_chaining.py` (`IntelligentProgramLearner`) | **12-step** unfamiliar-program learning in an isolated sandbox, strictly separating `known_functionality`, `inferred_functionality`, and `tested_functionality` (`PROMOTE_UNTESTED_EXAMPLE_TO_VERIFIED = False`). |
| **§195** | `dev_env_and_evolution.py` (`UniversalDevEnvironmentPartner`) | Multi-language project & toolchain partner (`Python`, `JS`, `TS`, `C`, `C++`, `Rust`, `Go`, `Java`, `Shell`, `SQL`, `HTML/CSS`), running non-polluting syntax/test checks (`PYTHONPYCACHEPREFIX` isolated) while preserving project layout. |
| **§199** | `dev_env_and_evolution.py` (`SelfImprovingKaliExpertise`) | **8-step** isolated self-improvement across **10 domains** (`ALLOW_SECURITY_OR_PRIVILEGE_ESCALATION = False`), requiring $\ge 3$ verified runs before promoting a `candidate` procedure to an `established_verified_rule`, with versioned history and instant rollback. |
| **§200** | `acceptance.py` (`nova.kali_intel.acceptance`) | **18-check** end-to-end live host acceptance verification suite (`all_passed == True`). |

---

## Verification & CLI Usage

```bash
# Run the 18-point §200 Final Kali Expertise Acceptance Test
python -m nova.kali_intel.acceptance

# Native CLI inspection & discovery
nova-x kali --system
nova-x kali --search "I want to inspect network traffic"
nova-x kali --profile openssl
nova-x kali --docs python3
nova-x kali --troubleshoot "externally-managed pip venv error"
nova-x kali --lesson kali_fundamentals
nova-x kali --capability "Which database software is installed?"
```
