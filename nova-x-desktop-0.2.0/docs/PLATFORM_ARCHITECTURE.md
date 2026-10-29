# NOVA X Platform Architecture & Functionality Reference (§90–§115)

NOVA X remains a **native Kali Linux desktop application** (`PySide6`/Qt + local CLI + local execution engine) backed by SQLite, scoped workspace tools, frontier AI provider orchestration, and the cognition layer (`nova/cognition/`). Nothing in this expansion replaces the desktop app with a browser application or forces heavy optional runtimes onto low-spec hardware.

---

## 1. Technology Stack & Dependency Discipline (§90)

| Layer | Shipped Baseline (Lightweight Core) | Optional / Probed Extensions (Not Mandatory) |
|---|---|---|
| Desktop UI | Python 3.11+, `PySide6` (`QtWidgets`, signals/slots), `AsyncService` worker thread | System `libGL`/`libEGL` + X11/Wayland session |
| Core & Validation | Typed dataclasses, `pydantic>=2.7`, `asyncio`, `PlatformService` (`nova/platform_service.py`) | — |
| Storage & Search | `sqlite3` (WAL mode), **SQLite FTS5** (`porter unicode61`), `json1` | Pluggable local/remote embedding callbacks (`sentence-transformers`, `ollama`, provider API) |
| Isolation Sandbox | Linux user/mount/PID/IPC/UTS/net namespaces via `unshare` + `nova.sandbox_child`, `setrlimit`, `PR_SET_NO_NEW_PRIVS` | `bubblewrap` (`bwrap`), `podman` (with explicit local image) |
| Tooling & Interop | Native `ToolRegistry`, `PluginManager` (§92), `ExtensionContext` SDK (§109), JSON-RPC 2.0 `MCPClientManager` (§93) | External `stdio` / `https` MCP servers |
| Local Execution | `CommandRunner`, `TerminalWorkspace` (`asyncio` subprocesses + POSIX `pty`) | `pkexec`/polkit, D-Bus (`dbus-send`) |
| Modalities & Data | Streaming stdlib CSV/TSV/JSON/JSONL/Markdown/log profiler; PNG/GIF/PPM header & byte diff; pluggable STT/TTS protocols | `tesseract` (OCR), `grim`/`scrot` (capture), `playwright`, `pandas`/`polars`, `ollama` |
| Security & Secrets | `SecretStore` (Linux Secret Service / keyring), `AutonomyPolicy`, `CommandPolicy`, `Redactor` | Minisign/GPG package signature verification |

---

## 2. Section-by-Section Mechanism Status (§91–§115)

| Section | Module | Status | Verified Mechanism & Explicit Limitations |
|---|---|---|---|
| **§91 Event-Driven Intelligence Bus** | `nova/events.py` | Implemented | Schema-validated immutable `Event` (`nova-event-v1`), wildcard subscriptions (`task.*`), causal-chain cycle refusal, depth cap (`4`), dedupe window, subscriber idempotency keys, bounded queue/history, retries, and pre-dispatch `AutonomyPolicy` checks so events never bypass permissions. Process-local only. |
| **§92 Plugin & Skill Marketplace** | `nova/plugins.py` | Implemented | Full 11-part `PluginManifest` validation, categories, checksum check, install-disabled-by-default with zero inherited permissions, explicit permission grant on enable, update without silent privilege escalation, candidate staging + sandboxed test execution, and `ToolRegistry` binding (`plugin.<name>.<op>`). Cryptographic signature verification beyond SHA-256 is not yet wired. |
| **§93 MCP & Tool Interoperability** | `nova/mcp_client.py` | Implemented | Optional JSON-RPC 2.0 client over `stdio`, `https` (loopback HTTP opt-in), and `memory` transports; protocol version negotiation; tool/resource discovery; JSON-Schema input validation; minimal argument forwarding (never sends conversation history or local files); `untrusted_external` output tagging; independent policy check; disconnect & credential revocation. No SSE stream resumption yet. |
| **§94 Local Knowledge Engine & Hybrid Search** | `nova/knowledge.py` | Implemented | SQLite FTS5 full-text index with BM25 ranking, snippets, line/page citations, provenance & 30-day staleness flags, code symbol & filename search, incremental hash-checked reindexing, deleted-file cleanup, forget/delete API, and reciprocal-rank fusion with optional embeddings. Binary PDF/Office extraction requires external parsers and is refused rather than garbled. |
| **§95 Context & Memory Optimization** | `nova/context_manager.py` | Implemented | Five separated compartments (`confidential_credentials` excluded from prompts), non-compressible anchors (objective, constraints, permissions, blockers, error evidence), separated `verified_facts` vs `hypotheses`, extractive stage summaries, fingerprint cache deduplication, and `requires_source_recheck` before high-impact actions. |
| **§96 Advanced Terminal Workspace** | `nova/terminal.py` | Implemented | Multi-session workspace, named workdirs, live stdout/stderr callbacks, actor attribution (`nova` vs `user`), launch-method tracking (`argv_exec`, `shell_pipeline`, `pty_interactive`), process-group cancellation, templates, unified diff helper, redacted env/diagnostic export, and replay-hazard guard blocking automatic replay of deploy/destructive/payment commands. |
| **§97 Workflow Visual Editor Backend** | `nova/workflows.py` | Backend implemented; Qt canvas deferred | Versioned `nova-workflow-v1` DAG supporting all 14 block types, cycle/orphan/cost/schedule validation, runtime + save-time `AutonomyPolicy` enforcement, JSON import/export, natural-language draft proposal, dry-run mode, and idempotency keys. Native Qt drag-and-drop node canvas is a documented follow-up. |
| **§98 Cross-Application Automation** | `nova/workflows.py` (`CrossAppCoordinator`) | Implemented (file/API/CLI) | End-to-end 8-stage notes → requirements → report → validation → save → checklist → local email draft pipeline with per-stage verification and checkpointed resume so failed late stages never repeat earlier verified stages. GUI/Playwright stages are refused honestly when absent. |
| **§99 Visual Understanding** | `nova/modalities.py` (`VisualAssistant`) | Partial (honest) | Explicit opt-in capture probe (`grim`/`scrot`), local `tesseract` OCR wrapper, pure-Python PNG/GIF/PPM dimension & byte-change comparison, log correlation, upload authorization gate, and mandatory `epistemic_kind='visual_observation'` (`verified_system_fact=False`). Continuous capture is disabled (`False`). |
| **§100 Advanced Developer Environment** | `nova/devtools.py` | Implemented | Read-only git status/branch/diff, approval gate on force-push/hard-reset/protected branches/deploy/publish, repo & symbol search, Python/Node dependency pinning & HTTP checks, `.venv`-first environment inspection, pytest discovery, traceback root-cause parser, and sandboxed candidate-patch testing without touching the working tree. |
| **§101 Safe Execution Sandbox** | `nova/sandbox.py`, `nova/sandbox_child.py` | Implemented | Probes `bwrap`, configured `podman`, then `unshare` user+mount+pid+ipc+uts+net namespaces; mounts `/` read-only, binds only granted writable dirs, hides credential dirs (`~/.ssh`, `~/.gnupg`, etc.), enforces `RLIMIT_*` + `PR_SET_NO_NEW_PRIVS`, escalates timeouts to `SIGKILL`, never claims `process_only` is a sandbox, and **refuses** risky execution when isolation is unavailable. |
| **§102 System Health & Diagnostics** | `nova/governance.py` (`SystemHealthCenter`) | Implemented | Event-driven / on-demand snapshot of all 15 health dimensions (app, worker, active tasks, providers, API errors, resources, CPU/RAM, disk, SQLite, crashes, scheduled jobs, active NOVA processes, security events, failed integrations, pending updates) + redacted diagnostic export. Wired into `DesktopRuntime.diagnostics()`. |
| **§103 Observability & Debugging** | `nova/observability.py` | Implemented | W3C/OTel-compatible `trace_id`/`span_id`, automatic secret & credential-pattern redaction, retention pruning, local-only default, opt-in OTel payload export, and `explain_task(task_id)` answering all 8 §103 trace questions. Wired into `TaskEngine`. |
| **§104 Updates & Version Management** | `nova/updates.py` (`UpdateManager`) | Implemented | Trusted HTTPS/local manifest check (rejects HTTP & remote scripts), SHA-256 verification, platform/Python compatibility, SQLite online `backup()` + settings snapshot, migration check, candidate launch probe with automatic rollback on failure, and rejection of AI-proposed untested builds. |
| **§105 API Gateway & Integration Manager** | `nova/mcp_client.py` (`IntegrationGateway`) | Implemented | Unified registry with capabilities, minimum scopes, per-minute rate limiting, health probes, fallback chains, credential revocation, and strict separation of `auth_verified` from per-operation scope permission. |
| **§106 Offline & Degraded Operation** | `nova/updates.py` (`OfflineCoordinator`) | Implemented | Explicit `online` / `provider_unavailable` / `offline` modes, RAM-aware local runtime check (never auto-downloads models), offline queue with assumption + permission revalidation before resume, and refusal to fabricate online answers. |
| **§107 Voice, Audio & Speech Layer** | `nova/modalities.py` (`VoiceLayer`) | Modular core implemented | Pluggable local-first STT/TTS protocols, consent gate, push-to-talk, speech barge-in interruption, microphone indicator, typed-input fallback, identical planner/policy routing as typed text, and `SPEAKER_ID_AUTHORIZES_PRIVILEGED = False`. Live hardware audio capture requires optional OS audio packages. |
| **§108 Data & Knowledge Workspace** | `nova/data_workspace.py` | Implemented | Streaming CSV/TSV/JSON/JSONL/log/Markdown profiler, type/null/numeric stats, filter + group-by + chart series spec, document diff, citation scanner, reproducible stdlib Python script generator, and strict separation of `source_metadata` vs `generated_analysis`. |
| **§109 Extension API & Developer SDK** | `nova/plugins.py`, `docs/EXTENSION_SDK.md` | Implemented | Capability-safe `ExtensionContext`, JSON-Schema input/output validation, AST boundary check blocking `nova.db`/`nova.autonomy` imports, dev-mode validator, and 4 built-in example extensions. |
| **§110 Performance & Resource Adaptation** | `nova/resources.py` | Implemented | `/proc` CPU/load/MemAvailable/disk sampler tuned for dual-core ~10 GB RAM hardware; load-corroborated CPU busy check; scales down NOVA's concurrency/indexing/capture under pressure; never kills unrelated user processes. |
| **§111 Privacy-First Data Governance** | `nova/governance.py` (`PrivacyGovernor`) | Implemented | Unified 9-category inventory (never exposing secret values), retention policy, user data export/deletion, and outbound transmission gate blocking unjustified third-party file or screenshot uploads. |
| **§112 Release Engineering** | `scripts/build_deb.sh`, `.github/workflows/ci.yml`, `docs/RELEASE_CHECKLIST.md` | Implemented | Version-synced `.deb` packaging, Python 3.11–3.13 lint/test matrix, offline GIE gate, Qt offscreen UI gate, DB migration test, and `.deb` extract/CLI/uninstall-separation test. |
| **§113 Feature Discovery & Roadmap** | `nova/capabilities.py` | Implemented | Cached non-importing capability probes across 24 features, explicit unavailable/degraded reasons, 6 vetted dependency proposals with licence/cost/privacy notes (`AUTO_INSTALL_PERMITTED = False`), and weighted `prioritize()` scorer. |

---

## 3. Integration Testing Matrix Results (§114)

Executed via `pytest tests/test_integration_matrix.py -q`:

| # | Matrix Requirement | Automated Test | Result in Development Environment |
|---|---|---|---|
| 1 | Native application starts without a browser | `test_matrix_01_native_application_starts_without_browser` + `tests/test_desktop_ui.py` | **PASS** (`DesktopRuntime` & CLI verified locally; Qt `NovaWindow` skips locally due to missing `libGL.so` and **PASSES** in CI `desktop-ui` job with `libgl1`) |
| 2 | Local task engine executes & reports permitted command | `test_matrix_02_task_engine_executes_and_reports_permitted_command` | **PASS** |
| 3 | Command cancellation works | `test_matrix_03_command_cancellation_terminates_process` | **PASS** |
| 4 | Plugin installation respects declared permissions | `test_matrix_04_plugin_installation_respects_declared_permissions` | **PASS** |
| 5 | Compatible MCP server connects, inspects & disconnects | `test_matrix_05_mcp_server_connect_inspect_call_and_disconnect` (real `stdio` JSON-RPC subprocess) | **PASS** |
| 6 | Disconnected integration produces useful error | `test_matrix_06_disconnected_integration_produces_useful_error` | **PASS** |
| 7 | Full-text search returns correct local document passages | `test_matrix_07_fts5_returns_correct_local_document_passages` | **PASS** |
| 8 | Optional semantic retrieval behaves correctly when configured | `test_matrix_08_optional_semantic_retrieval_behaves_honestly_and_hybridizes` | **PASS** |
| 9 | Sandboxed task cannot access resources outside granted scope | `test_matrix_09_sandboxed_task_cannot_access_outside_granted_scope` (real Linux namespaces + fail-closed check) | **PASS** |
| 10 | Background task state survives supported restarts | `test_matrix_10_background_task_state_survives_restart` | **PASS** |
| 11 | Logs redact configured secrets | `test_matrix_11_logs_and_diagnostics_redact_configured_secrets` | **PASS** |
| 12 | Resource controls operate within defined limits | `test_matrix_12_resource_controls_operate_within_defined_limits` | **PASS** |
| 13 | Application updates preserve user settings and data | `test_matrix_13_updates_preserve_user_settings_and_data` | **PASS** |
| 14 | Application operates in reduced offline mode | `test_matrix_14_application_operates_in_reduced_offline_mode` | **PASS** |
| 15 | Failed update/candidate does not destroy stable installation | `test_matrix_15_failed_update_rolls_back_and_preserves_stable_install` | **PASS** |
| 16 | Workflow cannot bypass authorization policy | `test_matrix_16_workflow_cannot_bypass_authorization_policy` | **PASS** |
| 17 | No UI element claims success without backend result | `test_matrix_17_no_ui_or_status_claims_success_without_backend_result` | **PASS** |
| 18 | Remains usable within target hardware constraints (2 cores / ~10 GB RAM) | `test_matrix_18_usable_within_dual_core_10gb_hardware_constraints` (< 64 MB peak traced heap on 5,000-row stream) | **PASS** |

---

## 4. Known Gaps & Deferred UI Surfaces

1. **Visual workflow node canvas (§97):** The DAG schema, validator, policy enforcer, importer/exporter, natural-language proposer, and executor are complete; a Qt drag-and-drop block canvas is not yet built.
2. **Cryptographic package/plugin signatures (§92, §104):** SHA-256 integrity checks are enforced; Minisign/GPG key-ring verification is planned before remote plugin repositories are enabled.
3. **Binary document parsers (§94, §108):** PDF/DOCX/XLSX files are explicitly refused rather than mis-parsed until lightweight optional extractors are approved by the operator.
4. **Live hardware audio/screen backends (§99, §107):** On headless hosts without `grim`/`scrot`, `tesseract`, or ALSA/PipeWire Python bindings, NOVA reports the exact missing binary and falls back to typed/text operation.
