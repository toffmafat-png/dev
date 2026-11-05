# DEV — Autonomous Architecture, Source Code Evolution & Self-Engineering Engine (§276–§295)

`nova.self_engineering` equips DEV with controlled, metric-verified, rollback-preserving software engineering capabilities over its own repository, SQLite persistence layer, dynamic plugins, release channels, and runtime health.

## Architecture & Module Map

- `nova/self_engineering/code_intel_and_arch.py`
  - **§276 Core Mission (`SELF_ENGINEERING_11_ROLES`):** Covers all 11 engineering roles from `principal_software_architect` through `technical_documentation_engineer`.
  - **§277 Self-Source-Code Intelligence (`SelfSourceCodeIntelligenceEngine`):** Inspects 20 repository domains via `git`, Python `ast`, import/call graphs, symbol indexing, SQLite `sqlite_master` introspection, FastAPI/CLI discovery, and test inventory. Never invents architectural details or trusts stale documentation over live code.
  - **§278 & §280 Architectural Analysis & Redesign (`AutonomousArchitecturalAnalyzer`):** Evaluates 16 engineering dimensions (tightly coupled modules, circular dependencies, duplicate AST bodies, high-LOC modules, blocking calls in `async def`, bare `except:`, unindexed query patterns, coverage gaps, etc.), records SQLite-persisted Architecture Decision Records (`self_eng_adrs`), and compares `modular_monolith` vs. `independent_local_processes` vs. `distributed_execution` without introducing gratuitous microservices, brokers, containers, or extra databases.
  - **§289 Architecture Knowledge Graph (`ArchitectureKnowledgeGraph`):** Builds a live 14-entity-kind graph from actual source/configuration and computes transitive change impact (`affected_modules`, `recommended_tests`) before refactoring.
- `nova/self_engineering/modification_modules_perf.py`
  - **§279 Autonomous Source Modification (`AutonomousSourceModifier`):** Stages multi-file edits inside isolated candidate clones (`data/self_engineering/workspaces/<channel>/<change_id>`), validates AST syntax + `pytest`, records unified diffs and pre-change snapshots, and rejects failed candidates without ever mutating the sole working production copy directly.
  - **§281 & §285 Dynamic Module Lifecycle & Controlled Hot-Reloading (`DynamicModuleAndPluginLifecycle`):** Enforces all 12 manifest fields (`MODULE_MANIFEST_12_FIELDS`) and executes the 11-step lifecycle (`DYNAMIC_MODULE_11_STEPS`). Stateless modules can hot-reload via `importlib.reload`; stateful modules with unmigratable active objects require `staged_restart_required=True`.
  - **§282 Autonomous Performance Engineering (`AutonomousPerformanceEngineer`):** Profiles code with `cProfile`, `tracemalloc`, `time.perf_counter`, and `time.process_time`, plus SQLite `EXPLAIN QUERY PLAN`, requiring measurable before-vs-after evidence (`claim_verified`).
  - **§293 Self-Modification Governance (`SelfModificationGovernance`):** Separates 6 zones (`stable_production_code`, `experimental_code`, `candidate_upgrades`, `core_security_and_authorization`, `user_data_and_persistent_memory`, `external_configurations_and_credentials`), requires stronger safeguards for security/permission/migration boundaries, and enforces immutable operator-control laws (`never_remove_ability_to_be_stopped`, `never_revoke_user_control`, `never_hide_activities`, `never_grant_unrestricted_privileges`).
- `nova/self_engineering/scale_storage_release_qa.py` & `recovery_launcher.py`
  - **§283 Scalable Architecture (`ScalableArchitectureCoordinator`):** Preserves the local Kali Linux desktop/control plane, evaluates 9 placement factors across 8 optional node kinds, keeps sensitive private data local, and maintains honest local fallback when extra nodes are offline.
  - **§284 Database & Storage Self-Migration (`DatabaseSelfMigrationEngine`):** Evaluates SQLite-WAL vs. PostgreSQL justification and executes 10-step schema migrations (`DB_MIGRATION_10_STEPS`) against a verified copy of the real database first, checking `PRAGMA integrity_check` and guaranteeing zero loss of user memories, conversations, or tasks.
  - **§286 Release & Self-Update (`ReleaseAndSelfUpdateEngine`):** Manages `experimental`, `candidate`, and `stable` channels, deterministic `.tar.gz` release packages with SHA-256 manifests, atomic update transaction journals, interrupted-update recovery, and instant rollback to known-good stable versions.
  - **§287 Independent QA (`IndependentQATestEngine`):** Covers 13 QA categories, prevents weakening assertions (`detect_test_weakening`), and stores verbatim versioned test output in `self_eng_test_runs`.
  - **§288 Self-Repair & Recovery (`SelfRepairAndRecoveryEngine` & `nova.self_engineering.recovery_launcher`):** Classifies failures across `ui`, `worker`, `database`, `plugin`, and `core_engine`, enforces an anti-endless-repair-loop circuit breaker, and ships a stdlib-only recovery CLI (`python -m nova.self_engineering.recovery_launcher`) if the main application cannot start.
- `nova/self_engineering/assistant_deps_roadmap.py`
  - **§290 Autonomous Engineering Assistant (`AutonomousEngineeringAssistant`):** Runs the 14-step self-directed engineering workflow from high-level natural-language objectives without requiring user-supplied file paths.
  - **§291 Dependency Intelligence (`SelfMaintainingDependencyIntelligence`):** Audits 10 dependency dimensions, flags incompatible/duplicate constraints, generates a CycloneDX-lite SBOM, and never blindly auto-upgrades all packages.
  - **§292 Continuous Architectural Improvement (`ContinuousArchitecturalImprovementEngine`):** Maintains a metric- and acceptance-gated engineering roadmap in `self_eng_roadmap_items`.

## CLI, HTTP API & Acceptance Suite

- **CLI:** `nova-x self-eng [--inspect | --architecture | --dependencies | --roadmap | --objective "..." | --recover]`
- **Standalone Recovery Launcher:** `python -m nova.self_engineering.recovery_launcher --data-dir ./data [--restore-stable 0.2.0]`
- **HTTP Endpoints:** `/api/self-engineering/status`, `/api/self-engineering/inspect`, `/api/self-engineering/architecture`, `/api/self-engineering/impact`, `/api/self-engineering/dependencies`, `/api/self-engineering/roadmap`, `/api/self-engineering/objective`
- **Acceptance Suite (§294):** `python -m nova.self_engineering.acceptance` (executes and reports all 20 real verification checks)
