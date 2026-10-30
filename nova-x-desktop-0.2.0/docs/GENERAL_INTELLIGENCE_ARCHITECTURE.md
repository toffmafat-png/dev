# DEV General Intelligence, Cognitive Architecture & Unlimited Capability Expansion (§236–§260)

This document describes the architecture, persistence model, safety invariants, and verification harness for Sections **236–260** (`nova/general_intelligence/` and `nova/tools/general_intelligence.py`).

## 1. Unified Cognitive & Memory Architecture (§236–§238, §256)

DEV coordinates all intelligence capabilities inside one local-first control plane (`PlatformService.general_intelligence` and `DesktopRuntime.general_intelligence`) rather than operating as disconnected agents with conflicting state (`DISCONNECTED_AGENT_REALITIES = False`).

- **§236 11 Coordinated Subsystems (`UnifiedCognitiveArchitecture`):**
  1. `perception_system` (`text`, `voice`, `document`, `screenshot`, `image`, `video`, `application_state`, `system_information`)
  2. `working_memory`
  3. `episodic_memory`
  4. `semantic_memory`
  5. `procedural_memory`
  6. `reasoning_engine`
  7. `planning_engine`
  8. `action_engine`
  9. `metacognitive_engine`
  10. `learning_engine`
  11. `executive_coordinator`
  All 11 subsystems read and update one monotonically versioned `SharedCognitiveContext` persisted in SQLite (`gi_cognitive_contexts`).
- **§237 & §256 11-Layer Memory, Consolidation & Claim Provenance (`MultiLayerMemoryAndProvenanceEngine`):**
  - Layers: `immediate_working_memory`, `conversation_memory`, `episodic_memory`, `semantic_memory`, `procedural_memory`, `project_memory`, `technical_knowledge`, `personal_preference_memory`, `environmental_memory`, `experimental_memory`, and `long_term_goal_memory`.
  - Tracks all 8 claim origins (`direct_user_statement`, `official_documentation`, `external_publication`, `tool_observation`, `measurement`, `experimental_result`, `model_generated_hypothesis`, `inferred_conclusion`) and preserves the strict distinction between source-reported claims and conclusions independently verified through testing.
  - Supports SHA-256 fingerprint deduplication, contradiction detection across opposing claims, outdated/expired claim detection, memory consolidation from transient layers into durable semantic/procedural/technical layers, controlled forgetting that protects verified history, and non-destructive updates preserving `correction_history`.
- **§238 15-Domain Dynamic World Model (`DynamicEnvironmentWorldModel`):**
  - Tracks `computer_hardware`, `operating_systems`, `applications`, `drivers`, `files`, `processes`, `services`, `networks`, `servers`, `databases`, `software_projects`, `ai_providers`, `user_defined_goals`, `external_information_sources`, and `connected_tools`.
  - Separates empirical `observation` records (with `observed_at` and `ttl_seconds`) from `prediction` records and traverses reverse dependency graphs (`predict_action_side_effects`) before consequential changes.

## 2. Scientific Reasoning, Metacognition, Autonomous Objectives & Strategic Roadmaps (§239–§242)

- **§239 12-Step Causal Reasoning & Hypothesis Engine (`ScientificCausalReasoningEngine`):**
  - Executes all 12 scientific problem-solving steps, compares competing hypotheses via real discriminating probes, runs numerical sensitivity and counterfactual (`what_if`) analysis, and enforces `UNTESTED_EXPLANATION_TREATED_AS_CONFIRMED = False`.
- **§240 Metacognition & Empirical Calibration (`MetacognitiveCalibrationEngine`):**
  - Evaluates 8 pre-decision checks, tracks empirical accuracy and Brier calibration per task domain in SQLite, maps claims onto `Verified`, `Strongly supported`, `Probable`, `Uncertain`, `Untested`, or `Unknown`, and enforces `MODEL_CONSENSUS_SUBSTITUTES_FOR_VERIFICATION = False` (multi-model agreement never upgrades an unverified claim to `Verified`).
- **§241 Bounded Autonomous Objective Generation (`AutonomousObjectiveGenerator`):**
  - Proposes justified maintenance/capability tasks tied to an explicit authorized goal or maintenance policy across 8 opportunity classes while enforcing active caps, signature deduplication, and recursion blocking (`ALLOW_UNBOUNDED_TASK_GENERATION = False`).
- **§242 Long-Term Strategic Planning (`LongTermStrategicPlanner`):**
  - Manages multi-week/month hierarchical roadmaps with DAG dependencies, checkpoints, fallback replanning on integration failures, and explicit detection of outdated or impossible objectives.

## 3. Transfer Learning, Continual Skill Acquisition, Research Lab & Multimodal Fusion (§243–§246)

- **§243 Transfer Learning (`CrossDomainTransferEngine`):** Inspects assumptions, prerequisites, and dependencies before adapting a procedure to a new domain, executes validation tests, and measures empirical improvement over baseline.
- **§244 12-Step Continual Skill Acquisition (`ContinualSkillAcquisitionEngine`):** Discovers CLI/library flags from documentation, builds and repairs isolated sandbox prototypes, writes `SKILL.md`, registers capabilities/tools, and requires passing an additional unseen holdout task (`READING_DOCS_ALONE_COUNTS_AS_ACQUIRED = False`).
- **§245 Scientific Discovery Lab (`ScientificDiscoveryLab`):** Performs CSV/JSON statistical analysis (missingness, IQR outliers, Pearson correlation, OLS regression, SHA-256 dataset provenance), preserves all 9 reproducibility fields, distinguishes `proposed_experiment`, `simulated_experiment`, and `completed_experiment`, and forbids fabricated citations (`FABRICATE_CITATIONS_OR_RESULTS = False`).
- **§246 Unified Multimodal Intelligence (`UnifiedMultimodalEngine`):** Combines screenshots/images, logs, documentation, audio/transcripts, PDF tables, code, and video while checking per-model modality capabilities (`ASSUME_ALL_MODELS_SUPPORT_ALL_MODALITIES = False`).

## 4. Collective Agents, Durable Execution & Distributed Nodes (§247–§249)

- **§247 Dynamic Collective Agents (`CollectiveAgentCoordinator`):** Spawns ephemeral task-scoped specialists across 12 roles (`PERMANENT_IDLE_AGENT_SWARM = False`), enforces resource-scope ownership locks against conflicting edits, emits A2A agent cards + MCP tool compatibility metadata, and reconciles outputs via `executive_coordinator` and `evidence_verifier`.
- **§248 Long-Horizon Durable Execution (`DurableExecutionEngine`):** Provides persistent SQLite WAL journals, step checkpoints, bounded retries, DAG scheduling, cooperative cancellation, resource-pressure pausing, and an `idempotency_ledger` guaranteeing that process restarts never repeat completed consequential operations. Evaluates scale-out frameworks such as Temporal without imposing multi-daemon infrastructure on single-PC Kali installs.
- **§249 Distributed Node Registry (`DistributedNodeOrchestrator`):** Tracks 8 node kinds and 9 hardware/capability/policy fields, signs workload envelopes with HMAC-SHA256, measures actual provisioned capacity (`CLAIM_UNLIMITED_SCALABILITY = False`), and falls back seamlessly to local execution when remote nodes are offline.

## 5. Evolution Lab, Evaluation, Fault Tolerance, AI Security, Alignment & Capability Roadmap (§250–§260)

- **§250 Evolution Lab (`EvolutionLaboratory`):** Evaluates 11 system dimensions and runs a 12-step isolated candidate pipeline with security AST/pattern checks and rollback protection (`CLAIMS_FRONTIER_WEIGHT_RETRAINING = False`).
- **§251 & §260 Evaluation Lab & 20-Task Unseen Acceptance Suite (`IndependentGIEvaluationLab`, `nova/general_intelligence/acceptance.py`):** Measures 17 intelligence dimensions across held-out unseen tasks without claiming AGI (`ADVERTISE_AGI_OR_HUMAN_LEVEL = False`).
- **§252 Reliability & Fault Tolerance (`ReliabilityAndFaultToleranceManager`):** Implements 15 reliability checks, 4 isolated failure-domain bulkheads (`desktop_ui`, `orchestration_engine`, `local_command_executor`, `background_workers`), versioned config rollback, and Safe Recovery Mode.
- **§253 AI Security & Model Governance (`AISecurityAndGovernanceEngine`):** Enforces 11 OWASP GenAI / NIST AI RMF controls, sanitizes untrusted documents against prompt injection, blocks self-permission expansion (`ALLOW_SELF_PERMISSION_EXPANSION = False`), and provides an automated adversarial test suite.
- **§254 & §255 Alignment & Non-Intrusive Oversight (`UserAlignmentAndOversightController`):** Manages 12 user preference categories (`PREFERENCE_IMPLIES_CONSEQUENTIAL_AUTHORIZATION = False`), executes routine authorized tasks without prompts, and finishes independent work before escalating on 8 consequential triggers.
- **§257–§259 Discovery, Cost/Compute Optimization & Living Capability Roadmap (`CapabilityExpansionAndOptimizationHub`):** Evaluates 10 technology categories (`AUTO_ADOPT_EVERY_DISCOVERY = False`), optimizes model/worker routing with verified caching (`ALLOW_AUTOMATIC_PURCHASES_OR_SUBSCRIPTIONS = False`), and resolves unfamiliar capability requests by searching existing abilities, acquiring verified tools, synthesizing & testing new Python tools, or stating exact limitations (`PRETEND_CAPABILITY_WHEN_IMPOSSIBLE = False`).

## 6. Verification Commands

```bash
# Run the 20-task §260 Final General Intelligence Acceptance Program
python -m nova.general_intelligence.acceptance

# Run the dedicated §236–§260 pytest suite
pytest tests/test_general_intelligence_expansion.py -q
```
