# NOVA X cognition layer — what is actually implemented

This document describes the general-intelligence expansion (§70–§89) in terms of
**mechanisms that exist in code and are verified by tests**, and states plainly
what does not exist. It is deliberately not a capability brochure.

Nothing here claims human-level intelligence, consciousness, independent
understanding, or AGI. What exists is a set of bounded, inspectable, persisted
reasoning mechanisms whose behaviour can be checked by running:

```bash
python -m nova.cognition --workspace ./workspace --db ./data/nova.sqlite3
```

That command runs the `nova-gie-v1` evaluation suite (§86) and exits non-zero if
any case fails. It makes no provider calls.

Location: `nova/cognition/`. Persistence: seven new tables in `nova/db.py`.
Wiring: `nova/engine.py` hooks and `/api/cognition/*` routes in `nova/main.py`.

---

## 1. Design rules the code enforces

These are not aspirations; each is a checked behaviour with a test.

| Rule | Where it is enforced |
|---|---|
| A statement with no evidence is not an observation | `epistemic.classify_claim` demotes it to `inference`/`unknown` |
| Confidence is scored against outcomes, never trusted | `epistemic.CalibrationLedger.report` (ECE, Brier, overconfidence) |
| Too few outcomes ⇒ no score is published | `report()` returns `insufficient_data` below 10 samples |
| A measured value that changed forces re-inspection | `world_model.WorldModel.requires_reinspection` |
| Environment facts expire | per-predicate TTLs; `Observation.is_stale` |
| Predicted and actual outcomes stay separate | `planning.Decision.record_actual`; `world_model.resolve_prediction` |
| One obvious cheap option ends the comparison | `planning.evaluate_options` short-circuit |
| Curiosity cannot leave the authorized roots | `curiosity.within_scope` (path-normalizing) |
| Curiosity cannot exceed its budget | `curiosity.resolve_gap` skips and escalates to the user |
| One success never makes a procedure established | `procedures._status_after_outcome` (3 attempts, 2 successes, ≥60%) |
| Established knowledge survives pruning | `procedures.prune_unreliable` skips established procedures |
| Wrong knowledge can be corrected/removed with provenance | `procedures.correct`, `procedures.remove`, history log |
| Agreement between models is not evidence | `orchestration.reconcile` caps confidence at 0.35 and marks it `unverified_consensus` |
| Roles follow the objective, not a fixed cast | `orchestration.derive_roles` |
| A model-derived assessment may not authorize itself | pre-flight verdicts are reported, never executed on (§84) |
| A cognition defect may not break a task | `service._guarded`; `TaskEngine._predict_tool_call`/`_assess_plan`/`_reflect` |
| Held-out cases are never used as a baseline | `evaluation.main` refuses; `db.get_latest_intelligence_baseline` filters them |
| Missing tools are reported as skips, not passes | `EvalOutcome(status="skipped", detail=...)` |

---

## 2. Status by section

### §70 General problem-solving engine — partial

**Implemented.** `orchestration.derive_roles` decomposes an objective into
subtasks, assigns each a *required capability* (not a persona), and marks a
subtask unassignable when no registered tool could carry it out. Unassignable
work is routed to `clarification` rather than answered from model text. Retrieval
of prior procedures (`procedures.ProcedureLibrary.retrieve`) means a familiar
shape of task reuses demonstrated knowledge.

**Not implemented.** There is no general solver, no automated means-ends
analysis, and no novelty detection. Decomposition is pattern-driven over the
objective and plan text; an objective phrased unlike anything in
`_SUBTASK_PATTERNS` falls back to a single `independent_analysis` subtask. The
system does not avoid predefined templates by being clever — it avoids them by
accumulating its own procedures from real runs, and that accumulation starts
empty.

### §71 Cross-domain learning and transfer — partial

**Implemented.** `procedures.transfer_check` compares a stored procedure's
recorded environment markers (OS, init system, runtime, required tools) against
the target context and returns `compatible` / `partially_compatible` /
`incompatible` / `unknown`, with explicit `required_adaptations` and a `reverify`
list. When no marker can be compared it returns **`unknown` with confidence
0.0** — it does not default to "compatible".

**Not implemented.** Transfer is marker comparison plus lexical retrieval, not
abstraction. There is no structural analogy reasoning, no embedding-based
similarity, and no automatic adaptation: the adaptations are *instructions to
the model*, and whether it follows them is not verified. Retrieval is token
overlap, so a procedure described in different vocabulary will not be found.

### §72 Meta-reasoning and self-evaluation — implemented (bounded)

**Implemented.** `meta_reasoning.preflight` produces a bounded assessment before
execution: understood facts, unknowns, missing evidence, riskiest assumptions,
failure modes, capability gaps (split into *blocking* and *policy-gated*),
derived acceptance criteria, the cheapest sufficient verification, abandon
conditions, a cheaper-alternative note, cost estimates, and a rule-based
confidence in 0.05–0.9. `meta_reasoning.post_hoc` attributes an outcome to one
of eight causes using recorded evidence (tool statuses, budget, contradictions,
criterion counts) rather than narrative.

The engine runs pre-flight on every fresh plan (`TaskEngine._assess_plan`),
persists it, emits a `cognition` task event, and injects the acceptance criteria
and blocking gaps into the execution prompt. Post-hoc runs on every terminal
state, including success.

**Limits.** Pre-flight is structural analysis of text, not foresight. Its
confidence is a heuristic score and is only meaningful because
`CalibrationLedger` scores it afterwards. A `blocked` verdict does **not** stop
the task: per §84 a model-derived assessment may not override the user's
authorization, so it is reported and surfaced instead.

### §73 Internal world model and causal reasoning — implemented (bounded)

**Implemented.** `world_model.WorldModel` stores observations keyed by
`(subject, predicate)` with per-predicate TTLs (`service.state` 30 s,
`resource.usage` 15 s, `command.exit_code` never stale), bounded history, and
LRU eviction (floor of 50 entries). `predict()` registers an expectation before
an action; `resolve_prediction()` compares it with what was observed, records
each contradiction individually, and flags the subject for re-inspection.
`hypothesize()` / `record_hypothesis_outcome()` require 3 confirmations to reach
`supported` and treat any refutation as terminal.

The engine predicts `tool:<name>.outcome = succeeded` before each call and
resolves it against the real result. Outcomes are compared in a **normalized
space** (`succeeded`/`failed`/`blocked`/`pending_approval`) because tools report
their own vocabulary — the calculator returns `"success"`, not `"ok"`. Comparing
raw strings made every successful call look like a contradiction; that defect was
found by the engine integration test and is fixed.

**Not implemented.** This is not causal inference. Relations carry an `inferred`
flag and unfounded inferences get their predicate suffixed `(unfounded)`, but
there is no do-calculus, no intervention reasoning, and no learned causal graph.
`_subject_of_key` recovers subjects by longest-prefix match against observed
subjects; a contradiction about a never-observed subject falls back to splitting
on the last dot and can mis-attribute.

### §74 Counterfactual planning and decision intelligence — implemented (bounded)

**Implemented.** `planning.evaluate_options` scores options on cost relative to
budget (0.30), risk banded against the operator-selected tolerance (0.35),
reversibility (0.15), verifiability (0.15) and authorization friction (0.05).
Options that need a missing capability, lack authorization, or exceed budget
score 0 and can never be chosen. When exactly one option is cheap, low-risk,
reversible and verifiable, the comparison **short-circuits** and says so.
`Decision.predicted_outcome` is prefixed `Predicted (not yet executed)` and
`record_actual()` stores the real result separately, yielding a measurable
`prediction_accuracy`.

Exposed as `POST /api/cognition/decisions`; resolved decisions are scored at
`GET /api/cognition/decisions`.

**Limits.** The scores are a fixed linear weighting over *caller-supplied*
estimates. NOVA does not measure real cost or risk from experience; if the
caller's estimates are wrong the ranking is wrong. Counterfactuals are enumerated
options, not simulated futures — nothing is rolled forward in a model of the
world.

### §75 Active learning and curiosity engine — implemented (bounded)

**Implemented.** `curiosity.resolve_gap` walks a seven-rung ladder in cost
order — recall from memory → local documentation → external search → specialist
model → bounded experiment → write a test case → ask the user — skipping any
rung that lacks a tool, lacks authorization, exceeds budget, or falls outside
the authorized roots. `within_scope` normalizes paths (collapsing `..`,
expanding `~`) and compares resolved absolute paths, so `workspace/../../etc/passwd`
is refused. Privacy-sensitive gaps refuse local exploration outright. An
exhausted budget escalates to the user rather than digging further.
`ExplorationLog` records what curiosity actually cost.

**Not implemented.** This produces a *plan*; the rungs are not executed
automatically. There is no autonomous experiment loop, no information-gain
estimate, and no intrinsic motivation. Gap discovery is not automatic either — a
gap must be stated by a caller.

### §76 Skill acquisition framework — **not implemented**

Deliberately. Acquiring a skill means running code or commands NOVA did not
write, in an environment it does not control. The existing roadmap already gates
this on a reviewed isolation design (ROADMAP item 13), and that gate has not been
passed. What exists is the *safe half*: `procedures` captures workflows NOVA
performed with already-authorized tools, and `meta_reasoning` flags capability
gaps as blocking so they are reported instead of worked around.

There is no plugin loader, no download-and-execute path, and no mechanism by
which a new skill could obtain filesystem or administrative access. Per the
requirement that externally downloaded code is untrusted until reviewed and
tested, nothing here automates that trust decision.

### §77 Continual learning without forgetting — implemented (bounded)

**Implemented.** Procedures carry `provenance` (`user`, `tool_result`,
`external_source`, `test`, `memory`, `model_generated`), evidence refs, source
task IDs, a version, and lineage (`supersedes` / `superseded_by`). Promotion to
`established` requires 3 attempts, 2 successes and a ≥60% ratio; an established
procedure that drops below 60% is demoted with a recorded reason. `correct()`
and `remove()` record who said so and why, and every mutation appends to a
history log. `prune_unreliable()` removes only non-established procedures with
enough attempts and a poor ratio, so accumulating experience cannot erase what
already works. State round-trips through `export_state`/`import_state` and the
`cognition_procedures` table; `import_state` sanitises unknown provenance and
status values instead of raising on corrupted rows.

The engine calls `learn_from_task` on every terminal state. A new task whose
objective matches an existing procedure at ≥0.60 **reinforces** it rather than
creating a near-duplicate — that is the actual transfer path.

**Limits.** When a run completes but independent verification found no
supporting evidence, the outcome is recorded as `not_scored` — neither success
nor failure — because guessing either way would corrupt the reliability figures.
There is no weight update of any kind and no forgetting curve; "without
forgetting" here means "pruning does not delete established procedures".

### §78 Long-horizon planning and goal management — partial

**Implemented.** Plans, checkpoints, milestones and tool results are persisted
in SQLite (`tasks.plan_json`, `tasks.checkpoint_json`) and survive a process
restart; the evaluation case `plan_persists_across_restart` opens a fresh
`Database` handle on the same file and recovers steps, `active_index`,
milestones and events. `recover_interrupted_tasks` and the existing goal
scheduler provide the resume path.

**Not implemented.** There is no milestone-level replanning, no automatic
decomposition of a goal into dependent sub-goals with their own budgets, and no
progress estimator. NOVA does not execute while the machine is off or the worker
is not running, and nothing here implies otherwise. Cancelled, expired and
superseded goals are not resumed: `run_task` returns immediately for terminal
states and `waiting_approval`.

### §79 Multimodal perception — **not implemented**

No image, audio, video or screen input is parsed anywhere in this layer. Per the
requirement to report the limitation instead of pretending to see it: if a task
needs a modality NOVA cannot observe, `preflight` classifies it as a blocking
capability gap (`screen capture`, `desktop GUI automation`) and the plan is
reported as blocked.

### §80 Scientific and engineering research — **not implemented**

No experiment runner, no measurement pipeline, no citation handling. The bounded
`run_bounded_experiment` rung in §75 exists as a *plan* step only and is not
executed. Nothing here generates hypotheses about the natural world, and no
result, citation or measurement is ever synthesized: `epistemic.classify_claim`
refuses to mark model text as an observation, which is the mechanism that would
otherwise let a fabricated result enter the world model.

### §81 Creative and strategic intelligence — **not implemented**

No novelty scoring, no ideation pipeline, no strategy search. `planning`
compares caller-supplied options; it does not generate them.

### §82 Social and collaborative intelligence — **not implemented**

No user modelling, no affect inference, no communication on the user's behalf.
Outbound communication is a **blocking** capability gap in `preflight`, and
`Option`s that require it can never be selected. NOVA does not impersonate the
user or make commitments.

### §83 Intelligence calibration and error awareness — implemented

**Implemented.** `CalibrationLedger` computes expected calibration error over 5
buckets, Brier score, mean confidence, observed success rate and overconfidence,
and reports `well_calibrated` (ECE ≤0.05), `acceptably_calibrated` (≤0.15),
`poorly_calibrated`, or `insufficient_data` (<10 samples). The engine records a
calibration entry for every finished task that had a pre-flight confidence, and
**only** for those — when NOVA made no prediction, no confidence is invented so
that a number can be published. `orchestration.reconcile` refuses to treat model
agreement as evidence: unanimous outputs with no independent evidence ref yield
`unverified_consensus` with confidence capped at 0.35 and an explicit warning.

Surfaced at `GET /api/cognition/calibration` and in `GET /api/health`.

### §84 Autonomous decision-making under constraints — partial

**Implemented.** Budget, risk tolerance and the authorized-option set are always
supplied by the caller from policy; nothing in the cognition layer can widen
them. Options requiring authorization that has not been granted score 0. A
pre-flight `blocked` verdict is reported and injected into the prompt but does
not cancel a user-authorized task. The existing autonomy policy, approval gates
and tool permission scopes remain authoritative and untouched.

**Not implemented.** There is no constraint solver and no automatic re-planning
when a constraint is violated mid-run. The engine's existing replanning loop is
unchanged.

### §85 Multi-agent coordination — implemented (bounded)

**Implemented.** `derive_roles` builds a coordination plan whose roles carry a
function, the objective feature that produced them, an output contract, and a
`provider_role` matching the identifiers `IntelligenceOrchestrator` already
emits (`independent_analysis`, `conflict_review`, `synthesis`, `targeted_critique`,
`revision`) — so a plan can drive the existing fusion pipeline instead of running
beside it. An objective that itself poses a choice gets an extra independent
pass; a budget under 4 remaining requests reduces coordination instead of
overspending. `detect_contradictions` finds polarity and numeric conflicts over
shared subject tokens; `find_agreements` finds shared statements; `reconcile`
gates the result on evidence sufficiency.

**Limits.** These are roles with checkable jobs, not agents — there is no
separate process, memory or incentive per role, and the module does not pretend
otherwise. Contradiction detection is lexical: it compares negation markers and
numeric tokens over shared vocabulary. Two statements that conflict
semantically without sharing words or numbers will not be caught.
`derive_roles` produces a plan; the engine does not yet execute multi-role
coordination through it (the existing fusion path is unchanged).

### §86 General intelligence evaluation suite — implemented

**Implemented.** `nova-gie-v1`: 30 executable cases over 11 capability areas,
27 in the default split and 3 held out. Each case returns `passed` / `failed` /
`skipped` / `blocked` with a recorded measurement. The whole suite runs in
roughly 10 ms with zero provider calls and is deterministic, so it can gate CI.

Baselines are versioned and stored in `intelligence_eval_runs`. Held-out runs
are persisted but never selected as a baseline, and the CLI refuses to save a
baseline from a run that included them. A baseline whose suite version differs,
or which stored no per-case rows, is reported as **not comparable** rather than
producing a vacuous "no regressions". Every report carries `claim_limitations`
stating what the suite cannot show.

```bash
python -m nova.cognition --workspace ./workspace --db ./data/nova.sqlite3
python -m nova.cognition --include-held-out          # never baseline on this
python -m nova.cognition --save-baseline baseline.json --baseline baseline.json
```

Also available at `POST /api/cognition/evaluation/run`, with the manifest at
`GET /api/cognition/evaluation/manifest`.

**Limits.** 30 cases is not a measure of general intelligence and the report says
so. The cases exercise NOVA's mechanisms, not open-ended competence on tasks
nobody anticipated. Provider-dependent behaviour is evaluated with injected
fakes; live model quality is measured by the separate `nova-eval-v1` runs.

### §87 Safe self-improvement and stable core — **deliberately minimal**

**Implemented, and only this:** evaluation, versioned baselines, regression
detection, and the correction/supersession/removal paths in §77. A learned
procedure can influence *retrieval ranking*; it cannot alter code, configuration,
permissions, authentication, secret handling, auditing, or shutdown behaviour.

**Not implemented, by design.** There is no path by which an AI-generated change
is applied to the running system. No self-modification, no auto-promotion of a
procedure into a tool, no automatic threshold tuning, no self-granted authority.
The security and authorization mechanisms (`nova/autonomy.py`,
`nova/desktop/policy.py`, `nova/desktop/secrets.py`, the session store) are
untouched by this work and are not reachable from the cognition layer. The
success criteria inside the evaluation suite are fixed in code and cannot be
edited at runtime by the system being evaluated.

A validated rollback path is not applicable because there is nothing to roll
back: no automatic change is ever made.

### §88 Continuous operation and human collaboration — partial

**Implemented.** The cognition layer degrades instead of failing: every public
`CognitionService` method runs inside `_guarded`, and the engine wraps each call
site. A storage failure is counted, logged once, and reported through
`snapshot()["degraded"]` and `GET /api/health`, while the user's task continues
to completion — verified by
`test_a_cognition_failure_cannot_break_task_execution`. Exceptions are reported
only where they matter; a persistence failure during observation is logged at
debug level rather than surfacing as an error.

Existing pause, resume, cancel, emergency-stop and approval controls are
unchanged and still take effect immediately. An unfinished task receives **no**
post-hoc attribution (`test_an_unfinished_task_gets_no_post_hoc_attribution`), so
NOVA never concludes anything about work the user has paused.

**Not implemented.** No new human-collaboration surface: there is no
negotiation, no explanation-on-demand dialogue beyond the persisted reviews, and
no cognition panel in the native Qt desktop window yet. The APIs exist; the
native UI does not render them.

### §89 Final acceptance test — partial, reported honestly

Tasks A–G were used to shape the mechanisms and are covered where they can be
exercised offline:

| Task | Covered by | Status |
|---|---|---|
| A — software engineering | `unfamiliar_task_decomposes`, engine tests with a real tool run | partial: no real repository work is executed |
| B — system diagnosis | `contradiction_forces_reinspection`, `post_hoc_attributes_denial`, engine denial test | partial: diagnosis is against recorded state, not a live host |
| C — research | `curiosity_is_bounded`, `curiosity_respects_scope` | not demonstrated: no external research is executed (§80 absent) |
| D — transfer learning | `transfer_detects_environment_change`, `retrieval_prefers_reliable`, `learning_reinforces_a_matching_procedure` | implemented |
| E — long-horizon planning | `plan_persists_across_restart` | partial: persistence yes, milestone replanning no |
| F — adaptation to provider outage | `test_a_cognition_failure_cannot_break_task_execution`, existing provider-failure tests | partial: a cognition failure is survived; provider-outage adaptation is the pre-existing fallback path |
| G — self-improvement | `reliability_thresholds_apply`, `pruning_does_not_forget`, `knowledge_can_be_corrected` | implemented as *learning*; §87 auto-apply is absent by design |

Both successful and failed tests are reported. Missing tools and configuration
limits appear as `skipped` with a reason naming the limitation — for example the
persistence case reports "No database supplied in this evaluation context"
rather than passing silently.

---

## 3. Persistence

Seven tables, created idempotently in `Database.initialize()`:

| Table | Holds |
|---|---|
| `cognition_observations` | world-model facts, with source, TTL, task and evidence ref |
| `cognition_predictions` | expectations and their resolution, agreement and contradictions |
| `cognition_procedures` | learned workflows: steps, environment, reliability, lineage, provenance |
| `cognition_calibration` | every scored prediction (confidence, outcome, domain, task) |
| `cognition_reviews` | pre-flight and post-hoc reviews per task |
| `cognition_decisions` | option evaluations, forecasts, and the actual outcomes |
| `intelligence_eval_runs` | `nova-gie-v1` runs, baselines and regression lists |

`CognitionService` hydrates from these at construction and persists on write.
Hydration is idempotent and tolerant: a corrupted procedure row is sanitised
rather than raising, and a database that throws is counted in `errors` and
reported as `degraded`.

## 4. HTTP surface

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/cognition` | live snapshot: world model, calibration, procedures, exploration, degraded flag |
| GET | `/api/cognition/beliefs` | claim summary over the current world model |
| GET | `/api/cognition/observations` | observations, re-inspection list, prediction accuracy |
| GET | `/api/cognition/calibration` | calibration report and recent records |
| GET | `/api/cognition/procedures` | counts, thresholds, stored procedures, activity history |
| GET | `/api/cognition/procedures/{id}/transfer` | environment-compatibility verdict for a new context |
| POST | `/api/cognition/procedures/{id}/correct` | mark knowledge wrong/outdated with reason and provenance |
| DELETE | `/api/cognition/procedures/{id}` | remove stored knowledge |
| GET | `/api/cognition/decisions` | decisions plus forecast-versus-actual accuracy |
| POST | `/api/cognition/decisions` | score candidate approaches |
| GET | `/api/cognition/tasks/{id}/reviews` | pre-flight and post-hoc reviews for one task |
| POST | `/api/cognition/gaps` | bounded plan to resolve a knowledge gap |
| GET | `/api/cognition/evaluation/manifest` | suite version, cases, capability map |
| GET | `/api/cognition/evaluation/baseline` | the current comparable baseline |
| GET | `/api/cognition/evaluation/runs` | run history |
| POST | `/api/cognition/evaluation/run` | execute the suite |

All routes sit behind the existing access-token gate. `limit` parameters are
clamped. Correction requires a provenance from the fixed vocabulary; an unknown
value is a 422.

## 5. Security posture

* The cognition layer holds no credentials and cannot request any.
* It cannot alter the autonomy policy, tool permissions, approval gates, session
  handling, or secret storage. Those modules are not imported by it.
* `within_scope` is the privacy boundary for exploration planning, and it
  normalizes paths before comparing them.
* Nothing executes: curiosity produces plans, planning produces scores,
  procedures produce ranked suggestions. Execution remains the engine's job,
  through the existing policy gate.
* Model output is never recorded as an observation. Only `tool_result`, `user`,
  `external_source` and `test` provenance can support one.

## 6. Known gaps, in priority order

1. **§76 skill acquisition** — blocked on the reviewed isolation design already
   tracked as ROADMAP item 13. Do not start without it.
2. **§85 execution** — `derive_roles` produces coordination plans that nothing
   consumes yet. Wiring them into `IntelligenceOrchestrator` is the next
   increment; until then the existing fusion path is what actually runs.
3. **Native desktop UI** — the Qt window does not render any cognition state.
   The APIs are there; the panel is not.
4. **§79 / §80 / §81 / §82** — absent, and intentionally so. Each needs a
   capability NOVA does not have (perception, experiment execution, generative
   search, user modelling) and should not be simulated.
5. **§78 milestone replanning** — milestones persist but nothing replans around
   them.
6. **Semantic retrieval** — procedure matching is lexical. A procedure described
   in different words will not be found, and no embedding step exists.
7. **Prediction vocabulary** — the engine predicts only "this tool call will
   succeed". Richer, task-level predictions would make `prediction_accuracy` a
   more useful signal.
8. **Calibration volume** — the ledger starts empty and needs ~10 resolved
   outcomes before it reports anything. A fresh install therefore reports
   `insufficient_data`, which is correct but means the signal takes time to
   exist.
