"""Cognition layer: the measurable mechanisms behind NOVA X's general capability.

Everything in this package is deliberately **offline, deterministic and
testable**. No module calls a model provider on its own: provider access is
always injected by the caller (the engine, the orchestrator or a test double),
which is what makes the reasoning behaviour assertable rather than merely
plausible.

Modules
-------
``epistemic``
    Claims with provenance, and calibration of stated confidence against
    observed outcomes (§72, §77, §83).
``world_model``
    A time-bounded model of the observed environment: observations with TTLs,
    relations, predictions that get resolved against reality, and hypotheses
    (§73).
``meta_reasoning``
    Pre-flight review of a plan and post-hoc attribution of the outcome to a
    cause, based on recorded evidence (§72).
``planning``
    Counterfactual option scoring on cost, risk, reversibility and
    verifiability, with a bounded short-circuit (§74, §84).
``curiosity``
    A cost-ordered ladder for resolving knowledge gaps inside hard resource,
    authorization and privacy bounds (§75).
``procedures``
    Learned workflows with reliability thresholds, environment transfer checks,
    correction/supersession, and pruning that does not forget what works
    (§71, §77).
``orchestration``
    Roles derived from the objective, contradiction detection, and the rule
    that agreement between models is not evidence (§85, §83).
``evaluation``
    The ``nova-gie-v1`` executable evaluation suite with a versioned baseline
    and a held-out split (§86, §89).

What this package does **not** claim
------------------------------------
It does not implement consciousness, independent understanding, or general
intelligence, and nothing here should be described that way. It implements
specific mechanisms - provenance tracking, staleness detection, calibration
scoring, budget enforcement, transfer checks, evidence gating - whose behaviour
can be verified by running the test suite. Capabilities that are not yet
implemented are recorded as gaps in ``docs/COGNITION.md`` rather than implied by
naming.
"""
from __future__ import annotations

from .curiosity import (
    DEFAULT_EXPERIMENT_TIMEOUT_SECONDS,
    DEFAULT_MAX_EXPERIMENTS,
    DEFAULT_MAX_PROVIDER_REQUESTS,
    DEFAULT_MAX_STEPS_PER_GAP,
    LADDER,
    LADDER_ORDER,
    CuriosityBudget,
    ExplorationLog,
    KnowledgeGap,
    PlannedStep,
    ResolutionPlan,
    ResolutionStep,
    prioritize_gaps,
    resolve_gap,
    within_scope,
)
from .epistemic import (
    CALIBRATION_BUCKETS,
    CLAIM_KINDS,
    CONFIDENCE_BEARING_KINDS,
    MIN_CALIBRATION_SAMPLES,
    OBSERVATIONAL_PROVENANCE,
    PROVENANCES,
    BeliefSummary,
    CalibrationLedger,
    CalibrationRecord,
    CalibrationReport,
    Claim,
    ClaimKind,
    EpistemicError,
    Provenance,
    brier_score,
    classify_claim,
    summarize,
)
from .evaluation import (
    SUITE_VERSION,
    CaseResult,
    EvalCase,
    EvalContext,
    EvalOutcome,
    EvalStatus,
    Report,
    available_cases,
    case,
    load_baseline,
    report_to_baseline,
    run_suite,
    suite_manifest,
    write_baseline,
)
from .meta_reasoning import (
    VERIFICATION_LADDER,
    FailureCause,
    PostHocReview,
    PreflightReview,
    ProceedDecision,
    derive_acceptance_criteria,
    detect_blocking_capability_gaps,
    detect_capability_gaps,
    post_hoc,
    preflight,
)
from .orchestration import (
    SUBJECT_OVERLAP_THRESHOLD,
    AgentOutput,
    ConsensusStatus,
    Contradiction,
    CoordinationPlan,
    Reconciliation,
    RoleAssignment,
    Subtask,
    SufficiencyVerdict,
    derive_roles,
    detect_contradictions,
    find_agreements,
    reconcile,
)
from .planning import (
    Decision,
    Option,
    OptionEvaluation,
    RiskTolerance,
    evaluate_options,
)
from .procedures import (
    MAX_STEPS,
    MIN_ATTEMPTS_FOR_RELIABILITY,
    MIN_ATTEMPTS_TO_ESTABLISH,
    MIN_SUCCESS_RATIO,
    MIN_SUCCESSES_TO_ESTABLISH,
    Procedure,
    ProcedureLibrary,
    ProcedureStatus,
    RetrievalHit,
    TransferCheck,
    TransferVerdictKind,
    transfer_check,
)
from .world_model import (
    DEFAULT_TTL_SECONDS,
    FALLBACK_TTL_SECONDS,
    MIN_HYPOTHESIS_CONFIRMATIONS,
    Hypothesis,
    Observation,
    ObservationSource,
    Prediction,
    Relation,
    WorldModel,
    WorldModelStats,
)

__all__ = [
    "CALIBRATION_BUCKETS",
    "CLAIM_KINDS",
    "CONFIDENCE_BEARING_KINDS",
    "DEFAULT_EXPERIMENT_TIMEOUT_SECONDS",
    "DEFAULT_MAX_EXPERIMENTS",
    "DEFAULT_MAX_PROVIDER_REQUESTS",
    "DEFAULT_MAX_STEPS_PER_GAP",
    "DEFAULT_TTL_SECONDS",
    "FALLBACK_TTL_SECONDS",
    "LADDER",
    "LADDER_ORDER",
    "MAX_STEPS",
    "MIN_ATTEMPTS_FOR_RELIABILITY",
    "MIN_ATTEMPTS_TO_ESTABLISH",
    "MIN_CALIBRATION_SAMPLES",
    "MIN_HYPOTHESIS_CONFIRMATIONS",
    "MIN_SUCCESSES_TO_ESTABLISH",
    "MIN_SUCCESS_RATIO",
    "OBSERVATIONAL_PROVENANCE",
    "PROVENANCES",
    "SUBJECT_OVERLAP_THRESHOLD",
    "SUITE_VERSION",
    "VERIFICATION_LADDER",
    "AgentOutput",
    "BeliefSummary",
    "CalibrationLedger",
    "CalibrationRecord",
    "CalibrationReport",
    "CaseResult",
    "Claim",
    "ClaimKind",
    "ConsensusStatus",
    "Contradiction",
    "CoordinationPlan",
    "CuriosityBudget",
    "Decision",
    "EpistemicError",
    "EvalCase",
    "EvalContext",
    "EvalOutcome",
    "EvalStatus",
    "ExplorationLog",
    "FailureCause",
    "Hypothesis",
    "KnowledgeGap",
    "Observation",
    "ObservationSource",
    "Option",
    "OptionEvaluation",
    "PlannedStep",
    "PostHocReview",
    "Prediction",
    "PreflightReview",
    "Procedure",
    "ProcedureLibrary",
    "ProcedureStatus",
    "ProceedDecision",
    "Provenance",
    "Reconciliation",
    "Relation",
    "Report",
    "ResolutionPlan",
    "ResolutionStep",
    "RetrievalHit",
    "RiskTolerance",
    "RoleAssignment",
    "Subtask",
    "SufficiencyVerdict",
    "TransferCheck",
    "TransferVerdictKind",
    "WorldModel",
    "WorldModelStats",
    "available_cases",
    "brier_score",
    "case",
    "classify_claim",
    "derive_acceptance_criteria",
    "derive_roles",
    "detect_blocking_capability_gaps",
    "detect_capability_gaps",
    "detect_contradictions",
    "evaluate_options",
    "find_agreements",
    "load_baseline",
    "post_hoc",
    "preflight",
    "prioritize_gaps",
    "reconcile",
    "report_to_baseline",
    "resolve_gap",
    "run_suite",
    "suite_manifest",
    "summarize",
    "transfer_check",
    "within_scope",
    "write_baseline",
]
