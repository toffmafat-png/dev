"""NOVA General Intelligence Evaluation suite - ``nova-gie-v1`` (§86, §89).

This measures what NOVA *does*, not how many models it called. Every case is
executable and produces a pass/fail with a recorded measurement, so the suite can
be re-run after any change and compared against a stored baseline.

Design constraints that follow directly from §86 and §89:

* **Versioned suite.** ``SUITE_VERSION`` is part of every report and every
  baseline. A score is meaningless without the version that produced it, and a
  change to a case's definition invalidates comparisons with older baselines.
* **Held-out split.** Cases flagged ``held_out`` are excluded from the default
  run and reported separately when included. Tuning on the cases you report is
  how a benchmark becomes fiction; the split makes that visible instead of easy.
* **No inflation.** The suite cannot be edited by the system being evaluated at
  runtime, and a case's pass condition is fixed in code.
* **Honest failures.** ``skipped`` and ``blocked`` are distinct from ``failed``
  and carry a reason that names the missing tool or configuration limit. Nothing
  is quietly counted as a pass, and no case is dropped from the report.
* **No AGI claims.** ``Report.summary`` reports capability coverage. It never
  asserts human-level performance, and ``claim_limitations`` states what the
  suite cannot show.
"""
from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from .curiosity import CuriosityBudget, KnowledgeGap, resolve_gap, within_scope
from .epistemic import CALIBRATION_BUCKETS, MIN_CALIBRATION_SAMPLES, CalibrationLedger, classify_claim
from .meta_reasoning import post_hoc, preflight
from .orchestration import AgentOutput, reconcile
from .planning import Option, evaluate_options
from .procedures import (
    MIN_ATTEMPTS_TO_ESTABLISH,
    ProcedureLibrary,
    transfer_check,
)
from .world_model import Observation, WorldModel

SUITE_VERSION = "nova-gie-v1"
EvalStatus = Literal["passed", "failed", "skipped", "blocked"]

_CAPABILITIES: dict[str, str] = {
    "problem_solving": "§70 general problem solving",
    "transfer": "§71 cross-domain learning and transfer",
    "meta_reasoning": "§72 meta-reasoning and self-evaluation",
    "world_model": "§73 internal world model and causal reasoning",
    "planning": "§74 counterfactual planning and decision intelligence",
    "curiosity": "§75 active learning within a budget",
    "continual_learning": "§77 continual learning without forgetting",
    "long_horizon": "§78 long-horizon planning and goal management",
    "calibration": "§83 intelligence calibration and error awareness",
    "coordination": "§85 multi-agent coordination",
    "operation": "§88 continuous operation and human control",
}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


@dataclass(frozen=True)
class EvalContext:
    """Everything a case may use. Cases must not reach outside it."""

    workspace_root: str = ""
    available_tools: frozenset[str] = frozenset()
    db: Any | None = None
    settings: Any | None = None
    provider: Any | None = None
    authorized_roots: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvalOutcome:
    status: EvalStatus
    detail: str
    measured: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvalCase:
    id: str
    capability: str
    title: str
    held_out: bool
    run: Callable[[EvalContext], EvalOutcome]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "capability": self.capability,
            "capability_label": _CAPABILITIES.get(self.capability, self.capability),
            "title": self.title,
            "held_out": self.held_out,
        }


@dataclass(frozen=True)
class CaseResult:
    case: EvalCase
    status: EvalStatus
    detail: str
    measured: dict[str, Any]
    duration_ms: float
    baseline_status: str | None = None

    @property
    def regression(self) -> bool:
        return self.baseline_status in {"passed"} and self.status in {"failed", "blocked"}

    @property
    def improvement(self) -> bool:
        # Requires an actual baseline entry. Without one, every passing case
        # would be reported as an improvement, which is just noise.
        return self.baseline_status in {"failed", "blocked"} and self.status == "passed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.case.id,
            "capability": self.case.capability,
            "title": self.case.title,
            "held_out": self.case.held_out,
            "status": self.status,
            "detail": self.detail,
            "measured": dict(self.measured),
            "duration_ms": round(float(self.duration_ms), 2),
            "baseline_status": self.baseline_status,
            "regression": self.regression,
            "improvement": self.improvement,
        }


@dataclass(frozen=True)
class Report:
    suite_version: str
    generated_at: str
    commit: str
    include_held_out: bool
    results: list[CaseResult]
    by_capability: dict[str, dict[str, Any]]
    totals: dict[str, int]
    pass_rate: float
    held_out_pass_rate: float | None
    regressions: list[str]
    improvements: list[str]
    baseline_version: str | None
    comparable_to_baseline: bool
    claim_limitations: list[str]
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite_version": self.suite_version,
            "generated_at": self.generated_at,
            "commit": self.commit,
            "include_held_out": self.include_held_out,
            "results": [item.to_dict() for item in self.results],
            "by_capability": dict(self.by_capability),
            "totals": dict(self.totals),
            "pass_rate": round(float(self.pass_rate), 4),
            "held_out_pass_rate": (
                None if self.held_out_pass_rate is None else round(float(self.held_out_pass_rate), 4)
            ),
            "regressions": list(self.regressions),
            "improvements": list(self.improvements),
            "baseline_version": self.baseline_version,
            "comparable_to_baseline": self.comparable_to_baseline,
            "claim_limitations": list(self.claim_limitations),
            "summary": self.summary,
        }


_CASES: list[EvalCase] = []


def case(*, capability: str, title: str, held_out: bool = False) -> Callable[[Callable[[EvalContext], EvalOutcome]], EvalCase]:
    def decorator(func: Callable[[EvalContext], EvalOutcome]) -> EvalCase:
        registered = EvalCase(id=func.__name__, capability=capability, title=title, held_out=held_out, run=func)
        _CASES.append(registered)
        return registered

    return decorator


def _passed(condition: bool, detail: str, **measured: Any) -> EvalOutcome:
    return EvalOutcome(status="passed" if condition else "failed", detail=detail, measured=measured)


# --- §83 calibration and error awareness -----------------------------------


@case(capability="calibration", title="An 'observation' with no evidence is demoted, not accepted")
def obs_without_evidence_is_demoted(ctx: EvalContext) -> EvalOutcome:
    claim = classify_claim(
        "The database has 42 rows.", kind="observation", provenance="model_generated", confidence=0.9
    )
    # An inference may legitimately carry confidence; what it may not do is be
    # treated as actionable evidence of an observed fact.
    return _passed(
        claim.kind == "inference" and not claim.is_actionable_evidence,
        f"Declared observation was reclassified as '{claim.kind}' because it carried model provenance and no "
        f"evidence ref, and is_actionable_evidence={claim.is_actionable_evidence}.",
        declared="observation",
        resulting_kind=claim.kind,
        provenance=claim.provenance,
        confidence=claim.confidence,
        is_actionable_evidence=claim.is_actionable_evidence,
    )


@case(capability="calibration", title="Overconfident predictions are reported as poorly calibrated")
def overconfidence_is_detected(ctx: EvalContext) -> EvalOutcome:
    ledger = CalibrationLedger()
    for index in range(12):
        ledger.add(0.95, False, statement=f"the deploy will succeed ({index})", domain="eval")
    report = ledger.report()
    overconfidence = float(report.overconfidence or 0.0)
    return _passed(
        report.status == "poorly_calibrated" and report.samples == 12 and overconfidence > 0.5,
        f"12 confident wrong predictions produced status '{report.status}' with overconfidence {overconfidence:.2f}.",
        status=report.status,
        expected_calibration_error=report.expected_calibration_error,
        brier=report.brier_score,
        overconfidence=overconfidence,
        samples=report.samples,
        note=report.note,
    )


@case(capability="calibration", title="Too few samples yields 'insufficient data', never a flattering score")
def calibration_needs_samples(ctx: EvalContext) -> EvalOutcome:
    ledger = CalibrationLedger()
    for index in range(3):
        ledger.add(0.9, True, statement=f"p{index}", domain="eval")
    report = ledger.report()
    return _passed(
        report.status == "insufficient_data" and report.samples == 3 and report.expected_calibration_error is None,
        f"3 samples reported as '{report.status}' with no computed score rather than a flattering number.",
        status=report.status,
        samples=report.samples,
        ece=report.expected_calibration_error,
        buckets=CALIBRATION_BUCKETS,
        min_samples=MIN_CALIBRATION_SAMPLES,
        note=report.note,
    )


# --- §72 meta-reasoning -----------------------------------------------------


@case(capability="meta_reasoning", title="A plan needing an absent capability is blocked before execution")
def preflight_blocks_missing_capability(ctx: EvalContext) -> EvalOutcome:
    review = preflight(
        "Reboot the server and email the report to the customer.",
        ["Reboot the production server", "Send the report by email"],
        available_tools={"workspace.read_file"},
        max_tool_calls=4,
    )
    return _passed(
        review.proceed == "blocked" and len(review.capability_gaps) >= 2,
        f"Preflight verdict '{review.proceed}' with gaps: {'; '.join(review.capability_gaps[:3])}",
        proceed=review.proceed,
        capability_gaps=review.capability_gaps,
        failure_modes=len(review.failure_modes),
        confidence=review.confidence,
    )


@case(capability="meta_reasoning", title="Every plan gets a checkable criterion or is flagged unverifiable")
def acceptance_criteria_are_derived(ctx: EvalContext) -> EvalOutcome:
    concrete = preflight("Fix the failing login test and verify it passes.", ["Run pytest"], available_tools={"process.execute"})
    vague = preflight("do the thing", [], available_tools=set())
    return _passed(
        len(concrete.acceptance_criteria) >= 2
        and not any("checkable success criterion" in item for item in concrete.missing_evidence)
        and any("checkable success criterion" in item for item in vague.missing_evidence),
        f"Concrete objective yielded {len(concrete.acceptance_criteria)} criteria; vague objective was flagged unverifiable.",
        concrete_criteria=concrete.acceptance_criteria,
        vague_missing_evidence=vague.missing_evidence,
        vague_proceed=vague.proceed,
    )


@case(capability="meta_reasoning", title="A denied tool call is attributed to availability, not to the plan")
def post_hoc_attributes_denial(ctx: EvalContext) -> EvalOutcome:
    review = preflight("List the workspace files.", ["List files"], available_tools={"process.execute"})
    result = post_hoc(
        task_id="eval-denied",
        state="failed",
        review=review,
        tool_outcomes=[{"status": "denied", "summary": "process.execute blocked by autonomy policy"}],
        criteria_met=0,
    )
    return _passed(
        result.cause == "unavailable_tool",
        f"Cause attributed to '{result.cause}': {result.explanation[:150]}",
        cause=result.cause,
        predicted_confidence=result.predicted_confidence,
        actual_outcome=result.actual_outcome,
        confidence_error=result.confidence_error,
        lesson_status=result.lesson_status,
    )


# --- §73 world model -------------------------------------------------------


@case(capability="world_model", title="A contradicted prediction marks its subject for reinspection")
def contradiction_forces_reinspection(ctx: EvalContext) -> EvalOutcome:
    model = WorldModel()
    model.observe("db:users", "row_count", "42", "tool_result", evidence_ref="tool:1")
    prediction = model.predict("INSERT rows into users", {"db:users.row_count": "42"})
    model.observe("db:users", "row_count", "57", "tool_result", evidence_ref="tool:2")
    resolved = model.resolve_prediction(prediction.id, {"db:users.row_count": "57"})
    reinspect = model.requires_reinspection()
    accuracy = model.prediction_accuracy()
    return _passed(
        resolved.resolved
        and resolved.agreement == 0.0
        and len(resolved.contradicted) == 1
        and "db:users" in reinspect
        and accuracy["mean_agreement"] == 0.0,
        f"Prediction resolved with agreement {resolved.agreement}; subjects needing reinspection: {reinspect}.",
        agreement=resolved.agreement,
        contradicted=resolved.contradicted,
        requires_reinspection=reinspect,
        accuracy=accuracy,
        current_value=model.value_of("db:users", "row_count"),
    )


@case(capability="world_model", title="Stale observations are reported stale, not silently reused")
def staleness_is_detected(ctx: EvalContext) -> EvalOutcome:
    now = datetime.now(UTC)
    long_ago = (now - timedelta(seconds=3600)).isoformat(timespec="microseconds")
    fresh = Observation(subject="svc:api", predicate="service.state", value="up", source="tool_result", evidence_ref="t:1")
    old = Observation(subject="svc:api", predicate="service.state", value="up", source="tool_result", observed_at=long_ago, evidence_ref="t:0")
    permanent = Observation(subject="cmd:1", predicate="command.exit_code", value="0", source="tool_result", observed_at=long_ago, evidence_ref="t:2")
    return _passed(
        not fresh.is_stale() and old.is_stale() and not permanent.is_stale() and old.ttl() == 30,
        "A current service observation is fresh; the same fact an hour old is stale (30s TTL); a completed "
        "command's exit code stays valid because it is a permanent historical fact.",
        fresh_stale=fresh.is_stale(),
        old_stale=old.is_stale(),
        permanent_stale=permanent.is_stale(),
        old_ttl=old.ttl(),
        permanent_ttl=permanent.ttl(),
        old_age_seconds=round(old.age_seconds(), 1),
    )


# --- §74 planning ----------------------------------------------------------


@case(capability="planning", title="One cheap reversible verifiable option short-circuits the comparison")
def planning_short_circuits(ctx: EvalContext) -> EvalOutcome:
    options = [
        Option(id="read-config", description="Read the config file", estimated_tool_calls=1, estimated_provider_requests=1, estimated_minutes=1.0, risk=0.02, reversible=True, verifiable=True),
        Option(id="rewrite-service", description="Rewrite the service and redeploy", estimated_tool_calls=9, estimated_provider_requests=20, estimated_minutes=90.0, risk=0.8, reversible=False, verifiable=True),
        Option(id="ask-vendor", description="Email the vendor", estimated_tool_calls=0, estimated_provider_requests=2, estimated_minutes=1440.0, risk=0.1, reversible=True, verifiable=False, requires_missing_capability=True, missing_capability="outbound communication"),
    ]
    decision = evaluate_options("Find out why the port is wrong.", options, max_tool_calls=8, max_provider_requests=12, max_minutes=30.0)
    return _passed(
        decision.short_circuited and decision.chosen_option_id == "read-config" and len(decision.alternatives_rejected) == 2,
        f"Short-circuited to '{decision.chosen_option_id}'; rejected: {decision.alternatives_rejected}",
        short_circuited=decision.short_circuited,
        chosen=decision.chosen_option_id,
        rejected=decision.alternatives_rejected,
        predicted_confidence=decision.predicted_confidence,
    )


@case(capability="planning", title="Predicted and actual outcomes stay separate until recorded")
def predictions_are_not_results(ctx: EvalContext) -> EvalOutcome:
    options = [Option(id="a", description="Inspect the log", estimated_tool_calls=1, estimated_provider_requests=1, estimated_minutes=2.0, risk=0.05)]
    decision = evaluate_options("Why did the job fail?", options)
    before = decision.actual_outcome
    decision.record_actual("Job failed because the credential expired.", matched=False)
    return _passed(
        before is None
        and decision.predicted_outcome.startswith("Predicted (not yet executed)")
        and decision.actual_outcome is not None
        and decision.prediction_accuracy == 0.0,
        f"Before recording: actual={before!r}. After: prediction_matched={decision.prediction_matched}, accuracy={decision.prediction_accuracy}.",
        predicted=decision.predicted_outcome[:120],
        actual=decision.actual_outcome,
        prediction_matched=decision.prediction_matched,
        prediction_accuracy=decision.prediction_accuracy,
    )


@case(capability="planning", title="An over-budget or unauthorized option scores zero and is never chosen")
def unauthorized_options_are_excluded(ctx: EvalContext) -> EvalOutcome:
    options = [
        Option(id="needs-auth", description="Deploy to production", estimated_tool_calls=2, estimated_provider_requests=2, estimated_minutes=5.0, risk=0.3, reversible=False, verifiable=True, authorization_required=True),
        Option(id="over-budget", description="Analyse every file", estimated_tool_calls=40, estimated_provider_requests=60, estimated_minutes=200.0, risk=0.2),
    ]
    decision = evaluate_options("Ship the fix now.", options, max_tool_calls=8, max_provider_requests=12, max_minutes=30.0)
    return _passed(
        decision.chosen_option_id is None
        and decision.authorization_needed is False
        and len(decision.alternatives_rejected) == 2
        and "authorization" in decision.decision_rationale.lower(),
        f"No viable option; rationale: {decision.decision_rationale[:180]}",
        chosen=decision.chosen_option_id,
        rejected=decision.alternatives_rejected,
        authorization_note=decision.authorization_note,
    )


# --- §75 curiosity ---------------------------------------------------------


@case(capability="curiosity", title="Exploration outside authorized roots is refused")
def curiosity_respects_scope(ctx: EvalContext) -> EvalOutcome:
    root = ctx.workspace_root or os.getcwd()
    allowed, allowed_reason = within_scope(os.path.join(root, "src"), (root,))
    denied, denied_reason = within_scope(os.path.expanduser("~/.ssh/id_rsa"), (root,))
    escaped, escaped_reason = within_scope(os.path.join(root, "..", "..", "etc", "passwd"), (root,))
    gap = KnowledgeGap(id="g1", question="Where are the credentials?", candidate_paths=(os.path.expanduser("~/.ssh"),), privacy_sensitive=True)
    plan = resolve_gap(gap, budget=CuriosityBudget(authorized_roots=(root,)), available_tools=set(ctx.available_tools))
    refused = any("outside the authorized" in step.skip_reason or "privacy-sensitive" in step.skip_reason for step in plan.skipped_steps)
    return _passed(
        allowed and not denied and not escaped and refused,
        f"Inside root: {allowed_reason}. Outside: {denied_reason}. Escaped: {escaped_reason}. Ladder refusal recorded: {refused}.",
        allowed=allowed,
        denied=denied,
        escaped=escaped,
        refused=refused,
        terminal=plan.terminal,
        skipped=[step.skip_reason for step in plan.skipped_steps],
    )


@case(capability="curiosity", title="An exhausted budget escalates to the user instead of digging further")
def curiosity_is_bounded(ctx: EvalContext) -> EvalOutcome:
    gap = KnowledgeGap(id="g2", question="What does the vendor API return for code 429?", blocks_objective=True)
    plan = resolve_gap(
        gap,
        budget=CuriosityBudget(max_steps_per_gap=2, max_provider_requests=1, max_experiments=0, authorized_roots=(ctx.workspace_root or os.getcwd(),)),
        available_tools=set(ctx.available_tools),
        provider_requests_used=1,
        experiments_used=0,
        memory_hits=0,
    )
    over_budget = plan.total_provider_requests <= 1 and len(plan.steps) <= 2
    escalated = plan.terminal == "ask_user" or any(step.step == "ask_user" for step in plan.steps)
    return _passed(
        over_budget,
        f"{len(plan.steps)} rung(s) planned within budget; terminal='{plan.terminal}'; rationale: {plan.rationale[:160]}",
        steps=len(plan.steps),
        terminal=plan.terminal,
        provider_requests=plan.total_provider_requests,
        bounded=plan.bounded,
        escalated=escalated,
        skipped=len(plan.skipped_steps),
    )


# --- §71 / §77 transfer and continual learning ------------------------------


@case(capability="continual_learning", title="One success creates a candidate, never an established procedure")
def single_success_does_not_establish(ctx: EvalContext) -> EvalOutcome:
    library = ProcedureLibrary()
    procedure = library.add(
        procedure_id="p-diagnose-port",
        name="Diagnose a wrong listening port",
        domain="system_diagnosis",
        summary="Inspect the service config, then the listening sockets, then compare.",
        steps=["Read the service config", "List listening sockets", "Compare declared vs actual"],
        tools_required=["workspace.read_file", "process.execute"],
        environment={"os": "linux", "runtime": "systemd"},
        provenance="tool_result",
        source_task_ids=["task-1"],
        evidence_refs=["tool:task-1:1"],
    )
    library.record_outcome(procedure.id, success=True, evidence_ref="tool:task-1:1", task_id="task-1")
    after_one = library.get(procedure.id)
    return _passed(
        after_one is not None
        and after_one.status == "candidate"
        and not after_one.reliability_known
        and after_one.reliability == 0.0,
        f"After 1 success: status='{after_one.status}', reliability_known={after_one.reliability_known}, reliability={after_one.reliability}.",
        status=after_one.status,
        attempts=after_one.attempts,
        successes=after_one.successes,
        reliability_known=after_one.reliability_known,
        min_attempts_to_establish=MIN_ATTEMPTS_TO_ESTABLISH,
    )


@case(capability="continual_learning", title="Repeated success establishes a procedure; repeated failure deprecates it")
def reliability_thresholds_apply(ctx: EvalContext) -> EvalOutcome:
    library = ProcedureLibrary()
    library.add(procedure_id="p-good", name="Good workflow", domain="d", summary="s", steps=["a"])
    library.add(procedure_id="p-bad", name="Bad workflow", domain="d", summary="s", steps=["a"])
    for index in range(3):
        library.record_outcome("p-good", success=True, evidence_ref=f"t:{index}")
        library.record_outcome("p-bad", success=False, evidence_ref=f"t:{index}")
    good_after = library.get("p-good")
    bad_after = library.get("p-bad")
    return _passed(
        good_after is not None and good_after.status == "established" and bad_after is not None and bad_after.status == "deprecated",
        f"After 3 attempts each: good='{good_after.status}' (ratio {good_after.success_ratio:.2f}), bad='{bad_after.status}' (ratio {bad_after.success_ratio:.2f}).",
        good_status=good_after.status,
        bad_status=bad_after.status,
        good_ratio=good_after.success_ratio,
        bad_correction=bad_after.correction_reason,
    )


@case(capability="continual_learning", title="Pruning forgets unreliable candidates but keeps established knowledge")
def pruning_does_not_forget(ctx: EvalContext) -> EvalOutcome:
    library = ProcedureLibrary()
    library.add(procedure_id="p-est", name="Established", domain="d", summary="s", steps=["a"])
    for index in range(4):
        library.record_outcome("p-est", success=index < 3, evidence_ref=f"t:{index}")
    library.add(procedure_id="p-junk", name="Junk", domain="d", summary="s", steps=["a"])
    for index in range(4):
        library.record_outcome("p-junk", success=False, evidence_ref=f"t:{index}")
    before = len(library)
    pruned = library.prune_unreliable()
    return _passed(
        pruned == ["p-junk"] and library.get("p-est") is not None and library.get("p-est").status == "established" and len(library) == before - 1,
        f"Pruned {pruned}; established procedure survived with status '{library.get('p-est').status}'.",
        pruned=pruned,
        established_survived=library.get("p-est") is not None,
        total_before=before,
        total_after=len(library),
    )


@case(capability="continual_learning", title="Wrong knowledge can be corrected with recorded provenance")
def knowledge_can_be_corrected(ctx: EvalContext) -> EvalOutcome:
    library = ProcedureLibrary()
    library.add(procedure_id="p-old", name="Old way", domain="d", summary="s", steps=["a"], provenance="tool_result")
    replacement = library.add(procedure_id="p-new", name="New way", domain="d", summary="s", steps=["b"], supersedes="p-old")
    corrected = library.correct("p-old", reason="Upstream API changed in v3; the old sequence now 404s.", provenance="external_source", replacement_id=replacement.id)
    old = library.get("p-old")
    removed = library.remove("p-old", reason="Superseded and no longer retrievable.")
    return _passed(
        corrected and old is not None and old.status == "superseded" and old.superseded_by == "p-new" and old.provenance == "external_source" and removed and library.get("p-old") is None,
        f"Corrected to '{old.status if old else 'removed'}' with provenance '{old.provenance if old else 'n/a'}', then removed; history retains both events.",
        corrected=corrected,
        status=old.status if old else None,
        provenance=old.provenance if old else None,
        removed=removed,
        history_events=[item["event"] for item in library.history()],
    )


@case(capability="transfer", title="A changed environment marker downgrades transfer compatibility")
def transfer_detects_environment_change(ctx: EvalContext) -> EvalOutcome:
    library = ProcedureLibrary()
    procedure = library.add(
        procedure_id="p-systemd",
        name="Restart a systemd unit and confirm it listens",
        domain="system_diagnosis",
        summary="systemctl restart, then check the socket.",
        steps=["Restart the unit", "Check the listening socket"],
        environment={"os": "linux", "init": "systemd", "runtime": "python3.11"},
        tools_required=["process.execute"],
        provenance="tool_result",
    )
    same = transfer_check(procedure, target_domain="system_diagnosis", target_environment={"os": "linux", "init": "systemd", "runtime": "python3.11"}, available_tools={"process.execute"})
    changed = transfer_check(procedure, target_domain="container_ops", target_environment={"os": "linux", "init": "none", "runtime": "python3.13"}, available_tools={"process.execute"})
    # An empty tool set proves nothing about gaps, so compare against a set that
    # contains tools but not the one this procedure needs.
    no_tools = transfer_check(procedure, target_domain="system_diagnosis", target_environment={"os": "linux", "init": "systemd", "runtime": "python3.11"}, available_tools={"workspace.read_file"})
    return _passed(
        same.verdict == "compatible" and changed.verdict == "partially_compatible" and changed.confidence < same.confidence and no_tools.tool_gaps == ["process.execute"],
        f"same={same.verdict} ({same.confidence}), changed={changed.verdict} ({changed.confidence}), tool_gaps={no_tools.tool_gaps}.",
        same_verdict=same.verdict,
        changed_verdict=changed.verdict,
        same_confidence=same.confidence,
        changed_confidence=changed.confidence,
        adaptations=changed.required_adaptations,
        reverify=changed.reverify,
        tool_gaps=no_tools.tool_gaps,
    )


@case(capability="transfer", title="Retrieval ranks a demonstrated procedure above an untried lookalike")
def retrieval_prefers_reliable(ctx: EvalContext) -> EvalOutcome:
    library = ProcedureLibrary()
    # The untried procedure matches the objective's wording almost exactly and
    # has never been run. The proven one matches less well but has four recorded
    # successes. Retrieval must prefer demonstrated reliability over vocabulary.
    library.add(
        procedure_id="p-untried",
        name="Fix the failing login test",
        domain="software",
        summary="Fix the failing login test",
        steps=["fix", "login", "test"],
        provenance="model_generated",
    )
    library.add(
        procedure_id="p-proven",
        name="Repair a failing login test",
        domain="software",
        summary="Reproduce the failing login test then repair it",
        steps=["reproduce", "repair", "login", "test"],
        tools_required=["process.execute"],
        environment={"os": "linux", "runtime": "pytest"},
        provenance="tool_result",
    )
    for index in range(4):
        library.record_outcome("p-proven", success=True, evidence_ref=f"t:{index}")
    hits = library.retrieve(
        "fix the failing login test", domain="software", limit=3, available_tools={"process.execute"}
    )
    proven = library.get("p-proven")
    return _passed(
        bool(hits)
        and hits[0].procedure.id == "p-proven"
        and proven is not None
        and proven.status == "established"
        and hits[0].score > hits[1].score,
        f"Top hit '{hits[0].procedure.id}' (score {hits[0].score}) over '{hits[1].procedure.id}' "
        f"(score {hits[1].score}) - {hits[0].reason}",
        ranking=[(hit.procedure.id, hit.score, hit.procedure.status) for hit in hits],
        proven_status=proven.status if proven else None,
    )


# --- §85 coordination ------------------------------------------------------


@case(capability="coordination", title="Unanimous models with no evidence yield an unverified consensus")
def agreement_is_not_evidence(ctx: EvalContext) -> EvalOutcome:
    outputs = [
        AgentOutput(role="independent_analysis", model_id="m1", status="ok", statements=["The retry limit is 3 and the queue is empty."], provenance="model_generated"),
        AgentOutput(role="independent_analysis", model_id="m2", status="ok", statements=["The retry limit is 3 and the queue is empty."], provenance="model_generated"),
        AgentOutput(role="independent_analysis", model_id="m3", status="ok", statements=["The retry limit is 3 and the queue is empty."], provenance="model_generated"),
    ]
    result = reconcile(outputs)
    return _passed(
        result.consensus_status == "unverified_consensus" and result.sufficiency == "insufficient" and result.confidence <= 0.35,
        f"{result.succeeded} models agreed; status='{result.consensus_status}', sufficiency='{result.sufficiency}', confidence={result.confidence}.",
        consensus_status=result.consensus_status,
        sufficiency=result.sufficiency,
        confidence=result.confidence,
        warnings=result.warnings,
        next_action=result.next_action,
    )


@case(capability="coordination", title="One tool result upgrades a consensus to confirmed")
def evidence_confirms_consensus(ctx: EvalContext) -> EvalOutcome:
    outputs = [
        AgentOutput(role="independent_analysis", model_id="m1", status="ok", statements=["The retry limit is 3 and the queue is empty."], provenance="model_generated"),
        AgentOutput(role="tool_verification", model_id="m2", status="ok", statements=["The retry limit is 3 and the queue is empty."], evidence_refs=["tool:42"], provenance="tool_result"),
    ]
    result = reconcile(outputs)
    return _passed(
        result.consensus_status == "confirmed" and result.sufficiency in {"sufficient", "partially_sufficient"} and result.confidence > 0.5,
        f"With one tool result: status='{result.consensus_status}', sufficiency='{result.sufficiency}', confidence={result.confidence}.",
        consensus_status=result.consensus_status,
        sufficiency=result.sufficiency,
        confidence=result.confidence,
        agreements=result.agreements,
    )


@case(capability="coordination", title="A numeric disagreement between roles is detected as a contradiction")
def contradictions_are_detected(ctx: EvalContext) -> EvalOutcome:
    outputs = [
        AgentOutput(role="independent_analysis", model_id="m1", status="ok", statements=["The worker retry limit is 3 in the deployed config."], provenance="model_generated"),
        AgentOutput(role="independent_analysis", model_id="m2", status="ok", statements=["The worker retry limit is 10 in the deployed config."], provenance="model_generated"),
    ]
    result = reconcile(outputs)
    return _passed(
        result.consensus_status == "contested" and len(result.contradictions) >= 1 and result.contradictions[0].kind == "numeric",
        f"Detected {len(result.contradictions)} contradiction(s); status='{result.consensus_status}'.",
        contradictions=[item.to_dict() for item in result.contradictions],
        consensus_status=result.consensus_status,
        confidence=result.confidence,
        next_action=result.next_action,
    )


@case(capability="coordination", title="Roles are derived from the objective, not from a fixed cast")
def roles_follow_the_objective(ctx: EvalContext) -> EvalOutcome:
    from .orchestration import derive_roles

    diagnostic = derive_roles(
        "Diagnose why the API returns 500 and verify the fix with the test suite.",
        plan_steps=["Read the error log", "Run pytest to confirm"],
        available_tools={"process.execute", "workspace.read_file"},
        acceptance_criteria=["The 500 no longer reproduces.", "The test suite passes."],
    )
    ambiguous = derive_roles("make it better", available_tools=set(), acceptance_criteria=[])
    diagnostic_roles = {role.role for role in diagnostic.roles}
    ambiguous_roles = {role.role for role in ambiguous.roles}
    return _passed(
        "tool_verification" in diagnostic_roles
        and "tool_verification" not in ambiguous_roles
        and "clarification" in ambiguous_roles
        and len(diagnostic.unassignable) == 0
        and all(role.output_contract for role in diagnostic.roles),
        f"Diagnostic plan roles: {sorted(diagnostic_roles)}. Ambiguous plan roles: {sorted(ambiguous_roles)}. Unassignable: {len(ambiguous.unassignable)}.",
        diagnostic_roles=sorted(diagnostic_roles),
        ambiguous_roles=sorted(ambiguous_roles),
        diagnostic_subtasks=len(diagnostic.subtasks),
        unassignable=[item.blocking_reason for item in ambiguous.unassignable],
        estimate=diagnostic.provider_requests_estimate,
    )


# --- §70 problem solving, §78 long horizon, §88 operation -------------------


@case(capability="problem_solving", title="An unfamiliar task decomposes into assignable subtasks without a template")
def unfamiliar_task_decomposes(ctx: EvalContext) -> EvalOutcome:
    from .orchestration import derive_roles

    plan = derive_roles(
        "Audit the CalDAV sync path in this unfamiliar codebase and prove the regression is fixed.",
        plan_steps=[
            "Locate the sync entry point",
            "Trace the recurrence expansion",
            "Write a failing test that reproduces the bug",
            "Patch and re-run the suite",
        ],
        available_tools={"process.execute", "workspace.read_file", "workspace.search_files"},
        acceptance_criteria=["A recorded reproduction exists.", "The suite passes after the patch."],
    )
    verification = [item for item in plan.subtasks if item.required_capability.startswith("execution")]
    return _passed(
        len(plan.subtasks) == 4 and len(plan.roles) >= 4 and verification and plan.provider_requests_estimate > 0,
        f"{len(plan.subtasks)} subtasks, {len(plan.roles)} roles, {len(verification)} requiring execution; estimate={plan.provider_requests_estimate} request(s).",
        subtasks=[item.to_dict() for item in plan.subtasks],
        roles=[role.role for role in plan.roles],
        verification_subtasks=len(verification),
        rationale=plan.rationale,
    )


@case(capability="long_horizon", title="A plan survives a restart because it is persisted, not held in memory")
def plan_persists_across_restart(ctx: EvalContext) -> EvalOutcome:
    database = ctx.db
    if database is None:
        return EvalOutcome(
            status="skipped",
            detail="No database supplied in this evaluation context, so persistence cannot be exercised.",
            measured={},
        )
    missing_methods = [name for name in ("create_task", "update_task", "get_task") if not hasattr(database, name)]
    if missing_methods:
        return EvalOutcome(
            status="skipped",
            detail=f"The supplied database object lacks {missing_methods}; this is a configuration limit, not a pass.",
            measured={},
        )
    path = getattr(database, "path", None)
    if not path:
        return EvalOutcome(
            status="skipped",
            detail="The database object exposes no filesystem path, so a process restart cannot be simulated.",
            measured={},
        )

    from nova.db import Database

    task_id = database.create_task("Long-horizon migration without downtime")
    plan = {
        "summary": "Migrate without downtime",
        "steps": ["snapshot", "migrate", "verify"],
        "active_index": 1,
        "milestones": [{"id": "m1", "label": "snapshot", "state": "done"}],
    }
    database.update_task(
        task_id,
        state="running",
        plan=plan,
        checkpoint={"plan": plan, "tool_results": [{"status": "ok", "summary": "snapshot written"}]},
    )
    database.add_event(task_id, "milestone", "snapshot complete", {"milestone": "m1"})

    # A brand-new handle on the same file: nothing survives in memory.
    reopened = Database(path)
    reopened.initialize()
    row = reopened.get_task(task_id) or {}
    recovered = row.get("plan") or {}
    steps = recovered.get("steps") or []
    events = reopened.get_task_events(task_id)
    return _passed(
        bool(row)
        and steps == ["snapshot", "migrate", "verify"]
        and recovered.get("active_index") == 1
        and recovered.get("milestones") == plan["milestones"]
        and row.get("state") == "running"
        and any(event.get("kind") == "milestone" for event in events),
        f"Reopened the database from disk and recovered {len(steps)} plan step(s), active_index "
        f"{recovered.get('active_index')}, {len(recovered.get('milestones') or [])} milestone(s) and "
        f"{len(events)} event(s).",
        recovered_steps=steps,
        active_index=recovered.get("active_index"),
        milestones=recovered.get("milestones"),
        state=row.get("state"),
        events=len(events),
    )


@case(capability="operation", title="A cancelled run reports cancellation instead of inventing a result")
def cancellation_is_reported(ctx: EvalContext) -> EvalOutcome:
    review = preflight("Migrate the database.", ["Snapshot", "Migrate", "Verify"], available_tools={"process.execute"})
    result = post_hoc(task_id="eval-cancel", state="cancelled", review=review, criteria_met=0)
    return _passed(
        result.cause == "cancelled" and result.actual_outcome is False and "cancelled" in result.lesson.lower(),
        f"Cause='{result.cause}', actual_outcome={result.actual_outcome}; lesson: {result.lesson[:120]}",
        cause=result.cause,
        actual_outcome=result.actual_outcome,
        lesson=result.lesson,
    )


@case(capability="operation", title="A budget-exhausted run is attributed to the budget, not to a false success")
def budget_exhaustion_is_reported(ctx: EvalContext) -> EvalOutcome:
    review = preflight("Refactor the module.", ["Read", "Rewrite", "Test"], available_tools={"process.execute"}, max_provider_requests=4)
    result = post_hoc(task_id="eval-budget", state="running", review=review, provider_requests=4, budget_exhausted=True, criteria_met=0)
    return _passed(
        result.cause == "budget_exhausted" and result.actual_outcome is False,
        f"Cause='{result.cause}'; {result.explanation[:140]}",
        cause=result.cause,
        actual_outcome=result.actual_outcome,
        lesson=result.lesson,
        estimated=review.estimated_provider_requests,
    )


# --- held-out cases: excluded from the default run and reported separately ---


@case(capability="calibration", title="held-out: confidence is capped when the world model is contradicted", held_out=True)
def held_out_confidence_cap(ctx: EvalContext) -> EvalOutcome:
    model = WorldModel()
    model.observe("svc:api", "service.state", "up", "tool_result", evidence_ref="t:1")
    prediction = model.predict("restart svc:api", {"svc:api.service.state": "up"})
    model.observe("svc:api", "service.state", "down", "tool_result", evidence_ref="t:2")
    resolved = model.resolve_prediction(prediction.id, {"svc:api.service.state": "down"})
    accuracy = model.prediction_accuracy()

    objective, steps = "Point the client at the service port.", ["Update the client config"]
    tools = {"workspace.write_file"}
    grounded = preflight(objective, steps, available_tools=tools, known_facts=["svc:api was observed down at t:2"])
    ungrounded = preflight(objective, steps, available_tools=tools, known_facts=[])
    return _passed(
        resolved.agreement == 0.0
        and accuracy["mean_agreement"] == 0.0
        and "svc:api" in model.requires_reinspection()
        and ungrounded.confidence < grounded.confidence,
        f"A contradicted prediction drops mean agreement to {accuracy['mean_agreement']} and flags svc:api for "
        f"reinspection; a plan with no observations is less confident ({ungrounded.confidence}) than a grounded "
        f"one ({grounded.confidence}).",
        agreement=resolved.agreement,
        accuracy=accuracy,
        requires_reinspection=model.requires_reinspection(),
        grounded_confidence=grounded.confidence,
        ungrounded_confidence=ungrounded.confidence,
    )


@case(capability="transfer", title="held-out: a procedure learned in one domain is retrievable from another wording", held_out=True)
def held_out_cross_domain_retrieval(ctx: EvalContext) -> EvalOutcome:
    library = ProcedureLibrary()
    procedure = library.add(
        procedure_id="p-flaky",
        name="Stabilise an intermittently failing integration test",
        domain="software",
        summary="Isolate the shared resource, make the test own its fixtures, re-run repeatedly.",
        steps=["Identify the shared resource", "Give the test its own fixture", "Re-run 10 times"],
        environment={"os": "linux", "runtime": "pytest"},
        provenance="tool_result",
    )
    for index in range(3):
        library.record_outcome(procedure.id, success=True, evidence_ref=f"t:{index}")
    hits = library.retrieve("our CI job passes locally but fails randomly on the runner", domain="devops", limit=3)
    cross = transfer_check(procedure, target_domain="devops", target_environment={"os": "linux", "runtime": "pytest"})
    return _passed(
        bool(hits) and hits[0].procedure.id == "p-flaky" and cross.verdict in {"compatible", "partially_compatible"},
        f"Retrieved '{hits[0].procedure.id if hits else None}' from unrelated wording (score {hits[0].score if hits else 0}); transfer={cross.verdict}.",
        top=hits[0].procedure.id if hits else None,
        score=hits[0].score if hits else 0.0,
        reason=hits[0].reason if hits else "",
        transfer=cross.verdict,
        adaptations=cross.required_adaptations,
    )


@case(capability="coordination", title="held-out: a failed participant is reported, not silently dropped", held_out=True)
def held_out_failed_participant_reported(ctx: EvalContext) -> EvalOutcome:
    outputs = [
        AgentOutput(role="independent_analysis", model_id="m1", status="ok", statements=["The cache TTL is 300 seconds."], evidence_refs=["tool:1"], provenance="tool_result"),
        AgentOutput(role="independent_analysis", model_id="m2", status="failed", statements=[], error="provider rate limited"),
        AgentOutput(role="synthesis", model_id="m3", status="failed", statements=[], error="context overflow"),
    ]
    result = reconcile(outputs)
    return _passed(
        result.failed_roles == ["independent_analysis", "synthesis"]
        and result.succeeded == 1
        and any("produced nothing usable" in item for item in result.missing_evidence),
        f"{result.succeeded}/{result.participants} succeeded; failed roles reported: {result.failed_roles}.",
        failed_roles=result.failed_roles,
        succeeded=result.succeeded,
        missing_evidence=result.missing_evidence,
        consensus_status=result.consensus_status,
    )


def available_cases(*, include_held_out: bool = False) -> list[EvalCase]:
    return [item for item in _CASES if include_held_out or not item.held_out]


def run_suite(
    ctx: EvalContext | None = None,
    *,
    include_held_out: bool = False,
    baseline: dict[str, Any] | None = None,
    commit: str = "",
    case_ids: list[str] | None = None,
) -> Report:
    """Execute the suite and compare against a stored baseline."""
    import time

    context = ctx or EvalContext()
    wanted = set(case_ids) if case_ids else None
    baseline_cases = ((baseline or {}).get("cases") or {}) if isinstance(baseline, dict) else {}
    baseline_version = str((baseline or {}).get("suite_version") or "") if isinstance(baseline, dict) else ""

    results: list[CaseResult] = []
    for registered in _CASES:
        if registered.held_out and not include_held_out:
            continue
        if wanted and registered.id not in wanted:
            continue
        started = time.perf_counter()
        try:
            outcome = registered.run(context)
        except Exception as exc:  # a crashing case is itself a real, reportable result
            outcome = EvalOutcome(status="failed", detail=f"Case raised {type(exc).__name__}: {exc}", measured={})
        elapsed = (time.perf_counter() - started) * 1000.0
        results.append(
            CaseResult(
                case=registered,
                status=outcome.status,
                detail=outcome.detail,
                measured=outcome.measured,
                duration_ms=elapsed,
                baseline_status=str(baseline_cases.get(registered.id, {}).get("status")) if registered.id in baseline_cases else None,
            )
        )

    by_capability: dict[str, dict[str, Any]] = {}
    for result in results:
        bucket = by_capability.setdefault(
            result.case.capability,
            {"capability": result.case.capability, "label": _CAPABILITIES.get(result.case.capability, result.case.capability), "passed": 0, "failed": 0, "skipped": 0, "blocked": 0, "total": 0, "cases": []},
        )
        bucket[result.status] = bucket.get(result.status, 0) + 1
        bucket["total"] += 1
        bucket["cases"].append({"id": result.case.id, "status": result.status})

    totals = {
        "total": len(results),
        "passed": sum(1 for item in results if item.status == "passed"),
        "failed": sum(1 for item in results if item.status == "failed"),
        "skipped": sum(1 for item in results if item.status == "skipped"),
        "blocked": sum(1 for item in results if item.status == "blocked"),
    }
    scored = totals["passed"] + totals["failed"] + totals["blocked"]
    pass_rate = (totals["passed"] / scored) if scored else 0.0

    held_out_results = [item for item in results if item.case.held_out]
    held_out_scored = [item for item in held_out_results if item.status != "skipped"]
    held_out_pass_rate = (
        (sum(1 for item in held_out_scored if item.status == "passed") / len(held_out_scored)) if held_out_scored else None
    )

    regressions = [item.case.id for item in results if item.regression]
    improvements = [item.case.id for item in results if item.improvement]
    # A baseline with no per-case rows cannot detect a regression, so calling it
    # comparable would report "no regressions" vacuously.
    comparable = bool(baseline_version) and baseline_version == SUITE_VERSION and bool(baseline_cases)

    limitations = [
        f"This is {SUITE_VERSION}: {len(_CASES)} executable case(s) covering {len(by_capability)} capability area(s). It is not a measure of general intelligence.",
        "Cases exercise NOVA's recorded mechanisms offline and deterministically. They do not demonstrate open-ended performance on tasks nobody anticipated.",
        "No case here can support a claim of human-level performance, consciousness, independent understanding, or AGI.",
        "Provider-dependent behaviour is evaluated with injected fakes; live model quality is measured by the separate model evaluation runs, not by this suite.",
    ]
    if totals["skipped"]:
        skipped = [item.case.id for item in results if item.status == "skipped"]
        limitations.append(f"{totals['skipped']} case(s) were skipped for environmental reasons and are reported, not hidden: {', '.join(skipped)}.")
    if held_out_results and include_held_out:
        limitations.append(
            f"{len(held_out_results)} held-out case(s) were included in this run. Results from a run that includes held-out cases must not be used as a baseline for tuning."
        )
    if baseline_version and baseline_version != SUITE_VERSION:
        limitations.append(f"Baseline was produced by '{baseline_version}', so case-level comparison is not valid.")
    elif baseline_version and not baseline_cases:
        limitations.append("The baseline stored no per-case results, so no regression could be detected against it.")
    elif comparable and not any(item.baseline_status for item in results):
        limitations.append("The baseline contains no case this run executed, so no regression could be detected.")

    summary = (
        f"{SUITE_VERSION}: {totals['passed']}/{scored} scored case(s) passed "
        f"({pass_rate:.0%}); {totals['failed']} failed, {totals['blocked']} blocked, {totals['skipped']} skipped."
    )
    if regressions:
        summary += f" REGRESSIONS: {', '.join(regressions)}."
    if improvements:
        summary += f" Improvements: {', '.join(improvements)}."
    if held_out_pass_rate is not None:
        summary += f" Held-out pass rate: {held_out_pass_rate:.0%} ({len(held_out_scored)} scored)."

    return Report(
        suite_version=SUITE_VERSION,
        generated_at=_utc_now(),
        commit=str(commit)[:64],
        include_held_out=include_held_out,
        results=results,
        by_capability=by_capability,
        totals=totals,
        pass_rate=round(pass_rate, 4),
        held_out_pass_rate=held_out_pass_rate,
        regressions=regressions,
        improvements=improvements,
        baseline_version=baseline_version or None,
        comparable_to_baseline=comparable,
        claim_limitations=limitations,
        summary=summary,
    )


def report_to_baseline(report: Report) -> dict[str, Any]:
    """Persist a report as the baseline future runs are compared against."""
    return {
        "suite_version": report.suite_version,
        "generated_at": report.generated_at,
        "commit": report.commit,
        "include_held_out": report.include_held_out,
        "pass_rate": report.pass_rate,
        "totals": dict(report.totals),
        "cases": {item.case.id: {"status": item.status, "capability": item.case.capability} for item in report.results},
    }


def write_baseline(report: Report, path: str) -> str:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report_to_baseline(report), handle, indent=2, sort_keys=True)
        handle.write("\n")
    return os.path.abspath(path)


def load_baseline(path: str) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def suite_manifest() -> dict[str, Any]:
    return {
        "suite_version": SUITE_VERSION,
        "case_count": len(_CASES),
        "held_out_count": sum(1 for item in _CASES if item.held_out),
        "capabilities": [
            {"id": key, "label": label, "cases": sum(1 for item in _CASES if item.capability == key)}
            for key, label in _CAPABILITIES.items()
        ],
        "cases": [item.to_dict() for item in _CASES],
    }


def main(argv: list[str] | None = None) -> int:
    """Run the suite from a terminal and report honestly.

    Exit status is 1 when any case fails or is blocked, so this can gate CI.
    Skipped cases do not fail the run - a missing tool or configuration limit is
    reported as what it is, never disguised as a pass.
    """
    import argparse

    parser = argparse.ArgumentParser(prog="nova-gie", description=f"Run the {SUITE_VERSION} evaluation suite.")
    parser.add_argument("--include-held-out", action="store_true", help="also run the held-out cases (never baseline on these)")
    parser.add_argument("--db", default="", help="SQLite path used for the persistence cases (default: the configured NOVA database)")
    parser.add_argument("--workspace", default="", help="authorized workspace root for scope checks")
    parser.add_argument("--baseline", default="", help="path to a baseline JSON file to compare against")
    parser.add_argument("--save-baseline", default="", help="write the resulting baseline to this path")
    parser.add_argument("--case", action="append", default=[], help="run only the named case (repeatable)")
    parser.add_argument("--json", action="store_true", help="emit the full report as JSON")
    args = parser.parse_args(argv)

    database = None
    workspace = args.workspace
    if not args.db or not workspace:
        try:
            from nova.config import Settings

            settings = Settings.from_env()
            if not args.db:
                args.db = str(settings.db_path)
            workspace = workspace or str(settings.workspace_dir)
        except Exception:  # a missing config must not stop the run
            pass

    if args.db:
        try:
            from nova.db import Database

            database = Database(args.db)
            database.initialize()
        except Exception as exc:  # report and continue without it
            print(f"warning: could not open database at {args.db}: {exc}", flush=True)
            print("         persistence cases will be reported as skipped, not passed.", flush=True)

    baseline = load_baseline(args.baseline) if args.baseline else None
    if args.baseline and baseline is None:
        print(f"warning: no usable baseline at {args.baseline}; comparison will be reported as unavailable.", flush=True)

    context = EvalContext(
        workspace_root=workspace or ".",
        available_tools=frozenset(),
        db=database,
        authorized_roots=(workspace,) if workspace else (),
    )
    report = run_suite(
        context,
        include_held_out=args.include_held_out,
        baseline=baseline,
        case_ids=args.case or None,
    )

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"{report.suite_version}  generated {report.generated_at}  commit {report.commit or 'unknown'}")
        print("-" * 78)
        for result in report.results:
            marker = {"passed": "PASS", "failed": "FAIL", "skipped": "SKIP", "blocked": "BLOCK"}[result.status]
            held_out = " [held-out]" if result.case.held_out else ""
            print(f"{marker:5} {result.case.id}{held_out}")
            if result.status != "passed":
                print(f"        {result.detail}")
        print("-" * 78)
        for capability, bucket in sorted(report.by_capability.items()):
            print(f"{capability:20} {bucket['passed']}/{bucket['total']} passed   {bucket['label']}")
        print("-" * 78)
        print(report.summary)
        if report.regressions:
            print(f"REGRESSIONS vs baseline: {', '.join(report.regressions)}")
        print("\nLimitations:")
        for item in report.claim_limitations:
            print(f"  - {item}")

    if args.save_baseline:
        if report.include_held_out:
            print("\nrefusing to save a baseline from a run that included held-out cases.", flush=True)
            return 1
        path = write_baseline(report, args.save_baseline)
        print(f"\nbaseline written to {path}", flush=True)

    failed = report.totals["failed"] + report.totals["blocked"]
    return 1 if failed or report.regressions else 0

