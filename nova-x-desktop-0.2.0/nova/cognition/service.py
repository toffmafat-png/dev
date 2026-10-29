"""CognitionService: the wiring between the cognition mechanisms and NOVA X.

The modules in this package are pure and offline. This service is what makes
them *operative*: it owns the live world model, procedure library and
calibration ledger, persists them through :class:`nova.db.Database`, and exposes
the small set of hooks the task engine and the HTTP API actually call.

Two invariants govern everything here.

**A cognition failure must never break a task.** Every public method runs inside
``_guarded``; if the reasoning layer raises, the exception is logged, counted in
``errors`` and reported through ``snapshot()["degraded"]`` rather than
propagating into task execution. Degrading the cognition layer is recoverable -
crashing a user's task is not.

**Nothing is recorded as knowledge without a source.** Observations carry
provenance from the tool that produced them, procedures carry the evidence refs
of the runs that produced them, and calibration records are only written when a
real prediction exists. Where NOVA made no prediction, no confidence is invented
so that a number can be reported.
"""
from __future__ import annotations

import hashlib
import logging
import platform
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .curiosity import CuriosityBudget, ExplorationLog, KnowledgeGap, resolve_gap, within_scope
from .epistemic import CalibrationLedger, classify_claim, summarize
from .evaluation import EvalContext, run_suite
from .meta_reasoning import post_hoc, preflight
from .planning import Decision, Option, evaluate_options
from .procedures import ProcedureLibrary, transfer_check
from .world_model import WorldModel

logger = logging.getLogger("nova.cognition")

# A retrieved procedure must match at least this well before a new task is
# treated as a reuse of it rather than the origin of a new one. Below this the
# similarity is mostly shared vocabulary.
REUSE_THRESHOLD = 0.60
MAX_OBSERVATIONS_PER_TOOL_RESULT = 4

# Tools report their own status vocabulary ('success', 'error', 'denied',
# 'approval_required'). Predictions are made and resolved in a normalized
# outcome space so that one tool's wording can never masquerade as a
# contradiction, and so a genuinely failed call always registers as one.
_SUCCESS_WORDS = frozenset({"success", "ok", "passed", "verified", "completed"})
_FAILURE_WORDS = frozenset({"error", "failed", "failure", "timeout", "insufficient"})
_BLOCKED_WORDS = frozenset({"denied", "blocked", "forbidden"})
_PENDING_WORDS = frozenset({"approval_required", "waiting_approval", "pending"})

# The engine's verification vocabulary, as produced by TaskEngine._verify.
VERIFICATION_CONFIRMED = frozenset({"verified", "partial"})
VERIFICATION_ABSENT = frozenset({"unverified", ""})


def normalize_tool_status(status: Any) -> str:
    """Map a raw tool status onto an outcome class."""
    lowered = str(status or "").strip().lower()
    if lowered in _SUCCESS_WORDS:
        return "succeeded"
    if lowered in _BLOCKED_WORDS:
        return "blocked"
    if lowered in _PENDING_WORDS:
        return "pending_approval"
    if lowered in _FAILURE_WORDS:
        return "failed"
    return lowered or "unknown"
_TOKEN_RE = re.compile(r"[a-z0-9_]{3,}")
_STOPWORD_TEXT = (
    "the and for with that this from have has are was were will would should could not but its their there "
    "they them you your nova task please can into about using use used"
)
_STOPWORDS = frozenset(_STOPWORD_TEXT.split())


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _signature(objective: str) -> str:
    """A stable identity for 'the same kind of task', used to reinforce rather
    than duplicate procedures."""
    tokens = sorted({t for t in _TOKEN_RE.findall(str(objective).lower()) if t not in _STOPWORDS})[:12]
    digest = hashlib.sha256("|".join(tokens).encode("utf-8")).hexdigest()[:12]
    return f"p-{digest}"


def environment_markers(workspace_root: str = "") -> dict[str, str]:
    """Facts about the running environment, measured rather than assumed."""
    return {
        "os": str(platform.system() or "").lower(),
        "platform": str(platform.machine() or ""),
        "python": platform.python_version(),
        "workspace": workspace_root or "",
    }


@contextmanager
def _guarded(service: CognitionService, operation: str) -> Iterator[None]:
    """Keep a cognition defect from taking down task execution."""
    try:
        yield
    except Exception as exc:  # deliberately broad: this is a bulkhead
        service.errors += 1
        service.last_error = f"{operation}: {type(exc).__name__}: {exc}"
        logger.warning("cognition operation %r failed: %s", operation, exc, exc_info=True)


@dataclass
class CognitionService:
    """Live cognition state for one NOVA X instance."""

    db: Any | None = None
    scope: str = "default"
    workspace_root: str = ""
    max_provider_requests: int = 12
    max_tool_calls: int = 8
    authorized_roots: tuple[str, ...] = ()
    verification_enabled: bool = True
    world_model: WorldModel = field(init=False)
    procedures: ProcedureLibrary = field(init=False)
    calibration: CalibrationLedger = field(init=False)
    exploration: ExplorationLog = field(init=False)
    errors: int = 0
    last_error: str = ""
    hydration_counts: dict[str, int] = field(default_factory=dict, init=False)
    _hydrated: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self.world_model = WorldModel(scope=self.scope, persist=self._persist_world_model_event)
        self.procedures = ProcedureLibrary()
        self.calibration = CalibrationLedger()
        self.exploration = ExplorationLog()
        if not self.authorized_roots and self.workspace_root:
            self.authorized_roots = (self.workspace_root,)
        self.hydration_counts = self.hydrate()

    # ------------------------------------------------------------ hydration

    def _persist_world_model_event(self, kind: str, payload: dict[str, Any]) -> None:
        if self.db is None:
            return
        try:
            if kind == "observation":
                self.db.save_observation({**payload, "scope": self.scope})
            elif kind in {"prediction", "prediction_resolved"}:
                self.db.save_prediction({**payload, "scope": self.scope})
        except Exception as exc:  # persistence is best-effort
            logger.debug("could not persist cognition %s: %s", kind, exc)

    def hydrate(self) -> dict[str, int]:
        """Reload persisted cognition state after a restart."""
        counts = {"observations": 0, "predictions": 0, "procedures": 0, "calibration": 0}
        if self.db is None or self._hydrated:
            # Idempotent: state is loaded once per service, at construction.
            return counts
        with _guarded(self, "hydrate"):
            for row in self.db.list_observations(self.scope, limit=500, include_history=False):
                self.world_model.observe(
                    str(row.get("subject") or ""),
                    str(row.get("predicate") or ""),
                    row.get("value"),
                    str(row.get("source") or "tool_result"),
                    ttl_seconds=row.get("ttl_seconds"),
                    task_id=str(row.get("task_id") or ""),
                    evidence_ref=str(row.get("evidence_ref") or ""),
                )
                counts["observations"] += 1
            for row in self.db.list_procedures(limit=500):
                self.procedures.import_state({"procedures": [row]})
                counts["procedures"] += 1
            for row in self.db.list_calibration_records(limit=2000):
                self.calibration.add(
                    float(row.get("confidence") or 0.0),
                    bool(row.get("outcome")),
                    statement=str(row.get("statement") or ""),
                    domain=str(row.get("domain") or ""),
                    task_id=str(row.get("task_id") or ""),
                )
                counts["calibration"] += 1
            self._hydrated = True
        return counts

    # ------------------------------------------------------- tool observation

    def available_tools(self, tools: Any | None = None) -> set[str]:
        """Names of tools that are actually usable right now."""
        if tools is None:
            return set()
        try:
            return {str(item["name"]) for item in tools.all_tools() if item.get("available")}
        except Exception as exc:  # a registry we cannot read is an empty toolset
            logger.debug("could not read tool registry: %s", exc)
            return set()

    def predict_tool_call(self, task_id: str, tool_name: str, *, arguments: dict[str, Any] | None = None) -> str:
        """Register an expectation *before* the call, so it can be falsified.

        The prediction is deliberately naive ("this tool call will succeed").
        Naive is the point: resolving it against the real outcome yields an
        honest agreement rate and flags tools whose behaviour has drifted. Both
        sides are expressed as outcome classes, never as one tool's raw status
        string.
        """
        prediction_id = ""
        with _guarded(self, "predict_tool_call"):
            prediction = self.world_model.predict(
                f"call {tool_name}", {f"tool:{tool_name}.outcome": "succeeded"}, task_id=task_id
            )
            prediction_id = prediction.id
        return prediction_id

    def observe_tool_result(
        self,
        task_id: str,
        tool_name: str,
        outcome: dict[str, Any],
        *,
        prediction_id: str = "",
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Turn a real tool result into observations and resolve the prediction."""
        recorded: dict[str, Any] = {"observations": 0, "resolved": None, "reinspection": []}
        with _guarded(self, "observe_tool_result"):
            raw_status = str(outcome.get("status") or "unknown")
            status = normalize_tool_status(raw_status)
            summary = str(outcome.get("summary") or "")[:300]
            subject = f"tool:{tool_name}"
            evidence = f"task:{task_id}:{tool_name}"
            # The normalized class drives prediction resolution; the raw status
            # is kept as its own observation so no information is lost.
            self.world_model.observe(subject, "outcome", status, "tool_result", task_id=task_id, evidence_ref=evidence)
            self.world_model.observe(subject, "status", raw_status, "tool_result", task_id=task_id, evidence_ref=evidence)
            recorded["observations"] += 2
            if summary:
                self.world_model.observe(
                    subject, "last_summary", summary, "tool_result", task_id=task_id, evidence_ref=evidence
                )
                # Structured results contribute a few concrete facts, bounded.
            data = outcome.get("data")
            if isinstance(data, dict):
                for key, value in list(data.items())[: MAX_OBSERVATIONS_PER_TOOL_RESULT - recorded["observations"]]:
                    if isinstance(value, (str, int, float, bool)) and str(value).strip():
                        self.world_model.observe(
                            subject,
                            f"data.{str(key)[:40]}",
                            str(value)[:200],
                            "tool_result",
                            task_id=task_id,
                            evidence_ref=evidence,
                        )
                        recorded["observations"] += 1
            if prediction_id:
                resolved = self.world_model.resolve_prediction(prediction_id, {f"{subject}.outcome": status})
                self._persist_world_model_event("prediction_resolved", resolved.to_dict())
                recorded["resolved"] = {
                    "agreement": resolved.agreement,
                    "contradicted": len(resolved.contradicted),
                }
            recorded["reinspection"] = self.world_model.requires_reinspection()
        return recorded

    # ------------------------------------------------------------- pre-flight

    def review_plan(
        self,
        task_id: str,
        objective: str,
        plan: dict[str, Any] | list[str],
        *,
        tools: Any | None = None,
        open_questions: list[str] | None = None,
    ) -> dict[str, Any]:
        """Assess a plan before it is executed, and persist the assessment."""
        steps = list(plan.get("steps") or []) if isinstance(plan, dict) else list(plan or [])
        available = self.available_tools(tools)
        known_facts = [
            f"{subject} {predicate} = {value}"
            for subject, predicate, value in self._recent_facts(limit=6)
        ]
        review = preflight(
            objective,
            steps,
            available_tools=available,
            known_facts=known_facts,
            open_questions=open_questions or [],
            max_tool_calls=self.max_tool_calls,
            max_provider_requests=self.max_provider_requests,
        )
        payload = review.to_dict()
        payload["task_id"] = task_id
        payload["world_model"] = {
            "requires_reinspection": self.world_model.requires_reinspection(),
            "stats": self.world_model.stats().to_dict(),
        }
        with _guarded(self, "persist_preflight"):
            if self.db is not None:
                self.db.save_review(task_id, "preflight", payload)
        return payload

    def _recent_facts(self, limit: int = 6) -> list[tuple[str, str, str]]:
        snapshot = self.world_model.snapshot(limit=limit, include_stale=False)
        facts: list[tuple[str, str, str]] = []
        for item in snapshot.get("observations") or []:
            facts.append((str(item.get("subject") or ""), str(item.get("predicate") or ""), str(item.get("value") or "")))
        return facts

    # ---------------------------------------------------------------- options

    def decide(
        self,
        objective: str,
        options: list[dict[str, Any]],
        *,
        task_id: str = "",
        tools: Any | None = None,
        risk_tolerance: str = "routine",
        authorization_granted: set[str] | None = None,
    ) -> dict[str, Any]:
        """Score candidate approaches and persist the decision with its forecast."""
        available = self.available_tools(tools)
        parsed = [
            Option(
                id=str(item.get("id") or f"option-{index}"),
                description=str(item.get("description") or ""),
                estimated_tool_calls=int(item.get("estimated_tool_calls") or 1),
                estimated_provider_requests=int(item.get("estimated_provider_requests") or 2),
                estimated_minutes=float(item.get("estimated_minutes") or 5.0),
                risk=float(item.get("risk") or 0.1),
                reversible=bool(item.get("reversible", True)),
                verifiable=bool(item.get("verifiable", True)),
                authorization_required=bool(item.get("authorization_required", False)),
                requires_missing_capability=bool(item.get("requires_missing_capability", False)),
                missing_capability=str(item.get("missing_capability") or ""),
            )
            for index, item in enumerate(options, start=1)
            if isinstance(item, dict) and str(item.get("description") or "").strip()
        ]
        decision: Decision = evaluate_options(
            objective,
            parsed,
            available_tools=available,
            max_tool_calls=self.max_tool_calls,
            max_provider_requests=self.max_provider_requests,
            risk_tolerance=risk_tolerance if risk_tolerance in {"cautious", "routine", "aggressive"} else "routine",
            authorization_granted=authorization_granted or set(),
        )
        payload = decision.to_dict()
        payload["task_id"] = task_id
        with _guarded(self, "persist_decision"):
            if self.db is not None:
                payload["id"] = self.db.save_decision(
                    {
                        "task_id": task_id,
                        "objective": decision.objective,
                        "chosen_option_id": decision.chosen_option_id,
                        "short_circuited": decision.short_circuited,
                        "risk_tolerance": decision.risk_tolerance,
                        "predicted_confidence": decision.predicted_confidence,
                        "predicted_outcome": decision.predicted_outcome,
                        "payload": payload,
                    }
                )
        return payload

    def resolve_decision(self, decision_id: str, actual_outcome: str, *, matched: bool | None = None) -> bool:
        """Record what actually happened, keeping it distinct from the forecast."""
        ok = False
        with _guarded(self, "resolve_decision"):
            resolved_matched = matched
            if resolved_matched is None:
                lowered = str(actual_outcome).lower()
                resolved_matched = not any(word in lowered for word in ("failed", "error", "denied", "cancelled"))
            if self.db is not None:
                ok = bool(self.db.resolve_decision(decision_id, str(actual_outcome)[:1000], bool(resolved_matched)))
            self.record_calibration(0.5, bool(resolved_matched), statement=f"decision {decision_id}", domain="decision")
        return ok

    # --------------------------------------------------------------- curiosity

    def resolve_knowledge_gap(
        self,
        question: str,
        *,
        gap_id: str = "",
        blocks_objective: bool = True,
        domain: str = "",
        candidate_paths: tuple[str, ...] = (),
        tools: Any | None = None,
        provider_requests_used: int = 0,
        budget: CuriosityBudget | None = None,
    ) -> dict[str, Any]:
        """Plan a bounded resolution for something NOVA does not know."""
        plan_payload: dict[str, Any] = {}
        with _guarded(self, "resolve_knowledge_gap"):
            active = budget or CuriosityBudget(
                max_provider_requests=self.max_provider_requests,
                authorized_roots=self.authorized_roots,
            )
            gap = KnowledgeGap(
                id=str(gap_id or _signature(question)),
                question=str(question)[:400],
                blocks_objective=blocks_objective,
                domain=str(domain)[:80],
                candidate_paths=tuple(str(path) for path in candidate_paths),
            )
            plan = resolve_gap(
                gap,
                budget=active,
                available_tools=self.available_tools(tools),
                provider_requests_used=provider_requests_used,
            )
            self.exploration.record(plan)
            plan_payload = plan.to_dict()
            out_of_scope = [
                path for path in gap.candidate_paths if not within_scope(path, active.authorized_roots)[0]
            ]
            if out_of_scope:
                plan_payload["refused_paths"] = out_of_scope
        return plan_payload

    # ---------------------------------------------------------------- finalize

    def finalize(
        self,
        task_id: str,
        state: str,
        *,
        objective: str = "",
        checkpoint: dict[str, Any] | None = None,
        verification: str = "",
        verification_note: str = "",
        provider_requests: int = 0,
        budget_exhausted: bool = False,
        tools: Any | None = None,
    ) -> dict[str, Any]:
        """Post-hoc attribution, calibration, and procedure learning for one run."""
        result: dict[str, Any] = {"posthoc": None, "calibration": None, "procedure": None}
        checkpoint = checkpoint or {}
        tool_outcomes = [item for item in (checkpoint.get("tool_results") or []) if isinstance(item, dict)]
        review_payload = self._latest_review(task_id, "preflight")
        review = _rehydrate_preflight(review_payload)

        criteria = list((review_payload or {}).get("acceptance_criteria") or [])
        criteria_met = _count_criteria_met(criteria, state, verification, tool_outcomes)
        cognition_state = checkpoint.get("cognition") or {}
        contradictions = int(cognition_state.get("contradictions") or 0) or int(
            self.world_model.stats().contradictions or 0
        )

        result["posthoc"] = post_hoc(
            task_id=task_id,
            state=state,
            review=review,
            tool_outcomes=tool_outcomes,
            criteria_met=criteria_met,
            provider_requests=provider_requests,
            budget_exhausted=budget_exhausted,
            contradictions=contradictions,
            observed_summary=str(verification_note or checkpoint.get("final_message") or "")[:300],
        ).to_dict()
        result["criteria_met"] = criteria_met
        result["criteria_total"] = len(criteria)

        with _guarded(self, "persist_posthoc"):
            if self.db is not None:
                self.db.save_review(task_id, "posthoc", result["posthoc"])

        # Calibration only when a real prediction exists. Inventing a confidence
        # so that a number can be published would corrupt the ledger.
        predicted_confidence = float((review_payload or {}).get("confidence") or 0.0)
        if predicted_confidence > 0.0:
            outcome = state == "completed" and (
                str(verification or "").lower() in VERIFICATION_CONFIRMED or not self.verification_enabled
            ) and (not criteria or criteria_met >= len(criteria))
            result["calibration"] = self.record_calibration(
                predicted_confidence,
                outcome,
                statement=str(objective or (review_payload or {}).get("objective") or "")[:300],
                domain="task",
                task_id=task_id,
            )
        else:
            result["calibration"] = {
                "recorded": False,
                "reason": "No pre-flight prediction with a stated confidence exists for this task, so nothing was scored.",
            }

        result["procedure"] = self.learn_from_task(
            task_id=task_id,
            objective=str(objective or (review_payload or {}).get("objective") or ""),
            state=state,
            plan=checkpoint.get("plan") or {},
            tool_outcomes=tool_outcomes,
            verification=verification,
            tools=tools,
        )
        result["verification"] = str(verification or "")
        result["world_model"] = self.world_model.stats().to_dict()
        return result

    def record_calibration(
        self, confidence: float, outcome: bool, *, statement: str = "", domain: str = "", task_id: str = ""
    ) -> dict[str, Any]:
        record = self.calibration.add(
            float(max(0.0, min(1.0, confidence))),
            bool(outcome),
            statement=statement,
            domain=domain,
            task_id=task_id,
        )
        with _guarded(self, "persist_calibration"):
            if self.db is not None:
                self.db.add_calibration_record(
                    record.confidence, record.outcome, statement=record.statement, domain=record.domain, task_id=record.task_id
                )
        report = self.calibration.report(domain)
        return {"recorded": True, "record": record.to_dict(), "report": report.to_dict()}

    def _latest_review(self, task_id: str, phase: str) -> dict[str, Any] | None:
        if self.db is None:
            return None
        try:
            reviews = self.db.get_reviews(task_id, phase)
        except Exception as exc:  # a missing review must not stop finalization
            logger.debug("could not load %s review for %s: %s", phase, task_id, exc)
            return None
        return reviews[-1].get("payload") if reviews else None

    # --------------------------------------------------------------- learning

    def learn_from_task(
        self,
        *,
        task_id: str,
        objective: str,
        state: str,
        plan: dict[str, Any] | list[str],
        tool_outcomes: list[dict[str, Any]],
        verification: str = "",
        tools: Any | None = None,
    ) -> dict[str, Any]:
        """Turn a finished run into a candidate procedure, or reinforce one.

        Reinforcement is the transfer mechanism: a new task whose objective is
        close enough to an existing procedure records an *outcome* against it
        instead of creating a near-duplicate. The library, not this method,
        decides when enough outcomes make a procedure established.
        """
        info: dict[str, Any] = {"action": "none"}
        with _guarded(self, "learn_from_task"):
            steps = list(plan.get("steps") or []) if isinstance(plan, dict) else list(plan or [])
            if not objective or not steps:
                info = {"action": "skipped", "reason": "No objective or no plan steps were recorded for this run."}
                return info

            completed = state == "completed"
            verification_value = str(verification or "").lower()
            scoreable = verification_value not in VERIFICATION_ABSENT or not self.verification_enabled
            success = completed and (
                verification_value in VERIFICATION_CONFIRMED or not self.verification_enabled
            )
            used_tools = sorted({str(item.get("tool") or "") for item in tool_outcomes if item.get("tool")})
            available = self.available_tools(tools)
            hits = self.procedures.retrieve(objective, limit=1, available_tools=available)
            reused = hits[0] if hits and hits[0].score >= REUSE_THRESHOLD else None

            if completed and not scoreable:
                # Independent verification ran and found no evidence. Recording
                # this as a success would inflate the procedure's reliability;
                # recording it as a failure would penalise a workflow for a
                # verification gap. Neither is honest, so it is not scored.
                info = {
                    "action": "not_scored",
                    "reason": (
                        "The run completed but independent verification found no supporting evidence "
                        f"(verification='{verification_value}'), so no reliability outcome was recorded."
                    ),
                    "verification": verification_value,
                }
                return info

            if reused is not None:
                procedure = self.procedures.record_outcome(
                    reused.procedure.id,
                    success=success,
                    evidence_ref=f"task:{task_id}",
                    task_id=task_id,
                )
                info = {
                    "action": "reinforced",
                    "procedure_id": reused.procedure.id,
                    "score": reused.score,
                    "status": procedure.status if procedure else None,
                    "attempts": procedure.attempts if procedure else None,
                    "success_ratio": round(procedure.success_ratio, 4) if procedure else None,
                }
            else:
                procedure_id = _signature(objective)
                existing = self.procedures.get(procedure_id)
                if existing is None:
                    provenance = "tool_result" if success and tool_outcomes else "model_generated"
                    self.procedures.add(
                        procedure_id=procedure_id,
                        name=str(objective)[:200],
                        domain=_infer_domain(objective, used_tools),
                        summary=f"Derived from task {task_id} which finished '{state}'.",
                        steps=steps,
                        preconditions=[f"tools available: {', '.join(used_tools)}"] if used_tools else [],
                        environment=environment_markers(self.workspace_root),
                        tools_required=used_tools,
                        tags=sorted({str(item.get("status") or "") for item in tool_outcomes if item.get("status")}),
                        source_task_ids=[task_id],
                        evidence_refs=[f"task:{task_id}"],
                        provenance=provenance,
                    )
                self.procedures.record_outcome(procedure_id, success=success, evidence_ref=f"task:{task_id}", task_id=task_id)
                procedure = self.procedures.get(procedure_id)
                info = {
                    "action": "created" if existing is None else "reinforced",
                    "procedure_id": procedure_id,
                    "verification": verification_value,
                    "status": procedure.status if procedure else None,
                    "attempts": procedure.attempts if procedure else None,
                    "success_ratio": round(procedure.success_ratio, 4) if procedure else None,
                    "provenance": procedure.provenance if procedure else None,
                }
                if not success:
                    info["note"] = (
                        "Recorded as a failed attempt. A procedure is only a candidate until enough attempts "
                        "succeed; a single outcome never establishes it."
                    )

            with _guarded(self, "persist_procedure"):
                if self.db is not None and info.get("procedure_id"):
                    stored = self.procedures.get(str(info["procedure_id"]))
                    if stored is not None:
                        self.db.upsert_procedure(stored.to_dict())
        return info

    def transfer(self, procedure_id: str, *, target_domain: str = "", target_environment: dict[str, str] | None = None, tools: Any | None = None) -> dict[str, Any]:
        """Check whether a stored procedure can carry over to a new context."""
        payload: dict[str, Any] = {"procedure_id": procedure_id, "verdict": "unknown"}
        with _guarded(self, "transfer"):
            procedure = self.procedures.get(procedure_id)
            if procedure is None and self.db is not None:
                row = self.db.get_procedure(procedure_id)
                if row:
                    self.procedures.import_state({"procedures": [row]})
                    procedure = self.procedures.get(procedure_id)
            if procedure is None:
                payload = {"procedure_id": procedure_id, "verdict": "unknown", "notes": f"No procedure '{procedure_id}' is stored."}
                return payload
            target = dict(target_environment or {})
            if not target:
                target = environment_markers(self.workspace_root)
            payload = transfer_check(
                procedure, target_domain=target_domain, target_environment=target, available_tools=self.available_tools(tools)
            ).to_dict()
        return payload

    # ------------------------------------------------------------- evaluation

    def run_evaluation(
        self,
        *,
        include_held_out: bool = False,
        tools: Any | None = None,
        commit: str = "",
        use_baseline: bool = True,
    ) -> dict[str, Any]:
        """Run the GIE suite, compare to the stored baseline, persist the run."""
        context = EvalContext(
            workspace_root=self.workspace_root,
            available_tools=frozenset(self.available_tools(tools)),
            db=self.db,
            authorized_roots=self.authorized_roots,
        )
        baseline = None
        if use_baseline and not include_held_out and self.db is not None:
            with _guarded(self, "load_baseline"):
                from .evaluation import SUITE_VERSION

                baseline = self.db.get_latest_intelligence_baseline(SUITE_VERSION)
        report = run_suite(context, include_held_out=include_held_out, baseline=baseline, commit=commit)
        payload = report.to_dict()
        with _guarded(self, "persist_eval_run"):
            if self.db is not None:
                payload["run_id"] = self.db.create_intelligence_eval_run(
                    report.suite_version,
                    "completed",
                    payload,
                    commit_ref=report.commit,
                    include_held_out=include_held_out,
                    pass_rate=report.pass_rate,
                    baseline_version=report.baseline_version,
                )
        return payload

    # ---------------------------------------------------------------- snapshot

    def snapshot(self, *, tools: Any | None = None) -> dict[str, Any]:
        """Everything the UI needs to show what NOVA currently believes and knows."""
        stats = self.world_model.stats().to_dict()
        calibration = self.calibration.report().to_dict()
        procedures = self.procedures.export_state()
        return {
            "scope": self.scope,
            "world_model": stats,
            "requires_reinspection": self.world_model.requires_reinspection(),
            "prediction_accuracy": self.world_model.prediction_accuracy(),
            "calibration": calibration,
            "procedures": {
                "counts": procedures["counts"],
                "thresholds": procedures["thresholds"],
                "recent": [item.to_dict() for item in self.procedures.all()[:10]],
            },
            "exploration": self.exploration.to_dict(),
            "available_tools": sorted(self.available_tools(tools)),
            "degraded": self.errors > 0,
            "errors": self.errors,
            "last_error": self.last_error,
        }

    def beliefs(self, *, subject: str = "", limit: int = 40) -> dict[str, Any]:
        """The current world-model snapshot plus a summary of what is claimed."""
        claims = [
            classify_claim(
                f"{item.get('subject')} {item.get('predicate')} = {item.get('value')}",
                provenance=str(item.get("source") or "model_generated"),
                evidence_refs=(str(item.get("evidence_ref")),) if item.get("evidence_ref") else (),
            )
            for item in (self.world_model.snapshot(subject=subject or None, limit=limit).get("observations") or [])
        ]
        summary = summarize(claims)
        return {
            "summary": summary.to_dict(),
            "snapshot": self.world_model.snapshot(subject=subject or None, limit=limit),
            "requires_reinspection": self.world_model.requires_reinspection(),
        }


def _rehydrate_preflight(payload: dict[str, Any] | None) -> Any:
    """Rebuild a PreflightReview from its persisted dict, or None."""
    if not payload:
        return None
    from .meta_reasoning import PreflightReview

    try:
        return PreflightReview(
            objective=str(payload.get("objective") or ""),
            required_outcome=str(payload.get("required_outcome") or ""),
            understood=list(payload.get("understood") or []),
            unknowns=list(payload.get("unknowns") or []),
            missing_evidence=list(payload.get("missing_evidence") or []),
            riskiest_assumptions=list(payload.get("riskiest_assumptions") or []),
            failure_modes=list(payload.get("failure_modes") or []),
            capability_gaps=list(payload.get("capability_gaps") or []),
            blocking_capability_gaps=list(payload.get("blocking_capability_gaps") or []),
            acceptance_criteria=list(payload.get("acceptance_criteria") or []),
            cheapest_verification=str(payload.get("cheapest_verification") or ""),
            verification_tool=str(payload.get("verification_tool") or ""),
            abandon_conditions=list(payload.get("abandon_conditions") or []),
            cheaper_alternative=payload.get("cheaper_alternative"),
            estimated_tool_calls=int(payload.get("estimated_tool_calls") or 0),
            estimated_provider_requests=int(payload.get("estimated_provider_requests") or 0),
            proceed=str(payload.get("proceed") or "proceed"),
            rationale=str(payload.get("rationale") or ""),
            confidence=float(payload.get("confidence") or 0.0),
            created_at=str(payload.get("created_at") or _utc_now()),
        )
    except (TypeError, ValueError) as exc:
        logger.debug("could not rehydrate preflight review: %s", exc)
        return None


def _count_criteria_met(criteria: list[str], state: str, verification: str, tool_outcomes: list[dict[str, Any]]) -> int:
    """How many acceptance criteria the recorded evidence actually satisfies.

    Deliberately conservative: a criterion counts only when something observable
    supports it. Completion state alone satisfies just the evidence criterion.
    """
    if not criteria:
        return 0
    met = 0
    ok_tools = [item for item in tool_outcomes if normalize_tool_status(item.get("status")) == "succeeded"]
    verified = str(verification or "").lower() in VERIFICATION_CONFIRMED
    completed = state == "completed"
    for criterion in criteria:
        lowered = criterion.lower()
        if "tool result" in lowered or "observation" in lowered:
            met += 1 if ok_tools else 0
        elif "test command" in lowered or "test suite" in lowered:
            met += 1 if verified or any("test" in str(item.get("tool") or "").lower() for item in ok_tools) else 0
        elif "no longer reproduces" in lowered:
            met += 1 if verified and completed else 0
        elif "written result" in lowered or "cites the evidence" in lowered:
            met += 1 if completed else 0
        elif "concrete result exists" in lowered:
            met += 1 if completed and ok_tools else 0
        else:
            met += 1 if completed and ok_tools else 0
    return met


def _infer_domain(objective: str, used_tools: list[str]) -> str:
    text = str(objective).lower()
    if re.search(r"\b(test|bug|defect|refactor|code|repo|function|class|compile)\b", text):
        return "software_engineering"
    if re.search(r"\b(diagnos|port|service|log|crash|slow|disk|memory|cpu|network)\b", text):
        return "system_diagnosis"
    if re.search(r"\b(research|paper|documentation|compare|survey|citation)\b", text):
        return "research"
    if any(tool.startswith("workspace.") for tool in used_tools):
        return "file_operations"
    if any(tool.startswith("process.") for tool in used_tools):
        return "system_operations"
    return "general"
