"""Counterfactual planning and decision intelligence (§74, §84).

Evaluates candidate approaches *before* committing to one, scores them on cost,
risk, reversibility and verifiability, and keeps the predicted outcome separate
from the observed one so the two can be compared afterwards.

Two properties matter more than the scoring formula:

* **Bounded comparison.** When one option is already cheap, low-risk, reversible
  and verifiable, the full comparison is skipped. Evaluating ten alternatives to
  pick an obvious one is itself a resource failure, and the short-circuit is
  reported explicitly rather than happening invisibly.
* **The model does not set its own rules.** Risk tolerance, budget and the set
  of authorized capabilities are supplied by the caller from policy. Nothing in
  here lets a plan widen its own authorization, and an option that needs a
  capability NOVA does not have is never silently substituted with a workaround.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

RiskTolerance = Literal["cautious", "routine", "aggressive"]

# How much a given risk level costs under each operator-selected tolerance.
_RISK_PENALTY: dict[RiskTolerance, tuple[float, ...]] = {
    "cautious": (0.0, 0.25, 0.6, 1.0),
    "routine": (0.0, 0.12, 0.35, 0.7),
    "aggressive": (0.0, 0.05, 0.15, 0.4),
}
_RISK_BANDS = (0.05, 0.2, 0.5)

# An option is short-circuited only when it clears every one of these.
_SHORT_CIRCUIT_MAX_TOOL_CALLS = 3
_SHORT_CIRCUIT_MAX_PROVIDER_REQUESTS = 6
_SHORT_CIRCUIT_MAX_MINUTES = 10.0
_SHORT_CIRCUIT_MAX_RISK = 0.15


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _risk_band(risk: float) -> int:
    for index, ceiling in enumerate(_RISK_BANDS):
        if risk <= ceiling:
            return index
    return len(_RISK_BANDS)


@dataclass(frozen=True)
class Option:
    """One candidate approach, described by facts rather than adjectives."""

    id: str
    description: str
    estimated_tool_calls: int = 1
    estimated_provider_requests: int = 2
    estimated_minutes: float = 5.0
    risk: float = 0.1
    reversible: bool = True
    verifiable: bool = True
    authorization_required: bool = False
    requires_missing_capability: bool = False
    missing_capability: str = ""
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not str(self.id).strip():
            raise ValueError("Option.id is required")
        if not str(self.description).strip():
            raise ValueError("Option.description is required")
        if not 0.0 <= float(self.risk) <= 1.0:
            raise ValueError("Option.risk must be between 0 and 1")
        if self.estimated_tool_calls < 0 or self.estimated_provider_requests < 0:
            raise ValueError("cost estimates cannot be negative")

    @property
    def is_short_circuit_eligible(self) -> bool:
        return (
            self.estimated_tool_calls <= _SHORT_CIRCUIT_MAX_TOOL_CALLS
            and self.estimated_provider_requests <= _SHORT_CIRCUIT_MAX_PROVIDER_REQUESTS
            and self.estimated_minutes <= _SHORT_CIRCUIT_MAX_MINUTES
            and self.risk <= _SHORT_CIRCUIT_MAX_RISK
            and self.reversible
            and self.verifiable
            and not self.requires_missing_capability
        )


@dataclass(frozen=True)
class OptionEvaluation:
    """Scored option. ``predicted_outcome`` is a forecast, never a result."""

    option: Option
    score: float
    rank: int
    within_budget: bool
    cost_ratio: float
    risk_penalty: float
    predicted_outcome: str
    rejection_reason: str
    actual_outcome: str | None = None
    prediction_matched: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.option.id,
            "description": self.option.description,
            "score": round(self.score, 4),
            "rank": self.rank,
            "within_budget": self.within_budget,
            "cost_ratio": round(self.cost_ratio, 4),
            "risk_penalty": round(self.risk_penalty, 4),
            "predicted_outcome": self.predicted_outcome,
            "rejection_reason": self.rejection_reason,
            "estimated_tool_calls": self.option.estimated_tool_calls,
            "estimated_provider_requests": self.option.estimated_provider_requests,
            "estimated_minutes": round(float(self.option.estimated_minutes), 2),
            "risk": round(float(self.option.risk), 4),
            "reversible": self.option.reversible,
            "verifiable": self.option.verifiable,
            "authorization_required": self.option.authorization_required,
            "requires_missing_capability": self.option.requires_missing_capability,
            "missing_capability": self.option.missing_capability,
            "actual_outcome": self.actual_outcome,
            "prediction_matched": self.prediction_matched,
        }


@dataclass
class Decision:
    """The record of a choice: what was picked, what was predicted, what happened."""

    objective: str
    chosen_option_id: str | None
    short_circuited: bool
    decision_rationale: str
    alternatives_considered: int
    alternatives_rejected: list[str]
    risk_tolerance: RiskTolerance
    predicted_outcome: str
    predicted_confidence: float
    authorization_needed: bool
    authorization_note: str
    evaluations: list[OptionEvaluation] = field(default_factory=list)
    actual_outcome: str | None = None
    prediction_matched: bool | None = None
    prediction_accuracy: float | None = None
    decided_at: str = field(default_factory=_utc_now)
    resolved_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "chosen_option_id": self.chosen_option_id,
            "short_circuited": self.short_circuited,
            "decision_rationale": self.decision_rationale,
            "alternatives_considered": self.alternatives_considered,
            "alternatives_rejected": list(self.alternatives_rejected),
            "risk_tolerance": self.risk_tolerance,
            "predicted_outcome": self.predicted_outcome,
            "predicted_confidence": round(float(self.predicted_confidence), 4),
            "authorization_needed": self.authorization_needed,
            "authorization_note": self.authorization_note,
            "evaluations": [item.to_dict() for item in self.evaluations],
            "actual_outcome": self.actual_outcome,
            "prediction_matched": self.prediction_matched,
            "prediction_accuracy": (
                None if self.prediction_accuracy is None else round(float(self.prediction_accuracy), 4)
            ),
            "decided_at": self.decided_at,
            "resolved_at": self.resolved_at,
        }

    def record_actual(self, outcome: str, *, matched: bool | None = None) -> None:
        """Attach what really happened. Predicted and actual stay distinguishable."""
        self.actual_outcome = str(outcome)[:500]
        self.resolved_at = _utc_now()
        if matched is None:
            matched = bool(outcome) and "failed" not in outcome.lower() and "error" not in outcome.lower()
        self.prediction_matched = bool(matched)
        self.prediction_accuracy = 1.0 if self.prediction_matched else 0.0
        for evaluation in self.evaluations:
            if evaluation.option.id == self.chosen_option_id:
                object.__setattr__(evaluation, "actual_outcome", self.actual_outcome)
                object.__setattr__(evaluation, "prediction_matched", self.prediction_matched)


def evaluate_options(
    objective: str,
    options: list[Option],
    *,
    available_tools: set[str] | None = None,
    max_tool_calls: int = 8,
    max_provider_requests: int = 12,
    max_minutes: float = 30.0,
    risk_tolerance: RiskTolerance = "routine",
    authorization_granted: set[str] | None = None,
) -> Decision:
    """Score options and choose one, honouring budget and policy limits."""
    tools = set(available_tools or set())
    granted = set(authorization_granted or set())
    if risk_tolerance not in _RISK_PENALTY:
        risk_tolerance = "routine"

    evaluations: list[OptionEvaluation] = []
    for option in options:
        over_budget = (
            option.estimated_tool_calls > max_tool_calls
            or option.estimated_provider_requests > max_provider_requests
            or option.estimated_minutes > max_minutes
        )
        rejection = ""
        if option.requires_missing_capability:
            rejection = f"Needs a capability NOVA does not have: {option.missing_capability or 'unspecified'}."
        elif option.authorization_required and option.id not in granted:
            rejection = "Requires operator authorization that has not been granted for this option."
        elif over_budget:
            rejection = (
                f"Exceeds the configured budget (tool calls {option.estimated_tool_calls}/{max_tool_calls}, "
                f"requests {option.estimated_provider_requests}/{max_provider_requests}, "
                f"minutes {option.estimated_minutes:.0f}/{max_minutes:.0f})."
            )

        cost_ratio = 0.0
        if max_tool_calls and max_provider_requests and max_minutes:
            cost_ratio = (
                (option.estimated_tool_calls / max_tool_calls)
                + (option.estimated_provider_requests / max_provider_requests)
                + (option.estimated_minutes / max_minutes)
            ) / 3.0
        risk_penalty = _RISK_PENALTY[risk_tolerance][_risk_band(option.risk)]

        score = 1.0
        score -= 0.30 * min(1.0, cost_ratio)
        score -= 0.35 * risk_penalty
        score -= 0.15 * (0.0 if option.reversible else 1.0)
        score -= 0.15 * (0.0 if option.verifiable else 1.0)
        score -= 0.05 * (0.0 if option.authorization_required else 1.0)
        if rejection:
            score = 0.0
        score = round(max(0.0, min(1.0, score)), 4)

        predicted = _predict(option, tools)
        evaluations.append(
            OptionEvaluation(
                option=option,
                score=score,
                rank=0,
                within_budget=not over_budget and not rejection,
                cost_ratio=cost_ratio,
                risk_penalty=risk_penalty,
                predicted_outcome=predicted,
                rejection_reason=rejection,
            )
        )

    evaluations.sort(key=lambda item: (-item.score, item.option.estimated_provider_requests, item.option.id))
    for index, evaluation in enumerate(evaluations, start=1):
        object.__setattr__(evaluation, "rank", index)

    viable = [item for item in evaluations if item.within_budget and item.score > 0]
    rejected = [item for item in evaluations if item.rejection_reason]

    # Bounded comparison: one clearly sufficient option ends the search here.
    eligible = [item for item in viable if item.option.is_short_circuit_eligible]
    short_circuited = len(eligible) == 1
    if short_circuited:
        chosen = eligible[0]
        rationale = (
            f"Short-circuited: '{chosen.option.id}' is already cheap "
            f"({chosen.option.estimated_tool_calls} tool call(s), "
            f"{chosen.option.estimated_provider_requests} request(s)), low risk "
            f"({chosen.option.risk:.2f}), reversible and verifiable. Comparing "
            f"{len(options) - 1} further alternative(s) would cost more than it could improve."
        )
    elif viable:
        chosen = viable[0]
        rationale = (
            f"Selected '{chosen.option.id}' with score {chosen.score:.3f} against "
            f"{len(viable) - 1} other viable option(s); best cost/risk/reversibility balance "
            f"under '{risk_tolerance}' tolerance."
        )
    else:
        chosen = None
        blockers = "; ".join(item.rejection_reason for item in rejected[:3]) or "no option was supplied"
        rationale = (
            f"No viable option: {blockers}. Report this precisely to the user instead of "
            "substituting an unauthorized or unavailable workaround."
        )

    authorization_needed = bool(chosen and chosen.option.authorization_required)
    authorization_note = ""
    if authorization_needed:
        authorization_note = (
            f"Option '{chosen.option.id}' is authorized for this decision, but NOVA cannot extend that "
            "authorization to a different option or a later run."
        )
    elif chosen is None and rejected:
        authorization_note = "At least one option was rejected on authorization grounds; only the operator can change that."

    predicted_outcome = chosen.predicted_outcome if chosen else "Nothing will be executed; no option is viable."
    predicted_confidence = 0.0
    if chosen:
        predicted_confidence = round(
            max(
                0.05,
                min(
                    0.9,
                    0.45
                    + (0.25 if chosen.option.verifiable else 0.0)
                    + (0.15 if chosen.option.reversible else 0.0)
                    + (0.10 * chosen.score)
                    - (0.20 * chosen.risk_penalty),
                ),
            ),
            4,
        )

    return Decision(
        objective=str(objective)[:500],
        chosen_option_id=chosen.option.id if chosen else None,
        short_circuited=short_circuited,
        decision_rationale=rationale,
        alternatives_considered=len(options),
        alternatives_rejected=[f"{item.option.id}: {item.rejection_reason}" for item in rejected],
        risk_tolerance=risk_tolerance,
        predicted_outcome=predicted_outcome,
        predicted_confidence=predicted_confidence,
        authorization_needed=authorization_needed,
        authorization_note=authorization_note,
        evaluations=evaluations,
    )


def _predict(option: Option, tools: set[str]) -> str:
    """A forecast phrased as a forecast. It is never reported as a result."""
    parts = [f"Predicted (not yet executed): '{option.description}'"]
    parts.append(
        f"should take about {option.estimated_tool_calls} tool call(s) and "
        f"{option.estimated_provider_requests} provider request(s) (~{option.estimated_minutes:.0f} min)."
    )
    if option.verifiable:
        parts.append("The outcome will be verifiable from a recorded tool result.")
    else:
        parts.append("WARNING: the outcome cannot be verified from tool results, so success would be self-reported only.")
    if not option.reversible:
        parts.append("WARNING: this option is not reversible; a mistake cannot be undone by NOVA.")
    if option.risk >= 0.5:
        parts.append(f"Carries substantial risk ({option.risk:.2f}); confirm with the user before executing.")
    if tools:
        parts.append(f"{len(tools)} tool(s) are available to carry it out.")
    return " ".join(parts)
