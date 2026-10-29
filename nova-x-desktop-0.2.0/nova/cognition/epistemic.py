"""Epistemic state: typed claims, provenance, and measured confidence calibration.

This module exists to make NOVA's certainty *falsifiable*. A confidence number
that is never compared against outcomes is decoration, so every prediction can
be recorded here and scored against what actually happened.

Design rules enforced in code, not in prose:

* An ``observation`` must carry evidence and a non-model provenance. A model
  cannot assert that it observed something; it can only infer or predict.
* ``unknown`` claims carry zero confidence by construction.
* Calibration is reported as ``insufficient_data`` until enough outcomes exist.
  A score computed from three samples would be noise presented as measurement.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

ClaimKind = Literal["observation", "inference", "assumption", "prediction", "unknown"]
Provenance = Literal[
    "user",
    "tool_result",
    "external_source",
    "test",
    "memory",
    "model_generated",
]

CLAIM_KINDS: tuple[ClaimKind, ...] = (
    "observation",
    "inference",
    "assumption",
    "prediction",
    "unknown",
)
PROVENANCES: tuple[Provenance, ...] = (
    "user",
    "tool_result",
    "external_source",
    "test",
    "memory",
    "model_generated",
)

# Provenance that can legitimately support a direct observation. A model's own
# output is excluded: text generation is not perception.
OBSERVATIONAL_PROVENANCE: frozenset[str] = frozenset({"tool_result", "user", "external_source", "test"})

# Confidence is only meaningful for forward-looking or derived statements.
CONFIDENCE_BEARING_KINDS: frozenset[str] = frozenset({"inference", "assumption", "prediction"})

# Below this many resolved outcomes, calibration numbers are not reported.
MIN_CALIBRATION_SAMPLES = 10
CALIBRATION_BUCKETS = 5


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


class EpistemicError(ValueError):
    """Raised when a claim violates the evidence rules of its declared kind."""


@dataclass(frozen=True)
class Claim:
    """A single unit of NOVA's stated belief, with its evidentiary basis."""

    statement: str
    kind: ClaimKind
    provenance: Provenance
    confidence: float = 0.0
    evidence_refs: tuple[str, ...] = ()
    domain: str = ""
    task_id: str = ""
    created_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        if self.kind not in CLAIM_KINDS:
            raise EpistemicError(f"Unknown claim kind: {self.kind!r}")
        if self.provenance not in PROVENANCES:
            raise EpistemicError(f"Unknown provenance: {self.provenance!r}")
        if not self.statement or not self.statement.strip():
            raise EpistemicError("A claim requires a non-empty statement.")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise EpistemicError("Confidence must be between 0.0 and 1.0.")

        if self.kind == "observation":
            if self.provenance not in OBSERVATIONAL_PROVENANCE:
                raise EpistemicError(
                    "An observation requires tool, user, external, or test provenance. "
                    "Model-generated text is an inference, never an observation."
                )
            if not self.evidence_refs:
                raise EpistemicError("An observation must reference the evidence that produced it.")
        elif self.kind == "unknown":
            if float(self.confidence) != 0.0:
                raise EpistemicError("An 'unknown' claim must carry zero confidence.")
        elif self.kind not in CONFIDENCE_BEARING_KINDS:
            raise EpistemicError(f"Claim kind {self.kind!r} cannot carry confidence.")

    @property
    def is_actionable_evidence(self) -> bool:
        """True when this claim may justify a consequential action on its own.

        Only direct observations and executed tests qualify. Inferences,
        assumptions and predictions may motivate a *check*, never an action.
        """
        return self.kind == "observation" or self.provenance == "test"

    def to_dict(self) -> dict[str, Any]:
        return {
            "statement": self.statement,
            "kind": self.kind,
            "provenance": self.provenance,
            "confidence": round(float(self.confidence), 4),
            "evidence_refs": list(self.evidence_refs),
            "domain": self.domain,
            "task_id": self.task_id,
            "created_at": self.created_at,
        }


def classify_claim(
    statement: str,
    provenance: Provenance,
    evidence_refs: tuple[str, ...] = (),
    confidence: float = 0.0,
    **kwargs: Any,
) -> Claim:
    """Build a claim, demoting it honestly when the evidence does not support it.

    Callers frequently believe they have an observation. If the provenance or
    evidence does not qualify, the claim is recorded as an ``inference`` (or
    ``unknown`` when nothing supports it) rather than being rejected outright, so
    the system never overstates what it knows.
    """
    declared_kind = str(kwargs.pop("kind", "observation"))
    if declared_kind == "observation" and (provenance not in OBSERVATIONAL_PROVENANCE or not evidence_refs):
        demoted = "inference" if confidence > 0 else "unknown"
        return Claim(
            statement=statement,
            kind=demoted,  # type: ignore[arg-type]
            provenance=provenance,
            confidence=confidence if demoted == "inference" else 0.0,
            evidence_refs=evidence_refs,
            **kwargs,
        )
    if declared_kind == "unknown":
        return Claim(statement=statement, kind="unknown", provenance=provenance, confidence=0.0, evidence_refs=evidence_refs, **kwargs)
    return Claim(
        statement=statement,
        kind=declared_kind,  # type: ignore[arg-type]
        provenance=provenance,
        confidence=confidence if declared_kind in CONFIDENCE_BEARING_KINDS else 0.0,
        evidence_refs=evidence_refs,
        **kwargs,
    )


@dataclass(frozen=True)
class BeliefSummary:
    """A partition of what NOVA currently holds, for honest reporting."""

    observations: int
    inferences: int
    assumptions: int
    predictions: int
    unknowns: int
    open_questions: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "observations": self.observations,
            "inferences": self.inferences,
            "assumptions": self.assumptions,
            "predictions": self.predictions,
            "unknowns": self.unknowns,
            "open_questions": list(self.open_questions),
            "total": self.observations + self.inferences + self.assumptions + self.predictions + self.unknowns,
        }


def summarize(claims: list[Claim], open_questions: tuple[str, ...] = ()) -> BeliefSummary:
    counts = dict.fromkeys(CLAIM_KINDS, 0)
    for claim in claims:
        counts[claim.kind] = counts.get(claim.kind, 0) + 1
    return BeliefSummary(
        observations=counts["observation"],
        inferences=counts["inference"],
        assumptions=counts["assumption"],
        predictions=counts["prediction"],
        unknowns=counts["unknown"],
        open_questions=tuple(open_questions),
    )


@dataclass(frozen=True)
class CalibrationRecord:
    """One resolved prediction: what NOVA expected and what happened."""

    confidence: float
    outcome: bool
    task_id: str = ""
    domain: str = ""
    statement: str = ""
    created_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence": round(float(self.confidence), 4),
            "outcome": bool(self.outcome),
            "task_id": self.task_id,
            "domain": self.domain,
            "statement": self.statement,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class CalibrationReport:
    """Measured agreement between stated confidence and observed outcomes."""

    samples: int
    status: str
    mean_confidence: float | None
    observed_success_rate: float | None
    expected_calibration_error: float | None
    brier_score: float | None
    overconfidence: float | None
    buckets: list[dict[str, Any]]
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "samples": self.samples,
            "status": self.status,
            "mean_confidence": self.mean_confidence,
            "observed_success_rate": self.observed_success_rate,
            "expected_calibration_error": self.expected_calibration_error,
            "brier_score": self.brier_score,
            "overconfidence": self.overconfidence,
            "buckets": self.buckets,
            "note": self.note,
        }


class CalibrationLedger:
    """Accumulates resolved predictions and scores NOVA's self-assessment.

    Purely arithmetic and fully offline: no model call participates, so the
    result is a measurement of the system rather than an opinion about it.
    """

    def __init__(self, records: list[CalibrationRecord] | None = None):
        self._records: list[CalibrationRecord] = list(records or [])

    def __len__(self) -> int:
        return len(self._records)

    def add(self, confidence: float, outcome: bool, **kwargs: Any) -> CalibrationRecord:
        if not 0.0 <= float(confidence) <= 1.0:
            raise EpistemicError("Confidence must be between 0.0 and 1.0.")
        record = CalibrationRecord(confidence=float(confidence), outcome=bool(outcome), **kwargs)
        self._records.append(record)
        return record

    @property
    def records(self) -> list[CalibrationRecord]:
        return list(self._records)

    def report(self, domain: str = "") -> CalibrationReport:
        rows = [item for item in self._records if not domain or item.domain == domain]
        n = len(rows)
        if n < MIN_CALIBRATION_SAMPLES:
            return CalibrationReport(
                samples=n,
                status="insufficient_data",
                mean_confidence=None,
                observed_success_rate=None,
                expected_calibration_error=None,
                brier_score=None,
                overconfidence=None,
                buckets=[],
                note=(
                    f"Calibration requires at least {MIN_CALIBRATION_SAMPLES} resolved predictions; "
                    f"{n} available. No calibration score is claimed."
                ),
            )

        confidences = [float(item.confidence) for item in rows]
        outcomes = [1.0 if item.outcome else 0.0 for item in rows]
        mean_confidence = sum(confidences) / n
        success_rate = sum(outcomes) / n
        brier = sum((c - o) ** 2 for c, o in zip(confidences, outcomes, strict=True)) / n

        buckets: list[dict[str, Any]] = []
        total_ece = 0.0
        for index in range(CALIBRATION_BUCKETS):
            low = index / CALIBRATION_BUCKETS
            high = (index + 1) / CALIBRATION_BUCKETS
            members = [
                (c, o)
                for c, o in zip(confidences, outcomes, strict=True)
                # The final bucket is closed so confidence == 1.0 is included.
                if (low <= c < high) or (index == CALIBRATION_BUCKETS - 1 and c == 1.0)
            ]
            if not members:
                buckets.append({"range": f"{low:.1f}-{high:.1f}", "count": 0, "mean_confidence": None, "observed_rate": None, "gap": None})
                continue
            bucket_confidence = sum(c for c, _ in members) / len(members)
            bucket_rate = sum(o for _, o in members) / len(members)
            gap = abs(bucket_confidence - bucket_rate)
            total_ece += (len(members) / n) * gap
            buckets.append({
                "range": f"{low:.1f}-{high:.1f}",
                "count": len(members),
                "mean_confidence": round(bucket_confidence, 4),
                "observed_rate": round(bucket_rate, 4),
                "gap": round(gap, 4),
            })

        overconfidence = mean_confidence - success_rate
        if total_ece <= 0.05:
            status, note = "well_calibrated", "Stated confidence tracks observed outcomes within 5 percentage points."
        elif total_ece <= 0.15:
            status, note = "acceptably_calibrated", "Moderate calibration error; treat confidence as indicative, not authoritative."
        else:
            status, note = "poorly_calibrated", "Large calibration error. Confidence outputs should not drive consequential decisions yet."
        if overconfidence > 0.15:
            note += " NOVA is systematically overconfident on this sample."
        elif overconfidence < -0.15:
            note += " NOVA is systematically underconfident on this sample."

        return CalibrationReport(
            samples=n,
            status=status,
            mean_confidence=round(mean_confidence, 4),
            observed_success_rate=round(success_rate, 4),
            expected_calibration_error=round(total_ece, 4),
            brier_score=round(brier, 4),
            overconfidence=round(overconfidence, 4),
            buckets=buckets,
            note=note,
        )


def brier_score(records: list[CalibrationRecord]) -> float | None:
    """Convenience accessor; returns None rather than a misleading 0.0."""
    if not records:
        return None
    return round(
        sum((float(item.confidence) - (1.0 if item.outcome else 0.0)) ** 2 for item in records) / len(records),
        4,
    )
