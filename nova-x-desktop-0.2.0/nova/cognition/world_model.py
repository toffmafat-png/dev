"""Internal world model: typed observations, relations, predictions, hypotheses.

§73 asks for an explicit, updateable representation of the task environment that
is *not* conversational history. This module stores facts as subject/predicate/
value triples with provenance and acquisition time, so NOVA can:

* tell a direct observation from an inferred relation (``inferred`` flag);
* know when a fact has gone stale and must be re-measured before it is trusted
  for a consequential action;
* predict the effect of an action, then compare prediction against observation
  and record the contradiction when they disagree;
* accumulate hypotheses and only promote them once independently confirmed.

The model is never treated as complete: ``snapshot`` reports coverage and
staleness alongside the values, and a contradiction marks the affected subject
as requiring reinspection.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from nova.cognition.epistemic import Provenance

ObservationSource = Provenance

# Facts about a live system that must not be trusted for long.
DEFAULT_TTL_SECONDS = {
    "process.running": 15,
    "service.state": 30,
    "network.interface": 60,
    "filesystem.exists": 60,
    "package.installed": 3600,
    "resource.usage": 15,
    "git.branch": 60,
    "command.exit_code": None,  # a completed run is a permanent historical fact
}
FALLBACK_TTL_SECONDS = 300

# The observation store has a floor so a caller cannot shrink the model into
# uselessness by passing a tiny bound.
MIN_MAX_OBSERVATIONS = 50


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _parse(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return _utc_now()
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


@dataclass(frozen=True)
class Observation:
    """One measured fact about the environment."""

    subject: str
    predicate: str
    value: str
    source: ObservationSource
    observed_at: str = field(default_factory=lambda: _utc_now().isoformat(timespec="microseconds"))
    ttl_seconds: int | None = None
    task_id: str = ""
    evidence_ref: str = ""

    def age_seconds(self, now: datetime | None = None) -> float:
        return max(0.0, ((now or _utc_now()) - _parse(self.observed_at)).total_seconds())

    def ttl(self) -> int | None:
        if self.ttl_seconds is not None:
            return self.ttl_seconds
        return DEFAULT_TTL_SECONDS.get(self.predicate, FALLBACK_TTL_SECONDS)

    def is_stale(self, now: datetime | None = None) -> bool:
        ttl = self.ttl()
        if ttl is None:
            return False
        return self.age_seconds(now) > ttl

    def to_dict(self, now: datetime | None = None) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "predicate": self.predicate,
            "value": self.value,
            "source": self.source,
            "observed_at": self.observed_at,
            "age_seconds": round(self.age_seconds(now), 1),
            "ttl_seconds": self.ttl(),
            "stale": self.is_stale(now),
            "task_id": self.task_id,
            "evidence_ref": self.evidence_ref,
        }


@dataclass(frozen=True)
class Relation:
    """An edge in the environment graph. ``inferred`` separates fact from guess."""

    subject: str
    predicate: str
    target: str
    inferred: bool = False
    evidence_refs: tuple[str, ...] = ()
    created_at: str = field(default_factory=lambda: _utc_now().isoformat(timespec="microseconds"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "predicate": self.predicate,
            "target": self.target,
            "inferred": self.inferred,
            "evidence_refs": list(self.evidence_refs),
            "created_at": self.created_at,
        }


@dataclass
class Prediction:
    """What NOVA expected an action to do, recorded *before* the outcome."""

    id: str
    action: str
    expected: dict[str, str]
    task_id: str = ""
    created_at: str = field(default_factory=lambda: _utc_now().isoformat(timespec="microseconds"))
    resolved: bool = False
    resolved_at: str = ""
    agreement: float | None = None
    matched: list[str] = field(default_factory=list)
    contradicted: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "expected": dict(self.expected),
            "task_id": self.task_id,
            "created_at": self.created_at,
            "resolved": self.resolved,
            "resolved_at": self.resolved_at,
            "agreement": self.agreement,
            "matched": list(self.matched),
            "contradicted": list(self.contradicted),
            "status": "pending" if not self.resolved else ("confirmed" if not self.contradicted else "contradicted"),
        }


@dataclass
class Hypothesis:
    """A candidate causal claim, promoted only on independent confirmation."""

    id: str
    cause: str
    effect: str
    task_id: str = ""
    confirmations: int = 0
    refutations: int = 0
    status: str = "untested"
    created_at: str = field(default_factory=lambda: _utc_now().isoformat(timespec="microseconds"))
    evidence_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "cause": self.cause,
            "effect": self.effect,
            "task_id": self.task_id,
            "confirmations": self.confirmations,
            "refutations": self.refutations,
            "status": self.status,
            "created_at": self.created_at,
            "evidence_refs": list(self.evidence_refs),
        }


# A hypothesis needs this many independent confirmations before "supported".
MIN_HYPOTHESIS_CONFIRMATIONS = 3


@dataclass(frozen=True)
class WorldModelStats:
    observations: int
    relations: int
    inferred_relations: int
    stale_observations: int
    predictions_total: int
    predictions_resolved: int
    prediction_agreement: float | None
    contradictions: int
    hypotheses_supported: int
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "observations": self.observations,
            "relations": self.relations,
            "inferred_relations": self.inferred_relations,
            "stale_observations": self.stale_observations,
            "predictions_total": self.predictions_total,
            "predictions_resolved": self.predictions_resolved,
            "prediction_agreement": self.prediction_agreement,
            "contradictions": self.contradictions,
            "hypotheses_supported": self.hypotheses_supported,
            "note": self.note,
        }


class WorldModel:
    """Bounded, inspectable environment model for a task or project scope."""

    def __init__(
        self,
        scope: str = "default",
        max_observations: int = 2_000,
        persist: Callable[[str, dict[str, Any]], None] | None = None,
    ):
        self.scope = scope
        self.max_observations = max(MIN_MAX_OBSERVATIONS, int(max_observations))
        self._persist = persist
        self._observations: dict[tuple[str, str], Observation] = {}
        self._history: list[Observation] = []
        self._relations: dict[tuple[str, str, str], Relation] = {}
        self._predictions: dict[str, Prediction] = {}
        self._hypotheses: dict[str, Hypothesis] = {}
        self._reinspect: set[str] = set()
        self._sequence = 0

    # ------------------------------------------------------------------ facts

    def observe(
        self,
        subject: str,
        predicate: str,
        value: Any,
        source: ObservationSource,
        *,
        ttl_seconds: int | None = None,
        task_id: str = "",
        evidence_ref: str = "",
    ) -> Observation:
        """Record a measured fact, superseding any previous value for the key."""
        if source not in {"tool_result", "user", "external_source", "test", "memory", "model_generated"}:
            raise ValueError(f"Unknown observation source: {source!r}")
        observation = Observation(
            subject=str(subject),
            predicate=str(predicate),
            value=str(value),
            source=source,
            ttl_seconds=ttl_seconds,
            task_id=task_id,
            evidence_ref=evidence_ref,
        )
        key = (observation.subject, observation.predicate)
        previous = self._observations.get(key)
        if previous is not None and previous.value != observation.value and previous.source != "model_generated":
            # A measured value changed: this is new information, not an error, but
            # anything that depended on the old value must be re-examined.
            self._reinspect.add(observation.subject)
        self._observations[key] = observation
        self._history.append(observation)
        if len(self._history) > self.max_observations * 4:
            del self._history[: self.max_observations]
        if len(self._observations) > self.max_observations:
            # Evict the oldest entries so a long-running session cannot grow the
            # model without bound.
            for stale_key in sorted(
                self._observations, key=lambda k: self._observations[k].observed_at
            )[: len(self._observations) - self.max_observations]:
                self._observations.pop(stale_key, None)
        self._emit("observation", observation.to_dict())
        return observation

    def relate(
        self,
        subject: str,
        predicate: str,
        target: str,
        *,
        inferred: bool = False,
        evidence_refs: tuple[str, ...] = (),
    ) -> Relation:
        """Add a graph edge. Inferred edges are kept distinct from observed ones."""
        if inferred and not evidence_refs:
            # An inference with no cited basis is a guess; record it as such so it
            # can never be mistaken for established structure.
            predicate = f"{predicate}(unfounded)"
        relation = Relation(subject, predicate, target, inferred=inferred, evidence_refs=tuple(evidence_refs))
        self._relations[(subject, predicate, target)] = relation
        self._emit("relation", relation.to_dict())
        return relation

    def query(self, subject: str, predicate: str, *, allow_stale: bool = False) -> dict[str, Any] | None:
        """Return the current value, or ``None`` if unknown or stale.

        ``allow_stale`` is deliberately opt-in: the default refuses to hand back a
        value that has outlived its TTL, which is what forces reinspection before
        consequential actions.
        """
        observation = self._observations.get((subject, predicate))
        if observation is None:
            return None
        payload = observation.to_dict()
        if payload["stale"] and not allow_stale:
            return None
        return payload

    def value_of(self, subject: str, predicate: str, *, allow_stale: bool = False) -> str | None:
        found = self.query(subject, predicate, allow_stale=allow_stale)
        return None if found is None else str(found["value"])

    def subjects(self) -> list[str]:
        return sorted({subject for subject, _ in self._observations})

    def requires_reinspection(self) -> list[str]:
        """Subjects whose measured values changed and must be re-examined."""
        return sorted(self._reinspect)

    def clear_reinspection(self, subject: str | None = None) -> None:
        if subject is None:
            self._reinspect.clear()
        else:
            self._reinspect.discard(subject)

    def relations_of(self, subject: str, *, include_inferred: bool = True) -> list[Relation]:
        return [
            relation
            for (edge_subject, _, _), relation in self._relations.items()
            if edge_subject == subject and (include_inferred or not relation.inferred)
        ]

    # ----------------------------------------------------------- predictions

    def predict(self, action: str, expected: dict[str, str], *, task_id: str = "") -> Prediction:
        """Register an expectation before acting, so it can be falsified."""
        if not expected:
            raise ValueError("A prediction must state at least one expected value.")
        self._sequence += 1
        prediction = Prediction(
            id=f"pred-{self._sequence:06d}",
            action=str(action),
            expected={str(k): str(v) for k, v in expected.items()},
            task_id=task_id,
        )
        self._predictions[prediction.id] = prediction
        self._emit("prediction", prediction.to_dict())
        return prediction

    def resolve_prediction(self, prediction_id: str, observed: dict[str, str]) -> Prediction:
        """Compare an expectation with what actually happened and update the model.

        ``observed`` keys are ``"subject.predicate"``. Agreement is the fraction of
        expectations that matched; contradictions are recorded individually and
        mark the subject for reinspection.
        """
        prediction = self._predictions.get(prediction_id)
        if prediction is None:
            raise KeyError(prediction_id)
        matched: list[str] = []
        contradicted: list[dict[str, Any]] = []
        for key, expected_value in prediction.expected.items():
            actual = observed.get(key)
            if actual is None:
                contradicted.append({"key": key, "expected": expected_value, "actual": None, "reason": "not_observed"})
                continue
            if str(actual) == str(expected_value):
                matched.append(key)
            else:
                contradicted.append({"key": key, "expected": expected_value, "actual": str(actual), "reason": "mismatch"})
                self._reinspect.add(self._subject_of_key(key))
        total = len(prediction.expected)
        prediction.matched = matched
        prediction.contradicted = contradicted
        prediction.agreement = round(len(matched) / total, 4) if total else None
        prediction.resolved = True
        prediction.resolved_at = _utc_now().isoformat(timespec="microseconds")
        self._emit("prediction_resolved", prediction.to_dict())
        return prediction

    def _subject_of_key(self, key: str) -> str:
        """Recover the subject from a ``"subject.predicate"`` key.

        Both halves may contain dots - subjects like ``tool:process.execute`` and
        predicates like ``data.exit_code`` - so splitting on the first dot would
        flag the wrong subject for reinspection. The key is matched against the
        subjects already observed, longest first, and only falls back to
        splitting when nothing matches.
        """
        best = ""
        for subject, _predicate in self._observations:
            if (key == subject or key.startswith(subject + ".")) and len(subject) > len(best):
                best = subject
        if best:
            return best
        return key.rsplit(".", 1)[0] if "." in key else key

    def prediction_accuracy(self) -> dict[str, Any]:
        resolved = [item for item in self._predictions.values() if item.resolved]
        if not resolved:
            return {
                "resolved": 0,
                "mean_agreement": None,
                "fully_confirmed": 0,
                "contradicted": 0,
                "status": "no_predictions_resolved",
                "note": "No prediction has been compared with an observation yet; no accuracy is claimed.",
            }
        agreements = [float(item.agreement or 0.0) for item in resolved]
        contradicted = sum(1 for item in resolved if item.contradicted)
        mean = sum(agreements) / len(agreements)
        return {
            "resolved": len(resolved),
            "mean_agreement": round(mean, 4),
            "fully_confirmed": sum(1 for value in agreements if value >= 1.0),
            "contradicted": contradicted,
            "status": "measured",
            "note": (
                f"{len(resolved)} prediction(s) compared with observations; mean agreement {mean:.0%}. "
                f"{contradicted} produced at least one contradiction."
            ),
        }

    # ------------------------------------------------------------ hypotheses

    def hypothesize(self, cause: str, effect: str, *, task_id: str = "", evidence_refs: tuple[str, ...] = ()) -> Hypothesis:
        self._sequence += 1
        hypothesis = Hypothesis(
            id=f"hyp-{self._sequence:06d}",
            cause=str(cause),
            effect=str(effect),
            task_id=task_id,
            evidence_refs=list(evidence_refs),
        )
        self._hypotheses[hypothesis.id] = hypothesis
        self.relate(cause, "hypothesized_cause_of", effect, inferred=True, evidence_refs=tuple(evidence_refs))
        return hypothesis

    def record_hypothesis_outcome(self, hypothesis_id: str, *, confirmed: bool, evidence_ref: str = "") -> Hypothesis:
        """Register one test result. A single success never proves a causal rule."""
        hypothesis = self._hypotheses.get(hypothesis_id)
        if hypothesis is None:
            raise KeyError(hypothesis_id)
        if confirmed:
            hypothesis.confirmations += 1
        else:
            hypothesis.refutations += 1
        if evidence_ref:
            hypothesis.evidence_refs.append(evidence_ref)
        if hypothesis.refutations > 0:
            hypothesis.status = "refuted"
        elif hypothesis.confirmations >= MIN_HYPOTHESIS_CONFIRMATIONS:
            hypothesis.status = "supported"
        elif hypothesis.confirmations > 0:
            hypothesis.status = "tentative"
        else:
            hypothesis.status = "untested"
        self._emit("hypothesis", hypothesis.to_dict())
        return hypothesis

    def hypotheses(self, status: str | None = None) -> list[Hypothesis]:
        return [item for item in self._hypotheses.values() if status is None or item.status == status]

    # -------------------------------------------------------------- reporting

    def snapshot(self, *, subject: str | None = None, limit: int = 60, include_stale: bool = True) -> dict[str, Any]:
        """A bounded structured view, suitable for prompting or the UI."""
        now = _utc_now()
        rows = [
            observation.to_dict(now)
            for key, observation in sorted(self._observations.items())
            if subject is None or key[0] == subject
        ]
        truncated = len(rows) > limit
        return {
            "scope": self.scope,
            "observations": rows[:limit],
            "truncated": truncated,
            "total_observations": len(rows),
            "relations": [
                relation.to_dict()
                for relation in list(self._relations.values())[:limit]
                if subject is None or relation.subject == subject
            ],
            "stale_count": sum(1 for row in rows if row["stale"]),
            "requires_reinspection": self.requires_reinspection(),
            "included_stale": include_stale,
        }

    def stats(self) -> WorldModelStats:
        now = _utc_now()
        accuracy = self.prediction_accuracy()
        resolved = [item for item in self._predictions.values() if item.resolved]
        supported = sum(1 for item in self._hypotheses.values() if item.status == "supported")
        inferred = sum(1 for item in self._relations.values() if item.inferred)
        stale = sum(1 for item in self._observations.values() if item.is_stale(now))
        if not resolved:
            note = "Environment model holds observations but no prediction has been checked yet."
        elif accuracy["mean_agreement"] is not None and float(accuracy["mean_agreement"]) >= 0.8:
            note = "Predictions largely match observations; the model is usable but not authoritative."
        else:
            note = "Predictions frequently disagree with observations; reinspect before relying on this model."
        return WorldModelStats(
            observations=len(self._observations),
            relations=len(self._relations),
            inferred_relations=inferred,
            stale_observations=stale,
            predictions_total=len(self._predictions),
            predictions_resolved=len(resolved),
            prediction_agreement=accuracy["mean_agreement"],
            contradictions=accuracy["contradicted"],
            hypotheses_supported=supported,
            note=note,
        )

    def history(self, subject: str, predicate: str, limit: int = 20) -> list[Observation]:
        rows = [item for item in self._history if item.subject == subject and item.predicate == predicate]
        return rows[-limit:]

    def _emit(self, kind: str, payload: dict[str, Any]) -> None:
        if self._persist is None:
            return
        try:
            self._persist(kind, payload)
        except Exception:
            # A failed audit write must not abort the task; the in-memory model
            # stays authoritative for this run.
            pass
