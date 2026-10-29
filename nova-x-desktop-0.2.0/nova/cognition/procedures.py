"""Procedures, transfer and continual learning (§71, §77).

A *procedure* is a workflow NOVA derived from something it actually did, stored
with the evidence that produced it. This is how knowledge moves between tasks:
retrieve a procedure, check whether its recorded environment still matches the
new one, and re-verify the parts that cannot be assumed to carry over.

Three rules are enforced in code because they are the ones that are easy to get
wrong:

* **A single success proves nothing.** A procedure created from one good run is
  a ``candidate``. It becomes ``established`` only after enough attempts with a
  good enough success ratio, and the thresholds are constants, not vibes.
* **Knowledge can be corrected, superseded or removed.** ``correct`` and
  ``remove`` record who said so and why, with provenance, instead of silently
  overwriting history.
* **Continual learning must not forget.** Pruning removes *unreliable candidates*
  only. Established procedures survive a prune, so accumulating new experience
  does not erase what already works.

This is deliberately not a fixed template library: procedures are created from
observed runs and retrieved by similarity to the current objective, so novel
tasks accumulate their own entries rather than being forced onto predefined ones.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from .epistemic import PROVENANCES, Provenance

ProcedureStatus = Literal["candidate", "established", "deprecated", "superseded", "removed"]
TransferVerdictKind = Literal["compatible", "partially_compatible", "incompatible", "unknown"]

MIN_ATTEMPTS_TO_ESTABLISH = 3
MIN_SUCCESSES_TO_ESTABLISH = 2
MIN_SUCCESS_RATIO = 0.6
MIN_ATTEMPTS_FOR_RELIABILITY = 3
MAX_STEPS = 24
_TOKEN_RE = re.compile(r"[a-z0-9_][a-z0-9_.+-]*")
_STOPWORD_TEXT = (
    "a an and are as at be but by for from has have how i if in into is it its of on or that the their then "
    "this to we what when which will with you your nova task please can should would"
)
_STOPWORDS = frozenset(_STOPWORD_TEXT.split())


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _tokens(text: str) -> set[str]:
    return {token for token in _TOKEN_RE.findall(str(text).lower()) if token not in _STOPWORDS and len(token) > 1}


def _similarity(a: str, b: str) -> float:
    left, right = _tokens(a), _tokens(b)
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


@dataclass
class Procedure:
    """A reusable workflow with its evidence, reliability and lineage."""

    id: str
    name: str
    domain: str
    summary: str
    steps: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)
    tools_required: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    source_task_ids: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    provenance: Provenance = "tool_result"
    status: ProcedureStatus = "candidate"
    version: int = 1
    attempts: int = 0
    successes: int = 0
    supersedes: str | None = None
    superseded_by: str | None = None
    correction_reason: str = ""
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        if not str(self.id).strip():
            raise ValueError("Procedure.id is required")
        if self.provenance not in PROVENANCES:
            raise ValueError(f"provenance must be one of {sorted(PROVENANCES)}")
        if len(self.steps) > MAX_STEPS:
            raise ValueError(f"at most {MAX_STEPS} steps are stored per procedure")

    @property
    def success_ratio(self) -> float:
        return (self.successes / self.attempts) if self.attempts else 0.0

    @property
    def reliability_known(self) -> bool:
        """False until enough attempts exist to say anything about reliability."""
        return self.attempts >= MIN_ATTEMPTS_FOR_RELIABILITY

    @property
    def reliability(self) -> float:
        if not self.reliability_known:
            return 0.0
        return round(self.success_ratio, 4)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "domain": self.domain,
            "summary": self.summary,
            "steps": list(self.steps),
            "preconditions": list(self.preconditions),
            "environment": dict(self.environment),
            "tools_required": list(self.tools_required),
            "tags": list(self.tags),
            "source_task_ids": list(self.source_task_ids),
            "evidence_refs": list(self.evidence_refs),
            "provenance": self.provenance,
            "status": self.status,
            "version": self.version,
            "attempts": self.attempts,
            "successes": self.successes,
            "success_ratio": round(self.success_ratio, 4),
            "reliability": self.reliability,
            "reliability_known": self.reliability_known,
            "supersedes": self.supersedes,
            "superseded_by": self.superseded_by,
            "correction_reason": self.correction_reason,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class TransferCheck:
    """Whether a procedure's recorded environment matches the new one."""

    procedure_id: str
    procedure_version: int
    target_domain: str
    verdict: TransferVerdictKind
    shared_markers: list[str]
    missing_markers: list[str]
    tool_gaps: list[str]
    required_adaptations: list[str]
    reverify: list[str]
    confidence: float
    notes: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "procedure_id": self.procedure_id,
            "procedure_version": self.procedure_version,
            "target_domain": self.target_domain,
            "verdict": self.verdict,
            "shared_markers": list(self.shared_markers),
            "missing_markers": list(self.missing_markers),
            "tool_gaps": list(self.tool_gaps),
            "required_adaptations": list(self.required_adaptations),
            "reverify": list(self.reverify),
            "confidence": round(float(self.confidence), 4),
            "notes": self.notes,
        }


def transfer_check(
    procedure: Procedure,
    *,
    target_domain: str = "",
    target_environment: dict[str, str] | None = None,
    available_tools: set[str] | None = None,
) -> TransferCheck:
    """Compare a stored procedure against a new context and say what must change.

    Compatibility is asserted only about *markers that can be compared*. Anything
    unverifiable lands in ``reverify`` rather than being assumed to carry over -
    a procedure that worked once on one project is not evidence it works here.
    """
    target_env = {str(key).lower(): str(value) for key, value in (target_environment or {}).items()}
    source_env = {str(key).lower(): str(value) for key, value in (procedure.environment or {}).items()}
    tools = set(available_tools or set())

    shared: list[str] = []
    missing: list[str] = []
    adaptations: list[str] = []
    for key, value in source_env.items():
        if key not in target_env:
            missing.append(f"{key} (was '{value}'; unknown in target)")
            continue
        if target_env[key].lower() == value.lower():
            shared.append(f"{key}={value}")
        else:
            missing.append(f"{key} changed: '{value}' -> '{target_env[key]}'")
            adaptations.append(f"Adapt every step that depends on {key}={value} to {key}={target_env[key]}.")

    tool_gaps = [tool for tool in procedure.tools_required if tools and tool not in tools]
    if tool_gaps:
        adaptations.append(
            "Substitute or install the missing tool(s): " + ", ".join(tool_gaps) + ". Do not fake their output."
        )

    domain_changed = bool(target_domain) and target_domain.lower() != str(procedure.domain).lower()
    if domain_changed:
        adaptations.append(
            f"Domain changed from '{procedure.domain}' to '{target_domain}'; re-check that the objective's "
            "constraints are the same shape, not merely similar words."
        )

    reverify: list[str] = list(procedure.preconditions)[:6]
    if not procedure.reliability_known:
        reverify.append(
            f"Only {procedure.attempts} attempt(s) recorded; reliability is unknown, so verify the first result explicitly."
        )
    reverify.append("Confirm the acceptance criteria of the new task, which are not inherited from the old one.")

    if tool_gaps or any("changed" in item for item in missing):
        verdict: TransferVerdictKind = "partially_compatible" if shared else "incompatible"
    elif missing and not shared:
        verdict = "unknown"
    elif missing:
        verdict = "partially_compatible"
    else:
        verdict = "compatible"

    comparable = len(shared) + len(missing)
    confidence = 0.0
    if not comparable and not tool_gaps:
        # Nothing could be compared, so nothing can be claimed. Reporting
        # 'compatible' here would be exactly the overclaim this check exists to
        # prevent.
        return TransferCheck(
            procedure_id=procedure.id,
            procedure_version=procedure.version,
            target_domain=target_domain or procedure.domain,
            verdict="unknown",
            shared_markers=[],
            missing_markers=[],
            tool_gaps=[],
            required_adaptations=adaptations[:8],
            reverify=reverify[:8],
            confidence=0.0,
            notes="No comparable environment markers were recorded, so compatibility cannot be assessed.",
        )
    if comparable:
        confidence = 0.35 + 0.45 * (len(shared) / comparable)
    if procedure.status == "established":
        confidence += 0.15
    elif procedure.status in {"deprecated", "superseded", "removed"}:
        confidence -= 0.30
    if tool_gaps:
        confidence -= 0.15
    confidence = round(max(0.0, min(0.95, confidence)), 4)

    notes = (
        f"{len(shared)}/{comparable} environment marker(s) match; {len(tool_gaps)} tool gap(s); "
        f"{len(adaptations)} adaptation(s) required."
        if comparable or tool_gaps
        else "No comparable environment markers were recorded, so compatibility cannot be assessed."
    )

    return TransferCheck(
        procedure_id=procedure.id,
        procedure_version=procedure.version,
        target_domain=target_domain or procedure.domain,
        verdict=verdict,
        shared_markers=shared,
        missing_markers=missing,
        tool_gaps=tool_gaps,
        required_adaptations=adaptations[:8],
        reverify=reverify[:8],
        confidence=confidence,
        notes=notes,
    )


@dataclass(frozen=True)
class RetrievalHit:
    procedure: Procedure
    score: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.procedure.id,
            "name": self.procedure.name,
            "domain": self.procedure.domain,
            "status": self.procedure.status,
            "version": self.procedure.version,
            "score": round(self.score, 4),
            "reason": self.reason,
            "reliability": self.procedure.reliability,
            "reliability_known": self.procedure.reliability_known,
            "attempts": self.procedure.attempts,
            "steps": list(self.procedure.steps),
        }


def _status_after_outcome(procedure: Procedure) -> tuple[ProcedureStatus, str]:
    """Threshold-driven promotion or demotion. No single run can establish anything."""
    candidate_ready = procedure.status == "candidate" and procedure.attempts >= MIN_ATTEMPTS_TO_ESTABLISH
    if (
        candidate_ready
        and procedure.successes >= MIN_SUCCESSES_TO_ESTABLISH
        and procedure.success_ratio >= MIN_SUCCESS_RATIO
    ):
        return "established", ""
    if candidate_ready and procedure.success_ratio < MIN_SUCCESS_RATIO:
        return (
            "deprecated",
            f"Deprecated after {procedure.attempts} attempts with a {procedure.success_ratio:.0%} success ratio.",
        )
    # An established procedure is held to the same bar that established it.
    # Demoting only at half that ratio would keep recommending a workflow that
    # fails two times out of three.
    if (
        procedure.status == "established"
        and procedure.attempts >= MIN_ATTEMPTS_FOR_RELIABILITY
        and procedure.success_ratio < MIN_SUCCESS_RATIO
    ):
        return (
            "deprecated",
            f"An established procedure degraded to a {procedure.success_ratio:.0%} success ratio; "
            "the environment or the procedure changed.",
        )
    return procedure.status, ""


class ProcedureLibrary:
    """Versioned store of learned procedures with reliability tracking."""

    def __init__(self) -> None:
        self._procedures: dict[str, Procedure] = {}
        self._history: list[dict[str, Any]] = []

    def __len__(self) -> int:
        return len(self._procedures)

    def get(self, procedure_id: str) -> Procedure | None:
        return self._procedures.get(procedure_id)

    def all(self) -> list[Procedure]:
        return sorted(self._procedures.values(), key=lambda item: (-item.successes, item.updated_at, item.id))

    def add(
        self,
        *,
        procedure_id: str,
        name: str,
        domain: str,
        summary: str,
        steps: Iterable[str],
        preconditions: Iterable[str] = (),
        environment: dict[str, str] | None = None,
        tools_required: Iterable[str] = (),
        tags: Iterable[str] = (),
        source_task_ids: Iterable[str] = (),
        evidence_refs: Iterable[str] = (),
        provenance: Provenance = "tool_result",
        supersedes: str | None = None,
    ) -> Procedure:
        """Insert a new procedure. It always starts as a ``candidate``."""
        procedure = Procedure(
            id=str(procedure_id),
            name=str(name)[:200],
            domain=str(domain)[:80],
            summary=str(summary)[:600],
            steps=[str(step)[:400] for step in steps][:MAX_STEPS],
            preconditions=[str(item)[:300] for item in preconditions][:12],
            environment={str(k).lower(): str(v)[:120] for k, v in (environment or {}).items()},
            tools_required=[str(tool) for tool in tools_required][:12],
            tags=[str(tag)[:40] for tag in tags][:12],
            source_task_ids=[str(item) for item in source_task_ids][:20],
            evidence_refs=[str(item) for item in evidence_refs][:20],
            provenance=provenance,
            status="candidate",
            supersedes=supersedes,
        )
        self._procedures[procedure.id] = procedure
        if supersedes and supersedes in self._procedures:
            previous = self._procedures[supersedes]
            previous.superseded_by = procedure.id
            if previous.status not in {"deprecated", "removed"}:
                previous.status = "superseded"
            previous.updated_at = _utc_now()
        self._record("added", procedure.id, f"candidate procedure '{procedure.name}' (v{procedure.version})")
        return procedure

    def record_outcome(self, procedure_id: str, *, success: bool, evidence_ref: str = "", task_id: str = "") -> Procedure | None:
        """Record one real use. Status promotion is threshold-driven."""
        procedure = self._procedures.get(procedure_id)
        if procedure is None or procedure.status == "removed":
            return None
        procedure.attempts += 1
        if success:
            procedure.successes += 1
        if evidence_ref:
            procedure.evidence_refs.append(str(evidence_ref)[:200])
            procedure.evidence_refs = procedure.evidence_refs[-20:]
        if task_id and task_id not in procedure.source_task_ids:
            procedure.source_task_ids.append(str(task_id))
            procedure.source_task_ids = procedure.source_task_ids[-20:]

        previous = procedure.status
        procedure.status, reason = _status_after_outcome(procedure)
        if reason:
            procedure.correction_reason = reason
        procedure.updated_at = _utc_now()
        if procedure.status != previous:
            self._record(
                "status_change",
                procedure.id,
                f"{previous} -> {procedure.status} after {procedure.attempts} attempt(s), {procedure.successes} success(es)",
            )
        else:
            self._record(
                "outcome",
                procedure.id,
                f"{'success' if success else 'failure'} (attempts={procedure.attempts}, ratio={procedure.success_ratio:.2f})",
            )
        return procedure

    def correct(self, procedure_id: str, *, reason: str, provenance: Provenance = "user", replacement_id: str | None = None) -> bool:
        """Mark stored knowledge wrong or outdated. The reason and source are kept."""
        procedure = self._procedures.get(procedure_id)
        if procedure is None:
            return False
        if provenance not in PROVENANCES:
            raise ValueError(f"provenance must be one of {sorted(PROVENANCES)}")
        procedure.correction_reason = str(reason)[:500]
        procedure.provenance = provenance
        procedure.status = "superseded" if replacement_id else "deprecated"
        if replacement_id:
            procedure.superseded_by = str(replacement_id)
        procedure.updated_at = _utc_now()
        self._record("corrected", procedure.id, f"{procedure.status}: {procedure.correction_reason} [provenance={provenance}]")
        return True

    def remove(self, procedure_id: str, *, reason: str = "") -> bool:
        """Delete stored knowledge. Removal is itself recorded in history."""
        procedure = self._procedures.pop(procedure_id, None)
        if procedure is None:
            return False
        self._record("removed", procedure_id, str(reason)[:300] or "no reason given")
        return True

    def retrieve(
        self,
        objective: str,
        *,
        domain: str = "",
        limit: int = 5,
        include_deprecated: bool = False,
        available_tools: set[str] | None = None,
    ) -> list[RetrievalHit]:
        """Similarity retrieval, deterministic and free of provider calls.

        Score = text similarity + domain match + reliability, with unusable
        procedures penalised. Established knowledge outranks a candidate that
        merely shares more words with the objective.
        """
        tools = set(available_tools or set())
        hits: list[RetrievalHit] = []
        for procedure in self._procedures.values():
            if procedure.status == "removed":
                continue
            if procedure.status in {"deprecated", "superseded"} and not include_deprecated:
                continue
            haystack = " ".join(
                [procedure.name, procedure.summary, procedure.domain, *procedure.tags, *procedure.steps]
            )
            score = _similarity(objective, haystack)
            reasons: list[str] = []
            if domain and procedure.domain.lower() == domain.lower():
                score += 0.25
                reasons.append(f"domain '{domain}' matches")
            if procedure.status == "established":
                # Demonstrated reliability outweighs a modest wording advantage: a
                # procedure proven to work is worth more than an untried one that
                # merely echoes the objective's vocabulary.
                score += 0.30 + 0.25 * procedure.reliability
                reasons.append(
                    f"established with {procedure.success_ratio:.0%} success over {procedure.attempts} attempt(s)"
                )
            elif procedure.reliability_known:
                score += 0.10 * procedure.reliability
                reasons.append(f"{procedure.attempts} attempt(s), {procedure.success_ratio:.0%} success")
            else:
                score -= 0.05
                reasons.append(f"candidate with only {procedure.attempts} attempt(s); reliability unknown")
            if tools and procedure.tools_required:
                gaps = [tool for tool in procedure.tools_required if tool not in tools]
                if gaps:
                    score -= 0.15 * len(gaps)
                    reasons.append("missing tool(s): " + ", ".join(gaps))
            if score <= 0.0:
                continue
            hits.append(RetrievalHit(procedure=procedure, score=round(min(1.5, score), 4), reason="; ".join(reasons)))
        hits.sort(key=lambda hit: (-hit.score, hit.procedure.id))
        return hits[: max(1, int(limit))]

    def prune_unreliable(self, *, min_attempts: int = MIN_ATTEMPTS_FOR_RELIABILITY, max_success_ratio: float = 0.34) -> list[str]:
        """Forget *bad* candidates without forgetting what works.

        Only non-established procedures with enough attempts and a poor ratio are
        removed. Established procedures are never pruned here, which is what keeps
        continual learning from degrading into catastrophic forgetting.
        """
        removed: list[str] = []
        for procedure_id, procedure in list(self._procedures.items()):
            if procedure.status == "established":
                continue
            if procedure.attempts < min_attempts:
                continue
            if procedure.success_ratio > max_success_ratio:
                continue
            self._procedures.pop(procedure_id, None)
            removed.append(procedure_id)
            self._record(
                "pruned",
                procedure_id,
                f"unreliable candidate: {procedure.attempts} attempts, {procedure.success_ratio:.0%} success",
            )
        return removed

    def export_state(self) -> dict[str, Any]:
        return {
            "procedures": [procedure.to_dict() for procedure in self.all()],
            "counts": {
                "total": len(self._procedures),
                "established": sum(1 for item in self._procedures.values() if item.status == "established"),
                "candidate": sum(1 for item in self._procedures.values() if item.status == "candidate"),
                "deprecated": sum(1 for item in self._procedures.values() if item.status == "deprecated"),
                "superseded": sum(1 for item in self._procedures.values() if item.status == "superseded"),
            },
            "thresholds": {
                "min_attempts_to_establish": MIN_ATTEMPTS_TO_ESTABLISH,
                "min_successes_to_establish": MIN_SUCCESSES_TO_ESTABLISH,
                "min_success_ratio": MIN_SUCCESS_RATIO,
                "min_attempts_for_reliability": MIN_ATTEMPTS_FOR_RELIABILITY,
            },
            "history": list(self._history[-100:]),
        }

    def import_state(self, payload: dict[str, Any]) -> int:
        """Restore procedures from persisted state (crash/restart continuity)."""
        imported = 0
        for raw in payload.get("procedures") or []:
            if not isinstance(raw, dict):
                continue
            procedure_id = str(raw.get("id") or "").strip()
            if not procedure_id:
                continue
            # Sanitise before constructing: persisted state may predate a schema
            # change or be hand-edited, and hydration must not raise on it.
            provenance = str(raw.get("provenance") or "tool_result")
            if provenance not in PROVENANCES:
                provenance = "model_generated"
            status = str(raw.get("status") or "candidate")
            if status not in {"candidate", "established", "deprecated", "superseded", "removed"}:
                status = "candidate"
            procedure = Procedure(
                id=procedure_id,
                name=str(raw.get("name") or procedure_id)[:200],
                domain=str(raw.get("domain") or "")[:80],
                summary=str(raw.get("summary") or "")[:600],
                steps=[str(step)[:400] for step in (raw.get("steps") or [])][:MAX_STEPS],
                preconditions=[str(item)[:300] for item in (raw.get("preconditions") or [])][:12],
                environment={str(k).lower(): str(v)[:120] for k, v in (raw.get("environment") or {}).items()},
                tools_required=[str(tool) for tool in (raw.get("tools_required") or [])][:12],
                tags=[str(tag)[:40] for tag in (raw.get("tags") or [])][:12],
                source_task_ids=[str(item) for item in (raw.get("source_task_ids") or [])][:20],
                evidence_refs=[str(item) for item in (raw.get("evidence_refs") or [])][:20],
                provenance=provenance,  # type: ignore[arg-type]
                status=status,  # type: ignore[arg-type]
                version=int(raw.get("version") or 1),
                attempts=int(raw.get("attempts") or 0),
                successes=int(raw.get("successes") or 0),
                supersedes=raw.get("supersedes"),
                superseded_by=raw.get("superseded_by"),
                correction_reason=str(raw.get("correction_reason") or "")[:500],
                created_at=str(raw.get("created_at") or _utc_now()),
                updated_at=str(raw.get("updated_at") or _utc_now()),
            )
            self._procedures[procedure.id] = procedure
            imported += 1
        return imported

    def history(self, limit: int = 50) -> list[dict[str, Any]]:
        return list(self._history[-max(1, int(limit)) :])

    def _record(self, event: str, procedure_id: str, detail: str) -> None:
        self._history.append(
            {"event": event, "procedure_id": procedure_id, "detail": detail[:300], "recorded_at": _utc_now()}
        )
        if len(self._history) > 400:
            del self._history[:200]
