"""Multi-agent coordination (§85) and the evidence gate that backs it (§83).

Roles here are **derived from the objective**, not drawn from a fixed cast of
named personalities. Each role carries a checkable job description and an output
contract; if a role cannot produce something checkable it is not added. The role
identifiers deliberately match the ones ``IntelligenceOrchestrator`` already
emits (``independent_analysis``, ``conflict_review``, ``synthesis``,
``targeted_critique``, ``revision``) so a coordination plan can drive the
existing fusion pipeline instead of running beside it.

The load-bearing rule is in ``reconcile``: agreement between models is *not*
evidence. A unanimous answer with no independent evidence ref is reported as an
unverified consensus with capped confidence, never as a confirmed result.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from .epistemic import OBSERVATIONAL_PROVENANCE, Provenance

SufficiencyVerdict = Literal["sufficient", "partially_sufficient", "insufficient"]
ConsensusStatus = Literal["confirmed", "unverified_consensus", "contested", "no_overlap", "failed"]

_NEGATION = re.compile(r"\b(not|no|never|cannot|can't|won't|doesn't|isn't|arent|aren't|fails|failed|absent|missing|impossible|unsupported|unavailable)\b")
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")
_WORD = re.compile(r"[a-z][a-z0-9_]{2,}")
_STOPWORD_TEXT = (
    "the and for with that this from have has are was were will would should could not but its their there "
    "they them you your nova task please answer result results value values using used use"
)
_STOPWORDS = frozenset(_STOPWORD_TEXT.split())

# Objective wording that already poses a choice. Such an objective warrants an
# extra independent pass, because the disagreement is in the question itself.
_CONTESTED_OBJECTIVE = re.compile(
    r"\b(compare|alternative|alternatives|option|options|trade-?offs?|versus|vs|which|whether|best|should we)\b"
)
SUBJECT_OVERLAP_THRESHOLD = 0.34


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _subject_tokens(text: str) -> set[str]:
    return {word for word in _WORD.findall(str(text).lower()) if word not in _STOPWORDS}


def _numbers(text: str) -> set[str]:
    return set(_NUMBER.findall(str(text)))


def _is_negated(text: str) -> bool:
    return bool(_NEGATION.search(str(text).lower()))


@dataclass(frozen=True)
class RoleAssignment:
    """A role with an actual job. ``output_contract`` is what makes it checkable."""

    role: str
    provider_role: str
    function: str
    derived_from: str
    output_contract: str
    independent: bool
    requires_tool: str
    model_capable_only: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "provider_role": self.provider_role,
            "function": self.function,
            "derived_from": self.derived_from,
            "output_contract": self.output_contract,
            "independent": self.independent,
            "requires_tool": self.requires_tool,
            "model_capable_only": self.model_capable_only,
        }


@dataclass(frozen=True)
class Subtask:
    """One decomposed unit of work, assigned by capability rather than by name."""

    id: str
    description: str
    required_capability: str
    assigned_role: str
    assignable: bool
    blocking_reason: str
    depends_on: tuple[str, ...] = ()
    acceptance: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "required_capability": self.required_capability,
            "assigned_role": self.assigned_role,
            "assignable": self.assignable,
            "blocking_reason": self.blocking_reason,
            "depends_on": list(self.depends_on),
            "acceptance": self.acceptance,
        }


@dataclass(frozen=True)
class CoordinationPlan:
    objective: str
    subtasks: list[Subtask]
    roles: list[RoleAssignment]
    unassignable: list[Subtask]
    provider_requests_estimate: int
    rationale: str
    created_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "subtasks": [item.to_dict() for item in self.subtasks],
            "roles": [item.to_dict() for item in self.roles],
            "unassignable": [item.to_dict() for item in self.unassignable],
            "provider_requests_estimate": self.provider_requests_estimate,
            "rationale": self.rationale,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class AgentOutput:
    """What one participant actually produced, with its evidence attached."""

    role: str
    model_id: str
    status: str
    statements: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    provenance: Provenance = "model_generated"
    error: str = ""

    @property
    def succeeded(self) -> bool:
        return self.status == "ok" and bool(self.statements)

    @property
    def independent_evidence(self) -> list[str]:
        return [ref for ref in self.evidence_refs if str(ref).strip()] if self.provenance in OBSERVATIONAL_PROVENANCE else []


@dataclass(frozen=True)
class Contradiction:
    left_role: str
    right_role: str
    left_statement: str
    right_statement: str
    kind: str
    shared_subject: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "left_role": self.left_role,
            "right_role": self.right_role,
            "left_statement": self.left_statement[:300],
            "right_statement": self.right_statement[:300],
            "kind": self.kind,
            "shared_subject": list(self.shared_subject[:10]),
        }


@dataclass(frozen=True)
class Reconciliation:
    participants: int
    succeeded: int
    failed_roles: list[str]
    agreements: list[str]
    contradictions: list[Contradiction]
    sufficiency: SufficiencyVerdict
    missing_evidence: list[str]
    consensus_status: ConsensusStatus
    consensus_statement: str
    consensus_provenance: Provenance
    confidence: float
    warnings: list[str]
    next_action: str
    created_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "participants": self.participants,
            "succeeded": self.succeeded,
            "failed_roles": list(self.failed_roles),
            "agreements": list(self.agreements),
            "contradictions": [item.to_dict() for item in self.contradictions],
            "sufficiency": self.sufficiency,
            "missing_evidence": list(self.missing_evidence),
            "consensus_status": self.consensus_status,
            "consensus_statement": self.consensus_statement,
            "consensus_provenance": self.consensus_provenance,
            "confidence": round(float(self.confidence), 4),
            "warnings": list(self.warnings),
            "next_action": self.next_action,
            "created_at": self.created_at,
        }


_CAPABILITY_ROLES: dict[str, RoleAssignment] = {
    "decomposition": RoleAssignment(
        role="decomposition",
        provider_role="independent_analysis",
        function="Split the objective into units of work that can each be checked on their own.",
        derived_from="objective has multiple distinct deliverables",
        output_contract="A list of subtasks, each naming the capability it needs and how its result is verified.",
        independent=False,
        requires_tool="",
    ),
    "independent_analysis": RoleAssignment(
        role="independent_analysis",
        provider_role="independent_analysis",
        function="Analyse the problem without seeing any other participant's answer.",
        derived_from="default for any objective with a non-trivial answer",
        output_contract="A conclusion plus the specific evidence refs it rests on; 'unknown' where evidence is absent.",
        independent=True,
        requires_tool="",
    ),
    "contradiction_check": RoleAssignment(
        role="contradiction_check",
        provider_role="conflict_review",
        function="Compare the independent outputs and name the specific disagreements.",
        derived_from="two or more independent analyses exist",
        output_contract="For each disagreement: both statements, the shared subject, and which evidence would settle it.",
        independent=False,
        requires_tool="",
    ),
    "evidence_sufficiency": RoleAssignment(
        role="evidence_sufficiency",
        provider_role="conflict_review",
        function="Decide whether the evidence is enough to act, independent of how many participants agree.",
        derived_from="always - agreement alone must never be treated as proof",
        output_contract="'sufficient', 'partially_sufficient' or 'insufficient' plus the exact evidence still missing.",
        independent=False,
        requires_tool="",
    ),
    "tool_verification": RoleAssignment(
        role="tool_verification",
        provider_role="independent_analysis",
        function="Produce an observation with an authorized tool rather than reasoning about one.",
        derived_from="the objective's acceptance criterion is checkable by execution",
        output_contract="A recorded tool result with its command, status and output, or an explicit statement that no tool could run.",
        independent=True,
        requires_tool="process.execute",
    ),
    "synthesis": RoleAssignment(
        role="synthesis",
        provider_role="synthesis",
        function="Integrate the surviving outputs into one answer that keeps the uncertainty visible.",
        derived_from="more than one input needs integrating",
        output_contract="One answer stating what is established, what is contested, and what remains unverified.",
        independent=False,
        requires_tool="",
    ),
    "targeted_critique": RoleAssignment(
        role="targeted_critique",
        provider_role="targeted_critique",
        function="Attack the synthesized draft at the specific points the contradiction check flagged.",
        derived_from="contradictions or insufficiency survived into synthesis",
        output_contract="Concrete defects with the evidence that would confirm or refute each one.",
        independent=False,
        requires_tool="",
    ),
    "revision": RoleAssignment(
        role="revision",
        provider_role="revision",
        function="Produce the final answer after critique, without discarding unresolved disagreement.",
        derived_from="a critique pass ran",
        output_contract="A revised answer that addresses each critique point or states why it was rejected.",
        independent=False,
        requires_tool="",
    ),
    "clarification": RoleAssignment(
        role="clarification",
        provider_role="independent_analysis",
        function="Turn an unresolvable ambiguity into a specific question for the user.",
        derived_from="objective has no checkable success criterion",
        output_contract="One or more closed questions whose answers would make the objective checkable.",
        independent=False,
        requires_tool="",
    ),
}

_SUBTASK_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (r"\b(diagnos|debug|trace|investigate|why|root cause)\b", "observation of current system state", "tool_verification"),
    (r"\b(test|verify|confirm|prove|check)\b", "execution of a check whose result is recorded", "tool_verification"),
    (r"\b(compare|alternativ|option|trade-?off|versus|vs\b|choose)\b", "independent evaluation of competing options", "independent_analysis"),
    (r"\b(research|document|specification|standard|reference)\b", "retrieval of external documentation", "independent_analysis"),
    (r"\b(fix|implement|write|create|build|refactor|patch)\b", "production of a change that must then be verified", "independent_analysis"),
    (r"\b(summar|report|explain|describe)\b", "integration of findings into a stated result", "synthesis"),
)


def derive_roles(
    objective: str,
    *,
    plan_steps: list[str] | None = None,
    available_tools: set[str] | None = None,
    subtask_descriptions: list[str] | None = None,
    acceptance_criteria: list[str] | None = None,
    max_independent_analyses: int = 3,
    provider_requests_remaining: int = 12,
) -> CoordinationPlan:
    """Build a coordination plan whose roles follow from the objective's features."""
    tools = set(available_tools or set())
    text = " ".join([objective, *(plan_steps or []), *(subtask_descriptions or [])]).lower()
    criteria = list(acceptance_criteria or [])

    subtasks: list[Subtask] = []
    descriptions = [item for item in (subtask_descriptions or []) if str(item).strip()][:12]
    if not descriptions:
        descriptions = [str(step) for step in (plan_steps or []) if str(step).strip()][:12]
    if not descriptions:
        descriptions = [objective]

    for index, description in enumerate(descriptions, start=1):
        lowered = str(description).lower()
        capability = "reasoning over the stated objective"
        role = "independent_analysis"
        for pattern, cap, assigned in _SUBTASK_PATTERNS:
            if re.search(pattern, lowered):
                capability, role = cap, assigned
                break
        blocking = ""
        assignable = True
        if role == "tool_verification" and not tools:
            assignable = False
            blocking = "No tool is registered, so this cannot be verified by execution; it would be an unverified claim."
        elif role == "tool_verification" and "process.execute" not in tools:
            assignable = False
            blocking = "'process.execute' is not available; the check cannot be run."
        subtasks.append(
            Subtask(
                id=f"st-{index}",
                description=str(description)[:300],
                required_capability=capability,
                assigned_role=role if assignable else "clarification",
                assignable=assignable,
                blocking_reason=blocking,
                depends_on=(),
                acceptance=(criteria[index - 1] if index <= len(criteria) else "A recorded result exists for this subtask."),
            )
        )

    roles: list[RoleAssignment] = []
    used = {item.assigned_role for item in subtasks}
    analyses_needed = min(max_independent_analyses, max(2, len([item for item in subtasks if item.assignable])))
    contested = bool(_CONTESTED_OBJECTIVE.search(text))
    if contested:
        analyses_needed = min(max_independent_analyses, analyses_needed + 1)
    if provider_requests_remaining < 4:
        analyses_needed = 1

    if len(subtasks) > 1:
        roles.append(_CAPABILITY_ROLES["decomposition"])
    for _ in range(analyses_needed):
        if _CAPABILITY_ROLES["independent_analysis"] not in roles:
            roles.append(_CAPABILITY_ROLES["independent_analysis"])
        else:
            # Additional independent passes are the same role run again, not a
            # new persona. Only one entry is kept; the count is carried separately.
            break
    if "tool_verification" in used:
        roles.append(_CAPABILITY_ROLES["tool_verification"])
    if analyses_needed >= 2:
        roles.append(_CAPABILITY_ROLES["contradiction_check"])
    roles.append(_CAPABILITY_ROLES["evidence_sufficiency"])
    if analyses_needed >= 2 or "synthesis" in used:
        roles.append(_CAPABILITY_ROLES["synthesis"])
    if not criteria or any("checkable success criterion" in item for item in criteria):
        roles.append(_CAPABILITY_ROLES["clarification"])
    if provider_requests_remaining >= 8 and analyses_needed >= 2:
        roles.append(_CAPABILITY_ROLES["targeted_critique"])
        roles.append(_CAPABILITY_ROLES["revision"])

    unassignable = [item for item in subtasks if not item.assignable]
    estimate = sum(1 for role in roles if role.provider_role) + max(0, analyses_needed - 1)
    estimate = min(estimate, max(0, provider_requests_remaining))

    rationale_parts = [
        f"{len(subtasks)} subtask(s) decomposed from the objective; {len(roles)} role(s) derived.",
        f"{analyses_needed} independent analysis pass(es) planned"
        + (" because the objective itself poses a choice." if contested else "."),
    ]
    if unassignable:
        rationale_parts.append(
            f"{len(unassignable)} subtask(s) cannot be assigned with the current tools and are routed to clarification "
            "rather than answered from model text."
        )
    if provider_requests_remaining < 4:
        rationale_parts.append(
            f"Only {provider_requests_remaining} provider request(s) remain, so multi-pass coordination was reduced."
        )
    rationale_parts.append("Agreement between roles is treated as a signal only; evidence_sufficiency gates the result.")

    return CoordinationPlan(
        objective=str(objective)[:500],
        subtasks=subtasks,
        roles=roles,
        unassignable=unassignable,
        provider_requests_estimate=estimate,
        rationale=" ".join(rationale_parts),
    )


def detect_contradictions(outputs: list[AgentOutput]) -> list[Contradiction]:
    """Find pairs of statements that cannot both be true.

    Two statements contradict when they share enough subject matter and either
    disagree in polarity (one negates what the other asserts) or attach different
    numeric values to that shared subject. Everything else is left alone - this
    is not a general semantic reasoner and does not pretend to be.
    """
    found: list[Contradiction] = []
    successful = [item for item in outputs if item.succeeded]
    for i, left in enumerate(successful):
        for right in successful[i + 1 :]:
            if left.role == right.role and left.model_id == right.model_id:
                continue
            for left_statement in left.statements[:8]:
                left_subject = _subject_tokens(left_statement)
                left_numbers = _numbers(left_statement)
                if not left_subject:
                    continue
                for right_statement in right.statements[:8]:
                    right_subject = _subject_tokens(right_statement)
                    if not right_subject:
                        continue
                    overlap = left_subject & right_subject
                    union = left_subject | right_subject
                    if not union or len(overlap) / len(union) < SUBJECT_OVERLAP_THRESHOLD:
                        continue
                    right_numbers = _numbers(right_statement)
                    polarity_conflict = _is_negated(left_statement) != _is_negated(right_statement)
                    numeric_conflict = bool(left_numbers and right_numbers and left_numbers != right_numbers)
                    if not (polarity_conflict or numeric_conflict):
                        continue
                    kind = "polarity" if polarity_conflict and not numeric_conflict else (
                        "numeric" if numeric_conflict and not polarity_conflict else "polarity_and_numeric"
                    )
                    found.append(
                        Contradiction(
                            left_role=left.role,
                            right_role=right.role,
                            left_statement=str(left_statement)[:300],
                            right_statement=str(right_statement)[:300],
                            kind=kind,
                            shared_subject=sorted(overlap),
                        )
                    )
                    break
    return found[:20]


def find_agreements(outputs: list[AgentOutput]) -> list[str]:
    """Statements that two or more successful participants independently share."""
    successful = [item for item in outputs if item.succeeded]
    agreements: list[str] = []
    for index, left in enumerate(successful):
        for right in successful[index + 1 :]:
            for statement in left.statements[:8]:
                left_subject = _subject_tokens(statement)
                if not left_subject:
                    continue
                for other in right.statements[:8]:
                    other_subject = _subject_tokens(other)
                    if not other_subject:
                        continue
                    union = left_subject | other_subject
                    overlap = left_subject & other_subject
                    if union and len(overlap) / len(union) >= 0.6 and _is_negated(statement) == _is_negated(other):
                        if statement not in agreements:
                            agreements.append(str(statement)[:300])
                        break
    return agreements[:10]


def reconcile(outputs: list[AgentOutput], *, required_independent_evidence: int = 1) -> Reconciliation:
    """Combine participant outputs, gating the result on evidence, not agreement."""
    succeeded = [item for item in outputs if item.succeeded]
    failed = [item.role for item in outputs if not item.succeeded]
    agreements = find_agreements(outputs)
    contradictions = detect_contradictions(outputs)

    independent_refs: list[str] = []
    for item in succeeded:
        for ref in item.independent_evidence:
            if ref not in independent_refs:
                independent_refs.append(ref)

    warnings: list[str] = []
    missing: list[str] = []
    if len(succeeded) < 2:
        missing.append(f"At least two independent analyses are needed; {len(succeeded)} succeeded.")
    if len(independent_refs) < required_independent_evidence:
        missing.append(
            f"{required_independent_evidence} independent evidence ref(s) required "
            f"(tool result, test, verified user statement); {len(independent_refs)} present. "
            "Model agreement does not substitute for evidence."
        )
    if failed:
        missing.append(f"Role(s) that produced nothing usable: {', '.join(sorted(set(failed)))}.")
    if contradictions:
        missing.append(f"{len(contradictions)} unresolved contradiction(s) between participants.")

    if not missing:
        sufficiency: SufficiencyVerdict = "sufficient"
    elif len(independent_refs) >= required_independent_evidence and not contradictions:
        sufficiency = "partially_sufficient"
    else:
        sufficiency = "insufficient"

    if not succeeded:
        consensus_status: ConsensusStatus = "failed"
        consensus = "No participant produced a usable output; nothing can be concluded."
        provenance: Provenance = "model_generated"
        confidence = 0.0
        next_action = "Report the failure precisely, including which roles failed and why, and ask the user how to proceed."
    elif contradictions:
        consensus_status = "contested"
        first = contradictions[0]
        consensus = (
            f"Contested: '{first.left_statement[:140]}' ({first.left_role}) conflicts with "
            f"'{first.right_statement[:140]}' ({first.right_role}) on {', '.join(first.shared_subject[:5])}."
        )
        provenance = "model_generated"
        confidence = 0.25
        next_action = (
            "Settle the contradiction with an observation - run the check or read the state - rather than "
            "counting which side has more supporters."
        )
    elif independent_refs:
        consensus_status = "confirmed"
        consensus = agreements[0] if agreements else succeeded[0].statements[0]
        provenance = succeeded[0].provenance if succeeded[0].provenance in OBSERVATIONAL_PROVENANCE else "tool_result"
        confidence = min(0.9, 0.5 + 0.1 * len(independent_refs) + (0.1 if agreements else 0.0))
        next_action = "Proceed, recording the evidence refs alongside the conclusion."
    else:
        consensus_status = "unverified_consensus"
        consensus = agreements[0] if agreements else succeeded[0].statements[0]
        provenance = "model_generated"
        confidence = min(0.35, 0.2 + 0.05 * len(succeeded))
        warnings.append(
            f"All {len(succeeded)} participant(s) agree, but no independent evidence supports the agreement. "
            "Consensus between models is not proof; this must be reported as unverified."
        )
        next_action = (
            "Obtain one independent observation before acting on this, or tell the user the conclusion is unverified."
        )

    if sufficiency != "sufficient" and consensus_status == "confirmed":
        consensus_status = "unverified_consensus"
        confidence = min(confidence, 0.5)
        warnings.append("Downgraded from 'confirmed': the evidence gate was not satisfied.")

    return Reconciliation(
        participants=len(outputs),
        succeeded=len(succeeded),
        failed_roles=sorted(set(failed)),
        agreements=agreements,
        contradictions=contradictions,
        sufficiency=sufficiency,
        missing_evidence=missing,
        consensus_status=consensus_status,
        consensus_statement=consensus,
        consensus_provenance=provenance,
        confidence=round(confidence, 4),
        warnings=warnings,
        next_action=next_action,
    )
