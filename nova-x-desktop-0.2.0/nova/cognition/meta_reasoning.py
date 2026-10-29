"""Meta-reasoning: pre-flight review of a plan and post-hoc attribution.

§72 asks NOVA to assess its own approach *before* spending resources, and to
explain afterwards why the result differed from the intention. Both halves here
are structural rather than rhetorical: the review is derived from the plan, the
registered tools, the budget and the world model, so the same inputs always
produce the same verdict and the verdict can be tested.

Deliberately excluded: open-ended chains of self-criticism. The review returns
one bounded verdict, explicit acceptance criteria, the cheapest sufficient
verification, and concrete abandon conditions.

Confidence produced here is a *prediction* and is meant to be handed to
``CalibrationLedger`` so it can be scored against what actually happened.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

ProceedDecision = Literal["proceed", "gather_information_first", "blocked"]
FailureCause = Literal[
    "success",
    "incorrect_information",
    "poor_planning",
    "unavailable_tool",
    "execution_error",
    "bad_success_criterion",
    "budget_exhausted",
    "cancelled",
    "unknown",
]

# Verification means ordered cheapest-first. The first one that is actually
# available wins; NOVA should not buy a second model call when a local test
# settles the question.
VERIFICATION_LADDER: tuple[tuple[str, str, str], ...] = (
    ("local_test", "Run the project's existing test command and read the result.", "process.execute"),
    ("recompute", "Recompute the value independently with the bounded calculator.", "math.calculate"),
    ("inspect_file", "Read the affected workspace file and compare with the expectation.", "workspace.read_file"),
    ("inspect_state", "Re-observe the system state with an authorized read-only command.", "process.execute"),
    ("search_workspace", "Search the workspace for corroborating evidence.", "workspace.search_files"),
    ("external_research", "Query an authorized external source for documentation.", "research.search_web"),
    (
        "second_model",
        "No observational verification is available. A second model review is possible, but agreement "
        "between models is not independent evidence and the result stays unverified.",
        "",
    ),
)

# Step phrasing that implies a capability NOVA may not have. The third element
# says whether the gap is *blocking*: True when no installed tool could ever
# satisfy the step and NOVA must not fake it (sending mail, spending money,
# driving a GUI, powering a machine, authenticating as the user), False when the
# action is possible but policy-gated, so the plan should surface it rather than
# stop dead.
_CAPABILITY_HINTS: tuple[tuple[str, str, bool], ...] = (
    (r"\b(install|apt|pip install|npm install)\b", "package installation", False),
    (r"\b(delete|remove|rm |drop)\b", "destructive file or data removal", False),
    (r"\b(email|send|post|publish|tweet)\b", "outbound communication", True),
    (r"\b(reboot|shutdown|restart service|systemctl)\b", "system power or service control", True),
    (r"\b(screenshot|screen capture|look at the screen)\b", "screen capture", True),
    (r"\b(click|type into|desktop automation|gui)\b", "desktop GUI automation", True),
    (r"\b(payment|buy|purchase|invoice)\b", "payment or purchasing", True),
    (r"\b(login|sign in|authenticate as)\b", "account authentication", True),
    (r"\b(browse|scrape|crawl)\b", "browser automation or scraping", True),
)

_DELIVERABLE_VERBS = ("produce", "create", "write", "generate", "build", "fix", "implement", "deliver", "report", "summarize", "export", "add", "update", "install", "configure", "verify", "test", "diagnose", "identify")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


@dataclass(frozen=True)
class PreflightReview:
    """A bounded assessment of a proposed approach, made before execution."""

    objective: str
    required_outcome: str
    understood: list[str]
    unknowns: list[str]
    missing_evidence: list[str]
    riskiest_assumptions: list[str]
    failure_modes: list[str]
    capability_gaps: list[str]
    blocking_capability_gaps: list[str]
    acceptance_criteria: list[str]
    cheapest_verification: str
    verification_tool: str
    abandon_conditions: list[str]
    cheaper_alternative: str | None
    estimated_tool_calls: int
    estimated_provider_requests: int
    proceed: ProceedDecision
    rationale: str
    confidence: float
    created_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "required_outcome": self.required_outcome,
            "understood": list(self.understood),
            "unknowns": list(self.unknowns),
            "missing_evidence": list(self.missing_evidence),
            "riskiest_assumptions": list(self.riskiest_assumptions),
            "failure_modes": list(self.failure_modes),
            "capability_gaps": list(self.capability_gaps),
            "blocking_capability_gaps": list(self.blocking_capability_gaps),
            "acceptance_criteria": list(self.acceptance_criteria),
            "cheapest_verification": self.cheapest_verification,
            "verification_tool": self.verification_tool,
            "abandon_conditions": list(self.abandon_conditions),
            "cheaper_alternative": self.cheaper_alternative,
            "estimated_tool_calls": self.estimated_tool_calls,
            "estimated_provider_requests": self.estimated_provider_requests,
            "proceed": self.proceed,
            "rationale": self.rationale,
            "confidence": round(float(self.confidence), 4),
            "created_at": self.created_at,
        }


def derive_acceptance_criteria(objective: str, plan_steps: list[str]) -> tuple[list[str], bool]:
    """Extract checkable criteria from the objective; report whether any exist.

    Returns ``(criteria, ambiguous)``. ``ambiguous`` is True when no criterion
    could be made concrete, which is itself the finding: the task cannot be
    verified as stated and the user should be asked to tighten it.
    """
    text = " ".join([objective, *plan_steps]).lower()
    criteria: list[str] = []
    for verb in _DELIVERABLE_VERBS:
        pattern = rf"\b{verb}\b[^.;\n]{{3,90}}"
        match = re.search(pattern, text)
        if match:
            fragment = match.group(0).strip().rstrip(".,;")
            criterion = f"A concrete result exists for: '{fragment[:120]}'."
            if criterion not in criteria:
                criteria.append(criterion)
        if len(criteria) >= 4:
            break
    if re.search(r"\b(test|tests|passing|pass)\b", text):
        criteria.append("The relevant test command exits successfully and its output is recorded.")
    if re.search(r"\b(fix|bug|defect|error|fail)\b", text):
        criteria.append("The originally reported failure no longer reproduces, demonstrated by re-running it.")
    if re.search(r"\b(report|summary|document|explain)\b", text):
        criteria.append("A written result exists that cites the evidence it is based on.")

    # Every task gets at least one evidence criterion, but if nothing concrete
    # could be derived the objective is flagged as unverifiable as written.
    criteria.append("At least one tool result or observation is recorded as evidence of the outcome.")
    ambiguous = len(criteria) <= 1
    deduped: list[str] = []
    for item in criteria:
        if item not in deduped:
            deduped.append(item)
    return deduped[:6], ambiguous


def _scan_capability_gaps(plan_steps: list[str], available_tools: set[str]) -> list[tuple[str, bool]]:
    """Return ``(gap, blocking)`` pairs for steps needing absent capabilities."""
    gaps: list[tuple[str, bool]] = []
    seen: set[str] = set()
    for step in plan_steps:
        lowered = str(step).lower()
        for pattern, label, blocking in _CAPABILITY_HINTS:
            if re.search(pattern, lowered) and label not in seen:
                seen.add(label)
                gaps.append((f"{label} (required by step: '{str(step)[:90]}')", blocking))
        # An explicit tool reference that is not registered is a hard gap.
        for referenced in sorted(set(re.findall(r"\b([a-z_]+\.[a-z_]{3,})\b", lowered))):
            if referenced in available_tools:
                continue
            label = f"tool '{referenced}'"
            if label in seen:
                continue
            seen.add(label)
            gaps.append((f"{label} is not registered", True))
    return gaps[:12]


def detect_capability_gaps(plan_steps: list[str], available_tools: set[str]) -> list[str]:
    """Find steps that need a capability NOVA does not currently have."""
    return [gap for gap, _blocking in _scan_capability_gaps(plan_steps, available_tools)]


def detect_blocking_capability_gaps(plan_steps: list[str], available_tools: set[str]) -> list[str]:
    """The subset of gaps that must stop the plan rather than be worked around."""
    return [gap for gap, blocking in _scan_capability_gaps(plan_steps, available_tools) if blocking]


def preflight(
    objective: str,
    plan_steps: list[str],
    available_tools: set[str] | None = None,
    *,
    assumptions: list[str] | None = None,
    known_facts: list[str] | None = None,
    open_questions: list[str] | None = None,
    max_tool_calls: int = 8,
    max_provider_requests: int = 12,
    supports_verification_call: bool = True,
    requires_external_evidence: bool = False,
    research_available: bool = False,
) -> PreflightReview:
    """Assess a plan before committing resources to it."""
    tools = set(available_tools or set())
    assumptions = list(assumptions or [])
    known_facts = list(known_facts or [])
    open_questions = list(open_questions or [])

    criteria, ambiguous = derive_acceptance_criteria(objective, plan_steps)
    scanned = _scan_capability_gaps(plan_steps, tools)
    gaps = [gap for gap, _blocking in scanned]
    blocking_gaps = [gap for gap, blocking in scanned if blocking]

    understood = [fact for fact in known_facts if fact][:5]
    if plan_steps:
        understood.append(f"A {len(plan_steps)}-step plan exists and was parsed successfully.")
    if tools:
        understood.append(f"{len(tools)} tool(s) are registered and reachable.")

    unknowns = [question for question in open_questions if question][:5]
    missing_evidence: list[str] = []
    if not known_facts:
        missing_evidence.append("No prior observation about this environment is recorded; the plan starts from assumptions.")
    if requires_external_evidence and not research_available:
        missing_evidence.append("The task needs external evidence but no authorized research tool is available.")
    if ambiguous:
        missing_evidence.append("The objective does not state a checkable success criterion.")

    failure_modes: list[str] = []
    if len(plan_steps) > max_tool_calls:
        failure_modes.append(
            f"The plan has {len(plan_steps)} steps but the tool budget allows {max_tool_calls}; it will be cut off mid-execution."
        )
    if not tools:
        failure_modes.append("No tool is available, so every step would be answered from model text alone.")
    if blocking_gaps:
        failure_modes.append(
            f"{len(blocking_gaps)} step(s) require capabilities that do not exist in this installation and cannot be simulated."
        )
    elif gaps:
        failure_modes.append(f"{len(gaps)} step(s) require capabilities that are policy-gated rather than available.")
    if not plan_steps:
        failure_modes.append("The plan is empty; there is nothing to execute or verify.")
    failure_modes.append("A provider call may fail or be rate limited, which stops the step that depends on it.")
    if ambiguous:
        failure_modes.append("Success cannot be demonstrated even if the work is done correctly.")

    verification, verification_tool = _choose_verification(tools, supports_verification_call, plan_steps)

    abandon_conditions = [
        f"Stop after {max_provider_requests} provider requests without a verified result.",
        "Stop after the same tool fails twice with the same error.",
        f"Stop after {max_tool_calls} tool calls without satisfying an acceptance criterion.",
    ]
    if gaps:
        abandon_conditions.append("Stop immediately if a step requires a capability listed as missing rather than working around it silently.")
    if blocking_gaps:
        abandon_conditions.append("Do not attempt to substitute model-generated text for a blocked capability's real output.")

    cheaper_alternative: str | None = None
    if len(plan_steps) > 3 and (gaps or blocking_gaps):
        cheaper_alternative = (
            "A narrower objective that stays inside the installed tool set would avoid the missing capabilities "
            "entirely and cost fewer requests."
        )
    elif requires_external_evidence and not research_available:
        cheaper_alternative = "Ask the user for the specific missing fact instead of searching for it."

    estimated_tool_calls = min(len(plan_steps), max_tool_calls) + (1 if verification_tool in tools else 0)
    # planning + one step-driving call per tool round + verification + synthesis
    estimated_provider_requests = min(max_provider_requests, 2 + estimated_tool_calls + (1 if supports_verification_call else 0))

    if blocking_gaps:
        proceed: ProceedDecision = "blocked"
        rationale = (
            f"{len(blocking_gaps)} step(s) need capabilities NOVA does not have and must not fake: "
            + "; ".join(blocking_gaps[:3])
            + ". Report the gap precisely instead of attempting a workaround."
        )
    elif missing_evidence or (open_questions and not known_facts):
        proceed = "gather_information_first"
        rationale = (
            "The plan can run, but a stated unknown or missing evidence would make its result unverifiable. "
            "Resolve the cheapest gap first: " + (missing_evidence[0] if missing_evidence else open_questions[0]) + "."
        )
    else:
        proceed = "proceed"
        rationale = "Requirements, tools and a checkable success criterion are all present; execute and then verify."

    confidence = _estimate_confidence(
        understood=understood,
        unknowns=unknowns,
        gaps=gaps,
        missing_evidence=missing_evidence,
        ambiguous=ambiguous,
        has_plan=bool(plan_steps),
        has_tools=bool(tools),
    )

    riskiest = list(assumptions)[:4]
    if not riskiest:
        riskiest = _infer_assumptions(objective, plan_steps, tools)

    return PreflightReview(
        objective=str(objective)[:500],
        required_outcome=criteria[0] if criteria else "No concrete outcome could be derived from the objective.",
        understood=understood,
        unknowns=unknowns,
        missing_evidence=missing_evidence,
        riskiest_assumptions=riskiest,
        failure_modes=failure_modes[:6],
        capability_gaps=gaps,
        blocking_capability_gaps=blocking_gaps,
        acceptance_criteria=criteria,
        cheapest_verification=verification,
        verification_tool=verification_tool,
        abandon_conditions=abandon_conditions,
        cheaper_alternative=cheaper_alternative,
        estimated_tool_calls=estimated_tool_calls,
        estimated_provider_requests=estimated_provider_requests,
        proceed=proceed,
        rationale=rationale,
        confidence=confidence,
    )


def _choose_verification(tools: set[str], supports_verification_call: bool, plan_steps: list[str]) -> tuple[str, str]:
    joined = " ".join(str(step).lower() for step in plan_steps)
    for name, description, required_tool in VERIFICATION_LADDER:
        if required_tool and required_tool not in tools:
            continue
        if name == "local_test" and not re.search(r"\b(test|pytest|spec|suite)\b", joined):
            continue
        if name == "recompute" and not re.search(r"\b(calc|comput|number|total|percent|sum|average)\b", joined):
            continue
        if name == "second_model" and not supports_verification_call:
            continue
        return description, required_tool or ("model" if name == "second_model" else "")
    return "No verification means is available; the result will be reported as unverified.", ""


def _infer_assumptions(objective: str, plan_steps: list[str], tools: set[str]) -> list[str]:
    assumptions: list[str] = []
    text = " ".join([objective, *plan_steps]).lower()
    if re.search(r"\b(project|repo|repository|codebase)\b", text):
        assumptions.append("The target project exists at the assumed path and has the assumed layout.")
    if re.search(r"\b(command|cli|run|execute)\b", text):
        assumptions.append("The referenced program is installed and behaves as its documentation describes.")
    if re.search(r"\b(test|tests)\b", text):
        assumptions.append("A working test command exists and currently reflects the code's real behaviour.")
    if re.search(r"\b(api|provider|model|network)\b", text):
        assumptions.append("The external service is reachable and the credential is valid and entitled.")
    if not tools:
        assumptions.append("No tool is registered, so any claimed action would be unverified text.")
    if not assumptions:
        assumptions.append("The objective's wording matches the user's actual intent; no clarification was requested.")
    return assumptions[:4]


def _estimate_confidence(
    *,
    understood: list[str],
    unknowns: list[str],
    gaps: list[str],
    missing_evidence: list[str],
    ambiguous: bool,
    has_plan: bool,
    has_tools: bool,
) -> float:
    """A deliberately conservative, rule-based confidence in the 0.05-0.9 band.

    This is a prediction, not a proof. It is meant to be recorded and later
    scored by ``CalibrationLedger``; a system that cannot be scored should not
    publish confidence at all.
    """
    score = 0.5
    if has_plan:
        score += 0.1
    if has_tools:
        score += 0.1
    score += min(0.15, 0.03 * len(understood))
    score -= min(0.3, 0.1 * len(unknowns))
    score -= min(0.25, 0.08 * len(gaps))
    score -= min(0.2, 0.07 * len(missing_evidence))
    if ambiguous:
        score -= 0.15
    return round(max(0.05, min(0.9, score)), 4)


@dataclass(frozen=True)
class PostHocReview:
    """Comparison of intended and observed outcome, with an attributed cause."""

    task_id: str
    state: str
    intended: str
    observed: str
    criteria_met: int
    criteria_total: int
    cause: FailureCause
    explanation: str
    predicted_confidence: float
    actual_outcome: bool
    confidence_error: float
    lesson: str
    lesson_status: str
    created_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "state": self.state,
            "intended": self.intended,
            "observed": self.observed,
            "criteria_met": self.criteria_met,
            "criteria_total": self.criteria_total,
            "cause": self.cause,
            "explanation": self.explanation,
            "predicted_confidence": round(float(self.predicted_confidence), 4),
            "actual_outcome": self.actual_outcome,
            "confidence_error": round(float(self.confidence_error), 4),
            "lesson": self.lesson,
            "lesson_status": self.lesson_status,
            "created_at": self.created_at,
        }


def post_hoc(
    *,
    task_id: str,
    state: str,
    review: PreflightReview | None,
    tool_outcomes: list[dict[str, Any]] | None = None,
    criteria_met: int = 0,
    provider_requests: int = 0,
    budget_exhausted: bool = False,
    contradictions: int = 0,
    observed_summary: str = "",
) -> PostHocReview:
    """Attribute the outcome to a cause using recorded evidence, not narrative."""
    outcomes = list(tool_outcomes or [])
    statuses = [str(item.get("status", "")) for item in outcomes]
    criteria_total = len(review.acceptance_criteria) if review else 0
    intended = review.required_outcome if review else "No pre-flight review was recorded."
    predicted = float(review.confidence) if review else 0.0
    actual = state == "completed" and (criteria_total == 0 or criteria_met >= max(1, criteria_total - 0))

    cause: FailureCause
    explanation: str
    lesson: str

    if state == "cancelled":
        cause = "cancelled"
        explanation = "Execution was stopped by the user or by an emergency stop before completion."
        lesson = "No capability lesson can be drawn from a user-cancelled run."
    elif budget_exhausted or (review and provider_requests >= review.estimated_provider_requests and state != "completed"):
        cause = "budget_exhausted"
        explanation = (
            f"The configured request budget was reached ({provider_requests} requests) before a verified result existed."
        )
        lesson = "Scope the objective narrower, or raise the budget explicitly, before retrying this class of task."
    elif "denied" in statuses:
        denied = [item for item in outcomes if str(item.get("status")) == "denied"]
        cause = "unavailable_tool"
        explanation = (
            f"{len(denied)} tool call(s) were denied by policy or availability: "
            + "; ".join(str(item.get("summary", ""))[:120] for item in denied[:2])
        )
        lesson = "Check tool availability and the autonomy policy before planning steps that depend on them."
    elif "approval_required" in statuses and state != "completed":
        cause = "unavailable_tool"
        explanation = "A step stopped at an approval gate that was never resolved, so the work could not continue."
        lesson = "Surface the pending approval to the user instead of waiting silently."
    elif "error" in statuses:
        errors = [item for item in outcomes if str(item.get("status")) == "error"]
        cause = "execution_error"
        explanation = (
            f"{len(errors)} tool call(s) failed during execution: "
            + "; ".join(str(item.get("summary", ""))[:120] for item in errors[:2])
        )
        lesson = "Inspect the actual error output and adapt the step rather than repeating the identical call."
    elif contradictions > 0:
        cause = "incorrect_information"
        explanation = (
            f"{contradictions} prediction(s) disagreed with observation, so the plan was built on a model of the "
            "environment that did not hold."
        )
        lesson = "Re-observe the environment before planning; do not reuse a contradicted assumption."
    elif state == "completed" and actual:
        cause = "success"
        explanation = f"The task completed and {criteria_met}/{criteria_total} acceptance criteria were satisfied by recorded evidence."
        lesson = "This approach worked under these conditions; it is a candidate for a reusable procedure."
    elif state == "completed" and criteria_total and criteria_met < criteria_total:
        cause = "bad_success_criterion"
        explanation = (
            f"The task was marked complete but only {criteria_met}/{criteria_total} acceptance criteria were met, so "
            "'complete' and 'correct' diverged."
        )
        lesson = "Tighten the acceptance criteria before execution; completion state alone is not evidence of success."
    elif review and review.proceed != "proceed":
        cause = "poor_planning"
        explanation = (
            f"The pre-flight review already recommended '{review.proceed}' ({review.rationale[:160]}), and execution "
            "proceeded anyway without resolving it."
        )
        lesson = "Honour a pre-flight verdict of 'blocked' or 'gather_information_first' instead of executing."
    elif state == "failed":
        cause = "poor_planning"
        explanation = "The task failed with no tool denial, execution error, or budget exhaustion recorded, which points at the plan itself."
        lesson = "Re-plan from observed state rather than retrying the same steps."
    else:
        cause = "unknown"
        explanation = "Recorded evidence does not distinguish between the candidate causes for this outcome."
        lesson = "Instrument the run further before drawing a conclusion; do not guess a cause."

    # A lesson from a single run is tentative. Corroboration is what promotes it,
    # and that happens in the procedure/lesson store, not here.
    lesson_status = "tentative" if cause != "unknown" else "unsupported"
    if observed_summary:
        explanation = f"{explanation} Observed: {observed_summary[:200]}"

    return PostHocReview(
        task_id=task_id,
        state=state,
        intended=intended,
        observed=observed_summary[:300] or f"Final state: {state}; {criteria_met}/{criteria_total} criteria met.",
        criteria_met=int(criteria_met),
        criteria_total=int(criteria_total),
        cause=cause,
        explanation=explanation,
        predicted_confidence=predicted,
        actual_outcome=bool(actual),
        confidence_error=round(predicted - (1.0 if actual else 0.0), 4),
        lesson=lesson,
        lesson_status=lesson_status,
    )
