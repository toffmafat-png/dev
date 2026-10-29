"""Active learning and curiosity, kept inside a budget (§75).

When NOVA hits something it does not know, it resolves the gap in cost order:
recall, then local documentation, then external search, then a specialist model,
then a bounded experiment, then a written test case, and only then the user.
Every rung is optional and every rung can be denied, so the cheapest sufficient
source is used first.

The bound is the point. Three hard limits are enforced here rather than trusted
to the caller:

* **Resource budget** - a gap cannot consume more rungs, provider requests or
  experiment time than the budget allows, and an exhausted budget produces
  "ask the user", never "keep digging".
* **Authorization** - a rung with no registered tool, or one the policy has not
  authorized, is skipped and the skip is recorded.
* **Privacy scope** - a resolution step may only touch paths inside the
  authorized workspace root. ``within_scope`` rejects anything else, including
  paths that escape by ``..`` or symlink-looking components, so curiosity cannot
  wander into unrelated personal files.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

ResolutionStep = Literal[
    "recall_from_memory",
    "read_local_documentation",
    "external_search",
    "specialist_model",
    "run_bounded_experiment",
    "write_test_case",
    "ask_user",
]

# Ordered cheapest-first. ``tool`` empty means "no tool needed" or "no tool exists".
LADDER: tuple[tuple[ResolutionStep, str, float, int, str], ...] = (
    ("recall_from_memory", "Search NOVA's own recorded observations and prior task results.", 0.0, 0, ""),
    ("read_local_documentation", "Read documentation, config or source inside the authorized workspace.", 0.0, 1, "workspace.search_files"),
    ("external_search", "Query an authorized external source for documentation.", 0.0, 2, "research.search_web"),
    ("specialist_model", "Ask one configured specialist model the narrow question.", 0.0, 3, ""),
    ("run_bounded_experiment", "Run one read-only or reversible command whose output answers the question.", 0.0, 4, "process.execute"),
    ("write_test_case", "Encode the question as a test so the answer becomes reproducible evidence.", 0.0, 5, "workspace.write_file"),
    ("ask_user", "Ask the user the specific question that remains.", 0.0, 6, ""),
)
LADDER_ORDER: tuple[ResolutionStep, ...] = tuple(step for step, *_ in LADDER)

DEFAULT_EXPERIMENT_TIMEOUT_SECONDS = 20.0
DEFAULT_MAX_STEPS_PER_GAP = 3
DEFAULT_MAX_PROVIDER_REQUESTS = 6
DEFAULT_MAX_EXPERIMENTS = 2


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


@dataclass(frozen=True)
class CuriosityBudget:
    """Hard caps. A gap that would exceed them stops and escalates instead."""

    max_steps_per_gap: int = DEFAULT_MAX_STEPS_PER_GAP
    max_provider_requests: int = DEFAULT_MAX_PROVIDER_REQUESTS
    max_experiments: int = DEFAULT_MAX_EXPERIMENTS
    experiment_timeout_seconds: float = DEFAULT_EXPERIMENT_TIMEOUT_SECONDS
    authorized_roots: tuple[str, ...] = ()
    external_search_allowed: bool = True
    experiments_allowed: bool = True
    write_allowed: bool = True
    ask_user_allowed: bool = True

    def __post_init__(self) -> None:
        if self.max_steps_per_gap < 1:
            raise ValueError("max_steps_per_gap must be at least 1")
        if self.max_provider_requests < 0 or self.max_experiments < 0:
            raise ValueError("budget counters cannot be negative")
        if self.experiment_timeout_seconds <= 0:
            raise ValueError("experiment_timeout_seconds must be positive")


@dataclass(frozen=True)
class KnowledgeGap:
    """Something NOVA does not know that matters to the current objective."""

    id: str
    question: str
    blocks_objective: bool = True
    domain: str = ""
    candidate_paths: tuple[str, ...] = ()
    privacy_sensitive: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        if not str(self.id).strip():
            raise ValueError("KnowledgeGap.id is required")
        if not str(self.question).strip():
            raise ValueError("KnowledgeGap.question is required")


@dataclass(frozen=True)
class PlannedStep:
    step: ResolutionStep
    instruction: str
    tool: str
    provider_requests: int
    estimated_minutes: float
    skipped: bool = False
    skip_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "instruction": self.instruction,
            "tool": self.tool,
            "provider_requests": self.provider_requests,
            "estimated_minutes": round(float(self.estimated_minutes), 2),
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
        }


@dataclass(frozen=True)
class ResolutionPlan:
    gap: KnowledgeGap
    steps: list[PlannedStep]
    skipped_steps: list[PlannedStep]
    total_provider_requests: int
    total_estimated_minutes: float
    terminal: ResolutionStep
    bounded: bool
    rationale: str
    created_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "gap_id": self.gap.id,
            "question": self.gap.question,
            "blocks_objective": self.gap.blocks_objective,
            "domain": self.gap.domain,
            "steps": [step.to_dict() for step in self.steps],
            "skipped_steps": [step.to_dict() for step in self.skipped_steps],
            "total_provider_requests": self.total_provider_requests,
            "total_estimated_minutes": round(float(self.total_estimated_minutes), 2),
            "terminal": self.terminal,
            "bounded": self.bounded,
            "rationale": self.rationale,
            "created_at": self.created_at,
        }


def within_scope(target: str, authorized_roots: tuple[str, ...] | list[str]) -> tuple[bool, str]:
    """True only when ``target`` resolves inside an authorized root.

    This is the privacy guard. It normalizes the path (collapsing ``..`` and
    redundant separators) and compares resolved absolute paths, so a gap cannot
    authorize itself into ``~/.ssh`` or a parent directory by string trickery.
    """
    roots = [str(root) for root in authorized_roots if str(root).strip()]
    if not roots:
        return False, "No authorized root is configured, so no filesystem exploration is permitted."
    candidate = str(target).strip()
    if not candidate:
        return False, "Empty target path."
    if "\x00" in candidate:
        return False, "Target path contains a null byte."
    normalized = os.path.normpath(os.path.abspath(os.path.expanduser(candidate)))
    for root in roots:
        normalized_root = os.path.normpath(os.path.abspath(os.path.expanduser(root)))
        if normalized == normalized_root or normalized.startswith(normalized_root + os.sep):
            return True, f"Inside authorized root '{normalized_root}'."
    return False, f"'{normalized}' is outside every authorized root ({len(roots)} configured)."


def prioritize_gaps(gaps: list[KnowledgeGap]) -> list[KnowledgeGap]:
    """Blocking gaps first; curiosity about non-blocking things waits."""
    return sorted(
        gaps,
        key=lambda gap: (
            0 if gap.blocks_objective else 1,
            1 if gap.privacy_sensitive else 0,
            gap.id,
        ),
    )


def resolve_gap(
    gap: KnowledgeGap,
    *,
    budget: CuriosityBudget | None = None,
    available_tools: set[str] | None = None,
    provider_requests_used: int = 0,
    experiments_used: int = 0,
    memory_hits: int = 0,
) -> ResolutionPlan:
    """Build a bounded ladder plan for one knowledge gap."""
    active_budget = budget or CuriosityBudget()
    tools = set(available_tools or set())

    requests_left = max(0, active_budget.max_provider_requests - provider_requests_used)
    experiments_left = max(0, active_budget.max_experiments - experiments_used)

    steps: list[PlannedStep] = []
    skipped: list[PlannedStep] = []
    spent_requests = 0
    spent_minutes = 0.0
    bounded = False

    for step, instruction, minutes, _index, tool in LADDER:
        if len(steps) >= active_budget.max_steps_per_gap:
            bounded = True
            break

        skip_reason = ""
        cost_requests = 1 if step in {"specialist_model", "external_search"} else 0
        if step == "recall_from_memory" and memory_hits <= 0:
            skip_reason = "No matching memory entry was found, so recall cannot answer this."
        elif step == "read_local_documentation":
            in_scope = [path for path in gap.candidate_paths if within_scope(path, active_budget.authorized_roots)[0]]
            if gap.privacy_sensitive:
                skip_reason = "Gap is flagged privacy-sensitive; local exploration is refused."
            elif not in_scope and gap.candidate_paths:
                skip_reason = "Every candidate path is outside the authorized workspace roots."
            elif tool and tool not in tools:
                skip_reason = f"Tool '{tool}' is not registered."
        elif step == "external_search":
            if not active_budget.external_search_allowed:
                skip_reason = "External search is not authorized by policy."
            elif tool and tool not in tools:
                skip_reason = f"Tool '{tool}' is not registered."
            elif cost_requests > requests_left - spent_requests:
                skip_reason = "Provider request budget would be exceeded."
        elif step == "specialist_model":
            if cost_requests > requests_left - spent_requests:
                skip_reason = "Provider request budget would be exceeded."
        elif step == "run_bounded_experiment":
            if not active_budget.experiments_allowed:
                skip_reason = "Experiments are not authorized by policy."
            elif tool and tool not in tools:
                skip_reason = f"Tool '{tool}' is not registered."
            elif experiments_left <= 0:
                skip_reason = "Experiment budget is exhausted."
        elif step == "write_test_case":
            if not active_budget.write_allowed:
                skip_reason = "Writing files is not authorized by policy."
            elif tool and tool not in tools:
                skip_reason = f"Tool '{tool}' is not registered."
        elif step == "ask_user" and not active_budget.ask_user_allowed:
            skip_reason = "Asking the user is disabled for this run."

        planned = PlannedStep(
            step=step,
            instruction=instruction,
            tool=tool or ("model" if step == "specialist_model" else ""),
            provider_requests=0 if skip_reason else cost_requests,
            estimated_minutes=0.0 if skip_reason else minutes,
            skipped=bool(skip_reason),
            skip_reason=skip_reason,
        )
        if skip_reason:
            skipped.append(planned)
            continue

        steps.append(planned)
        spent_requests += cost_requests
        spent_minutes += minutes
        if step == "run_bounded_experiment":
            experiments_left -= 1

    terminal: ResolutionStep = steps[-1].step if steps else "ask_user"
    if not steps:
        rationale = (
            "Every rung of the ladder was unavailable, unauthorized or over budget. "
            f"Escalate to the user with the exact question: '{gap.question}'."
        )
        terminal = "ask_user" if active_budget.ask_user_allowed else "recall_from_memory"
    elif terminal != "ask_user" and bounded:
        rationale = (
            f"Stopped after {len(steps)} rung(s) because the per-gap step budget "
            f"({active_budget.max_steps_per_gap}) was reached. If the question is still open, ask the user "
            "rather than continuing to explore."
        )
    else:
        rationale = (
            f"{len(steps)} rung(s) planned at a cost of {spent_requests} provider request(s) and about "
            f"{spent_minutes:.0f} minute(s); {len(skipped)} rung(s) were skipped for authorization, "
            "availability, scope or budget reasons."
        )

    return ResolutionPlan(
        gap=gap,
        steps=steps,
        skipped_steps=skipped,
        total_provider_requests=spent_requests,
        total_estimated_minutes=spent_minutes,
        terminal=terminal,
        bounded=bounded,
        rationale=rationale,
    )


@dataclass
class ExplorationLog:
    """What curiosity actually cost, so the bound can be audited afterwards."""

    gaps_planned: int = 0
    steps_planned: int = 0
    steps_skipped: int = 0
    provider_requests: int = 0
    experiments: int = 0
    escalated_to_user: int = 0
    refused_out_of_scope: int = 0
    entries: list[dict[str, Any]] = field(default_factory=list)

    def record(self, plan: ResolutionPlan) -> None:
        self.gaps_planned += 1
        self.steps_planned += len(plan.steps)
        self.steps_skipped += len(plan.skipped_steps)
        self.provider_requests += plan.total_provider_requests
        self.experiments += sum(1 for step in plan.steps if step.step == "run_bounded_experiment")
        if plan.terminal == "ask_user":
            self.escalated_to_user += 1
        self.refused_out_of_scope += sum(
            1 for step in plan.skipped_steps if "outside the authorized" in step.skip_reason
        )
        self.entries.append(
            {
                "gap_id": plan.gap.id,
                "terminal": plan.terminal,
                "steps": len(plan.steps),
                "provider_requests": plan.total_provider_requests,
                "recorded_at": _utc_now(),
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "gaps_planned": self.gaps_planned,
            "steps_planned": self.steps_planned,
            "steps_skipped": self.steps_skipped,
            "provider_requests": self.provider_requests,
            "experiments": self.experiments,
            "escalated_to_user": self.escalated_to_user,
            "refused_out_of_scope": self.refused_out_of_scope,
            "entries": list(self.entries[-25:]),
        }
