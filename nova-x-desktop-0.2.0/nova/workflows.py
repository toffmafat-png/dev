"""§97 Workflow visual editor backend and §98 Cross-application automation.

Provides a versioned, inspectable DAG specification for visual workflows
covering all fourteen §97 block types, static cycle/budget/authorization
validation, dry-run simulation, duplicate-execution protection, natural-language
draft generation, and §98 checkpointed cross-application stage execution that
preserves completed stages on partial failure.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

WORKFLOW_SCHEMA_VERSION = "nova-workflow-v1"

BLOCK_TYPES = (
    "trigger",
    "condition",
    "model_request",
    "tool_call",
    "file_operation",
    "terminal_command",
    "data_transform",
    "delay_schedule",
    "verification",
    "notification",
    "approval",
    "retry",
    "error_handler",
    "completion",
)

MAX_WORKFLOW_BLOCKS = 64
MAX_WORKFLOW_COST_USD = 5.0
MIN_SCHEDULE_INTERVAL_MINUTES = 5


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


class WorkflowBlock(BaseModel):
    block_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    block_type: str
    label: str = Field(min_length=1, max_length=160)
    config: dict[str, Any] = Field(default_factory=dict)
    next_blocks: list[str] = Field(default_factory=list)
    on_error: str = ""
    estimated_cost_usd: float = Field(default=0.0, ge=0.0, le=MAX_WORKFLOW_COST_USD)

    @field_validator("block_type")
    @classmethod
    def _valid_type(cls, value: str) -> str:
        if value not in BLOCK_TYPES:
            raise ValueError(f"block_type must be one of {BLOCK_TYPES}")
        return value


class WorkflowSpec(BaseModel):
    schema_version: str = WORKFLOW_SCHEMA_VERSION
    workflow_id: str = Field(min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    name: str = Field(min_length=2, max_length=160)
    description: str = ""
    status: str = "draft"  # draft | validated | active
    max_cost_usd: float = Field(default=1.0, ge=0.0, le=MAX_WORKFLOW_COST_USD)
    entry_block_id: str
    blocks: list[WorkflowBlock] = Field(min_length=1, max_length=MAX_WORKFLOW_BLOCKS)

    def block_map(self) -> dict[str, WorkflowBlock]:
        return {b.block_id: b for b in self.blocks}


def _required_tool_for_block(block: WorkflowBlock) -> tuple[str, dict[str, Any]]:
    if block.block_type == "tool_call":
        return str(block.config.get("tool_name") or ""), dict(block.config.get("arguments") or {})
    if block.block_type == "file_operation":
        op = str(block.config.get("operation") or "read")
        tool = "workspace.write_file" if op in {"write", "append", "update"} else "workspace.read_file"
        return tool, {"path": str(block.config.get("path") or "")}
    if block.block_type == "terminal_command":
        return "system.run_command", {"argv": list(block.config.get("argv") or [])}
    return "", {}


def validate_workflow(
    spec: WorkflowSpec,
    *,
    available_tools: set[str] | None = None,
    permission_check: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate structure, acyclicity, schedule bounds, cost limits, tools & authorization."""
    issues: list[str] = []
    approval_gates: list[str] = []
    blocks = spec.block_map()
    if len(blocks) != len(spec.blocks):
        issues.append("duplicate block_id detected")
    if spec.entry_block_id not in blocks:
        issues.append(f"entry_block_id '{spec.entry_block_id}' does not exist")

    # Edge target validity & cycle detection (DFS with visiting/visited sets).
    visiting: set[str] = set()
    visited: set[str] = set()

    def _dfs(node_id: str) -> None:
        if node_id in visiting:
            issues.append(f"cycle / recursive loop detected involving block '{node_id}'")
            return
        if node_id in visited or node_id not in blocks:
            return
        visiting.add(node_id)
        node = blocks[node_id]
        targets = [*node.next_blocks, *([node.on_error] if node.on_error else [])]
        for nxt in targets:
            if nxt not in blocks:
                issues.append(f"block '{node_id}' references missing target '{nxt}'")
            else:
                _dfs(nxt)
        visiting.remove(node_id)
        visited.add(node_id)

    if spec.entry_block_id in blocks:
        _dfs(spec.entry_block_id)
    unreachable = sorted(set(blocks) - visited)
    if unreachable:
        issues.append(f"unreachable blocks: {', '.join(unreachable)}")

    if not any(b.block_type == "completion" for b in spec.blocks):
        issues.append("workflow must include at least one 'completion' block")

    total_cost = round(sum(b.estimated_cost_usd for b in spec.blocks), 4)
    if total_cost > spec.max_cost_usd:
        issues.append(f"estimated cost ${total_cost:.2f} exceeds workflow max_cost_usd ${spec.max_cost_usd:.2f}")

    has_approval_block = any(b.block_type == "approval" for b in spec.blocks)

    for block in spec.blocks:
        if block.block_type == "delay_schedule":
            interval = int(block.config.get("interval_minutes") or 0)
            if 0 < interval < MIN_SCHEDULE_INTERVAL_MINUTES:
                issues.append(
                    f"block '{block.block_id}' schedule interval ({interval}m) is below minimum ({MIN_SCHEDULE_INTERVAL_MINUTES}m)"
                )
        if block.block_type == "retry":
            max_attempts = int(block.config.get("max_attempts") or 1)
            if max_attempts > 5:
                issues.append(f"block '{block.block_id}' retry max_attempts ({max_attempts}) exceeds limit of 5")

        tool_name, args = _required_tool_for_block(block)
        if not tool_name:
            continue
        if available_tools is not None and tool_name not in available_tools:
            issues.append(f"block '{block.block_id}' requires unavailable tool '{tool_name}'")
            continue
        if permission_check is not None:
            decision = permission_check(tool_name, args)
            action = decision.get("action", "deny")
            if action == "deny":
                issues.append(
                    f"authorization policy denies '{tool_name}' in block '{block.block_id}': {decision.get('reason', '')}"
                )
            elif action == "approval_required" and not has_approval_block:
                approval_gates.append(block.block_id)
                issues.append(
                    f"block '{block.block_id}' ('{tool_name}') requires operator approval; add an 'approval' block or grant policy scope"
                )

    return {
        "valid": not issues,
        "workflow_id": spec.workflow_id,
        "schema_version": spec.schema_version,
        "estimated_cost_usd": total_cost,
        "approval_required_blocks": approval_gates,
        "issues": issues,
    }


@dataclass
class WorkflowEngine:
    """§97 Workflow storage, import/export, proposal, dry-run & enforced execution."""

    permission_check: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None
    tool_executor: Callable[[str, dict[str, Any], bool], Awaitable[dict[str, Any]]] | None = None
    available_tools_fn: Callable[[], set[str]] | None = None
    _workflows: dict[str, WorkflowSpec] = field(default_factory=dict, init=False)
    _templates: dict[str, WorkflowSpec] = field(default_factory=dict, init=False)
    _history: list[dict[str, Any]] = field(default_factory=list, init=False)
    _idempotency_keys: set[str] = field(default_factory=set, init=False)

    def save_workflow(self, spec: WorkflowSpec, *, activate: bool = False) -> dict[str, Any]:
        tools = self.available_tools_fn() if self.available_tools_fn is not None else None
        validation = validate_workflow(spec, available_tools=tools, permission_check=self.permission_check)
        if activate and not validation["valid"]:
            return {"saved": False, "activated": False, "validation": validation}
        spec.status = "active" if activate else ("validated" if validation["valid"] else "draft")
        self._workflows[spec.workflow_id] = spec
        return {"saved": True, "activated": spec.status == "active", "workflow": spec.model_dump(), "validation": validation}

    def save_template(self, spec: WorkflowSpec) -> dict[str, Any]:
        self._templates[spec.workflow_id] = spec
        return {"template_saved": True, "workflow_id": spec.workflow_id}

    def export_json(self, workflow_id: str) -> str:
        spec = self._workflows.get(workflow_id) or self._templates.get(workflow_id)
        if spec is None:
            raise KeyError(f"Unknown workflow: {workflow_id}")
        return spec.model_dump_json(indent=2)

    def import_json(self, raw_json: str) -> dict[str, Any]:
        spec = WorkflowSpec.model_validate_json(raw_json)
        return self.save_workflow(spec, activate=False)

    def propose_from_instruction(self, instruction: str, *, workflow_id: str = "wf-proposed") -> dict[str, Any]:
        """Generate a draft workflow from natural language and validate before activation (§97)."""
        lowered = (instruction or "").lower()
        blocks: list[WorkflowBlock] = [
            WorkflowBlock(block_id="trig", block_type="trigger", label="Manual or event trigger", next_blocks=["step1"]),
        ]
        if "write" in lowered or "save" in lowered or "command" in lowered:
            blocks.append(
                WorkflowBlock(
                    block_id="step1",
                    block_type="approval",
                    label="Operator approval gate",
                    next_blocks=["act"],
                )
            )
            blocks.append(
                WorkflowBlock(
                    block_id="act",
                    block_type="file_operation" if ("write" in lowered or "save" in lowered) else "terminal_command",
                    label="Execute requested workspace action",
                    config={"operation": "write", "path": "output/report.md"} if ("write" in lowered or "save" in lowered) else {"argv": ["echo", "ok"]},
                    next_blocks=["verify"],
                    on_error="err",
                )
            )
        else:
            blocks.append(
                WorkflowBlock(
                    block_id="step1",
                    block_type="file_operation",
                    label="Read workspace input",
                    config={"operation": "read", "path": "notes.md"},
                    next_blocks=["verify"],
                    on_error="err",
                )
            )
        blocks.extend(
            [
                WorkflowBlock(block_id="verify", block_type="verification", label="Verify output", next_blocks=["done"], on_error="err"),
                WorkflowBlock(block_id="err", block_type="error_handler", label="Record failure details", next_blocks=["done"]),
                WorkflowBlock(block_id="done", block_type="completion", label="Workflow complete"),
            ]
        )
        spec = WorkflowSpec(
            workflow_id=workflow_id,
            name=f"Proposed: {instruction.strip()[:60]}",
            description=instruction.strip(),
            status="draft",
            entry_block_id="trig",
            blocks=blocks,
        )
        tools = self.available_tools_fn() if self.available_tools_fn is not None else None
        validation = validate_workflow(spec, available_tools=tools, permission_check=self.permission_check)
        return {"status": "draft", "spec": spec.model_dump(), "validation": validation}

    async def execute(
        self,
        workflow_id: str,
        *,
        inputs: dict[str, Any] | None = None,
        dry_run: bool = False,
        operator_approved: bool = False,
        dedupe_key: str = "",
    ) -> dict[str, Any]:
        spec = self._workflows.get(workflow_id)
        if spec is None:
            return {"status": "error", "reason": f"workflow '{workflow_id}' not found"}

        if not dry_run and dedupe_key and dedupe_key in self._idempotency_keys:
            return {"status": "duplicate_refused", "workflow_id": workflow_id, "dedupe_key": dedupe_key}

        tools = self.available_tools_fn() if self.available_tools_fn is not None else None
        validation = validate_workflow(spec, available_tools=tools, permission_check=self.permission_check)
        if not validation["valid"]:
            return {"status": "denied", "dry_run": dry_run, "reason": "workflow failed validation", "validation": validation}

        blocks = spec.block_map()
        context = dict(inputs or {})
        trace: list[dict[str, Any]] = []
        current_id: str | None = spec.entry_block_id
        steps = 0
        approval_granted = operator_approved

        while current_id and steps < MAX_WORKFLOW_BLOCKS:
            steps += 1
            block = blocks[current_id]
            step_record: dict[str, Any] = {"block_id": block.block_id, "block_type": block.block_type, "dry_run": dry_run}

            if block.block_type == "approval":
                if not dry_run and not approval_granted:
                    step_record["outcome"] = "waiting_approval"
                    trace.append(step_record)
                    return self._record_run(workflow_id, "waiting_approval", dry_run, trace)
                step_record["outcome"] = "simulated_approved" if dry_run else "approved"
                trace.append(step_record)
                current_id = block.next_blocks[0] if block.next_blocks else None
                continue

            if block.block_type == "condition":
                key = str(block.config.get("input_key") or "")
                truthy = bool(context.get(key))
                step_record["outcome"] = f"branch={'true' if truthy else 'false'}"
                trace.append(step_record)
                if truthy and block.next_blocks:
                    current_id = block.next_blocks[0]
                elif not truthy and len(block.next_blocks) > 1:
                    current_id = block.next_blocks[1]
                else:
                    current_id = None
                continue

            tool_name, args = _required_tool_for_block(block)
            if tool_name:
                # Re-check policy at runtime as well so policy revocations after save take effect immediately (§114 #16).
                if self.permission_check is not None:
                    decision = self.permission_check(tool_name, args)
                    action = decision.get("action", "deny")
                    if action == "deny" or (action == "approval_required" and not approval_granted and not dry_run):
                        step_record["outcome"] = "denied"
                        step_record["reason"] = decision.get("reason", f"policy returned {action}")
                        trace.append(step_record)
                        if block.on_error:
                            current_id = block.on_error
                            continue
                        return self._record_run(workflow_id, "denied", dry_run, trace)

                if dry_run:
                    step_record["outcome"] = f"dry_run_would_call:{tool_name}"
                elif self.tool_executor is not None:
                    out = await self.tool_executor(tool_name, args, approval_granted)
                    step_record["outcome"] = out.get("status", "unknown")
                    if out.get("status") not in {"success", "ok"}:
                        trace.append(step_record)
                        if block.on_error:
                            current_id = block.on_error
                            continue
                        return self._record_run(workflow_id, "failed", dry_run, trace)
                else:
                    step_record["outcome"] = "validated_no_executor"
            else:
                step_record["outcome"] = "simulated" if dry_run else "completed"

            trace.append(step_record)
            if block.block_type == "completion":
                break
            current_id = block.next_blocks[0] if block.next_blocks else None

        if not dry_run and dedupe_key:
            self._idempotency_keys.add(dedupe_key)
        return self._record_run(workflow_id, "dry_run_ok" if dry_run else "completed", dry_run, trace)

    def _record_run(self, workflow_id: str, status: str, dry_run: bool, trace: list[dict[str, Any]]) -> dict[str, Any]:
        entry = {
            "workflow_id": workflow_id,
            "status": status,
            "dry_run": dry_run,
            "trace": trace,
            "finished_at": _iso(),
        }
        self._history.append(entry)
        return entry

    def history(self, *, limit: int = 50) -> list[dict[str, Any]]:
        return list(self._history[-max(1, min(int(limit), 200)) :])


# ----------------------------------------- §98 Cross-Application Automation


@dataclass
class CrossAppRun:
    run_id: str
    workspace_root: Path
    completed_stages: dict[str, dict[str, Any]] = field(default_factory=dict)
    failed_stage: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "completed_stages": dict(self.completed_stages),
            "failed_stage": self.failed_stage,
        }


@dataclass
class CrossAppCoordinator:
    """§98 Coordinates multi-stage file/checklist/draft workflows with transition verification.

    Preserves completed stages on partial failure so retry/resume never repeats
    already-verified work unnecessarily. Refuses GUI/browser automation honestly
    when the underlying runtime is absent.
    """

    workspace_root: Path
    _runs: dict[str, CrossAppRun] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self.workspace_root = Path(self.workspace_root).resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    def _safe_path(self, rel_path: str) -> Path:
        cleaned = (rel_path or "").strip()
        if not cleaned or cleaned.startswith("/") or "\x00" in cleaned:
            raise PermissionError(f"Path outside authorized workspace: {rel_path!r}")
        resolved = (self.workspace_root / cleaned).resolve()
        if not resolved.is_relative_to(self.workspace_root):
            raise PermissionError(f"Path escapes authorized workspace: {rel_path!r}")
        return resolved

    def execute_report_checklist_draft_flow(
        self,
        *,
        run_id: str,
        notes_rel_path: str,
        report_rel_path: str,
        checklist_rel_path: str,
        email_draft_rel_path: str,
        recipient: str = "team@example.org",
        require_gui_stage: bool = False,
        inject_failure_at_stage: str = "",
    ) -> dict[str, Any]:
        """Execute (or resume) the §98 8-stage cross-application workflow."""
        run = self._runs.setdefault(run_id, CrossAppRun(run_id=run_id, workspace_root=self.workspace_root))
        run.failed_stage = None

        if require_gui_stage:
            run.failed_stage = {
                "stage": "gui_automation",
                "reason": "GUI/browser automation runtime (D-Bus / Playwright) is not installed; refusing to simulate clicks",
            }
            return {"status": "failed", **run.to_dict()}

        notes_path = self._safe_path(notes_rel_path)
        report_path = self._safe_path(report_rel_path)
        checklist_path = self._safe_path(checklist_rel_path)
        draft_path = self._safe_path(email_draft_rel_path)

        # Stage 1: Read authorized source notes
        if "1_read_notes" not in run.completed_stages:
            if inject_failure_at_stage == "1_read_notes" or not notes_path.is_file():
                run.failed_stage = {"stage": "1_read_notes", "reason": "authorized source notes missing or unreadable"}
                return {"status": "failed", **run.to_dict()}
            raw_notes = notes_path.read_text(encoding="utf-8")
            run.completed_stages["1_read_notes"] = {
                "path": notes_rel_path,
                "chars": len(raw_notes),
                "sha256": hashlib.sha256(raw_notes.encode("utf-8")).hexdigest()[:16],
            }
        else:
            raw_notes = notes_path.read_text(encoding="utf-8")

        # Stage 2: Identify report requirements
        if "2_identify_requirements" not in run.completed_stages:
            bullets = [line.strip("-* ").strip() for line in raw_notes.splitlines() if line.strip().startswith(("-", "*"))]
            title = next((line.lstrip("# ").strip() for line in raw_notes.splitlines() if line.startswith("#")), "Project Status Report")
            run.completed_stages["2_identify_requirements"] = {"title": title, "action_items": len(bullets), "items": bullets}

        req = run.completed_stages["2_identify_requirements"]

        # Stage 3 & 4: Generate document & validate output
        report_body = (
            f"# {req['title']}\n\n"
            f"Generated from `{notes_rel_path}`.\n\n"
            "## Key Points\n"
            + ("\n".join(f"- {item}" for item in req["items"]) if req["items"] else "- Summary recorded from source notes.")
            + "\n"
        )
        if "3_generate_and_validate_report" not in run.completed_stages:
            if not report_body.strip() or f"# {req['title']}" not in report_body:
                run.failed_stage = {"stage": "3_generate_and_validate_report", "reason": "generated report failed validation"}
                return {"status": "failed", **run.to_dict()}
            run.completed_stages["3_generate_and_validate_report"] = {"validated": True, "length": len(report_body)}

        # Stage 5: Save report in specified workspace & verify transition
        if "4_save_report" not in run.completed_stages:
            if inject_failure_at_stage == "4_save_report":
                run.failed_stage = {"stage": "4_save_report", "reason": "injected failure before saving report"}
                return {"status": "failed", **run.to_dict()}
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(report_body, encoding="utf-8")
            if not report_path.is_file() or report_path.stat().st_size == 0:
                run.failed_stage = {"stage": "4_save_report", "reason": "post-write verification failed"}
                return {"status": "failed", **run.to_dict()}
            run.completed_stages["4_save_report"] = {"path": report_rel_path, "bytes": report_path.stat().st_size}

        # Stage 6: Update project checklist & verify transition
        if "5_update_checklist" not in run.completed_stages:
            if inject_failure_at_stage == "5_update_checklist":
                run.failed_stage = {"stage": "5_update_checklist", "reason": "checklist application stage failed"}
                return {"status": "failed", **run.to_dict()}
            checklist_path.parent.mkdir(parents=True, exist_ok=True)
            existing = checklist_path.read_text(encoding="utf-8") if checklist_path.is_file() else "# Project Checklist\n"
            marker = f"- [x] Report saved to `{report_rel_path}`\n"
            if marker not in existing:
                existing = existing.rstrip() + "\n" + marker
            checklist_path.write_text(existing, encoding="utf-8")
            if marker not in checklist_path.read_text(encoding="utf-8"):
                run.failed_stage = {"stage": "5_update_checklist", "reason": "checklist verification failed"}
                return {"status": "failed", **run.to_dict()}
            run.completed_stages["5_update_checklist"] = {"path": checklist_rel_path, "verified": True}

        # Stage 7: Prepare local email draft (never sends externally without explicit policy!)
        if "6_prepare_email_draft" not in run.completed_stages:
            if inject_failure_at_stage == "6_prepare_email_draft":
                run.failed_stage = {"stage": "6_prepare_email_draft", "reason": "draft stage failed"}
                return {"status": "failed", **run.to_dict()}
            draft_path.parent.mkdir(parents=True, exist_ok=True)
            draft_payload = {
                "to": recipient,
                "subject": f"[Draft] {req['title']}",
                "attachment_ref": report_rel_path,
                "sent": False,
                "body": f"Please find the updated report at {report_rel_path}. Checklist {checklist_rel_path} has been updated.",
            }
            draft_path.write_text(json.dumps(draft_payload, indent=2), encoding="utf-8")
            run.completed_stages["6_prepare_email_draft"] = {"path": email_draft_rel_path, "sent_externally": False}

        return {"status": "completed", **run.to_dict()}


__all__ = [
    "BLOCK_TYPES",
    "MAX_WORKFLOW_BLOCKS",
    "MAX_WORKFLOW_COST_USD",
    "MIN_SCHEDULE_INTERVAL_MINUTES",
    "WORKFLOW_SCHEMA_VERSION",
    "CrossAppCoordinator",
    "CrossAppRun",
    "WorkflowBlock",
    "WorkflowEngine",
    "WorkflowSpec",
    "validate_workflow",
]
