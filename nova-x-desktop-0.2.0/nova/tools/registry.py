"""Tool registry with explicit availability, schemas, and permission metadata."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Type

from pydantic import BaseModel, ValidationError

from nova.config import Settings


@dataclass
class ToolOutcome:
    status: str
    summary: str
    data: Any = None
    approval_payload: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"status": self.status, "summary": self.summary}
        if self.data is not None:
            result["data"] = self.data
        if self.approval_payload is not None:
            result["approval"] = self.approval_payload
        return result


ToolHandler = Callable[[BaseModel, bool], Awaitable[ToolOutcome]]


@dataclass
class ToolDefinition:
    name: str
    description: str
    parameters: dict[str, Any]
    input_model: Type[BaseModel]
    handler: ToolHandler
    permission: str
    available: bool = True
    unavailable_reason: str = ""
    category: str = "utility"
    autonomy_class: str = "approval_required"
    approval_preview: Callable[[dict[str, Any]], dict[str, Any]] | None = None

    def openai_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def public_info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "permission": self.permission,
            "available": self.available,
            "unavailable_reason": self.unavailable_reason,
            "category": self.category,
            "autonomy_class": self.autonomy_class,
        }


class ToolRegistry:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, definition: ToolDefinition) -> None:
        if definition.name in self._tools:
            raise ValueError(f"Tool already registered: {definition.name}")
        if definition.autonomy_class not in {"routine", "approval_required"}:
            raise ValueError("Tool autonomy_class must be 'routine' or 'approval_required'")
        self._tools[definition.name] = definition

    def get(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def all_tools(self) -> list[dict[str, Any]]:
        return [tool.public_info() for tool in self._tools.values()]

    def available_openai_tools(self) -> list[dict[str, Any]]:
        return [tool.openai_schema() for tool in self._tools.values() if tool.available]

    async def execute(self, name: str, arguments: Any, approved: bool = False) -> ToolOutcome:
        tool = self._tools.get(name)
        if tool is None:
            return ToolOutcome("error", f"Tool '{name}' is not registered.")
        if not tool.available:
            return ToolOutcome("error", tool.unavailable_reason or f"Tool '{name}' is not configured.")
        if not isinstance(arguments, dict):
            return ToolOutcome("error", "Tool arguments must be a JSON object.")
        try:
            parsed = tool.input_model.model_validate(arguments)
        except ValidationError as exc:
            issues = [f"{'.'.join(str(x) for x in item['loc'])}: {item['msg']}" for item in exc.errors()[:5]]
            return ToolOutcome("error", "Invalid tool arguments: " + "; ".join(issues))
        try:
            outcome = await tool.handler(parsed, approved)
        except Exception:
            # Tool exceptions are intentionally not reflected verbatim: file paths and
            # lower-level errors may contain sensitive host details.
            return ToolOutcome("error", "The tool failed safely. Check its inputs or local configuration.")
        if not isinstance(outcome, ToolOutcome):
            return ToolOutcome("error", "Tool returned an invalid result format.")
        return self._clip(outcome)

    def _clip(self, outcome: ToolOutcome) -> ToolOutcome:
        limit = self.settings.max_tool_output_chars
        remaining = [limit]

        def clip(value: Any) -> Any:
            if isinstance(value, str):
                if len(value) > remaining[0]:
                    result = value[: max(0, remaining[0])] + "… [truncated by NOVA output limit]"
                    remaining[0] = 0
                    return result
                remaining[0] -= len(value)
                return value
            if isinstance(value, list):
                out = []
                for item in value:
                    if remaining[0] <= 0:
                        out.append("[remaining output truncated]")
                        break
                    out.append(clip(item))
                return out
            if isinstance(value, dict):
                out = {}
                for key, item in value.items():
                    if remaining[0] <= 0:
                        out["_truncated"] = True
                        break
                    out[key] = clip(item)
                return out
            return value

        summary = clip(outcome.summary)
        data = clip(outcome.data) if outcome.data is not None else None
        approval = clip(outcome.approval_payload) if outcome.approval_payload is not None else None
        return ToolOutcome(outcome.status, summary, data, approval)

    @staticmethod
    def serialize_outcome(outcome: ToolOutcome) -> str:
        return json.dumps(outcome.as_dict(), ensure_ascii=False, separators=(",", ":"), default=str)
