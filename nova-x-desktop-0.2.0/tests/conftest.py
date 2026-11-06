from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from nova.config import Settings
from nova.db import Database
from nova.tools import ToolRegistry, build_calculator_tool, build_research_tool, build_workspace_tools


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.failed and os.environ.get("GITHUB_ACTIONS") == "true":
        detail = str(report.longreprtext or report.longrepr or "failed").splitlines()
        tail = " | ".join(line.strip() for line in detail[-8:] if line.strip())[:900]
        print(
            f"::error title=Pytest failure::{report.nodeid} ({report.when}): {tail}",
            file=sys.stderr,
        )


class FakeProvider:
    def __init__(self, responses: list[dict[str, Any]] | None = None):
        self.responses = list(responses or [])
        self.calls: list[tuple[list[dict[str, Any]], list[dict[str, Any]] | None]] = []

    async def chat(self, messages, tools=None):
        self.calls.append((messages, tools))
        if not self.responses:
            raise AssertionError("Fake provider response queue exhausted")
        return self.responses.pop(0)


def msg(content: str | None = None, tool_calls: list[dict[str, Any]] | None = None):
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return {"message": message, "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}}


def calculator_call(expression: str = "18%" ):
    return msg(None, [{
        "id": "call-calculator-1",
        "type": "function",
        "function": {"name": "math.calculate", "arguments": json.dumps({"expression": expression})},
    }])


@pytest.fixture
def environment(tmp_path: Path):
    data_dir = tmp_path / "data"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        data_dir=data_dir,
        workspace_dir=workspace,
        db_path=data_dir / "nova.sqlite3",
        ai_base_url="https://unit.test/v1",
        ai_api_key="test-only-not-a-real-key",
        ai_model="test-model",
        ai_model_capabilities=("chat", "tools"),
        ai_timeout_seconds=5,
        max_task_steps=5,
        max_ai_requests_per_task=10,
        max_retries=0,
        max_task_seconds=30,
        max_parallel_tasks=1,
        max_tool_output_chars=12_000,
        max_request_chars=12_000,
        max_file_bytes=512 * 1024,
        verify_tasks=True,
        access_token="",
    )
    settings.ensure_dirs()
    db = Database(settings.db_path)
    db.initialize()
    registry = ToolRegistry(settings)
    registry.register(build_calculator_tool())
    for definition in build_workspace_tools(settings):
        registry.register(definition)
    registry.register(build_research_tool(settings))
    return settings, db, registry, workspace
