from __future__ import annotations

import json

import pytest

from nova.engine import TaskEngine
from tests.conftest import FakeProvider, msg


@pytest.mark.asyncio
async def test_multistep_task_uses_real_tool_and_verifies(environment):
    settings, db, registry, _workspace = environment
    provider = FakeProvider([
        msg('{"summary":"Calculate the requested percentage.","steps":["Compute 18 percent of 2450","Report the result"]}'),
        msg(None, [{
            "id": "call-1", "type": "function",
            "function": {"name": "math.calculate", "arguments": json.dumps({"expression": "2450 * 0.18"})},
        }]),
        msg("18% of 2,450 is 441. The calculator tool returned 441.0."),
        msg('{"status":"verified","note":"The arithmetic tool produced 441.0, supporting the requested calculation."}'),
    ])
    task_id = db.create_task("Calculate 18% of 2450", review_plan=False)
    db.add_event(task_id, "status", "Task queued")
    engine = TaskEngine(db, provider, registry, settings)
    await engine.run_task(task_id)

    task = db.get_task(task_id)
    assert task["state"] == "completed"
    assert task["verification"] == "verified"
    assert "441" in task["result"]
    assert task["tool_call_count"] == 1
    assert task["request_count"] == 4
    assert task["token_usage"] == 32
    assert any(event["kind"] == "tool_result" for event in db.get_task_events(task_id))


@pytest.mark.asyncio
async def test_overwrite_requires_approval_and_backups(environment):
    settings, db, registry, workspace = environment
    existing = workspace / "brief.txt"
    existing.write_text("old content", encoding="utf-8")
    provider = FakeProvider([
        msg('{"summary":"Update the named brief.","steps":["Write the requested content"]}'),
        msg(None, [{
            "id": "call-write", "type": "function",
            "function": {"name": "workspace.write_file", "arguments": json.dumps({"path": "brief.txt", "content": "new content"})},
        }]),
        msg("The approved file update is complete. A backup was created."),
        msg('{"status":"verified","note":"The file tool verified the saved output and retained the previous copy."}'),
    ])
    task_id = db.create_task("Update brief.txt with new content", review_plan=False)
    engine = TaskEngine(db, provider, registry, settings)
    await engine.run_task(task_id)
    waiting = db.get_task(task_id)
    assert waiting["state"] == "waiting_approval"
    assert existing.read_text(encoding="utf-8") == "old content"
    assert waiting["checkpoint"]["pending_action"]["name"] == "workspace.write_file"

    checkpoint = waiting["checkpoint"]
    checkpoint["approval_decision"] = True
    db.update_task(task_id, state="queued", checkpoint=checkpoint)
    await engine.run_task(task_id)
    done = db.get_task(task_id)
    assert done["state"] == "completed"
    assert existing.read_text(encoding="utf-8") == "new content"
    backups = list((workspace / ".nova_backups").glob("*.bak"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "old content"


@pytest.mark.asyncio
async def test_current_explicit_tool_deny_overrides_a_stale_pending_approval(environment):
    settings, db, registry, workspace = environment
    existing = workspace / "drafts" / "protected.txt"
    existing.parent.mkdir()
    existing.write_text("keep this", encoding="utf-8")
    db.update_autonomy_policy("routine", {"workspace.write_file": "deny"}, [])
    provider = FakeProvider([
        msg("The file remains unchanged because the current policy denies this tool."),
        msg('{"status":"unverified","note":"The latest policy denied the write."}'),
    ])
    task_id = db.create_task("Update protected.txt")
    checkpoint = {
        "plan": {"summary": "Previously authorized plan", "steps": ["Write the file"]},
        "pending_action": {
            "name": "workspace.write_file",
            "arguments": {"path": "drafts/protected.txt", "content": "replace this"},
            "tool_call_id": "stale-approval",
        },
        "waiting_kind": "tool",
        "approval_decision": True,
        "autonomy_level_started": "assisted",
    }
    db.update_task(task_id, state="queued", checkpoint=checkpoint)
    engine = TaskEngine(db, provider, registry, settings)
    await engine.run_task(task_id)

    task = db.get_task(task_id)
    assert task["state"] == "completed"
    assert existing.read_text(encoding="utf-8") == "keep this"
    results = task["checkpoint"]["tool_results"]
    assert results[-1]["status"] == "denied"
    assert "current autonomy policy" in results[-1]["summary"]


@pytest.mark.asyncio
async def test_plan_review_pauses_and_can_be_edited(environment):
    settings, db, registry, _workspace = environment
    provider = FakeProvider([
        msg('{"summary":"Initial plan","steps":["First step"]}'),
        msg("Task completed from the revised plan."),
        # no tool evidence, so no verification request is expected
    ])
    task_id = db.create_task("Do a simple task", review_plan=True)
    engine = TaskEngine(db, provider, registry, settings)
    await engine.run_task(task_id)
    waiting = db.get_task(task_id)
    assert waiting["state"] == "waiting_approval"
    assert waiting["checkpoint"]["waiting_kind"] == "plan_review"

    plan = {"summary": "Revised plan", "steps": ["Revised step"]}
    checkpoint = waiting["checkpoint"]
    checkpoint["plan"] = plan
    checkpoint["approval_decision"] = True
    db.update_task(task_id, state="queued", plan=plan, checkpoint=checkpoint)
    await engine.run_task(task_id)
    done = db.get_task(task_id)
    assert done["state"] == "completed"
    assert done["plan"] == plan
    assert done["verification"] == "unverified"
