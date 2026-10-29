from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from nova.engine import TaskEngine


class BlockingProvider:
    def __init__(self):
        self.started = asyncio.Event()
        self.never = asyncio.Event()

    async def chat(self, messages, tools=None):
        self.started.set()
        await self.never.wait()
        raise AssertionError("unreachable")


@pytest.mark.asyncio
async def test_cancel_active_task_and_task_queued_on_semaphore(environment):
    settings, db, registry, _workspace = environment
    settings = replace(settings, max_parallel_tasks=1)
    provider = BlockingProvider()
    engine = TaskEngine(db, provider, registry, settings)
    active_id = db.create_task("A task that blocks in planning")
    queued_id = db.create_task("A second task queued behind the worker")
    engine.launch(active_id)
    await asyncio.wait_for(provider.started.wait(), timeout=2)
    engine.launch(queued_id)
    await asyncio.sleep(0.05)

    await engine.cancel(queued_id)
    assert db.get_task(queued_id)["state"] == "cancelled"
    await engine.cancel(active_id)
    assert db.get_task(active_id)["state"] == "cancelled"


@pytest.mark.asyncio
async def test_interrupted_running_task_is_recoverable(environment):
    _settings, db, _registry, _workspace = environment
    task_id = db.create_task("Task interrupted by restart")
    db.update_task(task_id, state="running", checkpoint={"plan": {"summary": "saved", "steps": ["resume"]}})
    recovered = db.recover_interrupted_tasks()
    task = db.get_task(task_id)
    assert recovered == 1
    assert task["state"] == "paused"
    assert task["checkpoint"]["plan"]["summary"] == "saved"
    assert db.get_task_events(task_id)[-1]["kind"] == "recovery"
