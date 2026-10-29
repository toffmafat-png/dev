from __future__ import annotations

import pytest

from nova.config import Settings


def test_hugging_face_environment_fails_closed_without_access_token(monkeypatch):
    monkeypatch.setenv('SPACE_ID', 'owner/nova-x')
    monkeypatch.delenv('NOVA_ACCESS_TOKEN', raising=False)
    with pytest.raises(RuntimeError, match='Set NOVA_ACCESS_TOKEN'):
        Settings.from_env()


def test_autonomy_level_environment_is_bounded_to_the_four_supported_choices(monkeypatch):
    monkeypatch.delenv('SPACE_ID', raising=False)
    monkeypatch.delenv('NOVA_AUTONOMY_LEVEL', raising=False)
    assert Settings.from_env().autonomy_level == 'routine'
    monkeypatch.setenv('NOVA_AUTONOMY_LEVEL', 'assisted')
    assert Settings.from_env().autonomy_level == 'assisted'
    monkeypatch.setenv('NOVA_AUTONOMY_LEVEL', 'unlimited')
    assert Settings.from_env().autonomy_level == 'routine'


def test_goal_scheduler_limits_are_configurable_and_bounded(monkeypatch):
    monkeypatch.delenv('SPACE_ID', raising=False)
    monkeypatch.setenv('NOVA_GOAL_SCHEDULER_ENABLED', 'false')
    monkeypatch.setenv('NOVA_MAX_SCHEDULED_GOAL_RUNS_PER_DAY', '10000')
    monkeypatch.setenv('NOVA_GOAL_SCHEDULER_POLL_SECONDS', '1')
    settings = Settings.from_env()
    assert settings.goal_scheduler_enabled is False
    assert settings.max_scheduled_goal_runs_per_day == 100
    assert settings.goal_scheduler_poll_seconds == 10


def test_environment_model_does_not_enable_tool_calls_by_default(monkeypatch):
    monkeypatch.delenv('SPACE_ID', raising=False)
    monkeypatch.delenv('AI_MODEL_CAPABILITIES', raising=False)
    assert Settings.from_env().ai_model_capabilities == ('chat',)
    monkeypatch.setenv('AI_MODEL_CAPABILITIES', 'chat,tools')
    assert Settings.from_env().ai_model_capabilities == ('chat', 'tools')
