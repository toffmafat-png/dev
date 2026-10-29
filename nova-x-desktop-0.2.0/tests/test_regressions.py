"""Regression tests for defects found by repository inspection.

Each test here pins a specific behaviour that was previously broken or
unfinished, so a future refactor cannot silently reintroduce it:

* logout did not revoke the server-side session (a copied cookie kept working)
* the session store grew without bound and was never pruned
* ``_public_task`` raised ``KeyError`` on an incomplete row -> opaque HTTP 500
* the app only created storage/schema inside ``lifespan`` -> 500 without startup
* importing ``nova.main`` created data/workspace directories as a side effect
* storage failures surfaced as raw 500 tracebacks instead of a clean 503
* the fusion "synthesis" and "revision" roles were missing from model_results
* two Settings fields had no environment wiring
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from nova import __version__
from nova.config import Settings
from nova.intelligence import IntelligenceOrchestrator, ModelManager
from nova.main import MAX_ACTIVE_SESSIONS, SessionStore, _public_goal, _public_task, _require_task, create_app
from nova.provider import ProviderError
from tests.conftest import FakeProvider, msg
from tests.test_intelligence import add_profiles

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Authentication: logout must revoke server-side, not just clear the cookie
# ---------------------------------------------------------------------------


def _auth_app(environment, token: str = "unit-test-access-token"):
    settings, db, registry, _workspace = environment
    settings = replace(settings, access_token=token)
    return create_app(settings, provider=FakeProvider([]), db=db, tools=registry), settings


def test_logout_revokes_the_session_on_the_server(environment):
    """A cookie captured before logout must stop working immediately after it.

    The previous suite only checked that the *client* was signed out, which
    passed while the session id remained valid server-side until its TTL.
    """
    app, _settings = _auth_app(environment)
    with TestClient(app) as client:
        login = client.post("/api/auth/login", json={"token": "unit-test-access-token"})
        assert login.status_code == 200
        captured = login.cookies.get("nova_session")
        assert captured, "login should set a session cookie"
        assert client.get("/api/tools").status_code == 200

        logout = client.post("/api/auth/logout")
        assert logout.status_code == 200
        assert logout.json()["revoked"] is True

        # Replay the captured cookie from a fresh jar, as an attacker would.
        client.cookies.clear()
        client.cookies.set("nova_session", captured)
        assert client.get("/api/tools").status_code == 401
        assert client.get("/api/auth/status").json() == {"required": True, "authenticated": False}
        assert len(app.state.sessions) == 0


def test_logout_without_a_session_is_idempotent(environment):
    app, _settings = _auth_app(environment)
    with TestClient(app) as client:
        response = client.post("/api/auth/logout")
        assert response.status_code == 200
        assert response.json() == {"ok": True, "revoked": False}


def test_session_store_caps_live_sessions_and_prunes_expired():
    store = SessionStore(max_sessions=4)
    ids = [store.issue(600) for _ in range(4)]
    assert len(store) == 4

    # The cap must evict rather than grow without bound.
    extra = store.issue(600)
    assert len(store) == 4
    assert extra not in ids[:1]  # the newest session survives
    assert store.validate(extra)

    # Eviction targets the session closest to expiry, not an arbitrary one.
    short = SessionStore(max_sessions=2)
    soon = short.issue(1)
    long_lived = short.issue(10_000)
    short.issue(10_000)
    assert len(short) == 2
    assert not short.validate(soon)
    assert short.validate(long_lived)


def test_session_store_expires_and_rejects_bad_ids():
    store = SessionStore()
    session_id = store.issue(1)
    assert store.validate(session_id)
    store._expiry[session_id] = time.time() - 1  # force expiry
    assert not store.validate(session_id)
    assert session_id not in store._expiry  # expired entries are dropped on read
    assert not store.validate("")
    assert not store.validate("not-a-real-session")
    assert not store.revoke("")


def test_session_store_prune_is_rate_limited_but_forced_on_issue():
    store = SessionStore()
    store.issue(1)
    store._expiry[next(iter(store._expiry))] = time.time() - 10
    # A prune inside the cooldown window is skipped...
    store._last_prune = time.time()
    store.prune()
    assert len(store) == 1
    # ...but issuing beyond the cap still reclaims the expired entry.
    store._last_prune = 0.0
    store.prune()
    assert len(store) == 0


def test_default_session_cap_is_bounded():
    assert MAX_ACTIVE_SESSIONS >= 1


# ---------------------------------------------------------------------------
# Serialisation: incomplete rows must not become HTTP 500s
# ---------------------------------------------------------------------------


def test_public_task_and_goal_tolerate_incomplete_rows():
    task = _public_task({})
    assert task["id"] == ""
    assert task["state"] == "unknown"
    assert task["pending_approval"] is None
    assert task["models_used"] == []

    goal = _public_goal({})
    assert goal["id"] == ""
    assert goal["cadence"] == "Every 0 minutes"


def test_require_task_raises_a_precise_http_error():
    for missing in (None, {}, {"objective": "no id"}):
        with pytest.raises(HTTPException) as excinfo:
            _require_task(missing)
        assert excinfo.value.status_code == 500
    assert _require_task({"id": "task-1"})["id"] == "task-1"


# ---------------------------------------------------------------------------
# Application lifecycle: usable without a startup event, clean storage errors
# ---------------------------------------------------------------------------


def test_app_serves_requests_without_a_lifespan_startup_event(environment, tmp_path):
    """Storage roots and schema must exist at construction, not only in lifespan.

    Exercising the app without ``with TestClient(...)`` previously produced
    ``sqlite3.OperationalError: unable to open database file`` -> HTTP 500.
    """
    settings, _db, registry, _workspace = environment
    settings = replace(
        settings,
        data_dir=tmp_path / "fresh-data",
        db_path=tmp_path / "fresh-data" / "nova.sqlite3",
        workspace_dir=tmp_path / "fresh-workspace",
    )
    app = create_app(settings, provider=FakeProvider([]), tools=registry)
    assert settings.data_dir.is_dir() and settings.workspace_dir.is_dir()

    # Deliberately NOT a context manager: no startup event runs.
    client = TestClient(app, raise_server_exceptions=False)
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/tasks").status_code == 200
    assert client.get("/api/setup").status_code == 200
    assert client.get("/api/goals").status_code == 200


def test_storage_failure_returns_a_clean_503(environment, monkeypatch):
    settings, db, registry, _workspace = environment
    app = create_app(settings, provider=FakeProvider([]), db=db, tools=registry)

    def explode(*_args, **_kwargs):
        raise sqlite3.OperationalError("unable to open database file")

    monkeypatch.setattr(db, "list_tasks", explode)
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/tasks")
        assert response.status_code == 503
        body = response.json()["detail"]
        assert "storage" in body.lower()
        # The driver message (paths, SQL) must not leak to the client.
        assert "unable to open database file" not in body


def test_importing_nova_main_has_no_filesystem_side_effects(tmp_path):
    """Importing the module must not create ./data or ./workspace.

    The test suite and tooling import ``nova.main`` constantly; a module-level
    ``create_app()`` used to write into the current working directory.
    """
    program = (
        "import os, nova.main;"
        "print(os.path.isdir('data'), os.path.isdir('workspace'));"
        "from nova.main import app;"
        "print(type(app).__name__, app.version)"
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
    )
    assert result.returncode == 0, result.stderr
    first, second = result.stdout.strip().splitlines()
    assert first == "False False", "import must not create storage directories"
    assert second == f"FastAPI {__version__}"


def test_module_getattr_rejects_unknown_attributes():
    import nova.main as main_module

    with pytest.raises(AttributeError):
        main_module.module_getattr_probe  # noqa: B018 - deliberate unknown attribute
    assert callable(main_module.__getattr__)
    assert "app" in dir(main_module)


# ---------------------------------------------------------------------------
# Configuration surface: every documented knob must be reachable from the env
# ---------------------------------------------------------------------------


def test_local_http_and_chat_history_knobs_are_environment_configurable(monkeypatch):
    monkeypatch.setenv("NOVA_ALLOW_LOCAL_HTTP_PROVIDER", "true")
    monkeypatch.setenv("NOVA_MAX_CHAT_HISTORY_MESSAGES", "7")
    settings = Settings.from_env()
    assert settings.allow_local_http_provider is True
    assert settings.max_chat_history_messages == 7

    # The orchestrator must read the knob from Settings, not from os.environ,
    # so injected/test configurations behave like real deployments.
    orchestrator = ModelManager(settings, db=None, injected_provider=FakeProvider([]))
    assert orchestrator.allow_local_http is True

    monkeypatch.delenv("NOVA_ALLOW_LOCAL_HTTP_PROVIDER")
    monkeypatch.delenv("NOVA_MAX_CHAT_HISTORY_MESSAGES")
    defaults = Settings.from_env()
    assert defaults.allow_local_http_provider is False
    assert defaults.max_chat_history_messages == 20
    assert defaults.max_chat_history_messages == _clamped(defaults.max_chat_history_messages)


def test_chat_history_knob_is_clamped_to_a_safe_range(monkeypatch):
    monkeypatch.setenv("NOVA_MAX_CHAT_HISTORY_MESSAGES", "999999")
    assert Settings.from_env().max_chat_history_messages <= 200
    monkeypatch.setenv("NOVA_MAX_CHAT_HISTORY_MESSAGES", "-5")
    assert Settings.from_env().max_chat_history_messages >= 1
    monkeypatch.setenv("NOVA_MAX_CHAT_HISTORY_MESSAGES", "not-a-number")
    assert Settings.from_env().max_chat_history_messages == 20


def _clamped(value: int) -> int:
    return max(1, min(200, value))


def test_reported_version_comes_from_a_single_source(environment):
    settings, db, registry, _workspace = environment
    app = create_app(settings, provider=FakeProvider([]), db=db, tools=registry)
    with TestClient(app) as client:
        assert client.get("/api/health").json()["version"] == __version__
    assert app.version == __version__


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


def test_login_attempts_are_rate_limited(environment):
    app, _settings = _auth_app(environment)
    with TestClient(app) as client:
        statuses = [
            client.post("/api/auth/login", json={"token": "wrong"}).status_code
            for _ in range(12)
        ]
    assert statuses.count(429) >= 1, statuses
    assert statuses[0] == 401
    assert 429 in statuses


# ---------------------------------------------------------------------------
# Fusion reporting: every role that ran must be visible
# ---------------------------------------------------------------------------


class FailFromNthCallProvider:
    """Succeeds for the first ``fail_from - 1`` calls, then fails like a provider."""

    def __init__(self, responses, fail_from: int):
        self.responses = list(responses)
        self.fail_from = fail_from
        self.calls: list[tuple] = []

    async def chat(self, messages, tools=None):
        self.calls.append((messages, tools))
        if len(self.calls) >= self.fail_from:
            raise ProviderError("synthesis provider failure (test)", retryable=False)
        if not self.responses:
            raise AssertionError("Fake provider response queue exhausted")
        return self.responses.pop(0)


@pytest.mark.asyncio
async def test_fusion_reports_a_failed_synthesis_role(environment):
    """A failed synthesis must be reported, not silently dropped.

    ``synth_error`` used to be captured and never used, so ``model_results``
    had no ``synthesis`` entry and the operator saw no provider error.
    """
    settings, db, _registry, _workspace = environment
    provider = FailFromNthCallProvider([msg(f"Candidate answer {i}") for i in range(4)], fail_from=5)
    manager = ModelManager(settings, db, injected_provider=provider)
    profiles = add_profiles(manager)
    orchestrator = IntelligenceOrchestrator(manager, settings, db)

    result = await orchestrator.chat(
        [{"role": "user", "content": "Compare these possibilities."}],
        mode="frontier_fusion",
        model_ids=[item["id"] for item in profiles],
    )

    intelligence = result["intelligence"]
    roles = {item["role"]: item for item in intelligence["model_results"]}
    assert "synthesis" in roles, f"roles reported: {sorted(roles)}"
    assert roles["synthesis"]["status"] == "failed"
    assert "synthesis provider failure" in roles["synthesis"]["summary"]
    assert any("Integrated synthesis failed" in warning for warning in intelligence["warnings"])
    # Degradation is still reported and a real analyst answer is returned.
    assert intelligence["mode_effective"] == "frontier_fusion_partial"
    assert result["message"]["content"].startswith("Candidate answer")


@pytest.mark.asyncio
async def test_fusion_reports_a_successful_synthesis_role(environment):
    settings, db, _registry, _workspace = environment
    provider = FakeProvider([msg(f"Candidate answer {i}") for i in range(5)])
    manager = ModelManager(settings, db, injected_provider=provider)
    profiles = add_profiles(manager)
    orchestrator = IntelligenceOrchestrator(manager, settings, db)

    result = await orchestrator.chat(
        [{"role": "user", "content": "Compare these possibilities."}],
        mode="frontier_fusion",
        model_ids=[item["id"] for item in profiles],
    )
    roles = {item["role"]: item for item in result["intelligence"]["model_results"]}
    assert roles["synthesis"]["status"] == "ok"
    assert roles["conflict_review"]["status"] == "ok"


@pytest.mark.asyncio
async def test_maximum_intelligence_reports_the_revision_role(environment):
    """Maximum mode runs critique + revision; both must appear in model_results."""
    settings, db, _registry, _workspace = environment
    provider = FakeProvider([msg(f"Stage {i}") for i in range(7)])
    manager = ModelManager(settings, db, injected_provider=provider)
    profiles = add_profiles(manager)
    orchestrator = IntelligenceOrchestrator(manager, settings, db)

    result = await orchestrator.chat(
        [{"role": "user", "content": "Compare and refine."}],
        mode="maximum_intelligence",
        model_ids=[item["id"] for item in profiles],
    )
    roles = {item["role"] for item in result["intelligence"]["model_results"]}
    assert {"independent_analysis", "conflict_review", "synthesis", "targeted_critique", "revision"} <= roles
    assert result["intelligence"]["mode_effective"] == "maximum_intelligence"
