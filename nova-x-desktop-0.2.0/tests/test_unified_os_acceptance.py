"""§1–§27 Unified Universal AI Operating System tests & 18-point acceptance suite."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from nova.acceptance import run_acceptance_suite
from nova.desktop import cli as desktop_cli
from nova.main import create_app
from nova.model_providers import OllamaAdapter, ProviderError, check_local_model_resource_fit


@pytest.mark.asyncio
async def test_all_18_master_acceptance_checks_pass() -> None:
    report = await run_acceptance_suite()
    failed = [item for item in report["results"] if not item["passed"]]
    assert report["total"] == 18
    assert not failed, f"Acceptance failures: {failed}"
    assert report["all_passed"] is True
    mat = report["capability_matrix"]
    assert set(mat) == {"implemented", "tested", "untested", "unconfigured", "planned"}
    assert len(mat["implemented"]) >= 8


def test_ollama_local_resource_fit_and_keyless_profile(environment) -> None:
    settings, database, _registry, _workspace = environment
    from nova.intelligence import ModelManager

    fit_small = check_local_model_resource_fit("qwen2.5-coder:1.5b", available_ram_mb=10_240)
    fit_huge = check_local_model_resource_fit("llama3.1:70b", available_ram_mb=10_240)
    assert fit_small["fits_resource_budget"] is True
    assert fit_huge["fits_resource_budget"] is False

    mm = ModelManager(settings, database)
    profile = mm.create_profile(
        {
            "name": "Local Ollama 1.5B",
            "provider_type": "ollama",
            "base_url": "http://127.0.0.1:11434/v1",
            "model_id": "qwen2.5-coder:1.5b",
            "api_key_env": "",
        }
    )
    assert profile["configured"] is True
    assert profile["provider_type"] == "ollama"
    assert profile["api_key_env"] == ""


@pytest.mark.asyncio
async def test_ollama_adapter_loopback_and_oversized_guard() -> None:
    adapter = OllamaAdapter(timeout_seconds=10, allow_local_http=True)
    with (
        patch(
            "nova.model_providers.check_local_model_resource_fit",
            return_value={"fits_resource_budget": False, "reason": "Exceeds safe local RAM ceiling"},
        ),
        pytest.raises(ProviderError, match="RAM"),
    ):
        await adapter.chat(
            api_key_env="",
            base_url="http://127.0.0.1:11434/v1",
            model_id="llama3:70b",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_output_tokens=256,
        )

    fake_body = {
        "choices": [{"message": {"role": "assistant", "content": "Local response ok"}}],
        "usage": {"prompt_tokens": 9, "completion_tokens": 5, "total_tokens": 14},
    }
    with (
        patch(
            "nova.model_providers.check_local_model_resource_fit",
            return_value={"fits_resource_budget": True, "reason": "Fits local memory budget."},
        ),
        patch.object(adapter, "_request", AsyncMock(return_value=fake_body)),
    ):
        res = await adapter.chat(
            api_key_env="",
            base_url="http://127.0.0.1:11434/v1",
            model_id="qwen2.5:1.5b",
            messages=[{"role": "user", "content": "hello"}],
            tools=None,
            max_output_tokens=256,
        )
    assert res["message"]["content"] == "Local response ok"
    assert res["usage"]["total_tokens"] == 14


def test_unified_os_api_endpoints_and_memory_epistemics(environment) -> None:
    settings, database, registry, _workspace = environment
    app = create_app(settings=settings, db=database, tools=registry)
    with TestClient(app) as client:
        health = client.get("/api/health").json()
        assert health["unified_os"]["degraded"] is False
        assert health["unified_os"]["modules"] == 12

        manifest = client.get("/api/os/manifest").json()
        assert len(manifest["modules"]) == 12
        assert len(manifest["operating_modes"]) == 4

        # Model inference cannot self-upgrade to verified_fact without verified evidence
        stored = client.post(
            "/api/os/memory",
            json={
                "category": "ongoing_objectives",
                "subject": "Cache speedup hypothesis",
                "content": "Memoizing AST parse should cut latency by 20%.",
                "provenance": "model_inference",
                "evidence_verified": False,
            },
        )
        assert stored.status_code == 200
        entry = stored.json()["entry"]
        assert entry["verified_fact"] is False

        # Raw secret must be rejected with 400
        bad = client.post(
            "/api/os/memory",
            json={
                "category": "user_preferences",
                "subject": "Secret leak",
                "content": "sk-abcdefghijklmnopqrstuvwxyz123456",
            },
        )
        assert bad.status_code == 400

        hits = client.get("/api/os/memory", params={"query": "Memoizing AST"}).json()
        assert len(hits["snippets"]) >= 1
        assert hits["snippets"][0]["verified_fact"] is False

        worker = client.get("/api/os/worker").json()
        assert worker["running"] is False
        assert "not running" in worker["honesty_note"].lower()

        pipe = client.post(
            "/api/os/pipeline",
            json={
                "prompt": "Create an SVG vector icon badge and PNG raster export",
                "domain_override": "graphics",
                "package": True,
            },
        )
        assert pipe.status_code == 200
        pdata = pipe.json()
        assert len(pdata["stages"]) == 11
        assert pdata["deliverable"]["qa"]["passed"] is True
        assert Path(pdata["deliverable"]["package"]["archive_path"]).is_file()


def test_cli_setup_and_worker_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("NOVA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("NOVA_WORKSPACE_DIR", str(tmp_path / "ws"))
    rc_setup = desktop_cli.main(["setup"])
    assert rc_setup == 0
    setup_json = json.loads(capsys.readouterr().out)
    assert setup_json["root_required"] is False
    assert setup_json["running_as_root"] is False

    rc_worker = desktop_cli.main(["worker", "--once"])
    assert rc_worker == 0
    worker_json = json.loads(capsys.readouterr().out)
    assert worker_json["worker"]["worker_id"] == "nova-x-cli-worker"
