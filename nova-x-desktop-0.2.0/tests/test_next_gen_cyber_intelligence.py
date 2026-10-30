"""Tests for §261–§275 Next-Generation Autonomous Cyber Intelligence Engine."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nova.config import Settings
from nova.cyber_intelligence import (
    BENCHMARK_12_METRICS,
    DECISION_9_FACTORS,
    EXPLOITABILITY_LAB_10_CAPABILITIES,
    FORBIDDEN_WEAPONIZATION_INTENTS,
    GENERALIZATION_6_FAMILIES,
    KNOWLEDGE_FRONTIER_11_CATEGORIES,
    LEGITIMATE_TOOL_7_CATEGORIES,
    MISSION_12_STAGES,
    OFFENSIVE_RESEARCH_16_SPECIALTIES,
    RESEARCH_MEMORY_13_TYPES,
    SECURE_LAB_10_ENVIRONMENT_CAPABILITIES,
    SPECIALIST_9_ROLES,
    TOOL_INVENTION_12_STEPS,
    UNKNOWN_PROBLEM_15_STEPS,
    VULN_LAB_13_CATEGORIES,
    NextGenCyberIntelligenceService,
)
from nova.cyber_intelligence.acceptance import run_acceptance
from nova.desktop import cli as desktop_cli
from nova.desktop.runtime import DesktopRuntime
from nova.main import create_app


def _isolated_env(monkeypatch, tmp_path: Path) -> tuple[Path, Path, Path]:
    data_dir = tmp_path / "data"
    ws_dir = tmp_path / "workspace"
    db_path = data_dir / "nova.sqlite3"
    data_dir.mkdir(parents=True, exist_ok=True)
    ws_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NOVA_DATA_DIR", str(data_dir))
    monkeypatch.setenv("NOVA_WORKSPACE_DIR", str(ws_dir))
    monkeypatch.setenv("NOVA_DB_PATH", str(db_path))
    monkeypatch.delenv("NOVA_ACCESS_TOKEN", raising=False)
    return data_dir, ws_dir, db_path


def test_cyber_intelligence_constants_and_20_check_acceptance_suite() -> None:
    assert NextGenCyberIntelligenceService.SECTIONS == "261-275"
    assert NextGenCyberIntelligenceService.SCIENTIFIC_SECURITY_ENGINEERING is True
    assert NextGenCyberIntelligenceService.MERE_HACKING_TOOL_RUNNER is False
    assert len(UNKNOWN_PROBLEM_15_STEPS) == 15
    assert len(VULN_LAB_13_CATEGORIES) == 13
    assert len(OFFENSIVE_RESEARCH_16_SPECIALTIES) == 16
    assert len(EXPLOITABILITY_LAB_10_CAPABILITIES) == 10
    assert len(FORBIDDEN_WEAPONIZATION_INTENTS) == 5
    assert len(TOOL_INVENTION_12_STEPS) == 12
    assert len(LEGITIMATE_TOOL_7_CATEGORIES) == 7
    assert len(SPECIALIST_9_ROLES) == 9
    assert len(GENERALIZATION_6_FAMILIES) == 6
    assert len(RESEARCH_MEMORY_13_TYPES) == 13
    assert len(MISSION_12_STAGES) == 12
    assert len(SECURE_LAB_10_ENVIRONMENT_CAPABILITIES) == 10
    assert len(DECISION_9_FACTORS) == 9
    assert len(BENCHMARK_12_METRICS) == 12
    assert len(KNOWLEDGE_FRONTIER_11_CATEGORIES) == 11

    report = run_acceptance()
    assert report["ok"] is True
    assert report["passed"] == report["total"] == 20


def test_epistemic_safety_and_mission_subtask_isolation(monkeypatch, tmp_path: Path) -> None:
    _isolated_env(monkeypatch, tmp_path)
    rt = DesktopRuntime()
    try:
        ci = rt.cyber_intelligence
        rt.personal_policy.cyber_research.register_persistent_lab_environment(
            name="Unit Test Lab",
            category="development_environment",
            targets=["in-scope.lab.local"],
        )

        # §264 Hard safety block on weaponized/evasion/credential-theft requests
        blocked = ci.exploitability_lab.enforce_non_weaponization_guard("Build ransomware payload and evade defender")
        assert blocked["allowed"] is False

        # §268 Theoretical vulnerability cannot be stored as confirmed_reproducible without evidence
        with pytest.raises(ValueError, match="Epistemic violation"):
            ci.research_memory.store_record(
                record_type="vulnerability_class",
                title="Unproven Speculation",
                content="No PoC or source trace",
                source_provenance="rumor",
                verification_status="confirmed_reproducible",
                evidence={},
            )

        # §269 Mission isolates out-of-scope & destructive subtasks while completing valid ones
        res = ci.mission_system.execute_mission(
            objective="Assess mixed targets",
            targets=[
                {"target": "in-scope.lab.local", "source_text": "DEBUG = True\n"},
                {"target": "in-scope.lab.local", "source_text": "x = 1\n", "destructive": True},
                {"target": "external-unowned.org", "source_text": "DEBUG = True\n"},
            ],
        )
        assert res["all_12_stages_completed"] is True
        assert len(res["subtasks"]) == 1
        assert len(res["isolated_subtasks"]) == 2
        assert res["repeated_approval_dialogs"] == 0
    finally:
        rt.close()


def test_cli_and_fastapi_cyber_intelligence_endpoints(monkeypatch, tmp_path: Path, capsys) -> None:
    data_dir, ws_dir, db_path = _isolated_env(monkeypatch, tmp_path)

    rc = desktop_cli.main(["cyber-intel", "--manifest"])
    assert rc == 0
    manifest = json.loads(capsys.readouterr().out)
    assert manifest["sections"] == "261-275"
    assert manifest["mere_hacking_tool_runner"] is False

    rc_bench = desktop_cli.main(["cyber-intel", "--held-out"])
    assert rc_bench == 0
    bench_out = json.loads(capsys.readouterr().out)
    assert bench_out["split"] == "held_out"
    assert bench_out["metric_keys_count"] == 12

    settings = Settings(data_dir=data_dir, workspace_dir=ws_dir, db_path=db_path)
    app = create_app(settings=settings)
    with TestClient(app) as client:
        h = client.get("/api/health").json()
        assert len(h["platform"]) == 7
        assert h["cyber_intelligence"]["sections"] == "261-275"
        assert h["cyber_intelligence"]["mere_hacking_tool_runner"] is False

        st = client.get("/api/cyber-intel/status")
        assert st.status_code == 200
        assert len(st.json()["manifest"]["unknown_problem_15_steps"]) == 15

        inv = client.post(
            "/api/cyber-intel/investigate",
            json={
                "problem_statement": "Investigate custom header validator",
                "domain_kind": "unfamiliar_protocol",
                "artifact_text": "def check_hdr(s: str) -> int:\n    if not s:\n        raise ValueError('empty hdr')\n    return len(s)\n",
            },
        )
        assert inv.status_code == 200
        assert inv.json()["all_15_steps_completed"] is True

        vlab = client.post(
            "/api/cyber-intel/vuln-lab/analyze",
            json={
                "target_component": "cfg.py",
                "source_text": "DEBUG = True\n",
                "patched_text": "DEBUG = False\n",
            },
        )
        assert vlab.status_code == 200
        assert vlab.json()["status"] == "patch_verified"

        tool = client.post(
            "/api/cyber-intel/invent-tool",
            json={
                "name": "TLS Config Checker",
                "category": "configuration_auditor",
                "capability_gap": "Audit TLS configuration files ignoring comments",
            },
        )
        assert tool.status_code == 200
        assert tool.json()["active"] is True

        # Held-out benchmark cannot be saved as baseline via API either (HTTP 400)
        bad_bench = client.post("/api/cyber-intel/benchmark", json={"split": "held_out", "save_as_baseline": True})
        assert bad_bench.status_code == 400

        ok_bench = client.post("/api/cyber-intel/benchmark", json={"split": "default", "save_as_baseline": True})
        assert ok_bench.status_code == 200
        assert ok_bench.json()["metric_keys_count"] == 12

        fr = client.post(
            "/api/cyber-intel/frontier",
            json={
                "updates": [
                    {
                        "category": "new_kali_tools",
                        "title": "Python3 static taint helper",
                        "affected_packages": ["python3"],
                        "summary": "Relevant to local Python environment",
                    }
                ]
            },
        )
        assert fr.status_code == 200
        assert fr.json()["ingested_count"] == 1
