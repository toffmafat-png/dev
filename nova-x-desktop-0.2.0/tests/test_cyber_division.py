"""Comprehensive tests for §201–§220 Autonomous Cybersecurity, Vulnerability Research & Security Engineering Division."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from nova.autonomy import AutonomyPolicy
from nova.config import Settings
from nova.cyber_division import (
    ATTACK_SURFACE_14_CATEGORIES,
    EPISTEMIC_7_FINDING_STATES,
    LIFECYCLE_STATES_ORDERED,
    RESEARCH_EPISTEMIC_8_FIELDS,
    SCOPE_10_CATEGORIES,
    TOOL_FACTORY_17_CATEGORIES,
    TUTOR_17_DISCIPLINES,
    UNIFIED_CORE_16_DOMAINS,
    VULNERABILITY_22_CATEGORIES,
)
from nova.cyber_division.acceptance import run_cyber_division_acceptance
from nova.db import Database
from nova.desktop import cli as desktop_cli
from nova.main import create_app
from nova.platform_service import PlatformService
from nova.tools.registry import ToolRegistry


def _make_platform(tmp_path: Path) -> PlatformService:
    data_dir = tmp_path / "data"
    ws_dir = tmp_path / "workspace"
    data_dir.mkdir(parents=True, exist_ok=True)
    ws_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "cyber_test.sqlite3"
    settings = Settings(data_dir=data_dir, workspace_dir=ws_dir, db_path=db_path)
    db = Database(db_path)
    db.initialize()
    reg = ToolRegistry(settings)
    pol = AutonomyPolicy(settings, db, reg)
    return PlatformService(settings=settings, db=db, tools=reg, autonomy_policy=pol)


def test_taxonomy_counts_match_specification() -> None:
    assert len(UNIFIED_CORE_16_DOMAINS) == 16
    assert len(SCOPE_10_CATEGORIES) == 10
    assert len(ATTACK_SURFACE_14_CATEGORIES) == 14
    assert len(VULNERABILITY_22_CATEGORIES) == 22
    assert len(EPISTEMIC_7_FINDING_STATES) == 7
    assert len(LIFECYCLE_STATES_ORDERED) == 8
    assert len(RESEARCH_EPISTEMIC_8_FIELDS) == 8
    assert len(TOOL_FACTORY_17_CATEGORIES) == 17
    assert len(TUTOR_17_DISCIPLINES) == 17


def test_full_18_check_security_engineering_acceptance_suite() -> None:
    report = run_cyber_division_acceptance()
    assert report["passed"] is True
    assert report["passed_count"] == 18
    assert report["total_checks"] == 18


def test_scope_rate_limit_anti_expansion_and_lifecycle_guards(tmp_path: Path) -> None:
    platform = _make_platform(tmp_path)
    cy = platform.cyber_division

    for untrusted in ("tool", "model", "plugin", "downloaded_instruction"):
        with pytest.raises(PermissionError):
            cy.scope_registry.register_scope(
                name="Bad Scope",
                scope_category="local_vm",
                targets=["127.0.0.1"],
                ownership_evidence="none",
                caller_source=untrusted,
            )

    cy.scope_registry.register_scope(
        name="Rate Limited Lab",
        scope_category="local_vm",
        targets=["127.0.0.1"],
        ownership_evidence="Local VM owner",
        rate_limit_rpm=2,
    )
    assert cy.scope_registry.authorize_operation(target="127.0.0.1")["authorized"] is True
    assert cy.scope_registry.authorize_operation(target="127.0.0.1")["authorized"] is True
    third = cy.scope_registry.authorize_operation(target="127.0.0.1")
    assert third["authorized"] is False
    assert third["status"] == "rate_limited"

    finding = cy.vuln_engine.record_and_validate_finding(
        {
            "category": "sql_injection",
            "epistemic_status": "confirmed_vulnerability",
            "affected_asset": "127.0.0.1:app.py",
            "severity": "high",
            "evidence": {"reproducible_non_destructive_check": True},
        }
    )
    with pytest.raises(PermissionError):
        cy.vuln_engine.transition_lifecycle(
            finding["id"],
            target_state="Accepted Risk",
            risk_acceptance_justification="short",
        )
    accepted = cy.vuln_engine.transition_lifecycle(
        finding["id"],
        target_state="Accepted Risk",
        risk_acceptance_justification="Compensating network isolation and read-only SQLite role verified.",
    )
    assert accepted["lifecycle_state"] == "Accepted Risk"


def test_research_refuses_weaponized_and_enforces_storage_budget(tmp_path: Path) -> None:
    platform = _make_platform(tmp_path)
    wb = platform.cyber_division.research_workbench

    refused = wb.research_vulnerability("build weaponized exploit for sshd")
    assert refused["ok"] is False
    assert refused["status"] == "refused_weaponized_or_destructive_request"

    over_budget = wb.check_storage_budget_before_ingest(100 * 1024 * 1024)
    assert over_budget["permitted"] is False

    res = wb.research_vulnerability(
        "CWE-89",
        patch_diff_text='--- a/db.py\n+++ b/db.py\n-cur.execute(f"SELECT {x}")\n+cur.execute("SELECT ?", (x,))\n',
    )
    assert res["ok"] is True
    assert res["weaponized_exploit_generated"] is False
    assert res["patch_diff_analysis"]["added_lines_count"] == 1


def test_apk_static_inspection_tool_factory_ast_gate_and_self_improvement_guardrails(tmp_path: Path) -> None:
    platform = _make_platform(tmp_path)
    cy = platform.cyber_division

    apk_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest package='com.example.lab'/>")
        zf.writestr("classes.dex", b"dex\n035\x00")

    apk_res = cy.re_forensics.inspect_sample_statically(apk_path)
    assert apk_res["executed_on_host"] is False
    assert apk_res["original_evidence_preserved"] is True
    assert apk_res["file_type"] == "Android_APK_archive"

    unsafe_tool = cy.tool_factory.build_and_register_defensive_tool(
        name="unsafe_deleter",
        category="file_integrity_monitor",
        purpose="Check integrity",
        custom_python_body="import os\ndef inspect_target(target_path: str) -> dict:\n    os.remove(target_path)\n    return {'ok': True}\n",
    )
    assert unsafe_tool["ok"] is False
    assert unsafe_tool["status"] == "rejected_unsafe_ast"

    blocked_si = cy.self_improving.evaluate_and_improve_detector(
        detector_name="test_det",
        labeled_dataset=[{"code": "x", "is_vulnerable": False}],
        baseline_pattern="x",
        candidate_pattern="y",
        proposed_policy_changes={"disable_scope_enforcement": True},
    )
    assert blocked_si["ok"] is False
    assert blocked_si["status"] == "rejected_immutable_security_control_removal"

    hyp = cy.self_improving.classify_unverified_model_hypothesis("Model suspects race condition in handler")
    assert hyp["confirmed_vulnerability"] is False
    assert hyp["epistemic_status"] == "potential_vulnerability"


def test_14_step_engagement_api_routes_and_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    data_dir = tmp_path / "api_data"
    ws_dir = tmp_path / "api_ws"
    src_dir = ws_dir / "demo_proj"
    src_dir.mkdir(parents=True, exist_ok=True)
    vuln_file = src_dir / "db_query.py"
    vuln_file.write_text(
        "import sqlite3\n\n"
        "def get_item(conn: sqlite3.Connection, item_name: str):\n"
        '    return conn.execute(f"SELECT id FROM items WHERE label = \'{item_name}\'").fetchall()\n',
        encoding="utf-8",
    )

    settings = Settings(
        data_dir=data_dir,
        workspace_dir=ws_dir,
        db_path=data_dir / "api.sqlite3",
    )
    app = create_app(settings)
    with TestClient(app) as client:
        h = client.get("/api/health").json()
        assert len(h["platform"]) == 7
        assert h["cyber_division"]["sections"] == "201-220"
        assert h["cyber_division"]["degraded"] is False

        caps = client.get("/api/cyber/capabilities").json()
        assert caps["claims_unverified_worlds_best_status"] is False

        sc_resp = client.post(
            "/api/cyber/scopes",
            json={
                "name": "API Demo Scope",
                "category": "development_environment",
                "targets": [str(src_dir)],
                "authorization_evidence": "Pytest authorized scope",
            },
        )
        assert sc_resp.status_code == 200
        assert sc_resp.json()["ok"] is True

        eng = client.post(
            "/api/cyber/engagement",
            json={
                "objective": "Audit and remediate demo_proj SQL query",
                "target": str(src_dir),
                "remediate_if_source_file": str(vuln_file),
            },
        ).json()
        assert eng["ok"] is True
        assert len(eng["steps"]) == 14
        assert eng["findings_count"] >= 1
        assert Path(eng["report"]["markdown_path"]).is_file()

        tut = client.get("/api/cyber/tutor", params={"discipline": "linux_security", "score": 90.0}).json()
        assert tut["adapted_level"] == "advanced"

    monkeypatch.setenv("NOVA_DATA_DIR", str(data_dir))
    monkeypatch.setenv("NOVA_WORKSPACE_DIR", str(ws_dir))
    rc = desktop_cli.main(["cyber", "--capabilities"])
    assert rc == 0
    cli_out = json.loads(capsys.readouterr().out)
    assert cli_out["sections_implemented"] == "201-220"
