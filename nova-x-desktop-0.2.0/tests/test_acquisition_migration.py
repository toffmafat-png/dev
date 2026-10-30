"""Comprehensive tests for §221–§235 Autonomous Software Acquisition, Environment Management & Universal Migration."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from nova.acquisition_migration import (
    ACQUISITION_22_CATEGORIES,
    BACKUP_11_KINDS,
    MIGRATION_6_SECTIONS,
    PROVENANCE_13_INSPECTION_FIELDS,
    TRUST_CHANNEL_5_TIERS,
)
from nova.acquisition_migration.acceptance import run_acquisition_migration_acceptance
from nova.autonomy import AutonomyPolicy
from nova.config import Settings
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
    db_path = data_dir / "am_test.sqlite3"
    settings = Settings(data_dir=data_dir, workspace_dir=ws_dir, db_path=db_path)
    db = Database(db_path)
    db.initialize()
    reg = ToolRegistry(settings)
    pol = AutonomyPolicy(settings, db, reg)
    return PlatformService(settings=settings, db=db, tools=reg, autonomy_policy=pol)


def test_acquisition_and_migration_taxonomies() -> None:
    assert len(ACQUISITION_22_CATEGORIES) == 22
    assert len(TRUST_CHANNEL_5_TIERS) == 5
    assert len(PROVENANCE_13_INSPECTION_FIELDS) == 13
    assert len(MIGRATION_6_SECTIONS) == 6
    assert len(BACKUP_11_KINDS) == 11


def test_full_20_check_acquisition_and_migration_acceptance_suite() -> None:
    report = run_acquisition_migration_acceptance()
    assert report["passed"] is True
    assert report["passed_count"] == 20
    assert report["total_checks"] == 20


def test_separate_project_envs_conflicts_and_dependency_safe_uninstall(tmp_path: Path) -> None:
    platform = _make_platform(tmp_path)
    am = platform.acquisition_migration

    # Project A requires v1.0.0, Project B requires v2.0.0 — kept strictly separate (§224)
    proj_a = tmp_path / "workspace" / "proj_a"
    proj_b = tmp_path / "workspace" / "proj_b"
    proj_a.mkdir(parents=True)
    proj_b.mkdir(parents=True)
    (proj_a / "requirements.txt").write_text("shared_codec==1.0.0\n", encoding="utf-8")
    (proj_b / "requirements.txt").write_text("shared_codec==2.0.0\n", encoding="utf-8")

    res_a = am.dependency_resolver.inspect_and_resolve_project_dependencies(proj_a)
    res_b = am.dependency_resolver.inspect_and_resolve_project_dependencies(proj_b)
    assert res_a["ok"] and res_b["ok"]
    assert res_a["resolved_packages"][0]["version"] == "1.0.0"
    assert res_b["resolved_packages"][0]["version"] == "2.0.0"
    assert res_a["isolated_env_path"] != res_b["isolated_env_path"]

    # Conflicting constraints within one manifest are caught safely (§224)
    proj_bad = tmp_path / "workspace" / "proj_conflict"
    proj_bad.mkdir(parents=True)
    (proj_bad / "requirements.txt").write_text("alpha_pkg==1.0.0\nalpha_pkg==2.0.0\n", encoding="utf-8")
    conflict = am.dependency_resolver.inspect_and_resolve_project_dependencies(proj_bad)
    assert conflict["ok"] is False
    assert conflict["status"] == "dependency_conflict_detected"

    # Safe uninstall checks reverse dependents and preserves config (§227)
    inst = am.installer.acquire_verify_and_register("dev-csv-profiler")
    assert inst["ok"] is True
    am.db.upsert_managed_software(
        {
            "software_id": "sw:dependent-dashboard",
            "app_name": "Dependent Dashboard",
            "package_name": "dependent-dashboard",
            "dependencies": ["dev-csv-profiler"],
        }
    )
    blocked_rm = am.lifecycle.safe_uninstall("dev-csv-profiler")
    assert blocked_rm["ok"] is False
    assert blocked_rm["status"] == "blocked_by_active_dependents"

    am.db.delete_managed_software("sw:dependent-dashboard")
    clean_rm = am.lifecycle.safe_uninstall("dev-csv-profiler", preserve_configuration=True)
    assert clean_rm["ok"] is True
    assert clean_rm["configuration_preserved"] is True


def test_policy_unrelated_work_encrypted_backups_and_rollback(tmp_path: Path) -> None:
    platform = _make_platform(tmp_path)
    am = platform.acquisition_migration

    # Non-preauthorized APT install finishes unrelated tasks and reports exact missing authorization (§226)
    gated = am.installer.acquire_verify_and_register(
        "blender",
        explicit_operator_approval=False,
        unrelated_tasks=["index_docs", "verify_workspace"],
    )
    assert gated["ok"] is False
    assert gated["policy_decision"]["missing_authorization"] == "preauthorize_package:blender"
    assert len(gated["unrelated_work_completed"]) == 2

    # Encrypted complete backup + pre-update restore point + rollback (§232 & §234)
    marker = tmp_path / "workspace" / "notes_proj" / "readme.txt"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("original_v1", encoding="utf-8")

    enc_bak = am.backup.create_verified_backup("encrypted_complete_backup", passphrase="StrongBackupPassword!99")
    assert enc_bak["ok"] is True
    assert enc_bak["package"]["encrypted"] is True
    assert enc_bak["package"]["verified"] is True

    rp = am.backup.create_pre_update_recovery_point()
    assert rp["ok"] is True
    assert rp["package"]["backup_kind"] == "pre_update_restore_point"

    # Mutate workspace file, restore encrypted backup (creating pre-restore point), then rollback!
    marker.write_text("mutated_v2", encoding="utf-8")
    rest = am.migration.restore_migration_package(
        enc_bak["package"]["archive_path"],
        decrypt_archive_passphrase="StrongBackupPassword!99",
    )
    assert rest["ok"] is True
    assert marker.read_text(encoding="utf-8") == "original_v1"

    rolled = am.migration.rollback_restore(rest["audit"]["id"])
    assert rolled["ok"] is True
    assert marker.read_text(encoding="utf-8") == "mutated_v2"


def test_api_endpoints_tools_and_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    data_dir = tmp_path / "api_data"
    ws_dir = tmp_path / "api_ws"
    env_dir = ws_dir / "py_service"
    settings = Settings(data_dir=data_dir, workspace_dir=ws_dir, db_path=data_dir / "api.sqlite3")

    app = create_app(settings)
    with TestClient(app) as client:
        h = client.get("/api/health").json()
        assert len(h["platform"]) == 7
        assert h["acquisition_migration"]["sections"] == "221-235"
        assert h["acquisition_migration"]["degraded"] is False

        mgrs = client.get("/api/acquisition/managers").json()
        assert mgrs["assumed_managers_without_probing"] is False

        inst = client.post(
            "/api/acquisition/install",
            json={"capability_or_name": "dev-csv-profiler", "explicit_operator_approval": True},
        ).json()
        assert inst["ok"] is True

        env_res = client.post(
            "/api/acquisition/environment",
            json={"name": "Py Service Env", "domain": "python_development", "project_dir": str(env_dir)},
        ).json()
        assert env_res["ok"] is True
        assert len(env_res["steps"]) == 12

        bak = client.post("/api/migration/create", json={"backup_kind": "config_only"}).json()
        assert bak["ok"] is True

        prev = client.post(
            "/api/migration/restore",
            json={"archive_path": bak["package"]["archive_path"], "preview_only": True},
        ).json()
        assert prev["ok"] is True
        assert prev["preview_only"] is True

    # ToolRegistry execution check
    out = asyncio.run(app.state.engine.platform.tools.execute("software_generate_inventory", {}, approved=True))
    assert out.status in {"success", "completed"}

    # CLI check
    monkeypatch.setenv("NOVA_DATA_DIR", str(data_dir))
    monkeypatch.setenv("NOVA_WORKSPACE_DIR", str(ws_dir))
    assert desktop_cli.main(["acquire", "--managers"]) == 0
    cli_mgr = json.loads(capsys.readouterr().out)
    assert "python" in cli_mgr["ecosystems"]

    assert desktop_cli.main(["migrate", "--backup", "memory_only"]) == 0
    cli_bak = json.loads(capsys.readouterr().out)
    assert cli_bak["ok"] is True
