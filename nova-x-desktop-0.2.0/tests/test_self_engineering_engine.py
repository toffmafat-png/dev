"""Tests for §276–§295 Autonomous Architecture, Source Code Evolution & Self-Engineering Engine."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from starlette.testclient import TestClient

from nova.config import Settings
from nova.db import Database
from nova.desktop import cli
from nova.main import create_app
from nova.self_engineering import (
    ARCH_ANALYSIS_16_DIMENSIONS,
    ARCH_GRAPH_14_ENTITY_KINDS,
    DB_MIGRATION_10_STEPS,
    DEPENDENCY_10_DIMENSIONS,
    DYNAMIC_MODULE_11_STEPS,
    ENGINEERING_ASSISTANT_14_STEPS,
    GOVERNANCE_6_ZONES,
    IMMUTABLE_SELF_MODIFICATION_LAWS,
    MODULE_MANIFEST_12_FIELDS,
    PERFORMANCE_12_METRICS,
    PLACEMENT_9_FACTORS,
    QA_13_TESTING_TYPES,
    RELEASE_3_CHANNELS,
    REPAIR_10_FAILURE_CLASSES,
    SCALABLE_8_NODE_KINDS,
    SELF_ENGINEERING_11_ROLES,
    SOURCE_INTEL_20_DOMAINS,
    SelfEngineeringService,
    run_standalone_recovery,
)
from nova.self_engineering.acceptance import _seed_mini_repo, run_self_engineering_acceptance_suite


def test_self_engineering_taxonomy_constants() -> None:
    assert len(SELF_ENGINEERING_11_ROLES) == 11
    assert len(SOURCE_INTEL_20_DOMAINS) == 20
    assert len(ARCH_ANALYSIS_16_DIMENSIONS) == 16
    assert len(ARCH_GRAPH_14_ENTITY_KINDS) == 14
    assert len(MODULE_MANIFEST_12_FIELDS) == 12
    assert len(DYNAMIC_MODULE_11_STEPS) == 11
    assert len(PERFORMANCE_12_METRICS) == 12
    assert len(SCALABLE_8_NODE_KINDS) == 8
    assert len(PLACEMENT_9_FACTORS) == 9
    assert len(DB_MIGRATION_10_STEPS) == 10
    assert len(RELEASE_3_CHANNELS) == 3
    assert len(QA_13_TESTING_TYPES) == 13
    assert len(REPAIR_10_FAILURE_CLASSES) == 10
    assert len(ENGINEERING_ASSISTANT_14_STEPS) == 14
    assert len(DEPENDENCY_10_DIMENSIONS) == 10
    assert len(GOVERNANCE_6_ZONES) == 6
    assert len(IMMUTABLE_SELF_MODIFICATION_LAWS) == 4


def test_governance_immutable_laws_and_security_zone_safeguards(tmp_path: Path) -> None:
    db = Database(tmp_path / "gov.db")
    db.initialize()
    svc = SelfEngineeringService(db=db, repo_root=tmp_path, data_dir=tmp_path / "data")

    sec_eval = svc.governance.inspect_candidate_patch({"nova/autonomy.py": "# edit security boundary"})
    assert sec_eval["requires_stronger_review"] is True
    assert sec_eval["allowed"] is False
    assert sec_eval["zones"]["nova/autonomy.py"] == "core_security_and_authorization"

    forbidden = svc.governance.inspect_candidate_patch(
        {"nova/bad.py": "disable_emergency_stop = True\nUNRESTRICTED_ROOT_SELF_GRANT = True\n"}
    )
    assert forbidden["allowed"] is False
    assert len(forbidden["violations"]) >= 2


def test_scalable_placement_and_sqlite_vs_postgres_evaluation(tmp_path: Path) -> None:
    db = Database(tmp_path / "scale.db")
    db.initialize()
    svc = SelfEngineeringService(db=db, repo_root=tmp_path, data_dir=tmp_path / "data")

    svc.scalable_coordinator.register_compute_node(
        node_id="gpu-worker-01",
        node_kind="dedicated_inference_machine",
        ram_mb=32768,
        gpu_vram_mb=16384,
        installed_software=["python3", "ollama"],
        online=True,
        latency_ms=2.5,
    )
    priv = svc.scalable_coordinator.decide_task_placement(
        required_ram_mb=1024,
        sensitive_private_data=True,
        requires_gpu=True,
    )
    assert priv["selected_target"] == "local_kali_control_plane"

    gpu_route = svc.scalable_coordinator.decide_task_placement(
        required_ram_mb=4096,
        required_software=["ollama"],
        sensitive_private_data=False,
        requires_gpu=True,
    )
    assert gpu_route["selected_target"] == "gpu-worker-01"

    arch_style = svc.arch_analyzer.evaluate_architecture_redesign_paradigm(
        concurrent_users=1,
        multi_host_gpu_needed=False,
    )
    assert arch_style["recommended_paradigm"] == "modular_monolith"
    assert arch_style["unnecessary_microservices_rejected"] is True

    db_eval = svc.db_migrations.evaluate_sqlite_vs_postgresql(concurrent_writers=1)
    assert db_eval["postgresql_justified"] is False


def test_qa_test_weakening_guard_and_standalone_recovery_cli(tmp_path: Path) -> None:
    mini_repo = tmp_path / "mini_repo"
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    _seed_mini_repo(mini_repo)
    db = Database(data_dir / "nova.db")
    db.initialize()
    svc = SelfEngineeringService(db=db, repo_root=mini_repo, data_dir=data_dir)

    weak = svc.qa_engine.detect_test_weakening(
        "def test_x():\n    assert calc(2) == 4\n    assert calc(3) == 6\n",
        "def test_x():\n    assert True\n",
    )
    assert weak["weakened"] is True
    assert weak["trivial_assert_true_added"] is True

    svc.release_engine.publish_to_channel(
        version="0.2.0",
        channel="stable",
        source_dir=mini_repo,
        changelog="Baseline 0.2.0",
    )
    svc.release_engine.journal_file.write_text(
        json.dumps({"in_progress": True, "previous_stable": "0.2.0", "target_stable": "0.3.0-broken"}),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "nova.self_engineering.recovery_launcher",
            "--data-dir",
            str(data_dir),
            "--db-path",
            str(db.path),
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    out = json.loads(proc.stdout)
    assert out["ok"] is True
    assert out["interrupted_update_recovered"] is True
    assert out["restored_stable_version"] == "0.2.0"
    assert out["sqlite_integrity"] == "ok"

    direct = run_standalone_recovery(data_dir=data_dir, db_path=db.path, restore_version="0.2.0")
    assert direct["active_stable_version"] == "0.2.0"


def test_http_api_cli_and_tool_registry_integration(tmp_path: Path, monkeypatch, capsys) -> None:
    data_dir = tmp_path / "api_data"
    ws_dir = tmp_path / "api_ws"
    settings = Settings(data_dir=data_dir, db_path=data_dir / "nova.db", workspace_dir=ws_dir)
    app = create_app(settings=settings)

    with TestClient(app) as client:
        h = client.get("/api/health").json()
        assert set(h["platform"].keys()) == {
            "degraded",
            "operation_mode",
            "resource_pressure",
            "sandbox_mechanism",
            "sandbox_available",
            "fts5_available",
            "detail",
        }
        assert h["self_engineering"]["enabled"] is True
        assert h["self_engineering"]["degraded"] is False

        st = client.get("/api/self-engineering/status")
        assert st.status_code == 200
        assert st.json()["sections_covered"] == "276-295"

        deps = client.get("/api/self-engineering/dependencies")
        assert deps.status_code == 200
        assert deps.json()["healthy"] is True

        imp = client.post("/api/self-engineering/impact", json={"module_name": "nova.db"})
        assert imp.status_code == 200
        assert imp.json()["dependent_count"] >= 5

        obj = client.post(
            "/api/self-engineering/objective",
            json={"objective": "Inspect database persistence architecture and record ADR"},
        )
        assert obj.status_code == 200
        assert obj.json()["all_14_steps_completed"] is True

    monkeypatch.setenv("NOVA_DATA_DIR", str(data_dir))
    monkeypatch.setenv("NOVA_WORKSPACE_DIR", str(ws_dir))
    rc = cli.main(["self-eng", "--dependencies"])
    assert rc == 0
    cli_out = json.loads(capsys.readouterr().out)
    assert cli_out["healthy"] is True


def test_full_20_check_acceptance_suite() -> None:
    summary = run_self_engineering_acceptance_suite()
    assert summary["ok"] is True
    assert summary["only_actually_executed_tests_reported"] is True
    assert summary["total_executed"] == 20
    assert summary["passed"] == 20
