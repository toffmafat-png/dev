"""Comprehensive §149–§164 System Access, Hardware Intelligence & Continuous Autonomy tests."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nova.config import Settings
from nova.desktop.cli import main as cli_main
from nova.main import create_app
from nova.system_access.acceptance import ephemeral_openssh_server, run_system_access_acceptance
from nova.system_access.helper_cli import main as helper_cli_main
from nova.system_access.privilege import (
    EXPOSE_ADMIN_CREDENTIALS_TO_MODELS,
    MODEL_INSTRUCTION_SUFFICIENT_FOR_ADMIN,
    PLAINTEXT_SUDO_PASSWORD_STORAGE,
    RUN_ENTIRE_APP_AS_ROOT,
)
from nova.system_access.recording import (
    BYPASS_SESSION_PERMISSIONS,
    COVERT_SURVEILLANCE_PERMITTED,
    FABRICATE_UNCAPTURED_MEDIA,
    SILENT_RECORDING_WITHOUT_INDICATOR,
)
from nova.system_access.remote import (
    DISABLE_HOST_KEY_VERIFICATION,
    EXPOSE_SSH_KEYS_TO_AI_MODELS,
    PIVOT_TO_UNAUTHORIZED_HOSTS,
    STORE_PLAINTEXT_SSH_PASSWORDS,
    LocalNodeAgent,
)
from nova.system_access.resilience import REQUIRED_JOURNAL_FIELDS, USES_UNDOCUMENTED_DAEMONIZATION


def _make_test_app(tmp_path: Path) -> TestClient:
    settings = Settings(
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "nova.sqlite3",
        workspace_dir=tmp_path / "workspace",
        low_resource_mode=True,
        goal_scheduler_enabled=False,
    )
    settings.ensure_dirs()
    app = create_app(settings)
    return TestClient(app)


def test_security_and_ethical_invariants_pinned():
    assert RUN_ENTIRE_APP_AS_ROOT is False
    assert PLAINTEXT_SUDO_PASSWORD_STORAGE is False
    assert MODEL_INSTRUCTION_SUFFICIENT_FOR_ADMIN is False
    assert EXPOSE_ADMIN_CREDENTIALS_TO_MODELS is False
    assert USES_UNDOCUMENTED_DAEMONIZATION is False
    assert COVERT_SURVEILLANCE_PERMITTED is False
    assert BYPASS_SESSION_PERMISSIONS is False
    assert SILENT_RECORDING_WITHOUT_INDICATOR is False
    assert FABRICATE_UNCAPTURED_MEDIA is False
    assert DISABLE_HOST_KEY_VERIFICATION is False
    assert STORE_PLAINTEXT_SSH_PASSWORDS is False
    assert EXPOSE_SSH_KEYS_TO_AI_MODELS is False
    assert PIVOT_TO_UNAUTHORIZED_HOSTS is False
    assert len(REQUIRED_JOURNAL_FIELDS) == 17


def test_full_s164_acceptance_suite_20_checks():
    report = run_system_access_acceptance()
    assert report["total"] == 20
    assert report["failed_count"] == 0
    assert report["all_passed"] is True
    assert report["passed_count"] + report["could_not_run_count"] == 20


def test_device_operations_safety_gates_and_udev_diff(tmp_path: Path):
    client = _make_test_app(tmp_path)
    svc = client.app.state.engine.platform.system_access

    # Destructive critical hardware actions are unconditionally blocked
    blocked_disk = svc.device_ops.execute_operation("storage:sda", "storage_controller_reset")
    assert blocked_disk["ok"] is False
    assert blocked_disk["status"] == "blocked_critical_hardware"

    # Disabling loopback without approval warns and blocks
    lo_res = svc.device_ops.execute_operation("net:lo", "toggle_interface", params={"state": "down"}, dry_run=False)
    assert lo_res["ok"] is False
    assert lo_res["status"] == "blocked_active_primary_connection"

    # Dry-run preview works cleanly with operator approval
    lo_preview = svc.device_ops.execute_operation(
        "net:lo",
        "toggle_interface",
        params={"state": "up"},
        dry_run=True,
        operator_approved=True,
    )
    assert lo_preview["ok"] is True
    assert lo_preview["dry_run"] is True

    # Device change tracker initializes baseline cleanly
    diff = svc.device_ops.detect_device_changes()
    assert diff["total_tracked"] >= 6


def test_privileged_helper_cli_and_log_rotation(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv("NOVA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("NOVA_DB_PATH", str(tmp_path / "data" / "nova.sqlite3"))
    monkeypatch.setenv("NOVA_WORKSPACE_DIR", str(tmp_path / "workspace"))

    rc_list = helper_cli_main(["--list-operations"])
    out_list = json.loads(capsys.readouterr().out)
    assert rc_list == 0
    assert "driver.modprobe_load" in out_list

    rc_dry = helper_cli_main(["--operation", "driver.modprobe_load", "--params-json", '{"module": "iwlwifi"}', "--dry-run"])
    out_dry = json.loads(capsys.readouterr().out)
    assert rc_dry == 0
    assert out_dry["status"] == "dry_run_ok"

    rc_bad = helper_cli_main(["--operation", "driver.modprobe_load", "--params-json", '{"module": "bad;id"}', "--dry-run"])
    out_bad = json.loads(capsys.readouterr().out)
    assert rc_bad == 1
    assert out_bad["status"] == "rejected_malformed"

    client = _make_test_app(tmp_path)
    spol = client.app.state.engine.platform.system_access.startup_policy
    big_log = spol.log_dir / "worker.log"
    big_log.write_text("x" * 2048, encoding="utf-8")
    rot = spol.rotate_logs("worker.log", max_bytes=512, backups=3)
    assert rot["rotated"] is True
    assert (spol.log_dir / "worker.log.1").is_file()


def test_recording_session_events_and_infra_ttl(tmp_path: Path):
    client = _make_test_app(tmp_path)
    svc = client.app.state.engine.platform.system_access

    # Start -> Pause -> Resume -> Screen Lock event
    started = svc.recording_studio.start_recording(title="Session Lock Test", fps=8)
    rid = started["recording"]["id"]
    paused = svc.recording_studio.pause_recording(rid)
    assert paused["recording"]["status"] == "paused"
    resumed = svc.recording_studio.resume_recording(rid)
    assert resumed["recording"]["status"] == "recording"
    locked = svc.recording_studio.handle_session_event(rid, "screen_locked")
    assert locked["recording"]["status"] == "paused_screen_locked"
    assert locked["indicator"]["recording_active"] is False

    # Infrastructure knowledge TTL staleness detection
    rec = svc.infra_knowledge.record(
        category="deployment_paths",
        key="srv-app-dir",
        title="Staging Deployment Path",
        value={"path": "/srv/novax/releases"},
        source="operator",
        ttl_seconds=60,
        verified_at="2020-01-01T00:00:00+00:00",
    )
    assert rec["needs_revalidation"] is True


@pytest.mark.asyncio
async def test_unified_tool_registry_and_fastapi_system_endpoints(tmp_path: Path):
    client = _make_test_app(tmp_path)

    # Verify /api/health preserves exact platform 7 keys while exposing system_access
    h = client.get("/api/health").json()
    assert len(h["platform"]) == 7
    assert h["system_access"]["sqlite_wal_ok"] is True

    hw = client.get("/api/system/hardware?query=cpu").json()
    assert hw["match_count"] >= 1

    diag = client.post(
        "/api/system/drivers/diagnose",
        json={
            "diagnostic_evidence": {
                "kernel_logs": ["firmware: failed to load rtl_nic/rtl8168h-2.fw"],
            }
        },
    ).json()
    assert any(c["params"].get("package") == "firmware-realtek" for c in diag["candidate_repairs"])

    pol = client.post("/api/system/startup-policy", json={"updates": {"restore_dashboard_pages": True}}).json()
    assert pol["policy"]["restore_dashboard_pages"] is True
    assert len(pol["disclosures"]) == 9

    # Reject unconsented mic recording over HTTP 400
    bad_rec = client.post("/api/system/recordings/start", json={"microphone_audio": True, "explicit_mic_consent": False})
    assert bad_rec.status_code == 400

    good_rec = client.post("/api/system/recordings/start", json={"title": "API Capture", "fps": 6}).json()
    rid = good_rec["recording"]["id"]
    stopped = client.post(f"/api/system/recordings/{rid}/stop").json()
    assert stopped["recording"]["status"] == "completed"
    analyzed = client.get(f"/api/system/recordings/{rid}/analyze").json()
    assert "direct_observations" in analyzed and "ai_interpretations" in analyzed

    obs = client.get("/api/system/observability").json()
    assert "cpu" in obs["snapshot"] and "network" in obs["snapshot"]

    ik = client.post(
        "/api/system/infrastructure-knowledge",
        json={
            "category": "installed_toolchains",
            "key": "python3",
            "title": "Python Runtime",
            "value": {"binary": "/usr/bin/python3"},
        },
    )
    assert ik.status_code == 200

    # Verify unified ToolRegistry tools execute cleanly
    registry = client.app.state.engine.tools
    hw_tool = await registry.execute("hardware.explore", {"query": "memory"}, approved=True)
    assert hw_tool.status == "success"
    shot_gate = await registry.execute("screen.capture_screenshot", {"capture_mode": "full_screen"}, approved=False)
    assert shot_gate.status == "approval_required"
    shot_ok = await registry.execute("screen.capture_screenshot", {"capture_mode": "full_screen"}, approved=True)
    assert shot_ok.status == "success"


def test_cli_hardware_and_ephemeral_ssh_api(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv("NOVA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("NOVA_DB_PATH", str(tmp_path / "data" / "nova.sqlite3"))
    monkeypatch.setenv("NOVA_WORKSPACE_DIR", str(tmp_path / "workspace"))

    rc = cli_main(["hardware", "--query", "cpu"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["match_count"] >= 1

    client = _make_test_app(tmp_path)
    with ephemeral_openssh_server(tmp_path) as ssh_env:
        if ssh_env is not None:
            reg = client.post(
                "/api/system/servers",
                json={
                    "alias": "api-ssh",
                    "hostname": ssh_env["hostname"],
                    "port": ssh_env["port"],
                    "username": ssh_env["username"],
                    "private_key_path": ssh_env["client_private_key"],
                    "host_key_line": ssh_env["host_key_line"],
                },
            )
            assert reg.status_code == 200
            exec_res = client.post("/api/system/servers/api-ssh/exec", json={"command": "echo API_SSH_VERIFIED"}).json()
            assert exec_res["ok"] is True
            assert "API_SSH_VERIFIED" in exec_res["stdout"]

    # Node local policy enforcement via coordinator
    svc = client.app.state.engine.platform.system_access
    agent = LocalNodeAgent(
        node_name="edge-pi",
        shared_secret="hmac-edge-key-123",
        allowed_capabilities=["node.health"],
    )
    svc.nodes.register_node(
        node_name="edge-pi",
        endpoint="https://127.0.0.1:9444",
        shared_secret="hmac-edge-key-123",
        capabilities=["node.health", "node.reboot"],
        attach_local_agent=agent,
    )
    assert svc.nodes.dispatch_to_node("edge-pi", "node.health")["ok"] is True
    assert svc.nodes.dispatch_to_node("edge-pi", "node.reboot")["status"] == "rejected_by_local_node_policy"
    time.sleep(0.01)
