"""Tests for DEV Personal-Use Security & Autonomy Policy (Sections 1–7)."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from nova.config import Settings
from nova.desktop import cli as desktop_cli
from nova.desktop.commands import CommandRunner
from nova.desktop.runtime import DesktopRuntime
from nova.main import create_app
from nova.personal_policy import (
    ARTIFICIALLY_LIMIT_SECURITY_KNOWLEDGE,
    AUTONOMOUS_11_INDEPENDENT_OPERATIONS,
    COMPLIANCE_THEATRE_ENABLED,
    CYBER_8_RESEARCH_CAPABILITIES,
    DEPLOYMENT_MODEL,
    ENTERPRISE_CERTIFICATION_REQUIRED,
    EXPOSE_CREDENTIALS_TO_REMOTE_MODELS,
    EXPOSE_UNRESTRICTED_HOST_ACCESS_TO_REMOTE_MODELS,
    LOCAL_STORAGE_BY_DEFAULT,
    MATERIAL_9_PROTECTED_RISKS,
    MINIMAL_INTERVENTION_EQUALS_UNLIMITED_AUTHORIZATION,
    PERSONAL_14_COMPUTING_DOMAINS,
    PUBLIC_MULTI_TENANT_SAAS,
    STRICT_OWASP_CHECKLIST_MANDATORY,
)
from nova.personal_policy.acceptance import run_acceptance


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


def test_policy_constants_and_acceptance_suite() -> None:
    assert DEPLOYMENT_MODEL == "single_user_personal_kali_linux"
    assert PUBLIC_MULTI_TENANT_SAAS is False
    assert STRICT_OWASP_CHECKLIST_MANDATORY is False
    assert ENTERPRISE_CERTIFICATION_REQUIRED is False
    assert COMPLIANCE_THEATRE_ENABLED is False
    assert MINIMAL_INTERVENTION_EQUALS_UNLIMITED_AUTHORIZATION is False
    assert ARTIFICIALLY_LIMIT_SECURITY_KNOWLEDGE is False
    assert LOCAL_STORAGE_BY_DEFAULT is True
    assert EXPOSE_CREDENTIALS_TO_REMOTE_MODELS is False
    assert EXPOSE_UNRESTRICTED_HOST_ACCESS_TO_REMOTE_MODELS is False
    assert len(PERSONAL_14_COMPUTING_DOMAINS) == 14
    assert len(AUTONOMOUS_11_INDEPENDENT_OPERATIONS) == 11
    assert len(MATERIAL_9_PROTECTED_RISKS) == 9
    assert len(CYBER_8_RESEARCH_CAPABILITIES) == 8

    report = run_acceptance()
    assert report["ok"] is True
    assert report["passed"] == report["total"] == 16


def test_power_user_and_persistent_grants_eliminate_repeated_prompts_safely(monkeypatch, tmp_path: Path) -> None:
    data_dir, ws_dir, db_path = _isolated_env(monkeypatch, tmp_path)
    rt = DesktopRuntime()
    try:
        py_exe = "python3" if Path(sys.executable).name == "python3" else Path(sys.executable).name
        # Default unconfigured mode requires approval / blocks agent interpreter
        default_eval = rt.policy.evaluate([py_exe, "-c", "print(1)"], str(ws_dir))
        assert default_eval["action"] == "approval_required"

        # Configure personal_power_user mode: routine dev/test tools inside owned workspace run automatically
        rt.personal_policy.autonomy.configure_policy(profile_mode="personal_power_user")
        power_eval = rt.policy.evaluate(["git", "status"], str(ws_dir))
        assert power_eval["action"] == "allow"

        runner = CommandRunner(Settings(data_dir=data_dir, workspace_dir=ws_dir, db_path=db_path), rt.database, rt.policy)
        out1 = asyncio.run(runner.run([py_exe, "-c", "print('run-1')"], cwd=str(ws_dir), approved=False, source="agent_task"))
        out2 = asyncio.run(runner.run([py_exe, "-c", "print('run-2')"], cwd=str(ws_dir), approved=False, source="agent_task"))
        assert out1.status == "success"
        assert out2.status == "success"

        # Catastrophic commands and credential paths STILL blocked even in personal_power_user mode!
        cat = rt.policy.evaluate(["rm", "-rf", "/"], str(ws_dir))
        assert cat["action"] == "deny"
        assert cat["rule"] == "catastrophic_system_modification_blocked"

        cred = asyncio.run(
            runner.run([py_exe, str(ws_dir / ".ssh" / "id_ed25519")], cwd=str(ws_dir), approved=False, source="agent_task")
        )
        assert cred.status == "denied"
    finally:
        rt.close()


def test_cyber_lab_persistent_authorization_and_local_privacy(monkeypatch, tmp_path: Path) -> None:
    _isolated_env(monkeypatch, tmp_path)
    rt = DesktopRuntime()
    try:
        pp = rt.personal_policy
        lab = pp.cyber_research.register_persistent_lab_environment(
            name="Kali Local Lab",
            category="local_lab",
            targets=["127.0.0.1"],
        )
        assert lab["grant"]["persistent"] is True
        step_ok = pp.cyber_research.authorize_research_step(
            capability="reverse_engineering",
            target="127.0.0.1",
        )
        assert step_ok["authorized"] is True
        assert step_ok["requires_repeated_approval"] is False

        step_denied = pp.cyber_research.authorize_research_step(
            capability="controlled_exploitation_research",
            target="unowned-external-target.example",
        )
        assert step_denied["authorized"] is False

        # CloudPrivacyGateway integration automatically logs visible external transfers
        gw_res = rt.hybrid_cloud.privacy_gateway.inspect_and_prepare_outbound(
            task_id="t-vis",
            provider_type="openai",
            model_id="gpt-4o-mini",
            base_url="https://api.openai.com/v1",
            messages=[{"role": "user", "content": "Hello personal policy"}],
        )
        assert gw_res["permitted"] is True
        transfers = pp.local_privacy.inspect_external_transfers()
        assert transfers["transfer_count"] >= 1
    finally:
        rt.close()


def test_cli_and_fastapi_personal_policy_routes_without_extra_local_auth(monkeypatch, tmp_path: Path, capsys) -> None:
    data_dir, ws_dir, db_path = _isolated_env(monkeypatch, tmp_path)

    rc = desktop_cli.main(["personal-policy", "--manifest"])
    assert rc == 0
    manifest = json.loads(capsys.readouterr().out)
    assert manifest["deployment_model"] == "single_user_personal_kali_linux"
    assert manifest["strict_owasp_checklist_mandatory"] is False

    settings = Settings(data_dir=data_dir, workspace_dir=ws_dir, db_path=db_path)
    app = create_app(settings=settings)
    with TestClient(app) as client:
        # Single-user local API works without unnecessary auth ceremony when NOVA_ACCESS_TOKEN is unset
        h = client.get("/api/health").json()
        assert set(h["platform"].keys()) == {
            "degraded",
            "detail",
            "fts5_available",
            "operation_mode",
            "resource_pressure",
            "sandbox_available",
            "sandbox_mechanism",
        }
        assert h["personal_policy"]["deployment_model"] == "single_user_personal_kali_linux"
        assert h["personal_policy"]["strict_owasp_checklist_mandatory"] is False

        st = client.get("/api/personal-policy/status")
        assert st.status_code == 200
        assert st.json()["manifest"]["compliance_theatre_enabled"] is False

        cfg = client.put("/api/personal-policy/config", json={"profile_mode": "personal_power_user"})
        assert cfg.status_code == 200
        assert cfg.json()["profile_mode"] == "personal_power_user"

        gr = client.post(
            "/api/personal-policy/grants",
            json={
                "domain": "development_tools",
                "scope_target": str(ws_dir),
                "allowed_programs": ["pytest", "ruff"],
                "notes": "API grant",
            },
        )
        assert gr.status_code == 200
        gid = gr.json()["grant_id"]

        lab = client.post(
            "/api/personal-policy/cyber-labs",
            json={"name": "API Lab", "category": "local_lab", "targets": ["127.0.0.1"]},
        )
        assert lab.status_code == 200

        tr = client.get("/api/personal-policy/transfers")
        assert tr.status_code == 200
        assert tr.json()["local_storage_by_default"] is True

        rev = client.delete(f"/api/personal-policy/grants/{gid}")
        assert rev.status_code == 200
        assert rev.json()["revoked"] is True
