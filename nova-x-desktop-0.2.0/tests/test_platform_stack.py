"""Unit and HTTP API tests for NOVA X's §90–§113 platform expansion."""
from __future__ import annotations

import struct
import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from nova.capabilities import AUTO_INSTALL_PERMITTED, CapabilityRegistry, prioritize, recommendation_catalogue
from nova.context_manager import (
    COMPARTMENT_CONVERSATION,
    COMPARTMENT_CREDENTIALS,
    ContextOptimizer,
    StageRecord,
)
from nova.data_workspace import DataWorkspace
from nova.devtools import DeveloperWorkspace, analyze_traceback, check_git_or_deploy_action
from nova.events import (
    OUTCOME_CYCLE,
    OUTCOME_DELIVERED,
    OUTCOME_DUPLICATE,
    OUTCOME_IDEMPOTENT_SKIP,
    OUTCOME_PERMISSION_DENIED,
    Event,
    EventBus,
    Subscription,
)
from nova.governance import CONTENT_LOCAL_FILE, CONTENT_SCREENSHOT, PrivacyGovernor
from nova.main import create_app
from nova.mcp_client import (
    STATUS_DISABLED,
    STATUS_VERSION_INCOMPATIBLE,
    TRANSPORT_MEMORY,
    InMemoryMCPTransport,
    IntegrationGateway,
    IntegrationRecord,
    MCPClientManager,
    MCPServerConfig,
)
from nova.modalities import (
    CONTINUOUS_SCREEN_CAPTURE,
    SPEAKER_ID_AUTHORIZES_PRIVILEGED,
    DeterministicLoopbackRecognizer,
    DeterministicLoopbackSynthesizer,
    VisualAssistant,
    VoiceLayer,
)
from nova.plugins import PluginManager
from nova.terminal import ACTOR_NOVA, ACTOR_USER, TerminalWorkspace
from nova.workflows import CrossAppCoordinator, WorkflowBlock, WorkflowEngine, WorkflowSpec
from tests.conftest import FakeProvider


def _ts() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


@pytest.fixture
def platform_client(environment):
    settings, db, registry, _ws = environment
    # `environment` fixture already registers calculator & workspace tools.
    app = create_app(settings, provider=FakeProvider([]), db=db, tools=registry)
    with TestClient(app) as client:
        yield client, db, app, settings


# ---- §113 Capability Registry & Recommendations -----------------------------


def test_capability_registry_caches_probes_and_forbids_auto_install():
    assert AUTO_INSTALL_PERMITTED is False
    reg = CapabilityRegistry()
    reg.evaluate("knowledge_search")
    calls_after_first = reg.snapshot()["probe_calls"]
    reg.evaluate("knowledge_search")
    snap = reg.snapshot()
    assert snap["probe_calls"] == calls_after_first
    assert snap["probe_cache_hits"] >= 1

    ranked = prioritize(
        {
            "high_value_local": {
                "usefulness": 0.9,
                "reliability": 0.9,
                "performance": 0.85,
                "privacy": 1.0,
                "maintenance_cost": 0.9,
                "user_goal_alignment": 0.9,
            },
            "unevidenced": {},
        }
    )
    assert ranked[0].id == "high_value_local"
    assert ranked[1].total == 0.0
    assert len(recommendation_catalogue()) >= 5


# ---- §91 Event-Driven Intelligence Bus --------------------------------------


@pytest.mark.asyncio
async def test_event_bus_prevents_cycles_duplicates_and_permission_bypass():
    allowed_tools = {"workspace.read_file"}
    bus = EventBus(
        permission_check=lambda tool, args: {"action": "allow" if tool in allowed_tools else "deny", "reason": "policy"}
    )
    received: list[str] = []

    bus.subscribe(
        Subscription(
            id="sub-read",
            event_patterns=("file.changed",),
            requires_tool="workspace.read_file",
            idempotency_key=lambda evt: str(evt.payload.get("path", "")),
            handler=lambda evt, _b: received.append(evt.id),
        )
    )
    bus.subscribe(
        Subscription(
            id="sub-forbidden",
            event_patterns=("file.changed",),
            requires_tool="system.run_privileged",
            handler=lambda evt, _b: received.append("SHOULD_NOT_RUN"),
        )
    )

    e1 = Event(type="file.changed", source="editor", occurred_at=_ts(), payload={"path": "a.py"}, dedupe_key="dk-1")
    d1 = await bus.emit(e1)
    outcomes = {d.subscriber_id: d.outcome for d in d1}
    assert outcomes["sub-read"] == OUTCOME_DELIVERED
    assert outcomes["sub-forbidden"] == OUTCOME_PERMISSION_DENIED
    assert len(received) == 1

    # Duplicate dedupe_key is refused.
    dup = await bus.emit(Event(type="file.changed", source="editor", occurred_at=_ts(), payload={"path": "a.py"}, dedupe_key="dk-1"))
    assert dup[0].outcome == OUTCOME_DUPLICATE

    # Same idempotency key with different dedupe_key skips repeat execution.
    idem = await bus.emit(Event(type="file.changed", source="editor", occurred_at=_ts(), payload={"path": "a.py"}, dedupe_key="dk-2"))
    assert any(d.outcome == OUTCOME_IDEMPOTENT_SKIP for d in idem)

    # Circular causal chain is refused.
    cyclic = Event(type="file.changed", source="sub", occurred_at=_ts(), causal_chain=("file.changed",), causal_depth=1)
    cyc_out = await bus.emit(cyclic)
    assert cyc_out[0].outcome == OUTCOME_CYCLE


# ---- §95 Context & Memory Optimization --------------------------------------


def test_context_optimizer_separates_facts_hypotheses_and_protects_anchors():
    opt = ContextOptimizer(budget_chars=1_600)
    opt.add_item(item_id="secret-ref", compartment=COMPARTMENT_CREDENTIALS, content="DO_NOT_LEAK_KEY")
    opt.add_item(
        item_id="fact-1",
        compartment=COMPARTMENT_CONVERSATION,
        content="pytest suite passed 215 tests in local workspace",
        provenance="test",
        source_ref="pytest-run-1",
    )
    opt.add_item(
        item_id="hyp-1",
        compartment=COMPARTMENT_CONVERSATION,
        content="pytest slowness might come from DNS lookup",
        provenance="model_generated",
    )
    window = opt.assemble(
        objective="check pytest suite results",
        constraints=("preserve native Kali desktop",),
        permissions=("routine",),
        unresolved_blockers=("awaiting package signature",),
        stages=(StageRecord("s1", "lint", "ok", "ruff clean", "ev-lint", completed=True),),
        high_impact_action=True,
    )
    rendered = window.render_prompt_block()
    assert "DO_NOT_LEAK_KEY" not in rendered
    assert "preserve native Kali desktop" in rendered
    assert "awaiting package signature" in rendered
    assert len(window.verified_facts) == 1
    assert len(window.hypotheses) == 1


# ---- §111 Privacy Governance ------------------------------------------------


def test_privacy_governor_blocks_unjustified_file_and_screenshot_uploads(environment):
    _settings, db, _reg, _ws = environment
    gov = PrivacyGovernor(db=db)

    assert not gov.authorize_transmission(
        destination="third-party.example",
        content_kind=CONTENT_LOCAL_FILE,
        char_count=500,
        task_justified=True,
        permission_granted=True,
    ).allowed

    assert not gov.authorize_transmission(
        destination="vision.example",
        content_kind=CONTENT_SCREENSHOT,
        char_count=1_000,
        task_justified=True,
        permission_granted=True,
    ).allowed

    gov.update_policy(allow_third_party_file_upload=True)
    # Excluded path is still blocked even when file upload is enabled!
    assert not gov.authorize_transmission(
        destination="partner.example",
        content_kind=CONTENT_LOCAL_FILE,
        source_path="/home/user/.ssh/id_ed25519",
        char_count=200,
        task_justified=True,
        permission_granted=True,
    ).allowed


# ---- §92 / §93 Plugins, MCP & §105 Gateway ----------------------------------


def test_mcp_protocol_incompatibility_and_credential_revocation():
    mcp = MCPClientManager()
    bad_transport = InMemoryMCPTransport(protocol_version="1999-01-01")
    mcp.register_server(
        MCPServerConfig(server_id="legacy", transport=TRANSPORT_MEMORY, endpoint_or_cmd="mem://legacy", bearer_token="tok-12345678"),
        transport_override=bad_transport,
    )
    res = mcp.connect("legacy")
    assert res["connected"] is False
    assert res["status"] == STATUS_VERSION_INCOMPATIBLE

    revoked = mcp.disable_and_revoke("legacy")
    assert revoked["disabled"] is True and revoked["credentials_revoked"] is True
    assert mcp.list_servers()[0]["status"] == STATUS_DISABLED
    assert mcp.list_servers()[0]["credentials_configured"] is False


def test_integration_gateway_enforces_minimum_scopes_and_rate_limits():
    gw = IntegrationGateway()
    gw.register(
        IntegrationRecord(
            integration_id="svc",
            kind="external_service",
            label="Test Service",
            capabilities=("read", "write"),
            supported_operations={"read": "svc:read", "admin_wipe": "svc:admin"},
            minimum_scopes=("svc:read",),
            granted_scopes=("svc:read",),
            rate_limit_per_minute=2,
        )
    )
    gw.record_auth_test("svc", True)
    assert gw.check_operation("svc", "admin_wipe")["allowed"] is False
    assert gw.check_operation("svc", "read")["allowed"] is True
    assert gw.check_operation("svc", "read")["allowed"] is True
    limited = gw.check_operation("svc", "read")
    assert limited["allowed"] is False and limited["rate_limited"] is True


def test_plugin_update_does_not_auto_grant_newly_requested_permissions(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    pm = PluginManager(plugins_dir=tmp_path / "plugins", workspace_root=ws)

    v1 = tmp_path / "p_v1"
    v1.mkdir()
    (v1 / "plugin_main.py").write_text("import json\nprint(json.dumps({'ok': True}))\n", encoding="utf-8")
    (v1 / "plugin.json").write_text(
        '{"name":"demo-plug","version":"0.1.0","purpose":"Demo plugin v1","category":"development",'
        '"operations":[{"name":"run","description":"Run demo","input_schema":{"type":"object"},"output_schema":{"type":"object"}}],'
        '"required_permissions":["workspace.read"]}',
        encoding="utf-8",
    )
    assert pm.install_from_directory(v1)["installed"] is True
    assert pm.enable("demo-plug", granted_permissions=("workspace.read",))["enabled"] is True

    # v2 adds network.https_allowlist permission -> update installs disabled rather than escalating privileges!
    v2 = tmp_path / "p_v2"
    v2.mkdir()
    (v2 / "plugin_main.py").write_text("import json\nprint(json.dumps({'ok': True}))\n", encoding="utf-8")
    (v2 / "plugin.json").write_text(
        '{"name":"demo-plug","version":"0.2.0","purpose":"Demo plugin v2","category":"development",'
        '"operations":[{"name":"run","description":"Run demo","input_schema":{"type":"object"},"output_schema":{"type":"object"}}],'
        '"required_permissions":["workspace.read","network.https_allowlist"]}',
        encoding="utf-8",
    )
    upd = pm.update_plugin("demo-plug", v2)
    assert upd["updated"] is True
    assert upd["plugin"]["enabled"] is False


# ---- §96 Terminal, §97/§98 Workflows, §100 Devtools, §108 Data, §99/§107 ----


@pytest.mark.asyncio
async def test_terminal_workspace_distinguishes_nova_and_user_actors_and_diffs(tmp_path):
    tw = TerminalWorkspace(default_cwd=tmp_path)
    s = tw.create_session("dev", task_id="t1")
    await tw.execute_argv(s.session_id, ["echo", "from-nova"], actor=ACTOR_NOVA)
    await tw.execute_argv(s.session_id, ["echo", "from-user"], actor=ACTOR_USER)

    assert len(tw.search_history(actor=ACTOR_NOVA)) == 1
    assert len(tw.search_history(actor=ACTOR_USER)) == 1
    diff = tw.inspect_diff("a = 1\n", "a = 2\n", filename="cfg.py")
    assert diff["changed"] is True and diff["added_lines"] == 1 and diff["removed_lines"] == 1


@pytest.mark.asyncio
async def test_workflow_dry_run_and_duplicate_suppression():
    executed_live: list[str] = []

    async def _exec(tool: str, args: dict, approved: bool) -> dict:
        executed_live.append(tool)
        return {"status": "success"}

    we = WorkflowEngine(
        permission_check=lambda tool, args: {"action": "allow"},
        tool_executor=_exec,
        available_tools_fn=lambda: {"workspace.read_file"},
    )
    spec = WorkflowSpec(
        workflow_id="wf-read",
        name="Read notes",
        entry_block_id="trig",
        blocks=[
            WorkflowBlock(block_id="trig", block_type="trigger", label="Start", next_blocks=["rd"]),
            WorkflowBlock(block_id="rd", block_type="file_operation", label="Read", config={"operation": "read", "path": "n.md"}, next_blocks=["done"]),
            WorkflowBlock(block_id="done", block_type="completion", label="Done"),
        ],
    )
    we.save_workflow(spec, activate=True)

    dry = await we.execute("wf-read", dry_run=True)
    assert dry["status"] == "dry_run_ok" and executed_live == []

    live1 = await we.execute("wf-read", dedupe_key="run-once")
    assert live1["status"] == "completed" and len(executed_live) == 1
    live2 = await we.execute("wf-read", dedupe_key="run-once")
    assert live2["status"] == "duplicate_refused" and len(executed_live) == 1


def test_cross_app_gui_refusal_and_data_workspace_comparison(tmp_path):
    ca = CrossAppCoordinator(workspace_root=tmp_path)
    gui_res = ca.execute_report_checklist_draft_flow(
        run_id="gui-1",
        notes_rel_path="n.md",
        report_rel_path="r.md",
        checklist_rel_path="c.md",
        email_draft_rel_path="e.json",
        require_gui_stage=True,
    )
    assert gui_res["status"] == "failed"
    assert "refusing to simulate" in gui_res["failed_stage"]["reason"]

    (tmp_path / "v1.md").write_text("# Doc\nLine A\n", encoding="utf-8")
    (tmp_path / "v2.md").write_text("# Doc\nLine B [1](https://example.org)\n", encoding="utf-8")
    dw = DataWorkspace(workspace_root=tmp_path)
    cmp_out = dw.compare_documents("v1.md", "v2.md")
    assert cmp_out["generated_analysis"]["identical"] is False
    cites = dw.extract_knowledge_and_citations("v2.md")
    assert len(cites["generated_analysis"]["citations"]) >= 1


def test_devtools_and_modalities_invariants(tmp_path):
    assert CONTINUOUS_SCREEN_CAPTURE is False
    assert SPEAKER_ID_AUTHORIZES_PRIVILEGED is False

    assert not check_git_or_deploy_action("git reset --hard HEAD~1")["allowed"]
    assert check_git_or_deploy_action("git reset --hard HEAD~1", operator_approved=True)["allowed"]
    assert check_git_or_deploy_action("git status")["allowed"]

    tb = analyze_traceback('  File "mod.py", line 7, in f\n    raise ValueError("bad")\nValueError: bad')
    assert tb["exception_type"] == "ValueError"

    dev = DeveloperWorkspace(repo_root=Path(__file__).resolve().parent.parent)
    discovered = dev.discover_tests()
    assert discovered["file_count"] >= 5

    png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + struct.pack(">II", 16, 16) + b"abcd"
    (tmp_path / "shot.png").write_bytes(png)
    va = VisualAssistant(workspace_root=tmp_path, vision_analyzer=lambda b, p: {"summary": "button"})
    denied_upload = va.inspect_with_vision_model("shot.png", "describe", external_upload_authorized=False)
    assert denied_upload["ok"] is False and denied_upload["verified_system_fact"] is False

    vl = VoiceLayer(
        consent_granted=False,
        recognizers=[DeterministicLoopbackRecognizer()],
        synthesizers=[DeterministicLoopbackSynthesizer()],
    )
    assert vl.start_push_to_talk()["started"] is False
    vl.consent_granted = True
    assert vl.start_push_to_talk()["microphone_active"] is True
    assert vl.stop_push_to_talk()["microphone_active"] is False
    spoken = vl.speak_task_status("t-1", "waiting_approval", "Approval required.")
    assert spoken["spoken"] is True


# ---- Platform HTTP API & Health Probe Resilience ----------------------------


def test_platform_http_endpoints_and_health_resilience(platform_client):
    client, _db, app, _settings = platform_client

    h = client.get("/api/health").json()
    assert "platform" in h
    assert set(h["platform"].keys()) == {
        "operation_mode",
        "resource_pressure",
        "sandbox_mechanism",
        "sandbox_available",
        "fts5_available",
        "degraded",
        "detail",
    }

    assert client.get("/api/platform/summary").status_code == 200
    caps = client.get("/api/platform/capabilities?refresh=true").json()
    assert caps["auto_install_permitted"] is False
    assert len(caps["features"]) == 24

    idx = client.post(
        "/api/platform/knowledge/index",
        json={"document_id": "api-doc-1", "title": "Kali Notes", "text": "Namespace sandbox confinement verified.", "project": "p1"},
    )
    assert idx.status_code == 200 and idx.json()["action"] == "indexed"

    srch = client.post("/api/platform/knowledge/search", json={"query": "confinement", "project": "p1"})
    assert srch.status_code == 200 and srch.json()["result_count"] == 1

    plugins = client.get("/api/platform/plugins").json()["plugins"]
    assert len(plugins) >= 4
    assert client.post("/api/platform/plugins/readonly-fs-search/enable", json={"granted_permissions": []}).status_code == 422
    en = client.post("/api/platform/plugins/readonly-fs-search/enable", json={"granted_permissions": ["workspace.read"]})
    assert en.status_code == 200 and "plugin.readonly-fs-search.search" in en.json()["registered_tools"]

    prop = client.post("/api/platform/workflows/propose", json={"instruction": "Read workspace notes and verify"})
    assert prop.status_code == 200 and prop.json()["status"] == "draft"

    inv = client.get("/api/platform/privacy/inventory").json()
    assert inv["integration_credentials"]["values_exposed"] is False
    assert client.get("/api/platform/diagnostics/export").status_code == 200

    # Broken platform object must NEVER crash /api/health.
    class _BrokenPlatform:
        def __getattr__(self, _name):
            raise RuntimeError("boom")

    app.state.platform = _BrokenPlatform()
    h_broken = client.get("/api/health")
    assert h_broken.status_code == 200
    assert h_broken.json()["platform"]["degraded"] is True


def test_platform_routes_require_session_when_access_token_is_configured(environment):
    settings, db, registry, _ws = environment
    secured = replace(settings, access_token="test-access-token-123456")
    app = create_app(secured, provider=FakeProvider([]), db=db, tools=registry)
    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/platform/summary").status_code == 401
        assert client.get("/api/platform/privacy/inventory").status_code == 401


# ---- §112 Release Engineering: DB Migration, Install, Upgrade & Uninstall ---


def test_release_engineering_db_migration_and_deb_install_upgrade_uninstall(tmp_path):
    import shutil
    import sqlite3
    import subprocess

    from nova import __version__
    from nova.db import Database
    from nova.updates import UpdateManager

    # 1. Database migration test: create a minimal pre-cognition SQLite DB with user data,
    #    then run Database.initialize() + UpdateManager.check_migrations().
    legacy_db_path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(legacy_db_path) as conn:
        conn.execute(
            "CREATE TABLE conversations (id TEXT PRIMARY KEY, title TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO conversations(id, title, created_at, updated_at) VALUES ('c-legacy', 'Keep across migration', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
        )
        conn.commit()

    migrated = Database(legacy_db_path)
    migrated.initialize()
    um = UpdateManager(db=migrated, staging_dir=tmp_path / "upd")
    mig_check = um.check_migrations()
    assert mig_check["ok"] is True
    assert any(c["id"] == "c-legacy" for c in migrated.list_conversations())

    # 2. Debian package build, install-tree extraction, CLI smoke check & clean uninstall separation.
    if shutil.which("dpkg-deb") is None:
        return
    repo_root = Path(__file__).resolve().parent.parent
    build = subprocess.run(
        ["bash", str(repo_root / "scripts" / "build_deb.sh")],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    deb_file = repo_root / "releases" / f"nova-x-desktop_{__version__}_all.deb"
    assert deb_file.is_file()

    install_root = tmp_path / "pkgroot"
    extract = subprocess.run(
        ["dpkg-deb", "--extract", str(deb_file), str(install_root)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert extract.returncode == 0
    assert (install_root / "usr" / "lib" / "nova-x" / "nova" / "platform_service.py").is_file()
    assert (install_root / "usr" / "lib" / "nova-x" / "nova" / "sandbox.py").is_file()
    assert not list(install_root.rglob("*.pyc"))

    cli_run = subprocess.run(
        [sys.executable, str(install_root / "usr" / "bin" / "nova-x"), "--version"],
        env={"PYTHONPATH": str(install_root / "usr" / "lib" / "nova-x"), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert cli_run.returncode == 0
    assert __version__ in cli_run.stdout

    # Simulated uninstall removes /usr/lib/nova-x & /usr/bin/nova-x without touching user SQLite data.
    shutil.rmtree(install_root / "usr")
    assert legacy_db_path.is_file()
    assert any(c["id"] == "c-legacy" for c in migrated.list_conversations())
