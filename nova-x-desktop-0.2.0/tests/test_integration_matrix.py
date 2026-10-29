"""§114 Integration Testing Matrix — repeatable verification of items 1–18."""
from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import time
import tracemalloc
from pathlib import Path

import pytest

from nova.autonomy import AutonomyPolicy
from nova.context_manager import COMPARTMENT_APPROVED_MEMORY, ContextOptimizer
from nova.data_workspace import DataWorkspace
from nova.db import Database
from nova.desktop.commands import CommandRunner, build_command_tools
from nova.desktop.policy import CommandPolicy
from nova.desktop.runtime import DesktopRuntime
from nova.engine import TaskEngine
from nova.governance import SystemHealthCenter
from nova.knowledge import SOURCE_DOCUMENTATION, KnowledgeStore
from nova.mcp_client import (
     STATUS_DISCONNECTED,
    TRANSPORT_MEMORY,
    TRANSPORT_STDIO,
    InMemoryMCPTransport,
    IntegrationGateway,
    IntegrationRecord,
    MCPClientManager,
    MCPServerConfig,
)
from nova.observability import REDACTED, SPAN_MODEL_CALL, Redactor, TraceCollector
from nova.plugins import PluginManager, builtin_sdk_examples, validate_extension_source_ast
from nova.resources import (
    PRESSURE_CRITICAL,
    PRESSURE_HIGH,
    PRESSURE_NORMAL,
    ResourceManager,
    ResourceSample,
)
from nova.sandbox import (
    MECHANISM_NONE,
    RISK_UNTRUSTED_CODE,
    STATUS_COMPLETED,
    STATUS_REFUSED,
    IsolationCapability,
    Sandbox,
    SandboxPolicy,
)
from nova.terminal import ACTOR_NOVA, TerminalWorkspace
from nova.updates import (
    MODE_OFFLINE,
    MODE_ONLINE,
    OfflineCoordinator,
    ReleaseDescriptor,
    UpdateManager,
)
from nova.workflows import WorkflowBlock, WorkflowEngine, WorkflowSpec
from tests.conftest import FakeProvider, msg


# 1. The native application starts without a browser.
def test_matrix_01_native_application_starts_without_browser(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    ws_dir = tmp_path / "ws"
    monkeypatch.setenv("NOVA_DESKTOP_MODE", "1")
    monkeypatch.setenv("NOVA_DATA_DIR", str(data_dir))
    monkeypatch.setenv("NOVA_DB_PATH", str(data_dir / "nova.sqlite3"))
    monkeypatch.setenv("NOVA_WORKSPACE_DIR", str(ws_dir))

    runtime = DesktopRuntime()
    try:
        diag = runtime.diagnostics()
        assert diag["database_path"] == str((data_dir / "nova.sqlite3").resolve())
        assert "playwright" not in sys.modules
        assert runtime.platform.summary()["fts5_available"] is True
    finally:
        runtime.close()


# 2. The local task engine can execute and report a permitted command.
@pytest.mark.asyncio
async def test_matrix_02_task_engine_executes_and_reports_permitted_command(environment):
    settings, db, registry, workspace = environment
    db.set_desktop_setting("workspace_roots", [str(workspace)])
    db.set_desktop_setting("active_workspace", str(workspace))
    policy = CommandPolicy(db)
    runner = CommandRunner(settings, db, policy)
    for tool_def in build_command_tools(settings, db, runner):
        registry.register(tool_def)
    db.update_autonomy_policy("routine", {"system.run_command": "allow"}, [])

    call = {
        "id": "call-pwd",
        "type": "function",
        "function": {"name": "system.run_command", "arguments": '{"program":"pwd","arguments":[]}'},
    }
    provider = FakeProvider(
        [
            msg('{"summary":"Check cwd","steps":["Run pwd"]}'),
            msg(None, [call]),
            msg("Working directory confirmed."),
            msg('{"status":"verified","note":"pwd output matches workspace"}'),
        ]
    )
    engine = TaskEngine(db, provider, registry, settings)
    task_id = db.create_task("Print working directory", review_plan=False)
    await engine.run_task(task_id)

    task = db.get_task(task_id)
    assert task["state"] == "completed"
    assert task["verification"] == "verified"
    trace = engine.platform.traces.explain_task(task_id)
    assert "system.run_command" in trace["tools_invoked"]


# 3. Command cancellation works.
@pytest.mark.asyncio
async def test_matrix_03_command_cancellation_terminates_process(tmp_path):
    tw = TerminalWorkspace(default_cwd=tmp_path)
    session = tw.create_session("cancel-check")

    run_coro = asyncio.create_task(
        tw.execute_argv(
            session.session_id,
            [sys.executable, "-c", "import time; time.sleep(30)"],
            actor=ACTOR_NOVA,
            time_limit_seconds=30.0,
        )
    )
    await asyncio.sleep(0.15)
    run_coro.cancel()
    with pytest.raises(asyncio.CancelledError):
        await run_coro

    assert len(session.records) == 1
    rec = session.records[0]
    assert rec.cancelled is True
    assert rec.is_active() is False


# 4. Plugin installation respects declared permissions.
def test_matrix_04_plugin_installation_respects_declared_permissions(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "sample.txt").write_text("alpha beta gamma\n", encoding="utf-8")
    pm = PluginManager(plugins_dir=tmp_path / "plugins", workspace_root=ws)

    for ext in builtin_sdk_examples():
        pm.register_sdk_extension(ext)

    # Installed plugin starts disabled with zero granted permissions.
    denied_disabled = pm.execute("readonly-fs-search", "search", {"query": "alpha"})
    assert denied_disabled["status"] == "denied"

    # Cannot enable without granting required permissions.
    missing_grant = pm.enable("readonly-fs-search", granted_permissions=())
    assert missing_grant["enabled"] is False

    # Enabling with exact declared permission allows scoped execution.
    enabled = pm.enable("readonly-fs-search", granted_permissions=("workspace.read",))
    assert enabled["enabled"] is True
    ok = pm.execute("readonly-fs-search", "search", {"query": "beta"})
    assert ok["status"] == "success" and ok["data"]["count"] == 1

    # Escaping workspace scope is denied even when enabled.
    escape = pm.execute("readonly-fs-search", "search", {"query": "root", "subpath": "../../etc"})
    assert escape["status"] == "denied"

    # Direct imports of NOVA's permission/DB internals are rejected statically.
    assert validate_extension_source_ast("import nova.autonomy\n")


# 5. A compatible MCP server can be connected, inspected, and disconnected.
def test_matrix_05_mcp_server_connect_inspect_call_and_disconnect(tmp_path):
    server_script = tmp_path / "stdio_mcp_server.py"
    server_script.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    msg = json.loads(line)\n"
        "    if 'id' not in msg:\n"
        "        continue\n"
        "    m = msg['method']\n"
        "    if m == 'initialize':\n"
        "        res = {'protocolVersion': '2024-11-05', 'serverInfo': {'name': 'stdio-demo', 'version': '1.0'}, 'capabilities': {'tools': {}}}\n"
        "    elif m == 'tools/list':\n"
        "        res = {'tools': [{'name': 'ping', 'description': 'Echo ping', 'inputSchema': {'type': 'object', 'required': ['msg'], 'properties': {'msg': {'type': 'string'}}}}]}\n"
        "    elif m == 'resources/list':\n"
        "        res = {'resources': [{'uri': 'memo://1', 'name': 'Memo 1'}]}\n"
        "    elif m == 'tools/call':\n"
        "        res = {'content': [{'type': 'text', 'text': 'pong:' + msg['params']['arguments']['msg']}], 'isError': False}\n"
        "    else:\n"
        "        res = {}\n"
        "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': res}) + '\\n')\n"
        "    sys.stdout.flush()\n",
        encoding="utf-8",
    )

    mcp = MCPClientManager(permission_check=lambda tool, args: {"action": "allow"})
    mcp.register_server(
        MCPServerConfig(
            server_id="stdio_demo",
            transport=TRANSPORT_STDIO,
            endpoint_or_cmd=[sys.executable, str(server_script)],
            granted_scopes=("demo.ping",),
        )
    )
    connected = mcp.connect("stdio_demo")
    assert connected["connected"] is True
    assert connected["server_identity"]["name"] == "stdio-demo"
    assert connected["available_tools"][0]["name"] == "ping"
    assert connected["available_resources"][0]["uri"] == "memo://1"

    called = mcp.call_tool("stdio_demo", "ping", {"msg": "kali"})
    assert called["status"] == "success"
    assert called["trust_level"] == "untrusted_external"
    assert called["conversation_forwarded"] is False

    disc = mcp.disconnect("stdio_demo")
    assert disc["disconnected"] is True and disc["status"] == STATUS_DISCONNECTED


# 6. A disconnected integration produces a useful error.
def test_matrix_06_disconnected_integration_produces_useful_error():
    mcp = MCPClientManager()
    transport = InMemoryMCPTransport(tools=[{"name": "t1", "inputSchema": {"type": "object"}}])
    mcp.register_server(
        MCPServerConfig(server_id="srv", transport=TRANSPORT_MEMORY, endpoint_or_cmd="mem://srv"),
        transport_override=transport,
    )
    mcp.connect("srv")
    mcp.disconnect("srv")

    err = mcp.call_tool("srv", "t1", {})
    assert err["status"] == "error"
    assert "srv" in err["error"] and "disconnected" in err["error"]

    gw = IntegrationGateway()
    gw.register(
        IntegrationRecord(
            integration_id="cloud-primary",
            kind="ai_provider",
            label="Cloud Primary",
            capabilities=("chat",),
            supported_operations={"chat": "chat:use"},
            minimum_scopes=("chat:use",),
            credentials_present=False,
            fallback_ids=("local-fallback",),
        )
    )
    gw.register(
        IntegrationRecord(
            integration_id="local-fallback",
            kind="ai_provider",
            label="Local Fallback",
            capabilities=("chat",),
            supported_operations={"chat": "chat:use"},
            minimum_scopes=("chat:use",),
            granted_scopes=("chat:use",),
            credentials_present=True,
        )
    )
    chk = gw.check_operation("cloud-primary", "chat")
    assert chk["allowed"] is False
    assert "missing required credentials" in chk["reason"]
    assert chk["fallbacks"] == ["local-fallback"]


# 7. Full-text search returns the correct local document passages.
def test_matrix_07_fts5_returns_correct_local_document_passages(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    doc_a = ws / "sandbox_design.md"
    doc_b = ws / "cooking_notes.md"
    doc_a.write_text("Line 1\nBubblewrap mounts the root filesystem read-only and isolates PID namespaces.\n", encoding="utf-8")
    doc_b.write_text("Simmer tomatoes with basil for twenty minutes.\n", encoding="utf-8")

    store = KnowledgeStore(db_path=str(tmp_path / "k.sqlite3"), workspace_root=str(ws))
    try:
        store.index_directory(ws, project="sec")
        out = store.search("filesystem namespaces", project="sec", source_kinds=(SOURCE_DOCUMENTATION,), use_semantic=False)
        assert out["result_count"] == 1
        top = out["results"][0]
        assert "sandbox_design.md" in top["citation"]
        assert "line" in top["citation"].lower()
        assert "namespaces" in top["text"].lower()
    finally:
        store.close()


# 8. Optional semantic retrieval behaves correctly when configured.
def test_matrix_08_optional_semantic_retrieval_behaves_honestly_and_hybridizes(tmp_path):
    store = KnowledgeStore(db_path=str(tmp_path / "sem.sqlite3"))
    try:
        store.index_text(
            "Automobile engine thermal diagnostics and coolant pressure sensor.",
            document_id="doc-car",
            title="Vehicle manual",
        )
        store.index_text(
            "PostgreSQL B-tree index bloat vacuuming.",
            document_id="doc-db",
            title="DB notes",
        )
        # Without embedder: honestly reports semantic unavailable.
        unconfigured = store.search("car motor overheating", use_semantic=True)
        assert unconfigured["semantic"]["available"] is False

        # Configure deterministic 2-D concept embedder (paraphrase match with zero lexical overlap).
        def _embed(texts: list[str]) -> list[list[float]]:
            vecs = []
            for t in texts:
                low = t.lower()
                if any(w in low for w in ("automobile", "car", "motor", "thermal", "overheating")):
                    vecs.append([1.0, 0.0])
                else:
                    vecs.append([0.0, 1.0])
            return vecs

        store.embedder = _embed
        store.embedding_model = "deterministic-2d"
        store.embedding_location = "local"
        store.index_text(
            "Automobile engine thermal diagnostics and coolant pressure sensor. Updated.",
            document_id="doc-car",
            title="Vehicle manual",
            embed=True,
        )
        store.index_text(
            "PostgreSQL B-tree index bloat vacuuming. Updated.",
            document_id="doc-db",
            title="DB notes",
            embed=True,
        )
        configured = store.search("car motor overheating", use_semantic=True)
        assert configured["semantic"]["available"] is True
        assert configured["result_count"] >= 1
        assert configured["results"][0]["document_id"] == "doc-car"
    finally:
        store.close()


# 9. A sandboxed task cannot access resources outside its granted scope.
def test_matrix_09_sandboxed_task_cannot_access_outside_granted_scope(tmp_path, monkeypatch):
    allowed_dir = tmp_path / "allowed"
    outside_dir = tmp_path / "outside"
    secret_dir = tmp_path / "secrets"
    for d in (allowed_dir, outside_dir, secret_dir):
        d.mkdir()
    (secret_dir / "key.txt").write_text("TOP-SECRET-VALUE", encoding="utf-8")

    sbx = Sandbox()
    cap = sbx.detect(force=True)
    if cap.available:
        probe = (
            "import json, os, socket\n"
            f"allowed = {str(allowed_dir / 'ok.txt')!r}\n"
            f"outside = {str(outside_dir / 'escape.txt')!r}\n"
            f"secret = {str(secret_dir / 'key.txt')!r}\n"
            "res = {}\n"
            "open(allowed, 'w').write('allowed')\n"
            "res['allowed_write'] = True\n"
            "try:\n"
            "    open(outside, 'w').write('escaped')\n"
            "    res['outside_write'] = True\n"
            "except OSError:\n"
            "    res['outside_write'] = False\n"
            "try:\n"
            "    res['secret_read'] = open(secret).read()\n"
            "except OSError:\n"
            "    res['secret_read'] = None\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1', 53), timeout=1)\n"
            "    res['net'] = True\n"
            "except OSError:\n"
            "    res['net'] = False\n"
            "print(json.dumps(res))\n"
        )
        run = sbx.run(
            [sys.executable, "-c", probe],
            risk=RISK_UNTRUSTED_CODE,
            policy=SandboxPolicy(
                writable_roots=(str(allowed_dir),),
                hidden_paths=(str(secret_dir),),
                network=False,
                timeout_seconds=15.0,
            ),
        )
        assert run.status == STATUS_COMPLETED, run.stderr
        parsed = json.loads(run.stdout.strip())
        assert parsed["allowed_write"] is True
        assert parsed["outside_write"] is False
        assert parsed["secret_read"] is None
        assert parsed["net"] is False
        assert not (outside_dir / "escape.txt").exists()

    # Regardless of host kernel, when isolation is unavailable risky code MUST fail closed (never silently run on host).
    sbx_unavailable = Sandbox()
    monkeypatch.setattr(
        sbx_unavailable,
        "_detect",
        lambda: IsolationCapability(mechanism=MECHANISM_NONE, available=False, detail="kernel userns disabled"),
    )
    marker = outside_dir / "must_not_exist.txt"
    refused = sbx_unavailable.run(
        [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('ran')"],
        risk=RISK_UNTRUSTED_CODE,
    )
    assert refused.status == STATUS_REFUSED
    assert not marker.exists()


# 10. Background task state survives supported application restarts.
def test_matrix_10_background_task_state_survives_restart(tmp_path):
    db_file = tmp_path / "durable.sqlite3"
    db1 = Database(db_file)
    db1.initialize()
    task_id = db1.create_task("Long-horizon audit", review_plan=False)
    db1.update_task(
        task_id,
        state="running",
        plan={"summary": "Two-step audit", "steps": ["Inspect logs", "Summarize"]},
        checkpoint={"step_index": 1, "tool_results": [{"tool": "workspace.list_files", "status": "success"}]},
    )

    # Simulate application restart by opening a fresh Database instance and recovering interrupted tasks.
    db2 = Database(db_file)
    db2.initialize()
    recovered_count = db2.recover_interrupted_tasks()
    assert recovered_count == 1
    restored = db2.get_task(task_id)
    assert restored is not None
    assert restored["state"] == "paused"
    assert restored["plan"]["steps"] == ["Inspect logs", "Summarize"]
    assert restored["checkpoint"]["step_index"] == 1


# 11. Logs redact configured secrets.
def test_matrix_11_logs_and_diagnostics_redact_configured_secrets(tmp_path):
    db = Database(tmp_path / "red.sqlite3")
    db.initialize()
    secret_val = "nova-secret-token-987654"
    red = Redactor(literal_secrets=(secret_val,))
    traces = TraceCollector(redactor=red)
    traces.record(
        name="auth_call",
        kind=SPAN_MODEL_CALL,
        task_id="t-sec",
        result_summary=f"Authorization: Bearer {secret_val} and api_key=sk-abcdefghijklmnop1234",
        attributes={"password": "my-db-password", "url": "https://admin:hunter22@example.com/api"},
    )
    hc = SystemHealthCenter(db=db, redactor=red, traces=traces)
    hc.record_api_error("openai", f"failed with key {secret_val}")
    report = hc.export_diagnostic_report(configuration_checks={"access_token": secret_val})
    serialized = json.dumps(report)

    assert secret_val not in serialized
    assert "sk-abcdefghijklmnop1234" not in serialized
    assert "my-db-password" not in serialized
    assert "hunter22" not in serialized
    assert REDACTED in serialized


# 12. Resource controls operate within their defined limits.
def test_matrix_12_resource_controls_operate_within_defined_limits():
    rm = ResourceManager(low_resource_mode=True, baseline_parallel_tasks=2, baseline_model_concurrency=3)

    normal = rm.with_sample(
        ResourceSample(
            collected_at="2026-10-29T00:00:00+00:00",
            source="proc",
            cpu_count=2,
            load_1m=0.4,
            load_per_cpu=0.2,
            memory_total_mb=10_240,
            memory_available_mb=6_500,
            memory_available_ratio=0.63,
            disk_free_bytes=20 * 1024**3,
            disk_free_mb=20_480,
        )
    )
    assert normal.pressure == PRESSURE_NORMAL
    assert normal.indexing_enabled is True
    assert normal.allow_local_model_start is False

    high = rm.with_sample(
        ResourceSample(
            collected_at="2026-10-29T00:01:00+00:00",
            source="proc",
            cpu_count=2,
            load_1m=5.0,
            load_per_cpu=2.5,
            memory_total_mb=10_240,
            memory_available_mb=1_500,
            memory_available_ratio=0.14,
            disk_free_bytes=1 * 1024**3,
            disk_free_mb=1_024,
        )
    )
    assert high.pressure == PRESSURE_HIGH
    assert high.max_parallel_tasks == 1
    assert high.max_model_concurrency == 1
    assert high.indexing_enabled is False

    crit = rm.with_sample(
        ResourceSample(
            collected_at="2026-10-29T00:02:00+00:00",
            source="proc",
            cpu_count=2,
            load_1m=9.0,
            load_per_cpu=4.5,
            memory_total_mb=10_240,
            memory_available_mb=500,
            memory_available_ratio=0.05,
            disk_free_bytes=200 * 1024**2,
            disk_free_mb=200,
        )
    )
    assert crit.pressure == PRESSURE_CRITICAL
    assert crit.max_background_workers == 0


# 13. Application updates preserve user settings and data.
def test_matrix_13_updates_preserve_user_settings_and_data(tmp_path):
    db = Database(tmp_path / "upd.sqlite3")
    db.initialize()
    convo_id = db.create_conversation("Important Research")
    db.add_message(convo_id, "user", "Preserve this across updates.")
    db.set_desktop_setting("ui_theme", "kali-midnight")

    artifact = tmp_path / "nova-x-desktop_0.3.0_all.deb"
    artifact.write_bytes(b"verified-release-archive")
    sha = hashlib.sha256(artifact.read_bytes()).hexdigest()

    um = UpdateManager(db=db, staging_dir=tmp_path / "staging", current_version="0.2.0")
    res = um.stage_and_apply(
        ReleaseDescriptor(version="0.3.0", sha256=sha, signed=True),
        artifact_path=artifact,
        launch_probe=lambda: True,
        operator_confirmed=True,
        extra_settings={"ui_theme": "kali-midnight"},
    )
    assert res["applied"] is True
    assert um.current_version == "0.3.0"
    assert db.get_desktop_setting("ui_theme") == "kali-midnight"
    assert db.get_messages(convo_id)[0]["content"] == "Preserve this across updates."


# 14. The application can operate in a reduced offline mode.
def test_matrix_14_application_operates_in_reduced_offline_mode(tmp_path):
    oc = OfflineCoordinator()
    status = oc.set_mode(MODE_OFFLINE, reason="network interface down")
    assert status["degraded"] is True
    assert "search_indexed_local_documents_fts" in status["available_offline"]
    assert "live_external_web_research" in status["degraded_capabilities"]

    # Cloud/online calls are refused without fabricating output.
    blocked = oc.guard_online_operation("web.search")
    assert blocked["allowed"] is False and blocked["fabricated"] is False

    # Meanwhile local FTS5 search and deterministic tools still work completely offline.
    ks = KnowledgeStore(db_path=str(tmp_path / "off_k.sqlite3"))
    try:
        ks.index_text("Offline Kali manual entry for iproute2.", document_id="d1")
        assert ks.search("iproute2", use_semantic=False)["result_count"] == 1
    finally:
        ks.close()

    # Queued task revalidates assumptions & permissions before resuming.
    queued = oc.enqueue_for_online(objective="Run remote check", required_tool="web.search", assumptions=("branch_clean",))
    oc.set_mode(MODE_ONLINE)
    denied_resume = oc.prepare_resume(
        queued.queue_id,
        assumption_validator=lambda a: False,
    )
    assert denied_resume["resumable"] is False


# 15. A failed update or candidate release does not silently destroy the stable installation.
def test_matrix_15_failed_update_rolls_back_and_preserves_stable_install(tmp_path):
    db = Database(tmp_path / "rollback.sqlite3")
    db.initialize()
    cid = db.create_conversation("Stable state")

    artifact = tmp_path / "broken_0.3.1.deb"
    artifact.write_bytes(b"candidate-binary")
    sha = hashlib.sha256(artifact.read_bytes()).hexdigest()

    um = UpdateManager(db=db, staging_dir=tmp_path / "staging", current_version="0.2.0")

    # Case A: AI-proposed untested build is rejected outright.
    ai_build = um.stage_and_apply(
        ReleaseDescriptor(version="0.3.1", sha256=sha, origin="ai_model"),
        artifact_path=artifact,
        launch_probe=lambda: True,
        operator_confirmed=True,
    )
    assert ai_build["applied"] is False and um.current_version == "0.2.0"

    # Case B: Candidate fails launch probe -> rolls back cleanly to 0.2.0 with DB intact.
    failed_launch = um.stage_and_apply(
        ReleaseDescriptor(version="0.3.1", sha256=sha),
        artifact_path=artifact,
        launch_probe=lambda: False,
        operator_confirmed=True,
    )
    assert failed_launch["applied"] is False
    assert failed_launch["rolled_back"] is True
    assert um.current_version == "0.2.0"
    assert any(c["id"] == cid for c in db.list_conversations())


# 16. A workflow cannot bypass the authorization policy.
@pytest.mark.asyncio
async def test_matrix_16_workflow_cannot_bypass_authorization_policy(environment):
    settings, db, registry, _ws = environment
    # `environment` fixture already registers workspace & calculator tools.
    policy = AutonomyPolicy(settings, db, registry)

    # Explicitly deny workspace.write_file in autonomy policy.
    db.update_autonomy_policy("routine", {"workspace.write_file": "deny"}, [])

    wf_engine = WorkflowEngine(
        permission_check=policy.decide,
        available_tools_fn=lambda: {t["name"] for t in registry.all_tools() if t["available"]},
    )
    spec = WorkflowSpec(
        workflow_id="wf-unauth-write",
        name="Attempt unauthorized write",
        entry_block_id="start",
        blocks=[
            WorkflowBlock(block_id="start", block_type="trigger", label="Start", next_blocks=["write"]),
            WorkflowBlock(
                block_id="write",
                block_type="file_operation",
                label="Write file",
                config={"operation": "write", "path": "forbidden.txt"},
                next_blocks=["done"],
            ),
            WorkflowBlock(block_id="done", block_type="completion", label="Done"),
        ],
    )
    save_res = wf_engine.save_workflow(spec, activate=True)
    assert save_res["activated"] is False
    assert any("denies 'workspace.write_file'" in issue for issue in save_res["validation"]["issues"])

    # Even if saved as draft while allowed and later revoked before execution, runtime re-check blocks it!
    db.update_autonomy_policy("high", {"workspace.write_file": "allow"}, ["forbidden.txt"])
    assert wf_engine.save_workflow(spec, activate=True)["activated"] is True
    db.update_autonomy_policy("routine", {"workspace.write_file": "deny"}, [])
    exec_res = await wf_engine.execute("wf-unauth-write", operator_approved=True)
    assert exec_res["status"] == "denied"


# 17. No UI element claims success without a corresponding backend result.
@pytest.mark.asyncio
async def test_matrix_17_no_ui_or_status_claims_success_without_backend_result(environment):
    settings, db, registry, _ws = environment
    # `environment` fixture already registers workspace tools.

    # Trigger an approval-gated write: task stops in waiting_approval, NOT completed.
    call = {
        "id": "call-w",
        "type": "function",
        "function": {"name": "workspace.write_file", "arguments": '{"path":"a.txt","content":"hi"}'},
    }
    db.update_autonomy_policy("assisted", {}, [])
    engine = TaskEngine(
        db,
        FakeProvider([msg('{"summary":"Write","steps":["Write a.txt"]}'), msg(None, [call])]),
        registry,
        settings,
    )
    task_id = db.create_task("Write file with approval", review_plan=False)
    await engine.run_task(task_id)
    task = db.get_task(task_id)
    assert task["state"] == "waiting_approval"
    assert task["verification"] != "verified"

    # Verify static UI code gates completion styling strictly on backend task.state.
    app_js = (Path(__file__).resolve().parent.parent / "static" / "app.js").read_text(encoding="utf-8")
    desktop_py = (Path(__file__).resolve().parent.parent / "nova" / "desktop" / "app.py").read_text(encoding="utf-8")
    assert "friendlyState(task.state)" in app_js and "['completed', 'failed', 'cancelled']" in app_js
    assert "waiting_approval" in desktop_py and "completed" in desktop_py


# 18. The application remains usable within the target hardware constraints.
def test_matrix_18_usable_within_dual_core_10gb_hardware_constraints(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    # Generate a 5,000-row CSV to verify streaming memory discipline.
    csv_path = ws / "large_metrics.csv"
    with csv_path.open("w", encoding="utf-8") as fh:
        fh.write("host,cpu,mem_mb\n")
        for idx in range(5_000):
            fh.write(f"node-{idx % 12},{(idx % 95) * 0.9:.2f},{1024 + (idx % 4096)}\n")

    tracemalloc.start()
    started = time.monotonic()
    try:
        dw = DataWorkspace(workspace_root=ws)
        prof = dw.profile_dataset("large_metrics.csv")
        opt = ContextOptimizer(budget_chars=8_000)
        for i in range(40):
            opt.add_item(
                item_id=f"item-{i}",
                compartment=COMPARTMENT_APPROVED_MEMORY,
                content=f"Memory note {i} about node-{i % 5} latency and memory budget.",
                provenance="user",
            )
        win = opt.assemble(objective="check node-1 memory budget", constraints=("low_resource_mode",))
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    elapsed = time.monotonic() - started
    peak_mb = peak_bytes / (1024 * 1024)
    assert prof["generated_analysis"]["rows_scanned"] == 5_000
    assert win.used_chars <= win.budget_chars
    # Well under 64 MB peak Python allocation and < 3s on a 2-core machine.
    assert peak_mb < 64.0, f"Peak memory {peak_mb:.1f} MB exceeded low-spec budget"
    assert elapsed < 3.0, f"Elapsed {elapsed:.2f}s exceeded responsiveness budget"
