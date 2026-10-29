from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from nova.autonomy import AutonomyPolicy
from nova.desktop.commands import CommandRunner, build_command_tools
from nova.desktop.policy import CommandPolicy, redact_text
from nova.desktop.secrets import SecretStore, SecretStoreError
from nova.engine import TaskEngine
from nova.tools import ToolRegistry
from nova.tools.registry import ToolOutcome


class FakeProvider:
    def __init__(self, responses):
        self.responses = list(responses)

    async def chat(self, messages, tools=None):
        assert self.responses, "fake response queue exhausted"
        return self.responses.pop(0)


def message(content=None, tool_calls=None):
    result = {"message": {"role": "assistant", "content": content}, "usage": {"total_tokens": 8}}
    if tool_calls is not None:
        result["message"]["tool_calls"] = tool_calls
    return result


@pytest.fixture
def desktop_components(environment):
    settings, database, _registry, workspace = environment
    database.set_desktop_setting("workspace_roots", [str(workspace)])
    database.set_desktop_setting("active_workspace", str(workspace))
    policy = CommandPolicy(database)
    runner = CommandRunner(settings, database, policy)
    return settings, database, workspace, policy, runner


def test_desktop_settings_and_command_history_are_durable(environment):
    _settings, database, _registry, workspace = environment
    database.set_desktop_setting("active_workspace", str(workspace))
    assert database.get_desktop_setting("active_workspace") == str(workspace)
    assert database.get_desktop_setting("missing", "fallback") == "fallback"
    record_id = database.add_command_history({
        "program": "echo", "arguments": ["hello"], "cwd": str(workspace), "status": "success",
        "exit_code": 0, "stdout": "hello\n", "stderr": "", "duration_seconds": 0.02,
    })
    rows = database.list_command_history("hello")
    assert rows[0]["id"] == record_id
    assert rows[0]["arguments"] == ["hello"]
    assert rows[0]["exit_code"] == 0
    assert database.clear_command_history() == 1
    assert database.list_command_history() == []


def test_command_policy_uses_token_prefixes_workspace_and_fresh_review(desktop_components):
    _settings, database, workspace, policy, _runner = desktop_components
    assert policy.evaluate(["pwd"], str(workspace))["action"] == "allow"
    assert policy.evaluate(["ls", "/etc/shadow"], str(workspace))["action"] == "approval_required"
    assert policy.evaluate(["echo", "hi"], str(workspace))["action"] == "approval_required"
    assert policy.evaluate(["bash", "-c", "echo unsafe"], str(workspace))["action"] == "deny"
    assert policy.evaluate(["sudo", "id"], str(workspace))["action"] == "deny"
    assert policy.evaluate(["curl", "https://example.invalid"], str(workspace))["action"] == "approval_required"
    assert policy.evaluate(["git", "push"], str(workspace))["action"] == "approval_required"
    assert policy.evaluate(["python3", "-m", "pytest"], str(workspace))["action"] == "approval_required"
    database.set_desktop_setting("trusted_command_prefixes", [["python3", "-m", "pytest"]])
    assert policy.evaluate(["python3", "-m", "pytest"], str(workspace))["action"] == "approval_required"


def test_trusted_prefix_validation_rejects_shell_privilege_and_arbitrary_code(desktop_components):
    _settings, _database, _workspace, policy, _runner = desktop_components
    assert policy.validate_prefixes(["git status"]) == [["git", "status"]]
    for invalid in ("bash -c echo", "sudo apt update", "python3 -m pytest", "python3 -c print(1)", "python3.13", "gcc", "git", "curl https://example.invalid", "make test"):
        with pytest.raises(ValueError):
            policy.validate_prefixes([invalid])


@pytest.mark.asyncio
async def test_real_installed_command_runs_and_records_actual_result(desktop_components):
    _settings, database, workspace, _policy, runner = desktop_components
    outcome = await runner.run(["pwd"], cwd=str(workspace), source="manual_ui")
    assert outcome.status == "success"
    assert outcome.data["exit_code"] == 0
    assert outcome.data["stdout"].strip() == str(workspace)
    history = database.list_command_history()
    assert len(history) == 1
    assert history[0]["program"] == "pwd"
    assert history[0]["status"] == "success"
    assert Path(history[0]["log_path"]).is_file()


@pytest.mark.asyncio
async def test_unknown_command_requires_review_and_is_not_started_without_it(desktop_components):
    _settings, database, workspace, _policy, runner = desktop_components
    outcome = await runner.run(["echo", "hello"], cwd=str(workspace), source="manual_ui")
    assert outcome.status == "approval_required"
    assert database.list_command_history() == []
    approved = await runner.run(["echo", "hello"], cwd=str(workspace), approved=True, source="manual_ui")
    assert approved.status == "success"
    assert approved.data["stdout"].strip() == "hello"
    assert database.list_command_history()[0]["exit_code"] == 0


@pytest.mark.asyncio
async def test_user_authored_shell_requires_fresh_confirmation(desktop_components):
    _settings, database, workspace, _policy, runner = desktop_components
    pending = await runner.run_manual_shell("printf 'hello from reviewed shell\\n'", str(workspace), approved=False)
    assert pending.status == "approval_required"
    assert database.list_command_history() == []
    result = await runner.run_manual_shell("printf 'hello from reviewed shell\\n'", str(workspace), approved=True)
    assert result.status == "success"
    assert result.data["stdout"].strip() == "hello from reviewed shell"


@pytest.mark.asyncio
async def test_known_credential_argument_is_redacted_from_live_result_history_and_log(desktop_components):
    _settings, database, workspace, _policy, runner = desktop_components
    secret = "NOVA_TEST_SUPER_SECRET_VALUE"
    first = await runner.run(["echo", "--password", secret], cwd=str(workspace), source="manual_ui")
    assert first.status == "approval_required"
    result = await runner.run(["echo", "--password", secret], cwd=str(workspace), approved=True, source="manual_ui")
    assert result.status == "success"
    assert secret not in result.data["stdout"]
    row = database.list_command_history()[0]
    assert secret not in str(row)
    assert secret not in Path(row["log_path"]).read_text()
    assert "[REDACTED]" in row["stdout"]


@pytest.mark.asyncio
async def test_timeout_and_emergency_stop_terminate_child(desktop_components):
    _settings, _database, workspace, _policy, runner = desktop_components
    timed = await runner.run(["sleep", "3"], cwd=str(workspace), timeout_seconds=1, approved=True, source="manual_ui")
    assert timed.status == "error"
    assert timed.data["timed_out"] is True

    command = asyncio.create_task(runner.run(["sleep", "10"], cwd=str(workspace), approved=True, source="manual_ui"))
    active = {}
    for _ in range(30):
        await asyncio.sleep(0.02)
        active = runner.active_processes()
        if active:
            break
    assert active
    assert await runner.stop(next(iter(active))) is True
    stopped = await command
    assert stopped.status == "error"
    assert stopped.data["exit_code"] != 0


@pytest.mark.asyncio
async def test_agent_process_tool_cannot_read_key_paths_or_pass_secret_arguments(desktop_components):
    _settings, database, workspace, _policy, runner = desktop_components
    secret_dir = workspace / ".ssh"
    secret_dir.mkdir()
    (secret_dir / "id_ed25519").write_text("local-private-value")
    outcome = await runner.run(["cat", str(secret_dir / "id_ed25519")], cwd=str(workspace), approved=True, source="agent_task")
    assert outcome.status == "denied"
    assert "local-private-value" not in str(outcome.as_dict())
    code = await runner.run(["python3", "-c", "print('should not run')"], cwd=str(workspace), approved=True, source="agent_task")
    assert code.status == "denied"
    wrapped = await runner.run(["env", "python3", "-c", "print('still blocked')"], cwd=str(workspace), approved=True, source="agent_task")
    assert wrapped.status == "denied"
    shell = await runner.run(["bash", "script.sh"], cwd=str(workspace), approved=True, source="agent_task")
    scanner = await runner.run(["sha256sum", "notes.txt"], cwd=str(workspace), approved=True, source="agent_task")
    versioned = await runner.run(["python3.13", "-c", "print(1)"], cwd=str(workspace), approved=True, source="agent_task")
    compiler = await runner.run(["gcc", "-o", "payload"], cwd=str(workspace), approved=True, source="agent_task")
    git = await runner.run(["git", "status"], cwd=str(workspace), approved=True, source="agent_task")
    copy = await runner.run(["cp", "/etc/passwd", "./copied-passwd"], cwd=str(workspace), approved=True, source="agent_task")
    assert all(item.status == "denied" for item in (shell, scanner, versioned, compiler, git, copy))
    assert database.list_command_history() == []


def test_redaction_handles_api_tokens_authorization_and_private_keys():
    sample = "api_key=sk-1234567890abcdef1234\nAuthorization: Basic dXNlcjpwYXNz\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
    output = redact_text(sample)
    assert "sk-1234567890abcdef1234" not in output
    assert "dXNlcjpwYXNz" not in output
    assert "abc" not in output


@pytest.mark.asyncio
async def test_workspace_file_tools_exclude_credential_paths(environment):
    settings, database, _old_registry, workspace = environment
    from nova.tools.workspace import build_workspace_tools
    registry = ToolRegistry(settings)
    for definition in build_workspace_tools(settings):
        registry.register(definition)
    (workspace / ".env").write_text("OPENAI_API_KEY=local-secret")
    read = await registry.execute("workspace.read_file", {"path": ".env"})
    listed = await registry.execute("workspace.list_files", {"path": "."})
    assert read.status == "denied"
    assert "local-secret" not in str(read.as_dict())
    assert ".env" not in [entry["name"] for entry in listed.data["entries"]]


@pytest.mark.asyncio
async def test_task_engine_uses_structured_command_tool_and_records_result(desktop_components):
    settings, database, workspace, policy, runner = desktop_components
    registry = ToolRegistry(settings)
    for definition in build_command_tools(settings, database, runner):
        registry.register(definition)
    responses = [
        message('{"summary":"Check workspace","steps":["Print the current workspace"]}'),
        message(None, [{
            "id": "call-pwd",
            "type": "function",
            "function": {"name": "process.execute", "arguments": '{"program":"pwd"}'},
        }]),
        message("The current directory is recorded."),
        message('{"status":"verified","note":"pwd returned the selected workspace."}'),
    ]
    engine = TaskEngine(database, FakeProvider(responses), registry, settings, AutonomyPolicy(settings, database, registry))
    task_id = database.create_task("Check the current selected workspace", review_plan=False)
    await engine.run_task(task_id)
    task = database.get_task(task_id)
    assert task["state"] == "completed"
    assert task["verification"] == "verified"
    results = task["checkpoint"]["tool_results"]
    assert results[0]["tool"] == "process.execute"
    assert results[0]["data"]["exit_code"] == 0
    assert results[0]["data"]["stdout"].strip() == str(workspace)
    assert database.list_command_history()[0]["status"] == "success"


@pytest.mark.asyncio
async def test_privileged_tool_approval_preview_shows_exact_command_without_running(desktop_components):
    settings, database, workspace, _policy, runner = desktop_components
    registry = ToolRegistry(settings)
    for definition in build_command_tools(settings, database, runner):
        registry.register(definition)
    call = {
        "id": "call-pkexec",
        "type": "function",
        "function": {
            "name": "system.run_privileged",
            "arguments": '{"program":"apt-get","arguments":["install","example-package"]}',
        },
    }
    responses = [
        message('{"summary":"Install only if approved","steps":["Review the proposed package installation"]}'),
        message(None, [call]),
    ]
    engine = TaskEngine(database, FakeProvider(responses), registry, settings, AutonomyPolicy(settings, database, registry))
    task_id = database.create_task("Review a privileged package installation", review_plan=False)
    await engine.run_task(task_id)
    task = database.get_task(task_id)
    assert task["state"] == "waiting_approval"
    summary = task["checkpoint"]["pending_approval_summary"]["summary"]
    assert "apt-get install example-package" in summary
    assert "polkit" in summary.lower()
    assert database.list_command_history() == []


class FakeSecretServiceBackend:
    priority = 1


FakeSecretServiceBackend.__module__ = "keyring.backends.SecretService"


class FakeKeyring:
    def __init__(self):
        self.backend = FakeSecretServiceBackend()
        self.values = {}

    def get_keyring(self):
        return self.backend

    def set_password(self, service, name, secret):
        self.values[(service, name)] = secret

    def get_password(self, service, name):
        return self.values.get((service, name))

    def delete_password(self, service, name):
        self.values.pop((service, name), None)


def test_secret_store_accepts_only_verified_secret_service_and_restores_environment(monkeypatch):
    import os
    fake = FakeKeyring()
    store = SecretStore(fake)
    assert store.backend_status()["available"] is True
    monkeypatch.delenv("NOVA_OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("AI_API_KEY", "original-env-key")
    store.set_secret("NOVA_OPENAI_API_KEY", "secret-value")
    assert store.get_secret("NOVA_OPENAI_API_KEY") == "secret-value"
    store.activate_environment()
    assert os.environ["AI_API_KEY"] == "secret-value"
    store.deactivate_environment()
    assert os.environ["AI_API_KEY"] == "original-env-key"
    with pytest.raises(ValueError):
        store.set_secret("AI_API_KEY", "secret-value")


def test_secret_store_refuses_plaintext_fallback_and_ignores_unmanaged_environment(monkeypatch):
    import os
    fallback = SimpleNamespace(get_keyring=lambda: SimpleNamespace(priority=0))
    store = SecretStore(fallback)
    assert store.backend_status()["available"] is False
    monkeypatch.setenv("OPENAI_API_KEY", "unmanaged-env-secret")
    with pytest.raises(SecretStoreError):
        store.set_secret("NOVA_OPENAI_API_KEY", "secret-value")
    with pytest.raises(SecretStoreError):
        store.activate_environment()
    assert "OPENAI_API_KEY" not in os.environ
    store.deactivate_environment()
    assert os.environ["OPENAI_API_KEY"] == "unmanaged-env-secret"
