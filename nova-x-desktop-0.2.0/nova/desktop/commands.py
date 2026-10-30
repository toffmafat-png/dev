"""Real, bounded local process execution for the native NOVA X runtime."""
from __future__ import annotations

import asyncio
import os
import shlex
import shutil
import signal
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nova.config import Settings
from nova.db import Database
from nova.desktop.policy import (
    AGENT_BLOCKED_PROGRAMS,
    AGENT_BLOCKED_WRAPPERS,
    AGENT_ONLY_BLOCKED_PROGRAMS,
    CommandPolicy,
    _is_interpreter_program,
    redact_text,
    safe_argv_for_history,
    sensitive_values_from_argv,
)
from nova.tools.registry import ToolDefinition, ToolOutcome

StreamCallback = Callable[[str, str], None]


def _safe_environment() -> dict[str, str]:
    """Pass desktop/session essentials, never provider credentials or arbitrary env overrides."""
    keep_exact = {
        "PATH", "HOME", "USER", "LOGNAME", "LANG", "LANGUAGE", "TERM", "COLORTERM",
        "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_DESKTOP", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "SHELL", "TMPDIR",
    }
    result = {key: value for key, value in os.environ.items() if key in keep_exact or key.startswith("LC_")}
    result["PATH"] = result.get("PATH", "/usr/local/bin:/usr/bin:/bin")
    result["HOME"] = result.get("HOME", str(Path.home()))
    result["LANG"] = result.get("LANG", "C.UTF-8")
    result["PYTHONDONTWRITEBYTECODE"] = "1"
    return result


class _StreamingRedactor:
    """Hold a suffix so known argument secrets split across pipe chunks are redacted."""

    def __init__(self, emit: Callable[[str], None], secrets: list[str] | None = None):
        self.emit = emit
        self.secrets = [value for value in (secrets or []) if value]
        longest_secret = max((len(value) for value in self.secrets), default=0)
        self.tail_chars = min(8192, max(512, longest_secret + 64))
        self.pending = ""

    def _redact(self, text: str) -> str:
        value = redact_text(text)
        for secret in sorted(self.secrets, key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]")
        return value

    def push(self, text: str, final: bool = False) -> None:
        self.pending += text
        if final:
            output = self.pending
            self.pending = ""
        elif len(self.pending) > self.tail_chars:
            cut = len(self.pending) - self.tail_chars
            output = self.pending[:cut]
            self.pending = self.pending[cut:]
        else:
            return
        if output:
            self.emit(self._redact(output))


class ProcessRunInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    program: str = Field(min_length=1, max_length=500, description="Installed program name or authorized executable path")
    arguments: list[str] = Field(default_factory=list, max_length=127, description="Structured arguments; not shell-parsed")
    cwd: str | None = Field(default=None, max_length=2000, description="Working directory; selected workspace or one-time approved path")
    timeout_seconds: int = Field(default=120, ge=1, le=600)


class PrivilegedRunInput(ProcessRunInput):
    pass


class CommandRunner:
    def __init__(
        self,
        settings: Settings,
        database: Database,
        policy: CommandPolicy,
        output_callback: StreamCallback | None = None,
    ):
        self.settings = settings
        self.database = database
        self.policy = policy
        self.output_callback = output_callback
        self._active: dict[str, asyncio.subprocess.Process] = {}

    def active_processes(self) -> dict[str, int]:
        return {key: proc.pid for key, proc in self._active.items() if proc.returncode is None}

    async def stop(self, command_id: str) -> bool:
        process = self._active.get(command_id)
        if not process or process.returncode is not None:
            return False
        await self._terminate(process)
        return True

    async def run(
        self,
        argv: list[str],
        cwd: str | None = None,
        timeout_seconds: int = 120,
        approved: bool = False,
        privileged: bool = False,
        source: str = "task",
    ) -> ToolOutcome:
        if not isinstance(argv, list) or not argv:
            return ToolOutcome("denied", "Command must contain an executable and structured arguments.")
        cwd_value = str(cwd or self.database.get_desktop_setting("active_workspace", "") or Path.home())
        if source in {"agent_task", "agent_task_privileged"}:
            program_name = Path(argv[0]).name.lower() if isinstance(argv[0], str) else ""
            if self.policy._has_sensitive_path_or_flag(argv):
                return ToolOutcome("denied", "Agent-mediated process commands cannot access credential/private-key paths or pass secret-like arguments to an external process. Use the local UI and keyring for credential work.")
            personal_grant = self.policy.check_personal_grant(argv, cwd_value, privileged=privileged)
            if personal_grant is None and (
                program_name in AGENT_BLOCKED_PROGRAMS
                or program_name in AGENT_BLOCKED_WRAPPERS
                or program_name in AGENT_ONLY_BLOCKED_PROGRAMS
                or _is_interpreter_program(program_name)
            ):
                return ToolOutcome("denied", "Agent-mediated shells/interpreters, build runners, file readers/scanners/mutators, Git commands, and indirect command wrappers are disabled by default until authorized via a persistent personal permission grant or personal power-user profile.")
        decision = self.policy.evaluate(argv, cwd_value, privileged=privileged)
        if decision["action"] == "deny":
            return ToolOutcome("denied", decision["reason"], {"rule": decision["rule"]})
        if decision["action"] == "approval_required" and not approved:
            safe_argv = safe_argv_for_history(argv)
            display = " ".join(shlex.quote(item) for item in safe_argv)
            payload = {
                "operation": "privileged_command" if privileged else "run_command",
                "program": safe_argv[0] if safe_argv else "unknown",
                "arguments": safe_argv[1:],
                "cwd": cwd_value,
                "risk": decision["rule"],
                "requires_polkit": bool(privileged),
            }
            privilege_note = " It will request authentication through the system's polkit agent; NOVA never reads or stores your password." if privileged else ""
            return ToolOutcome(
                "approval_required",
                f"{decision['reason']} Review command: {display}. Working directory: {cwd_value}.{privilege_note}",
                {"command_preview": display, "cwd": cwd_value, "risk": decision["rule"]},
                payload,
            )
        if privileged:
            pkexec = shutil.which("pkexec")
            if not pkexec:
                return ToolOutcome("error", "pkexec is not installed. NOVA will not fall back to storing or piping a sudo password.")
            argv = [pkexec, *argv]
        executable = shutil.which(argv[0])
        if not executable:
            return ToolOutcome("error", f"Command '{Path(argv[0]).name}' was not found on PATH.")
        resolved_cwd = self._resolve_cwd(cwd_value)
        if resolved_cwd is None:
            return ToolOutcome("denied", "Working directory is unavailable or cannot be resolved safely.")
        normalized_argv = [executable, *argv[1:]]
        return await self._spawn(normalized_argv, str(resolved_cwd), timeout_seconds, source, privileged)

    async def run_manual_shell(
        self,
        script: str,
        cwd: str,
        timeout_seconds: int = 120,
        approved: bool = False,
        source: str = "manual_shell",
    ) -> ToolOutcome:
        """Run a user-typed shell script only after the native UI's explicit confirmation."""
        if not approved:
            return ToolOutcome("approval_required", "Shell scripts can perform arbitrary operations. Review the script and confirm in the desktop interface before execution.")
        if not isinstance(script, str) or not script.strip() or len(script) > 12_000 or "\x00" in script:
            return ToolOutcome("denied", "Shell script is empty, too long, or contains an invalid NUL byte.")
        bash = shutil.which("bash")
        if not bash:
            return ToolOutcome("error", "Bash is not installed; no shell command was run.")
        resolved_cwd = self._resolve_cwd(cwd)
        if resolved_cwd is None:
            return ToolOutcome("denied", "Working directory is unavailable or cannot be resolved safely.")
        return await self._spawn([bash, "--noprofile", "--norc", "-c", script], str(resolved_cwd), timeout_seconds, source, False, show_script=True)

    def _resolve_cwd(self, raw: str) -> Path | None:
        try:
            path = Path(raw).expanduser().resolve(strict=True)
            return path if path.is_dir() else None
        except (OSError, RuntimeError):
            return None

    async def _spawn(
        self,
        argv: list[str],
        cwd: str,
        timeout_seconds: int,
        source: str,
        privileged: bool,
        show_script: bool = False,
    ) -> ToolOutcome:
        command_id = str(uuid.uuid4())
        started = datetime.now(UTC).isoformat(timespec="microseconds")
        started_monotonic = time.monotonic()
        executable_display = Path(argv[0]).name
        history_argv = argv[1:]
        display_argv = [executable_display, *safe_argv_for_history(history_argv)]
        output: dict[str, list[str]] = {"stdout": [], "stderr": []}
        redaction_secrets = sensitive_values_from_argv(argv)
        captured = {"stdout": 0, "stderr": 0}
        total_chars = 0
        output_limit = min(max(8_000, self.settings.max_tool_output_chars * 4), 100_000)
        timed_out = False

        def emit(stream_name: str, text: str) -> None:
            nonlocal total_chars
            if not text:
                return
            remaining = max(0, output_limit - total_chars)
            clipped = text[:remaining]
            if clipped:
                output[stream_name].append(clipped)
                captured[stream_name] += len(clipped)
                total_chars += len(clipped)
                if self.output_callback:
                    try:
                        self.output_callback(stream_name, clipped)
                    except Exception:
                        pass

        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                cwd=cwd,
                env=_safe_environment(),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        except FileNotFoundError:
            return ToolOutcome("error", f"Command '{executable_display}' was not found.")
        except PermissionError:
            return ToolOutcome("denied", f"The current user cannot execute '{executable_display}'. No privilege escalation was attempted.")
        except OSError as exc:
            return ToolOutcome("error", f"Could not start '{executable_display}' ({type(exc).__name__}).")
        self._active[command_id] = process

        async def read_stream(stream: asyncio.StreamReader, name: str) -> None:
            redactor = _StreamingRedactor(lambda text: emit(name, text), redaction_secrets)
            while True:
                chunk = await stream.read(4096)
                if not chunk:
                    break
                redactor.push(chunk.decode("utf-8", errors="replace"))
                if total_chars >= output_limit:
                    # Continue draining the pipe to avoid blocking the child, but do not retain more output.
                    continue
            redactor.push("", final=True)

        stdout_task = asyncio.create_task(read_stream(process.stdout, "stdout"))
        stderr_task = asyncio.create_task(read_stream(process.stderr, "stderr"))
        status = "success"
        try:
            await asyncio.wait_for(process.wait(), timeout=max(1, min(int(timeout_seconds), 600)))
        except TimeoutError:
            timed_out = True
            status = "timeout"
            await self._terminate(process)
        except asyncio.CancelledError:
            status = "cancelled"
            await self._terminate(process)
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            self._active.pop(command_id, None)
            self._record(command_id, display_argv, cwd, status, process.returncode, output, started, started_monotonic, source)
            raise
        finally:
            if process.returncode is None:
                await self._terminate(process)
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        self._active.pop(command_id, None)
        duration = time.monotonic() - started_monotonic
        exit_code = process.returncode
        if not timed_out and status != "cancelled" and exit_code not in {0, None}:
            status = "failed"
        self._record(command_id, display_argv, cwd, status, exit_code, output, started, started_monotonic, source)

        stdout_text = "".join(output["stdout"])
        stderr_text = "".join(output["stderr"])
        truncated = total_chars >= output_limit
        data = {
            "command_id": command_id,
            "program": executable_display,
            "arguments": safe_argv_for_history(history_argv),
            "cwd": cwd,
            "exit_code": exit_code,
            "duration_seconds": round(duration, 3),
            "stdout": stdout_text[-min(self.settings.max_tool_output_chars, 20_000):],
            "stderr": stderr_text[-min(self.settings.max_tool_output_chars, 20_000):],
            "timed_out": timed_out,
            "output_truncated": truncated,
            "privileged": privileged,
            "log_path": self._log_path(command_id),
            "shell_script": bool(show_script),
        }
        if timed_out:
            return ToolOutcome("error", f"Command timed out after {timeout_seconds} seconds and was terminated. Exit status: {exit_code}.", data)
        if exit_code != 0:
            return ToolOutcome("error", f"Command exited with status {exit_code}.", data)
        return ToolOutcome("success", f"Command completed successfully in {duration:.2f}s (exit code 0).", data)

    async def _terminate(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.terminate()
            except ProcessLookupError:
                pass
        try:
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except TimeoutError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            await process.wait()

    def _log_path(self, command_id: str) -> str:
        return str(self.settings.data_dir / "command-logs" / f"{command_id}.log")

    def _record(
        self,
        command_id: str,
        argv: list[str],
        cwd: str,
        status: str,
        exit_code: int | None,
        output: dict[str, list[str]],
        started: str,
        started_monotonic: float,
        source: str,
    ) -> None:
        stdout_text = redact_text("".join(output["stdout"]))[:20_000]
        stderr_text = redact_text("".join(output["stderr"]))[:20_000]
        duration = max(0.0, time.monotonic() - started_monotonic)
        log_path = Path(self._log_path(command_id))
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(log_path.parent, 0o700)
            with log_path.open("w", encoding="utf-8") as stream:
                os.chmod(log_path, 0o600)
                stream.write(f"source: {source}\nstatus: {status}\nexit_code: {exit_code}\nstarted_at: {started}\ncwd: {cwd}\ncommand: {shlex.quote(argv[0])} {shlex_join_safe(argv[1:])}\n\n[stdout]\n{stdout_text}\n\n[stderr]\n{stderr_text}\n")
        except OSError:
            log_path_text = ""
        else:
            log_path_text = str(log_path)
        try:
            prior_rows = self.database.list_command_history("", 500)
            self.database.add_command_history({
                "id": command_id,
                "program": argv[0] if argv else "",
                "arguments": argv[1:],
                "cwd": cwd,
                "status": status,
                "exit_code": exit_code,
                "stdout": stdout_text,
                "stderr": stderr_text,
                "started_at": started,
                "duration_seconds": duration,
                "log_path": log_path_text,
            })
            if len(prior_rows) >= 500:
                self._delete_owned_log(str(prior_rows[-1].get("log_path", "")))
        except Exception:
            pass

    def _delete_owned_log(self, raw_path: str) -> None:
        if not raw_path:
            return
        try:
            path = Path(raw_path).resolve(strict=True)
            root = (self.settings.data_dir / "command-logs").resolve()
            if path.parent == root and path.name.endswith(".log"):
                path.unlink(missing_ok=True)
        except (OSError, RuntimeError):
            return


def shlex_join_safe(args: list[str]) -> str:
    # `shlex` is imported at module scope; no local re-import is needed.
    return shlex.join(safe_argv_for_history(args))


def _approval_preview(args: dict[str, Any], privileged: bool = False) -> dict[str, Any]:
    program = str(args.get("program", ""))[:200]
    arguments = [str(value) for value in (args.get("arguments") or [])[:32]]
    safe = safe_argv_for_history([program, *arguments])
    command = shlex.join(safe)
    cwd = str(args.get("cwd") or "selected workspace")[:300]
    mode = "polkit-authenticated privileged command" if privileged else "local user command"
    return {
        "summary": f"NOVA proposes a {mode}: {command}. Working directory: {cwd}. Review the exact operation before approval.",
        "approval": {
            "operation": "privileged_command" if privileged else "run_command",
            "program": safe[0] if safe else "unknown",
            "arguments": safe[1:],
            "cwd": cwd,
            "requires_polkit": privileged,
        },
    }


def build_command_tools(
    settings: Settings,
    database: Database,
    runner: CommandRunner,
) -> list[ToolDefinition]:
    # The runner owns policy evaluation; these handlers only translate validated
    # tool arguments into a structured argv and forward the approval decision.

    async def execute(args: BaseModel, approved: bool) -> ToolOutcome:
        values = args.model_dump()
        argv = [values["program"], *values.get("arguments", [])]
        return await runner.run(
            argv,
            cwd=values.get("cwd"),
            timeout_seconds=values.get("timeout_seconds", 120),
            approved=approved,
            source="agent_task",
        )

    async def execute_privileged(args: BaseModel, approved: bool) -> ToolOutcome:
        values = args.model_dump()
        argv = [values["program"], *values.get("arguments", [])]
        return await runner.run(
            argv,
            cwd=values.get("cwd"),
            timeout_seconds=values.get("timeout_seconds", 120),
            approved=approved,
            privileged=True,
            source="agent_task_privileged",
        )

    return [
        ToolDefinition(
            name="process.execute",
            description=(
                "Run an installed Linux command as the logged-in user. Pass the program and arguments separately; "
                "this agent tool does not invoke a shell. Saved exact-prefix commands in a selected workspace may run automatically; "
                "other commands pause for user approval. Output is redacted, bounded, saved locally, and returned with the real exit code."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "program": {"type": "string", "minLength": 1, "maxLength": 500},
                    "arguments": {"type": "array", "items": {"type": "string", "maxLength": 8192}, "maxItems": 127},
                    "cwd": {"type": "string", "maxLength": 2000},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 600, "default": 120},
                },
                "required": ["program"],
                "additionalProperties": False,
            },
            input_model=ProcessRunInput,
            handler=execute,
            permission="local process execution under current user; exact saved command policy or one-time approval; no shell string parsing",
            category="system",
            autonomy_class="routine",
            approval_preview=lambda values: _approval_preview(values),
        ),
        ToolDefinition(
            name="system.run_privileged",
            description=(
                "Run an installed system command through pkexec/polkit, if available. Every call requires fresh user approval "
                "and the desktop's normal authentication agent; NOVA never stores or pipes a sudo password."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "program": {"type": "string", "minLength": 1, "maxLength": 500},
                    "arguments": {"type": "array", "items": {"type": "string", "maxLength": 8192}, "maxItems": 127},
                    "cwd": {"type": "string", "maxLength": 2000},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 600, "default": 120},
                },
                "required": ["program"],
                "additionalProperties": False,
            },
            input_model=PrivilegedRunInput,
            handler=execute_privileged,
            permission="privileged system operation; explicit NOVA approval plus system polkit authentication required",
            category="system",
            autonomy_class="approval_required",
            approval_preview=lambda values: _approval_preview(values, privileged=True),
        ),
    ]
