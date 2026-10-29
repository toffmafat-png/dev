"""§96 Advanced terminal workspace.

Provides multi-session terminal management, named working directories, live
stdout/stderr streaming, optional PTY execution, actor attribution (``nova`` vs
``user``), process liveness & cancellation, searchable history, command
templates, diff inspection, redacted diagnostic export, and a side-effect guard
that blocks automatic replay of destructive, deployment or payment commands.
"""
from __future__ import annotations

import asyncio
import difflib
import os
import pty
import re
import selectors
import shlex
import signal
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nova.desktop.policy import safe_argv_for_history
from nova.observability import Redactor

ACTOR_NOVA = "nova"
ACTOR_USER = "user"
ACTORS = (ACTOR_NOVA, ACTOR_USER)

LAUNCH_ARGV = "argv_exec"
LAUNCH_PIPELINE = "shell_pipeline"
LAUNCH_PTY = "pty_interactive"

DEFAULT_CAPTURE_LIMIT = 12_000
DEFAULT_TIME_LIMIT_SECONDS = 30.0
MAX_TIME_LIMIT_SECONDS = 600.0

# Commands matching these tokens must never be replayed automatically during
# recovery without fresh confirmation (§96).
_SIDE_EFFECT_REPLAY_PATTERNS = re.compile(
    r"\b(rm|rmdir|dd|mkfs|shred|deploy|kubectl\s+apply|helm\s+upgrade|terraform\s+apply|"
    r"git\s+push|npm\s+publish|twine\s+upload|stripe|charge|pay|invoice|reboot|shutdown|"
    r"apt|apt-get|dpkg)\b",
    re.IGNORECASE,
)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def classify_replay_safety(command_display: str) -> dict[str, Any]:
    match = _SIDE_EFFECT_REPLAY_PATTERNS.search(command_display or "")
    if match:
        return {
            "auto_replay_safe": False,
            "matched_token": match.group(1),
            "reason": f"contains side-effecting token '{match.group(1)}'; automatic replay is prohibited",
        }
    return {"auto_replay_safe": True, "matched_token": "", "reason": "no deployment, destructive or payment token matched"}


@dataclass
class CommandTemplate:
    template_id: str
    title: str
    argv_template: tuple[str, ...]
    description: str = ""

    def render(self, variables: dict[str, str]) -> list[str]:
        rendered: list[str] = []
        for token in self.argv_template:
            out = token
            for key, value in variables.items():
                if "\x00" in value or "\n" in value:
                    raise ValueError(f"Invalid template value for '{key}'")
                out = out.replace("{" + key + "}", value)
            if "{" in out and "}" in out:
                raise ValueError(f"Unfilled template placeholder in '{out}'")
            rendered.append(out)
        return rendered

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "title": self.title,
            "argv_template": list(self.argv_template),
            "description": self.description,
        }


@dataclass
class TerminalCommandRecord:
    record_id: str
    session_id: str
    task_id: str
    actor: str  # "nova" | "user"
    launch_method: str
    display_command: str
    cwd: str
    pid: int | None
    started_at: str
    ended_at: str = ""
    exit_code: int | None = None
    timed_out: bool = False
    cancelled: bool = False
    stdout: str = ""
    stderr: str = ""
    auto_replay_safe: bool = False
    replay_note: str = ""

    def is_active(self) -> bool:
        if self.ended_at or self.pid is None or self.pid <= 0:
            return False
        try:
            os.kill(self.pid, 0)
            return True
        except OSError:
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "session_id": self.session_id,
            "task_id": self.task_id,
            "actor": self.actor,
            "started_by_nova": self.actor == ACTOR_NOVA,
            "launch_method": self.launch_method,
            "display_command": self.display_command,
            "cwd": self.cwd,
            "pid": self.pid,
            "active": self.is_active(),
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "auto_replay_safe": self.auto_replay_safe,
            "replay_note": self.replay_note,
        }


@dataclass
class TerminalSession:
    session_id: str
    name: str
    cwd: Path
    task_id: str = ""
    created_at: str = field(default_factory=_iso)
    log_entries: list[str] = field(default_factory=list)
    records: list[TerminalCommandRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "name": self.name,
            "cwd": str(self.cwd),
            "task_id": self.task_id,
            "created_at": self.created_at,
            "commands_run": len(self.records),
            "active_pids": [r.pid for r in self.records if r.is_active() and r.pid],
        }


@dataclass
class TerminalWorkspace:
    """§96 Multi-session terminal manager with actor tracking, PTY and cancellation."""

    default_cwd: Path
    redactor: Redactor = field(default_factory=Redactor)
    capture_limit_chars: int = DEFAULT_CAPTURE_LIMIT
    policy_check: Callable[[list[str], str, str], dict[str, Any]] | None = None
    _sessions: dict[str, TerminalSession] = field(default_factory=dict, init=False)
    _named_dirs: dict[str, Path] = field(default_factory=dict, init=False)
    _templates: dict[str, CommandTemplate] = field(default_factory=dict, init=False)
    _active_procs: dict[str, subprocess.Popen[Any] | asyncio.subprocess.Process] = field(default_factory=dict, init=False)
    _seq: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.default_cwd = Path(self.default_cwd).resolve()
        self.default_cwd.mkdir(parents=True, exist_ok=True)
        self._named_dirs["workspace"] = self.default_cwd
        self.register_template(
            CommandTemplate(
                template_id="pytest-file",
                title="Run pytest on a single file",
                argv_template=("python3", "-m", "pytest", "-q", "{target}"),
                description="Run quiet pytest against one test module.",
            )
        )
        self.register_template(
            CommandTemplate(
                template_id="git-status-short",
                title="Short git status",
                argv_template=("git", "status", "--short"),
                description="Inspect modified and untracked repository files.",
            )
        )

    # -- named working directories & templates

    def register_workdir(self, alias: str, directory: Path | str) -> dict[str, str]:
        resolved = Path(directory).expanduser().resolve()
        if not resolved.is_dir():
            raise ValueError(f"Working directory does not exist: {resolved}")
        self._named_dirs[alias] = resolved
        return {"alias": alias, "path": str(resolved)}

    def named_workdirs(self) -> dict[str, str]:
        return {name: str(path) for name, path in self._named_dirs.items()}

    def register_template(self, template: CommandTemplate) -> None:
        self._templates[template.template_id] = template

    def list_templates(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self._templates.values()]

    # -- sessions

    def create_session(self, name: str, *, workdir: str | Path = "", task_id: str = "") -> TerminalSession:
        self._seq += 1
        session_id = f"term-{self._seq:04d}"
        if isinstance(workdir, str) and workdir in self._named_dirs:
            cwd = self._named_dirs[workdir]
        elif str(workdir).strip():
            cwd = Path(workdir).expanduser().resolve()
        else:
            cwd = self.default_cwd
        if not cwd.is_dir():
            raise ValueError(f"Session working directory does not exist: {cwd}")
        session = TerminalSession(session_id=session_id, name=name, cwd=cwd, task_id=task_id)
        self._sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> TerminalSession | None:
        return self._sessions.get(session_id)

    def list_sessions(self, *, task_id: str = "") -> list[dict[str, Any]]:
        rows = self._sessions.values()
        if task_id:
            rows = [item for item in rows if item.task_id == task_id]
        return [item.to_dict() for item in rows]

    # -- environment & diff helpers

    def inspect_environment(self) -> dict[str, str]:
        """Return safe, secret-redacted environment summary (§96)."""
        exposed = ("PATH", "HOME", "SHELL", "LANG", "TERM", "VIRTUAL_ENV", "PYTHONPATH")
        env_out: dict[str, str] = {}
        for key in exposed:
            if key in os.environ:
                env_out[key] = self.redactor.scrub_text(os.environ[key], max_chars=240)
        return env_out

    @staticmethod
    def inspect_diff(original: str, updated: str, *, filename: str = "file") -> dict[str, Any]:
        diff_lines = list(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                updated.splitlines(keepends=True),
                fromfile=f"a/{filename}",
                tofile=f"b/{filename}",
            )
        )
        added = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
        removed = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))
        return {
            "filename": filename,
            "changed": bool(diff_lines),
            "added_lines": added,
            "removed_lines": removed,
            "patch": "".join(diff_lines)[:16_000],
        }

    # -- execution

    def _safe_child_env(self) -> dict[str, str]:
        keep = ("PATH", "HOME", "LANG", "LC_ALL", "TERM")
        env = {k: os.environ[k] for k in keep if k in os.environ}
        env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
        return env

    async def execute_argv(
        self,
        session_id: str,
        argv: list[str],
        *,
        actor: str = ACTOR_NOVA,
        time_limit_seconds: float = DEFAULT_TIME_LIMIT_SECONDS,
        on_stdout: Callable[[str], None] | None = None,
        on_stderr: Callable[[str], None] | None = None,
    ) -> TerminalCommandRecord:
        if actor not in ACTORS:
            raise ValueError(f"Unknown command actor: {actor}")
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"Unknown terminal session: {session_id}")
        if not argv or any("\x00" in item for item in argv):
            raise ValueError("Invalid command argv")

        if self.policy_check is not None:
            decision = self.policy_check(argv, str(session.cwd), actor)
            if decision.get("action") not in {"allow", "auto"}:
                self._seq += 1
                denied_rec = TerminalCommandRecord(
                    record_id=f"cmd-{self._seq:05d}",
                    session_id=session_id,
                    task_id=session.task_id,
                    actor=actor,
                    launch_method=LAUNCH_ARGV,
                    display_command=shlex.join(safe_argv_for_history(argv)),
                    cwd=str(session.cwd),
                    pid=None,
                    started_at=_iso(),
                    ended_at=_iso(),
                    exit_code=126,
                    stderr=f"Denied by authorization policy: {decision.get('reason', 'blocked')}",
                )
                session.records.append(denied_rec)
                return denied_rec

        self._seq += 1
        rec_id = f"cmd-{self._seq:05d}"
        safe_display = shlex.join(safe_argv_for_history(argv))
        replay_info = classify_replay_safety(safe_display)
        timeout = max(0.2, min(float(time_limit_seconds), MAX_TIME_LIMIT_SECONDS))

        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(session.cwd),
            env=self._safe_child_env(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        record = TerminalCommandRecord(
            record_id=rec_id,
            session_id=session_id,
            task_id=session.task_id,
            actor=actor,
            launch_method=LAUNCH_ARGV,
            display_command=safe_display,
            cwd=str(session.cwd),
            pid=proc.pid,
            started_at=_iso(),
            auto_replay_safe=bool(replay_info["auto_replay_safe"]),
            replay_note=str(replay_info["reason"]),
        )
        session.records.append(record)
        self._active_procs[rec_id] = proc

        out_buf: list[str] = []
        err_buf: list[str] = []

        async def _pump(stream: asyncio.StreamReader | None, sink: list[str], cb: Callable[[str], None] | None) -> None:
            if stream is None:
                return
            used = 0
            while True:
                chunk = await stream.read(4096)
                if not chunk:
                    break
                text = self.redactor.scrub_text(chunk.decode("utf-8", errors="replace"), max_chars=4096)
                if cb is not None:
                    cb(text)
                if used < self.capture_limit_chars:
                    room = self.capture_limit_chars - used
                    sink.append(text[:room])
                    used += len(text[:room])

        try:
            await asyncio.wait_for(
                asyncio.gather(
                    _pump(proc.stdout, out_buf, on_stdout),
                    _pump(proc.stderr, err_buf, on_stderr),
                    proc.wait(),
                ),
                timeout=timeout,
            )
        except TimeoutError:
            record.timed_out = True
            self._kill_pid_group(proc.pid)
            await proc.wait()
        except asyncio.CancelledError:
            record.cancelled = True
            self._kill_pid_group(proc.pid)
            await proc.wait()
            raise
        finally:
            self._active_procs.pop(rec_id, None)
            record.stdout = "".join(out_buf)
            record.stderr = "".join(err_buf)
            record.exit_code = proc.returncode
            record.ended_at = _iso()
            session.log_entries.append(
                f"[{record.started_at}] ({record.actor}/{record.launch_method}) $ {record.display_command} -> exit={record.exit_code}"
            )
        return record

    async def execute_pipeline(
        self,
        session_id: str,
        pipeline: str,
        *,
        actor: str = ACTOR_NOVA,
        time_limit_seconds: float = DEFAULT_TIME_LIMIT_SECONDS,
    ) -> TerminalCommandRecord:
        """Execute a validated shell pipeline while preserving policy enforcement & logging (§96)."""
        cleaned = (pipeline or "").strip()
        if not cleaned or "\x00" in cleaned:
            raise ValueError("Invalid pipeline string")
        argv = ["/bin/sh", "-c", cleaned]
        rec = await self.execute_argv(session_id, argv, actor=actor, time_limit_seconds=time_limit_seconds)
        rec.launch_method = LAUNCH_PIPELINE
        rec.display_command = self.redactor.scrub_text(cleaned, max_chars=240)
        replay = classify_replay_safety(cleaned)
        rec.auto_replay_safe = bool(replay["auto_replay_safe"])
        rec.replay_note = str(replay["reason"])
        return rec

    def run_pty_command(
        self,
        session_id: str,
        argv: list[str],
        *,
        stdin_text: str = "",
        actor: str = ACTOR_USER,
        time_limit_seconds: float = 10.0,
    ) -> TerminalCommandRecord:
        """Execute an interactive command attached to a pseudo-terminal (§96 optional PTY)."""
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"Unknown terminal session: {session_id}")
        if self.policy_check is not None:
            decision = self.policy_check(argv, str(session.cwd), actor)
            if decision.get("action") not in {"allow", "auto"}:
                raise PermissionError(decision.get("reason", "PTY command blocked by policy"))

        master_fd, slave_fd = pty.openpty()
        self._seq += 1
        rec_id = f"cmd-{self._seq:05d}"
        safe_display = shlex.join(safe_argv_for_history(argv))
        replay = classify_replay_safety(safe_display)
        proc = subprocess.Popen(
            argv,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            cwd=str(session.cwd),
            env=self._safe_child_env(),
            start_new_session=True,
            close_fds=True,
        )
        os.close(slave_fd)
        collected = bytearray()
        timed_out = False
        try:
            if stdin_text:
                os.write(master_fd, stdin_text.encode("utf-8", errors="replace"))
            sel = selectors.DefaultSelector()
            os.set_blocking(master_fd, False)
            sel.register(master_fd, selectors.EVENT_READ)
            deadline = time.monotonic() + max(0.2, min(float(time_limit_seconds), MAX_TIME_LIMIT_SECONDS))
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        self._kill_pid_group(proc.pid)
                        break
                    events = sel.select(timeout=min(remaining, 0.1))
                    if not events:
                        if proc.poll() is not None:
                            break
                        continue
                    try:
                        chunk = os.read(master_fd, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    if len(collected) < self.capture_limit_chars:
                        collected.extend(chunk[: self.capture_limit_chars - len(collected)])
            finally:
                sel.close()
            proc.wait(timeout=3)
        finally:
            try:
                os.close(master_fd)
            except OSError:
                pass

        record = TerminalCommandRecord(
            record_id=rec_id,
            session_id=session_id,
            task_id=session.task_id,
            actor=actor,
            launch_method=LAUNCH_PTY,
            display_command=safe_display,
            cwd=str(session.cwd),
            pid=proc.pid,
            started_at=_iso(),
            ended_at=_iso(),
            exit_code=proc.returncode,
            timed_out=timed_out,
            stdout=self.redactor.scrub_text(collected.decode("utf-8", errors="replace"), max_chars=self.capture_limit_chars),
            auto_replay_safe=bool(replay["auto_replay_safe"]),
            replay_note=str(replay["reason"]),
        )
        session.records.append(record)
        return record

    @staticmethod
    def _kill_pid_group(pid: int | None) -> bool:
        if pid is None or pid <= 0:
            return False
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except OSError:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                return False
        time.sleep(0.05)
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except OSError:
            pass
        return True

    def terminate_command(self, record_id: str) -> dict[str, Any]:
        proc = self._active_procs.get(record_id)
        for session in self._sessions.values():
            for rec in session.records:
                if rec.record_id == record_id:
                    rec.cancelled = True
                    killed = self._kill_pid_group(rec.pid or (proc.pid if proc else None))
                    return {"terminated": killed, "record_id": record_id, "pid": rec.pid}
        return {"terminated": False, "record_id": record_id, "reason": "command record not found"}

    # -- history, recovery & export

    def search_history(self, query: str = "", *, actor: str = "", limit: int = 50) -> list[dict[str, Any]]:
        needle = (query or "").strip().lower()
        matches: list[dict[str, Any]] = []
        for session in self._sessions.values():
            for rec in session.records:
                if actor and rec.actor != actor:
                    continue
                if needle and needle not in rec.display_command.lower() and needle not in rec.stdout.lower():
                    continue
                matches.append(rec.to_dict())
        return matches[-max(1, min(int(limit), 200)) :]

    def active_nova_processes(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for session in self._sessions.values():
            for rec in session.records:
                if rec.actor == ACTOR_NOVA and rec.is_active():
                    out.append(rec.to_dict())
        return out

    def eligible_for_recovery(self, record_id: str) -> dict[str, Any]:
        for session in self._sessions.values():
            for rec in session.records:
                if rec.record_id == record_id:
                    if not rec.auto_replay_safe:
                        return {
                            "recoverable_automatically": False,
                            "record_id": record_id,
                            "reason": rec.replay_note,
                        }
                    return {
                        "recoverable_automatically": True,
                        "record_id": record_id,
                        "display_command": rec.display_command,
                        "cwd": rec.cwd,
                    }
        return {"recoverable_automatically": False, "record_id": record_id, "reason": "record not found"}

    def copy_output(self, record_id: str) -> str:
        for session in self._sessions.values():
            for rec in session.records:
                if rec.record_id == record_id:
                    return (rec.stdout + ("\n" + rec.stderr if rec.stderr else "")).strip()
        return ""

    def export_diagnostic_report(self) -> dict[str, Any]:
        return {
            "exported_at": _iso(),
            "sessions": [s.to_dict() for s in self._sessions.values()],
            "named_workdirs": self.named_workdirs(),
            "environment": self.inspect_environment(),
            "active_nova_processes": self.active_nova_processes(),
            "recent_commands": self.search_history(limit=30),
        }


__all__ = [
    "ACTORS",
    "ACTOR_NOVA",
    "ACTOR_USER",
    "DEFAULT_CAPTURE_LIMIT",
    "DEFAULT_TIME_LIMIT_SECONDS",
    "LAUNCH_ARGV",
    "LAUNCH_PIPELINE",
    "LAUNCH_PTY",
    "MAX_TIME_LIMIT_SECONDS",
    "CommandTemplate",
    "TerminalCommandRecord",
    "TerminalSession",
    "TerminalWorkspace",
    "classify_replay_safety",
]
