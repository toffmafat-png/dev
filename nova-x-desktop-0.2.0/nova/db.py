"""Small SQLite persistence layer; each operation uses a short-lived connection."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_JSON_COLUMNS = {"plan", "checkpoint", "selected_model_ids"}
_TASK_COLUMNS = {
    "state", "plan", "result", "error", "verification", "verification_note",
    "request_count", "tool_call_count", "token_usage", "checkpoint", "intelligence_mode", "selected_model_ids",
    "cancel_requested", "pause_requested", "review_plan",
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


class Database:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._lock = threading.RLock()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS conversations (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, created_at);
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    objective TEXT NOT NULL,
                    state TEXT NOT NULL,
                    plan_json TEXT NOT NULL DEFAULT '[]',
                    result TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    verification TEXT NOT NULL DEFAULT 'unverified',
                    verification_note TEXT NOT NULL DEFAULT '',
                    request_count INTEGER NOT NULL DEFAULT 0,
                    tool_call_count INTEGER NOT NULL DEFAULT 0,
                    token_usage INTEGER NOT NULL DEFAULT 0,
                    intelligence_mode TEXT NOT NULL DEFAULT 'balanced',
                    selected_model_ids_json TEXT NOT NULL DEFAULT '[]',
                    checkpoint_json TEXT NOT NULL DEFAULT '{}',
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    pause_requested INTEGER NOT NULL DEFAULT 0,
                    review_plan INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state, updated_at);
                CREATE TABLE IF NOT EXISTS goals (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    interval_minutes INTEGER NOT NULL CHECK(interval_minutes >= 60 AND interval_minutes <= 10080),
                    enabled INTEGER NOT NULL DEFAULT 0,
                    next_run_at TEXT NOT NULL,
                    last_run_at TEXT NOT NULL DEFAULT '',
                    last_task_id TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_goals_due ON goals(enabled, next_run_at);
                CREATE TABLE IF NOT EXISTS goal_runs (
                    id TEXT PRIMARY KEY,
                    goal_id TEXT NOT NULL REFERENCES goals(id) ON DELETE CASCADE,
                    scheduled_for TEXT NOT NULL,
                    source TEXT NOT NULL,
                    task_id TEXT NOT NULL UNIQUE REFERENCES tasks(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    UNIQUE(goal_id, scheduled_for)
                );
                CREATE INDEX IF NOT EXISTS idx_goal_runs_created ON goal_runs(source, created_at);
                CREATE TABLE IF NOT EXISTS desktop_settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS command_history (
                    id TEXT PRIMARY KEY,
                    program TEXT NOT NULL,
                    arguments_json TEXT NOT NULL,
                    cwd TEXT NOT NULL,
                    status TEXT NOT NULL,
                    exit_code INTEGER,
                    stdout TEXT NOT NULL DEFAULT '',
                    stderr TEXT NOT NULL DEFAULT '',
                    started_at TEXT NOT NULL,
                    duration_seconds REAL NOT NULL DEFAULT 0,
                    log_path TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_command_history_started ON command_history(started_at DESC);
                CREATE TABLE IF NOT EXISTS autonomy_policy (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    level TEXT NOT NULL DEFAULT 'routine',
                    tool_overrides_json TEXT NOT NULL DEFAULT '{}',
                    authorized_overwrite_prefixes_json TEXT NOT NULL DEFAULT '[]',
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS task_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    message TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_task_events_task ON task_events(task_id, id);
                CREATE TABLE IF NOT EXISTS model_profiles (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    provider_type TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    api_key_env TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL DEFAULT '["chat"]',
                    context_window INTEGER NOT NULL DEFAULT 0,
                    input_cost_per_million REAL,
                    output_cost_per_million REAL,
                    priority INTEGER NOT NULL DEFAULT 50,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    is_default INTEGER NOT NULL DEFAULT 0,
                    availability_status TEXT NOT NULL DEFAULT 'unknown',
                    availability_checked_at TEXT NOT NULL DEFAULT '',
                    last_test_status TEXT NOT NULL DEFAULT 'untested',
                    last_test_at TEXT NOT NULL DEFAULT '',
                    last_latency_ms REAL,
                    calls_total INTEGER NOT NULL DEFAULT 0,
                    calls_success INTEGER NOT NULL DEFAULT 0,
                    calls_failed INTEGER NOT NULL DEFAULT 0,
                    last_used_at TEXT NOT NULL DEFAULT '',
                    last_error TEXT NOT NULL DEFAULT '',
                    config_fingerprint TEXT NOT NULL DEFAULT '',
                    tools_test_status TEXT NOT NULL DEFAULT 'untested',
                    tools_test_at TEXT NOT NULL DEFAULT '',
                    tools_test_fingerprint TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_models_enabled ON model_profiles(enabled, is_default, priority);
                CREATE TABLE IF NOT EXISTS model_runtime_state (
                    profile_id TEXT PRIMARY KEY,
                    availability_status TEXT NOT NULL DEFAULT 'unknown',
                    availability_checked_at TEXT NOT NULL DEFAULT '',
                    last_test_status TEXT NOT NULL DEFAULT 'untested',
                    last_test_at TEXT NOT NULL DEFAULT '',
                    last_latency_ms REAL,
                    calls_total INTEGER NOT NULL DEFAULT 0,
                    calls_success INTEGER NOT NULL DEFAULT 0,
                    calls_failed INTEGER NOT NULL DEFAULT 0,
                    last_used_at TEXT NOT NULL DEFAULT '',
                    last_error TEXT NOT NULL DEFAULT '',
                    config_fingerprint TEXT NOT NULL DEFAULT '',
                    tools_test_status TEXT NOT NULL DEFAULT 'untested',
                    tools_test_at TEXT NOT NULL DEFAULT '',
                    tools_test_fingerprint TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS intelligence_runs (
                    id TEXT PRIMARY KEY,
                    conversation_id TEXT,
                    task_id TEXT,
                    mode_requested TEXT NOT NULL,
                    mode_effective TEXT NOT NULL,
                    degraded_reason TEXT NOT NULL DEFAULT '',
                    models_json TEXT NOT NULL DEFAULT '[]',
                    provider_requests INTEGER NOT NULL DEFAULT 0,
                    total_tokens INTEGER NOT NULL DEFAULT 0,
                    estimated_cost_usd REAL,
                    cost_estimate_complete INTEGER NOT NULL DEFAULT 0,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_intelligence_runs_created ON intelligence_runs(created_at);
                CREATE TABLE IF NOT EXISTS intelligence_feedback (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES intelligence_runs(id) ON DELETE CASCADE,
                    rating INTEGER NOT NULL,
                    comment TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS model_eval_runs (
                    id TEXT PRIMARY KEY,
                    model_id TEXT NOT NULL,
                    suite_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    results_json TEXT NOT NULL,
                    provider_requests INTEGER NOT NULL DEFAULT 0,
                    total_tokens INTEGER NOT NULL DEFAULT 0,
                    estimated_cost_usd REAL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_model_eval_model ON model_eval_runs(model_id, created_at);
                """
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(tasks)").fetchall()}
            if "intelligence_mode" not in columns:
                conn.execute("ALTER TABLE tasks ADD COLUMN intelligence_mode TEXT NOT NULL DEFAULT 'balanced'")
            if "selected_model_ids_json" not in columns:
                conn.execute("ALTER TABLE tasks ADD COLUMN selected_model_ids_json TEXT NOT NULL DEFAULT '[]'")
            model_columns = {row[1] for row in conn.execute("PRAGMA table_info(model_profiles)").fetchall()}
            if "availability_status" not in model_columns:
                conn.execute("ALTER TABLE model_profiles ADD COLUMN availability_status TEXT NOT NULL DEFAULT 'unknown'")
            if "availability_checked_at" not in model_columns:
                conn.execute("ALTER TABLE model_profiles ADD COLUMN availability_checked_at TEXT NOT NULL DEFAULT ''")
            if "config_fingerprint" not in model_columns:
                conn.execute("ALTER TABLE model_profiles ADD COLUMN config_fingerprint TEXT NOT NULL DEFAULT ''")
            capability_columns = (("tools_test_status", "'untested'"), ("tools_test_at", "''"), ("tools_test_fingerprint", "''"))
            for column, default in capability_columns:
                if column not in model_columns:
                    conn.execute(f"ALTER TABLE model_profiles ADD COLUMN {column} TEXT NOT NULL DEFAULT {default}")
            runtime_columns = {row[1] for row in conn.execute("PRAGMA table_info(model_runtime_state)").fetchall()}
            if "config_fingerprint" not in runtime_columns:
                conn.execute("ALTER TABLE model_runtime_state ADD COLUMN config_fingerprint TEXT NOT NULL DEFAULT ''")
            for column, default in capability_columns:
                if column not in runtime_columns:
                    conn.execute(f"ALTER TABLE model_runtime_state ADD COLUMN {column} TEXT NOT NULL DEFAULT {default}")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def health_check(self) -> bool:
        try:
            with self._lock, self._connect() as conn:
                return conn.execute("SELECT 1").fetchone()[0] == 1
        except sqlite3.Error:
            return False

    def get_autonomy_policy(self, default_level: str = "routine") -> dict[str, Any]:
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO autonomy_policy (id, level, tool_overrides_json, "
                "authorized_overwrite_prefixes_json, updated_at) VALUES (1, ?, '{}', '[]', ?)",
                (default_level, now),
            )
            row = conn.execute("SELECT * FROM autonomy_policy WHERE id = 1").fetchone()
        return {
            "level": row["level"],
            "tool_overrides": json.loads(row["tool_overrides_json"] or "{}"),
            "authorized_overwrite_prefixes": json.loads(row["authorized_overwrite_prefixes_json"] or "[]"),
            "updated_at": row["updated_at"],
        }

    def update_autonomy_policy(
        self,
        level: str,
        tool_overrides: dict[str, str],
        authorized_overwrite_prefixes: list[str],
    ) -> dict[str, Any]:
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO autonomy_policy (id, level, tool_overrides_json, "
                "authorized_overwrite_prefixes_json, updated_at) VALUES (1, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET level=excluded.level, "
                "tool_overrides_json=excluded.tool_overrides_json, "
                "authorized_overwrite_prefixes_json=excluded.authorized_overwrite_prefixes_json, "
                "updated_at=excluded.updated_at",
                (level, _dump(tool_overrides), _dump(authorized_overwrite_prefixes), now),
            )
        return {
            "level": level,
            "tool_overrides": tool_overrides,
            "authorized_overwrite_prefixes": authorized_overwrite_prefixes,
            "updated_at": now,
        }

    def create_goal(self, name: str, objective: str, interval_minutes: int, enabled: bool = False) -> dict[str, Any]:
        goal_id = str(uuid.uuid4())
        now = datetime.now(UTC)
        now_text = now.isoformat(timespec="microseconds")
        next_run_at = (now + timedelta(minutes=interval_minutes)).isoformat(timespec="microseconds")
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO goals (id, name, objective, interval_minutes, enabled, next_run_at, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (goal_id, name.strip(), objective.strip(), interval_minutes, int(enabled), next_run_at, now_text, now_text),
            )
        return self.get_goal(goal_id) or {}

    def get_goal(self, goal_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT g.*, t.state AS last_task_state FROM goals g "
                "LEFT JOIN tasks t ON t.id = g.last_task_id WHERE g.id = ?",
                (goal_id,),
            ).fetchone()
        return self._goal_row(row) if row else None

    def list_goals(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT g.*, t.state AS last_task_state FROM goals g "
                "LEFT JOIN tasks t ON t.id = g.last_task_id ORDER BY g.created_at DESC LIMIT 200"
            ).fetchall()
        return [self._goal_row(row) for row in rows]

    @staticmethod
    def _goal_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["enabled"] = bool(item["enabled"])
        return item

    def update_goal(self, goal_id: str, **fields: Any) -> dict[str, Any] | None:
        allowed = {"name", "objective", "interval_minutes", "enabled"}
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"Unsupported goal fields: {', '.join(sorted(unknown))}")
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM goals WHERE id = ?", (goal_id,)).fetchone()
            if not row:
                return None
            now = datetime.now(UTC)
            now_text = now.isoformat(timespec="microseconds")
            interval = int(fields.get("interval_minutes", row["interval_minutes"]))
            enabled = bool(fields.get("enabled", row["enabled"]))
            reset_schedule = "interval_minutes" in fields or (enabled and not bool(row["enabled"]))
            updates = dict(fields)
            updates["enabled"] = int(enabled)
            updates["updated_at"] = now_text
            if reset_schedule:
                updates["next_run_at"] = (now + timedelta(minutes=interval)).isoformat(timespec="microseconds")
            assignments = ", ".join(f"{key} = ?" for key in updates)
            conn.execute(f"UPDATE goals SET {assignments} WHERE id = ?", (*updates.values(), goal_id))
        return self.get_goal(goal_id)

    def run_goal_now(self, goal_id: str) -> str | None:
        task_id = str(uuid.uuid4())
        run_id = str(uuid.uuid4())
        now_text = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            goal = conn.execute("SELECT * FROM goals WHERE id = ?", (goal_id,)).fetchone()
            if not goal:
                return None
            checkpoint = {"origin": {"type": "goal_manual", "goal_id": goal_id, "goal_name": goal["name"]}}
            conn.execute(
                "INSERT INTO tasks (id, objective, state, plan_json, checkpoint_json, intelligence_mode, "
                "selected_model_ids_json, review_plan, created_at, updated_at) "
                "VALUES (?, ?, 'queued', '[]', ?, 'balanced', '[]', 0, ?, ?)",
                (task_id, goal["objective"], _dump(checkpoint), now_text, now_text),
            )
            conn.execute(
                "INSERT INTO goal_runs (id, goal_id, scheduled_for, source, task_id, created_at) VALUES (?, ?, ?, 'manual', ?, ?)",
                (run_id, goal_id, f"manual:{now_text}:{run_id}", task_id, now_text),
            )
            conn.execute(
                "UPDATE goals SET last_run_at = ?, last_task_id = ?, updated_at = ? WHERE id = ?",
                (now_text, task_id, now_text, goal_id),
            )
            conn.execute(
                "INSERT INTO task_events (task_id, kind, message, payload_json, created_at) VALUES (?, 'status', ?, ?, ?)",
                (task_id, f"Task queued from the configured goal '{goal['name']}' by an explicit run-now request.", _dump({"goal_id": goal_id, "source": "manual"}), now_text),
            )
        return task_id

    def dispatch_due_goals(self, daily_limit: int = 5, now: datetime | None = None) -> list[dict[str, Any]]:
        """Atomically create at most the daily cap of due goal tasks; never burst missed intervals."""
        if daily_limit <= 0:
            return []
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            current = current.replace(tzinfo=UTC)
        current = current.astimezone(UTC)
        now_text = current.isoformat(timespec="microseconds")
        day_start = current.replace(hour=0, minute=0, second=0, microsecond=0).isoformat(timespec="microseconds")
        created: list[dict[str, Any]] = []
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            used = conn.execute(
                "SELECT COUNT(*) FROM goal_runs WHERE source = 'scheduled' AND created_at >= ?",
                (day_start,),
            ).fetchone()[0]
            remaining = max(0, daily_limit - int(used))
            if remaining == 0:
                return []
            due = conn.execute(
                "SELECT * FROM goals WHERE enabled = 1 AND next_run_at <= ? ORDER BY next_run_at, id LIMIT ?",
                (now_text, remaining),
            ).fetchall()
            for goal in due:
                try:
                    scheduled_dt = datetime.fromisoformat(goal["next_run_at"])
                except ValueError:
                    scheduled_dt = current
                if scheduled_dt.tzinfo is None:
                    scheduled_dt = scheduled_dt.replace(tzinfo=UTC)
                scheduled_dt = scheduled_dt.astimezone(UTC)
                next_dt = scheduled_dt
                interval = int(goal["interval_minutes"])
                while next_dt <= current:
                    next_dt += timedelta(minutes=interval)
                scheduled_for = goal["next_run_at"]
                run_id = str(uuid.uuid4())
                task_id = str(uuid.uuid4())
                created_at = utc_now()
                origin = {"type": "scheduled_goal", "goal_id": goal["id"], "goal_name": goal["name"], "scheduled_for": scheduled_for}
                checkpoint = {"origin": origin}
                conn.execute(
                    "INSERT INTO tasks (id, objective, state, plan_json, checkpoint_json, intelligence_mode, "
                    "selected_model_ids_json, review_plan, created_at, updated_at) "
                    "VALUES (?, ?, 'queued', '[]', ?, 'balanced', '[]', 0, ?, ?)",
                    (task_id, goal["objective"], _dump(checkpoint), created_at, created_at),
                )
                conn.execute(
                    "INSERT INTO goal_runs (id, goal_id, scheduled_for, source, task_id, created_at) VALUES (?, ?, ?, 'scheduled', ?, ?)",
                    (run_id, goal["id"], scheduled_for, task_id, created_at),
                )
                conn.execute(
                    "UPDATE goals SET next_run_at = ?, last_run_at = ?, last_task_id = ?, updated_at = ? WHERE id = ?",
                    (next_dt.isoformat(timespec="microseconds"), scheduled_for, task_id, created_at, goal["id"]),
                )
                conn.execute(
                    "INSERT INTO task_events (task_id, kind, message, payload_json, created_at) VALUES (?, 'status', ?, ?, ?)",
                    (task_id, f"Task queued from configured schedule for goal '{goal['name']}'.", _dump({"goal_id": goal["id"], "source": "scheduled", "scheduled_for": scheduled_for}), created_at),
                )
                created.append({"task_id": task_id, "goal_id": goal["id"], "goal_name": goal["name"], "objective": goal["objective"], "scheduled_for": scheduled_for})
        return created

    def create_task(
        self,
        objective: str,
        review_plan: bool = False,
        intelligence_mode: str = "balanced",
        selected_model_ids: list[str] | None = None,
    ) -> str:
        task_id = str(uuid.uuid4())
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO tasks (id, objective, state, plan_json, checkpoint_json, intelligence_mode, "
                "selected_model_ids_json, review_plan, created_at, updated_at) "
                "VALUES (?, ?, 'queued', '[]', '{}', ?, ?, ?, ?, ?)",
                (task_id, objective, intelligence_mode, _dump(selected_model_ids or []), int(review_plan), now, now),
            )
        return task_id

    def update_task(self, task_id: str, **fields: Any) -> None:
        unknown = set(fields) - _TASK_COLUMNS
        if unknown:
            raise ValueError(f"Unsupported task fields: {', '.join(sorted(unknown))}")
        if not fields:
            return
        converted = {}
        for key, value in fields.items():
            if key in _JSON_COLUMNS:
                value = _dump(value)
            elif key in {"cancel_requested", "pause_requested", "review_plan"}:
                value = int(bool(value))
            converted[key] = value
        converted["updated_at"] = utc_now()
        assignments = ", ".join(f"{key if key not in _JSON_COLUMNS else key + '_json'} = ?" for key in fields)
        values = [converted[key] for key in fields]
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                f"UPDATE tasks SET {assignments}, updated_at = ? WHERE id = ?",
                (*values, converted["updated_at"], task_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(task_id)

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return self._task_row(row) if row else None

    def list_tasks(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM tasks ORDER BY updated_at DESC LIMIT ?", (max(1, min(limit, 200)),)
            ).fetchall()
        return [self._task_row(row) for row in rows]

    @staticmethod
    def _task_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["plan"] = json.loads(item.pop("plan_json") or "[]")
        item["checkpoint"] = json.loads(item.pop("checkpoint_json") or "{}")
        item["selected_model_ids"] = json.loads(item.pop("selected_model_ids_json", "[]") or "[]")
        item["cancel_requested"] = bool(item["cancel_requested"])
        item["pause_requested"] = bool(item["pause_requested"])
        item["review_plan"] = bool(item["review_plan"])
        return item

    def add_event(self, task_id: str, kind: str, message: str, payload: Any | None = None) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO task_events (task_id, kind, message, payload_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (task_id, kind, message, _dump(payload or {}), utc_now()),
            )

    def get_task_events(self, task_id: str, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT id, kind, message, payload_json, created_at FROM task_events "
                "WHERE task_id = ? ORDER BY id DESC LIMIT ?",
                (task_id, max(1, min(limit, 500))),
            ).fetchall()
        result = []
        for row in reversed(rows):
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json") or "{}")
            result.append(item)
        return result

    def recover_interrupted_tasks(self) -> int:
        """Mark work that was in-flight at process shutdown as resumable, not complete."""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT id, cancel_requested FROM tasks WHERE state IN ('queued', 'planning', 'running')"
            ).fetchall()
            if not rows:
                return 0
            now = utc_now()
            for row in rows:
                task_id = row["id"]
                if row["cancel_requested"]:
                    state, pause_requested = "cancelled", 0
                    message = "Cancellation was pending when the process restarted; task marked cancelled without replaying tools."
                else:
                    state, pause_requested = "paused", 1
                    message = "Process restarted; checkpoint preserved. Review and resume when ready."
                conn.execute(
                    "UPDATE tasks SET state = ?, pause_requested = ?, updated_at = ? WHERE id = ?",
                    (state, pause_requested, now, task_id),
                )
                conn.execute(
                    "INSERT INTO task_events (task_id, kind, message, payload_json, created_at) VALUES (?, 'recovery', ?, '{}', ?)",
                    (task_id, message, now),
                )
            return len(rows)

    def create_conversation(self, title: str = "New conversation") -> str:
        conversation_id = str(uuid.uuid4())
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO conversations (id, title, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (conversation_id, title[:120], now, now),
            )
        return conversation_id

    def add_message(self, conversation_id: str, role: str, content: str) -> dict[str, str]:
        message_id = str(uuid.uuid4())
        now = utc_now()
        with self._lock, self._connect() as conn:
            exists = conn.execute("SELECT id FROM conversations WHERE id = ?", (conversation_id,)).fetchone()
            if not exists:
                raise KeyError(conversation_id)
            conn.execute(
                "INSERT INTO messages (id, conversation_id, role, content, created_at) VALUES (?, ?, ?, ?, ?)",
                (message_id, conversation_id, role, content, now),
            )
            if role == "user":
                conn.execute(
                    "UPDATE conversations SET title = CASE WHEN title = 'New conversation' THEN ? ELSE title END, updated_at = ? WHERE id = ?",
                    (content[:100].replace("\n", " "), now, conversation_id),
                )
            else:
                conn.execute("UPDATE conversations SET updated_at = ? WHERE id = ?", (now, conversation_id))
        return {"id": message_id, "conversation_id": conversation_id, "role": role, "content": content, "created_at": now}

    def get_messages(self, conversation_id: str, limit: int = 100) -> list[dict[str, str]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT id, conversation_id, role, content, created_at FROM messages "
                "WHERE conversation_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (conversation_id, max(1, min(limit, 500))),
            ).fetchall()
            exists = conn.execute("SELECT id FROM conversations WHERE id = ?", (conversation_id,)).fetchone()
        if not exists:
            raise KeyError(conversation_id)
        return [dict(row) for row in reversed(rows)]

    def list_conversations(self, limit: int = 50) -> list[dict[str, str]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT id, title, created_at, updated_at FROM conversations ORDER BY updated_at DESC LIMIT ?",
                (max(1, min(limit, 200)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_conversation(self, conversation_id: str) -> bool:
        with self._lock, self._connect() as conn:
            run_ids = [row[0] for row in conn.execute(
                "SELECT id FROM intelligence_runs WHERE conversation_id = ?", (conversation_id,)
            ).fetchall()]
            if run_ids:
                placeholders = ",".join("?" for _ in run_ids)
                conn.execute(f"DELETE FROM intelligence_feedback WHERE run_id IN ({placeholders})", run_ids)
                conn.execute(f"DELETE FROM intelligence_runs WHERE id IN ({placeholders})", run_ids)
            cursor = conn.execute("DELETE FROM conversations WHERE id = ?", (conversation_id,))
            return cursor.rowcount > 0

    @staticmethod
    def _model_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["capabilities"] = json.loads(item.pop("capabilities_json") or '["chat"]')
        item["enabled"] = bool(item["enabled"])
        item["is_default"] = bool(item["is_default"])
        return item

    def create_model_profile(self, profile: dict[str, Any]) -> dict[str, Any]:
        profile_id = profile.get("id") or str(uuid.uuid4())
        now = utc_now()
        with self._lock, self._connect() as conn:
            if profile.get("is_default"):
                conn.execute("UPDATE model_profiles SET is_default = 0")
            conn.execute(
                "INSERT INTO model_profiles (id, name, provider_type, base_url, model_id, api_key_env, "
                "capabilities_json, context_window, input_cost_per_million, output_cost_per_million, priority, "
                "enabled, is_default, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    profile_id, profile["name"], profile["provider_type"], profile["base_url"], profile["model_id"],
                    profile["api_key_env"], _dump(profile.get("capabilities", ["chat"])),
                    int(profile.get("context_window", 0)), profile.get("input_cost_per_million"),
                    profile.get("output_cost_per_million"), int(profile.get("priority", 50)),
                    int(bool(profile.get("enabled", True))), int(bool(profile.get("is_default", False))), now, now,
                ),
            )
            row = conn.execute("SELECT * FROM model_profiles WHERE id = ?", (profile_id,)).fetchone()
        return self._model_row(row)

    def update_model_profile(self, profile_id: str, fields: dict[str, Any]) -> dict[str, Any] | None:
        allowed = {
            "name", "base_url", "model_id", "api_key_env", "capabilities", "context_window",
            "input_cost_per_million", "output_cost_per_million", "priority", "enabled", "is_default",
        }
        if set(fields) - allowed:
            raise ValueError("Unsupported model profile fields")
        if not fields:
            return self.get_model_profile(profile_id)
        converted = {}
        for key, value in fields.items():
            if key == "capabilities":
                converted["capabilities_json"] = _dump(value)
            elif key in {"enabled", "is_default"}:
                converted[key] = int(bool(value))
            else:
                converted[key] = value
        with self._lock, self._connect() as conn:
            if fields.get("is_default"):
                conn.execute("UPDATE model_profiles SET is_default = 0")
            assignments = ", ".join(f"{key} = ?" for key in converted)
            cursor = conn.execute(
                f"UPDATE model_profiles SET {assignments}, updated_at = ? WHERE id = ?",
                (*converted.values(), utc_now(), profile_id),
            )
            if cursor.rowcount == 0:
                return None
            row = conn.execute("SELECT * FROM model_profiles WHERE id = ?", (profile_id,)).fetchone()
        return self._model_row(row)

    def get_model_profile(self, profile_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM model_profiles WHERE id = ?", (profile_id,)).fetchone()
        return self._model_row(row) if row else None

    def list_model_profiles(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM model_profiles ORDER BY is_default DESC, priority ASC, name COLLATE NOCASE"
            ).fetchall()
        return [self._model_row(row) for row in rows]

    def delete_model_profile(self, profile_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM model_profiles WHERE id = ?", (profile_id,))
            return cursor.rowcount > 0

    def get_profile_runtime_state(self, profile_id: str) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM model_runtime_state WHERE profile_id = ?", (profile_id,)).fetchone()
        return dict(row) if row else {}

    def record_profile_test(
        self, profile_id: str, status: str, latency_ms: float | None = None, error: str = "", config_fingerprint: str = "",
    ) -> None:
        tested_at = utc_now()
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE model_profiles SET last_test_status = ?, last_test_at = ?, last_latency_ms = ?, "
                "last_error = ?, availability_status = CASE WHEN config_fingerprint <> ? THEN 'unknown' ELSE availability_status END, "
                "availability_checked_at = CASE WHEN config_fingerprint <> ? THEN '' ELSE availability_checked_at END, "
                "config_fingerprint = ?, updated_at = ? WHERE id = ?",
                (status, tested_at, latency_ms, error[:500], config_fingerprint, config_fingerprint, config_fingerprint, tested_at, profile_id),
            )
            if cursor.rowcount == 0:
                conn.execute(
                    "INSERT INTO model_runtime_state (profile_id, last_test_status, last_test_at, last_latency_ms, last_error, config_fingerprint) "
                    "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(profile_id) DO UPDATE SET "
                    "last_test_status = excluded.last_test_status, last_test_at = excluded.last_test_at, "
                    "last_latency_ms = excluded.last_latency_ms, last_error = excluded.last_error, "
                    "availability_status = CASE WHEN model_runtime_state.config_fingerprint <> excluded.config_fingerprint THEN 'unknown' ELSE model_runtime_state.availability_status END, "
                    "availability_checked_at = CASE WHEN model_runtime_state.config_fingerprint <> excluded.config_fingerprint THEN '' ELSE model_runtime_state.availability_checked_at END, "
                    "config_fingerprint = excluded.config_fingerprint",
                    (profile_id, status, tested_at, latency_ms, error[:500], config_fingerprint),
                )

    def record_profile_tool_test(self, profile_id: str, status: str, config_fingerprint: str) -> None:
        tested_at = utc_now()
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE model_profiles SET tools_test_status = ?, tools_test_at = ?, tools_test_fingerprint = ?, updated_at = ? WHERE id = ?",
                (status, tested_at, config_fingerprint, tested_at, profile_id),
            )
            if cursor.rowcount == 0:
                conn.execute(
                    "INSERT INTO model_runtime_state (profile_id, tools_test_status, tools_test_at, tools_test_fingerprint) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT(profile_id) DO UPDATE SET "
                    "tools_test_status = excluded.tools_test_status, tools_test_at = excluded.tools_test_at, "
                    "tools_test_fingerprint = excluded.tools_test_fingerprint",
                    (profile_id, status, tested_at, config_fingerprint),
                )

    def record_profile_catalog_status(self, profile_id: str, status: str, config_fingerprint: str = "") -> None:
        checked_at = utc_now()
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE model_profiles SET availability_status = ?, availability_checked_at = ?, "
                "last_test_status = CASE WHEN config_fingerprint <> ? THEN 'untested' ELSE last_test_status END, "
                "last_test_at = CASE WHEN config_fingerprint <> ? THEN '' ELSE last_test_at END, "
                "config_fingerprint = ?, updated_at = ? WHERE id = ?",
                (status, checked_at, config_fingerprint, config_fingerprint, config_fingerprint, checked_at, profile_id),
            )
            if cursor.rowcount == 0:
                conn.execute(
                    "INSERT INTO model_runtime_state (profile_id, availability_status, availability_checked_at, config_fingerprint) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT(profile_id) DO UPDATE SET "
                    "availability_status = excluded.availability_status, availability_checked_at = excluded.availability_checked_at, "
                    "last_test_status = CASE WHEN model_runtime_state.config_fingerprint <> excluded.config_fingerprint THEN 'untested' ELSE model_runtime_state.last_test_status END, "
                    "last_test_at = CASE WHEN model_runtime_state.config_fingerprint <> excluded.config_fingerprint THEN '' ELSE model_runtime_state.last_test_at END, "
                    "config_fingerprint = excluded.config_fingerprint",
                    (profile_id, status, checked_at, config_fingerprint),
                )

    def record_profile_call(self, profile_id: str, success: bool, latency_ms: float, error: str = "") -> None:
        used_at = utc_now()
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE model_profiles SET calls_total = calls_total + 1, "
                "calls_success = calls_success + ?, calls_failed = calls_failed + ?, last_latency_ms = ?, "
                "last_used_at = ?, last_error = ?, updated_at = ? WHERE id = ?",
                (int(success), int(not success), max(0.0, latency_ms), used_at, error[:500], used_at, profile_id),
            )
            if cursor.rowcount == 0:
                conn.execute(
                    "INSERT INTO model_runtime_state (profile_id, calls_total, calls_success, calls_failed, last_latency_ms, last_used_at, last_error) "
                    "VALUES (?, 1, ?, ?, ?, ?, ?) ON CONFLICT(profile_id) DO UPDATE SET "
                    "calls_total = calls_total + 1, calls_success = calls_success + excluded.calls_success, "
                    "calls_failed = calls_failed + excluded.calls_failed, last_latency_ms = excluded.last_latency_ms, "
                    "last_used_at = excluded.last_used_at, last_error = excluded.last_error",
                    (profile_id, int(success), int(not success), max(0.0, latency_ms), used_at, error[:500]),
                )

    def record_intelligence_run(self, details: dict[str, Any]) -> str:
        run_id = details.get("id") or str(uuid.uuid4())
        models = details.get("models", [])
        safe_details = {
            key: details.get(key) for key in (
                "mode_requested", "mode_effective", "degraded_reason", "models", "provider_requests",
                "total_tokens", "usage_complete", "estimated_cost_usd", "cost_estimate_complete", "checks_performed",
            ) if key in details
        }
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO intelligence_runs (id, conversation_id, task_id, mode_requested, mode_effective, "
                "degraded_reason, models_json, provider_requests, total_tokens, estimated_cost_usd, "
                "cost_estimate_complete, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id, details.get("conversation_id"), details.get("task_id"),
                    details.get("mode_requested", "balanced"), details.get("mode_effective", "balanced"),
                    details.get("degraded_reason", ""), _dump(models), int(details.get("provider_requests", 0)),
                    int(details.get("total_tokens", 0)), details.get("estimated_cost_usd"),
                    int(bool(details.get("cost_estimate_complete", False))), _dump(safe_details), utc_now(),
                ),
            )
        return run_id

    def list_intelligence_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM intelligence_runs ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 200)),)
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["models"] = json.loads(item.pop("models_json") or "[]")
            item["details"] = json.loads(item.pop("details_json") or "{}")
            item["cost_estimate_complete"] = bool(item["cost_estimate_complete"])
            result.append(item)
        return result

    def add_intelligence_feedback(self, run_id: str, rating: int, comment: str = "") -> str:
        feedback_id = str(uuid.uuid4())
        with self._lock, self._connect() as conn:
            exists = conn.execute("SELECT id FROM intelligence_runs WHERE id = ?", (run_id,)).fetchone()
            if not exists:
                raise KeyError(run_id)
            conn.execute(
                "INSERT INTO intelligence_feedback (id, run_id, rating, comment, created_at) VALUES (?, ?, ?, ?, ?)",
                (feedback_id, run_id, rating, comment[:1000], utc_now()),
            )
        return feedback_id

    def create_eval_run(self, model_id: str, suite_version: str, status: str, results: dict[str, Any],
                        provider_requests: int, total_tokens: int, estimated_cost_usd: float | None) -> str:
        run_id = str(uuid.uuid4())
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO model_eval_runs (id, model_id, suite_version, status, results_json, provider_requests, "
                "total_tokens, estimated_cost_usd, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, model_id, suite_version, status, _dump(results), provider_requests, total_tokens,
                 estimated_cost_usd, utc_now()),
            )
        return run_id

    def list_eval_runs(self, model_id: str | None = None, limit: int = 30) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            if model_id:
                rows = conn.execute(
                    "SELECT * FROM model_eval_runs WHERE model_id = ? ORDER BY created_at DESC LIMIT ?",
                    (model_id, max(1, min(limit, 100))),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM model_eval_runs ORDER BY created_at DESC LIMIT ?",
                    (max(1, min(limit, 100)),),
                ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["results"] = json.loads(item.pop("results_json") or "{}")
            result.append(item)
        return result

    def get_desktop_setting(self, key: str, default: Any = None) -> Any:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT value_json FROM desktop_settings WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value_json"]) if row else default

    def set_desktop_setting(self, key: str, value: Any) -> None:
        if not isinstance(key, str) or not key or len(key) > 100:
            raise ValueError("Desktop setting key is invalid")
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO desktop_settings (key, value_json, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                (key, _dump(value), utc_now()),
            )

    def add_command_history(self, record: dict[str, Any], limit: int = 500) -> str:
        command_id = str(record.get("id") or uuid.uuid4())
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO command_history (id, program, arguments_json, cwd, status, exit_code, stdout, stderr, started_at, duration_seconds, log_path) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    command_id,
                    str(record.get("program", ""))[:256],
                    _dump(record.get("arguments", [])[:128]),
                    str(record.get("cwd", ""))[:2000],
                    str(record.get("status", "unknown"))[:40],
                    record.get("exit_code"),
                    str(record.get("stdout", ""))[:20_000],
                    str(record.get("stderr", ""))[:20_000],
                    str(record.get("started_at", utc_now()))[:80],
                    max(0.0, float(record.get("duration_seconds", 0.0) or 0.0)),
                    str(record.get("log_path", ""))[:2000],
                ),
            )
            conn.execute(
                "DELETE FROM command_history WHERE id IN (SELECT id FROM command_history ORDER BY started_at DESC LIMIT -1 OFFSET ?)",
                (max(50, min(int(limit), 5000)),),
            )
        return command_id

    def list_command_history(self, query: str = "", limit: int = 100) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 500))
        with self._lock, self._connect() as conn:
            if query.strip():
                needle = f"%{query.strip()[:200]}%"
                rows = conn.execute(
                    "SELECT * FROM command_history WHERE program LIKE ? OR cwd LIKE ? OR stdout LIKE ? OR stderr LIKE ? "
                    "ORDER BY started_at DESC LIMIT ?",
                    (needle, needle, needle, needle, bounded_limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM command_history ORDER BY started_at DESC LIMIT ?",
                    (bounded_limit,),
                ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["arguments"] = json.loads(item.pop("arguments_json") or "[]")
            result.append(item)
        return result

    def clear_command_history(self) -> int:
        with self._lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM command_history")
            return int(cursor.rowcount)
