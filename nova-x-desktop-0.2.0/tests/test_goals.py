from __future__ import annotations

from datetime import datetime, timedelta, timezone


def test_only_enabled_configured_goals_are_dispatched_and_missed_runs_do_not_burst(environment):
    _settings, db, _registry, _workspace = environment
    disabled = db.create_goal("Disabled", "Do not run until enabled", 60, enabled=False)
    assert db.dispatch_due_goals(now=datetime.now(timezone.utc) + timedelta(days=3)) == []

    enabled = db.update_goal(disabled["id"], enabled=True)
    assert enabled and enabled["enabled"] is True
    late = datetime.now(timezone.utc) + timedelta(days=3)
    due = db.dispatch_due_goals(daily_limit=5, now=late)
    assert len(due) == 1
    assert due[0]["goal_id"] == disabled["id"]
    task = db.get_task(due[0]["task_id"])
    assert task["state"] == "queued"
    assert task["intelligence_mode"] == "balanced"
    assert task["checkpoint"]["origin"]["type"] == "scheduled_goal"
    assert task["checkpoint"]["origin"]["goal_id"] == disabled["id"]
    # A long outage generates one task, not a backlog burst.
    assert db.dispatch_due_goals(daily_limit=5, now=late) == []
    assert datetime.fromisoformat(db.get_goal(disabled["id"])["next_run_at"]) > late


def test_scheduled_goal_runs_obey_daily_cap_and_manual_runs_are_explicit(environment):
    _settings, db, _registry, _workspace = environment
    first = db.create_goal("First", "First configured objective", 60, enabled=True)
    second = db.create_goal("Second", "Second configured objective", 60, enabled=True)
    now = datetime.now(timezone.utc)
    due_at = (now - timedelta(minutes=2)).isoformat(timespec="microseconds")
    with db._lock, db._connect() as conn:
        conn.execute("UPDATE goals SET next_run_at = ? WHERE id IN (?, ?)", (due_at, first["id"], second["id"]))

    dispatched = db.dispatch_due_goals(daily_limit=1, now=now)
    assert len(dispatched) == 1
    assert db.dispatch_due_goals(daily_limit=1, now=now + timedelta(seconds=1)) == []

    manual_id = db.run_goal_now(second["id"])
    assert manual_id
    manual = db.get_task(manual_id)
    assert manual["checkpoint"]["origin"]["type"] == "goal_manual"
    assert manual["checkpoint"]["origin"]["goal_id"] == second["id"]
    assert manual["state"] == "queued"


def test_goal_updates_reset_the_next_run_and_preserve_task_history(environment):
    _settings, db, _registry, _workspace = environment
    goal = db.create_goal("Review project", "Review project files safely", 1440, enabled=False)
    enabled = db.update_goal(goal["id"], enabled=True)
    assert enabled["enabled"] is True
    assert datetime.fromisoformat(enabled["next_run_at"]) > datetime.now(timezone.utc)
    changed = db.update_goal(goal["id"], name="Review notes", interval_minutes=10080)
    assert changed["name"] == "Review notes"
    assert changed["interval_minutes"] == 10080
    assert datetime.fromisoformat(changed["next_run_at"]) > datetime.now(timezone.utc)
