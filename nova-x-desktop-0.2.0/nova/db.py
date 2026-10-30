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


def _observation_is_stale(row: dict[str, Any]) -> bool:
    """Answer staleness with the cognition TTL rules rather than a second copy.

    The import is local so ``nova.db`` never depends on the cognition package at
    module load time; if that package is unavailable the row is simply reported
    as not stale instead of raising.
    """
    try:
        from nova.cognition.world_model import Observation
    except ImportError:
        return False
    try:
        return Observation(
            subject=str(row.get("subject") or ""),
            predicate=str(row.get("predicate") or ""),
            value=str(row.get("value") or ""),
            source=str(row.get("source") or "model_generated"),
            observed_at=str(row.get("observed_at") or ""),
            ttl_seconds=row.get("ttl_seconds"),
        ).is_stale()
    except (TypeError, ValueError):
        return False


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
                CREATE TABLE IF NOT EXISTS cognition_observations (
                    id TEXT PRIMARY KEY,
                    scope TEXT NOT NULL DEFAULT 'default',
                    subject TEXT NOT NULL,
                    predicate TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    ttl_seconds INTEGER,
                    task_id TEXT NOT NULL DEFAULT '',
                    evidence_ref TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_cog_obs_key ON cognition_observations(scope, subject, predicate);
                CREATE INDEX IF NOT EXISTS idx_cog_obs_time ON cognition_observations(observed_at);
                CREATE TABLE IF NOT EXISTS cognition_predictions (
                    id TEXT PRIMARY KEY,
                    scope TEXT NOT NULL DEFAULT 'default',
                    action TEXT NOT NULL,
                    expected_json TEXT NOT NULL DEFAULT '{}',
                    task_id TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    resolved INTEGER NOT NULL DEFAULT 0,
                    resolved_at TEXT NOT NULL DEFAULT '',
                    agreement REAL,
                    matched_json TEXT NOT NULL DEFAULT '[]',
                    contradicted_json TEXT NOT NULL DEFAULT '[]'
                );
                CREATE INDEX IF NOT EXISTS idx_cog_pred_open ON cognition_predictions(scope, resolved);
                CREATE TABLE IF NOT EXISTS cognition_procedures (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    domain TEXT NOT NULL DEFAULT '',
                    summary TEXT NOT NULL DEFAULT '',
                    steps_json TEXT NOT NULL DEFAULT '[]',
                    preconditions_json TEXT NOT NULL DEFAULT '[]',
                    environment_json TEXT NOT NULL DEFAULT '{}',
                    tools_required_json TEXT NOT NULL DEFAULT '[]',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    source_task_ids_json TEXT NOT NULL DEFAULT '[]',
                    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
                    provenance TEXT NOT NULL DEFAULT 'tool_result',
                    status TEXT NOT NULL DEFAULT 'candidate',
                    version INTEGER NOT NULL DEFAULT 1,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    successes INTEGER NOT NULL DEFAULT 0,
                    supersedes TEXT,
                    superseded_by TEXT,
                    correction_reason TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cog_proc_status ON cognition_procedures(status, updated_at);
                CREATE TABLE IF NOT EXISTS cognition_calibration (
                    id TEXT PRIMARY KEY,
                    confidence REAL NOT NULL,
                    outcome INTEGER NOT NULL,
                    statement TEXT NOT NULL DEFAULT '',
                    domain TEXT NOT NULL DEFAULT '',
                    task_id TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cog_cal_domain ON cognition_calibration(domain, created_at);
                CREATE TABLE IF NOT EXISTS cognition_reviews (
                    id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cog_review_task ON cognition_reviews(task_id, phase);
                CREATE TABLE IF NOT EXISTS cognition_decisions (
                    id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL DEFAULT '',
                    objective TEXT NOT NULL DEFAULT '',
                    chosen_option_id TEXT,
                    short_circuited INTEGER NOT NULL DEFAULT 0,
                    risk_tolerance TEXT NOT NULL DEFAULT 'routine',
                    predicted_confidence REAL NOT NULL DEFAULT 0,
                    predicted_outcome TEXT NOT NULL DEFAULT '',
                    actual_outcome TEXT,
                    prediction_matched INTEGER,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    resolved_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_cog_decision_created ON cognition_decisions(created_at);
                CREATE TABLE IF NOT EXISTS intelligence_eval_runs (
                    id TEXT PRIMARY KEY,
                    suite_version TEXT NOT NULL,
                    commit_ref TEXT NOT NULL DEFAULT '',
                    include_held_out INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    pass_rate REAL NOT NULL DEFAULT 0,
                    totals_json TEXT NOT NULL DEFAULT '{}',
                    cases_json TEXT NOT NULL DEFAULT '{}',
                    baseline_version TEXT,
                    regressions_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_intel_eval_suite ON intelligence_eval_runs(suite_version, created_at);
                CREATE TABLE IF NOT EXISTS creation_projects (
                    id TEXT PRIMARY KEY,
                    slug TEXT NOT NULL,
                    name TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'draft',
                    project_dir TEXT NOT NULL,
                    current_version INTEGER NOT NULL DEFAULT 0,
                    spec_json TEXT NOT NULL DEFAULT '{}',
                    toolchain_json TEXT NOT NULL DEFAULT '{}',
                    latest_report_json TEXT NOT NULL DEFAULT '{}',
                    known_issues_json TEXT NOT NULL DEFAULT '[]',
                    license TEXT NOT NULL DEFAULT 'MIT',
                    archived INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_creation_projects_updated ON creation_projects(archived, updated_at);
                CREATE INDEX IF NOT EXISTS idx_creation_projects_domain ON creation_projects(domain, status);
                CREATE TABLE IF NOT EXISTS creation_revisions (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES creation_projects(id) ON DELETE CASCADE,
                    version INTEGER NOT NULL,
                    stage TEXT NOT NULL DEFAULT 'build',
                    summary TEXT NOT NULL DEFAULT '',
                    snapshot_dir TEXT NOT NULL DEFAULT '',
                    artifacts_json TEXT NOT NULL DEFAULT '[]',
                    qa_json TEXT NOT NULL DEFAULT '{}',
                    quality_score REAL NOT NULL DEFAULT 0,
                    retained INTEGER NOT NULL DEFAULT 1,
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_creation_revisions_proj ON creation_revisions(project_id, version);
                CREATE TABLE IF NOT EXISTS creation_assets (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL DEFAULT '',
                    filename TEXT NOT NULL,
                    rel_path TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    sha256 TEXT NOT NULL DEFAULT '',
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    version INTEGER NOT NULL DEFAULT 1,
                    parent_asset_id TEXT NOT NULL DEFAULT '',
                    provenance TEXT NOT NULL DEFAULT 'procedural',
                    license TEXT NOT NULL DEFAULT 'MIT',
                    reusable INTEGER NOT NULL DEFAULT 1,
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    usage_notes TEXT NOT NULL DEFAULT '',
                    preview_rel_path TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_creation_assets_proj ON creation_assets(project_id, media_type);
                CREATE INDEX IF NOT EXISTS idx_creation_assets_sha ON creation_assets(sha256);
                CREATE TABLE IF NOT EXISTS creation_blueprints (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL DEFAULT '1.0.0',
                    domain TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    source_project_id TEXT NOT NULL DEFAULT '',
                    objective TEXT NOT NULL DEFAULT '',
                    license TEXT NOT NULL DEFAULT 'MIT',
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_creation_blueprints_domain ON creation_blueprints(domain, updated_at);
                CREATE TABLE IF NOT EXISTS creation_runs (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL DEFAULT '',
                    kind TEXT NOT NULL DEFAULT 'build',
                    status TEXT NOT NULL,
                    summary TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_creation_runs_created ON creation_runs(created_at);
                CREATE TABLE IF NOT EXISTS memory_entries (
                    id TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    content TEXT NOT NULL,
                    provenance TEXT NOT NULL DEFAULT 'user_stated',
                    verified_fact INTEGER NOT NULL DEFAULT 0,
                    source_ref TEXT NOT NULL DEFAULT '',
                    project_id TEXT NOT NULL DEFAULT '',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_memory_entries_cat ON memory_entries(category, updated_at);
                CREATE TABLE IF NOT EXISTS improvement_experiments (
                    id TEXT PRIMARY KEY,
                    mechanism TEXT NOT NULL,
                    title TEXT NOT NULL,
                    hypothesis TEXT NOT NULL,
                    status TEXT NOT NULL,
                    safety_passed INTEGER NOT NULL DEFAULT 0,
                    tests_passed INTEGER NOT NULL DEFAULT 0,
                    baseline_score REAL NOT NULL DEFAULT 0,
                    candidate_score REAL NOT NULL DEFAULT 0,
                    applied INTEGER NOT NULL DEFAULT 0,
                    staging_dir TEXT NOT NULL DEFAULT '',
                    backup_dir TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_improvement_experiments_updated ON improvement_experiments(updated_at);
                CREATE TABLE IF NOT EXISTS worker_heartbeats (
                    worker_id TEXT PRIMARY KEY,
                    pid INTEGER NOT NULL DEFAULT 0,
                    mode TEXT NOT NULL DEFAULT 'user_worker',
                    status TEXT NOT NULL DEFAULT 'stopped',
                    dispatched_count INTEGER NOT NULL DEFAULT 0,
                    detail TEXT NOT NULL DEFAULT '',
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS driver_repairs (
                    id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    device_class TEXT NOT NULL,
                    issue_summary TEXT NOT NULL,
                    proposed_action TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    recovery_path TEXT NOT NULL DEFAULT '',
                    applied INTEGER NOT NULL DEFAULT 0,
                    verified_functional INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    evidence_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_driver_repairs_created ON driver_repairs(created_at DESC);
                CREATE TABLE IF NOT EXISTS privileged_helper_policies (
                    id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    scope_pattern TEXT NOT NULL DEFAULT '*',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    allow_without_prompt INTEGER NOT NULL DEFAULT 0,
                    notes TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(operation, scope_pattern)
                );
                CREATE TABLE IF NOT EXISTS privileged_helper_audit (
                    id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    target TEXT NOT NULL DEFAULT '',
                    requester TEXT NOT NULL DEFAULT 'user_ui',
                    authorized INTEGER NOT NULL DEFAULT 0,
                    auth_mechanism TEXT NOT NULL DEFAULT 'denied',
                    dry_run INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_priv_audit_created ON privileged_helper_audit(created_at DESC);
                CREATE TABLE IF NOT EXISTS task_recovery_journal (
                    task_id TEXT PRIMARY KEY,
                    objective TEXT NOT NULL,
                    permissions_json TEXT NOT NULL DEFAULT '{}',
                    execution_plan_json TEXT NOT NULL DEFAULT '[]',
                    current_step INTEGER NOT NULL DEFAULT 0,
                    completed_steps_json TEXT NOT NULL DEFAULT '[]',
                    actual_results_json TEXT NOT NULL DEFAULT '[]',
                    pending_steps_json TEXT NOT NULL DEFAULT '[]',
                    dependencies_json TEXT NOT NULL DEFAULT '[]',
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    last_checkpoint_json TEXT NOT NULL DEFAULT '{}',
                    required_resources_json TEXT NOT NULL DEFAULT '{}',
                    working_directory TEXT NOT NULL DEFAULT '',
                    expected_outputs_json TEXT NOT NULL DEFAULT '[]',
                    verification_status TEXT NOT NULL DEFAULT 'pending',
                    cancellation_state TEXT NOT NULL DEFAULT 'none',
                    last_known_blocker TEXT NOT NULL DEFAULT '',
                    active_before_shutdown INTEGER NOT NULL DEFAULT 0,
                    detached_background INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_recovery_active ON task_recovery_journal(active_before_shutdown, updated_at DESC);
                CREATE TABLE IF NOT EXISTS operation_idempotency (
                    idempotency_key TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    step_index INTEGER NOT NULL DEFAULT 0,
                    operation_kind TEXT NOT NULL,
                    repeatable INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL DEFAULT 'started',
                    expected_effect_json TEXT NOT NULL DEFAULT '{}',
                    observed_result_json TEXT NOT NULL DEFAULT '{}',
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS screen_recordings (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    capture_mode TEXT NOT NULL,
                    session_type TEXT NOT NULL,
                    backend TEXT NOT NULL,
                    output_format TEXT NOT NULL DEFAULT 'avi',
                    fps INTEGER NOT NULL DEFAULT 5,
                    resolution TEXT NOT NULL DEFAULT '640x360',
                    quality TEXT NOT NULL DEFAULT 'balanced',
                    max_size_mb INTEGER NOT NULL DEFAULT 250,
                    audio_source TEXT NOT NULL DEFAULT 'none',
                    mic_enabled INTEGER NOT NULL DEFAULT 0,
                    task_id TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    interruption_reason TEXT NOT NULL DEFAULT '',
                    output_path TEXT NOT NULL DEFAULT '',
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    duration_seconds REAL NOT NULL DEFAULT 0,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    started_at TEXT NOT NULL,
                    ended_at TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_recordings_started ON screen_recordings(started_at DESC);
                CREATE TABLE IF NOT EXISTS recording_segments (
                    id TEXT PRIMARY KEY,
                    recording_id TEXT NOT NULL REFERENCES screen_recordings(id) ON DELETE CASCADE,
                    segment_index INTEGER NOT NULL,
                    file_path TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    frame_count INTEGER NOT NULL DEFAULT 0,
                    duration_seconds REAL NOT NULL DEFAULT 0,
                    finalized INTEGER NOT NULL DEFAULT 0,
                    sha256 TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    UNIQUE(recording_id, segment_index)
                );
                CREATE TABLE IF NOT EXISTS observability_alerts (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    comparator TEXT NOT NULL,
                    threshold REAL NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_triggered_at TEXT NOT NULL DEFAULT '',
                    action_workflow TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS registered_servers (
                    id TEXT PRIMARY KEY,
                    alias TEXT NOT NULL UNIQUE,
                    hostname TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 22,
                    username TEXT NOT NULL,
                    purpose TEXT NOT NULL DEFAULT '',
                    auth_method TEXT NOT NULL DEFAULT 'ssh_key',
                    key_path TEXT NOT NULL DEFAULT '',
                    known_hosts_path TEXT NOT NULL DEFAULT '',
                    host_key_fingerprint TEXT NOT NULL DEFAULT '',
                    host_key_status TEXT NOT NULL DEFAULT 'unverified',
                    granted_permissions_json TEXT NOT NULL DEFAULT '[]',
                    authorized_operations_json TEXT NOT NULL DEFAULT '[]',
                    connection_health TEXT NOT NULL DEFAULT 'unknown',
                    last_connected_at TEXT NOT NULL DEFAULT '',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS remote_task_runs (
                    id TEXT PRIMARY KEY,
                    server_id TEXT NOT NULL REFERENCES registered_servers(id) ON DELETE CASCADE,
                    operation TEXT NOT NULL,
                    command_summary TEXT NOT NULL,
                    dry_run INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    exit_code INTEGER,
                    output_excerpt TEXT NOT NULL DEFAULT '',
                    error_excerpt TEXT NOT NULL DEFAULT '',
                    duration_ms REAL NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_remote_runs_server ON remote_task_runs(server_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS infrastructure_knowledge (
                    id TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    content TEXT NOT NULL,
                    source TEXT NOT NULL,
                    target_ref TEXT NOT NULL DEFAULT '',
                    ttl_seconds INTEGER NOT NULL DEFAULT 3600,
                    observed_at TEXT NOT NULL,
                    revalidated_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_infra_knowledge_cat ON infrastructure_knowledge(category, updated_at DESC);
                CREATE TABLE IF NOT EXISTS remote_nodes (
                    node_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    endpoint TEXT NOT NULL DEFAULT '',
                    pairing_key_id TEXT NOT NULL DEFAULT '',
                    capabilities_json TEXT NOT NULL DEFAULT '[]',
                    allowed_operations_json TEXT NOT NULL DEFAULT '[]',
                    resources_json TEXT NOT NULL DEFAULT '{}',
                    software_version TEXT NOT NULL DEFAULT '0.2.0',
                    connection_state TEXT NOT NULL DEFAULT 'paired_offline',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_seen_at TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS startup_recovery_policy (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    policy_json TEXT NOT NULL DEFAULT '{}',
                    safe_recovery_mode INTEGER NOT NULL DEFAULT 0,
                    last_unclean_shutdown_reason TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS privacy_network_config (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    tor_enabled INTEGER NOT NULL DEFAULT 0,
                    socks_host TEXT NOT NULL DEFAULT '127.0.0.1',
                    socks_port INTEGER NOT NULL DEFAULT 9050,
                    control_port INTEGER NOT NULL DEFAULT 9051,
                    tor_browser_path TEXT NOT NULL DEFAULT '',
                    onion_hosting_enabled INTEGER NOT NULL DEFAULT 0,
                    component_routing_json TEXT NOT NULL DEFAULT '{}',
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS onion_bookmarks (
                    id TEXT PRIMARY KEY,
                    onion_address TEXT NOT NULL UNIQUE,
                    title TEXT NOT NULL DEFAULT '',
                    source_obtained_from TEXT NOT NULL DEFAULT '',
                    official_reference_url TEXT NOT NULL DEFAULT '',
                    trust_status TEXT NOT NULL DEFAULT 'unverified',
                    reachability_status TEXT NOT NULL DEFAULT 'unchecked',
                    last_http_status INTEGER,
                    last_accessed_at TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_onion_bookmarks_updated ON onion_bookmarks(updated_at DESC);
                CREATE TABLE IF NOT EXISTS internet_search_runs (
                    id TEXT PRIMARY KEY,
                    query TEXT NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'unified_search',
                    sources_consulted_json TEXT NOT NULL DEFAULT '[]',
                    sources_skipped_json TEXT NOT NULL DEFAULT '[]',
                    query_limitations_json TEXT NOT NULL DEFAULT '[]',
                    retrieval_errors_json TEXT NOT NULL DEFAULT '[]',
                    result_count INTEGER NOT NULL DEFAULT 0,
                    report_id TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_search_runs_created ON internet_search_runs(created_at DESC);
                CREATE TABLE IF NOT EXISTS threat_intel_findings (
                    id TEXT PRIMARY KEY,
                    finding_kind TEXT NOT NULL,
                    source_classification TEXT NOT NULL,
                    confidence_tier TEXT NOT NULL DEFAULT 'claim',
                    severity TEXT NOT NULL DEFAULT 'info',
                    asset_scope TEXT NOT NULL DEFAULT '',
                    indicators_json TEXT NOT NULL DEFAULT '{}',
                    summary TEXT NOT NULL,
                    remediation TEXT NOT NULL DEFAULT '',
                    source_refs_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_threat_findings_created ON threat_intel_findings(created_at DESC);
                CREATE TABLE IF NOT EXISTS quarantined_downloads (
                    id TEXT PRIMARY KEY,
                    source_url TEXT NOT NULL,
                    via_network TEXT NOT NULL DEFAULT 'clearnet',
                    original_filename TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    extracted_dir TEXT NOT NULL DEFAULT '',
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    sha256 TEXT NOT NULL,
                    sha512 TEXT NOT NULL DEFAULT '',
                    detected_mime TEXT NOT NULL DEFAULT 'application/octet-stream',
                    signature_status TEXT NOT NULL DEFAULT 'not_provided',
                    clamav_status TEXT NOT NULL DEFAULT 'not_scanned',
                    static_analysis_json TEXT NOT NULL DEFAULT '{}',
                    duplicate_of_id TEXT NOT NULL DEFAULT '',
                    auto_executed INTEGER NOT NULL DEFAULT 0,
                    provenance_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_quarantined_sha ON quarantined_downloads(sha256);
                CREATE TABLE IF NOT EXISTS onion_hosting_plans (
                    id TEXT PRIMARY KEY,
                    service_name TEXT NOT NULL UNIQUE,
                    local_bind_host TEXT NOT NULL DEFAULT '127.0.0.1',
                    local_bind_port INTEGER NOT NULL,
                    virtual_port INTEGER NOT NULL DEFAULT 80,
                    enabled INTEGER NOT NULL DEFAULT 0,
                    key_vault_ref TEXT NOT NULL DEFAULT '',
                    torrc_snippet TEXT NOT NULL DEFAULT '',
                    deployment_plan_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS research_monitors (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    topic_or_query TEXT NOT NULL,
                    allowed_sources_json TEXT NOT NULL DEFAULT '[]',
                    asset_targets_json TEXT NOT NULL DEFAULT '[]',
                    interval_seconds INTEGER NOT NULL DEFAULT 3600,
                    rate_limit_per_hour INTEGER NOT NULL DEFAULT 6,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    checkpoint_hash TEXT NOT NULL DEFAULT '',
                    last_run_at TEXT NOT NULL DEFAULT '',
                    last_success_at TEXT NOT NULL DEFAULT '',
                    last_summary TEXT NOT NULL DEFAULT '',
                    alert_condition TEXT NOT NULL DEFAULT 'any_change',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_research_monitors_enabled ON research_monitors(enabled, updated_at DESC);
                CREATE TABLE IF NOT EXISTS dynamic_provider_specs (
                    provider_type TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    default_base_url TEXT NOT NULL,
                    default_key_env TEXT NOT NULL DEFAULT '',
                    adapter_family TEXT NOT NULL DEFAULT 'openai_compatible',
                    official_host TEXT NOT NULL DEFAULT '',
                    local_only INTEGER NOT NULL DEFAULT 0,
                    supports_streaming INTEGER NOT NULL DEFAULT 1,
                    supports_structured_outputs INTEGER NOT NULL DEFAULT 1,
                    supports_tools INTEGER NOT NULL DEFAULT 1,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS provider_privacy_policies (
                    provider_type TEXT PRIMARY KEY,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    max_payload_chars INTEGER NOT NULL DEFAULT 24000,
                    allow_diagnostic_context INTEGER NOT NULL DEFAULT 1,
                    allow_file_excerpts INTEGER NOT NULL DEFAULT 1,
                    require_sensitive_transfer_approval INTEGER NOT NULL DEFAULT 1,
                    allowed_categories_json TEXT NOT NULL DEFAULT '["prompt","diagnostics","workspace_excerpt"]',
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS local_only_projects (
                    project_key TEXT PRIMARY KEY,
                    project_path TEXT NOT NULL,
                    local_only INTEGER NOT NULL DEFAULT 1,
                    allow_quantized_local_fallback INTEGER NOT NULL DEFAULT 1,
                    reason TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cloud_transmission_ledger (
                    id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL DEFAULT '',
                    provider_type TEXT NOT NULL,
                    model_id TEXT NOT NULL DEFAULT '',
                    endpoint_host TEXT NOT NULL DEFAULT '',
                    decision TEXT NOT NULL,
                    payload_chars INTEGER NOT NULL DEFAULT 0,
                    redacted_items_count INTEGER NOT NULL DEFAULT 0,
                    included_files_json TEXT NOT NULL DEFAULT '[]',
                    included_categories_json TEXT NOT NULL DEFAULT '[]',
                    reason TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cloud_transmission_ledger_time ON cloud_transmission_ledger(created_at DESC);
                CREATE TABLE IF NOT EXISTS offline_cloud_queue (
                    id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL DEFAULT '',
                    goal TEXT NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'balanced',
                    messages_json TEXT NOT NULL DEFAULT '[]',
                    requested_model_ids_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'queued_waiting_cloud',
                    checkpoint_id TEXT NOT NULL DEFAULT '',
                    idempotency_key TEXT NOT NULL DEFAULT '',
                    local_fallback_allowed INTEGER NOT NULL DEFAULT 0,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT '',
                    result_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_offline_cloud_queue_status ON offline_cloud_queue(status, created_at ASC);
                CREATE TABLE IF NOT EXISTS kali_system_snapshots (
                    id TEXT PRIMARY KEY,
                    distro_id TEXT NOT NULL DEFAULT '',
                    distro_version TEXT NOT NULL DEFAULT '',
                    kernel_release TEXT NOT NULL DEFAULT '',
                    architecture TEXT NOT NULL DEFAULT '',
                    dpkg_fingerprint TEXT NOT NULL DEFAULT '',
                    snapshot_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_kali_system_snapshots_time ON kali_system_snapshots(created_at DESC);
                CREATE TABLE IF NOT EXISTS kali_tool_profiles (
                    tool_key TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    command_name TEXT NOT NULL DEFAULT '',
                    package_name TEXT NOT NULL DEFAULT '',
                    category TEXT NOT NULL DEFAULT '',
                    installation_status TEXT NOT NULL DEFAULT 'unavailable',
                    executable_path TEXT NOT NULL DEFAULT '',
                    version TEXT NOT NULL DEFAULT '',
                    integration_method TEXT NOT NULL DEFAULT 'documented_cli',
                    tested_compatibility INTEGER NOT NULL DEFAULT 0,
                    profile_json TEXT NOT NULL DEFAULT '{}',
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_kali_tool_profiles_cat ON kali_tool_profiles(category, installation_status);
                CREATE TABLE IF NOT EXISTS kali_knowledge_documents (
                    doc_key TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    tool_or_topic TEXT NOT NULL DEFAULT '',
                    priority_tier INTEGER NOT NULL DEFAULT 1,
                    source_kind TEXT NOT NULL DEFAULT 'local_man_or_help',
                    source_ref TEXT NOT NULL DEFAULT '',
                    reliability TEXT NOT NULL DEFAULT 'official_verified',
                    version_context TEXT NOT NULL DEFAULT '',
                    license_note TEXT NOT NULL DEFAULT '',
                    content_sha256 TEXT NOT NULL DEFAULT '',
                    content_excerpt TEXT NOT NULL DEFAULT '',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    retrieved_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_kali_knowledge_topic ON kali_knowledge_documents(tool_or_topic, priority_tier ASC);
                CREATE TABLE IF NOT EXISTS kali_cyber_labs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    runtime_kind TEXT NOT NULL DEFAULT 'isolated_local_sandbox',
                    network_scope TEXT NOT NULL DEFAULT '127.0.0.1/32',
                    isolated INTEGER NOT NULL DEFAULT 1,
                    authorized_scope TEXT NOT NULL DEFAULT 'local_owned_lab',
                    status TEXT NOT NULL DEFAULT 'stopped',
                    resources_json TEXT NOT NULL DEFAULT '{}',
                    snapshots_json TEXT NOT NULL DEFAULT '[]',
                    datasets_json TEXT NOT NULL DEFAULT '[]',
                    progress_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS kali_training_progress (
                    topic_id TEXT PRIMARY KEY,
                    track TEXT NOT NULL,
                    level TEXT NOT NULL DEFAULT 'beginner',
                    completed INTEGER NOT NULL DEFAULT 0,
                    quiz_score REAL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    flashcards_json TEXT NOT NULL DEFAULT '[]',
                    notes_json TEXT NOT NULL DEFAULT '{}',
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS kali_expertise_revisions (
                    id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'candidate',
                    verified_runs INTEGER NOT NULL DEFAULT 0,
                    failed_runs INTEGER NOT NULL DEFAULT 0,
                    proposal_json TEXT NOT NULL DEFAULT '{}',
                    test_result_json TEXT NOT NULL DEFAULT '{}',
                    rollback_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_kali_expertise_domain ON kali_expertise_revisions(domain, status, updated_at DESC);
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

    # ------------------------------------------------------------ cognition
    # Persistence for the mechanisms in nova.cognition. Everything here is
    # additive: the tables are created by initialize() and each writer accepts
    # the dataclass-shaped dict produced by the cognition modules, so the
    # reasoning layer stays free of any database dependency and remains testable
    # on its own.

    def save_observation(self, record: dict[str, Any]) -> str:
        """Store one world-model observation. Superseding happens on read."""
        observation_id = str(record.get("id") or uuid.uuid4())
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cognition_observations (id, scope, subject, predicate, value, source, "
                "observed_at, ttl_seconds, task_id, evidence_ref) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    observation_id,
                    str(record.get("scope") or "default"),
                    str(record.get("subject") or ""),
                    str(record.get("predicate") or ""),
                    str(record.get("value") or ""),
                    str(record.get("source") or "model_generated"),
                    str(record.get("observed_at") or utc_now()),
                    record.get("ttl_seconds"),
                    str(record.get("task_id") or ""),
                    str(record.get("evidence_ref") or ""),
                ),
            )
        return observation_id

    def list_observations(
        self, scope: str = "default", subject: str = "", limit: int = 200, include_history: bool = False
    ) -> list[dict[str, Any]]:
        """Most recent value per (subject, predicate), or the full history."""
        query = "SELECT * FROM cognition_observations WHERE scope = ?"
        params: list[Any] = [scope]
        if subject:
            query += " AND subject = ?"
            params.append(subject)
        if not include_history:
            query += (
                " AND observed_at = (SELECT MAX(o2.observed_at) FROM cognition_observations o2 "
                "WHERE o2.scope = cognition_observations.scope AND o2.subject = cognition_observations.subject "
                "AND o2.predicate = cognition_observations.predicate)"
            )
        query += " ORDER BY observed_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 2000)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._observation_row(row) for row in rows]

    @staticmethod
    def _observation_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["stale"] = _observation_is_stale(item)
        return item

    def save_prediction(self, record: dict[str, Any]) -> str:
        prediction_id = str(record.get("id") or uuid.uuid4())
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cognition_predictions (id, scope, action, expected_json, task_id, created_at, "
                "resolved, resolved_at, agreement, matched_json, contradicted_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    prediction_id,
                    str(record.get("scope") or "default"),
                    str(record.get("action") or ""),
                    _dump(record.get("expected") or {}),
                    str(record.get("task_id") or ""),
                    str(record.get("created_at") or utc_now()),
                    int(bool(record.get("resolved"))),
                    str(record.get("resolved_at") or ""),
                    record.get("agreement"),
                    _dump(record.get("matched") or []),
                    _dump(record.get("contradicted") or []),
                ),
            )
        return prediction_id

    def list_predictions(self, scope: str = "default", resolved: bool | None = None, limit: int = 100) -> list[dict[str, Any]]:
        query = "SELECT * FROM cognition_predictions WHERE scope = ?"
        params: list[Any] = [scope]
        if resolved is not None:
            query += " AND resolved = ?"
            params.append(int(resolved))
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 1000)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._prediction_row(row) for row in rows]

    @staticmethod
    def _prediction_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["expected"] = json.loads(item.pop("expected_json") or "{}")
        item["matched"] = json.loads(item.pop("matched_json") or "[]")
        item["contradicted"] = json.loads(item.pop("contradicted_json") or "[]")
        item["resolved"] = bool(item["resolved"])
        return item

    def upsert_procedure(self, record: dict[str, Any]) -> str:
        procedure_id = str(record.get("id") or uuid.uuid4())
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO cognition_procedures (id, name, domain, summary, steps_json, preconditions_json, "
                "environment_json, tools_required_json, tags_json, source_task_ids_json, evidence_refs_json, "
                "provenance, status, version, attempts, successes, supersedes, superseded_by, correction_reason, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET name=excluded.name, domain=excluded.domain, summary=excluded.summary, "
                "steps_json=excluded.steps_json, preconditions_json=excluded.preconditions_json, "
                "environment_json=excluded.environment_json, tools_required_json=excluded.tools_required_json, "
                "tags_json=excluded.tags_json, source_task_ids_json=excluded.source_task_ids_json, "
                "evidence_refs_json=excluded.evidence_refs_json, provenance=excluded.provenance, "
                "status=excluded.status, version=excluded.version, attempts=excluded.attempts, "
                "successes=excluded.successes, supersedes=excluded.supersedes, superseded_by=excluded.superseded_by, "
                "correction_reason=excluded.correction_reason, updated_at=excluded.updated_at",
                (
                    procedure_id,
                    str(record.get("name") or procedure_id)[:200],
                    str(record.get("domain") or "")[:80],
                    str(record.get("summary") or "")[:600],
                    _dump(record.get("steps") or []),
                    _dump(record.get("preconditions") or []),
                    _dump(record.get("environment") or {}),
                    _dump(record.get("tools_required") or []),
                    _dump(record.get("tags") or []),
                    _dump(record.get("source_task_ids") or []),
                    _dump(record.get("evidence_refs") or []),
                    str(record.get("provenance") or "tool_result"),
                    str(record.get("status") or "candidate"),
                    int(record.get("version") or 1),
                    int(record.get("attempts") or 0),
                    int(record.get("successes") or 0),
                    record.get("supersedes"),
                    record.get("superseded_by"),
                    str(record.get("correction_reason") or "")[:500],
                    str(record.get("created_at") or now),
                    str(record.get("updated_at") or now),
                ),
            )
        return procedure_id

    def list_procedures(self, status: str = "", limit: int = 200) -> list[dict[str, Any]]:
        query = "SELECT * FROM cognition_procedures"
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY successes DESC, updated_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 1000)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._procedure_row(row) for row in rows]

    def get_procedure(self, procedure_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM cognition_procedures WHERE id = ?", (procedure_id,)).fetchone()
        return self._procedure_row(row) if row else None

    def delete_procedure(self, procedure_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM cognition_procedures WHERE id = ?", (procedure_id,))
            return cursor.rowcount > 0

    @staticmethod
    def _procedure_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        for key in ("steps", "preconditions", "tools_required", "tags", "source_task_ids", "evidence_refs"):
            item[key] = json.loads(item.pop(f"{key}_json") or "[]")
        item["environment"] = json.loads(item.pop("environment_json") or "{}")
        attempts = int(item.get("attempts") or 0)
        successes = int(item.get("successes") or 0)
        item["success_ratio"] = round(successes / attempts, 4) if attempts else 0.0
        return item

    def add_calibration_record(
        self, confidence: float, outcome: bool, *, statement: str = "", domain: str = "", task_id: str = ""
    ) -> str:
        record_id = str(uuid.uuid4())
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO cognition_calibration (id, confidence, outcome, statement, domain, task_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    record_id,
                    float(max(0.0, min(1.0, confidence))),
                    int(bool(outcome)),
                    str(statement)[:500],
                    str(domain)[:80],
                    str(task_id)[:64],
                    utc_now(),
                ),
            )
        return record_id

    def list_calibration_records(self, domain: str = "", limit: int = 500) -> list[dict[str, Any]]:
        query = "SELECT * FROM cognition_calibration"
        params: list[Any] = []
        if domain:
            query += " WHERE domain = ?"
            params.append(domain)
        query += " ORDER BY created_at ASC LIMIT ?"
        params.append(max(1, min(int(limit), 5000)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [{**dict(row), "outcome": bool(row["outcome"])} for row in rows]

    def save_review(self, task_id: str, phase: str, payload: dict[str, Any]) -> str:
        review_id = str(uuid.uuid4())
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO cognition_reviews (id, task_id, phase, payload_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (review_id, str(task_id), str(phase), _dump(payload), utc_now()),
            )
        return review_id

    def get_reviews(self, task_id: str, phase: str = "") -> list[dict[str, Any]]:
        query = "SELECT * FROM cognition_reviews WHERE task_id = ?"
        params: list[Any] = [task_id]
        if phase:
            query += " AND phase = ?"
            params.append(phase)
        query += " ORDER BY created_at ASC LIMIT 200"
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [{**dict(row), "payload": json.loads(row["payload_json"] or "{}")} for row in rows]

    def save_decision(self, record: dict[str, Any]) -> str:
        decision_id = str(record.get("id") or uuid.uuid4())
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO cognition_decisions (id, task_id, objective, chosen_option_id, short_circuited, "
                "risk_tolerance, predicted_confidence, predicted_outcome, actual_outcome, prediction_matched, "
                "payload_json, created_at, resolved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    decision_id,
                    str(record.get("task_id") or "")[:64],
                    str(record.get("objective") or "")[:500],
                    record.get("chosen_option_id"),
                    int(bool(record.get("short_circuited"))),
                    str(record.get("risk_tolerance") or "routine"),
                    float(record.get("predicted_confidence") or 0.0),
                    str(record.get("predicted_outcome") or "")[:1000],
                    record.get("actual_outcome"),
                    None if record.get("prediction_matched") is None else int(bool(record["prediction_matched"])),
                    _dump(record.get("payload") or {}),
                    str(record.get("created_at") or utc_now()),
                    record.get("resolved_at"),
                ),
            )
        return decision_id

    def resolve_decision(self, decision_id: str, actual_outcome: str, prediction_matched: bool) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE cognition_decisions SET actual_outcome = ?, prediction_matched = ?, resolved_at = ? WHERE id = ?",
                (str(actual_outcome)[:1000], int(bool(prediction_matched)), utc_now(), decision_id),
            )
            return cursor.rowcount > 0

    def list_decisions(self, limit: int = 50, unresolved_only: bool = False) -> list[dict[str, Any]]:
        query = "SELECT * FROM cognition_decisions"
        if unresolved_only:
            query += " WHERE resolved_at IS NULL"
        query += " ORDER BY created_at DESC LIMIT ?"
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, (max(1, min(int(limit), 500)),)).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json") or "{}")
            item["short_circuited"] = bool(item["short_circuited"])
            item["prediction_matched"] = None if item["prediction_matched"] is None else bool(item["prediction_matched"])
            results.append(item)
        return results

    def create_intelligence_eval_run(
        self,
        suite_version: str,
        status: str,
        results: dict[str, Any],
        *,
        commit_ref: str = "",
        include_held_out: bool = False,
        pass_rate: float = 0.0,
        totals: dict[str, Any] | None = None,
        cases: dict[str, Any] | None = None,
        baseline_version: str | None = None,
        regressions: list[str] | None = None,
    ) -> str:
        run_id = str(uuid.uuid4())
        if totals is None:
            totals = results.get("totals", {})
        if cases is None:
            # A Report dict carries its per-case rows under "results". Persisting
            # an empty case map would make every later comparison vacuous - the
            # baseline would report "no regressions" while comparing nothing - so
            # derive the map instead of silently storing nothing.
            cases = {
                str(item.get("id")): {"status": item.get("status"), "capability": item.get("capability")}
                for item in (results.get("results") or [])
                if isinstance(item, dict) and item.get("id")
            }
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO intelligence_eval_runs (id, suite_version, commit_ref, include_held_out, status, "
                "pass_rate, totals_json, cases_json, baseline_version, regressions_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    str(suite_version)[:64],
                    str(commit_ref)[:64],
                    int(bool(include_held_out)),
                    str(status)[:32],
                    float(pass_rate),
                    _dump(totals),
                    _dump(cases),
                    baseline_version,
                    _dump(regressions or results.get("regressions", [])),
                    utc_now(),
                ),
            )
        return run_id

    def list_intelligence_eval_runs(self, suite_version: str = "", limit: int = 30) -> list[dict[str, Any]]:
        query = "SELECT * FROM intelligence_eval_runs"
        params: list[Any] = []
        if suite_version:
            query += " WHERE suite_version = ?"
            params.append(suite_version)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 200)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["totals"] = json.loads(item.pop("totals_json") or "{}")
            item["cases"] = json.loads(item.pop("cases_json") or "{}")
            item["regressions"] = json.loads(item.pop("regressions_json") or "[]")
            item["include_held_out"] = bool(item["include_held_out"])
            results.append(item)
        return results

    def get_latest_intelligence_baseline(self, suite_version: str) -> dict[str, Any] | None:
        """The most recent non-held-out run of a suite version, usable as a baseline."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM intelligence_eval_runs WHERE suite_version = ? AND include_held_out = 0 "
                "ORDER BY created_at DESC LIMIT 1",
                (suite_version,),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        return {
            "suite_version": item["suite_version"],
            "generated_at": item["created_at"],
            "commit": item["commit_ref"],
            "include_held_out": False,
            "pass_rate": item["pass_rate"],
            "totals": json.loads(item["totals_json"] or "{}"),
            "cases": json.loads(item["cases_json"] or "{}"),
        }

    def cognition_stats(self) -> dict[str, Any]:
        """Row counts for the cognition tables, for the health/setup endpoints."""
        tables = (
            "cognition_observations",
            "cognition_predictions",
            "cognition_procedures",
            "cognition_calibration",
            "cognition_reviews",
            "cognition_decisions",
            "intelligence_eval_runs",
        )
        counts: dict[str, int] = {}
        with self._lock, self._connect() as conn:
            for table in tables:
                try:
                    counts[table] = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                except sqlite3.Error:
                    counts[table] = 0
        return counts

    # ------------------------------------------------- Creation Engine (§116–§148)

    def save_creation_project(self, record: dict[str, Any]) -> str:
        project_id = str(record.get("id") or uuid.uuid4())
        now = utc_now()
        created_at = str(record.get("created_at") or now)
        updated_at = str(record.get("updated_at") or now)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO creation_projects (
                    id, slug, name, domain, artifact_type, objective, status, project_dir,
                    current_version, spec_json, toolchain_json, latest_report_json,
                    known_issues_json, license, archived, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    slug = excluded.slug,
                    name = excluded.name,
                    domain = excluded.domain,
                    artifact_type = excluded.artifact_type,
                    objective = excluded.objective,
                    status = excluded.status,
                    project_dir = excluded.project_dir,
                    current_version = excluded.current_version,
                    spec_json = excluded.spec_json,
                    toolchain_json = excluded.toolchain_json,
                    latest_report_json = excluded.latest_report_json,
                    known_issues_json = excluded.known_issues_json,
                    license = excluded.license,
                    archived = excluded.archived,
                    updated_at = excluded.updated_at
                """,
                (
                    project_id,
                    str(record.get("slug") or project_id)[:120],
                    str(record.get("name") or "Untitled Project")[:200],
                    str(record.get("domain") or "software")[:64],
                    str(record.get("artifact_type") or "software_project")[:64],
                    str(record.get("objective") or "")[:4000],
                    str(record.get("status") or "draft")[:32],
                    str(record.get("project_dir") or "")[:1000],
                    int(record.get("current_version") or 0),
                    _dump(record.get("spec") or {}),
                    _dump(record.get("toolchain") or {}),
                    _dump(record.get("latest_report") or {}),
                    _dump(record.get("known_issues") or []),
                    str(record.get("license") or "MIT")[:64],
                    int(bool(record.get("archived"))),
                    created_at,
                    updated_at,
                ),
            )
        return project_id

    @staticmethod
    def _unpack_creation_project(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["spec"] = json.loads(item.pop("spec_json") or "{}")
        item["toolchain"] = json.loads(item.pop("toolchain_json") or "{}")
        item["latest_report"] = json.loads(item.pop("latest_report_json") or "{}")
        item["known_issues"] = json.loads(item.pop("known_issues_json") or "[]")
        item["archived"] = bool(item["archived"])
        return item

    def get_creation_project(self, project_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM creation_projects WHERE id = ?", (project_id,)).fetchone()
        return self._unpack_creation_project(row) if row is not None else None

    def list_creation_projects(
        self,
        *,
        domain: str = "",
        include_archived: bool = False,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if not include_archived:
            clauses.append("archived = 0")
        if domain:
            clauses.append("domain = ?")
            params.append(domain)
        query = "SELECT * FROM creation_projects"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._unpack_creation_project(row) for row in rows]

    def delete_creation_project(self, project_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM creation_projects WHERE id = ?", (project_id,))
            conn.execute("DELETE FROM creation_assets WHERE project_id = ?", (project_id,))
            return cursor.rowcount > 0

    def save_creation_revision(self, record: dict[str, Any]) -> str:
        rev_id = str(record.get("id") or uuid.uuid4())
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO creation_revisions (
                    id, project_id, version, stage, summary, snapshot_dir,
                    artifacts_json, qa_json, quality_score, retained, size_bytes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    stage = excluded.stage,
                    summary = excluded.summary,
                    snapshot_dir = excluded.snapshot_dir,
                    artifacts_json = excluded.artifacts_json,
                    qa_json = excluded.qa_json,
                    quality_score = excluded.quality_score,
                    retained = excluded.retained,
                    size_bytes = excluded.size_bytes
                """,
                (
                    rev_id,
                    str(record["project_id"]),
                    int(record.get("version") or 1),
                    str(record.get("stage") or "build")[:64],
                    str(record.get("summary") or "")[:500],
                    str(record.get("snapshot_dir") or "")[:1000],
                    _dump(record.get("artifacts") or []),
                    _dump(record.get("qa") or {}),
                    float(record.get("quality_score") or 0.0),
                    int(bool(record.get("retained", True))),
                    int(record.get("size_bytes") or 0),
                    str(record.get("created_at") or utc_now()),
                ),
            )
        return rev_id

    def list_creation_revisions(self, project_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM creation_revisions WHERE project_id = ? ORDER BY version ASC, created_at ASC LIMIT ?",
                (project_id, max(1, min(int(limit), 500))),
            ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["artifacts"] = json.loads(item.pop("artifacts_json") or "[]")
            item["qa"] = json.loads(item.pop("qa_json") or "{}")
            item["retained"] = bool(item["retained"])
            results.append(item)
        return results

    def delete_creation_revision(self, rev_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM creation_revisions WHERE id = ?", (rev_id,))
            return cursor.rowcount > 0

    def save_creation_asset(self, record: dict[str, Any]) -> str:
        asset_id = str(record.get("id") or uuid.uuid4())
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO creation_assets (
                    id, project_id, filename, rel_path, media_type, sha256, size_bytes,
                    version, parent_asset_id, provenance, license, reusable,
                    tags_json, metadata_json, usage_notes, preview_rel_path, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    sha256 = excluded.sha256,
                    size_bytes = excluded.size_bytes,
                    version = excluded.version,
                    provenance = excluded.provenance,
                    license = excluded.license,
                    reusable = excluded.reusable,
                    tags_json = excluded.tags_json,
                    metadata_json = excluded.metadata_json,
                    usage_notes = excluded.usage_notes,
                    preview_rel_path = excluded.preview_rel_path,
                    updated_at = excluded.updated_at
                """,
                (
                    asset_id,
                    str(record.get("project_id") or "")[:64],
                    str(record.get("filename") or "")[:260],
                    str(record.get("rel_path") or "")[:600],
                    str(record.get("media_type") or "application/octet-stream")[:120],
                    str(record.get("sha256") or "")[:128],
                    int(record.get("size_bytes") or 0),
                    int(record.get("version") or 1),
                    str(record.get("parent_asset_id") or "")[:64],
                    str(record.get("provenance") or "procedural")[:64],
                    str(record.get("license") or "MIT")[:120],
                    int(bool(record.get("reusable", True))),
                    _dump(record.get("tags") or []),
                    _dump(record.get("metadata") or {}),
                    str(record.get("usage_notes") or "")[:1000],
                    str(record.get("preview_rel_path") or "")[:600],
                    str(record.get("created_at") or now),
                    now,
                ),
            )
        return asset_id

    def list_creation_assets(
        self,
        *,
        project_id: str = "",
        query: str = "",
        media_type: str = "",
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        if media_type:
            clauses.append("media_type LIKE ?")
            params.append(f"{media_type}%")
        if query:
            clauses.append("(LOWER(filename) LIKE ? OR LOWER(tags_json) LIKE ? OR LOWER(usage_notes) LIKE ?)")
            needle = f"%{query.lower()}%"
            params.extend([needle, needle, needle])
        sql = "SELECT * FROM creation_assets"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["tags"] = json.loads(item.pop("tags_json") or "[]")
            item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
            item["reusable"] = bool(item["reusable"])
            results.append(item)
        return results

    def save_creation_blueprint(self, record: dict[str, Any]) -> str:
        blueprint_id = str(record.get("id") or uuid.uuid4())
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO creation_blueprints (
                    id, name, version, domain, artifact_type, source_project_id,
                    objective, license, payload_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    version = excluded.version,
                    domain = excluded.domain,
                    artifact_type = excluded.artifact_type,
                    objective = excluded.objective,
                    license = excluded.license,
                    payload_json = excluded.payload_json,
                    updated_at = excluded.updated_at
                """,
                (
                    blueprint_id,
                    str(record.get("name") or "Blueprint")[:200],
                    str(record.get("version") or "1.0.0")[:32],
                    str(record.get("domain") or "software")[:64],
                    str(record.get("artifact_type") or "software_project")[:64],
                    str(record.get("source_project_id") or "")[:64],
                    str(record.get("objective") or "")[:2000],
                    str(record.get("license") or "MIT")[:64],
                    _dump(record.get("payload") or {}),
                    str(record.get("created_at") or now),
                    now,
                ),
            )
        return blueprint_id

    def get_creation_blueprint(self, blueprint_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM creation_blueprints WHERE id = ?", (blueprint_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json") or "{}")
        return item

    def list_creation_blueprints(self, *, domain: str = "", limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM creation_blueprints"
        params: list[Any] = []
        if domain:
            sql += " WHERE domain = ?"
            params.append(domain)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json") or "{}")
            results.append(item)
        return results

    def save_creation_run(self, record: dict[str, Any]) -> str:
        run_id = str(record.get("id") or uuid.uuid4())
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO creation_runs (id, project_id, kind, status, summary, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    str(record.get("project_id") or "")[:64],
                    str(record.get("kind") or "build")[:64],
                    str(record.get("status") or "completed")[:32],
                    str(record.get("summary") or "")[:1000],
                    _dump(record.get("payload") or {}),
                    str(record.get("created_at") or utc_now()),
                ),
            )
        return run_id

    def list_creation_runs(self, *, project_id: str = "", limit: int = 50) -> list[dict[str, Any]]:
        sql = "SELECT * FROM creation_runs"
        params: list[Any] = []
        if project_id:
            sql += " WHERE project_id = ?"
            params.append(project_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 200)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json") or "{}")
            results.append(item)
        return results

    def creation_stats(self) -> dict[str, int]:
        tables = (
            "creation_projects",
            "creation_revisions",
            "creation_assets",
            "creation_blueprints",
            "creation_runs",
        )
        counts: dict[str, int] = {}
        with self._lock, self._connect() as conn:
            for table in tables:
                try:
                    counts[table] = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                except sqlite3.Error:
                    counts[table] = 0
        return counts

    # ---------------- §14, §16 & §17 Unified Memory, Improvement & Worker CRUD

    def save_memory_entry(self, record: dict[str, Any]) -> dict[str, Any]:
        entry_id = str(record.get("id") or uuid.uuid4())
        now = utc_now()
        created = str(record.get("created_at") or now)
        updated = str(record.get("updated_at") or now)
        row_data = {
            "id": entry_id,
            "category": str(record["category"]).strip()[:64],
            "subject": str(record["subject"]).strip()[:200],
            "content": str(record["content"]).strip()[:16_000],
            "provenance": str(record.get("provenance") or "user_stated")[:48],
            "verified_fact": int(bool(record.get("verified_fact", False))),
            "source_ref": str(record.get("source_ref") or "")[:300],
            "project_id": str(record.get("project_id") or "")[:64],
            "metadata_json": _dump(record.get("metadata") or {}),
            "created_at": created,
            "updated_at": updated,
        }
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO memory_entries (
                    id, category, subject, content, provenance, verified_fact,
                    source_ref, project_id, metadata_json, created_at, updated_at
                ) VALUES (
                    :id, :category, :subject, :content, :provenance, :verified_fact,
                    :source_ref, :project_id, :metadata_json, :created_at, :updated_at
                )
                ON CONFLICT(id) DO UPDATE SET
                    category=excluded.category,
                    subject=excluded.subject,
                    content=excluded.content,
                    provenance=excluded.provenance,
                    verified_fact=excluded.verified_fact,
                    source_ref=excluded.source_ref,
                    project_id=excluded.project_id,
                    metadata_json=excluded.metadata_json,
                    updated_at=excluded.updated_at
                """,
                row_data,
            )
        return self.get_memory_entry(entry_id) or row_data

    def get_memory_entry(self, entry_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM memory_entries WHERE id = ?", (entry_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["verified_fact"] = bool(item["verified_fact"])
        item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
        return item

    def list_memory_entries(self, *, category: str = "", query: str = "", limit: int = 100) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if category:
            clauses.append("category = ?")
            params.append(category)
        if query:
            clauses.append("(LOWER(subject) LIKE ? OR LOWER(content) LIKE ?)")
            pat = f"%{query.lower()}%"
            params.extend([pat, pat])
        sql = "SELECT * FROM memory_entries"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["verified_fact"] = bool(item["verified_fact"])
            item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
            out.append(item)
        return out

    def delete_memory_entry(self, entry_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM memory_entries WHERE id = ?", (entry_id,))
            return cur.rowcount > 0

    def prune_memory_category(self, category: str, keep_limit: int) -> int:
        cap = max(1, int(keep_limit))
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT id FROM memory_entries WHERE category = ? ORDER BY updated_at DESC",
                (category,),
            ).fetchall()
            excess = [r["id"] for r in rows[cap:]]
            if not excess:
                return 0
            placeholders = ",".join("?" for _ in excess)
            cur = conn.execute(f"DELETE FROM memory_entries WHERE id IN ({placeholders})", excess)
            return int(cur.rowcount)

    def save_improvement_experiment(self, record: dict[str, Any]) -> dict[str, Any]:
        exp_id = str(record.get("id") or uuid.uuid4())
        now = utc_now()
        row_data = {
            "id": exp_id,
            "mechanism": str(record["mechanism"]).strip()[:64],
            "title": str(record["title"]).strip()[:180],
            "hypothesis": str(record["hypothesis"]).strip()[:2000],
            "status": str(record.get("status") or "evaluated")[:32],
            "safety_passed": int(bool(record.get("safety_passed", False))),
            "tests_passed": int(bool(record.get("tests_passed", False))),
            "baseline_score": float(record.get("baseline_score") or 0.0),
            "candidate_score": float(record.get("candidate_score") or 0.0),
            "applied": int(bool(record.get("applied", False))),
            "staging_dir": str(record.get("staging_dir") or "")[:500],
            "backup_dir": str(record.get("backup_dir") or "")[:500],
            "payload_json": _dump(record.get("payload") or {}),
            "created_at": str(record.get("created_at") or now),
            "updated_at": now,
        }
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO improvement_experiments (
                    id, mechanism, title, hypothesis, status, safety_passed, tests_passed,
                    baseline_score, candidate_score, applied, staging_dir, backup_dir,
                    payload_json, created_at, updated_at
                ) VALUES (
                    :id, :mechanism, :title, :hypothesis, :status, :safety_passed, :tests_passed,
                    :baseline_score, :candidate_score, :applied, :staging_dir, :backup_dir,
                    :payload_json, :created_at, :updated_at
                )
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    safety_passed=excluded.safety_passed,
                    tests_passed=excluded.tests_passed,
                    baseline_score=excluded.baseline_score,
                    candidate_score=excluded.candidate_score,
                    applied=excluded.applied,
                    backup_dir=excluded.backup_dir,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                row_data,
            )
        return self.get_improvement_experiment(exp_id) or row_data

    def get_improvement_experiment(self, exp_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM improvement_experiments WHERE id = ?", (exp_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["safety_passed"] = bool(item["safety_passed"])
        item["tests_passed"] = bool(item["tests_passed"])
        item["applied"] = bool(item["applied"])
        item["payload"] = json.loads(item.pop("payload_json") or "{}")
        return item

    def list_improvement_experiments(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM improvement_experiments ORDER BY updated_at DESC LIMIT ?",
                (max(1, min(int(limit), 200)),),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["safety_passed"] = bool(item["safety_passed"])
            item["tests_passed"] = bool(item["tests_passed"])
            item["applied"] = bool(item["applied"])
            item["payload"] = json.loads(item.pop("payload_json") or "{}")
            out.append(item)
        return out

    def upsert_worker_heartbeat(
        self,
        worker_id: str,
        *,
        pid: int,
        mode: str = "user_worker",
        status: str = "running",
        dispatched_count: int = 0,
        detail: str = "",
    ) -> dict[str, Any]:
        now = utc_now()
        with self._lock, self._connect() as conn:
            existing = conn.execute("SELECT started_at FROM worker_heartbeats WHERE worker_id = ?", (worker_id,)).fetchone()
            started = existing["started_at"] if existing else now
            conn.execute(
                """
                INSERT INTO worker_heartbeats (worker_id, pid, mode, status, dispatched_count, detail, started_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(worker_id) DO UPDATE SET
                    pid=excluded.pid,
                    mode=excluded.mode,
                    status=excluded.status,
                    dispatched_count=excluded.dispatched_count,
                    detail=excluded.detail,
                    updated_at=excluded.updated_at
                """,
                (worker_id[:64], int(pid), mode[:40], status[:32], int(dispatched_count), detail[:400], started, now),
            )
            row = conn.execute("SELECT * FROM worker_heartbeats WHERE worker_id = ?", (worker_id[:64],)).fetchone()
        return dict(row) if row else {}

    def list_worker_heartbeats(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM worker_heartbeats ORDER BY updated_at DESC").fetchall()
        return [dict(r) for r in rows]

    # ---------------- §149–§163 System Access, Resilience, Recording & Remote CRUD

    def save_driver_repair(self, record: dict[str, Any]) -> dict[str, Any]:
        rep_id = str(record.get("id") or f"drv-{uuid.uuid4().hex[:12]}")
        now = utc_now()
        row = {
            "id": rep_id,
            "device_id": str(record.get("device_id") or "")[:160],
            "device_class": str(record.get("device_class") or "other")[:64],
            "issue_summary": str(record.get("issue_summary") or "")[:500],
            "proposed_action": str(record.get("proposed_action") or "")[:500],
            "risk_level": str(record.get("risk_level") or "low")[:32],
            "recovery_path": str(record.get("recovery_path") or "")[:500],
            "applied": int(bool(record.get("applied", False))),
            "verified_functional": int(bool(record.get("verified_functional", False))),
            "status": str(record.get("status") or "proposed")[:48],
            "evidence_json": _dump(record.get("evidence") or {}),
            "created_at": str(record.get("created_at") or now),
            "updated_at": now,
        }
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO driver_repairs (
                    id, device_id, device_class, issue_summary, proposed_action, risk_level,
                    recovery_path, applied, verified_functional, status, evidence_json, created_at, updated_at
                ) VALUES (
                    :id, :device_id, :device_class, :issue_summary, :proposed_action, :risk_level,
                    :recovery_path, :applied, :verified_functional, :status, :evidence_json, :created_at, :updated_at
                )
                ON CONFLICT(id) DO UPDATE SET
                    applied=excluded.applied,
                    verified_functional=excluded.verified_functional,
                    status=excluded.status,
                    evidence_json=excluded.evidence_json,
                    updated_at=excluded.updated_at
                """,
                row,
            )
        return self.get_driver_repair(rep_id) or row

    def get_driver_repair(self, repair_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM driver_repairs WHERE id = ?", (repair_id,)).fetchone()
        if r is None:
            return None
        d = dict(r)
        d["applied"] = bool(d["applied"])
        d["verified_functional"] = bool(d["verified_functional"])
        d["evidence"] = json.loads(d.pop("evidence_json") or "{}")
        return d

    def list_driver_repairs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM driver_repairs ORDER BY created_at DESC LIMIT ?", (max(1, min(int(limit), 200)),)).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            d["applied"] = bool(d["applied"])
            d["verified_functional"] = bool(d["verified_functional"])
            d["evidence"] = json.loads(d.pop("evidence_json") or "{}")
            out.append(d)
        return out

    def upsert_privileged_policy(
        self,
        operation: str,
        scope_pattern: str = "*",
        *,
        enabled: bool = True,
        allow_without_prompt: bool = False,
        notes: str = "",
    ) -> dict[str, Any]:
        pol_id = f"ppol-{uuid.uuid4().hex[:12]}"
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO privileged_helper_policies (
                    id, operation, scope_pattern, enabled, allow_without_prompt, notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(operation, scope_pattern) DO UPDATE SET
                    enabled=excluded.enabled,
                    allow_without_prompt=excluded.allow_without_prompt,
                    notes=excluded.notes,
                    updated_at=excluded.updated_at
                """,
                (pol_id, operation[:80], scope_pattern[:160], int(bool(enabled)), int(bool(allow_without_prompt)), notes[:300], now, now),
            )
            row = conn.execute(
                "SELECT * FROM privileged_helper_policies WHERE operation = ? AND scope_pattern = ?",
                (operation[:80], scope_pattern[:160]),
            ).fetchone()
        d = dict(row) if row else {}
        if d:
            d["enabled"] = bool(d["enabled"])
            d["allow_without_prompt"] = bool(d["allow_without_prompt"])
        return d

    def list_privileged_policies(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM privileged_helper_policies ORDER BY operation, scope_pattern").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["enabled"] = bool(d["enabled"])
            d["allow_without_prompt"] = bool(d["allow_without_prompt"])
            out.append(d)
        return out

    def add_privileged_audit(self, entry: dict[str, Any]) -> dict[str, Any]:
        aud_id = str(entry.get("id") or f"paud-{uuid.uuid4().hex[:12]}")
        now = utc_now()
        row = (
            aud_id,
            str(entry.get("operation") or "")[:80],
            str(entry.get("target") or "")[:200],
            str(entry.get("requester") or "user_ui")[:64],
            int(bool(entry.get("authorized", False))),
            str(entry.get("auth_mechanism") or "denied")[:48],
            int(bool(entry.get("dry_run", False))),
            str(entry.get("status") or "rejected")[:40],
            str(entry.get("detail") or "")[:500],
            now,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO privileged_helper_audit (
                    id, operation, target, requester, authorized, auth_mechanism, dry_run, status, detail, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                row,
            )
            saved = conn.execute("SELECT * FROM privileged_helper_audit WHERE id = ?", (aud_id,)).fetchone()
        d = dict(saved) if saved else {}
        if d:
            d["authorized"] = bool(d["authorized"])
            d["dry_run"] = bool(d["dry_run"])
        return d

    def list_privileged_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM privileged_helper_audit ORDER BY created_at DESC LIMIT ?", (max(1, min(int(limit), 500)),)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["authorized"] = bool(d["authorized"])
            d["dry_run"] = bool(d["dry_run"])
            out.append(d)
        return out

    def upsert_task_journal(self, entry: dict[str, Any]) -> dict[str, Any]:
        tid = str(entry["task_id"])[:80]
        now = utc_now()
        row = {
            "task_id": tid,
            "objective": str(entry.get("objective") or "")[:4000],
            "permissions_json": _dump(entry.get("permissions") or {}),
            "execution_plan_json": _dump(entry.get("execution_plan") or []),
            "current_step": int(entry.get("current_step", 0)),
            "completed_steps_json": _dump(entry.get("completed_steps") or []),
            "actual_results_json": _dump(entry.get("actual_results") or []),
            "pending_steps_json": _dump(entry.get("pending_steps") or []),
            "dependencies_json": _dump(entry.get("dependencies") or []),
            "retry_count": int(entry.get("retry_count", 0)),
            "last_checkpoint_json": _dump(entry.get("last_checkpoint") or {}),
            "required_resources_json": _dump(entry.get("required_resources") or {}),
            "working_directory": str(entry.get("working_directory") or "")[:500],
            "expected_outputs_json": _dump(entry.get("expected_outputs") or []),
            "verification_status": str(entry.get("verification_status") or "pending")[:48],
            "cancellation_state": str(entry.get("cancellation_state") or "none")[:48],
            "last_known_blocker": str(entry.get("last_known_blocker") or "")[:500],
            "active_before_shutdown": int(bool(entry.get("active_before_shutdown", False))),
            "detached_background": int(bool(entry.get("detached_background", False))),
            "created_at": str(entry.get("created_at") or now),
            "updated_at": now,
        }
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO task_recovery_journal (
                    task_id, objective, permissions_json, execution_plan_json, current_step,
                    completed_steps_json, actual_results_json, pending_steps_json, dependencies_json,
                    retry_count, last_checkpoint_json, required_resources_json, working_directory,
                    expected_outputs_json, verification_status, cancellation_state, last_known_blocker,
                    active_before_shutdown, detached_background, created_at, updated_at
                ) VALUES (
                    :task_id, :objective, :permissions_json, :execution_plan_json, :current_step,
                    :completed_steps_json, :actual_results_json, :pending_steps_json, :dependencies_json,
                    :retry_count, :last_checkpoint_json, :required_resources_json, :working_directory,
                    :expected_outputs_json, :verification_status, :cancellation_state, :last_known_blocker,
                    :active_before_shutdown, :detached_background, :created_at, :updated_at
                )
                ON CONFLICT(task_id) DO UPDATE SET
                    objective=excluded.objective,
                    permissions_json=excluded.permissions_json,
                    execution_plan_json=excluded.execution_plan_json,
                    current_step=excluded.current_step,
                    completed_steps_json=excluded.completed_steps_json,
                    actual_results_json=excluded.actual_results_json,
                    pending_steps_json=excluded.pending_steps_json,
                    dependencies_json=excluded.dependencies_json,
                    retry_count=excluded.retry_count,
                    last_checkpoint_json=excluded.last_checkpoint_json,
                    required_resources_json=excluded.required_resources_json,
                    working_directory=excluded.working_directory,
                    expected_outputs_json=excluded.expected_outputs_json,
                    verification_status=excluded.verification_status,
                    cancellation_state=excluded.cancellation_state,
                    last_known_blocker=excluded.last_known_blocker,
                    active_before_shutdown=excluded.active_before_shutdown,
                    detached_background=excluded.detached_background,
                    updated_at=excluded.updated_at
                """,
                row,
            )
        return self.get_task_journal(tid) or {}

    @staticmethod
    def _unpack_journal_row(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["permissions"] = json.loads(d.pop("permissions_json") or "{}")
        d["execution_plan"] = json.loads(d.pop("execution_plan_json") or "[]")
        d["completed_steps"] = json.loads(d.pop("completed_steps_json") or "[]")
        d["actual_results"] = json.loads(d.pop("actual_results_json") or "[]")
        d["pending_steps"] = json.loads(d.pop("pending_steps_json") or "[]")
        d["dependencies"] = json.loads(d.pop("dependencies_json") or "[]")
        d["last_checkpoint"] = json.loads(d.pop("last_checkpoint_json") or "{}")
        d["required_resources"] = json.loads(d.pop("required_resources_json") or "{}")
        d["expected_outputs"] = json.loads(d.pop("expected_outputs_json") or "[]")
        d["active_before_shutdown"] = bool(d["active_before_shutdown"])
        d["detached_background"] = bool(d["detached_background"])
        return d

    def get_task_journal(self, task_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM task_recovery_journal WHERE task_id = ?", (task_id,)).fetchone()
        return self._unpack_journal_row(r) if r else None

    def list_task_journals(self, *, active_only: bool = False, limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM task_recovery_journal"
        if active_only:
            sql += " WHERE active_before_shutdown = 1"
        sql += " ORDER BY updated_at DESC LIMIT ?"
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, (max(1, min(int(limit), 500)),)).fetchall()
        return [self._unpack_journal_row(r) for r in rows]

    def upsert_operation_idempotency(self, record: dict[str, Any]) -> dict[str, Any]:
        ikey = str(record["idempotency_key"])[:160]
        now = utc_now()
        row = {
            "idempotency_key": ikey,
            "task_id": str(record.get("task_id") or "")[:80],
            "step_index": int(record.get("step_index", 0)),
            "operation_kind": str(record.get("operation_kind") or "generic")[:64],
            "repeatable": int(bool(record.get("repeatable", False))),
            "state": str(record.get("state") or "started")[:32],
            "expected_effect_json": _dump(record.get("expected_effect") or {}),
            "observed_result_json": _dump(record.get("observed_result") or {}),
            "started_at": str(record.get("started_at") or now),
            "completed_at": str(record.get("completed_at") or ""),
        }
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO operation_idempotency (
                    idempotency_key, task_id, step_index, operation_kind, repeatable,
                    state, expected_effect_json, observed_result_json, started_at, completed_at
                ) VALUES (
                    :idempotency_key, :task_id, :step_index, :operation_kind, :repeatable,
                    :state, :expected_effect_json, :observed_result_json, :started_at, :completed_at
                )
                ON CONFLICT(idempotency_key) DO UPDATE SET
                    state=excluded.state,
                    observed_result_json=excluded.observed_result_json,
                    completed_at=excluded.completed_at
                """,
                row,
            )
        return self.get_operation_idempotency(ikey) or {}

    def get_operation_idempotency(self, idempotency_key: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM operation_idempotency WHERE idempotency_key = ?", (idempotency_key,)).fetchone()
        if r is None:
            return None
        d = dict(r)
        d["repeatable"] = bool(d["repeatable"])
        d["expected_effect"] = json.loads(d.pop("expected_effect_json") or "{}")
        d["observed_result"] = json.loads(d.pop("observed_result_json") or "{}")
        return d

    def list_task_idempotency_records(self, task_id: str) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM operation_idempotency WHERE task_id = ? ORDER BY step_index ASC",
                (task_id,),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["repeatable"] = bool(d["repeatable"])
            d["expected_effect"] = json.loads(d.pop("expected_effect_json") or "{}")
            d["observed_result"] = json.loads(d.pop("observed_result_json") or "{}")
            out.append(d)
        return out

    def save_screen_recording(self, record: dict[str, Any]) -> dict[str, Any]:
        rec_id = str(record.get("id") or f"rec-{uuid.uuid4().hex[:12]}")
        now = utc_now()
        row = {
            "id": rec_id,
            "title": str(record.get("title") or "Screen Session")[:200],
            "capture_mode": str(record.get("capture_mode") or "full_display")[:40],
            "session_type": str(record.get("session_type") or "headless")[:32],
            "backend": str(record.get("backend") or "procedural_frames")[:64],
            "output_format": str(record.get("output_format") or "avi")[:16],
            "fps": max(1, min(int(record.get("fps", 5)), 60)),
            "resolution": str(record.get("resolution") or "640x360")[:32],
            "quality": str(record.get("quality") or "balanced")[:24],
            "max_size_mb": max(1, int(record.get("max_size_mb", 250))),
            "audio_source": str(record.get("audio_source") or "none")[:64],
            "mic_enabled": int(bool(record.get("mic_enabled", False))),
            "task_id": str(record.get("task_id") or "")[:80],
            "status": str(record.get("status") or "recording")[:32],
            "interruption_reason": str(record.get("interruption_reason") or "")[:300],
            "output_path": str(record.get("output_path") or "")[:500],
            "size_bytes": int(record.get("size_bytes", 0)),
            "duration_seconds": float(record.get("duration_seconds", 0.0)),
            "metadata_json": _dump(record.get("metadata") or {}),
            "started_at": str(record.get("started_at") or now),
            "ended_at": str(record.get("ended_at") or ""),
            "updated_at": now,
        }
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO screen_recordings (
                    id, title, capture_mode, session_type, backend, output_format, fps,
                    resolution, quality, max_size_mb, audio_source, mic_enabled, task_id,
                    status, interruption_reason, output_path, size_bytes, duration_seconds,
                    metadata_json, started_at, ended_at, updated_at
                ) VALUES (
                    :id, :title, :capture_mode, :session_type, :backend, :output_format, :fps,
                    :resolution, :quality, :max_size_mb, :audio_source, :mic_enabled, :task_id,
                    :status, :interruption_reason, :output_path, :size_bytes, :duration_seconds,
                    :metadata_json, :started_at, :ended_at, :updated_at
                )
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    interruption_reason=excluded.interruption_reason,
                    output_path=excluded.output_path,
                    size_bytes=excluded.size_bytes,
                    duration_seconds=excluded.duration_seconds,
                    metadata_json=excluded.metadata_json,
                    ended_at=excluded.ended_at,
                    updated_at=excluded.updated_at
                """,
                row,
            )
        return self.get_screen_recording(rec_id) or {}

    def get_screen_recording(self, rec_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM screen_recordings WHERE id = ?", (rec_id,)).fetchone()
            segs = conn.execute(
                "SELECT * FROM recording_segments WHERE recording_id = ? ORDER BY segment_index ASC",
                (rec_id,),
            ).fetchall()
        if r is None:
            return None
        d = dict(r)
        d["mic_enabled"] = bool(d["mic_enabled"])
        d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
        d["segments"] = [{**dict(s), "finalized": bool(s["finalized"])} for s in segs]
        return d

    def list_screen_recordings(self, *, query: str = "", limit: int = 50) -> list[dict[str, Any]]:
        sql = "SELECT id FROM screen_recordings"
        params: list[Any] = []
        if query:
            sql += " WHERE LOWER(title) LIKE ? OR LOWER(task_id) LIKE ? OR LOWER(interruption_reason) LIKE ?"
            pat = f"%{query.lower()}%"
            params.extend([pat, pat, pat])
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 200)))
        with self._lock, self._connect() as conn:
            ids = [r["id"] for r in conn.execute(sql, params).fetchall()]
        return [item for rid in ids if (item := self.get_screen_recording(rid)) is not None]

    def save_recording_segment(self, seg: dict[str, Any]) -> dict[str, Any]:
        seg_id = str(seg.get("id") or f"seg-{uuid.uuid4().hex[:12]}")
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO recording_segments (
                    id, recording_id, segment_index, file_path, size_bytes,
                    frame_count, duration_seconds, finalized, sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(recording_id, segment_index) DO UPDATE SET
                    file_path=excluded.file_path,
                    size_bytes=excluded.size_bytes,
                    frame_count=excluded.frame_count,
                    duration_seconds=excluded.duration_seconds,
                    finalized=excluded.finalized,
                    sha256=excluded.sha256
                """,
                (
                    seg_id,
                    str(seg["recording_id"]),
                    int(seg["segment_index"]),
                    str(seg["file_path"])[:500],
                    int(seg.get("size_bytes", 0)),
                    int(seg.get("frame_count", 0)),
                    float(seg.get("duration_seconds", 0.0)),
                    int(bool(seg.get("finalized", False))),
                    str(seg.get("sha256") or "")[:64],
                    now,
                ),
            )
            r = conn.execute(
                "SELECT * FROM recording_segments WHERE recording_id = ? AND segment_index = ?",
                (str(seg["recording_id"]), int(seg["segment_index"])),
            ).fetchone()
        return {**dict(r), "finalized": bool(r["finalized"])} if r else {}

    def save_observability_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        aid = str(alert.get("id") or f"alrt-{uuid.uuid4().hex[:10]}")
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO observability_alerts (
                    id, name, metric, comparator, threshold, enabled, last_triggered_at, action_workflow, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    metric=excluded.metric,
                    comparator=excluded.comparator,
                    threshold=excluded.threshold,
                    enabled=excluded.enabled,
                    last_triggered_at=excluded.last_triggered_at,
                    action_workflow=excluded.action_workflow,
                    updated_at=excluded.updated_at
                """,
                (
                    aid,
                    str(alert["name"])[:120],
                    str(alert["metric"])[:64],
                    str(alert.get("comparator") or ">=")[:8],
                    float(alert["threshold"]),
                    int(bool(alert.get("enabled", True))),
                    str(alert.get("last_triggered_at") or ""),
                    str(alert.get("action_workflow") or "")[:120],
                    now,
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM observability_alerts WHERE id = ?", (aid,)).fetchone()
        return {**dict(r), "enabled": bool(r["enabled"])} if r else {}

    def list_observability_alerts(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM observability_alerts ORDER BY created_at DESC").fetchall()
        return [{**dict(r), "enabled": bool(r["enabled"])} for r in rows]

    def save_registered_server(self, srv: dict[str, Any]) -> dict[str, Any]:
        sid = str(srv.get("id") or f"srv-{uuid.uuid4().hex[:12]}")
        now = utc_now()
        row = {
            "id": sid,
            "alias": str(srv["alias"]).strip()[:80],
            "hostname": str(srv["hostname"]).strip()[:255],
            "port": max(1, min(int(srv.get("port", 22)), 65535)),
            "username": str(srv["username"]).strip()[:80],
            "purpose": str(srv.get("purpose") or "")[:300],
            "auth_method": str(srv.get("auth_method") or "ssh_key")[:32],
            "key_path": str(srv.get("key_path") or "")[:500],
            "known_hosts_path": str(srv.get("known_hosts_path") or "")[:500],
            "host_key_fingerprint": str(srv.get("host_key_fingerprint") or "")[:200],
            "host_key_status": str(srv.get("host_key_status") or "unverified")[:40],
            "granted_permissions_json": _dump(srv.get("granted_permissions") or []),
            "authorized_operations_json": _dump(srv.get("authorized_operations") or []),
            "connection_health": str(srv.get("connection_health") or "unknown")[:40],
            "last_connected_at": str(srv.get("last_connected_at") or ""),
            "metadata_json": _dump(srv.get("metadata") or {}),
            "created_at": str(srv.get("created_at") or now),
            "updated_at": now,
        }
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO registered_servers (
                    id, alias, hostname, port, username, purpose, auth_method, key_path,
                    known_hosts_path, host_key_fingerprint, host_key_status,
                    granted_permissions_json, authorized_operations_json, connection_health,
                    last_connected_at, metadata_json, created_at, updated_at
                ) VALUES (
                    :id, :alias, :hostname, :port, :username, :purpose, :auth_method, :key_path,
                    :known_hosts_path, :host_key_fingerprint, :host_key_status,
                    :granted_permissions_json, :authorized_operations_json, :connection_health,
                    :last_connected_at, :metadata_json, :created_at, :updated_at
                )
                ON CONFLICT(alias) DO UPDATE SET
                    hostname=excluded.hostname,
                    port=excluded.port,
                    username=excluded.username,
                    purpose=excluded.purpose,
                    auth_method=excluded.auth_method,
                    key_path=excluded.key_path,
                    known_hosts_path=excluded.known_hosts_path,
                    host_key_fingerprint=excluded.host_key_fingerprint,
                    host_key_status=excluded.host_key_status,
                    granted_permissions_json=excluded.granted_permissions_json,
                    authorized_operations_json=excluded.authorized_operations_json,
                    connection_health=excluded.connection_health,
                    last_connected_at=excluded.last_connected_at,
                    metadata_json=excluded.metadata_json,
                    updated_at=excluded.updated_at
                """,
                row,
            )
        return self.get_registered_server_by_alias(row["alias"]) or {}

    @staticmethod
    def _unpack_server(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["granted_permissions"] = json.loads(d.pop("granted_permissions_json") or "[]")
        d["authorized_operations"] = json.loads(d.pop("authorized_operations_json") or "[]")
        d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
        return d

    def get_registered_server(self, server_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM registered_servers WHERE id = ?", (server_id,)).fetchone()
        return self._unpack_server(r) if r else None

    def get_registered_server_by_alias(self, alias: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM registered_servers WHERE alias = ?", (alias.strip(),)).fetchone()
        return self._unpack_server(r) if r else None

    def list_registered_servers(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM registered_servers ORDER BY alias ASC").fetchall()
        return [self._unpack_server(r) for r in rows]

    def delete_registered_server(self, alias_or_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM registered_servers WHERE id = ? OR alias = ?", (alias_or_id, alias_or_id))
            return cur.rowcount > 0

    def add_remote_task_run(self, run: dict[str, Any]) -> dict[str, Any]:
        rid = str(run.get("id") or f"rrun-{uuid.uuid4().hex[:12]}")
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO remote_task_runs (
                    id, server_id, operation, command_summary, dry_run, status,
                    exit_code, output_excerpt, error_excerpt, duration_ms, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rid,
                    str(run["server_id"]),
                    str(run["operation"])[:64],
                    str(run.get("command_summary") or "")[:300],
                    int(bool(run.get("dry_run", False))),
                    str(run["status"])[:32],
                    run.get("exit_code"),
                    str(run.get("output_excerpt") or "")[:4000],
                    str(run.get("error_excerpt") or "")[:2000],
                    float(run.get("duration_ms", 0.0)),
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM remote_task_runs WHERE id = ?", (rid,)).fetchone()
        return {**dict(r), "dry_run": bool(r["dry_run"])} if r else {}

    def list_remote_task_runs(self, server_id: str = "", limit: int = 50) -> list[dict[str, Any]]:
        sql = "SELECT * FROM remote_task_runs"
        params: list[Any] = []
        if server_id:
            sql += " WHERE server_id = ?"
            params.append(server_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 200)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [{**dict(r), "dry_run": bool(r["dry_run"])} for r in rows]

    def save_infrastructure_knowledge(self, item: dict[str, Any]) -> dict[str, Any]:
        kid = str(item.get("id") or f"ikb-{uuid.uuid4().hex[:12]}")
        now = utc_now()
        obs = str(item.get("observed_at") or now)
        rev = str(item.get("revalidated_at") or obs)
        row = {
            "id": kid,
            "category": str(item["category"])[:64],
            "subject": str(item["subject"])[:200],
            "content": str(item["content"])[:16_000],
            "source": str(item.get("source") or "system_probe")[:120],
            "target_ref": str(item.get("target_ref") or "")[:160],
            "ttl_seconds": max(60, int(item.get("ttl_seconds", 3600))),
            "observed_at": obs,
            "revalidated_at": rev,
            "metadata_json": _dump(item.get("metadata") or {}),
            "updated_at": now,
        }
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO infrastructure_knowledge (
                    id, category, subject, content, source, target_ref, ttl_seconds,
                    observed_at, revalidated_at, metadata_json, updated_at
                ) VALUES (
                    :id, :category, :subject, :content, :source, :target_ref, :ttl_seconds,
                    :observed_at, :revalidated_at, :metadata_json, :updated_at
                )
                ON CONFLICT(id) DO UPDATE SET
                    category=excluded.category,
                    subject=excluded.subject,
                    content=excluded.content,
                    source=excluded.source,
                    target_ref=excluded.target_ref,
                    ttl_seconds=excluded.ttl_seconds,
                    revalidated_at=excluded.revalidated_at,
                    metadata_json=excluded.metadata_json,
                    updated_at=excluded.updated_at
                """,
                row,
            )
        return self.get_infrastructure_knowledge(kid) or {}

    def get_infrastructure_knowledge(self, kid: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM infrastructure_knowledge WHERE id = ?", (kid,)).fetchone()
        if r is None:
            return None
        d = dict(r)
        d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
        return d

    def list_infrastructure_knowledge(self, *, category: str = "", query: str = "", limit: int = 100) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if category:
            clauses.append("category = ?")
            params.append(category)
        if query:
            clauses.append("(LOWER(subject) LIKE ? OR LOWER(content) LIKE ? OR LOWER(target_ref) LIKE ?)")
            pat = f"%{query.lower()}%"
            params.extend([pat, pat, pat])
        sql = "SELECT * FROM infrastructure_knowledge"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
            out.append(d)
        return out

    def delete_infrastructure_knowledge(self, kid: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM infrastructure_knowledge WHERE id = ?", (kid,))
            return cur.rowcount > 0

    def save_remote_node(self, node: dict[str, Any]) -> dict[str, Any]:
        nid = str(node.get("node_id") or f"node-{uuid.uuid4().hex[:10]}")[:80]
        now = utc_now()
        row = {
            "node_id": nid,
            "name": str(node["name"])[:120],
            "role": str(node.get("role") or "dev_server")[:48],
            "endpoint": str(node.get("endpoint") or "")[:255],
            "pairing_key_id": str(node.get("pairing_key_id") or "")[:80],
            "capabilities_json": _dump(node.get("capabilities") or []),
            "allowed_operations_json": _dump(node.get("allowed_operations") or []),
            "resources_json": _dump(node.get("resources") or {}),
            "software_version": str(node.get("software_version") or "0.2.0")[:32],
            "connection_state": str(node.get("connection_state") or "paired_offline")[:32],
            "enabled": int(bool(node.get("enabled", True))),
            "last_seen_at": str(node.get("last_seen_at") or ""),
            "created_at": str(node.get("created_at") or now),
            "updated_at": now,
        }
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO remote_nodes (
                    node_id, name, role, endpoint, pairing_key_id, capabilities_json,
                    allowed_operations_json, resources_json, software_version,
                    connection_state, enabled, last_seen_at, created_at, updated_at
                ) VALUES (
                    :node_id, :name, :role, :endpoint, :pairing_key_id, :capabilities_json,
                    :allowed_operations_json, :resources_json, :software_version,
                    :connection_state, :enabled, :last_seen_at, :created_at, :updated_at
                )
                ON CONFLICT(node_id) DO UPDATE SET
                    name=excluded.name,
                    role=excluded.role,
                    endpoint=excluded.endpoint,
                    pairing_key_id=excluded.pairing_key_id,
                    capabilities_json=excluded.capabilities_json,
                    allowed_operations_json=excluded.allowed_operations_json,
                    resources_json=excluded.resources_json,
                    software_version=excluded.software_version,
                    connection_state=excluded.connection_state,
                    enabled=excluded.enabled,
                    last_seen_at=excluded.last_seen_at,
                    updated_at=excluded.updated_at
                """,
                row,
            )
            r = conn.execute("SELECT * FROM remote_nodes WHERE node_id = ?", (nid,)).fetchone()
        return self._unpack_node(r) if r else {}

    @staticmethod
    def _unpack_node(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["capabilities"] = json.loads(d.pop("capabilities_json") or "[]")
        d["allowed_operations"] = json.loads(d.pop("allowed_operations_json") or "[]")
        d["resources"] = json.loads(d.pop("resources_json") or "{}")
        d["enabled"] = bool(d["enabled"])
        return d

    def get_remote_node(self, node_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM remote_nodes WHERE node_id = ?", (node_id,)).fetchone()
        return self._unpack_node(r) if r else None

    def list_remote_nodes(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM remote_nodes ORDER BY name ASC").fetchall()
        return [self._unpack_node(r) for r in rows]

    def get_startup_recovery_policy(self, defaults: dict[str, Any] | None = None) -> dict[str, Any]:
        now = utc_now()
        init_policy = defaults or {}
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO startup_recovery_policy (id, policy_json, safe_recovery_mode, last_unclean_shutdown_reason, updated_at) "
                "VALUES (1, ?, 0, '', ?)",
                (_dump(init_policy), now),
            )
            r = conn.execute("SELECT * FROM startup_recovery_policy WHERE id = 1").fetchone()
        saved = json.loads(r["policy_json"] or "{}") if r else {}
        merged = {**init_policy, **saved}
        return {
            "policy": merged,
            "safe_recovery_mode": bool(r["safe_recovery_mode"]) if r else False,
            "last_unclean_shutdown_reason": str(r["last_unclean_shutdown_reason"]) if r else "",
            "updated_at": str(r["updated_at"]) if r else now,
        }

    def quick_check(self) -> bool:
        with self._lock, self._connect() as conn:
            row = conn.execute("PRAGMA quick_check").fetchone()
        return bool(row and str(row[0]).lower() == "ok")

    def delete_privileged_policy(self, policy_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM privileged_helper_policies WHERE id = ?", (policy_id,))
            return cur.rowcount > 0

    def delete_remote_node(self, node_id_or_name: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM remote_nodes WHERE node_id = ? OR name = ?",
                (node_id_or_name, node_id_or_name),
            )
            return cur.rowcount > 0

    def list_recording_segments(self, recording_id: str) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM recording_segments WHERE recording_id = ? ORDER BY segment_index ASC",
                (recording_id,),
            ).fetchall()
        return [{**dict(r), "finalized": bool(r["finalized"])} for r in rows]

    def update_startup_recovery_policy(
        self,
        policy: dict[str, Any],
        *,
        safe_recovery_mode: bool | None = None,
        last_unclean_shutdown_reason: str | None = None,
    ) -> dict[str, Any]:
        current = self.get_startup_recovery_policy()
        next_safe = current["safe_recovery_mode"] if safe_recovery_mode is None else bool(safe_recovery_mode)
        next_reason = (
            current["last_unclean_shutdown_reason"]
            if last_unclean_shutdown_reason is None
            else str(last_unclean_shutdown_reason)[:300]
        )
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO startup_recovery_policy (id, policy_json, safe_recovery_mode, last_unclean_shutdown_reason, updated_at)
                VALUES (1, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    policy_json=excluded.policy_json,
                    safe_recovery_mode=excluded.safe_recovery_mode,
                    last_unclean_shutdown_reason=excluded.last_unclean_shutdown_reason,
                    updated_at=excluded.updated_at
                """,
                (_dump(policy), int(next_safe), next_reason, now),
            )
        return self.get_startup_recovery_policy()

    # ------------------------------------------------- §165 Privacy, Tor & OSINT

    def get_privacy_network_config(self, default_routing: dict[str, str] | None = None) -> dict[str, Any]:
        now = utc_now()
        init_routing = default_routing or {}
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO privacy_network_config (
                    id, tor_enabled, socks_host, socks_port, control_port,
                    tor_browser_path, onion_hosting_enabled, component_routing_json, updated_at
                ) VALUES (1, 0, '127.0.0.1', 9050, 9051, '', 0, ?, ?)
                """,
                (_dump(init_routing), now),
            )
            r = conn.execute("SELECT * FROM privacy_network_config WHERE id = 1").fetchone()
        if r is None:
            return {
                "tor_enabled": False,
                "socks_host": "127.0.0.1",
                "socks_port": 9050,
                "control_port": 9051,
                "tor_browser_path": "",
                "onion_hosting_enabled": False,
                "component_routing": dict(init_routing),
                "updated_at": now,
            }
        saved_routing = json.loads(r["component_routing_json"] or "{}")
        return {
            "tor_enabled": bool(r["tor_enabled"]),
            "socks_host": str(r["socks_host"]),
            "socks_port": int(r["socks_port"]),
            "control_port": int(r["control_port"]),
            "tor_browser_path": str(r["tor_browser_path"]),
            "onion_hosting_enabled": bool(r["onion_hosting_enabled"]),
            "component_routing": {**init_routing, **saved_routing},
            "updated_at": str(r["updated_at"]),
        }

    def update_privacy_network_config(self, updates: dict[str, Any], *, default_routing: dict[str, str] | None = None) -> dict[str, Any]:
        cur = self.get_privacy_network_config(default_routing=default_routing)
        next_routing = {**cur["component_routing"], **dict(updates.get("component_routing") or {})}
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE privacy_network_config SET
                    tor_enabled = ?,
                    socks_host = ?,
                    socks_port = ?,
                    control_port = ?,
                    tor_browser_path = ?,
                    onion_hosting_enabled = ?,
                    component_routing_json = ?,
                    updated_at = ?
                WHERE id = 1
                """,
                (
                    int(bool(updates.get("tor_enabled", cur["tor_enabled"]))),
                    str(updates.get("socks_host", cur["socks_host"]))[:255],
                    max(1, min(int(updates.get("socks_port", cur["socks_port"])), 65535)),
                    max(1, min(int(updates.get("control_port", cur["control_port"])), 65535)),
                    str(updates.get("tor_browser_path", cur["tor_browser_path"]))[:500],
                    int(bool(updates.get("onion_hosting_enabled", cur["onion_hosting_enabled"]))),
                    _dump(next_routing),
                    now,
                ),
            )
        return self.get_privacy_network_config(default_routing=default_routing)

    def save_onion_bookmark(self, item: dict[str, Any]) -> dict[str, Any]:
        bid = str(item.get("id") or f"onion-{uuid.uuid4().hex[:12]}")
        addr = str(item["onion_address"]).strip().lower()[:128]
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO onion_bookmarks (
                    id, onion_address, title, source_obtained_from, official_reference_url,
                    trust_status, reachability_status, last_http_status, last_accessed_at,
                    notes, metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(onion_address) DO UPDATE SET
                    title=excluded.title,
                    source_obtained_from=excluded.source_obtained_from,
                    official_reference_url=excluded.official_reference_url,
                    trust_status=excluded.trust_status,
                    reachability_status=excluded.reachability_status,
                    last_http_status=excluded.last_http_status,
                    last_accessed_at=excluded.last_accessed_at,
                    notes=excluded.notes,
                    metadata_json=excluded.metadata_json,
                    updated_at=excluded.updated_at
                """,
                (
                    bid,
                    addr,
                    str(item.get("title") or "")[:300],
                    str(item.get("source_obtained_from") or "user_supplied")[:300],
                    str(item.get("official_reference_url") or "")[:500],
                    str(item.get("trust_status") or "unverified")[:48],
                    str(item.get("reachability_status") or "unchecked")[:48],
                    item.get("last_http_status"),
                    str(item.get("last_accessed_at") or ""),
                    str(item.get("notes") or "")[:1000],
                    _dump(item.get("metadata") or {}),
                    str(item.get("created_at") or now),
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM onion_bookmarks WHERE onion_address = ?", (addr,)).fetchone()
        if r is None:
            return {}
        d = dict(r)
        d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
        return d

    def list_onion_bookmarks(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM onion_bookmarks ORDER BY updated_at DESC LIMIT ?",
                (max(1, min(int(limit), 500)),),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
            out.append(d)
        return out

    def delete_onion_bookmark(self, addr_or_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM onion_bookmarks WHERE id = ? OR onion_address = ?",
                (addr_or_id, addr_or_id.strip().lower()),
            )
            return cur.rowcount > 0

    def add_internet_search_run(self, entry: dict[str, Any]) -> dict[str, Any]:
        sid = str(entry.get("id") or f"srun-{uuid.uuid4().hex[:12]}")
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO internet_search_runs (
                    id, query, mode, sources_consulted_json, sources_skipped_json,
                    query_limitations_json, retrieval_errors_json, result_count, report_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sid,
                    str(entry.get("query") or "")[:1000],
                    str(entry.get("mode") or "unified_search")[:48],
                    _dump(entry.get("sources_consulted") or []),
                    _dump(entry.get("sources_skipped") or []),
                    _dump(entry.get("query_limitations") or []),
                    _dump(entry.get("retrieval_errors") or []),
                    int(entry.get("result_count", 0)),
                    str(entry.get("report_id") or "")[:120],
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM internet_search_runs WHERE id = ?", (sid,)).fetchone()
        if r is None:
            return {}
        d = dict(r)
        d["sources_consulted"] = json.loads(d.pop("sources_consulted_json") or "[]")
        d["sources_skipped"] = json.loads(d.pop("sources_skipped_json") or "[]")
        d["query_limitations"] = json.loads(d.pop("query_limitations_json") or "[]")
        d["retrieval_errors"] = json.loads(d.pop("retrieval_errors_json") or "[]")
        return d

    def list_internet_search_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM internet_search_runs ORDER BY created_at DESC LIMIT ?",
                (max(1, min(int(limit), 200)),),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["sources_consulted"] = json.loads(d.pop("sources_consulted_json") or "[]")
            d["sources_skipped"] = json.loads(d.pop("sources_skipped_json") or "[]")
            d["query_limitations"] = json.loads(d.pop("query_limitations_json") or "[]")
            d["retrieval_errors"] = json.loads(d.pop("retrieval_errors_json") or "[]")
            out.append(d)
        return out

    def add_threat_intel_finding(self, item: dict[str, Any]) -> dict[str, Any]:
        fid = str(item.get("id") or f"tif-{uuid.uuid4().hex[:12]}")
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO threat_intel_findings (
                    id, finding_kind, source_classification, confidence_tier, severity,
                    asset_scope, indicators_json, summary, remediation, source_refs_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fid,
                    str(item.get("finding_kind") or "advisory")[:64],
                    str(item.get("source_classification") or "external_report")[:64],
                    str(item.get("confidence_tier") or "claim")[:32],
                    str(item.get("severity") or "info")[:24],
                    str(item.get("asset_scope") or "")[:200],
                    _dump(item.get("indicators") or {}),
                    str(item.get("summary") or "")[:4000],
                    str(item.get("remediation") or "")[:2000],
                    _dump(item.get("source_refs") or []),
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM threat_intel_findings WHERE id = ?", (fid,)).fetchone()
        if r is None:
            return {}
        d = dict(r)
        d["indicators"] = json.loads(d.pop("indicators_json") or "{}")
        d["source_refs"] = json.loads(d.pop("source_refs_json") or "[]")
        return d

    def list_threat_intel_findings(self, *, asset_scope: str = "", limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM threat_intel_findings"
        params: list[Any] = []
        if asset_scope:
            sql += " WHERE LOWER(asset_scope) = ?"
            params.append(asset_scope.strip().lower())
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["indicators"] = json.loads(d.pop("indicators_json") or "{}")
            d["source_refs"] = json.loads(d.pop("source_refs_json") or "[]")
            out.append(d)
        return out

    def save_quarantined_download(self, item: dict[str, Any]) -> dict[str, Any]:
        qid = str(item.get("id") or f"qdl-{uuid.uuid4().hex[:12]}")
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO quarantined_downloads (
                    id, source_url, via_network, original_filename, quarantine_path,
                    extracted_dir, size_bytes, sha256, sha512, detected_mime,
                    signature_status, clamav_status, static_analysis_json,
                    duplicate_of_id, auto_executed, provenance_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    qid,
                    str(item.get("source_url") or "")[:1000],
                    str(item.get("via_network") or "clearnet")[:32],
                    str(item.get("original_filename") or "download.bin")[:255],
                    str(item.get("quarantine_path") or "")[:500],
                    str(item.get("extracted_dir") or "")[:500],
                    int(item.get("size_bytes", 0)),
                    str(item["sha256"])[:64],
                    str(item.get("sha512") or "")[:128],
                    str(item.get("detected_mime") or "application/octet-stream")[:120],
                    str(item.get("signature_status") or "not_provided")[:64],
                    str(item.get("clamav_status") or "not_scanned")[:64],
                    _dump(item.get("static_analysis") or {}),
                    str(item.get("duplicate_of_id") or "")[:64],
                    _dump(item.get("provenance") or {}),
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM quarantined_downloads WHERE id = ?", (qid,)).fetchone()
        return self._unpack_quarantined(r) if r else {}

    @staticmethod
    def _unpack_quarantined(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["auto_executed"] = bool(d["auto_executed"])
        d["static_analysis"] = json.loads(d.pop("static_analysis_json") or "{}")
        d["provenance"] = json.loads(d.pop("provenance_json") or "{}")
        return d

    def find_quarantined_by_sha256(self, sha256_hex: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute(
                "SELECT * FROM quarantined_downloads WHERE sha256 = ? ORDER BY created_at ASC LIMIT 1",
                (sha256_hex,),
            ).fetchone()
        return self._unpack_quarantined(r) if r else None

    def list_quarantined_downloads(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM quarantined_downloads ORDER BY created_at DESC LIMIT ?",
                (max(1, min(int(limit), 200)),),
            ).fetchall()
        return [self._unpack_quarantined(r) for r in rows]

    def save_onion_hosting_plan(self, item: dict[str, Any]) -> dict[str, Any]:
        pid = str(item.get("id") or f"ohost-{uuid.uuid4().hex[:10]}")
        sname = str(item["service_name"]).strip()[:80]
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO onion_hosting_plans (
                    id, service_name, local_bind_host, local_bind_port, virtual_port,
                    enabled, key_vault_ref, torrc_snippet, deployment_plan_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(service_name) DO UPDATE SET
                    local_bind_host=excluded.local_bind_host,
                    local_bind_port=excluded.local_bind_port,
                    virtual_port=excluded.virtual_port,
                    enabled=excluded.enabled,
                    key_vault_ref=excluded.key_vault_ref,
                    torrc_snippet=excluded.torrc_snippet,
                    deployment_plan_json=excluded.deployment_plan_json,
                    updated_at=excluded.updated_at
                """,
                (
                    pid,
                    sname,
                    str(item.get("local_bind_host") or "127.0.0.1")[:64],
                    int(item["local_bind_port"]),
                    int(item.get("virtual_port", 80)),
                    int(bool(item.get("enabled", False))),
                    str(item.get("key_vault_ref") or "")[:120],
                    str(item.get("torrc_snippet") or "")[:4000],
                    _dump(item.get("deployment_plan") or {}),
                    str(item.get("created_at") or now),
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM onion_hosting_plans WHERE service_name = ?", (sname,)).fetchone()
        if r is None:
            return {}
        d = dict(r)
        d["enabled"] = bool(d["enabled"])
        d["deployment_plan"] = json.loads(d.pop("deployment_plan_json") or "{}")
        return d

    def list_onion_hosting_plans(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM onion_hosting_plans ORDER BY service_name ASC").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["enabled"] = bool(d["enabled"])
            d["deployment_plan"] = json.loads(d.pop("deployment_plan_json") or "{}")
            out.append(d)
        return out

    def save_research_monitor(self, item: dict[str, Any]) -> dict[str, Any]:
        mid = str(item.get("id") or f"rmon-{uuid.uuid4().hex[:12]}")
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO research_monitors (
                    id, name, topic_or_query, allowed_sources_json, asset_targets_json,
                    interval_seconds, rate_limit_per_hour, enabled, checkpoint_hash,
                    last_run_at, last_success_at, last_summary, alert_condition,
                    metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    topic_or_query=excluded.topic_or_query,
                    allowed_sources_json=excluded.allowed_sources_json,
                    asset_targets_json=excluded.asset_targets_json,
                    interval_seconds=excluded.interval_seconds,
                    rate_limit_per_hour=excluded.rate_limit_per_hour,
                    enabled=excluded.enabled,
                    checkpoint_hash=excluded.checkpoint_hash,
                    last_run_at=excluded.last_run_at,
                    last_success_at=excluded.last_success_at,
                    last_summary=excluded.last_summary,
                    alert_condition=excluded.alert_condition,
                    metadata_json=excluded.metadata_json,
                    updated_at=excluded.updated_at
                """,
                (
                    mid,
                    str(item["name"])[:200],
                    str(item["topic_or_query"])[:1000],
                    _dump(item.get("allowed_sources") or []),
                    _dump(item.get("asset_targets") or []),
                    max(60, int(item.get("interval_seconds", 3600))),
                    max(1, min(int(item.get("rate_limit_per_hour", 6)), 120)),
                    int(bool(item.get("enabled", True))),
                    str(item.get("checkpoint_hash") or "")[:128],
                    str(item.get("last_run_at") or ""),
                    str(item.get("last_success_at") or ""),
                    str(item.get("last_summary") or "")[:2000],
                    str(item.get("alert_condition") or "any_change")[:120],
                    _dump(item.get("metadata") or {}),
                    str(item.get("created_at") or now),
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM research_monitors WHERE id = ?", (mid,)).fetchone()
        return self._unpack_research_monitor(r) if r else {}

    @staticmethod
    def _unpack_research_monitor(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["enabled"] = bool(d["enabled"])
        d["allowed_sources"] = json.loads(d.pop("allowed_sources_json") or "[]")
        d["asset_targets"] = json.loads(d.pop("asset_targets_json") or "[]")
        d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
        return d

    def get_research_monitor(self, monitor_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM research_monitors WHERE id = ?", (monitor_id,)).fetchone()
        return self._unpack_research_monitor(r) if r else None

    def list_research_monitors(self, *, enabled_only: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM research_monitors"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY updated_at DESC"
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql).fetchall()
        return [self._unpack_research_monitor(r) for r in rows]

    def delete_research_monitor(self, monitor_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM research_monitors WHERE id = ?", (monitor_id,))
            return cur.rowcount > 0

    # --- Corrected Master Architecture (§2, §5, §6): Dynamic Providers, Privacy Gateway & Offline Cloud Queue ---

    def upsert_dynamic_provider_spec(self, item: dict[str, Any]) -> dict[str, Any]:
        ptype = str(item.get("provider_type") or "").strip().lower()
        if not ptype:
            raise ValueError("provider_type is required.")
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO dynamic_provider_specs (
                    provider_type, label, default_base_url, default_key_env,
                    adapter_family, official_host, local_only,
                    supports_streaming, supports_structured_outputs, supports_tools,
                    metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider_type) DO UPDATE SET
                    label = excluded.label,
                    default_base_url = excluded.default_base_url,
                    default_key_env = excluded.default_key_env,
                    adapter_family = excluded.adapter_family,
                    official_host = excluded.official_host,
                    local_only = excluded.local_only,
                    supports_streaming = excluded.supports_streaming,
                    supports_structured_outputs = excluded.supports_structured_outputs,
                    supports_tools = excluded.supports_tools,
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
                """,
                (
                    ptype[:64],
                    str(item.get("label") or ptype)[:120],
                    str(item.get("default_base_url") or "")[:300],
                    str(item.get("default_key_env") or "")[:64],
                    str(item.get("adapter_family") or "openai_compatible")[:48],
                    str(item.get("official_host") or "")[:200],
                    1 if item.get("local_only") else 0,
                    1 if item.get("supports_streaming", True) else 0,
                    1 if item.get("supports_structured_outputs", True) else 0,
                    1 if item.get("supports_tools", True) else 0,
                    _dump(item.get("metadata") or {}),
                    now,
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM dynamic_provider_specs WHERE provider_type = ?", (ptype,)).fetchone()
        return self._unpack_dynamic_provider_spec(r) if r else {}

    @staticmethod
    def _unpack_dynamic_provider_spec(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        for flag in ("local_only", "supports_streaming", "supports_structured_outputs", "supports_tools"):
            d[flag] = bool(d[flag])
        d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
        return d

    def list_dynamic_provider_specs(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM dynamic_provider_specs ORDER BY provider_type ASC").fetchall()
        return [self._unpack_dynamic_provider_spec(r) for r in rows]

    def delete_dynamic_provider_spec(self, provider_type: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM dynamic_provider_specs WHERE provider_type = ?", (provider_type.strip().lower(),))
            return cur.rowcount > 0

    def upsert_provider_privacy_policy(self, item: dict[str, Any]) -> dict[str, Any]:
        ptype = str(item.get("provider_type") or "").strip().lower()
        if not ptype:
            raise ValueError("provider_type is required.")
        now = utc_now()
        categories = item.get("allowed_categories")
        if not isinstance(categories, list):
            categories = ["prompt", "diagnostics", "workspace_excerpt"]
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO provider_privacy_policies (
                    provider_type, enabled, max_payload_chars,
                    allow_diagnostic_context, allow_file_excerpts,
                    require_sensitive_transfer_approval, allowed_categories_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider_type) DO UPDATE SET
                    enabled = excluded.enabled,
                    max_payload_chars = excluded.max_payload_chars,
                    allow_diagnostic_context = excluded.allow_diagnostic_context,
                    allow_file_excerpts = excluded.allow_file_excerpts,
                    require_sensitive_transfer_approval = excluded.require_sensitive_transfer_approval,
                    allowed_categories_json = excluded.allowed_categories_json,
                    updated_at = excluded.updated_at
                """,
                (
                    ptype[:64],
                    1 if item.get("enabled", True) else 0,
                    max(256, min(int(item.get("max_payload_chars", 24000)), 500000)),
                    1 if item.get("allow_diagnostic_context", True) else 0,
                    1 if item.get("allow_file_excerpts", True) else 0,
                    1 if item.get("require_sensitive_transfer_approval", True) else 0,
                    _dump([str(c)[:64] for c in categories]),
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM provider_privacy_policies WHERE provider_type = ?", (ptype,)).fetchone()
        return self._unpack_provider_privacy_policy(r) if r else {}

    @staticmethod
    def _unpack_provider_privacy_policy(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        for flag in ("enabled", "allow_diagnostic_context", "allow_file_excerpts", "require_sensitive_transfer_approval"):
            d[flag] = bool(d[flag])
        d["allowed_categories"] = json.loads(d.pop("allowed_categories_json") or "[]")
        return d

    def get_provider_privacy_policy(self, provider_type: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute(
                "SELECT * FROM provider_privacy_policies WHERE provider_type = ?",
                (provider_type.strip().lower(),),
            ).fetchone()
        return self._unpack_provider_privacy_policy(r) if r else None

    def list_provider_privacy_policies(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM provider_privacy_policies ORDER BY provider_type ASC").fetchall()
        return [self._unpack_provider_privacy_policy(r) for r in rows]

    def upsert_local_only_project(self, item: dict[str, Any]) -> dict[str, Any]:
        pkey = str(item.get("project_key") or "").strip()
        if not pkey:
            raise ValueError("project_key is required.")
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO local_only_projects (
                    project_key, project_path, local_only,
                    allow_quantized_local_fallback, reason, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_key) DO UPDATE SET
                    project_path = excluded.project_path,
                    local_only = excluded.local_only,
                    allow_quantized_local_fallback = excluded.allow_quantized_local_fallback,
                    reason = excluded.reason,
                    updated_at = excluded.updated_at
                """,
                (
                    pkey[:120],
                    str(item.get("project_path") or pkey)[:500],
                    1 if item.get("local_only", True) else 0,
                    1 if item.get("allow_quantized_local_fallback", True) else 0,
                    str(item.get("reason") or "")[:400],
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM local_only_projects WHERE project_key = ?", (pkey,)).fetchone()
        return self._unpack_local_only_project(r) if r else {}

    @staticmethod
    def _unpack_local_only_project(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["local_only"] = bool(d["local_only"])
        d["allow_quantized_local_fallback"] = bool(d["allow_quantized_local_fallback"])
        return d

    def get_local_only_project(self, project_key: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM local_only_projects WHERE project_key = ?", (project_key.strip(),)).fetchone()
        return self._unpack_local_only_project(r) if r else None

    def list_local_only_projects(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM local_only_projects ORDER BY updated_at DESC").fetchall()
        return [self._unpack_local_only_project(r) for r in rows]

    def delete_local_only_project(self, project_key: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM local_only_projects WHERE project_key = ?", (project_key.strip(),))
            return cur.rowcount > 0

    def record_cloud_transmission(self, item: dict[str, Any]) -> dict[str, Any]:
        tid = str(item.get("id") or f"ctxm-{uuid.uuid4().hex[:12]}")
        now = utc_now()
        files = [str(f)[:300] for f in (item.get("included_files") or []) if str(f).strip()]
        cats = [str(c)[:80] for c in (item.get("included_categories") or []) if str(c).strip()]
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO cloud_transmission_ledger (
                    id, task_id, provider_type, model_id, endpoint_host,
                    decision, payload_chars, redacted_items_count,
                    included_files_json, included_categories_json, reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tid,
                    str(item.get("task_id") or "")[:120],
                    str(item.get("provider_type") or "")[:64],
                    str(item.get("model_id") or "")[:120],
                    str(item.get("endpoint_host") or "")[:200],
                    str(item.get("decision") or "blocked")[:40],
                    max(0, int(item.get("payload_chars") or 0)),
                    max(0, int(item.get("redacted_items_count") or 0)),
                    _dump(files),
                    _dump(cats),
                    str(item.get("reason") or "")[:500],
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM cloud_transmission_ledger WHERE id = ?", (tid,)).fetchone()
        if r is None:
            return {}
        d = dict(r)
        d["included_files"] = json.loads(d.pop("included_files_json") or "[]")
        d["included_categories"] = json.loads(d.pop("included_categories_json") or "[]")
        return d

    def list_cloud_transmissions(self, *, task_id: str = "", provider_type: str = "", limit: int = 100) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if task_id:
            clauses.append("task_id = ?")
            params.append(task_id.strip())
        if provider_type:
            clauses.append("provider_type = ?")
            params.append(provider_type.strip().lower())
        sql = "SELECT * FROM cloud_transmission_ledger"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["included_files"] = json.loads(d.pop("included_files_json") or "[]")
            d["included_categories"] = json.loads(d.pop("included_categories_json") or "[]")
            out.append(d)
        return out

    def enqueue_offline_cloud_task(self, item: dict[str, Any]) -> dict[str, Any]:
        qid = str(item.get("id") or f"ocq-{uuid.uuid4().hex[:12]}")
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO offline_cloud_queue (
                    id, task_id, goal, mode, messages_json, requested_model_ids_json,
                    status, checkpoint_id, idempotency_key, local_fallback_allowed,
                    attempt_count, last_error, result_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    qid,
                    str(item.get("task_id") or "")[:120],
                    str(item.get("goal") or "")[:4000],
                    str(item.get("mode") or "balanced")[:48],
                    _dump(item.get("messages") or []),
                    _dump(item.get("requested_model_ids") or []),
                    str(item.get("status") or "queued_waiting_cloud")[:48],
                    str(item.get("checkpoint_id") or "")[:120],
                    str(item.get("idempotency_key") or "")[:160],
                    1 if item.get("local_fallback_allowed") else 0,
                    max(0, int(item.get("attempt_count") or 0)),
                    str(item.get("last_error") or "")[:1000],
                    _dump(item.get("result") or {}),
                    now,
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM offline_cloud_queue WHERE id = ?", (qid,)).fetchone()
        return self._unpack_offline_cloud_task(r) if r else {}

    @staticmethod
    def _unpack_offline_cloud_task(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["local_fallback_allowed"] = bool(d["local_fallback_allowed"])
        d["messages"] = json.loads(d.pop("messages_json") or "[]")
        d["requested_model_ids"] = json.loads(d.pop("requested_model_ids_json") or "[]")
        d["result"] = json.loads(d.pop("result_json") or "{}")
        return d

    def update_offline_cloud_task(self, queue_id: str, **updates: Any) -> dict[str, Any] | None:
        allowed_scalar = {"status", "checkpoint_id", "attempt_count", "last_error"}
        sets: list[str] = ["updated_at = ?"]
        params: list[Any] = [utc_now()]
        for key, value in updates.items():
            if key in allowed_scalar:
                sets.append(f"{key} = ?")
                params.append(value)
            elif key == "result":
                sets.append("result_json = ?")
                params.append(_dump(value or {}))
        params.append(queue_id)
        with self._lock, self._connect() as conn:
            conn.execute(f"UPDATE offline_cloud_queue SET {', '.join(sets)} WHERE id = ?", params)
            r = conn.execute("SELECT * FROM offline_cloud_queue WHERE id = ?", (queue_id,)).fetchone()
        return self._unpack_offline_cloud_task(r) if r else None

    def get_offline_cloud_task(self, queue_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM offline_cloud_queue WHERE id = ?", (queue_id,)).fetchone()
        return self._unpack_offline_cloud_task(r) if r else None

    def list_offline_cloud_tasks(self, *, status: str = "", limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM offline_cloud_queue"
        params: list[Any] = []
        if status:
            sql += " WHERE status = ?"
            params.append(status.strip())
        sql += " ORDER BY created_at ASC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._unpack_offline_cloud_task(r) for r in rows]

    # --- Sections 181–200: Advanced Kali Linux Intelligence, Application Mastery & Universal Integration ---

    def save_kali_system_snapshot(self, item: dict[str, Any]) -> dict[str, Any]:
        sid = str(item.get("id") or f"ksys-{uuid.uuid4().hex[:12]}")
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO kali_system_snapshots (
                    id, distro_id, distro_version, kernel_release, architecture,
                    dpkg_fingerprint, snapshot_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sid,
                    str(item.get("distro_id") or "")[:64],
                    str(item.get("distro_version") or "")[:80],
                    str(item.get("kernel_release") or "")[:120],
                    str(item.get("architecture") or "")[:48],
                    str(item.get("dpkg_fingerprint") or "")[:128],
                    _dump(item.get("snapshot") or {}),
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM kali_system_snapshots WHERE id = ?", (sid,)).fetchone()
        if r is None:
            return {}
        d = dict(r)
        d["snapshot"] = json.loads(d.pop("snapshot_json") or "{}")
        return d

    def latest_kali_system_snapshot(self) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM kali_system_snapshots ORDER BY created_at DESC LIMIT 1").fetchone()
        if r is None:
            return None
        d = dict(r)
        d["snapshot"] = json.loads(d.pop("snapshot_json") or "{}")
        return d

    def upsert_kali_tool_profile(self, item: dict[str, Any]) -> dict[str, Any]:
        tkey = str(item.get("tool_key") or item.get("name") or "").strip().lower()
        if not tkey:
            raise ValueError("tool_key or name is required.")
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO kali_tool_profiles (
                    tool_key, name, command_name, package_name, category,
                    installation_status, executable_path, version,
                    integration_method, tested_compatibility, profile_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tool_key) DO UPDATE SET
                    name = excluded.name,
                    command_name = excluded.command_name,
                    package_name = excluded.package_name,
                    category = excluded.category,
                    installation_status = excluded.installation_status,
                    executable_path = excluded.executable_path,
                    version = excluded.version,
                    integration_method = excluded.integration_method,
                    tested_compatibility = excluded.tested_compatibility,
                    profile_json = excluded.profile_json,
                    updated_at = excluded.updated_at
                """,
                (
                    tkey[:120],
                    str(item.get("name") or tkey)[:120],
                    str(item.get("command_name") or tkey)[:120],
                    str(item.get("package_name") or "")[:120],
                    str(item.get("category") or "general")[:80],
                    str(item.get("installation_status") or "unavailable")[:40],
                    str(item.get("executable_path") or "")[:300],
                    str(item.get("version") or "")[:120],
                    str(item.get("integration_method") or "documented_cli")[:64],
                    1 if item.get("tested_compatibility") else 0,
                    _dump(item.get("profile") or {}),
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM kali_tool_profiles WHERE tool_key = ?", (tkey[:120],)).fetchone()
        return self._unpack_kali_tool_profile(r) if r else {}

    @staticmethod
    def _unpack_kali_tool_profile(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["tested_compatibility"] = bool(d["tested_compatibility"])
        d["profile"] = json.loads(d.pop("profile_json") or "{}")
        return d

    def get_kali_tool_profile(self, tool_key: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM kali_tool_profiles WHERE tool_key = ?", (tool_key.strip().lower(),)).fetchone()
        return self._unpack_kali_tool_profile(r) if r else None

    def list_kali_tool_profiles(self, *, category: str = "", status: str = "", limit: int = 300) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if category:
            clauses.append("LOWER(category) = ?")
            params.append(category.strip().lower())
        if status:
            clauses.append("installation_status = ?")
            params.append(status.strip())
        sql = "SELECT * FROM kali_tool_profiles"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY tool_key ASC LIMIT ?"
        params.append(max(1, min(int(limit), 1000)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._unpack_kali_tool_profile(r) for r in rows]

    def upsert_kali_knowledge_doc(self, item: dict[str, Any]) -> dict[str, Any]:
        dkey = str(item.get("doc_key") or f"kdoc-{uuid.uuid4().hex[:12]}").strip()
        now = utc_now()
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT content_sha256, retrieved_at FROM kali_knowledge_documents WHERE doc_key = ?",
                (dkey,),
            ).fetchone()
            new_sha = str(item.get("content_sha256") or "")[:128]
            unchanged = bool(existing and new_sha and existing["content_sha256"] == new_sha)
            retrieved_at = str(existing["retrieved_at"]) if unchanged and existing else str(item.get("retrieved_at") or now)
            conn.execute(
                """
                INSERT INTO kali_knowledge_documents (
                    doc_key, title, tool_or_topic, priority_tier, source_kind,
                    source_ref, reliability, version_context, license_note,
                    content_sha256, content_excerpt, metadata_json, retrieved_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(doc_key) DO UPDATE SET
                    title = excluded.title,
                    tool_or_topic = excluded.tool_or_topic,
                    priority_tier = excluded.priority_tier,
                    source_kind = excluded.source_kind,
                    source_ref = excluded.source_ref,
                    reliability = excluded.reliability,
                    version_context = excluded.version_context,
                    license_note = excluded.license_note,
                    content_sha256 = excluded.content_sha256,
                    content_excerpt = excluded.content_excerpt,
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
                """,
                (
                    dkey[:160],
                    str(item.get("title") or dkey)[:200],
                    str(item.get("tool_or_topic") or "").lower()[:120],
                    max(1, min(int(item.get("priority_tier") or 1), 5)),
                    str(item.get("source_kind") or "local_man_or_help")[:80],
                    str(item.get("source_ref") or "")[:400],
                    str(item.get("reliability") or "official_verified")[:64],
                    str(item.get("version_context") or "")[:160],
                    str(item.get("license_note") or "")[:240],
                    new_sha,
                    str(item.get("content_excerpt") or "")[:12000],
                    _dump(item.get("metadata") or {}),
                    retrieved_at,
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM kali_knowledge_documents WHERE doc_key = ?", (dkey[:160],)).fetchone()
        if r is None:
            return {}
        d = dict(r)
        d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
        d["incremental_unchanged"] = unchanged
        return d

    def search_kali_knowledge_docs(
        self,
        *,
        query: str = "",
        tool_or_topic: str = "",
        max_priority_tier: int = 5,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        clauses = ["priority_tier <= ?"]
        params: list[Any] = [max(1, min(int(max_priority_tier), 5))]
        if tool_or_topic:
            clauses.append("LOWER(tool_or_topic) = ?")
            params.append(tool_or_topic.strip().lower())
        if query:
            q = f"%{query.strip().lower()}%"
            clauses.append("(LOWER(title) LIKE ? OR LOWER(tool_or_topic) LIKE ? OR LOWER(content_excerpt) LIKE ?)")
            params.extend([q, q, q])
        sql = f"SELECT * FROM kali_knowledge_documents WHERE {' AND '.join(clauses)} ORDER BY priority_tier ASC, updated_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 200)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
            out.append(d)
        return out

    def upsert_kali_cyber_lab(self, item: dict[str, Any]) -> dict[str, Any]:
        lid = str(item.get("id") or f"klab-{uuid.uuid4().hex[:10]}")
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO kali_cyber_labs (
                    id, name, purpose, runtime_kind, network_scope, isolated,
                    authorized_scope, status, resources_json, snapshots_json,
                    datasets_json, progress_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    purpose = excluded.purpose,
                    runtime_kind = excluded.runtime_kind,
                    network_scope = excluded.network_scope,
                    isolated = excluded.isolated,
                    authorized_scope = excluded.authorized_scope,
                    status = excluded.status,
                    resources_json = excluded.resources_json,
                    snapshots_json = excluded.snapshots_json,
                    datasets_json = excluded.datasets_json,
                    progress_json = excluded.progress_json,
                    updated_at = excluded.updated_at
                """,
                (
                    lid[:80],
                    str(item.get("name") or lid)[:160],
                    str(item.get("purpose") or "")[:500],
                    str(item.get("runtime_kind") or "isolated_local_sandbox")[:80],
                    str(item.get("network_scope") or "127.0.0.1/32")[:80],
                    1 if item.get("isolated", True) else 0,
                    str(item.get("authorized_scope") or "local_owned_lab")[:120],
                    str(item.get("status") or "stopped")[:40],
                    _dump(item.get("resources") or {}),
                    _dump(item.get("snapshots") or []),
                    _dump(item.get("datasets") or []),
                    _dump(item.get("progress") or {}),
                    str(item.get("created_at") or now),
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM kali_cyber_labs WHERE id = ?", (lid[:80],)).fetchone()
        return self._unpack_kali_cyber_lab(r) if r else {}

    @staticmethod
    def _unpack_kali_cyber_lab(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["isolated"] = bool(d["isolated"])
        d["resources"] = json.loads(d.pop("resources_json") or "{}")
        d["snapshots"] = json.loads(d.pop("snapshots_json") or "[]")
        d["datasets"] = json.loads(d.pop("datasets_json") or "[]")
        d["progress"] = json.loads(d.pop("progress_json") or "{}")
        return d

    def get_kali_cyber_lab(self, lab_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM kali_cyber_labs WHERE id = ?", (lab_id,)).fetchone()
        return self._unpack_kali_cyber_lab(r) if r else None

    def list_kali_cyber_labs(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM kali_cyber_labs ORDER BY updated_at DESC").fetchall()
        return [self._unpack_kali_cyber_lab(r) for r in rows]

    def upsert_kali_training_progress(self, item: dict[str, Any]) -> dict[str, Any]:
        tid = str(item.get("topic_id") or "").strip().lower()
        if not tid:
            raise ValueError("topic_id is required.")
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO kali_training_progress (
                    topic_id, track, level, completed, quiz_score,
                    attempts, flashcards_json, notes_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(topic_id) DO UPDATE SET
                    track = excluded.track,
                    level = excluded.level,
                    completed = excluded.completed,
                    quiz_score = excluded.quiz_score,
                    attempts = excluded.attempts,
                    flashcards_json = excluded.flashcards_json,
                    notes_json = excluded.notes_json,
                    updated_at = excluded.updated_at
                """,
                (
                    tid[:120],
                    str(item.get("track") or "fundamentals")[:80],
                    str(item.get("level") or "beginner")[:32],
                    1 if item.get("completed") else 0,
                    float(item["quiz_score"]) if item.get("quiz_score") is not None else None,
                    max(0, int(item.get("attempts") or 0)),
                    _dump(item.get("flashcards") or []),
                    _dump(item.get("notes") or {}),
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM kali_training_progress WHERE topic_id = ?", (tid[:120],)).fetchone()
        if r is None:
            return {}
        d = dict(r)
        d["completed"] = bool(d["completed"])
        d["flashcards"] = json.loads(d.pop("flashcards_json") or "[]")
        d["notes"] = json.loads(d.pop("notes_json") or "{}")
        return d

    def list_kali_training_progress(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM kali_training_progress ORDER BY updated_at DESC").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["completed"] = bool(d["completed"])
            d["flashcards"] = json.loads(d.pop("flashcards_json") or "[]")
            d["notes"] = json.loads(d.pop("notes_json") or "{}")
            out.append(d)
        return out

    def upsert_kali_expertise_revision(self, item: dict[str, Any]) -> dict[str, Any]:
        rid = str(item.get("id") or f"kexp-{uuid.uuid4().hex[:10]}")
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO kali_expertise_revisions (
                    id, domain, subject, version, status, verified_runs,
                    failed_runs, proposal_json, test_result_json, rollback_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    domain = excluded.domain,
                    subject = excluded.subject,
                    version = excluded.version,
                    status = excluded.status,
                    verified_runs = excluded.verified_runs,
                    failed_runs = excluded.failed_runs,
                    proposal_json = excluded.proposal_json,
                    test_result_json = excluded.test_result_json,
                    rollback_json = excluded.rollback_json,
                    updated_at = excluded.updated_at
                """,
                (
                    rid[:80],
                    str(item.get("domain") or "tool_selection")[:80],
                    str(item.get("subject") or "")[:200],
                    max(1, int(item.get("version") or 1)),
                    str(item.get("status") or "candidate")[:40],
                    max(0, int(item.get("verified_runs") or 0)),
                    max(0, int(item.get("failed_runs") or 0)),
                    _dump(item.get("proposal") or {}),
                    _dump(item.get("test_result") or {}),
                    _dump(item.get("rollback") or {}),
                    str(item.get("created_at") or now),
                    now,
                ),
            )
            r = conn.execute("SELECT * FROM kali_expertise_revisions WHERE id = ?", (rid[:80],)).fetchone()
        return self._unpack_kali_expertise_revision(r) if r else {}

    @staticmethod
    def _unpack_kali_expertise_revision(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["proposal"] = json.loads(d.pop("proposal_json") or "{}")
        d["test_result"] = json.loads(d.pop("test_result_json") or "{}")
        d["rollback"] = json.loads(d.pop("rollback_json") or "{}")
        return d

    def get_kali_expertise_revision(self, revision_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM kali_expertise_revisions WHERE id = ?", (revision_id,)).fetchone()
        return self._unpack_kali_expertise_revision(r) if r else None

    def list_kali_expertise_revisions(self, *, domain: str = "", limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM kali_expertise_revisions"
        params: list[Any] = []
        if domain:
            sql += " WHERE domain = ?"
            params.append(domain.strip())
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._unpack_kali_expertise_revision(r) for r in rows]


