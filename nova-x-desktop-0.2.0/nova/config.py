"""Environment-based configuration with conservative defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# The native desktop build deliberately ignores repository .env files. Its provider
# credentials come from the desktop's Secret Service/keyring. The optional server
# keeps dotenv compatibility for existing deployments.
if os.getenv("NOVA_DESKTOP_MODE") != "1":
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass


def _int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _float_env(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path("./data"))
    workspace_dir: Path = field(default_factory=lambda: Path("./workspace"))
    db_path: Path = field(default_factory=lambda: Path("./data/nova.sqlite3"))
    ai_base_url: str = "https://api.openai.com/v1"
    ai_api_key: str = ""
    ai_model: str = ""
    ai_model_capabilities: tuple[str, ...] = ("chat",)
    ai_timeout_seconds: int = 45
    max_task_steps: int = 8
    max_ai_requests_per_task: int = 12
    max_ai_requests_per_minute: int = 20
    max_retries: int = 1
    max_task_seconds: int = 240
    max_parallel_tasks: int = 1
    max_tool_output_chars: int = 12_000
    max_context_chars: int = 100_000
    max_fusion_models: int = 3
    max_intelligence_requests: int = 7
    max_model_concurrency: int = 3
    max_model_fallbacks: int = 1
    max_intelligence_seconds: int = 180
    max_fusion_output_tokens: int = 1200
    max_fusion_budget_usd: float = 1.0
    default_intelligence_mode: str = "balanced"
    autonomy_level: str = "routine"
    goal_scheduler_enabled: bool = True
    goal_scheduler_poll_seconds: int = 30
    max_scheduled_goal_runs_per_day: int = 5
    max_request_chars: int = 12_000
    max_file_bytes: int = 512 * 1024
    low_resource_mode: bool = True
    verify_tasks: bool = True
    access_token: str = ""
    allow_custom_provider_endpoints: bool = False
    allow_local_http_provider: bool = False
    session_ttl_seconds: int = 8 * 60 * 60
    tavily_api_key: str = ""
    max_chat_history_messages: int = 20

    @classmethod
    def from_env(cls) -> Settings:
        data_dir = Path(os.getenv("NOVA_DATA_DIR", "./data")).expanduser()
        workspace_dir = Path(os.getenv("NOVA_WORKSPACE_DIR", "./workspace")).expanduser()
        db_path = Path(os.getenv("NOVA_DB_PATH", str(data_dir / "nova.sqlite3"))).expanduser()
        base_url = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").strip().rstrip("/")
        if not base_url:
            base_url = "https://api.openai.com/v1"
        access_token = os.getenv("NOVA_ACCESS_TOKEN", "")
        # Hugging Face Spaces can be public by default. Fail closed there rather
        # than silently exposing a configured provider key or workspace API.
        if os.getenv("SPACE_ID") and not access_token:
            raise RuntimeError("Set NOVA_ACCESS_TOKEN in Hugging Face Space secrets before starting NOVA X.")
        low_resource_mode = _bool_env("NOVA_LOW_RESOURCE_MODE", True)
        configured_mode = os.getenv("NOVA_DEFAULT_INTELLIGENCE_MODE", "balanced").strip().lower()
        default_mode = configured_mode if configured_mode in {"fast", "balanced", "frontier_fusion", "maximum_intelligence"} else "balanced"
        configured_autonomy = os.getenv("NOVA_AUTONOMY_LEVEL", "routine").strip().lower()
        autonomy_level = configured_autonomy if configured_autonomy in {"assisted", "routine", "advanced", "high"} else "routine"
        declared_capabilities = tuple(
            item.strip().lower() for item in os.getenv("AI_MODEL_CAPABILITIES", "chat").split(",")
            if item.strip().lower() in {"chat", "tools"}
        )
        return cls(
            data_dir=data_dir,
            workspace_dir=workspace_dir,
            db_path=db_path,
            ai_base_url=base_url,
            ai_api_key=os.getenv("AI_API_KEY", "").strip(),
            ai_model=os.getenv("AI_MODEL", "").strip(),
            ai_model_capabilities=declared_capabilities,
            ai_timeout_seconds=_int_env("AI_TIMEOUT_SECONDS", 45, 5, 180),
            max_task_steps=_int_env("NOVA_MAX_TASK_STEPS", 8, 1, 30),
            max_ai_requests_per_task=_int_env("NOVA_MAX_AI_REQUESTS_PER_TASK", 12, 2, 60),
            max_ai_requests_per_minute=_int_env("NOVA_MAX_AI_REQUESTS_PER_MINUTE", 20, 1, 300),
            max_retries=_int_env("NOVA_MAX_RETRIES", 1, 0, 4),
            max_task_seconds=_int_env("NOVA_MAX_TASK_SECONDS", 240, 10, 3600),
            max_parallel_tasks=_int_env("NOVA_MAX_PARALLEL_TASKS", 1 if low_resource_mode else 2, 1, 8),
            max_tool_output_chars=_int_env("NOVA_MAX_TOOL_OUTPUT_CHARS", 12_000, 500, 100_000),
            max_context_chars=_int_env("NOVA_MAX_CONTEXT_CHARS", 100_000, 8_000, 1_000_000),
            max_fusion_models=_int_env("NOVA_MAX_FUSION_MODELS", 3, 2, 6),
            max_intelligence_requests=_int_env("NOVA_MAX_INTELLIGENCE_REQUESTS", 7, 1, 20),
            max_model_concurrency=_int_env("NOVA_MAX_MODEL_CONCURRENCY", 3, 1, 6),
            max_model_fallbacks=_int_env("NOVA_MAX_MODEL_FALLBACKS", 1, 0, 3),
            max_intelligence_seconds=_int_env("NOVA_MAX_INTELLIGENCE_SECONDS", 180, 10, 900),
            max_fusion_output_tokens=_int_env("NOVA_MAX_FUSION_OUTPUT_TOKENS", 1200, 128, 8000),
            max_fusion_budget_usd=_float_env("NOVA_MAX_FUSION_BUDGET_USD", 1.0, 0.0, 1000.0),
            default_intelligence_mode=default_mode,
            autonomy_level=autonomy_level,
            goal_scheduler_enabled=_bool_env("NOVA_GOAL_SCHEDULER_ENABLED", True),
            goal_scheduler_poll_seconds=_int_env("NOVA_GOAL_SCHEDULER_POLL_SECONDS", 30, 10, 300),
            max_scheduled_goal_runs_per_day=_int_env("NOVA_MAX_SCHEDULED_GOAL_RUNS_PER_DAY", 5, 0, 100),
            max_request_chars=_int_env("NOVA_MAX_REQUEST_CHARS", 12_000, 500, 100_000),
            max_file_bytes=_int_env("NOVA_MAX_FILE_BYTES", 512 * 1024, 1024, 10 * 1024 * 1024),
            low_resource_mode=low_resource_mode,
            verify_tasks=_bool_env("NOVA_VERIFY_TASKS", True),
            access_token=access_token,
            allow_custom_provider_endpoints=_bool_env("NOVA_ALLOW_CUSTOM_PROVIDER_ENDPOINTS", False),
            allow_local_http_provider=_bool_env("NOVA_ALLOW_LOCAL_HTTP_PROVIDER", False),
            session_ttl_seconds=_int_env("NOVA_SESSION_TTL_SECONDS", 8 * 60 * 60, 300, 30 * 24 * 60 * 60),
            tavily_api_key=os.getenv("TAVILY_API_KEY", "").strip(),
            max_chat_history_messages=_int_env("NOVA_MAX_CHAT_HISTORY_MESSAGES", 20, 1, 200),
        )

    @property
    def ai_configured(self) -> bool:
        return bool(self.ai_api_key and self.ai_model and self.ai_base_url)

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
