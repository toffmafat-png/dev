"""§90 Modular technology platform service layer.

Wires NOVA X's §91–§113 subsystems into one coherent, local-first service object
shared by ``TaskEngine``, the native Qt ``DesktopRuntime`` and the local HTTP
surface without forcing optional external dependencies into the core install.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nova.acquisition_migration.service import AutonomousAcquisitionAndMigrationService
from nova.autonomy import AutonomyPolicy
from nova.capabilities import CapabilityRegistry, prioritize, recommendation_catalogue
from nova.config import Settings
from nova.context_manager import ContextOptimizer
from nova.creation.engine import UniversalCreationEngine
from nova.cyber_division.service import CybersecurityEngineeringDivision
from nova.cyber_intelligence.service import NextGenCyberIntelligenceService
from nova.data_workspace import DataWorkspace
from nova.db import Database
from nova.desktop_control import LinuxDesktopController, build_desktop_control_tools
from nova.devtools import DeveloperWorkspace
from nova.events import Event, EventBus
from nova.general_intelligence.service import GeneralIntelligenceService
from nova.governance import PrivacyGovernor, SystemHealthCenter
from nova.hybrid_cloud.service import HybridCloudIntelligenceService, register_hybrid_cloud_tools
from nova.intelligence import IntelligenceOrchestrator, ModelManager
from nova.kali_intel.service import KaliIntelligenceService
from nova.knowledge import KnowledgeStore
from nova.mcp_client import IntegrationGateway, IntegrationRecord, MCPClientManager
from nova.memory_hub import SharedMemorySystem
from nova.modalities import (
    DeterministicLoopbackRecognizer,
    DeterministicLoopbackSynthesizer,
    VisualAssistant,
    VoiceLayer,
)
from nova.observability import Redactor, TraceCollector
from nova.personal_policy.service import PersonalSecurityAndAutonomyService
from nova.plugins import PluginManager, builtin_sdk_examples
from nova.privacy_intel.service import PrivacyIntelligenceService
from nova.resources import ResourceManager
from nova.sandbox import Sandbox
from nova.self_improvement import ControlledImprovementEngine
from nova.system_access.service import SystemAccessService
from nova.terminal import TerminalWorkspace
from nova.tools.acquisition_migration import build_acquisition_migration_tools
from nova.tools.creation import build_creation_tools
from nova.tools.cyber_division import build_cyber_division_tools
from nova.tools.cyber_intelligence import build_cyber_intelligence_tools
from nova.tools.general_intelligence import build_general_intelligence_tools
from nova.tools.kali_intel import build_kali_intel_tools
from nova.tools.personal_policy import build_personal_policy_tools
from nova.tools.privacy_intel import build_privacy_intel_tools
from nova.tools.registry import ToolRegistry
from nova.tools.system_access import build_system_access_tools
from nova.unified_os import UnifiedOperatingKernel
from nova.updates import MODE_ONLINE, MODE_PROVIDER_UNAVAILABLE, OfflineCoordinator, UpdateManager
from nova.workflows import CrossAppCoordinator, WorkflowEngine

logger = logging.getLogger(__name__)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


@dataclass
class PlatformService:
    """Unified facade over NOVA X's advanced local platform capabilities (§90–§113)."""

    settings: Settings
    db: Database
    tools: ToolRegistry
    autonomy_policy: AutonomyPolicy
    repo_root: Path | None = None
    errors: int = 0
    last_error: str = ""

    redactor: Redactor = field(init=False)
    traces: TraceCollector = field(init=False)
    capabilities: CapabilityRegistry = field(init=False)
    resources: ResourceManager = field(init=False)
    sandbox: Sandbox = field(init=False)
    events: EventBus = field(init=False)
    knowledge: KnowledgeStore = field(init=False)
    context: ContextOptimizer = field(init=False)
    plugins: PluginManager = field(init=False)
    mcp: MCPClientManager = field(init=False)
    gateway: IntegrationGateway = field(init=False)
    terminal: TerminalWorkspace = field(init=False)
    workflows: WorkflowEngine = field(init=False)
    cross_app: CrossAppCoordinator = field(init=False)
    devtools: DeveloperWorkspace = field(init=False)
    data_workspace: DataWorkspace = field(init=False)
    visual: VisualAssistant = field(init=False)
    voice: VoiceLayer = field(init=False)
    updates: UpdateManager = field(init=False)
    offline: OfflineCoordinator = field(init=False)
    privacy: PrivacyGovernor = field(init=False)
    health_center: SystemHealthCenter = field(init=False)
    creation: UniversalCreationEngine = field(init=False)
    desktop_control: LinuxDesktopController = field(init=False)
    memory: SharedMemorySystem = field(init=False)
    improvement: ControlledImprovementEngine = field(init=False)
    unified_os: UnifiedOperatingKernel = field(init=False)
    system_access: SystemAccessService = field(init=False)
    privacy_intel: PrivacyIntelligenceService = field(init=False)
    hybrid_cloud: HybridCloudIntelligenceService = field(init=False)
    kali_intel: KaliIntelligenceService = field(init=False)
    cyber_division: CybersecurityEngineeringDivision = field(init=False)
    acquisition_migration: AutonomousAcquisitionAndMigrationService = field(init=False)
    general_intelligence: GeneralIntelligenceService = field(init=False)
    personal_policy: PersonalSecurityAndAutonomyService = field(init=False)
    cyber_intelligence: NextGenCyberIntelligenceService = field(init=False)

    def __post_init__(self) -> None:
        data_dir = Path(self.settings.data_dir)
        workspace_dir = Path(self.settings.workspace_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        workspace_dir.mkdir(parents=True, exist_ok=True)

        secrets = tuple(
            s
            for s in (
                self.settings.ai_api_key,
                self.settings.access_token,
                self.settings.tavily_api_key,
            )
            if s
        )
        self.redactor = Redactor(literal_secrets=secrets)
        self.traces = TraceCollector(redactor=self.redactor)

        self.capabilities = CapabilityRegistry(
            credentials={
                "ai_api_key": bool(self.settings.ai_api_key),
                "tavily_api_key": bool(self.settings.tavily_api_key),
            },
            configuration={
                "low_resource_mode": bool(self.settings.low_resource_mode),
                "verify_tasks": bool(self.settings.verify_tasks),
            },
        )
        self.resources = ResourceManager(
            disk_path=str(data_dir),
            low_resource_mode=bool(self.settings.low_resource_mode),
            baseline_parallel_tasks=self.settings.max_parallel_tasks,
            baseline_model_concurrency=self.settings.max_model_concurrency,
        )
        self.sandbox = Sandbox()
        self.events = EventBus(permission_check=self.autonomy_policy.decide)

        self.knowledge = KnowledgeStore(
            db_path=str(data_dir / "knowledge.sqlite3"),
            workspace_root=str(workspace_dir),
        )
        self.context = ContextOptimizer(
            budget_chars=min(self.settings.max_context_chars, 24_000),
            redactor=self.redactor,
            knowledge_store=self.knowledge,
        )

        self.plugins = PluginManager(
            plugins_dir=data_dir / "plugins",
            workspace_root=workspace_dir,
            sandbox=self.sandbox,
            redactor=self.redactor,
        )
        # Register the 4 §109 reference SDK extensions (disabled by default until enabled).
        for example in builtin_sdk_examples():
            self.plugins.register_sdk_extension(example, auto_enable=False)

        self.mcp = MCPClientManager(permission_check=self.autonomy_policy.decide, redactor=self.redactor)
        self.gateway = IntegrationGateway(redactor=self.redactor)
        self._register_baseline_integrations()

        self.terminal = TerminalWorkspace(
            default_cwd=workspace_dir,
            redactor=self.redactor,
            capture_limit_chars=self.settings.max_tool_output_chars,
        )

        async def _exec_tool(tool_name: str, args: dict[str, Any], approved: bool) -> dict[str, Any]:
            outcome = await self.tools.execute(tool_name, args, approved=approved)
            return outcome.as_dict()

        self.workflows = WorkflowEngine(
            permission_check=self.autonomy_policy.decide,
            tool_executor=_exec_tool,
            available_tools_fn=lambda: {t["name"] for t in self.tools.all_tools() if t.get("available")},
        )
        self.cross_app = CrossAppCoordinator(workspace_root=workspace_dir)

        resolved_repo = Path(self.repo_root).resolve() if self.repo_root else Path(__file__).resolve().parent.parent
        self.devtools = DeveloperWorkspace(repo_root=resolved_repo, sandbox=self.sandbox)
        self.data_workspace = DataWorkspace(workspace_root=workspace_dir)

        self.visual = VisualAssistant(workspace_root=workspace_dir)
        self.voice = VoiceLayer(
            recognizers=[DeterministicLoopbackRecognizer()],
            synthesizers=[DeterministicLoopbackSynthesizer()],
        )

        self.updates = UpdateManager(db=self.db, staging_dir=data_dir / "updates")
        self.offline = OfflineCoordinator(
            resources=self.resources,
            mode=MODE_ONLINE if self.settings.ai_configured else MODE_PROVIDER_UNAVAILABLE,
            degraded_reason="" if self.settings.ai_configured else "no cloud model credentials configured; running local-first",
        )

        self.privacy = PrivacyGovernor(
            db=self.db,
            redactor=self.redactor,
            knowledge_store=self.knowledge,
            traces=self.traces,
            artifacts_dir=workspace_dir,
            credential_descriptors=lambda: [
                {"name": "AI_API_KEY", "storage": "secret_service_or_env", "configured": bool(self.settings.ai_api_key)},
                {"name": "TAVILY_API_KEY", "storage": "secret_service_or_env", "configured": bool(self.settings.tavily_api_key)},
                {"name": "NOVA_ACCESS_TOKEN", "storage": "env", "configured": bool(self.settings.access_token)},
            ],
        )
        self.health_center = SystemHealthCenter(
            db=self.db,
            resources=self.resources,
            redactor=self.redactor,
            traces=self.traces,
            provider_status_fn=lambda: {
                "available": self.settings.ai_configured,
                "mode": self.offline.mode,
            },
            processes_fn=self.terminal.active_nova_processes,
            integrations_fn=self.gateway.list_integrations,
            pending_updates_fn=self.updates.status,
        )
        self.creation = UniversalCreationEngine(
            db=self.db,
            workspace_root=workspace_dir,
            resources=self.resources,
            redactor=self.redactor,
            plugins=self.plugins,
            workflows=self.workflows,
            permission_check=self.autonomy_policy.decide,
            provider_status_fn=lambda: {
                "configured": bool(self.settings.ai_configured),
                "capabilities": tuple(self.settings.ai_model_capabilities),
            },
            integrations_fn=self.gateway.list_integrations,
        )
        for creation_tool in build_creation_tools(lambda: self.creation):
            if self.tools.get(creation_tool.name) is None:
                self.tools.register(creation_tool)

        self.desktop_control = LinuxDesktopController(
            workspace_root_fn=lambda: Path(self.settings.workspace_dir),
            permission_check=self.autonomy_policy.decide,
        )
        for d_tool in build_desktop_control_tools(self.desktop_control):
            if self.tools.get(d_tool.name) is None:
                self.tools.register(d_tool)

        self.memory = SharedMemorySystem(
            db=self.db,
            knowledge=self.knowledge,
            redactor=self.redactor,
        )
        self.improvement = ControlledImprovementEngine(
            db=self.db,
            data_dir=data_dir,
            stable_root=workspace_dir,
        )
        self.unified_os = UnifiedOperatingKernel(
            db=self.db,
            platform=self,
        )
        self.system_access = SystemAccessService(
            db=self.db,
            redactor=self.redactor,
            resource_manager=self.resources,
            state_dir=data_dir / "system_access",
            workspace_path=workspace_dir,
            worker_status_fn=self.unified_os.worker.status,
        )
        for sa_tool in build_system_access_tools(lambda: self.system_access):
            if self.tools.get(sa_tool.name) is None:
                self.tools.register(sa_tool)
        self.privacy_intel = PrivacyIntelligenceService(
            db=self.db,
            knowledge=self.knowledge,
            memory_os=self.memory,
            vault=self.system_access.vault,
            state_dir=data_dir / "privacy_intel",
            workspace_dir=workspace_dir,
            redactor=self.redactor,
            scheduler_active_probe=lambda: self.unified_os.worker.status().get("status") == "running",
            resource_manager=self.resources,
        )
        self.unified_os.worker.monitor_tick_fn = self.privacy_intel.monitors.run_due_monitors
        for pi_tool in build_privacy_intel_tools(lambda: self.privacy_intel):
            if self.tools.get(pi_tool.name) is None:
                self.tools.register(pi_tool)
        default_mm = ModelManager(self.settings, self.db)
        default_orch = IntelligenceOrchestrator(default_mm, self.settings, self.db)
        self.hybrid_cloud = HybridCloudIntelligenceService(
            settings=self.settings,
            db=self.db,
            model_manager=default_mm,
            orchestrator=default_orch,
            tool_registry=self.tools,
            autonomy_policy=self.autonomy_policy,
            resource_monitor=self.resources,
            redactor=self.redactor,
            knowledge_store=self.knowledge,
            offline_coordinator=self.offline,
            app_root=resolved_repo,
        )
        register_hybrid_cloud_tools(self.tools, self.hybrid_cloud)
        self.kali_intel = KaliIntelligenceService(
            db=self.db,
            workspace_dir=workspace_dir,
            knowledge_store=self.knowledge,
            autonomy_policy=self.autonomy_policy,
            hybrid_cloud=self.hybrid_cloud,
            redactor=self.redactor,
        )
        for ki_tool in build_kali_intel_tools(lambda: self.kali_intel):
            if self.tools.get(ki_tool.name) is None:
                self.tools.register(ki_tool)
        self.cyber_division = CybersecurityEngineeringDivision(
            db=self.db,
            workspace_dir=workspace_dir,
            kali_intel=self.kali_intel,
            knowledge_store=self.knowledge,
            tool_registry=self.tools,
            hybrid_cloud=self.hybrid_cloud,
        )
        for cy_tool in build_cyber_division_tools(lambda: self.cyber_division):
            if self.tools.get(cy_tool.name) is None:
                self.tools.register(cy_tool)
        self.acquisition_migration = AutonomousAcquisitionAndMigrationService(
            db=self.db,
            workspace_dir=workspace_dir,
            kali_intel=self.kali_intel,
            capabilities=self.capabilities,
            tool_registry=self.tools,
        )
        for am_tool in build_acquisition_migration_tools(lambda: self.acquisition_migration):
            if self.tools.get(am_tool.name) is None:
                self.tools.register(am_tool)
        self.general_intelligence = GeneralIntelligenceService(
            db=self.db,
            workspace_dir=workspace_dir,
            data_dir=data_dir,
            knowledge=self.knowledge,
            redactor=self.redactor,
            capabilities=self.capabilities,
            tool_registry=self.tools,
            improvement_engine=self.improvement,
            acquisition_service=self.acquisition_migration,
            cyber_division=self.cyber_division,
            creation_engine=self.creation,
        )
        for gi_tool in build_general_intelligence_tools(lambda: self.general_intelligence):
            if self.tools.get(gi_tool.name) is None:
                self.tools.register(gi_tool)
        self.personal_policy = PersonalSecurityAndAutonomyService(
            db=self.db,
            workspace_dir=workspace_dir,
            redactor=self.redactor,
            autonomy_policy=self.autonomy_policy,
            cyber_division=self.cyber_division,
        )
        for pp_tool in build_personal_policy_tools(lambda: self.personal_policy):
            if self.tools.get(pp_tool.name) is None:
                self.tools.register(pp_tool)
        self.cyber_intelligence = NextGenCyberIntelligenceService(
            db=self.db,
            workspace_dir=workspace_dir,
            cyber_division=self.cyber_division,
            personal_policy=self.personal_policy,
            kali_intel=self.kali_intel,
            knowledge_store=self.knowledge,
            tool_registry=self.tools,
            resource_manager=self.resources,
        )
        for ci_tool in build_cyber_intelligence_tools(lambda: self.cyber_intelligence):
            if self.tools.get(ci_tool.name) is None:
                self.tools.register(ci_tool)

    def _register_baseline_integrations(self) -> None:
        self.gateway.register(
            IntegrationRecord(
                integration_id="primary_ai_provider",
                kind="ai_provider",
                label="Primary OpenAI-Compatible Provider",
                capabilities=self.settings.ai_model_capabilities,
                supported_operations={"chat.completions": "inference:chat"},
                minimum_scopes=("inference:chat",),
                granted_scopes=("inference:chat",) if self.settings.ai_configured else (),
                credentials_present=self.settings.ai_configured,
                rate_limit_per_minute=self.settings.max_ai_requests_per_minute,
            )
        )
        self.gateway.register(
            IntegrationRecord(
                integration_id="tavily_search",
                kind="external_service",
                label="Tavily Web Research",
                capabilities=("web_search",),
                supported_operations={"web.search": "search:query"},
                minimum_scopes=("search:query",),
                granted_scopes=("search:query",) if bool(self.settings.tavily_api_key) else (),
                credentials_present=bool(self.settings.tavily_api_key),
                rate_limit_per_minute=20,
            )
        )

    async def safe_emit_event(self, event_type: str, source: str, *, task_id: str = "", payload: dict[str, Any] | None = None) -> None:
        """Emit an event without ever allowing a bus error to disrupt task execution."""
        try:
            await self.events.emit(
                Event(
                    type=event_type,
                    source=source,
                    occurred_at=_iso(),
                    task_id=task_id,
                    payload=self.redactor.scrub(dict(payload or {})),
                )
            )
        except Exception as exc:
            self.errors += 1
            self.last_error = f"{type(exc).__name__}: {exc}"
            logger.warning("platform event emit failed safely (%s)", self.last_error)

    def safe_record_span(self, **kwargs: Any) -> None:
        try:
            self.traces.record(**kwargs)
        except Exception as exc:
            self.errors += 1
            self.last_error = f"{type(exc).__name__}: {exc}"

    def summary(self) -> dict[str, Any]:
        """Compact, secret-free summary for health & UI surfaces."""
        sbx_cap = self.sandbox.detect()
        budget = self.resources.assess()
        return {
            "degraded": bool(self.errors),
            "errors": self.errors,
            "operation_mode": self.offline.mode,
            "resource_pressure": budget.pressure,
            "sandbox_mechanism": sbx_cap.mechanism,
            "sandbox_available": sbx_cap.available,
            "fts5_available": self.knowledge.fts_available,
            "plugins_installed": len(self.plugins.list_plugins()),
            "mcp_servers_registered": len(self.mcp.list_servers()),
            "event_bus": self.events.stats(),
            "observability": self.traces.stats(),
            "creation": self.creation.summary(),
            "memory_enabled": self.memory.is_enabled(),
            "desktop_session": self.desktop_control.inspect_session().display_server,
            "worker_status": self.unified_os.worker.status()["status"],
            "system_access": self.system_access.health_summary(),
            "privacy_intel": {
                "tor_enabled": bool(self.privacy_intel.tor.get_config()["tor_enabled"]),
                "onion_hosting_enabled": bool(self.privacy_intel.tor.get_config()["onion_hosting_enabled"]),
            },
            "personal_policy": self.personal_policy.status_summary(),
            "cyber_intelligence": self.cyber_intelligence.status_summary(),
            "recommendations": [item.to_dict() for item in recommendation_catalogue()],
        }

    @staticmethod
    def prioritize_recommendations(scores: dict[str, dict[str, Any]], *, goals: tuple[str, ...] = ()) -> list[dict[str, Any]]:
        return [item.to_dict() for item in prioritize(scores, goals=goals)]


__all__ = ["PlatformService"]
