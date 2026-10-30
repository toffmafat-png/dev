"""§165 Unified Privacy-Network, Tor, OSINT & Defensive Threat-Intelligence Service."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from nova.db import Database
from nova.knowledge import KnowledgeStore
from nova.memory_hub import SharedMemorySystem
from nova.observability import Redactor
from nova.privacy_intel.search_and_research import (
    ALL_SOURCE_CATEGORIES,
    AutonomousResearchMonitor,
    DarkWebResearchAssistant,
    UnifiedSearchOrchestrator,
)
from nova.privacy_intel.threat_and_files import (
    AUTO_OPEN_EXECUTE_OR_INSTALL_DOWNLOADS,
    CLAIM_BREACH_FROM_UNVERIFIED_POST,
    COLLECT_OR_USE_STOLEN_CREDENTIALS,
    OrganizationalExposureMonitor,
    SecureDownloadAndAnalysisPipeline,
    ThreatIntelligenceAnalyzer,
    check_request_ethics_guardrail,
)
from nova.privacy_intel.tor_network import (
    ASSUME_SYSTEM_WIDE_TOR_ROUTING,
    BYPASS_ACCESS_CONTROLS_OR_CAPTCHAS,
    EXPOSE_NOVA_ADMIN_AS_ONION_BY_DEFAULT,
    PROMISE_PERFECT_ANONYMITY,
    REACHABILITY_IMPLIES_TRUST,
    SILENT_SYSTEM_NETWORK_MUTATION,
    OnionServiceBrowser,
    OptionalOnionHostingHelper,
    TorIntegrationManager,
)
from nova.system_access.remote import ProtectedCredentialVault


class PrivacyIntelligenceService:
    """§165 Coordinator integrating Tor, `.onion` research, 11-category OSINT search,
    12-step Dark-Web Research Assistant, defensive threat intel, quarantined file
    analysis, optional onion hosting, and restart-persistent research monitors.

    Constructed lazily without filesystem `mkdir()` or unguarded SQLite queries in
    `__init__` so `create_app()` import-time checks stay completely side-effect-free.
    """

    def __init__(
        self,
        *,
        db: Database,
        knowledge: KnowledgeStore,
        memory_os: SharedMemorySystem,
        vault: ProtectedCredentialVault,
        state_dir: Path,
        workspace_dir: Path,
        redactor: Redactor,
        cognition: Any | None = None,
        scheduler_active_probe: Callable[[], bool] | None = None,
        resource_manager: Any | None = None,
    ) -> None:
        self.db = db
        self.knowledge = knowledge
        self.memory_os = memory_os
        self.vault = vault
        self.state_dir = state_dir
        self.workspace_dir = workspace_dir
        self.redactor = redactor

        self.tor = TorIntegrationManager(db=db, redactor=redactor)
        self.onion_browser = OnionServiceBrowser(db=db, tor_manager=self.tor, redactor=redactor)
        self.onion_hosting = OptionalOnionHostingHelper(db=db, tor_manager=self.tor, vault=vault, state_dir=state_dir)
        self.search = UnifiedSearchOrchestrator(
            db=db,
            knowledge=knowledge,
            tor_manager=self.tor,
            onion_browser=self.onion_browser,
            workspace_dir=workspace_dir,
            redactor=redactor,
        )
        self.research_assistant = DarkWebResearchAssistant(
            db=db,
            search_orchestrator=self.search,
            onion_browser=self.onion_browser,
            knowledge=knowledge,
            memory_os=memory_os,
            redactor=redactor,
            cognition=cognition,
        )
        self.threat_intel = ThreatIntelligenceAnalyzer(db=db, redactor=redactor)
        self.exposure_monitor = OrganizationalExposureMonitor(db=db, redactor=redactor)
        self.downloads = SecureDownloadAndAnalysisPipeline(
            db=db,
            tor_manager=self.tor,
            onion_browser=self.onion_browser,
            state_dir=state_dir,
            redactor=redactor,
        )
        self.monitors = AutonomousResearchMonitor(
            db=db,
            search_orchestrator=self.search,
            scheduler_active_probe=scheduler_active_probe,
            resource_manager=resource_manager,
        )

    def plan_intelligence_routing(
        self,
        objective: str,
        *,
        registered_tool_names: list[str] | None = None,
    ) -> dict[str, Any]:
        """§165.11 Determine which of the 8 intelligence/source dimensions a task needs
        and select the smallest sufficient collection of registered tools.
        """
        ol = objective.lower()
        needs = {
            "ordinary_web_search": any(k in ol for k in ("http://", "https://", "website", "search web", "news", "public web")) and ".onion" not in ol,
            "official_documentation": any(k in ol for k in ("docs", "documentation", "manual", "rfc", "specification", "api reference")),
            "permitted_onion_service": any(k in ol for k in (".onion", "onion service", "tor hidden", "dark web")),
            "cybersecurity_intelligence": any(k in ol for k in ("cve-", "advisory", "vulnerability", "ioc", "threat", "breach", "exposure", "malware")),
            "local_file": any(k in ol for k in ("workspace", "file", "read ", "write ", "archive", ".txt", ".md", ".py", ".json", ".log")),
            "specialist_model": any(k in ol for k in ("compare models", "review", "deep analysis", "synthesize", "verify hypothesis")),
            "local_diagnostic_tool": any(k in ol for k in ("hardware", "driver", "cpu", "memory", "tor status", "diagnostics", "disk")),
            "remote_service_connection": any(k in ol for k in ("ssh", "remote server", "remote node", "registered server")),
        }
        if not any(needs.values()):
            needs["local_file"] = True

        candidate_tools: list[str] = []
        if needs["ordinary_web_search"] or needs["official_documentation"]:
            candidate_tools.extend(["research.web_search", "advanced_internet_search"])
        if needs["permitted_onion_service"]:
            candidate_tools.extend(["tor_status_and_dashboard", "onion_open_page", "onion_verify_reference", "dark_web_research_report"])
        if needs["cybersecurity_intelligence"]:
            candidate_tools.extend(["threat_intel_analyze", "advanced_internet_search", "dark_web_research_report"])
        if needs["local_file"]:
            candidate_tools.extend(["workspace.list_files", "workspace.read_file", "workspace.write_file"])
        if needs["local_diagnostic_tool"]:
            candidate_tools.extend(["tor_status_and_dashboard", "hardware_explore", "system_health_observability"])
        if needs["remote_service_connection"]:
            candidate_tools.append("remote_servers_audit")

        available_set = set(registered_tool_names) if registered_tool_names is not None else None
        minimum_tools: list[str] = []
        for t in candidate_tools:
            if t not in minimum_tools and (available_set is None or t in available_set):
                minimum_tools.append(t)

        return {
            "needs": needs,
            "minimum_sufficient_tools": minimum_tools,
            "invokes_tor": bool(needs["permitted_onion_service"] and self.tor.get_config()["tor_enabled"]),
            "requires_specialist_model_review": needs["specialist_model"] or needs["cybersecurity_intelligence"],
            "policy_bypass_allowed": False,
        }

    def check_ethics(self, text: str) -> dict[str, Any]:
        return check_request_ethics_guardrail(text)

    def status_summary(self) -> dict[str, Any]:
        """Full §165 operational & safety telemetry snapshot for `/api/health`, `/api/privacy/status`, CLI & Qt UI."""
        dashboard = self.tor.privacy_dashboard()
        mon_snap = self.monitors.status_snapshot()
        bookmarks = self.db.list_onion_bookmarks(limit=25)
        recent_searches = self.db.list_internet_search_runs(limit=15)
        findings = self.db.list_threat_intel_findings(limit=25)
        quarantine = self.db.list_quarantined_downloads(limit=20)
        hosting_plans = self.db.list_onion_hosting_plans()

        return {
            "section": "165",
            "tor_status": self.tor.detect_installation_and_status(),
            "privacy_dashboard": dashboard,
            "supported_search_categories": list(ALL_SOURCE_CATEGORIES),
            "onion_bookmarks_count": len(bookmarks),
            "onion_bookmarks": bookmarks,
            "recent_searches": recent_searches,
            "threat_findings_count": len(findings),
            "threat_findings": findings,
            "quarantined_downloads_count": len(quarantine),
            "quarantined_downloads": quarantine,
            "onion_hosting_enabled": bool(self.tor.get_config()["onion_hosting_enabled"]),
            "onion_hosting_plans": [{k: v for k, v in p.items() if k != "key_vault_ref"} for p in hosting_plans],
            "research_monitors": mon_snap,
            "hard_invariants": {
                "assume_system_wide_tor_routing": ASSUME_SYSTEM_WIDE_TOR_ROUTING,
                "silent_system_network_mutation": SILENT_SYSTEM_NETWORK_MUTATION,
                "reachability_implies_trust": REACHABILITY_IMPLIES_TRUST,
                "bypass_access_controls_or_captchas": BYPASS_ACCESS_CONTROLS_OR_CAPTCHAS,
                "promise_perfect_anonymity": PROMISE_PERFECT_ANONYMITY,
                "expose_nova_admin_as_onion_by_default": EXPOSE_NOVA_ADMIN_AS_ONION_BY_DEFAULT,
                "collect_or_use_stolen_credentials": COLLECT_OR_USE_STOLEN_CREDENTIALS,
                "claim_breach_from_unverified_post": CLAIM_BREACH_FROM_UNVERIFIED_POST,
                "auto_open_execute_or_install_downloads": AUTO_OPEN_EXECUTE_OR_INSTALL_DOWNLOADS,
            },
        }
