"""Unified Kali Intelligence Layer Facade (§181–§200) inside DEV's single local architecture."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from nova.db import Database
from nova.kali_intel.community_and_research import (
    KaliCommunityForumIntelligence,
    TechnicalResearchVerifier,
)
from nova.kali_intel.cyber_labs_and_education import (
    AutonomousCyberLabManager,
    CybersecurityKnowledgeBase,
    KaliTrainingAcademy,
    KaliTroubleshootingEngine,
)
from nova.kali_intel.dev_env_and_evolution import (
    SelfImprovingKaliExpertise,
    UniversalDevEnvironmentPartner,
)
from nova.kali_intel.system_model import (
    KaliPackageIntelligence,
    KaliSystemKnowledgeModel,
)
from nova.kali_intel.tool_and_doc_engine import (
    AutomaticDocumentationEngine,
    IntelligentToolSelectorAndExecutor,
    KaliToolIntelligenceEngine,
)
from nova.kali_intel.universal_apps_and_chaining import (
    IntelligentProgramLearner,
    MultiAppWorkflowAndChainEngine,
    UniversalApplicationRegistry,
)
from nova.knowledge import KnowledgeStore
from nova.observability import Redactor


class KaliIntelligenceService:
    """§181–§200 Unified Kali Linux Intelligence, Application Mastery, and Universal Software Integration layer."""

    UNIFIED_SINGLE_ARCHITECTURE = True

    def __init__(
        self,
        *,
        db: Database,
        workspace_dir: Path,
        knowledge_store: KnowledgeStore | None = None,
        autonomy_policy: Any = None,
        cognition: Any = None,
        hybrid_cloud: Any = None,
        redactor: Redactor | None = None,
    ):
        self.db = db
        self.workspace_dir = workspace_dir
        self.knowledge_store = knowledge_store
        self.autonomy_policy = autonomy_policy
        self.cognition = cognition
        self.hybrid_cloud = hybrid_cloud
        self.redactor = redactor or Redactor()

        # §181 & §190
        self.system_model = KaliSystemKnowledgeModel(db=db, redactor=self.redactor)
        self.package_intel = KaliPackageIntelligence(system_model=self.system_model)

        # §182, §183, §184 & §191
        self.doc_engine = AutomaticDocumentationEngine(
            db=db,
            system_model=self.system_model,
            knowledge_store=knowledge_store,
        )
        self.tool_engine = KaliToolIntelligenceEngine(
            db=db,
            system_model=self.system_model,
            package_intel=self.package_intel,
            doc_engine=self.doc_engine,
        )
        self.tool_executor = IntelligentToolSelectorAndExecutor(
            db=db,
            tool_engine=self.tool_engine,
            doc_engine=self.doc_engine,
            autonomy_policy=autonomy_policy,
            cognition=cognition,
        )

        # §185 & §197
        self.community_intel = KaliCommunityForumIntelligence(
            db=db,
            system_model=self.system_model,
            doc_engine=self.doc_engine,
            redactor=self.redactor,
        )
        self.research_verifier = TechnicalResearchVerifier(
            db=db,
            doc_engine=self.doc_engine,
        )

        # §186, §187, §194, §196 & §198
        self.app_registry = UniversalApplicationRegistry(
            db=db,
            system_model=self.system_model,
            package_intel=self.package_intel,
            doc_engine=self.doc_engine,
        )
        self.program_learner = IntelligentProgramLearner(
            db=db,
            package_intel=self.package_intel,
            doc_engine=self.doc_engine,
        )
        self.chain_engine = MultiAppWorkflowAndChainEngine(
            db=db,
            workspace_dir=workspace_dir,
        )

        # §188, §189, §192 & §193
        self.cyber_kb = CybersecurityKnowledgeBase(
            system_model=self.system_model,
            doc_engine=self.doc_engine,
        )
        self.lab_manager = AutonomousCyberLabManager(
            db=db,
            system_model=self.system_model,
            cyber_kb=self.cyber_kb,
            workspace_dir=workspace_dir,
        )
        self.training_academy = KaliTrainingAcademy(
            db=db,
            system_model=self.system_model,
        )
        self.troubleshooter = KaliTroubleshootingEngine(
            db=db,
            system_model=self.system_model,
            package_intel=self.package_intel,
            doc_engine=self.doc_engine,
        )

        # §195 & §199
        self.dev_partner = UniversalDevEnvironmentPartner(workspace_dir=workspace_dir)
        self.expertise_evolution = SelfImprovingKaliExpertise(db=db)

    def status_summary(self) -> dict[str, Any]:
        """Lightweight health/status snapshot without mutating host state."""
        latest_sys = self.db.latest_kali_system_snapshot()
        profiles = self.db.list_kali_tool_profiles(limit=200)
        docs = self.db.search_kali_knowledge_docs(limit=200)
        labs = self.db.list_kali_cyber_labs()
        training = self.db.list_kali_training_progress()
        revisions = self.db.list_kali_expertise_revisions(limit=100)
        return {
            "sections_implemented": "181-200",
            "unified_single_architecture": True,
            "frontier_gateway_connected": self.hybrid_cloud is not None,
            "system_snapshot_cached": latest_sys is not None,
            "distro": latest_sys["distro_id"] if latest_sys else "uninspected",
            "indexed_tool_and_app_profiles": len(profiles),
            "indexed_knowledge_documents": len(docs),
            "managed_cyber_labs": len(labs),
            "training_topics_tracked": len(training),
            "expertise_revisions": len(revisions),
        }

    async def cloud_assisted_kali_guidance(self, question: str) -> dict[str, Any]:
        """Combine real local host inspection + local docs with privacy-scrubbed frontier AI synthesis when available."""
        env = self.system_model.get_or_refresh_model()["model"]
        discovery = self.tool_engine.search_tools_for_objective(question)
        diag = self.troubleshooter.diagnose_13_steps(question)
        cloud_synthesis: dict[str, Any] = {"used_cloud": False, "text": ""}
        if self.hybrid_cloud is not None:
            coord = getattr(self.hybrid_cloud, "kali_diagnostic_coordinator", None)
            if coord is not None and hasattr(coord, "diagnose"):
                try:
                    res = await coord.diagnose(question)
                    cloud_synthesis = {
                        "used_cloud": bool(res.get("cloud_used")),
                        "text": str(res.get("synthesis") or ""),
                    }
                except Exception as exc:
                    cloud_synthesis = {"used_cloud": False, "error": str(exc)}
        return {
            "question": question,
            "local_distro": env["distribution"]["pretty_name"],
            "recommended_installed_tool": discovery["recommended_tool"],
            "local_diagnostic_domain": diag["classified_domain"],
            "cloud_synthesis": cloud_synthesis,
        }
