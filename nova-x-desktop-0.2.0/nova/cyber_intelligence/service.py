"""§261–§275 Unified Next-Generation Autonomous Cyber Intelligence Service."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from nova.cyber_intelligence.benchmarking_improvement_frontier import (
    BENCHMARK_12_METRICS,
    KNOWLEDGE_FRONTIER_11_CATEGORIES,
    ContinuousCybersecurityImprover,
    CybersecurityBenchmarkSuite,
    SecurityResearchKnowledgeFrontier,
)
from nova.cyber_intelligence.invention_multimodel_memory import (
    GENERALIZATION_6_FAMILIES,
    LEGITIMATE_TOOL_7_CATEGORIES,
    RESEARCH_MEMORY_13_TYPES,
    SPECIALIST_9_ROLES,
    TOOL_INVENTION_12_STEPS,
    AdvancedSecurityResearchMemory,
    AutonomousSecurityToolInventor,
    MultiModelCyberIntelligenceCouncil,
    SecurityKnowledgeGeneralizer,
)
from nova.cyber_intelligence.missions_labs_decisions import (
    DECISION_9_FACTORS,
    MISSION_12_STAGES,
    SECURE_LAB_10_ENVIRONMENT_CAPABILITIES,
    AutonomousSecurityMissionSystem,
    IntelligentSecurityDecisionEngine,
    SecureLabAndExperimentationEngine,
)
from nova.cyber_intelligence.unknown_and_vuln_lab import (
    EXPLOITABILITY_LAB_10_CAPABILITIES,
    FORBIDDEN_WEAPONIZATION_INTENTS,
    OFFENSIVE_RESEARCH_16_SPECIALTIES,
    UNKNOWN_PROBLEM_15_STEPS,
    VULN_LAB_13_CATEGORIES,
    AuthorizedOffensiveMethodologyEngine,
    AutonomousVulnerabilityResearchLab,
    ControlledExploitabilityAndPatchLab,
    UnknownProblemMasteryEngine,
)
from nova.db import Database


class NextGenCyberIntelligenceService:
    """§261–§275 Scientific cybersecurity research, unknown-problem mastery & autonomous security engineering."""

    SECTIONS = "261-275"
    MERE_HACKING_TOOL_RUNNER = False
    SCIENTIFIC_SECURITY_ENGINEERING = True

    def __init__(
        self,
        *,
        db: Database,
        workspace_dir: Path,
        cyber_division: Any | None = None,
        personal_policy: Any | None = None,
        kali_intel: Any | None = None,
        knowledge_store: Any | None = None,
        tool_registry: Any | None = None,
        resource_manager: Any | None = None,
    ) -> None:
        self.db = db
        self.workspace_dir = Path(workspace_dir)
        self.cyber_division = cyber_division
        self.personal_policy = personal_policy

        # §266 & §268
        self.specialist_council = MultiModelCyberIntelligenceCouncil()
        self.research_memory = AdvancedSecurityResearchMemory(db=db, knowledge_store=knowledge_store)

        # §261, §262, §263 & §264
        self.unknown_mastery = UnknownProblemMasteryEngine(
            db=db,
            workspace_dir=self.workspace_dir,
            kali_intel=kali_intel,
            knowledge_store=knowledge_store,
            specialist_council=self.specialist_council,
        )
        self.vuln_lab = AutonomousVulnerabilityResearchLab(
            db=db,
            workspace_dir=self.workspace_dir,
            research_memory=self.research_memory,
        )
        scope_reg = getattr(cyber_division, "scope_registry", None)
        pers_cyber = getattr(personal_policy, "cyber_research", None)
        self.methodology_engine = AuthorizedOffensiveMethodologyEngine(
            scope_registry=scope_reg,
            personal_cyber=pers_cyber,
            vuln_lab=self.vuln_lab,
        )
        self.exploitability_lab = ControlledExploitabilityAndPatchLab(
            db=db,
            scope_checker=self.methodology_engine,
        )

        # §265 & §267
        self.tool_inventor = AutonomousSecurityToolInventor(
            db=db,
            workspace_dir=self.workspace_dir,
            tool_registry=tool_registry,
            research_memory=self.research_memory,
        )
        self.generalizer = SecurityKnowledgeGeneralizer(db=db)

        # §269, §270 & §271
        self.decision_engine = IntelligentSecurityDecisionEngine(
            methodology_engine=self.methodology_engine,
            resource_manager=resource_manager,
        )
        self.secure_lab = SecureLabAndExperimentationEngine(
            db=db,
            workspace_dir=self.workspace_dir,
            resource_manager=resource_manager,
        )
        self.mission_system = AutonomousSecurityMissionSystem(
            db=db,
            decision_engine=self.decision_engine,
            vuln_lab=self.vuln_lab,
            cyber_division=cyber_division,
        )

        # §272, §273 & §274
        self.benchmarks = CybersecurityBenchmarkSuite(
            db=db,
            vuln_lab=self.vuln_lab,
            mission_system=self.mission_system,
        )
        self.improver = ContinuousCybersecurityImprover(
            db=db,
            benchmark_suite=self.benchmarks,
            tool_inventor=self.tool_inventor,
            research_memory=self.research_memory,
        )
        self.knowledge_frontier = SecurityResearchKnowledgeFrontier(
            db=db,
            scope_registry=scope_reg,
        )

    def capability_manifest(self) -> dict[str, Any]:
        return {
            "sections": self.SECTIONS,
            "scientific_security_engineering": self.SCIENTIFIC_SECURITY_ENGINEERING,
            "mere_hacking_tool_runner": self.MERE_HACKING_TOOL_RUNNER,
            "unknown_problem_15_steps": list(UNKNOWN_PROBLEM_15_STEPS),
            "vuln_lab_13_categories": list(VULN_LAB_13_CATEGORIES),
            "offensive_research_16_specialties": list(OFFENSIVE_RESEARCH_16_SPECIALTIES),
            "exploitability_lab_10_capabilities": list(EXPLOITABILITY_LAB_10_CAPABILITIES),
            "forbidden_weaponization_intents": list(FORBIDDEN_WEAPONIZATION_INTENTS),
            "tool_invention_12_steps": list(TOOL_INVENTION_12_STEPS),
            "legitimate_tool_7_categories": list(LEGITIMATE_TOOL_7_CATEGORIES),
            "specialist_9_roles": list(SPECIALIST_9_ROLES),
            "generalization_6_families": list(GENERALIZATION_6_FAMILIES),
            "research_memory_13_types": list(RESEARCH_MEMORY_13_TYPES),
            "mission_12_stages": list(MISSION_12_STAGES),
            "secure_lab_10_capabilities": list(SECURE_LAB_10_ENVIRONMENT_CAPABILITIES),
            "decision_9_factors": list(DECISION_9_FACTORS),
            "benchmark_12_metrics": list(BENCHMARK_12_METRICS),
            "knowledge_frontier_11_categories": list(KNOWLEDGE_FRONTIER_11_CATEGORIES),
        }

    def status_summary(self) -> dict[str, Any]:
        return {
            "sections": self.SECTIONS,
            "scientific_security_engineering": self.SCIENTIFIC_SECURITY_ENGINEERING,
            "mere_hacking_tool_runner": self.MERE_HACKING_TOOL_RUNNER,
            "unknown_investigations_count": len(self.db.list_cyber_intel_investigations(limit=200)),
            "vuln_lab_cases_count": len(self.db.list_cyber_intel_vuln_cases(limit=200)),
            "invented_tools_count": len(self.db.list_cyber_intel_invented_tools(active_only=True)),
            "generalized_procedures_count": len(self.db.list_cyber_intel_procedures(limit=200)),
            "research_memory_records_count": len(self.db.list_cyber_intel_memory_records(limit=500)),
            "completed_missions_count": len(self.db.list_cyber_intel_missions(limit=200)),
            "benchmark_runs_count": len(self.db.list_cyber_intel_benchmark_runs(limit=100)),
            "frontier_items_count": len(self.db.list_cyber_intel_frontier_items(limit=300)),
        }
