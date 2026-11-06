"""Unified Self-Engineering Service (§276–§295) for DEV."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from nova.db import Database
from nova.self_engineering.assistant_deps_roadmap import (
    DEPENDENCY_10_DIMENSIONS,
    ENGINEERING_ASSISTANT_14_STEPS,
    AutonomousEngineeringAssistant,
    ContinuousArchitecturalImprovementEngine,
    SelfMaintainingDependencyIntelligence,
)
from nova.self_engineering.code_intel_and_arch import (
    ARCH_ANALYSIS_16_DIMENSIONS,
    ARCH_GRAPH_14_ENTITY_KINDS,
    SELF_ENGINEERING_11_ROLES,
    SOURCE_INTEL_20_DOMAINS,
    ArchitectureKnowledgeGraph,
    AutonomousArchitecturalAnalyzer,
    SelfSourceCodeIntelligenceEngine,
)
from nova.self_engineering.modification_modules_perf import (
    DYNAMIC_MODULE_11_STEPS,
    GOVERNANCE_6_ZONES,
    IMMUTABLE_SELF_MODIFICATION_LAWS,
    MODULE_MANIFEST_12_FIELDS,
    PERFORMANCE_12_METRICS,
    AutonomousPerformanceEngineer,
    AutonomousSourceModifier,
    DynamicModuleAndPluginLifecycle,
    SelfModificationGovernance,
)
from nova.self_engineering.recovery_launcher import run_standalone_recovery
from nova.self_engineering.scale_storage_release_qa import (
    DB_MIGRATION_10_STEPS,
    PLACEMENT_9_FACTORS,
    QA_13_TESTING_TYPES,
    RELEASE_3_CHANNELS,
    REPAIR_10_FAILURE_CLASSES,
    SCALABLE_8_NODE_KINDS,
    DatabaseSelfMigrationEngine,
    IndependentQATestEngine,
    ReleaseAndSelfUpdateEngine,
    ScalableArchitectureCoordinator,
    SelfRepairAndRecoveryEngine,
)


class SelfEngineeringService:
    """§276–§295 Autonomous Architecture, Source Code Evolution & Self-Engineering Engine."""

    def __init__(
        self,
        *,
        db: Database,
        repo_root: Path | None = None,
        data_dir: Path | None = None,
        resource_manager: Any | None = None,
        capabilities: Any | None = None,
        tool_registry: Any | None = None,
    ) -> None:
        self.db = db
        self.repo_root = Path(repo_root or Path(__file__).resolve().parents[2]).resolve()
        self.data_dir = Path(data_dir or self.db.path.parent).resolve()

        self.governance = SelfModificationGovernance()
        self.knowledge_graph = ArchitectureKnowledgeGraph(repo_root=self.repo_root)
        self.source_intel = SelfSourceCodeIntelligenceEngine(
            repo_root=self.repo_root,
            arch_graph=self.knowledge_graph,
        )
        self.arch_analyzer = AutonomousArchitecturalAnalyzer(
            db=self.db,
            repo_root=self.repo_root,
            arch_graph=self.knowledge_graph,
        )
        self.source_modifier = AutonomousSourceModifier(
            db=self.db,
            data_dir=self.data_dir,
            target_project_root=self.repo_root,
            arch_graph=self.knowledge_graph,
            governance=self.governance,
        )
        self.dynamic_modules = DynamicModuleAndPluginLifecycle(
            db=self.db,
            data_dir=self.data_dir,
            capabilities=capabilities,
            tool_registry=tool_registry,
        )
        self.perf_engineer = AutonomousPerformanceEngineer(db=self.db)
        self.scalable_coordinator = ScalableArchitectureCoordinator(resource_manager=resource_manager)
        self.db_migrations = DatabaseSelfMigrationEngine(db=self.db, data_dir=self.data_dir)
        self.qa_engine = IndependentQATestEngine(db=self.db)
        self.release_engine = ReleaseAndSelfUpdateEngine(db=self.db, data_dir=self.data_dir)
        self.self_repair = SelfRepairAndRecoveryEngine(db=self.db, release_engine=self.release_engine)
        self.dep_intel = SelfMaintainingDependencyIntelligence(repo_root=self.repo_root)
        self.roadmap_engine = ContinuousArchitecturalImprovementEngine(
            db=self.db,
            arch_analyzer=self.arch_analyzer,
            dep_intel=self.dep_intel,
        )
        self.engineering_assistant = AutonomousEngineeringAssistant(
            db=self.db,
            source_intel=self.source_intel,
            arch_analyzer=self.arch_analyzer,
            source_modifier=self.source_modifier,
            perf_engineer=self.perf_engineer,
            dep_intel=self.dep_intel,
        )

    def run_recovery_launcher(self, *, restore_version: str = "") -> dict[str, Any]:
        return run_standalone_recovery(
            data_dir=self.data_dir,
            db_path=self.db.path,
            restore_version=restore_version,
        )

    def status_summary(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "sections_covered": "276-295",
            "engineering_roles": list(SELF_ENGINEERING_11_ROLES),
            "source_intel_domains": len(SOURCE_INTEL_20_DOMAINS),
            "architecture_dimensions": len(ARCH_ANALYSIS_16_DIMENSIONS),
            "knowledge_graph_entity_kinds": len(ARCH_GRAPH_14_ENTITY_KINDS),
            "dynamic_module_manifest_fields": len(MODULE_MANIFEST_12_FIELDS),
            "dynamic_module_lifecycle_steps": len(DYNAMIC_MODULE_11_STEPS),
            "performance_metrics_count": len(PERFORMANCE_12_METRICS),
            "scalable_node_kinds": len(SCALABLE_8_NODE_KINDS),
            "placement_factors": len(PLACEMENT_9_FACTORS),
            "db_migration_steps": len(DB_MIGRATION_10_STEPS),
            "release_channels": list(RELEASE_3_CHANNELS),
            "qa_testing_types": len(QA_13_TESTING_TYPES),
            "repair_failure_classes": len(REPAIR_10_FAILURE_CLASSES),
            "engineering_assistant_steps": len(ENGINEERING_ASSISTANT_14_STEPS),
            "dependency_dimensions": len(DEPENDENCY_10_DIMENSIONS),
            "governance_zones": list(GOVERNANCE_6_ZONES),
            "immutable_laws": list(IMMUTABLE_SELF_MODIFICATION_LAWS),
            "active_stable_release": self.release_engine.active_version("stable"),
            "registered_dynamic_modules": len(self.db.list_self_eng_dynamic_modules()),
            "recorded_adrs": len(self.db.list_self_eng_adrs(limit=50)),
            "recorded_change_sets": len(self.db.list_self_eng_change_sets(limit=50)),
        }
