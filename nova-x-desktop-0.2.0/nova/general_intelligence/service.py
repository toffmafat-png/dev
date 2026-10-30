"""§236–§260 Unified General Intelligence, Cognitive Architecture & Capability Expansion Service."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from nova.capabilities import CapabilityRegistry
from nova.db import Database
from nova.general_intelligence.cognitive_and_memory import (
    COGNITIVE_11_SUBSYSTEMS,
    MEMORY_11_LAYERS,
    WORLD_15_DOMAINS,
    DynamicEnvironmentWorldModel,
    MultiLayerMemoryAndProvenanceEngine,
    UnifiedCognitiveArchitecture,
)
from nova.general_intelligence.collective_durable_distributed import (
    NODE_8_KINDS,
    SPECIALIST_12_ROLES,
    CollectiveAgentCoordinator,
    DistributedNodeOrchestrator,
    DurableExecutionEngine,
)
from nova.general_intelligence.evolution_reliability_governance import (
    ADVERTISE_AGI_OR_HUMAN_LEVEL,
    AI_SECURITY_11_CONTROLS,
    ALLOW_AUTOMATIC_PURCHASES_OR_SUBSCRIPTIONS,
    ALLOW_SELF_PERMISSION_EXPANSION,
    CLAIMS_FRONTIER_WEIGHT_RETRAINING,
    EVALUATION_17_DIMENSIONS,
    EVOLUTION_11_DIMENSIONS,
    RELIABILITY_4_FAILURE_DOMAINS,
    RELIABILITY_15_CONTROLS,
    AISecurityAndGovernanceEngine,
    CapabilityExpansionAndOptimizationHub,
    EvolutionLaboratory,
    IndependentGIEvaluationLab,
    ReliabilityAndFaultToleranceManager,
    UserAlignmentAndOversightController,
)
from nova.general_intelligence.learning_research_multimodal import (
    ContinualSkillAcquisitionEngine,
    CrossDomainTransferEngine,
    ScientificDiscoveryLab,
    UnifiedMultimodalEngine,
)
from nova.general_intelligence.reasoning_metacog_planning import (
    EPISTEMIC_6_LEVELS,
    AutonomousObjectiveGenerator,
    LongTermStrategicPlanner,
    MetacognitiveCalibrationEngine,
    ScientificCausalReasoningEngine,
)
from nova.knowledge import KnowledgeStore
from nova.observability import Redactor
from nova.self_improvement import ControlledImprovementEngine
from nova.tools.registry import ToolRegistry


class GeneralIntelligenceService:
    """Single coordinated facade across Sections 236–260 integrated into PlatformService and DesktopRuntime."""

    def __init__(
        self,
        *,
        db: Database,
        workspace_dir: Path,
        data_dir: Path | None = None,
        knowledge: KnowledgeStore | None = None,
        redactor: Redactor | None = None,
        capabilities: CapabilityRegistry | None = None,
        tool_registry: ToolRegistry | None = None,
        improvement_engine: ControlledImprovementEngine | None = None,
        acquisition_service: Any | None = None,
        cyber_division: Any | None = None,
        creation_engine: Any | None = None,
    ) -> None:
        self.db = db
        self.workspace_dir = Path(workspace_dir)
        self.data_dir = Path(data_dir) if data_dir is not None else self.workspace_dir
        self.redactor = redactor or Redactor()
        self.capabilities = capabilities
        self.tool_registry = tool_registry
        self.acquisition_service = acquisition_service
        self.cyber_division = cyber_division
        self.creation_engine = creation_engine

        self.memory_engine = MultiLayerMemoryAndProvenanceEngine(
            db=self.db,
            knowledge=knowledge,
            redactor=self.redactor,
        )
        self.world_model = DynamicEnvironmentWorldModel(
            db=self.db,
            workspace_dir=self.workspace_dir,
        )
        self.cognitive_arch = UnifiedCognitiveArchitecture(
            db=self.db,
            memory_engine=self.memory_engine,
            world_model=self.world_model,
        )
        self.causal_engine = ScientificCausalReasoningEngine(
            db=self.db,
            memory_engine=self.memory_engine,
            world_model=self.world_model,
            workspace_dir=self.workspace_dir,
        )
        self.metacognition = MetacognitiveCalibrationEngine(db=self.db)
        self.objective_generator = AutonomousObjectiveGenerator(db=self.db)
        self.strategic_planner = LongTermStrategicPlanner(db=self.db)

        self.transfer_engine = CrossDomainTransferEngine(db=self.db)
        self.skill_acquisition = ContinualSkillAcquisitionEngine(
            db=self.db,
            workspace_dir=self.workspace_dir,
            capabilities=self.capabilities,
            tool_registry=self.tool_registry,
        )
        self.research_lab = ScientificDiscoveryLab(
            db=self.db,
            workspace_dir=self.workspace_dir,
        )
        self.multimodal = UnifiedMultimodalEngine(db=self.db)

        self.collective_agents = CollectiveAgentCoordinator(db=self.db)
        self.durable_execution = DurableExecutionEngine(db=self.db)
        self.distributed_nodes = DistributedNodeOrchestrator(db=self.db)

        self._improvement_engine = improvement_engine
        self._evolution_lab: EvolutionLaboratory | None = (
            EvolutionLaboratory(db=self.db, improvement_engine=improvement_engine)
            if improvement_engine is not None
            else None
        )
        self.evaluation_lab = IndependentGIEvaluationLab(db=self.db)
        self.reliability = ReliabilityAndFaultToleranceManager(
            db=self.db,
            workspace_dir=self.workspace_dir,
        )
        self.ai_security = AISecurityAndGovernanceEngine(
            db=self.db,
            redactor=self.redactor,
        )
        self.alignment = UserAlignmentAndOversightController(db=self.db)
        self.expansion_hub = CapabilityExpansionAndOptimizationHub(
            db=self.db,
            workspace_dir=self.workspace_dir,
            capabilities=self.capabilities,
            tool_registry=self.tool_registry,
            acquisition_service=self.acquisition_service,
        )

    @property
    def evolution_lab(self) -> EvolutionLaboratory:
        if self._evolution_lab is None:
            imp = self._improvement_engine or ControlledImprovementEngine(
                db=self.db,
                data_dir=self.data_dir,
                stable_root=self.workspace_dir,
            )
            self._evolution_lab = EvolutionLaboratory(db=self.db, improvement_engine=imp)
        return self._evolution_lab

    def honest_capability_statement(self) -> dict[str, Any]:
        return {
            "architecture": "Unified Local Control Plane + Configured Frontier AI Models (§236–§260)",
            "cognitive_subsystems": list(COGNITIVE_11_SUBSYSTEMS),
            "memory_layers": list(MEMORY_11_LAYERS),
            "world_model_domains": list(WORLD_15_DOMAINS),
            "epistemic_levels": list(EPISTEMIC_6_LEVELS),
            "specialist_roles": list(SPECIALIST_12_ROLES),
            "distributed_node_kinds": list(NODE_8_KINDS),
            "evolution_dimensions": list(EVOLUTION_11_DIMENSIONS),
            "evaluation_dimensions": list(EVALUATION_17_DIMENSIONS),
            "failure_domains": list(RELIABILITY_4_FAILURE_DOMAINS),
            "reliability_controls": list(RELIABILITY_15_CONTROLS),
            "ai_security_controls": list(AI_SECURITY_11_CONTROLS),
            "hard_invariants": {
                "claims_frontier_weight_retraining": CLAIMS_FRONTIER_WEIGHT_RETRAINING,
                "advertises_agi_or_human_level": ADVERTISE_AGI_OR_HUMAN_LEVEL,
                "allow_self_permission_expansion": ALLOW_SELF_PERMISSION_EXPANSION,
                "allow_automatic_purchases_or_subscriptions": ALLOW_AUTOMATIC_PURCHASES_OR_SUBSCRIPTIONS,
            },
        }

    def status_summary(self) -> dict[str, Any]:
        ctx = self.db.get_gi_cognitive_context("default")
        memories = self.db.list_gi_memories(limit=500)
        world_entities = self.db.list_gi_world_records(record_type="entity", limit=500)
        goals = self.db.list_gi_goals_and_roadmaps(limit=200)
        skills = self.db.list_gi_skills_and_studies(record_kind="acquired_skill", limit=200)
        studies = self.db.list_gi_skills_and_studies(record_kind="scientific_study", limit=200)
        workflows = self.db.list_gi_durable_workflows(limit=100)
        nodes = self.db.list_gi_distributed_nodes()
        benchmarks = self.db.list_gi_benchmark_runs(limit=20)
        return {
            "cognitive_subsystems_count": len(COGNITIVE_11_SUBSYSTEMS),
            "shared_context_version": int(ctx["state_version"]) if ctx else 0,
            "multilayer_memories_count": len(memories),
            "world_model_entities_count": len(world_entities),
            "strategic_and_autonomous_goals_count": len(goals),
            "validated_acquired_skills_count": sum(1 for s in skills if s["validated"]),
            "scientific_studies_count": len(studies),
            "durable_workflows_count": len(workflows),
            "registered_distributed_nodes_count": len(nodes),
            "benchmark_runs_count": len(benchmarks),
            "recovery_mode_active": self.reliability.recovery_mode_active,
            "advertises_agi": ADVERTISE_AGI_OR_HUMAN_LEVEL,
        }
