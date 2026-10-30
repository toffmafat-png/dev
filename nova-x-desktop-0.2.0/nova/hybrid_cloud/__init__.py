"""DEV Corrected Master Architecture (§1–§11): Locally Hosted Autonomous AI Platform Powered by Cloud Frontier Intelligence."""
from __future__ import annotations

from nova.hybrid_cloud.architecture import (
    CLOUD_INTELLIGENCE_COMPONENTS,
    HYBRID_INVARIANTS,
    LOCAL_HOSTED_COMPONENTS,
    LlamaCppFallbackAdvisor,
    UntrustedExternalInputValidator,
    verify_hybrid_architecture_integrity,
)
from nova.hybrid_cloud.gateway_and_fusion import (
    SPECIALIST_ROLES,
    SpecialistFusionCoordinator,
    UnifiedCloudFrontierGateway,
)
from nova.hybrid_cloud.persistence_and_resources import (
    CloudAndLocalResourceIntelligence,
    OfflineCloudQueueManager,
    UnifiedAutonomousSubtaskCoordinator,
)
from nova.hybrid_cloud.privacy_gateway import (
    CloudPrivacyGateway,
    KaliLocalCloudDiagnosticCoordinator,
)
from nova.hybrid_cloud.service import (
    HybridCloudIntelligenceService,
    register_hybrid_cloud_tools,
)

__all__ = [
    "CLOUD_INTELLIGENCE_COMPONENTS",
    "HYBRID_INVARIANTS",
    "LOCAL_HOSTED_COMPONENTS",
    "SPECIALIST_ROLES",
    "CloudAndLocalResourceIntelligence",
    "CloudPrivacyGateway",
    "HybridCloudIntelligenceService",
    "KaliLocalCloudDiagnosticCoordinator",
    "LlamaCppFallbackAdvisor",
    "OfflineCloudQueueManager",
    "SpecialistFusionCoordinator",
    "UnifiedAutonomousSubtaskCoordinator",
    "UnifiedCloudFrontierGateway",
    "UntrustedExternalInputValidator",
    "register_hybrid_cloud_tools",
    "verify_hybrid_architecture_integrity",
]
