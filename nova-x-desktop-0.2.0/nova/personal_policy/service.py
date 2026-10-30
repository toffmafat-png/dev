"""Unified Personal-Use Security and Autonomy Policy Service (Sections 1–7)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from nova.db import Database
from nova.observability import Redactor
from nova.personal_policy.engine import (
    ARTIFICIALLY_LIMIT_SECURITY_KNOWLEDGE,
    AUTONOMOUS_11_INDEPENDENT_OPERATIONS,
    COMPLIANCE_THEATRE_ENABLED,
    CYBER_8_RESEARCH_CAPABILITIES,
    DEPLOYMENT_MODEL,
    ENTERPRISE_CERTIFICATION_REQUIRED,
    EXPOSE_CREDENTIALS_TO_REMOTE_MODELS,
    EXPOSE_UNRESTRICTED_HOST_ACCESS_TO_REMOTE_MODELS,
    LOCAL_STORAGE_BY_DEFAULT,
    MATERIAL_9_PROTECTED_RISKS,
    MINIMAL_INTERVENTION_EQUALS_UNLIMITED_AUTHORIZATION,
    PERSONAL_14_COMPUTING_DOMAINS,
    PUBLIC_MULTI_TENANT_SAAS,
    STRICT_OWASP_CHECKLIST_MANDATORY,
    FrameworkFlexibilityAndAntiTheatreGuard,
    LocalFirstPrivacyController,
    PersonalAutonomyAndCapabilityEngine,
    PersonalCyberResearchAuthorizer,
    RiskProportionateSafeguardEngine,
)


class PersonalSecurityAndAutonomyService:
    """Single-user Kali Linux personal security, persistent permissions & risk-proportionate safeguards facade."""

    def __init__(
        self,
        *,
        db: Database,
        workspace_dir: Path,
        redactor: Redactor | None = None,
        autonomy_policy: Any | None = None,
        cyber_division: Any | None = None,
    ) -> None:
        self.db = db
        self.workspace_dir = Path(workspace_dir)
        self.redactor = redactor or Redactor()
        self.anti_theatre = FrameworkFlexibilityAndAntiTheatreGuard()
        self.safeguards = RiskProportionateSafeguardEngine(
            db=self.db,
            workspace_dir=self.workspace_dir,
            redactor=self.redactor,
        )
        self.autonomy = PersonalAutonomyAndCapabilityEngine(
            db=self.db,
            workspace_dir=self.workspace_dir,
            safeguards=self.safeguards,
            autonomy_policy=autonomy_policy,
        )
        self.cyber_research = PersonalCyberResearchAuthorizer(
            db=self.db,
            autonomy_engine=self.autonomy,
            cyber_division=cyber_division,
        )
        self.local_privacy = LocalFirstPrivacyController(
            db=self.db,
            autonomy_engine=self.autonomy,
            redactor=self.redactor,
        )

    def policy_manifest(self) -> dict[str, Any]:
        return {
            "deployment_model": DEPLOYMENT_MODEL,
            "public_multi_tenant_saas": PUBLIC_MULTI_TENANT_SAAS,
            "strict_owasp_checklist_mandatory": STRICT_OWASP_CHECKLIST_MANDATORY,
            "enterprise_certification_required": ENTERPRISE_CERTIFICATION_REQUIRED,
            "compliance_theatre_enabled": COMPLIANCE_THEATRE_ENABLED,
            "minimal_intervention_equals_unlimited_authorization": MINIMAL_INTERVENTION_EQUALS_UNLIMITED_AUTHORIZATION,
            "artificially_limit_security_knowledge": ARTIFICIALLY_LIMIT_SECURITY_KNOWLEDGE,
            "local_storage_by_default": LOCAL_STORAGE_BY_DEFAULT,
            "expose_credentials_to_remote_models": EXPOSE_CREDENTIALS_TO_REMOTE_MODELS,
            "expose_unrestricted_host_access_to_remote_models": EXPOSE_UNRESTRICTED_HOST_ACCESS_TO_REMOTE_MODELS,
            "personal_computing_domains": list(PERSONAL_14_COMPUTING_DOMAINS),
            "autonomous_independent_operations": list(AUTONOMOUS_11_INDEPENDENT_OPERATIONS),
            "material_protected_risks": list(MATERIAL_9_PROTECTED_RISKS),
            "cyber_research_capabilities": list(CYBER_8_RESEARCH_CAPABILITIES),
        }

    def status_summary(self) -> dict[str, Any]:
        pol = self.autonomy.get_policy()
        grants = self.db.list_personal_persistent_grants(active_only=True)
        transfers = self.db.list_personal_external_transfers(limit=100)
        return {
            "deployment_model": DEPLOYMENT_MODEL,
            "profile_mode": pol["profile_mode"],
            "strict_owasp_checklist_mandatory": STRICT_OWASP_CHECKLIST_MANDATORY,
            "compliance_theatre_enabled": COMPLIANCE_THEATRE_ENABLED,
            "active_persistent_grants_count": len(grants),
            "cyber_lab_grants_count": sum(1 for g in grants if g["domain"] == "software_and_security_research"),
            "external_transfers_logged_count": len(transfers),
            "local_only_projects_count": len(pol["settings"].get("local_only_projects") or []),
            "local_storage_by_default": LOCAL_STORAGE_BY_DEFAULT,
        }
