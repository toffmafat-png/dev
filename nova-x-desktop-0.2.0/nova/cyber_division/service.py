"""§201 Master Cybersecurity Mission & §202 Unified Cybersecurity Intelligence Core."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from nova.cyber_division.assessment_and_code_sec import (
    NetworkSecurityWorkspace,
    SourceCodeSecurityEngineer,
    VulnerabilityDiscoveryAndLifecycleEngine,
    WebAndApiSecurityLab,
)
from nova.cyber_division.factory_purple_automation import (
    AutonomousPurpleTeamCoordinator,
    AutonomousSecurityToolFactory,
    ContinuousSecurityAutomationEngine,
    CybersecurityExpertTutor,
    SelfImprovingSecurityIntelligence,
)
from nova.cyber_division.research_forensics_wireless import (
    IncidentResponseAssistant,
    ReverseEngineeringAndForensicsLab,
    SecurityKnowledgeAndResearchWorkbench,
    WirelessAndHardwareSecurityLab,
)
from nova.cyber_division.scope_and_surface import (
    AttackSurfaceManager,
    SecurityScopeRegistry,
)
from nova.db import Database, utc_now
from nova.kali_intel.service import KaliIntelligenceService
from nova.knowledge import KnowledgeStore
from nova.tools.registry import ToolRegistry

UNIFIED_CORE_16_DOMAINS: tuple[str, ...] = (
    "operating_systems",
    "applications",
    "network_protocols",
    "databases",
    "apis",
    "authentication_systems",
    "cloud_infrastructure",
    "containers",
    "web_technologies",
    "software_dependencies",
    "hardware",
    "firmware",
    "security_configurations",
    "vulnerability_classes",
    "threat_intelligence",
    "defensive_controls",
)


class CybersecurityEngineeringDivision:
    """§201–§220 Unified Autonomous Cybersecurity, Vulnerability Research, and Security Engineering Core."""

    UNSUBSTANTIATED_WORLDS_BEST_CLAIMS = False

    def __init__(
        self,
        *,
        db: Database,
        workspace_dir: Path,
        kali_intel: KaliIntelligenceService,
        knowledge_store: KnowledgeStore | None = None,
        tool_registry: ToolRegistry | None = None,
        hybrid_cloud: Any = None,
    ):
        self.db = db
        self.workspace_dir = workspace_dir
        self.kali_intel = kali_intel
        self.knowledge_store = knowledge_store
        self.tool_registry = tool_registry
        self.hybrid_cloud = hybrid_cloud

        # §203 & §204
        self.scope_registry = SecurityScopeRegistry(db=db)
        self.surface_manager = AttackSurfaceManager(
            db=db,
            scope_registry=self.scope_registry,
            system_model=kali_intel.system_model,
        )

        # §205, §206, §207, §208 & §216
        self.vuln_engine = VulnerabilityDiscoveryAndLifecycleEngine(
            db=db,
            scope_registry=self.scope_registry,
        )
        self.network_security = NetworkSecurityWorkspace(
            scope_registry=self.scope_registry,
            system_model=kali_intel.system_model,
        )
        self.web_api_lab = WebAndApiSecurityLab(
            scope_registry=self.scope_registry,
            vuln_engine=self.vuln_engine,
        )
        self.code_security = SourceCodeSecurityEngineer(
            scope_registry=self.scope_registry,
            vuln_engine=self.vuln_engine,
        )

        # §209, §210, §211, §212 & §213
        self.research_workbench = SecurityKnowledgeAndResearchWorkbench(
            db=db,
            knowledge_store=knowledge_store,
        )
        self.re_forensics = ReverseEngineeringAndForensicsLab(workspace_dir=workspace_dir)
        self.wireless_hw_lab = WirelessAndHardwareSecurityLab(system_model=kali_intel.system_model)
        self.dfir_assistant = IncidentResponseAssistant(db=db, workspace_dir=workspace_dir)

        # §214, §215, §217, §218 & §219
        self.tool_factory = AutonomousSecurityToolFactory(
            db=db,
            workspace_dir=workspace_dir,
            scope_registry=self.scope_registry,
            tool_registry=tool_registry,
        )
        self.purple_team = AutonomousPurpleTeamCoordinator(scope_registry=self.scope_registry)
        self.continuous_automation = ContinuousSecurityAutomationEngine(
            db=db,
            scope_registry=self.scope_registry,
            surface_manager=self.surface_manager,
        )
        self.expert_tutor = CybersecurityExpertTutor(db=db)
        self.self_improving = SelfImprovingSecurityIntelligence(db=db)

    def execute_14_step_security_engagement(
        self,
        *,
        objective: str,
        target: str,
        remediate_if_source_file: str = "",
    ) -> dict[str, Any]:
        """§202 Execute the complete 14-step unified local security assessment & reporting workflow."""
        steps: list[dict[str, Any]] = []

        # 1 & 2. Understand security objective & identify environment
        env_model = self.kali_intel.system_model.get_or_refresh_model()["model"]
        steps.append({"step": 1, "name": "understand_security_objective", "objective": objective})
        steps.append(
            {
                "step": 2,
                "name": "identify_environment",
                "distro": env_model["distribution"]["pretty_name"],
                "relationship_domains_modeled": len(UNIFIED_CORE_16_DOMAINS),
            }
        )

        # 3. Establish & enforce applicable testing scope
        scope_check = self.scope_registry.authorize_operation(
            target=target,
            activity="non_destructive_vulnerability_scanning",
        )
        steps.append({"step": 3, "name": "establish_testing_scope", "decision": scope_check})
        if not scope_check["authorized"]:
            return {
                "ok": False,
                "status": scope_check["status"],
                "reason": scope_check["reason"],
                "steps": steps,
            }

        # 4 & 5. Discover available tools & inspect relevant documentation
        net_tools = self.network_security.inventory_network_security_tools()
        doc_ref = self.kali_intel.doc_engine.retrieve_prioritized_documentation("python3")
        steps.append({"step": 4, "name": "discover_available_tools", "installed_net_tools": len(net_tools["installed_tools"])})
        steps.append({"step": 5, "name": "inspect_relevant_documentation", "doc_sources": len(doc_ref["sources"])})

        # 6 & 7. Develop testing plan & assign analytical specialist roles (local execution enforced!)
        specialist_roles: Any = ["security_architect", "code_auditor", "verification_analyst"]
        if self.hybrid_cloud is not None and hasattr(self.hybrid_cloud, "fusion"):
            try:
                specialist_roles = self.hybrid_cloud.fusion.assign_specialist_roles(objective, mode="frontier_fusion")
            except Exception:
                pass
        steps.append({"step": 6, "name": "develop_testing_plan", "non_destructive": True})
        steps.append(
            {
                "step": 7,
                "name": "assign_specialist_agents",
                "execution_authority": "local_security_engine_only",
                "specialists": specialist_roles,
            }
        )

        # 8, 9 & 10. Execute permitted assessment, collect actual evidence & validate findings
        findings: list[dict[str, Any]] = []
        false_positives: list[dict[str, Any]] = []
        p_target = Path(target)
        if target.startswith(("http://", "https://")):
            web_res = self.web_api_lab.assess_http_application(target)
            findings.extend(web_res.get("findings") or [])
        elif p_target.exists():
            code_res = self.code_security.analyze_project(p_target if p_target.is_dir() else p_target.parent)
            findings.extend(code_res.get("findings") or [])
            false_positives.extend(code_res.get("false_positives_filtered") or [])
        else:
            surf_res = self.surface_manager.assess_target_surface(target)
            steps.append({"step": 8, "surface_checked": surf_res.get("ok", False)})

        steps.append({"step": 8, "name": "execute_permitted_activities", "target": target})
        steps.append({"step": 9, "name": "collect_actual_evidence", "findings_collected": len(findings)})
        steps.append(
            {
                "step": 10,
                "name": "validate_findings",
                "confirmed_or_reproducible": len([f for f in findings if f["epistemic_status"] in {"confirmed_vulnerability", "reproducible_security_defect"}]),
                "false_positives_filtered": len(false_positives),
            }
        )

        # 11 & 12. Evaluate severity/impact & generate remediation recommendations
        findings.sort(key=lambda f: -float(f.get("priority_score", 0.0)))
        remediations = [
            {"finding_id": f["id"], "asset": f["affected_asset"], "recommendation": f["recommended_correction"]}
            for f in findings
        ]
        steps.append({"step": 11, "name": "evaluate_severity_and_impact", "top_priority_score": findings[0]["priority_score"] if findings else 0.0})
        steps.append({"step": 12, "name": "generate_remediation_recommendations", "count": len(remediations)})

        # 13. Retest after fix where authorized
        retest_summary: dict[str, Any] = {"executed": False}
        if remediate_if_source_file and Path(remediate_if_source_file).is_file():
            rem_res = self.code_security.remediate_and_verify_10_steps(remediate_if_source_file)
            retest_summary = {"executed": True, "ok": rem_res.get("ok"), "status": rem_res.get("status")}
            if rem_res.get("ok"):
                for f in findings:
                    if str(Path(remediate_if_source_file).resolve()) in f["affected_asset"]:
                        self.vuln_engine.transition_lifecycle(
                            f["id"],
                            target_state="Resolved",
                            retest_passed=True,
                            evidence_note=f"Automated regression test passed ({rem_res.get('regression_test_file')}).",
                        )
        steps.append({"step": 13, "name": "retest_after_fix", "retest": retest_summary})

        # 14. Produce professional final report
        report = self.generate_professional_report(
            title=f"Security Assessment Report: {objective[:80]}",
            scope_id=scope_check["scope_id"],
            findings=findings,
            false_positives=false_positives,
            retest_summary=retest_summary,
        )
        steps.append({"step": 14, "name": "produce_final_report", "report_path": report["markdown_path"]})

        return {
            "ok": True,
            "scope_id": scope_check["scope_id"],
            "findings_count": len(findings),
            "false_positives_count": len(false_positives),
            "report": report,
            "steps": steps,
        }

    def generate_professional_report(
        self,
        *,
        title: str,
        scope_id: str,
        findings: list[dict[str, Any]],
        false_positives: list[dict[str, Any]] | None = None,
        retest_summary: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """§201 & §220.6 Generate an evidence-backed Markdown & JSON professional security assessment report."""
        reports_dir = self.workspace_dir / "security_reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        stamp = utc_now().replace(":", "").replace(".", "")[:15]
        md_path = reports_dir / f"security_report_{stamp}.md"
        json_path = reports_dir / f"security_report_{stamp}.json"

        lines = [
            f"# {title}",
            f"- **Generated (UTC):** `{utc_now()}`",
            f"- **Authorized Scope ID:** `{scope_id}`",
            f"- **Validated Findings:** `{len(findings)}`",
            f"- **Filtered False Positives:** `{len(false_positives or [])}`",
            "",
            "## Prioritized Findings & Evidence",
        ]
        if not findings:
            lines.append("_No confirmed or reproducible security defects detected within the assessed scope._")
        for idx, f in enumerate(findings, start=1):
            lines.extend(
                [
                    f"### {idx}. [{f['severity'].upper()} · Priority {f['priority_score']}] {f['category']} (`{f['epistemic_status']}`)",
                    f"- **Affected Asset:** `{f['affected_asset']}`",
                    f"- **Lifecycle State:** `{f['lifecycle_state']}`",
                    f"- **Evidence:** `{json.dumps(f['evidence'])}`",
                    f"- **Recommended Remediation:** {f['recommended_correction']}",
                    "",
                ]
            )
        if retest_summary and retest_summary.get("executed"):
            lines.extend(
                [
                    "## Remediation & Regression Verification",
                    f"- **Status:** `{retest_summary.get('status')}` (`ok={retest_summary.get('ok')}`)",
                ]
            )

        md_text = "\n".join(lines) + "\n"
        payload = {
            "title": title,
            "scope_id": scope_id,
            "findings": findings,
            "false_positives": list(false_positives or []),
            "retest_summary": retest_summary or {},
        }
        md_path.write_text(md_text, encoding="utf-8")
        json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return {
            "title": title,
            "markdown_path": str(md_path),
            "json_path": str(json_path),
            "markdown_excerpt": md_text[:2500],
        }

    def honest_capability_statement(self) -> dict[str, Any]:
        """§201 & §220 Distinguish empirically tested local capabilities from optional external tools."""
        net_inv = self.network_security.inventory_network_security_tools()
        re_inv = self.re_forensics.inventory_re_and_forensic_tools()
        return {
            "sections_implemented": "201-220",
            "claims_unverified_worlds_best_status": False,
            "empirically_tested_builtin_capabilities": [
                "centralized_scope_enforcement_and_standing_authorization",
                "attack_surface_fingerprinting_and_delta_detection",
                "python_ast_sast_sca_dockerfile_audit_and_10_step_auto_remediation",
                "non_destructive_http_header_cookie_cors_and_openapi_lab",
                "passive_binary_libpcap_capture_inspector",
                "non_executing_static_elf_pe_apk_artifact_inspector",
                "dfir_timeline_and_0400_forensic_preservation",
                "isolated_defensive_security_tool_factory_with_policy_binding",
                "purple_team_detection_gap_refinement",
                "contextual_risk_prioritization_and_verified_lifecycle",
                "resource_bounded_recurring_security_automation",
            ],
            "installed_external_security_tools": {
                "network": [t["tool"] for t in net_inv["installed_tools"]],
                "re_and_forensics": sorted(re_inv["installed"].keys()),
                "code_scanners": [s for s in self.code_security.EXTERNAL_SCANNERS if shutil.which(s)],
            },
            "proposed_or_optional_external_integrations": {
                "uninstalled_network_tools": net_inv["unavailable_tools"],
                "uninstalled_re_forensic_tools": re_inv["unavailable"],
            },
        }

    def status_summary(self) -> dict[str, Any]:
        return {
            "sections_implemented": "201-220",
            "unified_architecture": True,
            "active_scopes": len(self.db.list_cyber_scopes(active_only=True)),
            "inventoried_assets": len(self.db.list_cyber_assets(limit=300)),
            "tracked_findings": len(self.db.list_cyber_findings(limit=300)),
            "research_dossiers": len(self.db.list_cyber_research_dossiers(limit=200)),
            "generated_defensive_tools": len(self.db.list_cyber_generated_tools()),
            "recurring_assessments": len(self.db.list_cyber_recurring_assessments()),
        }
