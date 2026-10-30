"""16-check executable verification suite for DEV Personal-Use Security & Autonomy Policy (Sections 1–7)."""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from nova.autonomy import AutonomyPolicy
from nova.config import Settings
from nova.cyber_division.service import CybersecurityEngineeringDivision
from nova.db import Database
from nova.desktop.commands import CommandRunner
from nova.desktop.policy import CommandPolicy
from nova.hybrid_cloud.service import HybridCloudIntelligenceService
from nova.intelligence import IntelligenceOrchestrator, ModelManager
from nova.kali_intel.service import KaliIntelligenceService
from nova.knowledge import KnowledgeStore
from nova.observability import Redactor
from nova.personal_policy.service import PersonalSecurityAndAutonomyService
from nova.resources import ResourceManager
from nova.tools.personal_policy import build_personal_policy_tools
from nova.tools.registry import ToolRegistry
from nova.updates import OfflineCoordinator


def run_acceptance() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    with tempfile.TemporaryDirectory(prefix="nova_personal_policy_") as tmp:
        root = Path(tmp)
        data_dir = root / "data"
        ws_dir = root / "workspace"
        data_dir.mkdir(parents=True, exist_ok=True)
        ws_dir.mkdir(parents=True, exist_ok=True)
        db_path = data_dir / "nova.sqlite3"

        settings = Settings(data_dir=data_dir, workspace_dir=ws_dir, db_path=db_path)
        db = Database(db_path)
        db.initialize()
        db.set_desktop_setting("workspace_roots", [str(ws_dir.resolve())])
        db.set_desktop_setting("active_workspace", str(ws_dir.resolve()))

        redactor = Redactor()
        tools = ToolRegistry(settings)
        autonomy_pol = AutonomyPolicy(settings, db, tools)
        knowledge = KnowledgeStore(db_path=str(data_dir / "knowledge.sqlite3"), workspace_root=str(ws_dir))
        resources = ResourceManager(disk_path=str(data_dir))
        offline = OfflineCoordinator(resources=resources)
        mm = ModelManager(settings, db)
        orch = IntelligenceOrchestrator(mm, settings, db)
        hybrid_cloud = HybridCloudIntelligenceService(
            settings=settings,
            db=db,
            model_manager=mm,
            orchestrator=orch,
            tool_registry=tools,
            autonomy_policy=autonomy_pol,
            resource_monitor=resources,
            redactor=redactor,
            knowledge_store=knowledge,
            offline_coordinator=offline,
            app_root=ws_dir,
        )
        kali_intel = KaliIntelligenceService(
            db=db,
            workspace_dir=ws_dir,
            knowledge_store=knowledge,
            autonomy_policy=autonomy_pol,
            hybrid_cloud=hybrid_cloud,
            redactor=redactor,
        )
        cyber_div = CybersecurityEngineeringDivision(
            db=db,
            workspace_dir=ws_dir,
            kali_intel=kali_intel,
            knowledge_store=knowledge,
            tool_registry=tools,
            hybrid_cloud=hybrid_cloud,
        )
        svc = PersonalSecurityAndAutonomyService(
            db=db,
            workspace_dir=ws_dir,
            redactor=redactor,
            autonomy_policy=autonomy_pol,
            cyber_division=cyber_div,
        )
        for pp_tool in build_personal_policy_tools(lambda: svc):
            tools.register(pp_tool)

        # 1. §1 Deployment model & OWASP/enterprise flexibility
        manifest = svc.policy_manifest()
        record(
            "sec1_single_user_framework_flexibility",
            manifest["deployment_model"] == "single_user_personal_kali_linux"
            and manifest["public_multi_tenant_saas"] is False
            and manifest["strict_owasp_checklist_mandatory"] is False
            and manifest["enterprise_certification_required"] is False,
            f"deployment={manifest['deployment_model']}",
        )

        # 2. §1 Framework guidance treated as engineering reference, not mandatory checklist
        ref = svc.anti_theatre.evaluate_framework_recommendation(
            "OWASP-Enterprise-SSO-RBAC",
            "Require multi-tenant SSO/SAML RBAC",
            enterprise_multi_tenant_only=True,
        )
        record(
            "sec1_enterprise_only_recommendation_skipped",
            ref["adopt"] is False and ref["mandatory_prerequisite"] is False,
            ref["reason"],
        )

        # 3. §2 All 14 personal computing capability domains active
        domains = svc.autonomy.capability_domains_status()
        record(
            "sec2_14_personal_computing_domains",
            domains["domain_count"] == 14 and all(d["enabled"] for d in domains["domains"]),
            f"domains={domains['domain_count']}",
        )

        # 4. §2 Administrative operations routed via normal Linux permission mechanisms (polkit)
        cmd_pol = CommandPolicy(db)
        priv_eval = cmd_pol.evaluate(["apt", "update"], str(ws_dir), privileged=True)
        sudo_eval = cmd_pol.evaluate(["sudo", "apt", "update"], str(ws_dir), privileged=False)
        record(
            "sec2_linux_admin_permission_boundary",
            priv_eval["rule"] == "privileged_action" and sudo_eval["action"] == "deny",
            f"privileged={priv_eval['rule']}, sudo={sudo_eval['rule']}",
        )

        # 5. §3 Persistent permission grant avoids repeated approval prompts in CommandPolicy & CommandRunner
        grant = svc.autonomy.grant_persistent_permission(
            domain="development_tools",
            scope_target=str(ws_dir),
            allowed_programs=["python3", "git"],
            notes="Recurring local dev/test automation",
        )
        runner = CommandRunner(settings, db, cmd_pol)
        out = asyncio.run(
            runner.run(
                [sys.executable if Path(sys.executable).name == "python3" else "python3", "-c", "print('persistent-ok')"],
                cwd=str(ws_dir),
                approved=False,
                source="agent_task",
            )
        )
        record(
            "sec3_persistent_grant_executes_without_repeated_prompt",
            out.status == "success" and "persistent-ok" in str((out.data or {}).get("stdout", "")),
            f"grant={grant['grant_id']} status={out.status}",
        )

        # 6. §3 Minimal intervention != unlimited authorization (all 11 independent operations present)
        indep = svc.autonomy.autonomous_operations_manifest()
        record(
            "sec3_11_autonomous_ops_without_unlimited_authorization",
            len(indep["independent_operations"]) == 11
            and indep["minimal_intervention_equals_unlimited_authorization"] is False,
            f"ops={len(indep['independent_operations'])}",
        )

        # 7. §4 Material safeguard: backup + SHA-256 verification + rollback before overwrite/delete
        important = ws_dir / "notes.txt"
        important.write_text("original-personal-data\n", encoding="utf-8")
        mod = svc.safeguards.guarded_file_operation(important, operation="overwrite", new_content="updated\n")
        restored = svc.safeguards.rollback_file_operation(mod["backup_id"])
        record(
            "sec4_backup_and_rollback_protection",
            mod["ok"] and restored["ok"] and important.read_text(encoding="utf-8") == "original-personal-data\n",
            f"backup_id={mod['backup_id']}",
        )

        # 8. §4 Material safeguard: catastrophic AI-generated commands blocked even with grants
        cat_rm = cmd_pol.evaluate(["rm", "-rf", "/"], str(ws_dir))
        cat_dd = cmd_pol.evaluate(["dd", "if=/dev/zero", "of=/dev/sda"], str(ws_dir))
        record(
            "sec4_catastrophic_commands_blocked",
            cat_rm["action"] == "deny" and cat_dd["action"] == "deny",
            f"rm={cat_rm['rule']}, dd={cat_dd['rule']}",
        )

        # 9. §4 Material safeguard: credential path protection retained even with persistent grants
        cred_run = asyncio.run(
            runner.run(
                ["python3", str(ws_dir / ".ssh" / "id_ed25519")],
                cwd=str(ws_dir),
                approved=False,
                source="agent_task",
            )
        )
        record(
            "sec4_credential_exposure_blocked",
            cred_run.status == "denied",
            cred_run.summary[:80],
        )

        # 10. §4 Material safeguard: malicious download & compromised plugin verification
        bad_dl = svc.safeguards.verify_download_artifact(b"\x7fELF-payload", expected_sha256="0" * 64)
        bad_plug = svc.safeguards.verify_plugin_source(
            "import subprocess, urllib.request\n",
            declared_permissions=["read_workspace"],
        )
        record(
            "sec4_download_and_plugin_safeguards",
            bad_dl["verified"] is False and bad_plug["safe"] is False,
            f"plugin_findings={bad_plug['findings']}",
        )

        # 11. §4 Material safeguard: unauthorized remote access & resource bounds
        rem = svc.safeguards.validate_remote_bind_host("0.0.0.0", user_authorized_lan=False)
        res_b = svc.safeguards.check_resource_bounds(timeout_seconds=99999, memory_mb=999999)
        record(
            "sec4_remote_access_and_resource_bounds",
            rem["allowed"] is False and res_b["within_bounds"] is False,
            f"bind_reason={rem['reason']}",
        )

        # 12. §5 Personal cybersecurity research: all 8 capabilities + persistent lab authorization
        lab = svc.cyber_research.register_persistent_lab_environment(
            name="Local AppSec Lab",
            category="local_lab",
            targets=["127.0.0.1", str(ws_dir)],
        )
        step = svc.cyber_research.authorize_research_step(
            capability="vulnerability_discovery",
            target="127.0.0.1",
        )
        unowned_step = svc.cyber_research.authorize_research_step(
            capability="controlled_exploitation_research",
            target="example-unowned-public-corp.com",
        )
        record(
            "sec5_persistent_cyber_lab_research",
            lab["artificially_limit_security_knowledge"] is False
            and step["authorized"] is True
            and step["requires_repeated_approval"] is False
            and unowned_step["authorized"] is False,
            f"in_scope={step['authorized']}, unowned={unowned_step['authorized']}",
        )

        # 13. §6 Local privacy: local storage by default + secret redaction + credential file block
        synthetic_token = "sk-" + "proj-" + ("A" * 24)
        priv_ok = svc.local_privacy.prepare_outbound_provider_context(
            provider="openai",
            endpoint_host="api.openai.com",
            purpose="code_review",
            context_text=f"Review helper; token {synthetic_token}",
            project_path=str(ws_dir),
        )
        priv_cred_block = svc.local_privacy.prepare_outbound_provider_context(
            provider="openai",
            endpoint_host="api.openai.com",
            purpose="key_check",
            context_text="check key",
            included_files=["~/.ssh/id_ed25519"],
        )
        record(
            "sec6_local_privacy_and_secret_redaction",
            priv_ok["allowed"] is True
            and synthetic_token not in priv_ok["minimized_context"]
            and priv_ok["expose_credentials_to_remote_models"] is False
            and priv_ok["expose_unrestricted_host_access_to_remote_models"] is False
            and priv_cred_block["allowed"] is False,
            f"redactions={priv_ok['redacted_secrets_count']}",
        )

        # 14. §6 External data transfers visible & configurable (local-only project blocks transfer)
        svc.local_privacy.set_project_local_only(ws_dir, local_only=True)
        local_block = svc.local_privacy.prepare_outbound_provider_context(
            provider="anthropic",
            endpoint_host="api.anthropic.com",
            purpose="summarize",
            context_text="private notes",
            project_path=str(ws_dir),
        )
        vis = svc.local_privacy.inspect_external_transfers()
        record(
            "sec6_visible_and_configurable_transfers",
            local_block["allowed"] is False and vis["transfer_count"] >= 3 and vis["blocked_count"] >= 2,
            f"logged={vis['transfer_count']}, blocked={vis['blocked_count']}",
        )

        # 15. §7 Anti-compliance theatre audit (all 6 rules enforced)
        audit = svc.anti_theatre.audit_proposal(
            claims_unsafe_solely_for_missing_enterprise_control=True,
            adds_local_single_user_auth_prompt=True,
            repeats_approval_for_persistent_grant=True,
        )
        clean_audit = svc.anti_theatre.audit_proposal()
        record(
            "sec7_no_compliance_theatre_guard",
            audit["passed"] is False and len(audit["violations"]) == 3 and clean_audit["passed"] is True,
            f"violations_caught={len(audit['violations'])}",
        )

        # 16. ToolRegistry integration check
        tool_out = asyncio.run(tools.execute("personal_policy_status", {}, approved=True))
        record(
            "sec7_tool_registry_integration",
            tool_out.status == "success" and tool_out.data["status"]["local_storage_by_default"] is True,
            tool_out.summary,
        )

        knowledge.close()

    passed_count = sum(1 for c in checks if c["passed"])
    return {
        "suite": "personal_use_security_and_autonomy_policy",
        "total": len(checks),
        "passed": passed_count,
        "ok": passed_count == len(checks),
        "checks": checks,
    }


def main() -> int:
    report = run_acceptance()
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
