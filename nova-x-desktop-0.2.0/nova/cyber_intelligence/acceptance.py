"""20-check executable acceptance suite for §261–§275 Next-Generation Autonomous Cyber Intelligence Engine."""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

from nova.autonomy import AutonomyPolicy
from nova.config import Settings
from nova.cyber_division.service import CybersecurityEngineeringDivision
from nova.cyber_intelligence.service import NextGenCyberIntelligenceService
from nova.db import Database
from nova.hybrid_cloud.service import HybridCloudIntelligenceService
from nova.intelligence import IntelligenceOrchestrator, ModelManager
from nova.kali_intel.service import KaliIntelligenceService
from nova.knowledge import KnowledgeStore
from nova.observability import Redactor
from nova.personal_policy.service import PersonalSecurityAndAutonomyService
from nova.resources import ResourceManager
from nova.tools.cyber_intelligence import build_cyber_intelligence_tools
from nova.tools.registry import ToolRegistry
from nova.updates import OfflineCoordinator


def run_acceptance() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    with tempfile.TemporaryDirectory(prefix="nova_cyber_intel_261_275_") as tmp:
        root = Path(tmp)
        data_dir = root / "data"
        ws_dir = root / "workspace"
        data_dir.mkdir(parents=True, exist_ok=True)
        ws_dir.mkdir(parents=True, exist_ok=True)
        db_path = data_dir / "nova.sqlite3"

        settings = Settings(data_dir=data_dir, workspace_dir=ws_dir, db_path=db_path)
        db = Database(db_path)
        db.initialize()
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
        personal_pol = PersonalSecurityAndAutonomyService(
            db=db,
            workspace_dir=ws_dir,
            redactor=redactor,
            autonomy_policy=autonomy_pol,
            cyber_division=cyber_div,
        )
        svc = NextGenCyberIntelligenceService(
            db=db,
            workspace_dir=ws_dir,
            cyber_division=cyber_div,
            personal_policy=personal_pol,
            kali_intel=kali_intel,
            knowledge_store=knowledge,
            tool_registry=tools,
            resource_manager=resources,
        )
        for ci_tool in build_cyber_intelligence_tools(lambda: svc):
            tools.register(ci_tool)

        # Register persistent personal lab scope for 127.0.0.1 and owned workspace
        personal_pol.cyber_research.register_persistent_lab_environment(
            name="Owned Dev Security Lab",
            category="development_environment",
            targets=["127.0.0.1", "dev-app.lab.local"],
        )

        # 1. §261 Unknown-Problem Mastery: 15-step scientific investigation on unfamiliar frame parser
        unfamiliar_code = (
            "def parse_custom_tlv(frame: str) -> int:\n"
            "    if frame == '-1':\n"
            "        raise ValueError('negative length overflow in custom TLV header')\n"
            "    return len(frame)\n"
        )
        inv = svc.unknown_mastery.investigate_unknown_problem(
            problem_statement="Investigate unfamiliar custom TLV framing parser defect",
            domain_kind="unfamiliar_protocol",
            artifact_text=unfamiliar_code,
        )
        record(
            "s261_unknown_problem_15_steps_with_prototype",
            inv["all_15_steps_completed"] is True
            and inv["solution_or_barrier"]["validated"] is True
            and len(inv["rejected_approaches"]) >= 1
            and inv["invented_knowledge"] is False,
            f"status={inv['status']}, steps={inv['step_count']}",
        )

        # 2. §261 Unknown-Problem Mastery refuses to invent knowledge when evidence is absent
        inv_no_ev = svc.unknown_mastery.investigate_unknown_problem(
            problem_statement="Analyze proprietary black-box ASIC bus with zero captures",
            domain_kind="unfamiliar_hardware",
            artifact_text="",
        )
        record(
            "s261_no_fabricated_knowledge_without_evidence",
            inv_no_ev["solution_or_barrier"]["validated"] is False
            and inv_no_ev["solution_or_barrier"]["outcome"] == "remaining_technical_barrier_explained",
            inv_no_ev["solution_or_barrier"]["barrier"],
        )

        # 3. §262 Autonomous Vulnerability Research Lab: 13 categories + patch diff verification
        vcase = svc.vuln_lab.analyze_artifact_in_isolated_lab(
            target_component="auth_db.py",
            source_text="def login(cur, u):\n    cur.execute(f'SELECT * FROM users WHERE name = {u}')\n",
            patched_text="def login(cur, u):\n    cur.execute('SELECT * FROM users WHERE name = ?', (u,))\n",
        )
        record(
            "s262_vuln_lab_13_categories_and_patch_diff",
            vcase["reproducible"] is True
            and len(vcase["details"]["supported_categories"]) == 13
            and vcase["details"]["patch_analysis"]["eliminates_detected_patterns"] is True,
            f"case={vcase['case_id']} status={vcase['status']}",
        )

        # 4. §263 Authorized Offensive Methodology Engine: 16 specialties, scope enforcement & quality scoring
        in_scope_ass = svc.methodology_engine.run_authorized_assessment(
            target="127.0.0.1",
            specialty="api_penetration_testing",
            artifacts={"token_util.py": "import hashlib\nh = hashlib.md5(b'secret')\n"},
        )
        out_scope_ass = svc.methodology_engine.run_authorized_assessment(
            target="unowned-external-bank.example",
            specialty="web_application_penetration_testing",
        )
        record(
            "s263_methodology_scope_and_quality_metrics",
            in_scope_ass["ok"] is True
            and in_scope_ass["repeated_approval_prompted"] is False
            and in_scope_ass["quality_metrics"]["scored_by_alert_volume_or_attack_attempts"] is False
            and out_scope_ass["ok"] is False,
            f"verified={in_scope_ass['quality_metrics']['verified_findings_count']}",
        )

        # 5. §264 Controlled Exploitability & Patch Lab: harmless PoC & vulnerable-vs-patched comparison
        exp_cmp = svc.exploitability_lab.run_controlled_patch_comparison(
            target_scope="127.0.0.1",
            component_name="packet_len.py",
            vulnerable_code="def decode_len(n: int) -> list[int]:\n    if n < 0:\n        raise IndexError('negative length underflow')\n    return [0] * min(n, 8)\n",
            patched_code="def decode_len(n: int) -> list[int]:\n    if n < 0:\n        return []\n    return [0] * min(n, 8)\n",
            function_name="decode_len",
            harmless_boundary_input=-4,
        )
        record(
            "s264_harmless_poc_and_patch_comparison",
            exp_cmp["ok"] is True
            and exp_cmp["defect_reproduced_in_vulnerable"] is True
            and exp_cmp["patch_remediated_defect"] is True
            and exp_cmp["harmless_poc_only"] is True,
            f"case={exp_cmp['case_id']}",
        )

        # 6. §264 Hard safety block on weaponized/persistence/credential-theft/destructive/evasion requests
        blocked_weap = svc.exploitability_lab.run_controlled_patch_comparison(
            target_scope="127.0.0.1",
            component_name="bad.py",
            vulnerable_code="def f(x): return x\n",
            patched_code="def f(x): return x\n",
            function_name="f",
            harmless_boundary_input=1,
            intent_description="Generate stealth backdoor and evade EDR while stealing credentials",
        )
        record(
            "s264_weaponization_and_evasion_hard_blocked",
            blocked_weap["ok"] is False and blocked_weap["status"] == "blocked_by_safety_policy",
            blocked_weap["blocked_reason"],
        )

        # 7. §265 Autonomous Security Tool Invention: 12-step synthesis, testing, benchmark, registration & rollback
        inv_v1 = svc.tool_inventor.invent_security_tool(
            name="SSH Hardening Auditor",
            category="configuration_auditor",
            capability_gap="Ignore commented sshd_config directives to eliminate grep false positives",
        )
        inv_v2 = svc.tool_inventor.invent_security_tool(
            name="SSH Hardening Auditor",
            category="configuration_auditor",
            capability_gap="Add X11Forwarding check in v2",
        )
        rb = svc.tool_inventor.rollback_invented_tool(inv_v2["tool_id"])
        record(
            "s265_12_step_tool_invention_and_rollback",
            len(inv_v1["pipeline"]["steps_completed"]) == 12
            and inv_v1["pipeline"]["isolated_tests_passed"] is True
            and inv_v1["pipeline"]["security_audit_passed"] is True
            and tools.get(inv_v1["pipeline"]["registered_tool_name"]) is not None
            and rb["active_version"] == 1,
            f"tool={inv_v1['tool_id']} rolled_back_to=v{rb['active_version']}",
        )

        # 8. §266 Multi-Model Cyber Intelligence: 9 specialist roles & model agreement != verification
        unverified_council = svc.specialist_council.convene_specialists(
            problem="Speculative zero-day claim with no code or reproduction",
            empirical_evidence={},
            unverified_consensus_claim="All models agree it might be vulnerable",
        )
        verified_council = svc.specialist_council.convene_specialists(
            problem="Verified SQLi reproduction",
            empirical_evidence={"reproducible_test_passed": True},
        )
        record(
            "s266_9_specialist_roles_and_evidence_arbiter",
            len(unverified_council["roles_convened"]) == 9
            and unverified_council["model_agreement_substitutes_verification"] is False
            and unverified_council["verified_by_evidence"] is False
            and verified_council["verified_by_evidence"] is True,
            f"unverified={unverified_council['credibility_verdict']}, verified={verified_council['credibility_verdict']}",
        )

        # 9. §267 Security Knowledge Generalization: environment delta check + versioned procedures
        proc_v1 = svc.generalizer.generalize_methodology(
            family="linux_security_to_unfamiliar_distro",
            source_env="Kali Linux (Debian/dpkg/AppArmor)",
            target_env="Alpine Linux (musl/apk/OpenRC)",
        )
        proc_v2 = svc.generalizer.generalize_methodology(
            family="linux_security_to_unfamiliar_distro",
            source_env="Kali Linux (Debian/dpkg/AppArmor)",
            target_env="Alpine Linux (musl/apk/OpenRC)",
        )
        record(
            "s267_knowledge_generalization_and_versioning",
            proc_v1["delta"]["environment_differences_examined"] is True
            and proc_v1["version"] == 1
            and proc_v2["version"] == 2,
            f"procedure={proc_v2['procedure_id']} v{proc_v2['version']}",
        )

        # 10. §268 Advanced Security Research Memory: 13 types, relational links & theoretical != confirmed
        rejected_fake_confirm = False
        try:
            svc.research_memory.store_record(
                record_type="cve_record",
                title="CVE-2099-0001 Theoretical",
                content="Purely theoretical speculation",
                source_provenance="advisory",
                verification_status="confirmed_reproducible",
                evidence={},
            )
        except ValueError:
            rejected_fake_confirm = True

        theo = svc.research_memory.store_record(
            record_type="cve_record",
            title="CVE-2026-10001 Advisory",
            content="Advisory under investigation",
            source_provenance="vendor_bulletin",
            software_version="1.2.3",
            verification_status="theoretical_unconfirmed",
        )
        rem = svc.research_memory.store_record(
            record_type="remediation_method",
            title="Upgrade package >= 1.2.4",
            content="Pin patched release",
            source_provenance="vendor_patch",
            software_version="1.2.4",
            verification_status="remediated_verified",
        )
        svc.research_memory.link_records(
            from_record_id=theo["record_id"],
            relation_type="remediated_by",
            to_record_id=rem["record_id"],
        )
        mem_search = svc.research_memory.search_with_relations("CVE-2026-10001")
        record(
            "s268_research_memory_provenance_relations_and_epistemic_guard",
            rejected_fake_confirm is True
            and mem_search["results"][0]["is_confirmed_finding"] is False
            and len(mem_search["results"][0]["relations"]) == 1,
            f"rejected_unproven_confirm={rejected_fake_confirm}",
        )

        # 11. §269 Autonomous Security Mission System: 12 stages, zero repeated prompts, isolates out-of-scope subtask
        mission = svc.mission_system.execute_mission(
            objective="Assess registered dev environment, isolate out-of-scope asset, remediate & retest",
            targets=[
                {"target": "dev-app.lab.local", "source_text": "import yaml\nDEBUG = True\ndef p(x): return yaml.load(x)\n"},
                {"target": "out-of-scope-prod.example", "source_text": "DEBUG = True\n"},
            ],
        )
        record(
            "s269_12_stage_mission_with_subtask_isolation",
            mission["all_12_stages_completed"] is True
            and mission["repeated_approval_dialogs"] == 0
            and len(mission["subtasks"]) == 1
            and len(mission["isolated_subtasks"]) == 1
            and mission["subtasks"][0]["retest_passed"] is True,
            f"completed={len(mission['subtasks'])}, isolated={len(mission['isolated_subtasks'])}",
        )

        # 12. §270 Secure Lab & Experimentation Engine: hardware check, snapshot/restore & selective temp cleanup
        lab_env = svc.secure_lab.create_isolated_experiment_lab(name="Protocol Fuzz Sandbox", requested_ram_mb=64)
        snap = svc.secure_lab.create_snapshot(lab_env["lab_id"], label="clean")
        (Path(lab_env["temp_experiment_dir"]) / "mutated.tmp").write_text("dirty", encoding="utf-8")
        svc.secure_lab.restore_snapshot(lab_env["lab_id"], snap["snapshot_id"])
        restored_clean = not (Path(lab_env["temp_experiment_dir"]) / "mutated.tmp").exists()
        cleanup = svc.secure_lab.cleanup_temporary_experiment_data(lab_env["lab_id"])
        record(
            "s270_secure_lab_snapshot_restore_and_selective_cleanup",
            lab_env["ok"] is True
            and restored_clean is True
            and cleanup["temporary_data_cleaned"] is True
            and cleanup["research_results_retained"] is True,
            f"lab={lab_env['lab_id']}, removed_temp={cleanup['removed_temp_files']}",
        )

        # 13. §271 Intelligent Security Decision Engine: 9 factors, least-disruptive first & destructive escalation
        d_routine = svc.decision_engine.evaluate_security_action(
            target="127.0.0.1",
            proposed_action="passive_header_and_config_inspection",
            destructive_or_irreversible=False,
        )
        d_destruct = svc.decision_engine.evaluate_security_action(
            target="127.0.0.1",
            proposed_action="live_table_drop_stress_test",
            destructive_or_irreversible=True,
        )
        record(
            "s271_9_factor_least_disruptive_decision_engine",
            len(d_routine["factors_checked"]) == 9
            and d_routine["proceed_autonomously"] is True
            and d_destruct["proceed_autonomously"] is False
            and d_destruct["escalate_to_operator"] is True,
            f"routine={d_routine['decision']}, destructive={d_destruct['decision']}",
        )

        # 14. §272 Security Performance & Benchmarking: 12 metrics + held-out split protection + zero fake superiority
        bench_base = svc.benchmarks.run_suite(split="default", save_as_baseline=True)
        bench_held = svc.benchmarks.run_suite(split="held_out", save_as_baseline=False)
        held_blocked = False
        try:
            svc.benchmarks.run_suite(split="held_out", save_as_baseline=True)
        except ValueError:
            held_blocked = True
        record(
            "s272_12_metric_benchmark_and_held_out_guard",
            bench_base["metric_keys_count"] == 12
            and bench_base["metrics"]["vulnerability_detection_quality"] == 1.0
            and bench_base["metrics"]["false_positive_rate"] == 0.0
            and bench_held["metric_keys_count"] == 12
            and held_blocked is True
            and bench_base["fabricated_superiority_claims"] is False,
            f"acc={bench_base['metrics']['technical_accuracy']}, held_out_baseline_blocked={held_blocked}",
        )

        # 15. §273 Continuous Cybersecurity Improvement: failure diagnosis & regression-rejecting baseline gate
        diag = svc.improver.diagnose_failed_research_task(
            task_objective="Audit custom binary format",
            error_detail="Parser utility missing on PATH",
        )
        reg_gate = svc.improver.refine_false_positive_filter_with_baseline_gate(candidate_ignore_comments=False)
        ok_gate = svc.improver.refine_false_positive_filter_with_baseline_gate(candidate_ignore_comments=True)
        record(
            "s273_continuous_improvement_rejects_regressions",
            diag["root_cause_category"] == "missing_security_tool_or_parser"
            and reg_gate["accepted"] is False
            and ok_gate["accepted"] is True,
            f"regressing_candidate_accepted={reg_gate['accepted']}",
        )

        # 16. §274 Security Research Knowledge Frontier: 11 categories prioritized by installed software
        fr = svc.knowledge_frontier.ingest_frontier_updates(
            [
                {
                    "category": "important_patches",
                    "title": "Python3 urllib URL parsing security update",
                    "affected_packages": ["python3"],
                    "summary": "Affects installed Python runtime on host.",
                },
                {
                    "category": "new_research_papers",
                    "title": "Obscure mainframe OS paper",
                    "affected_packages": ["nonexistent_mainframe_pkg_xyz"],
                    "summary": "Not installed locally.",
                },
            ]
        )
        top_item = fr["prioritized_frontier"][0]
        record(
            "s274_knowledge_frontier_host_prioritization",
            len(fr["supported_categories"]) == 11
            and "python3" in top_item["affected_packages"]
            and top_item["relevance_score"] > fr["prioritized_frontier"][-1]["relevance_score"],
            f"top={top_item['title']} (score={top_item['relevance_score']})",
        )

        # 17–20. §275 Unified Architecture, Manifest Completeness & ToolRegistry Execution
        manifest = svc.capability_manifest()
        record(
            "s275_scientific_engineering_posture",
            manifest["scientific_security_engineering"] is True
            and manifest["mere_hacking_tool_runner"] is False,
            f"sections={manifest['sections']}",
        )
        t_status = asyncio.run(tools.execute("cyber_intel_status", {}, approved=True))
        record(
            "s275_tool_registry_status_execution",
            t_status.status == "success" and t_status.data["status"]["sections"] == "261-275",
            t_status.summary,
        )
        t_inv = asyncio.run(
            tools.execute(
                "cyber_intel_investigate_unknown",
                {"problem_statement": "Inspect simple framing function", "artifact_text": "def f(x): return str(x)\n"},
                approved=True,
            )
        )
        record(
            "s275_tool_registry_investigation_execution",
            t_inv.status == "success" and t_inv.data["all_15_steps_completed"] is True,
            t_inv.summary,
        )
        t_bench = asyncio.run(tools.execute("cyber_intel_run_benchmark", {"split": "default"}, approved=True))
        record(
            "s275_tool_registry_benchmark_execution",
            t_bench.status == "success" and t_bench.data["metric_keys_count"] == 12,
            t_bench.summary,
        )

        knowledge.close()

    passed_count = sum(1 for c in checks if c["passed"])
    return {
        "suite": "next_generation_autonomous_cyber_intelligence_261_275",
        "sections": "261-275",
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
