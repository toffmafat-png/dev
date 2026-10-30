"""Comprehensive tests for §181–§200 Advanced Kali Linux Intelligence,
Application Mastery, and Universal Software Integration.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from nova.autonomy import AutonomyPolicy
from nova.config import Settings
from nova.db import Database
from nova.desktop import cli as desktop_cli
from nova.engine import TaskEngine
from nova.intelligence import IntelligenceOrchestrator, ModelManager
from nova.kali_intel.acceptance import run_acceptance_suite
from nova.kali_intel.cyber_labs_and_education import (
    CYBERSECURITY_25_DOMAINS,
    KALI_TRAINING_11_TRACKS,
    TROUBLESHOOTING_19_DOMAINS,
)
from nova.kali_intel.dev_env_and_evolution import SELF_IMPROVEMENT_10_DOMAINS, SUPPORTED_DEV_LANGUAGES
from nova.kali_intel.service import KaliIntelligenceService
from nova.kali_intel.system_model import APPLICATION_LIFECYCLE_STATES, KALI_SYSTEM_DIMENSIONS
from nova.kali_intel.tool_and_doc_engine import REQUIRED_20_TOOL_PROFILE_FIELDS
from nova.kali_intel.universal_apps_and_chaining import (
    INTEGRATION_HIERARCHY_6_TIER,
    REQUIRED_15_APP_PROFILE_FIELDS,
)
from nova.main import create_app
from nova.tools.registry import ToolRegistry


@pytest.fixture()
def kali_env(tmp_path: Path):
    data_dir = tmp_path / "data"
    ws_dir = tmp_path / "workspace"
    db_path = data_dir / "nova.sqlite3"
    settings = Settings(
        data_dir=data_dir,
        workspace_dir=ws_dir,
        db_path=db_path,
        access_token="test-kali-access-token",
    )
    settings.ensure_dirs()
    db = Database(db_path)
    db.initialize()
    reg = ToolRegistry(settings)
    mm = ModelManager(settings, db)
    orch = IntelligenceOrchestrator(mm, settings, db)
    pol = AutonomyPolicy(settings, db, reg)
    engine = TaskEngine(db, orch, reg, settings, pol)
    return settings, db, engine, engine.platform.kali_intel


def test_s181_system_model_21_dimensions_and_6_states(kali_env):
    _, _, _, ki = kali_env
    res1 = ki.system_model.get_or_refresh_model(force_refresh=True)
    assert res1["refreshed"] is True
    model = res1["model"]
    assert len(KALI_SYSTEM_DIMENSIONS) == 21
    assert set(KALI_SYSTEM_DIMENSIONS).issubset(model.keys())

    # Second call without package state change reuses fresh snapshot
    res2 = ki.system_model.get_or_refresh_model(force_refresh=False)
    assert res2["refreshed"] is False

    py_state = ki.system_model.classify_application_state("python3")
    assert set(py_state["states"].keys()) == set(APPLICATION_LIFECYCLE_STATES)
    assert py_state["states"]["installed"] is True
    assert py_state["states"]["functional"] is True

    missing = ki.system_model.classify_application_state("definitely-missing-kali-binary-999")
    assert missing["primary_state"] == "unavailable"
    assert missing["states"]["unavailable"] is True


def test_s182_s183_tool_intelligence_and_13_step_execution(kali_env):
    _, _, _, ki = kali_env
    prof = ki.tool_engine.build_tool_profile("python3")
    assert set(REQUIRED_20_TOOL_PROFILE_FIELDS).issubset(prof.keys())
    assert prof["executable_path"] != ""

    uninstalled_prof = ki.tool_engine.build_tool_profile("definitely-uninstalled-tool-xyz")
    assert uninstalled_prof["executable_path"] == ""
    assert uninstalled_prof["installation_status"] == "unavailable"

    discovery = ki.tool_engine.search_tools_for_objective("I want to inspect network traffic")
    assert discovery["assumed_all_kali_tools_installed"] is False
    assert discovery["recommended_tool"] is not None

    # §183: Never invent CLI flags
    bad = ki.tool_executor.execute_13_step_objective(
        "probe python",
        explicit_argv=["python3", "--invented-bogus-flag-777"],
    )
    assert bad["ok"] is False
    assert bad["status"] == "rejected_unverified_cli_option"

    # §183: Mutating args require explicit approval
    gated = ki.tool_executor.execute_13_step_objective(
        "mutating check",
        explicit_argv=["python3", "-V", "install"],
        approved=False,
    )
    assert gated["status"] == "approval_required"

    good = ki.tool_executor.execute_13_step_objective(
        "probe python version",
        explicit_argv=["python3", "--version"],
    )
    assert good["ok"] is True
    assert len(good["steps"]) == 13
    assert "Python" in (good["stdout"] or good["stderr"])


def test_s184_s185_s191_s197_docs_forum_safety_and_reconciliation(kali_env):
    _, _, _, ki = kali_env
    docs = ki.doc_engine.retrieve_prioritized_documentation("openssl")
    tiers = [s["priority_tier"] for s in docs["sources"]]
    assert tiers == sorted(tiers)
    assert 2 in tiers and 3 in tiers

    # Incremental deduplication on unchanged content
    first = ki.doc_engine.ingest_custom_or_community_note(
        doc_key="test:dedup",
        title="Kali Note",
        topic="openssl",
        content="Verify X.509 SAN fields with openssl x509 -noout -text.",
        priority_tier=2,
    )
    second = ki.doc_engine.ingest_custom_or_community_note(
        doc_key="test:dedup",
        title="Kali Note",
        topic="openssl",
        content="Verify X.509 SAN fields with openssl x509 -noout -text.",
        priority_tier=2,
    )
    assert first["incremental_unchanged"] is False
    assert second["incremental_unchanged"] is True

    # §185 Forum command safety & secret redaction
    audit = ki.community_intel.inspect_forum_command_safety(
        "apt-key add key.gpg && dd if=/dev/zero of=/dev/sda"
    )
    assert audit["auto_execution_permitted"] is False
    assert "raw_block_device_write" in audit["destructive_or_unsafe_hazards"]
    assert any(w["flag"] == "deprecated_apt_key" for w in audit["outdated_kali_release_warnings"])

    synthetic_pw = "password=" + "topSecretVal_" + ("4" * 16)
    draft = ki.community_intel.prepare_redacted_support_draft(
        issue_title="Package verification question",
        observed_error=f"Auth error with {synthetic_pw}",
        steps_reproduced=["dpkg --audit"],
        raw_log_excerpt=synthetic_pw,
    )
    assert draft["published_online"] is False
    assert "topSecretVal_" not in draft["support_post_markdown"]
    assert "topSecretVal_" not in draft["redacted_log_report"]

    # §197 Conflict resolution favors official tiers over outdated community posts
    res = ki.research_verifier.research_and_reconcile(
        "openssl",
        additional_claims=[
            {
                "source_ref": "https://forums.kali.org/t/old",
                "title": "Legacy advice",
                "priority_tier": 5,
                "version_context": "kali-sana",
                "date": "2016-01-01",
                "statement": "Use apt-key add to install old SSL repo.",
            }
        ],
    )
    assert res["conflicts_detected"] >= 1


def test_s186_s187_s194_s196_s198_apps_learning_capabilities_and_chaining(kali_env):
    settings, db, _, ki = kali_env
    ws = settings.workspace_dir

    ch = ki.app_registry.discover_13_channels_summary(workspace_dir=ws)
    assert ch["channels_inspected"] == 13

    app_prof = ki.app_registry.build_15_field_app_profile("python3")
    assert set(REQUIRED_15_APP_PROFILE_FIELDS).issubset(app_prof.keys())
    assert app_prof["automation_methods"]["hierarchy"] == list(INTEGRATION_HIERARCHY_6_TIER)
    assert app_prof["integration_status"] == "tested_compatible"

    # §194 Unfamiliar program learning
    script = ws / "demo_cli.py"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "if '--version' in sys.argv:\n    print('demo_cli 2.0.0')\n"
        "elif '--help' in sys.argv:\n    print('Usage: demo_cli [--version] [--help] [--verbose]')\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    learned = ki.program_learner.learn_unfamiliar_program(str(script))
    assert learned["ok"] is True
    assert learned["untested_examples_promoted_to_verified"] is False
    assert len(learned["tested_functionality"]) == 1

    # §196 Capability Registry search
    cap = ki.app_registry.query_capabilities("Which tool can convert this document?")
    assert cap["matched_capability_domain"] == "document_conversion"
    assert cap["environment_can_fulfill_now"] is True

    # §187 & §198 Format-checked tool chain + fallback recovery under ONE central task record
    bad_chain = ki.chain_engine.execute_verified_tool_chain(
        goal="Incompatible format test",
        stages=[
            {"name": "s1", "input_format": "none", "output_format": "pcap", "argv": ["python3", "-c", "print('x')"]},
            {"name": "s2", "input_format": "sqlite3", "output_format": "json", "argv": ["python3", "-c", "print('{}')"]},
        ],
    )
    assert bad_chain["ok"] is False
    assert bad_chain["status"] == "format_incompatible"

    good_chain = ki.chain_engine.execute_verified_tool_chain(
        goal="Fallback recovery & verified multi-stage chain",
        stages=[
            {
                "name": "stage_with_fallback",
                "input_format": "none",
                "output_format": "json",
                "argv": ["nonexistent-tool-xyz999", "--version"],
                "fallback_argv": ["python3", "-c", "import json; print(json.dumps({'items': [10, 20]}))"],
            },
            {
                "name": "consume_json",
                "input_format": "json",
                "output_format": "txt",
                "argv": [
                    "python3",
                    "-c",
                    "import json, pathlib, sys; d=json.loads(pathlib.Path(sys.argv[1]).read_text()); print(sum(d['items']))",
                    "{prev}",
                ],
            },
        ],
    )
    assert good_chain["ok"] is True
    assert good_chain["stage_results"][0]["recovered_via_fallback"] is True
    stored_task = db.get_task(good_chain["central_task_id"])
    assert stored_task is not None
    assert stored_task["state"] == "completed"


def test_s188_s189_s190_s192_s193_s195_s199_labs_edu_troubleshooting_and_evolution(kali_env):
    settings, _, _, ki = kali_env

    # §188 & §189
    assert len(CYBERSECURITY_25_DOMAINS) == 25
    denied = ki.cyber_kb.verify_authorization_scope(
        objective="steal credentials from remote portal",
        target="198.51.100.10",
    )
    assert denied["permitted"] is False
    allowed = ki.cyber_kb.verify_authorization_scope(
        objective="inspect local socket listener",
        target="127.0.0.1",
    )
    assert allowed["permitted"] is True

    lab = ki.lab_manager.create_isolated_lab(
        name="Isolated Packet Lab",
        purpose="Loopback training",
        requested_ram_mb=64,
        network_scope="127.0.0.1/32",
    )
    assert lab["ok"] is True

    # §190 Massive metapackage guard
    meta_pkg = ki.package_intel.inspect_package("kali-tools-all")
    assert meta_pkg["is_massive_metapackage"] is True
    assert meta_pkg["prepared_install_argv"] == []

    # §192 Kali Training Academy
    assert len(KALI_TRAINING_11_TRACKS) == 11
    lesson = ki.training_academy.generate_lesson("kali_fundamentals", level="advanced")
    assert lesson["attribution"]["reproduces_restricted_paid_content"] is False
    graded = ki.training_academy.grade_quiz_and_update_roadmap("kali_fundamentals", selected_option="B")
    assert graded["correct"] is True

    # §193 Troubleshooting across 19 domains
    assert len(TROUBLESHOOTING_19_DOMAINS) == 19
    diag = ki.troubleshooter.diagnose_13_steps("dns_resolution")
    assert len(diag["steps"]) == 13

    # §195 Universal Dev Environment
    assert len(SUPPORTED_DEV_LANGUAGES) >= 11
    tc = ki.dev_partner.inspect_installed_toolchains()
    assert len(tc["toolchain_categories"]["interpreters"]) >= 1
    proj = ki.dev_partner.analyze_and_verify_project(settings.workspace_dir)
    assert proj["preserved_existing_structure"] is True

    # §199 Self-Improving Kali Expertise
    assert len(SELF_IMPROVEMENT_10_DOMAINS) == 10
    blocked = ki.expertise_evolution.propose_and_test_improvement(
        domain="task_planning",
        subject="bad_priv",
        baseline_argv=["python3", "--version"],
        improved_argv=["ufw disable"],
        hypothesis="Never disable firewall",
    )
    assert blocked["ok"] is False
    assert blocked["status"] == "rejected_security_or_privilege_mutation"


def test_unified_tools_fastapi_cli_and_s200_acceptance(kali_env, monkeypatch, capsys):
    settings, db, engine, _ = kali_env

    # ToolRegistry execution
    out = asyncio.run(engine.platform.tools.execute("kali_search_tools", {"objective": "inspect network traffic"}, approved=True))
    assert out.status in {"success", "completed"}
    assert out.data["assumed_all_kali_tools_installed"] is False

    # FastAPI endpoints & /api/health
    app = create_app(settings)
    with TestClient(app) as client:
        h = client.get("/api/health").json()
        assert len(h["platform"]) == 7
        assert h["kali_intel"]["sections"] == "181-200"
        assert h["kali_intel"]["degraded"] is False

        login = client.post("/api/auth/login", json={"token": "test-kali-access-token"})
        assert login.status_code == 200

        st = client.get("/api/kali/status")
        assert st.status_code == 200
        assert st.json()["unified_single_architecture"] is True

        srch = client.get("/api/kali/tools/search", params={"objective": "inspect network traffic"})
        assert srch.status_code == 200
        assert srch.json()["total_matches"] >= 1

        les = client.get("/api/kali/training/lesson", params={"track": "security_concepts", "level": "beginner"})
        assert les.status_code == 200
        assert les.json()["track"] == "security_concepts"

    # CLI `nova-x kali`
    monkeypatch.setenv("NOVA_DATA_DIR", str(settings.data_dir))
    monkeypatch.setenv("NOVA_WORKSPACE_DIR", str(settings.workspace_dir))
    rc = desktop_cli.main(["kali", "--search", "inspect network traffic"])
    assert rc == 0
    captured = capsys.readouterr().out
    assert '"assumed_all_kali_tools_installed": false' in captured

    # Full §200 18-point acceptance suite
    suite = run_acceptance_suite()
    assert suite["all_passed"] is True
    assert suite["passed"] == 18
    assert suite["total"] == 18

    # Restart persistence sanity check on fixture DB
    db_reopened = Database(settings.db_path)
    db_reopened.initialize()
    ki_reopened = KaliIntelligenceService(db=db_reopened, workspace_dir=settings.workspace_dir)
    assert ki_reopened.status_summary()["unified_single_architecture"] is True
