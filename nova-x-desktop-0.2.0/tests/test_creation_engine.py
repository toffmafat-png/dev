"""Comprehensive verification suite for NOVA X Universal Creation Engine (§116–§148)."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nova.autonomy import AutonomyPolicy
from nova.creation import (
    CAPABILITY_SUITE_VERSION,
    DOMAIN_LAYOUTS,
    SILENT_SYSTEM_INSTALL_PERMITTED,
    MultiModalCreationTeam,
    QualityAssuranceEngine,
    RefinementLoop,
    SpecialistAssignment,
    TechnologyProposal,
    UniversalFormatConverter,
)
from nova.creation.__main__ import main as creation_cli_main
from nova.desktop.runtime import DesktopRuntime
from nova.engine import TaskEngine
from nova.intelligence import IntelligenceOrchestrator, ModelManager
from nova.main import create_app
from nova.platform_service import PlatformService
from tests.conftest import FakeProvider


def _make_platform(environment) -> PlatformService:
    settings, db, registry, _ws = environment
    policy = AutonomyPolicy(settings, db, registry)
    return PlatformService(settings=settings, db=db, tools=registry, autonomy_policy=policy)


# ---- §136, §137 & §147 Discovery, Toolchain & Technology Registry -----------


def test_technology_registry_discovery_and_proposal_evaluator(environment):
    platform = _make_platform(environment)
    creation = platform.creation

    assert SILENT_SYSTEM_INSTALL_PERMITTED is False
    disc = creation.discovery.discover(refresh=True)
    assert "software" in disc["local_runnable_domains"]
    assert "3d" in disc["local_runnable_domains"]
    assert ".png" in disc["processable_formats"]
    assert disc["silent_install_permitted"] is False

    # Redundant proposal when existing low-cost installed tool already covers (.png, visual_design) -> use_existing.
    redundant = creation.registry.evaluate_proposal(
        TechnologyProposal(
            id="redundant-png-framework",
            name="RedundantPNGFramework",
            kind="python_module",
            domains=("visual_design",),
            solves="Generate basic PNG previews.",
            supported_formats=(".png",),
        )
    )
    assert redundant.decision == "use_existing"
    assert redundant.approved_for_proposal is False

    # Unsafe proposal modifying APT repos or replacing system libraries -> reject.
    unsafe = creation.registry.evaluate_proposal(
        TechnologyProposal(
            id="unsafe-lib-replacer",
            name="UnsafeLibcPatch",
            kind="binary",
            domains=("software",),
            solves="Replace core system runtime.",
            supported_formats=(".elfx",),
            replaces_system_libraries=True,
            modifies_apt_repositories=True,
        )
    )
    assert unsafe.decision == "reject"
    assert unsafe.approved_for_proposal is False

    # Genuinely novel, safe format capability -> adopt_with_approval (still never auto-installed).
    novel = creation.registry.evaluate_proposal(
        TechnologyProposal(
            id="step-cad-exporter",
            name="StepCadExporter",
            kind="python_module",
            domains=("engineering",),
            solves="Export ISO-10303 STEP assemblies.",
            supported_formats=(".step",),
            min_ram_mb=128,
            cpu_cost="low",
        )
    )
    assert novel.decision == "adopt_with_approval"
    assert novel.approved_for_proposal is True
    assert novel.to_dict()["auto_install_permitted"] is False

    plan = creation.discovery.propose_setup_plan("3d", ".blend")
    assert plan["requires_authorization"] is True
    assert plan["auto_executed"] is False


# ---- §118 & §§120–134 Specialized Production Studios ------------------------


@pytest.mark.asyncio
async def test_all_specialized_studios_produce_verified_deliverables(environment):
    platform = _make_platform(environment)
    creation = platform.creation

    # Game studio (§123): playable prototype + automated gameplay pytest verification + save-state check
    game = await creation.create_from_intent(
        "Make a playable 2D grid game with original mechanics and save-state.",
        name="Sector Cores",
        domain_override="game",
        package=True,
    )
    assert game["qa"]["passed"] is True
    assert any(c["name"] == "automated_pytest_suite" and c["passed"] for c in game["qa"]["checks"])
    assert game["package"]["packaged"] is True

    # Web & mobile deliverable (§124)
    web = await creation.create_from_intent(
        "Create a responsive progressive web application with a local SQLite backend.",
        name="Field Ops PWA",
        domain_override="web_mobile",
        package=False,
    )
    assert web["qa"]["passed"] is True
    assert any("Production deployment" in lim for lim in web["limitations"])

    # Database & ETL studio (§125)
    db_proj = await creation.create_from_intent(
        "Design a relational database schema with SQL migrations and deduplicating ETL.",
        name="Orders Warehouse",
        domain_override="database",
        package=False,
    )
    assert db_proj["qa"]["passed"] is True

    # Hardware & electronics engineering (§127)
    eng = await creation.create_from_intent(
        "Design a microcontroller temperature sensor circuit schematic, BOM, and firmware.",
        name="Thermal Node",
        domain_override="engineering",
        package=False,
    )
    assert eng["qa"]["passed"] is True
    calc = json.loads((Path(eng["project_dir"]) / "calculations" / "power_budget.json").read_text(encoding="utf-8"))
    assert calc["simulated_only"] is True
    assert calc["physical_hardware_tested"] is False

    # Scientific simulation (§128)
    sim = await creation.create_from_intent(
        "Create a bounded numerical simulation with fixed seed and plot.",
        name="Thermal Drift Sim",
        domain_override="simulation",
        package=False,
    )
    assert sim["qa"]["passed"] is True
    assert sim["build_detail"]["metrics"]["evidence_classification"] == "illustrative_simulation_or_synthetic"

    # Education (§129): quiz consistency + primary source separation
    edu = await creation.create_from_intent(
        "Create an interactive educational course with flashcards, quiz, and coding exercise.",
        name="Systems Reliability 101",
        domain_override="education",
        options={"lecture_notes": "Primary Lecture Note: Always bound queue growth."},
        package=False,
    )
    assert edu["qa"]["passed"] is True
    lesson_md = (Path(edu["project_dir"]) / "curriculum" / "lesson_plan.md").read_text(encoding="utf-8")
    assert "Primary Lecture Note: Always bound queue growth." in lesson_md
    assert "Supplementary Explanation" in lesson_md

    # Business & startup (§130): explicit assumptions, never claiming customer validation
    biz = await creation.create_from_intent(
        "Generate a business product specification, pricing scenarios, and landing prototype.",
        name="OpsLedger Startup",
        domain_override="business",
        package=False,
    )
    assert biz["qa"]["passed"] is True
    assert any("zero real-world customer validation" in lim for lim in biz["limitations"])

    # Publishing & creative writing (§118B, §131) + API integration (§133) + Design-to-code bridge (§134)
    doc = await creation.create_from_intent(
        "Write a short science-fiction story outline and export DOCX, PDF, and XLSX.",
        name="Orbital Relay Story",
        domain_override="writing",
        package=False,
    )
    assert doc["qa"]["passed"] is True

    integ = await creation.create_from_intent(
        "Create a webhook handler and API connector with tests.",
        name="Sync Webhook",
        domain_override="integration",
        package=False,
    )
    assert integ["qa"]["passed"] is True

    bridge = await creation.create_from_intent(
        "Extract design tokens and generate a reusable UI component.",
        name="Token Card Bridge",
        domain_override="visual_design",
        options={"bridge_mode": True},
        package=False,
    )
    assert bridge["qa"]["passed"] is True
    assert bridge["build_detail"]["ui_spec"]["pixel_exact_claimed"] is False


# ---- §132 Universal Format Conversion & Safe File Repair --------------------


def test_format_converter_and_safe_file_repair(tmp_path: Path):
    conv = UniversalFormatConverter()
    assert conv.NEVER_EXECUTE_UNKNOWN_FILES is True

    unknown_script = tmp_path / "mystery.bin"
    unknown_script.write_bytes(b"#!/bin/sh\necho SHOULD_NEVER_RUN\n")
    inspected = conv.inspect_file(unknown_script)
    assert inspected["executed_to_inspect"] is False

    # Broken JSON with UTF-8 BOM + trailing comma -> repaired cleanly without touching original.
    broken_json = tmp_path / "broken.json"
    broken_json.write_bytes(b'\xef\xbb\xbf{"alpha": 1, "items": [10, 20,], }\r\n')
    repaired_json = tmp_path / "repaired.json"
    rep = conv.repair_file(broken_json, repaired_json)
    assert rep["repaired"] is True
    assert rep["source_preserved"] is True
    assert "stripped_utf8_bom" in rep["issues_fixed"]
    assert "removed_trailing_json_commas" in rep["issues_fixed"]
    assert json.loads(repaired_json.read_text(encoding="utf-8")) == {"alpha": 1, "items": [10, 20]}

    # Ragged CSV repair + conversions across CSV -> JSON / XLSX / SQLite & MD -> DOCX / PDF.
    ragged_csv = tmp_path / "ragged.csv"
    ragged_csv.write_text("id,name,score\n1,Ada,98\n2,Grace\n", encoding="utf-8")
    clean_csv = tmp_path / "clean.csv"
    conv.repair_file(ragged_csv, clean_csv)
    assert conv.inspect_file(clean_csv)["valid"] is True

    c_json = conv.convert(clean_csv, tmp_path / "out.json")
    c_xlsx = conv.convert(clean_csv, tmp_path / "out.xlsx")
    c_db = conv.convert(clean_csv, tmp_path / "out.sqlite3")
    assert c_json["converted"] and c_xlsx["converted"] and c_db["converted"]

    md = tmp_path / "guide.md"
    md.write_text("# Field Manual\n\n## Safety\n- Verify inputs.\n", encoding="utf-8")
    c_docx = conv.convert(md, tmp_path / "guide.docx")
    c_pdf = conv.convert(md, tmp_path / "guide.pdf")
    assert c_docx["converted"] and c_docx["lossless"] is False
    assert c_pdf["converted"] and len(c_pdf["information_lost"]) >= 1


# ---- §119, §135, §141, §143 & §144 Workspace, Assets, Blueprints & Lineage --


@pytest.mark.asyncio
async def test_workspace_asset_copyright_blueprints_lineage_and_handover_reopen(environment):
    settings, db, registry, ws = environment
    secret_tok = "sk-liveSecretShouldNeverEnterBlueprint987654"
    secured_settings = replace(settings, ai_api_key=secret_tok)
    policy = AutonomyPolicy(secured_settings, db, registry)
    platform = PlatformService(settings=secured_settings, db=db, tools=registry, autonomy_policy=policy)
    creation = platform.creation

    assert DOMAIN_LAYOUTS["3d"] != DOMAIN_LAYOUTS["software"]

    built = await creation.create_from_intent(
        "Build a Python CLI utility with tests and package it.",
        name="Checksum Tool",
        domain_override="software",
        package=True,
    )
    pid = built["project_id"]
    pdir = Path(built["project_dir"])

    # Inject a stray secret + .env into project dir and verify Blueprint + Handover scrub/exclude them!
    (pdir / ".env").write_text(f"AI_API_KEY={secret_tok}\n", encoding="utf-8")
    (pdir / "docs" / "NOTE.md").write_text(f"# Note\nToken ref: {secret_tok}\n", encoding="utf-8")

    proj_row = db.get_creation_project(pid)
    assert proj_row is not None
    bp = creation.workspace.blueprints.create_from_project(proj_row, blueprint_name="Clean CLI Blueprint")
    serialized_bp = json.dumps(bp)
    assert secret_tok not in serialized_bp

    inst = creation.workspace.blueprints.instantiate(
        bp["id"],
        ws / "from_blueprint",
        installed_tool_ids={t["id"] for t in creation.registry.list_technologies(installed_only=True)},
    )
    assert inst["instantiated"] is True and inst["compatible"] is True

    # §135 AssetLibrary copyright guard & duplicate detection
    ext_img = ws / "external_banner.svg"
    ext_img.write_text('<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40"><title>Ext</title><rect width="40" height="40"/></svg>', encoding="utf-8")
    restricted_asset = creation.workspace.assets.register_asset(
        ext_img,
        project_id=pid,
        provenance="external_sourced",
        license_name="copyrighted",
        tags=["banner"],
    )
    assert restricted_asset["reusable"] is False
    assert "RESTRICTED" in restricted_asset["usage_notes"]

    dup_copy = ws / "external_banner_copy.svg"
    dup_copy.write_bytes(ext_img.read_bytes())
    creation.workspace.assets.register_asset(dup_copy, project_id=pid, provenance="procedural", license_name="MIT")
    assert len(creation.workspace.assets.find_duplicates(project_id=pid)) >= 1

    # §143 Handover archive excludes `.env` and can be reopened inside NOVA!
    pkg = await creation.package_project(pid, archive_format="zip")
    assert pkg["packaged"] is True
    reopened = creation.workspace.reopen_handover_archive(Path(pkg["archive_path"]))
    assert reopened["reopened"] is True
    reopened_dir = Path(reopened["project"]["project_dir"])
    assert not (reopened_dir / ".env").exists()

    # §119 Policy-gated project deletion requires approval unless approved=True
    denied_del = creation.workspace.delete_project(reopened["project"]["id"], approved=False)
    assert denied_del["deleted"] is False
    ok_del = creation.workspace.delete_project(reopened["project"]["id"], approved=True)
    assert ok_del["deleted"] is True


# ---- §138, §139 & §140 QA, Retain/Revert Refinement & Multi-Modal Team ------


def test_qa_rejects_broken_artifacts_and_refinement_retains_or_reverts(tmp_path: Path, environment):
    _settings, db, _registry, _ws = environment
    qa = QualityAssuranceEngine()
    from nova.creation.workspace import LineageTracker

    lineage = LineageTracker(db, max_revisions_per_project=5)
    refiner = RefinementLoop(qa, lineage, max_iterations=3)

    # Case A: SVG missing <title> and missing PNG preview -> autonomously repaired & retained as v2!
    pdir = tmp_path / "visual_fix"
    (pdir / "sources").mkdir(parents=True)
    (pdir / "sources" / "icon.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" width="120" height="120">'
        '<rect width="120" height="120" fill="#101826"/>'
        '<circle cx="60" cy="60" r="36" fill="#38d6c5"/>'
        '</svg>',
        encoding="utf-8",
    )
    pid_a = db.save_creation_project({"name": "FixMe", "domain": "visual_design", "artifact_type": "svg", "objective": "icon", "project_dir": str(pdir)})
    res_a = refiner.run(project_id=pid_a, domain="visual_design", project_dir=pdir)
    assert res_a["qa"]["passed"] is True
    assert res_a["final_version"] == 2
    assert (pdir / "renders" / "icon_preview.png").is_file()

    # Case B: Bad repair attempt introduces syntax error -> automatically reverted to working checkpoint!
    pdir_b = tmp_path / "revert_guard"
    (pdir_b / "sources").mkdir(parents=True)
    (pdir_b / "sources" / "ok.py").write_text("VALUE = 42\n", encoding="utf-8")
    (pdir_b / "docs").mkdir(parents=True)
    (pdir_b / "docs" / "guide.md").write_text("body without h1 heading but plenty of words one two three four five six seven eight nine ten eleven twelve\n", encoding="utf-8")
    pid_b = db.save_creation_project({"name": "RevertGuard", "domain": "software", "artifact_type": "cli", "objective": "guard", "project_dir": str(pdir_b)})

    def _bad_repair(target_dir: Path, _defects, _step: int) -> list[str]:
        # Break working Python source while trying to edit
        (target_dir / "sources" / "ok.py").write_text("def broken(:\n", encoding="utf-8")
        return ["corrupted_python_file"]

    res_b = refiner.run(project_id=pid_b, domain="software", project_dir=pdir_b, custom_repair_fn=_bad_repair)
    assert res_b["final_version"] == 1
    assert any(h.get("action") == "reverted_non_improving_attempt" for h in res_b["history"])
    assert (pdir_b / "sources" / "ok.py").read_text(encoding="utf-8") == "VALUE = 42\n"


def test_multimodal_team_disjoint_scopes_and_secret_leak_blocker(tmp_path: Path):
    team = MultiModalCreationTeam()
    for dom in ("software", "game", "ml", "media", "education"):
        plan = team.assemble_team(dom)
        assert plan["disjoint_ownership_verified"] is True

    overlapping = [
        SpecialistAssignment("a", "Agent A", "Write src", ("src",), ()),
        SpecialistAssignment("b", "Agent B", "Also write src", ("src",), ()),
    ]
    assert len(team.detect_scope_conflicts(overlapping)) == 1

    (tmp_path / "PROJECT_SPEC.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "leaked.txt").write_text("api = 'sk-1234567890abcdefghijklmnop'\n", encoding="utf-8")
    integ = team.validate_integration(tmp_path, team.assemble_team("software"), {"passed": True, "quality_score": 1.0})
    assert integ["integrated_valid"] is False
    assert any("credential" in issue for issue in integ["issues"])


# ---- §145, §146 & HTTP Creation Endpoints + DesktopRuntime Studio -----------


@pytest.mark.asyncio
async def test_natural_language_commands_http_api_and_desktop_studio(environment, tmp_path: Path, monkeypatch):
    settings, db, registry, ws = environment
    app = create_app(settings, provider=FakeProvider([]), db=db, tools=registry)

    with TestClient(app) as client:
        h = client.get("/api/health").json()
        assert "creation" in h and h["creation"]["degraded"] is False

        rec = client.post("/api/creation/recognize", json={"prompt": "Create a 3D printable bracket model"}).json()
        assert rec["domain"] == "3d"

        disc = client.get("/api/creation/discover").json()
        assert len(disc["local_runnable_domains"]) >= 10

        created = client.post(
            "/api/creation/projects",
            json={"prompt": "Build the smallest working prototype first for a CLI note utility"},
        )
        assert created.status_code == 201
        pid = created.json()["project_id"]

        cont = client.post(f"/api/creation/projects/{pid}/continue", json={"instruction": "Document edge cases"})
        assert cont.status_code == 200 and cont.json()["version"] == 2

        cmp_res = client.get(f"/api/creation/projects/{pid}/compare").json()
        assert cmp_res["comparable"] is True and cmp_res["version_b"] == 2

        cmd_tools = client.post("/api/creation/command", json={"command": "Find the best available tools for creating a 3D model"}).json()
        assert cmd_tools["command_kind"] == "discover_tools"

        cmd_bp = client.post("/api/creation/command", json={"command": "Turn this successful workflow into a reusable skill", "project_id": pid}).json()
        assert cmd_bp["command_kind"] == "promote_blueprint"

        cmd_pkg = client.post("/api/creation/command", json={"command": "Package everything necessary to run this project", "project_id": pid}).json()
        assert cmd_pkg["command_kind"] == "package_project" and cmd_pkg["package"]["packaged"] is True

    # Auth gate check when NOVA_ACCESS_TOKEN is set
    secured_app = create_app(replace(settings, access_token="creation-secret-token-999"), provider=FakeProvider([]), db=db, tools=registry)
    with TestClient(secured_app) as unauth_client:
        assert unauth_client.get("/api/health").status_code == 200
        assert unauth_client.get("/api/creation/summary").status_code == 401
        assert unauth_client.post("/api/creation/projects", json={"prompt": "Build a CLI"}).status_code == 401

    # TaskEngine invoking `creation.build` tool under AutonomyPolicy
    tool_call_msg = {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "call_create_1",
                "type": "function",
                "function": {"name": "creation.build", "arguments": json.dumps({"prompt": "Design a vector SVG badge", "domain": "visual_design", "package": False})},
            }
        ],
    }
    fake_prov = FakeProvider(
        [
            {"choices": [{"message": {"role": "assistant", "content": json.dumps({"summary": "Build badge", "steps": ["Call creation.build"]})}}]},
            {"choices": [{"message": tool_call_msg}]},
            {"choices": [{"message": {"role": "assistant", "content": "Created verified SVG badge."}}]},
        ]
    )
    task_settings = replace(
        settings,
        ai_api_key="test-key",
        ai_base_url="https://api.openai.com/v1",
        ai_model="gpt-4o-mini",
        verify_tasks=False,
    )
    mm = ModelManager(task_settings, db, injected_provider=fake_prov)
    orch = IntelligenceOrchestrator(mm, mm.settings, db)
    pol = AutonomyPolicy(mm.settings, db, registry)
    t_engine = TaskEngine(db, orch, registry, mm.settings, pol)
    tid = db.create_task("Create a vector SVG badge")
    await t_engine.run_task(tid)
    done_task = db.get_task(tid)
    assert done_task is not None and done_task["state"] == "completed"

    # Native DesktopRuntime Creation Studio wiring (§146)
    d_state = tmp_path / "desktop_state"
    d_ws = tmp_path / "desktop_ws"
    monkeypatch.setenv("NOVA_DESKTOP_MODE", "1")
    monkeypatch.setenv("NOVA_DATA_DIR", str(d_state))
    monkeypatch.setenv("NOVA_DB_PATH", str(d_state / "nova.sqlite3"))
    monkeypatch.setenv("NOVA_WORKSPACE_DIR", str(d_ws))
    runtime = DesktopRuntime()
    try:
        snap = runtime.creation_studio_snapshot()
        assert snap["summary"]["suite_version"] == CAPABILITY_SUITE_VERSION
        built_desk = await runtime.create_deliverable("Create an editable SVG icon", domain_override="visual_design", package=False)
        assert built_desk["qa"]["passed"] is True
    finally:
        runtime.close()


# ---- §148 End-to-End 8-Domain Universal Creation Capability Test ------------


@pytest.mark.asyncio
async def test_full_8_domain_universal_creation_capability_suite_and_cli(environment, tmp_path: Path):
    platform = _make_platform(environment)
    suite = await platform.creation.run_capability_suite()

    assert suite["suite_version"] == CAPABILITY_SUITE_VERSION
    assert suite["total_cases"] == 8
    assert suite["passed_cases"] == 8
    assert suite["all_demonstrated_passed"] is True
    assert suite["all_creation_domains_claimed_universal"] is False

    ids = [c["id"] for c in suite["cases"]]
    assert ids == [
        "01_software_desktop_utility",
        "02_visual_design_editable_asset",
        "03_media_short_video_assembly",
        "04_data_analysis_and_visualization",
        "05_3d_parametric_model_validation",
        "06_automation_authorized_workflow",
        "07_new_capability_isolated_extension",
        "08_tool_failure_reporting_and_recovery",
    ]
    assert all(c["genuinely_ran"] and c["passed"] for c in suite["cases"])


def test_creation_cli_entrypoint(tmp_path: Path):
    rc = creation_cli_main(["--db", str(tmp_path / "cli.sqlite3"), "--workspace", str(tmp_path / "cli_ws")])
    assert rc == 0
