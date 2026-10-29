"""§165 Dark Web, Tor Network & Advanced Internet Intelligence Unit & Integration Suite."""
from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nova.autonomy import AutonomyPolicy
from nova.config import Settings
from nova.db import Database
from nova.desktop import cli as desktop_cli
from nova.knowledge import KnowledgeStore
from nova.main import create_app
from nova.memory_hub import SharedMemorySystem
from nova.observability import Redactor
from nova.privacy_intel.acceptance import ephemeral_test_network, run_acceptance_suite
from nova.privacy_intel.service import PrivacyIntelligenceService
from nova.privacy_intel.threat_and_files import check_request_ethics_guardrail, minimize_pii_in_text
from nova.privacy_intel.tor_network import derive_v3_onion_from_pubkey_bytes, validate_v3_onion_address
from nova.system_access.remote import ProtectedCredentialVault
from nova.tools.privacy_intel import build_privacy_intel_tools
from nova.tools.registry import ToolRegistry


@pytest.fixture()
def privacy_env(tmp_path: Path):
    settings = Settings(
        data_dir=tmp_path / "data",
        workspace_dir=tmp_path / "workspace",
        db_path=tmp_path / "data" / "nova.sqlite3",
    )
    settings.ensure_dirs()
    db = Database(settings.db_path)
    db.initialize()
    redactor = Redactor()
    knowledge = KnowledgeStore(
        db_path=str(settings.data_dir / "knowledge.sqlite3"),
        workspace_root=str(settings.workspace_dir),
    )
    memory = SharedMemorySystem(db=db, knowledge=knowledge, redactor=redactor)
    vault = ProtectedCredentialVault(vault_dir=settings.data_dir / "vault", redactor=redactor)
    svc = PrivacyIntelligenceService(
        db=db,
        knowledge=knowledge,
        memory_os=memory,
        vault=vault,
        state_dir=settings.data_dir / "privacy_intel",
        workspace_dir=settings.workspace_dir,
        redactor=redactor,
        scheduler_active_probe=lambda: False,
    )
    yield settings, db, svc
    knowledge.close()


def test_v3_onion_cryptographic_checksum_and_v2_rejection():
    valid_onion = derive_v3_onion_from_pubkey_bytes(b"A" * 32)
    res_ok = validate_v3_onion_address(f"http://{valid_onion}/index.html")
    assert res_ok["valid"] is True
    assert res_ok["version"] == 3
    assert res_ok["onion_address"] == valid_onion

    # Flip one base32 character to corrupt the SHA3-256 checksum
    corrupted = ("b" if valid_onion[0] != "b" else "c") + valid_onion[1:]
    res_bad = validate_v3_onion_address(corrupted)
    assert res_bad["valid"] is False
    assert "checksum mismatch" in res_bad["reason"]

    # Retired 16-char v2 onion must be rejected with clear explanation
    res_v2 = validate_v3_onion_address("abcdefghijklmnop.onion")
    assert res_v2["valid"] is False
    assert res_v2["version"] == 2


def test_socks5h_onion_browsing_ordinary_isolation_and_killswitch(privacy_env):
    _settings, _db, svc = privacy_env
    with ephemeral_test_network() as net:
        relay = net["relay"]
        onion_host = net["onion_host"]

        # Disabled by default -> immediate block, zero SOCKS traffic
        blocked = svc.onion_browser.open_onion_page(f"http://{onion_host}/")
        assert blocked["ok"] is False
        assert blocked["status"] == "tor_integration_disabled"
        assert len(relay.observed_requests) == 0

        # Enable Tor pointing at local RFC 1928 SOCKS5h relay
        svc.tor.update_config({"tor_enabled": True, "socks_host": relay.host, "socks_port": relay.port})
        ver = svc.onion_browser.verify_against_official_reference(onion_host, onion_host, reference_source="https://official.example/onion.txt")
        assert ver["matched"] is True

        mismatch = svc.onion_browser.verify_against_official_reference(onion_host, net["unhosted_onion"])
        assert mismatch["matched"] is False
        assert mismatch["trust_status"] == "mismatch_warning"

        # Restore verified reference and open page
        svc.onion_browser.verify_against_official_reference(onion_host, onion_host)
        opened = svc.onion_browser.open_onion_page(f"http://{onion_host}/")
        assert opened["ok"] is True
        assert opened["reachability_implies_trust"] is False
        assert opened["trust_status"] == "verified_against_reference"
        assert relay.observed_requests[-1]["atyp"] == 0x03  # Remote DNS/onion resolution on proxy

        # Unreachable onion returns structured SOCKS5 host-unreachable status
        unreach = svc.onion_browser.open_onion_page(f"http://{net['unhosted_onion']}/")
        assert unreach["ok"] is False
        assert unreach["status"] == "onion_service_or_host_unreachable"

        # Ordinary website bypasses Tor completely; `.onion` rejected on direct client
        direct_onion = svc.onion_browser.fetch_ordinary_website(f"http://{onion_host}/")
        assert direct_onion["ok"] is False
        assert direct_onion["status"] == "onion_requires_tor_client"

        socks_count = len(relay.observed_requests)
        clear_res = svc.onion_browser.fetch_ordinary_website(net["clearnet_url"])
        assert clear_res["ok"] is True
        assert clear_res["used_tor"] is False
        assert len(relay.observed_requests) == socks_count


def test_minimum_sufficient_sources_and_12_step_epistemic_research(privacy_env):
    _settings, _db, svc = privacy_env
    # Ordinary question must NOT select `public_onion_services` or `privacy_network_search`
    ordinary_cats = svc.search.select_minimum_sufficient_sources("Python sqlite3 WAL concurrency documentation")
    assert "public_onion_services" not in ordinary_cats
    assert "privacy_network_search" not in ordinary_cats

    onion_cats = svc.search.select_minimum_sufficient_sources("Inspect dark web .onion mirror status")
    assert "public_onion_services" in onion_cats

    # Index one authoritative local doc and one external scam rumor
    svc.knowledge.index_text(
        "Advisory: WidgetTLS 1.4.2 is not affected by CVE-2026-9000; no breach occurred.",
        document_id="local:advisory-1",
        title="Internal Security Verification",
        source_kind="documentation",
        external=False,
    )
    svc.knowledge.index_text(
        "WidgetTLS breached! Full database for sale — send Monero XMR now with 100% undetectable exploit.",
        document_id="ext:paste-99",
        title="Anon Paste Claim",
        source_kind="external_source",
        external=True,
    )
    report = svc.research_assistant.conduct_research("WidgetTLS CVE-2026-9000 breach claim")
    assert len(report["workflow_steps_completed"]) == 12
    assert len(report["epistemic_separation"]["verified_facts"]) >= 1
    assert len(report["epistemic_separation"]["claims"]) >= 1
    assert len(report["contradictions"]) >= 1
    assert len(report["scam_and_unsupported_flags"]) >= 1
    assert report["multi_model_agreement_is_proof"] if "multi_model_agreement_is_proof" in report else (
        report["multi_model_review"]["multi_model_agreement_treated_as_proof"] is False
    )


def test_threat_intel_exposure_guardrails_and_pii_minimization(privacy_env, tmp_path: Path):
    _settings, _db, svc = privacy_env
    # Prohibited credential/contraband requests are refused
    blocked = check_request_ethics_guardrail("Purchase stolen credentials combo list from marketplace")
    assert blocked["allowed"] is False

    scrubbed = minimize_pii_in_text("Leak sample: john.doe@corp-example.com:MyPassword!99")
    assert "john.doe" not in scrubbed
    assert "MyPassword!99" not in scrubbed
    assert "@corp-example.com:<credential-value-discarded>" in scrubbed

    # Version CVE check records verified_local_observation
    ver_check = svc.threat_intel.check_software_versions(
        {"openssl": "3.0.1", "curl": "8.9.0"},
        advisory_rules=[{"package": "openssl", "fixed_version": "3.0.14", "cve": "CVE-2024-5535", "severity": "high"}],
    )
    assert len(ver_check["vulnerable_matches"]) == 1

    # Local secret scan + unverified external post on authorized org
    repo_dir = tmp_path / "authorized_repo"
    repo_dir.mkdir()
    fake_tok = "ghp_" + ("A" * 28)
    (repo_dir / "config.py").write_text(f"TOKEN = '{fake_tok}'\n", encoding="utf-8")

    unauth = svc.exposure_monitor.assess_authorized_exposure(
        organization_name="CorpExample",
        authorized_domains=["corp-example.com"],
        operator_authorized=False,
    )
    assert unauth["status"] == "authorization_required"

    auth_res = svc.exposure_monitor.assess_authorized_exposure(
        organization_name="CorpExample",
        authorized_domains=["corp-example.com"],
        operator_authorized=True,
        external_posts_or_notices=[{"text": "corp-example.com hacked!", "source_url": "onion://rumor", "is_official_disclosure": False}],
        local_scan_paths=[str(repo_dir)],
    )
    assert auth_res["ok"] is True
    assert len(auth_res["verified_local_findings"]) == 1
    assert fake_tok not in json.dumps(auth_res)
    assert auth_res["external_report_findings"][0]["breach_confirmed"] is False


def test_quarantine_pipeline_spoof_detection_pdf_tar_and_size_caps(privacy_env):
    _settings, _db, svc = privacy_env
    # 1. Size limit enforcement
    too_big = svc.downloads.quarantine_and_analyze_bytes(b"X" * 4096, original_filename="big.bin", max_bytes=1024)
    assert too_big["ok"] is False
    assert too_big["status"] == "exceeds_size_limit"

    # 2. Magic-byte spoof detection: ELF binary disguised as `.pdf`
    elf_spoof = svc.downloads.quarantine_and_analyze_bytes(b"\x7fELF\x02\x01\x01\x00payload", original_filename="report.pdf")
    rec_elf = elf_spoof["record"]
    assert elf_spoof["auto_executed"] is False
    assert rec_elf["detected_mime"] == "application/x-executable-elf"
    assert rec_elf["static_analysis"]["file_type_check"]["extension_mismatch_or_spoof"] is True
    assert rec_elf["provenance"]["executable_bits_set"] is False

    # 3. Duplicate SHA-256 detection
    dup = svc.downloads.quarantine_and_analyze_bytes(b"\x7fELF\x02\x01\x01\x00payload", original_filename="copy.pdf")
    assert dup["record"]["duplicate_of_id"] == rec_elf["id"]

    # 4. PDF active-content & remote-URL isolation without loading remote URLs
    pdf_bytes = b"%PDF-1.7\n1 0 obj << /OpenAction << /JS (app.alert(1)) /URI (https://tracker.example/pixel) >> >>\n(Quarterly Summary Text)\n"
    pdf_res = svc.downloads.quarantine_and_analyze_bytes(pdf_bytes, original_filename="doc.pdf")
    sa = pdf_res["record"]["static_analysis"]
    assert "pdf_active_content_marker:/OpenAction" in sa["risk_indicators"]
    assert "pdf_active_content_marker:/JS" in sa["risk_indicators"]
    assert sa["remote_resources_loaded"] is False
    assert "Quarterly Summary Text" in sa["safe_text_preview"]

    # 5. Safe archive isolated extraction vs Tar traversal rejection
    safe_zip = io.BytesIO()
    with zipfile.ZipFile(safe_zip, "w") as zf:
        zf.writestr("subdir/readme.txt", "clean content")
    ok_zip = svc.downloads.quarantine_and_analyze_bytes(safe_zip.getvalue(), original_filename="clean.zip", extract_archive_isolated=True)
    assert ok_zip["record"]["static_analysis"]["archive_inspection"]["safe_to_extract"] is True
    extracted_dir = Path(ok_zip["record"]["extracted_dir"])
    extracted_file = extracted_dir / "subdir" / "readme.txt"
    assert extracted_file.is_file()
    assert (extracted_file.stat().st_mode & 0o111) == 0

    bad_tar = io.BytesIO()
    with tarfile.open(fileobj=bad_tar, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name="../escape.sh")
        payload = b"#!/bin/sh\nid\n"
        ti.size = len(payload)
        tf.addfile(ti, io.BytesIO(payload))
    res_tar = svc.downloads.quarantine_and_analyze_bytes(bad_tar.getvalue(), original_filename="bad.tar.gz", extract_archive_isolated=True)
    assert res_tar["record"]["static_analysis"]["archive_inspection"]["safe_to_extract"] is False
    assert res_tar["record"]["extracted_dir"] == ""


@pytest.mark.asyncio
async def test_tool_registry_autonomy_gating_api_routes_and_cli(privacy_env, tmp_path: Path, monkeypatch, capsys):
    settings, db, svc = privacy_env
    reg = ToolRegistry(settings)
    for tdef in build_privacy_intel_tools(lambda: svc):
        reg.register(tdef)
    pol = AutonomyPolicy(settings, db, reg)

    # Routine tool runs under default routine autonomy; approval_required tools pause for approval
    d_routine = pol.decide("tor_status_and_dashboard", {})
    assert d_routine["action"] == "allow"
    out_status = await reg.execute("tor_status_and_dashboard", {}, approved=d_routine["approved"])
    assert out_status.status == "success"

    d_gated = pol.decide("privacy_network_configure", {"tor_enabled": True})
    assert d_gated["action"] == "approval_required"
    out_unapproved = await reg.execute("privacy_network_configure", {"tor_enabled": True}, approved=False)
    assert out_unapproved.status == "approval_required"
    out_approved = await reg.execute("privacy_network_configure", {"tor_enabled": True}, approved=True)
    assert out_approved.status == "success"

    # FastAPI endpoints & /api/health privacy_intel block
    app = create_app(settings=settings, db=db)
    with TestClient(app) as client:
        h = client.get("/api/health").json()
        assert "privacy_intel" in h
        assert h["privacy_intel"]["degraded"] is False

        st = client.get("/api/privacy/status")
        assert st.status_code == 200
        assert st.json()["hard_invariants"]["auto_open_execute_or_install_downloads"] is False

        # Prohibited query over HTTP returns 403
        bad = client.post("/api/privacy/search", json={"query": "buy stolen credentials combo list"})
        assert bad.status_code == 403

        ok_s = client.post("/api/privacy/search", json={"query": "local architecture overview"})
        assert ok_s.status_code == 200
        assert "sources_consulted" in ok_s.json()

    # CLI `nova-x tor --dashboard` and `nova-x osint`
    cli_data = tmp_path / "cli_state"
    monkeypatch.setenv("NOVA_DATA_DIR", str(cli_data))
    monkeypatch.setenv("NOVA_DB_PATH", str(cli_data / "nova.sqlite3"))
    monkeypatch.setenv("NOVA_WORKSPACE_DIR", str(tmp_path / "cli_ws"))
    rc_tor = desktop_cli.main(["tor", "--dashboard"])
    assert rc_tor == 0
    tor_stdout = json.loads(capsys.readouterr().out)
    assert "privacy_dashboard" in tor_stdout

    rc_osint = desktop_cli.main(["osint", "CVE-2026-1111 security advisory"])
    assert rc_osint == 0
    osint_stdout = json.loads(capsys.readouterr().out)
    assert osint_stdout["single_engine_indexes_entire_dark_web"] is False


def test_section_165_11_eight_dimension_routing_and_multi_model_non_promotion(privacy_env):
    _settings, _db, svc = privacy_env
    # 1. Ordinary file/docs objective does NOT invoke Tor
    r_local = svc.plan_intelligence_routing(
        "Read workspace README.md and check official documentation",
        registered_tool_names=["workspace.read_file", "advanced_internet_search", "onion_open_page"],
    )
    assert r_local["needs"]["local_file"] is True
    assert r_local["needs"]["official_documentation"] is True
    assert r_local["needs"]["permitted_onion_service"] is False
    assert "onion_open_page" not in r_local["minimum_sufficient_tools"]
    assert r_local["policy_bypass_allowed"] is False

    # 2. Onion + CVE objective selects minimum sufficient Tor & threat tools
    r_onion = svc.plan_intelligence_routing(
        "Verify .onion mirror for CVE-2026-4242 advisory and audit remote server over SSH",
        registered_tool_names=["tor_status_and_dashboard", "onion_open_page", "threat_intel_analyze", "remote_servers_audit"],
    )
    assert r_onion["needs"]["permitted_onion_service"] is True
    assert r_onion["needs"]["cybersecurity_intelligence"] is True
    assert r_onion["needs"]["remote_service_connection"] is True
    assert set(r_onion["minimum_sufficient_tools"]) == {
        "tor_status_and_dashboard",
        "onion_open_page",
        "threat_intel_analyze",
        "remote_servers_audit",
    }

    # 3. Multi-model consensus NEVER upgrades an unverified claim to `verified_facts`
    svc.knowledge.index_text(
        "Unverified claim: vendor-x compromised!",
        document_id="ext:unverified-post",
        title="Unverified Post",
        source_kind="external_source",
        external=True,
    )
    rep = svc.research_assistant.conduct_research(
        "Assess vendor-x claim",
        independent_model_reviews=[
            {"model": "m1", "agrees_with_claim": True},
            {"model": "m2", "agrees_with_claim": True},
            {"model": "m3", "agrees_with_claim": True},
        ],
    )
    assert rep["multi_model_review"]["models_concurring_on_unverified_claims"] == 3
    assert rep["multi_model_review"]["promoted_unverified_claims_from_consensus"] == 0
    assert rep["epistemic_separation"]["verified_facts"] == []
    assert len(rep["epistemic_separation"]["claims"]) >= 1


def test_full_section_165_13_acceptance_suite():
    report = run_acceptance_suite()
    assert report["all_passed"] is True
    assert report["passed"] == 15
    assert report["total"] == 15
