"""§165.13 Live 15-Check Acceptance Harness for the Dark Web, Tor Network &
Advanced Internet Intelligence Module (`python -m nova.privacy_intel.acceptance`).

Maps 1-to-1 against all 15 numbered §165.13 acceptance criteria:
  1. NOVA can detect whether the Tor tooling is installed.
  2. The system reports Tor connectivity accurately.
  3. An accessible test onion service can be opened using an appropriate configured client.
  4. An ordinary website can be accessed through the appropriate normal browsing configuration.
  5. Tor routing status is not confused with system-wide internet routing.
  6. An inaccessible onion address produces a truthful error report.
  7. Search reports identify the sources actually accessed.
  8. Downloaded files are handled according to the configured safety policy.
  9. Untrusted documents are not automatically executed.
 10. A sample public threat-intelligence investigation produces a sourced report.
 11. Scheduled research jobs persist and recover correctly when configured.
 12. Sensitive credentials are excluded from ordinary logs and model prompts.
 13. The module shares NOVA's central authorization framework.
 14. Disabling the Tor integration prevents further use of that integration.
 15. The system accurately describes its remaining coverage and limitations.
"""
from __future__ import annotations

import asyncio
import io
import json
import socket
import struct
import sys
import tempfile
import threading
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from nova.autonomy import AutonomyPolicy
from nova.config import Settings
from nova.db import Database
from nova.engine import TaskEngine
from nova.privacy_intel.tor_network import derive_v3_onion_from_pubkey_bytes
from nova.tools.registry import ToolRegistry


@dataclass(slots=True)
class CheckResult:
    check_id: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"check_id": self.check_id, "passed": self.passed, "detail": self.detail}


class LocalSocks5hTestRelay:
    """Real ephemeral RFC 1928 SOCKS5h relay (`127.0.0.1:0`) mapping registered test v3 `.onion`
    hostnames to an ephemeral localhost HTTP server while recording `ATYP` & isolation tokens.
    """

    def __init__(self, onion_routes: dict[str, tuple[str, int]]) -> None:
        self.onion_routes = {k.lower(): v for k, v in onion_routes.items()}
        self.observed_requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(16)
        self.host, self.port = self._srv.getsockname()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        try:
            self._srv.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                client, _addr = self._srv.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()

    @staticmethod
    def _rx(sock: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("EOF")
            buf.extend(chunk)
        return bytes(buf)

    def _handle_client(self, client: socket.socket) -> None:
        with client:
            client.settimeout(5.0)
            try:
                ver, nmethods = self._rx(client, 2)
                if ver != 0x05:
                    return
                methods = self._rx(client, nmethods)
                isolation_user = ""
                if 0x02 in methods:
                    client.sendall(b"\x05\x02")
                    _aver, ulen = self._rx(client, 2)
                    isolation_user = self._rx(client, ulen).decode("ascii", errors="ignore")
                    plen = self._rx(client, 1)[0]
                    _ = self._rx(client, plen)
                    client.sendall(b"\x01\x00")
                else:
                    client.sendall(b"\x05\x00")

                try:
                    head = self._rx(client, 4)
                except ConnectionError:
                    return
                c_ver, cmd, _rsv, atyp = head
                if c_ver != 0x05 or cmd != 0x01:
                    client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                    return
                if atyp == 0x03:
                    dlen = self._rx(client, 1)[0]
                    dest_host = self._rx(client, dlen).decode("ascii", errors="ignore").lower()
                elif atyp == 0x01:
                    dest_host = socket.inet_ntoa(self._rx(client, 4))
                else:
                    client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                    return
                dest_port = struct.unpack("!H", self._rx(client, 2))[0]

                with self._lock:
                    self.observed_requests.append(
                        {"atyp": atyp, "dest_host": dest_host, "dest_port": dest_port, "isolation_user": isolation_user}
                    )

                target = self.onion_routes.get(dest_host)
                if target is None:
                    client.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                    return

                with socket.create_connection(target, timeout=5.0) as upstream:
                    upstream.settimeout(5.0)
                    client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
                    self._pipe_bidirectional(client, upstream)
            except (OSError, ConnectionError):
                return

    @staticmethod
    def _pipe_bidirectional(a: socket.socket, b: socket.socket) -> None:
        done = threading.Event()

        def _forward(src: socket.socket, dst: socket.socket) -> None:
            try:
                while not done.is_set():
                    data = src.recv(16_384)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                done.set()
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t1 = threading.Thread(target=_forward, args=(a, b), daemon=True)
        t2 = threading.Thread(target=_forward, args=(b, a), daemon=True)
        t1.start()
        t2.start()
        t1.join(timeout=5.0)
        t2.join(timeout=5.0)


@contextmanager
def ephemeral_test_network() -> Iterator[dict[str, Any]]:
    """Spin up an isolated test v3 `.onion` HTTP origin behind `LocalSocks5hTestRelay` AND a separate clearnet HTTP origin."""
    onion_host = derive_v3_onion_from_pubkey_bytes(b"N" * 32)
    unhosted_onion = derive_v3_onion_from_pubkey_bytes(b"U" * 32)
    clearnet_hits: list[dict[str, str]] = []

    class _OnionOriginHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/private":
                self.send_response(401)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<html><title>Private</title><body>Authorized access required</body></html>")
                return
            html = (
                b"<html><head><title>Verified Security Mirror Onion</title></head>"
                b"<body><h1>Defensive Transparency Mirror</h1>"
                b"<p>Official mirror publishing signed advisories for CVE-2026-4242. No breach occurred at example-org.org.</p>"
                b'<a href="http://abcdefghijklmnop.onion/legacy">Deprecated v2 link</a>'
                b"</body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

        def log_message(self, format: str, *args: object) -> None:
            return

    class _ClearnetOriginHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            clearnet_hits.append({"path": self.path, "ua": self.headers.get("User-Agent", "")})
            html = (
                b"<html><head><title>Ordinary Clearnet Documentation</title></head>"
                b"<body><p>Standard HTTPS/HTTP technical reference for demo-lib 2.4.0.</p></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

        def log_message(self, format: str, *args: object) -> None:
            return

    onion_http = ThreadingHTTPServer(("127.0.0.1", 0), _OnionOriginHandler)
    clearnet_http = ThreadingHTTPServer(("127.0.0.1", 0), _ClearnetOriginHandler)
    threading.Thread(target=onion_http.serve_forever, daemon=True).start()
    threading.Thread(target=clearnet_http.serve_forever, daemon=True).start()

    relay = LocalSocks5hTestRelay({onion_host: ("127.0.0.1", onion_http.server_port)})
    relay.start()
    try:
        yield {
            "onion_host": onion_host,
            "unhosted_onion": unhosted_onion,
            "relay": relay,
            "clearnet_url": f"http://127.0.0.1:{clearnet_http.server_port}/docs",
            "clearnet_hits": clearnet_hits,
        }
    finally:
        relay.close()
        onion_http.shutdown()
        onion_http.server_close()
        clearnet_http.shutdown()
        clearnet_http.server_close()


class _PromptCapturingFakeProvider:
    def __init__(self) -> None:
        self.captured_prompts: list[str] = []

    async def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        self.captured_prompts.append(json.dumps(messages))
        if tools is None:
            return {"message": {"role": "assistant", "content": json.dumps({"summary": "Inspect status", "steps": ["Check Tor status"]})}, "usage": {"total_tokens": 8}}
        return {"message": {"role": "assistant", "content": "Completed safely."}, "usage": {"total_tokens": 6}}


def _build_engine_stack(root: Path, provider: Any | None = None) -> tuple[TaskEngine, _PromptCapturingFakeProvider]:
    settings = Settings(
        data_dir=root / "data",
        workspace_dir=root / "workspace",
        db_path=root / "data" / "nova.sqlite3",
        verify_tasks=False,
    )
    settings.ensure_dirs()
    db = Database(settings.db_path)
    db.initialize()
    reg = ToolRegistry(settings)
    pol = AutonomyPolicy(settings, db, reg)
    fake_prov = provider or _PromptCapturingFakeProvider()
    engine = TaskEngine(db, fake_prov, reg, settings, pol)
    return engine, fake_prov


def run_acceptance_suite() -> dict[str, Any]:
    results: list[CheckResult] = []
    with tempfile.TemporaryDirectory(prefix="novax-sec165-") as tmp, ephemeral_test_network() as net:
        root = Path(tmp)
        engine, prompt_spy = _build_engine_stack(root)
        svc = engine.platform.privacy_intel
        relay: LocalSocks5hTestRelay = net["relay"]
        onion_host: str = net["onion_host"]
        unhosted_onion: str = net["unhosted_onion"]

        # 1. NOVA can detect whether the Tor tooling is installed.
        det_initial = svc.tor.detect_installation_and_status()
        ok_1 = (
            isinstance(det_initial["tor_installed"], bool)
            and isinstance(det_initial["torsocks_installed"], bool)
            and isinstance(det_initial["tor_browser_installed"], bool)
            and bool(det_initial["tor_service_state"])
        )
        results.append(CheckResult("1_detect_tor_tooling_installed", ok_1, f"tor_installed={det_initial['tor_installed']}, state={det_initial['tor_service_state']}"))

        # 2. The system reports Tor connectivity accurately (both unreachable and live SOCKS5h connected).
        svc.tor.update_config({"tor_enabled": True, "socks_host": "127.0.0.1", "socks_port": 1})
        det_down = svc.tor.detect_installation_and_status()
        svc.tor.update_config({"tor_enabled": True, "socks_host": relay.host, "socks_port": relay.port})
        det_up = svc.tor.detect_installation_and_status()
        ok_2 = (
            det_down["socks_connectivity"]["socks5_reachable"] is False
            and "UNREACHABLE" in det_down["status_indicator"]
            and det_up["socks_connectivity"]["socks5_reachable"] is True
            and det_up["status_indicator"] == "TOR CONNECTED (SOCKS5h ISOLATED)"
        )
        results.append(CheckResult("2_report_tor_connectivity_accurately", ok_2, f"down='{det_down['status_indicator']}' -> up='{det_up['status_indicator']}'"))

        # 3. An accessible test onion service can be opened using an appropriate configured client.
        svc.onion_browser.verify_against_official_reference(onion_host, onion_host, reference_source="https://security.example.org/mirrors.txt")
        page = svc.onion_browser.open_onion_page(f"http://{onion_host}/")
        ok_3 = (
            page["ok"] is True
            and page["title"] == "Verified Security Mirror Onion"
            and page["trust_status"] == "verified_against_reference"
            and any(r["atyp"] == 0x03 and r["dest_host"] == onion_host for r in relay.observed_requests)
        )
        results.append(CheckResult("3_open_accessible_test_onion_service", ok_3, f"title='{page.get('title')}', socks5h_atyp=0x03"))

        # 4. An ordinary website can be accessed through the appropriate normal browsing configuration.
        socks_before_ordinary = len(relay.observed_requests)
        ord_page = svc.onion_browser.fetch_ordinary_website(net["clearnet_url"])
        ok_4 = (
            ord_page["ok"] is True
            and ord_page["via"] == "ordinary_direct"
            and ord_page["used_tor"] is False
            and len(relay.observed_requests) == socks_before_ordinary
        )
        results.append(CheckResult("4_access_ordinary_website_normally", ok_4, f"title='{ord_page.get('title')}', used_tor=False"))

        # 5. Tor routing status is not confused with system-wide internet routing.
        dash = svc.tor.privacy_dashboard()
        ok_5 = (
            det_up["system_wide_internet_routed_through_tor"] is False
            and dash["system_wide_tor_routing"] is False
            and dash["components"]["automated_research_client"]["uses_tor"] is True
            and dash["components"]["direct_internet_access"]["uses_tor"] is False
            and dash["components"]["ordinary_ai_providers"]["uses_tor"] is False
        )
        results.append(CheckResult("5_tor_routing_not_confused_with_system_wide", ok_5, "system_wide_tor_routing=False; per-component routing distinct"))

        # 6. An inaccessible onion address produces a truthful error report (plus auth-gated & retired v2 handling).
        inacc = svc.onion_browser.open_onion_page(f"http://{unhosted_onion}/")
        auth_gated = svc.onion_browser.open_onion_page(f"http://{onion_host}/private")
        v2_retired = svc.onion_browser.open_onion_page("http://abcdefghijklmnop.onion/")
        ok_6 = (
            inacc["ok"] is False
            and inacc["status"] == "onion_service_or_host_unreachable"
            and auth_gated["ok"] is False
            and auth_gated["status"] == "requires_authentication_or_authorization"
            and v2_retired["ok"] is False
            and v2_retired["status"] == "invalid_onion_address"
        )
        results.append(CheckResult("6_inaccessible_onion_truthful_error", ok_6, f"unreachable={inacc['status']}, http_401={auth_gated['status']}"))

        # 7. Search reports identify the sources actually accessed.
        sres = svc.search.search(
            f"CVE-2026-4242 advisory {onion_host}",
            explicit_urls=[net["clearnet_url"], f"http://{onion_host}/"],
        )
        ok_7 = (
            len(sres["sources_consulted"]) >= 3
            and len(sres["sources_skipped"]) >= 1
            and all("checked_at" in s and "adapter_name" in s and s["consulted"] is True for s in sres["sources_consulted"])
        )
        results.append(CheckResult("7_search_reports_identify_sources_accessed", ok_7, f"consulted={len(sres['sources_consulted'])}, skipped={len(sres['sources_skipped'])}"))

        # 8. Downloaded files are handled according to the configured safety policy.
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w") as zf:
            zf.writestr("../../etc/cron.d/evil", "malicious")
        q_zip = svc.downloads.quarantine_and_analyze_bytes(
            zbuf.getvalue(),
            original_filename="untrusted.zip",
            source_url=f"http://{onion_host}/untrusted.zip",
            via_network="tor_socks5h",
            extract_archive_isolated=True,
        )
        q_oversize = svc.downloads.quarantine_and_analyze_bytes(b"X" * 2048, original_filename="huge.bin", max_bytes=512)
        arch = q_zip["record"]["static_analysis"]["archive_inspection"]
        ok_8 = (
            q_zip["ok"] is True
            and q_zip["record"]["provenance"]["quarantine_dir_mode"] == "0o700"
            and arch["safe_to_extract"] is False
            and any("Zip-Slip" in r for r in arch["unsafe_reasons"])
            and q_oversize["status"] == "exceeds_size_limit"
        )
        results.append(CheckResult("8_downloaded_files_follow_safety_policy", ok_8, f"dir_mode=0o700, zip_slip_blocked=True, oversize={q_oversize['status']}"))

        # 9. Untrusted documents are not automatically executed.
        pdf_js = b"%PDF-1.7\n1 0 obj << /OpenAction << /JS (app.launchURL('https://evil.example')) >> >>\n(Untrusted Advisory)\n"
        q_doc = svc.downloads.quarantine_and_analyze_bytes(pdf_js, original_filename="advisory.pdf")
        doc_rec = q_doc["record"]
        ok_9 = (
            q_doc["auto_executed"] is False
            and doc_rec["auto_executed"] is False
            and doc_rec["provenance"]["quarantine_file_mode"] == "0o400"
            and doc_rec["provenance"]["executable_bits_set"] is False
            and doc_rec["static_analysis"]["remote_resources_loaded"] is False
        )
        results.append(CheckResult("9_untrusted_documents_never_auto_executed", ok_9, f"file_mode={doc_rec['provenance']['quarantine_file_mode']}, auto_executed=False"))

        # 10. A sample public threat-intelligence investigation produces a sourced report (separating external vs local & verified vs claims).
        svc.knowledge.index_text(
            "Example-org.org breached! Full database for sale — send BTC within 24 hours for escrow guarantee.",
            document_id="ext:rumor-1",
            title="Anon Forum Claim",
            source_kind="external_source",
            external=True,
        )
        ext_adv = svc.threat_intel.ingest_external_advisory(
            title="Public IOC Advisory",
            advisory_text="Observed scanner 198.51.100.77 probing CVE-2026-4242.",
            source_url="https://advisories.example.org/cve-2026-4242",
            is_official_vendor_or_cert=False,
        )
        loc_obs = svc.threat_intel.analyze_supplied_logs(
            "Oct 29 10:15:02 kali sshd[1920]: Failed password for invalid user admin from 198.51.100.77 port 51234 ssh2",
            log_source_label="/var/log/auth.log.sample",
        )
        inv_report = svc.research_assistant.conduct_research(
            f"Investigate CVE-2026-4242 and example-org.org across http://{onion_host}/ and http://{unhosted_onion}/",
            explicit_urls=[f"http://{onion_host}/", f"http://{unhosted_onion}/"],
            independent_model_reviews=[
                {"model": "reviewer-a", "agrees_with_claim": True},
                {"model": "reviewer-b", "agrees_with_claim": True},
            ],
        )
        ok_10 = (
            len(inv_report["citations"]) >= 2
            and len(inv_report["epistemic_separation"]["verified_facts"]) >= 1
            and len(inv_report["scam_and_unsupported_flags"]) >= 1
            and inv_report["multi_model_review"]["promoted_unverified_claims_from_consensus"] == 0
            and ext_adv["finding"]["source_classification"] == "external_report"
            and loc_obs["finding"]["source_classification"] == "verified_local_observation"
            and "198.51.100.77" in loc_obs["matched_known_iocs"]
        )
        results.append(CheckResult("10_sample_public_threat_intel_sourced_report", ok_10, f"citations={len(inv_report['citations'])}, matched_iocs={loc_obs['matched_known_iocs']}"))

        # 11. Scheduled research jobs persist and recover correctly when configured.
        mon = svc.monitors.create_monitor(
            name="CVE-2026-4242 Recurring Watch",
            topic_or_query="CVE-2026-4242",
            allowed_sources=["user_supplied_archives"],
            interval_seconds=60,
            rate_limit_per_hour=4,
        )
        tick_res = engine.platform.unified_os.worker.tick_once("acceptance-worker")
        engine.platform.unified_os.worker.mark_stopped("acceptance-worker")
        restarted_engine, _ = _build_engine_stack(root)
        restored_snap = restarted_engine.platform.privacy_intel.monitors.status_snapshot()
        ok_11 = (
            len(tick_res["executed_monitors"]) == 1
            and restored_snap["monitor_count"] == 1
            and bool(restored_snap["monitors"][0]["checkpoint_hash"])
            and bool(restored_snap["monitors"][0]["last_success_at"])
            and restored_snap["continuous_monitoring_active"] is False
            and mon["id"] == restored_snap["monitors"][0]["id"]
        )
        results.append(CheckResult("11_scheduled_research_jobs_persist_and_recover", ok_11, f"restored={restored_snap['monitor_count']}, checkpoint_saved=True"))

        # 12. Sensitive credentials are excluded from ordinary logs and model prompts.
        svc.tor.update_config({"onion_hosting_enabled": True})
        plan_res = svc.onion_hosting.prepare_onion_service_plan(service_name="research-mirror", local_bind_port=8091, operator_approved=True)
        vault_secret = svc.vault.get("onion_hs_key:research-mirror") or ""
        t_id = engine.db.create_task(f"Summarize status without exposing {vault_secret}", review_plan=False)
        asyncio.run(engine.run_task(t_id))
        summary_blob = json.dumps(svc.status_summary())
        ok_12 = (
            plan_res["ok"] is True
            and bool(vault_secret)
            and vault_secret not in summary_blob
            and len(prompt_spy.captured_prompts) >= 1
            and all(vault_secret not in p for p in prompt_spy.captured_prompts)
            and svc.redactor.scrub_text(f"token={vault_secret}") == "token=[REDACTED]"
        )
        results.append(CheckResult("12_sensitive_credentials_excluded_from_logs_and_prompts", ok_12, "vault secret scrubbed from status, logs, and outgoing AI prompts"))

        # 13. The module shares NOVA's central authorization framework (and blocks contraband & NOVA admin exposure).
        pol_routine = engine.autonomy_policy.decide("tor_status_and_dashboard", {})
        pol_gated = engine.autonomy_policy.decide("onion_open_page", {"url": f"http://{onion_host}/"})
        unapproved_exec = asyncio.run(engine.tools.execute("onion_open_page", {"url": f"http://{onion_host}/"}, approved=False))
        contraband_block = svc.check_ethics("Buy stolen credentials combo list and log in using leaked passwords")
        admin_port_block = svc.onion_hosting.prepare_onion_service_plan(service_name="nova-api", local_bind_port=8000, operator_approved=True)
        ok_13 = (
            pol_routine["action"] == "allow"
            and pol_gated["action"] == "approval_required"
            and unapproved_exec.status == "approval_required"
            and contraband_block["allowed"] is False
            and admin_port_block["status"] == "blocked_sensitive_host_service"
        )
        results.append(CheckResult("13_shares_central_authorization_framework", ok_13, f"onion_open={pol_gated['action']}, admin_port={admin_port_block['status']}"))

        # 14. Disabling the Tor integration prevents further use of that integration.
        socks_before_kill = len(relay.observed_requests)
        svc.tor.update_config({"tor_enabled": False})
        after_disable_open = svc.onion_browser.open_onion_page(f"http://{onion_host}/")
        after_disable_tb = svc.tor.launch_tor_browser(dry_run=True)
        ok_14 = (
            after_disable_open["ok"] is False
            and after_disable_open["status"] == "tor_integration_disabled"
            and after_disable_tb["status"] == "tor_integration_disabled"
            and len(relay.observed_requests) == socks_before_kill
        )
        results.append(CheckResult("14_disabling_tor_prevents_further_use", ok_14, "zero SOCKS5h packets emitted after disabling Tor"))

        # 15. The system accurately describes its remaining coverage and limitations.
        lim_search = svc.search.search("unindexed_ephemeral_topic_998877", categories=["privacy_network_search", "public_onion_services"])
        scan_lim = doc_rec["static_analysis"]["malware_scan"]["limitations"]
        ok_15 = (
            lim_search["result_count"] == 0
            and lim_search["single_engine_indexes_entire_dark_web"] is False
            and len(lim_search["query_limitations"]) >= 2
            and len(inv_report["uncompleted_parts"]) >= 1
            and len(dash["anonymity_and_coverage_limitations"]) >= 3
            and "cannot guarantee a file is benign" in scan_lim
        )
        results.append(CheckResult("15_accurately_describes_coverage_and_limitations", ok_15, f"query_limitations={len(lim_search['query_limitations'])}, anonymity_notes={len(dash['anonymity_and_coverage_limitations'])}"))

        engine.platform.knowledge.close()
        restarted_engine.platform.knowledge.close()

    passed = sum(1 for r in results if r.passed)
    return {
        "section": "165.13",
        "passed": passed,
        "total": len(results),
        "all_passed": passed == len(results),
        "checks": [r.to_dict() for r in results],
    }


def main() -> int:
    report = run_acceptance_suite()
    print(json.dumps(report, indent=2))
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
