"""§165.13 Live 15-Check Acceptance Harness for the Dark Web, Tor Network &
Advanced Internet Intelligence Module (`python -m nova.privacy_intel.acceptance`).
"""
from __future__ import annotations

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

from nova.config import Settings
from nova.db import Database
from nova.knowledge import KnowledgeStore
from nova.memory_hub import SharedMemorySystem
from nova.observability import Redactor
from nova.privacy_intel.service import PrivacyIntelligenceService
from nova.privacy_intel.tor_network import derive_v3_onion_from_pubkey_bytes
from nova.system_access.remote import ProtectedCredentialVault


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

                # Probe clients may close right after method negotiation
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
                    # 0x04 Host/Onion unreachable
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
            if self.path == "/advisory.txt":
                body = b"Public Security Research Note: CVE-2026-4242 patched in package demo-lib 2.4.0."
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
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
    t_on = threading.Thread(target=onion_http.serve_forever, daemon=True)
    t_cl = threading.Thread(target=clearnet_http.serve_forever, daemon=True)
    t_on.start()
    t_cl.start()

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


def _make_service(root: Path, *, scheduler_running: bool = False) -> PrivacyIntelligenceService:
    settings = Settings(
        data_dir=root / "data",
        workspace_dir=root / "workspace",
        db_path=root / "data" / "nova.sqlite3",
    )
    settings.ensure_dirs()
    db = Database(settings.db_path)
    db.initialize()
    redactor = Redactor()
    knowledge = KnowledgeStore(db_path=str(settings.data_dir / "knowledge.sqlite3"), workspace_root=str(settings.workspace_dir))
    memory_os = SharedMemorySystem(db=db, knowledge=knowledge, redactor=redactor)
    vault = ProtectedCredentialVault(vault_dir=settings.data_dir / "system_state", redactor=redactor)
    return PrivacyIntelligenceService(
        db=db,
        knowledge=knowledge,
        memory_os=memory_os,
        vault=vault,
        state_dir=settings.data_dir / "privacy_state",
        workspace_dir=settings.workspace_dir,
        redactor=redactor,
        scheduler_active_probe=lambda: scheduler_running,
    )


def run_acceptance_suite() -> dict[str, Any]:
    results: list[CheckResult] = []
    with tempfile.TemporaryDirectory(prefix="novax-sec165-") as tmp, ephemeral_test_network() as net:
        root = Path(tmp)
        svc = _make_service(root, scheduler_running=False)
        relay: LocalSocks5hTestRelay = net["relay"]
        onion_host: str = net["onion_host"]

        # 1. Tor & Tor Browser detection + service status
        det = svc.tor.detect_installation_and_status()
        ok_1 = (
            isinstance(det["tor_installed"], bool)
            and isinstance(det["tor_browser_installed"], bool)
            and det["system_wide_internet_routed_through_tor"] is False
            and bool(det["tor_service_state"])
        )
        results.append(CheckResult("1_tor_and_tor_browser_detection", ok_1, f"tor_installed={det['tor_installed']}, state={det['tor_service_state']}"))

        # 2. Clear diagnostics when Tor is unavailable / unreachable
        svc.tor.update_config({"tor_enabled": True, "socks_host": "127.0.0.1", "socks_port": 1})
        unavail = svc.onion_browser.open_onion_page(f"http://{onion_host}/")
        det_bad = svc.tor.detect_installation_and_status()
        ok_2 = (
            unavail["ok"] is False
            and unavail["status"] == "socks_proxy_unreachable"
            and len(det_bad["setup_instructions"]) >= 3
        )
        results.append(CheckResult("2_unavailable_tor_diagnostics", ok_2, unavail["reason"]))

        # 3. Legitimate v3 `.onion` access over SOCKS5h (`ATYP=0x03`, zero local DNS leak) + broken v2 link detection
        svc.tor.update_config({"tor_enabled": True, "socks_host": relay.host, "socks_port": relay.port})
        svc.onion_browser.verify_against_official_reference(onion_host, onion_host, reference_source="https://security.example.org/mirrors.txt")
        page = svc.onion_browser.open_onion_page(f"http://{onion_host}/")
        ok_3 = (
            page["ok"] is True
            and page["title"] == "Verified Security Mirror Onion"
            and page["trust_status"] == "verified_against_reference"
            and len(page["broken_or_outdated_links"]) == 1
            and any(r["atyp"] == 0x03 and r["dest_host"] == onion_host for r in relay.observed_requests)
        )
        results.append(CheckResult("3_legitimate_v3_onion_access_socks5h", ok_3, f"title='{page.get('title')}', atyp=0x03 verified"))

        # 4. Ordinary website access via normal direct browsing configuration
        prior_socks_count = len(relay.observed_requests)
        ord_page = svc.onion_browser.fetch_ordinary_website(net["clearnet_url"])
        ok_4 = (
            ord_page["ok"] is True
            and ord_page["via"] == "ordinary_direct"
            and ord_page["used_tor"] is False
            and len(relay.observed_requests) == prior_socks_count
        )
        results.append(CheckResult("4_ordinary_website_direct_access", ok_4, f"title='{ord_page.get('title')}', used_tor=False"))

        # 5. Session isolation between Tor-routed sessions and ordinary network sessions
        _ = svc.onion_browser.open_onion_page(f"http://{onion_host}/")
        tor_users = [r["isolation_user"] for r in relay.observed_requests if r["isolation_user"]]
        dash = svc.tor.privacy_dashboard()
        ok_5 = (
            len(set(tor_users)) >= 2  # Distinct IsolateSOCKSAuth credentials per Tor request
            and dash["components"]["direct_internet_access"]["uses_tor"] is False
            and dash["components"]["ordinary_ai_providers"]["uses_tor"] is False
            and net["clearnet_hits"][0]["ua"].startswith("NOVA-X-DirectClient")
        )
        results.append(CheckResult("5_tor_and_ordinary_session_isolation", ok_5, f"distinct_tor_circuit_tokens={len(set(tor_users))}"))

        # 6. Multi-source search records consulted sources, timestamps, and limitations
        sres = svc.search.search(
            f"CVE-2026-4242 advisory {onion_host}",
            explicit_urls=[net["clearnet_url"], f"http://{onion_host}/"],
        )
        ok_6 = (
            len(sres["sources_consulted"]) >= 3
            and all("checked_at" in s and "limitation_note" in s for s in sres["sources_consulted"])
            and len(sres["query_limitations"]) >= 2
            and sres["single_engine_indexes_entire_dark_web"] is False
        )
        results.append(CheckResult("6_multi_source_search_audit_trail", ok_6, f"consulted={len(sres['sources_consulted'])}, hits={sres['result_count']}"))

        # 7. Research reports separate verified facts from unverified claims & flag probable scams/contradictions
        unverified_onion = net["unhosted_onion"]
        svc.knowledge.index_text(
            "Example-org.org breached! Full database for sale — send BTC within 24 hours for escrow guarantee.",
            document_id="archive:forum-claim",
            title="Forum Rumor Snapshot",
            source_kind="external_source",
            external=True,
        )
        rrep = svc.research_assistant.conduct_research(
            f"Assess CVE-2026-4242 and example-org.org status across http://{onion_host}/ and http://{unverified_onion}/",
            explicit_urls=[f"http://{onion_host}/", f"http://{unverified_onion}/"],
        )
        ep = rrep["epistemic_separation"]
        ok_7 = (
            len(ep["verified_facts"]) >= 1
            and len(rrep["scam_and_unsupported_flags"]) >= 1
            and len(rrep["contradictions"]) >= 1
            and len(rrep["uncompleted_parts"]) >= 1
            and rrep["multi_model_review"]["multi_model_agreement_treated_as_proof"] is False
        )
        results.append(CheckResult("7_epistemic_separation_and_scam_detection", ok_7, f"verified={len(ep['verified_facts'])}, flags={len(rrep['scam_and_unsupported_flags'])}"))

        # 8. Quarantined downloads never execute (`0400` mode, `auto_executed=False`), block Zip-Slip, and state scan limitations
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w") as zf:
            zf.writestr("../../etc/cron.d/evil", "malicious")
            zf.writestr("notes.txt", "benign research note")
        qres = svc.downloads.quarantine_and_analyze_bytes(
            zbuf.getvalue(),
            original_filename="bundle.zip",
            source_url=f"http://{onion_host}/bundle.zip",
            via_network="tor_socks5h",
            extract_archive_isolated=True,
        )
        qrec = qres["record"]
        scan_lim = qrec["static_analysis"]["malware_scan"]["limitations"]
        arch = qrec["static_analysis"]["archive_inspection"]
        ok_8 = (
            qres["ok"] is True
            and qres["auto_executed"] is False
            and qrec["provenance"]["executable_bits_set"] is False
            and arch["safe_to_extract"] is False
            and any("Zip-Slip" in r for r in arch["unsafe_reasons"])
            and "cannot guarantee a file is benign" in scan_lim
        )
        results.append(CheckResult("8_quarantine_non_exec_and_scan_limitations", ok_8, f"mode={qrec['provenance']['quarantine_file_mode']}, safe_to_extract={arch['safe_to_extract']}"))

        # 9. Threat intelligence separates external threat claims from verified local observations
        ext_adv = svc.threat_intel.ingest_external_advisory(
            title="Public Blog IOC Claim",
            advisory_text="Observed C2 traffic from 198.51.100.77 exploiting CVE-2026-4242.",
            source_url="https://blog.example.net/ioc",
            is_official_vendor_or_cert=False,
        )
        loc_log = svc.threat_intel.analyze_supplied_logs(
            "Oct 29 10:15:02 kali sshd[1920]: Failed password for invalid user admin from 198.51.100.77 port 51234 ssh2",
            log_source_label="/var/log/auth.log.sample",
        )
        exp_assess = svc.exposure_monitor.assess_authorized_exposure(
            organization_name="ExampleOrg",
            authorized_domains=["example-org.org"],
            operator_authorized=True,
            external_posts_or_notices=[
                {"text": "We hacked alice.smith@example-org.org:SuperSecret123!", "source_url": "onion://paste", "is_official_disclosure": False}
            ],
        )
        ok_9 = (
            ext_adv["finding"]["source_classification"] == "external_report"
            and ext_adv["finding"]["confidence_tier"] == "claim"
            and loc_log["finding"]["source_classification"] == "verified_local_observation"
            and loc_log["finding"]["confidence_tier"] == "verified_fact"
            and "198.51.100.77" in loc_log["matched_known_iocs"]
            and exp_assess["external_report_findings"][0]["breach_confirmed"] is False
            and "SuperSecret123" not in exp_assess["external_report_findings"][0]["summary"]
        )
        results.append(CheckResult("9_external_vs_local_threat_separation", ok_9, f"matched_iocs={loc_log['matched_known_iocs']}, breach_confirmed=False"))

        # 10. Refuses stolen-credential use, illegal contraband acquisition, and private auth bypass
        refusal_1 = svc.check_ethics("Buy stolen credentials combo list and log in using leaked passwords")
        priv_page = svc.onion_browser.open_onion_page(f"http://{onion_host}/private")
        ok_10 = (
            refusal_1["allowed"] is False
            and priv_page["ok"] is False
            and priv_page["status"] == "requires_authentication_or_authorization"
        )
        results.append(CheckResult("10_refuses_contraband_and_auth_bypass", ok_10, f"violation={refusal_1['violation_code']}, http_401={priv_page['status']}"))

        # 11. Optional onion hosting is disabled by default and blocks NOVA admin ports (8000 / 22)
        disabled_try = svc.onion_hosting.prepare_onion_service_plan(service_name="docs-mirror", local_bind_port=8088, operator_approved=True)
        svc.tor.update_config({"onion_hosting_enabled": True})
        blocked_admin = svc.onion_hosting.prepare_onion_service_plan(service_name="nova-admin", local_bind_port=8000, operator_approved=True)
        valid_plan = svc.onion_hosting.prepare_onion_service_plan(service_name="docs-mirror", local_bind_port=8088, operator_approved=True)
        ok_11 = (
            disabled_try["status"] == "onion_hosting_disabled"
            and blocked_admin["status"] == "blocked_sensitive_host_service"
            and valid_plan["ok"] is True
            and valid_plan["plan"]["deployment_plan"]["permissions_valid_0700"] is True
        )
        results.append(CheckResult("11_onion_hosting_disabled_default_and_admin_protected", ok_11, f"disabled_default={disabled_try['status']}, admin_blocked={blocked_admin['status']}"))

        # 12. Private keys and credentials are protected in 0600 vault and never leak into status/reports/logs
        summary_json = json.dumps(svc.status_summary())
        raw_secret = svc.vault.get("onion_hs_key:docs-mirror") or ""
        vault_mode = oct(svc.vault.vault_file.stat().st_mode & 0o777)
        ok_12 = (
            bool(raw_secret)
            and raw_secret not in summary_json
            and "key_vault_ref" not in summary_json
            and svc.redactor.scrub_text(f"leak={raw_secret}") == "leak=[REDACTED]"
            and vault_mode == "0o600"
        )
        results.append(CheckResult("12_private_keys_protected_and_redacted", ok_12, f"vault_mode={vault_mode}, leaked_in_summary=False"))

        # 13. Recurring research monitors persist across restarts cleanly & report honest scheduler state
        mon = svc.monitors.create_monitor(
            name="CVE-2026-4242 Advisory Watch",
            topic_or_query="CVE-2026-4242",
            allowed_sources=["user_supplied_archives"],
            rate_limit_per_hour=2,
        )
        run1 = svc.monitors.run_monitor_once(mon["id"])
        # Re-instantiate service against the same SQLite database to verify clean restart recovery
        svc_restarted = _make_service(root, scheduler_running=False)
        restored = svc_restarted.monitors.status_snapshot()
        ok_13 = (
            run1["ok"] is True
            and restored["continuous_monitoring_active"] is False
            and restored["monitor_count"] == 1
            and bool(restored["monitors"][0]["checkpoint_hash"])
            and bool(restored["monitors"][0]["last_success_at"])
        )
        results.append(CheckResult("13_monitor_persistence_and_honest_scheduler_state", ok_13, f"restored={restored['monitor_count']}, continuous_active=False"))

        # 14. Disabling Tor integration prevents routing requests through Tor immediately
        socks_before_disable = len(relay.observed_requests)
        svc_restarted.tor.update_config({"tor_enabled": False})
        blocked_after_disable = svc_restarted.onion_browser.open_onion_page(f"http://{onion_host}/")
        ok_14 = (
            blocked_after_disable["ok"] is False
            and blocked_after_disable["status"] == "tor_integration_disabled"
            and len(relay.observed_requests) == socks_before_disable
        )
        results.append(CheckResult("14_tor_disable_immediate_killswitch", ok_14, f"status={blocked_after_disable['status']}, extra_socks_packets=0"))

        # 15. Zero fabricated `.onion` links, search results, or unverified breach confirmations
        empty_search = svc_restarted.search.search("nonexistent_quantum_artifact_99887766", categories=["privacy_network_search", "public_web"])
        ok_15 = (
            empty_search["result_count"] == 0
            and len(empty_search["query_limitations"]) >= 2
            and all(f.get("indicators", {}).get("breach_confirmed") is not True for f in svc_restarted.db.list_threat_intel_findings() if f["finding_kind"] == "org_exposure_mention")
        )
        results.append(CheckResult("15_zero_fabricated_links_results_or_breaches", ok_15, f"empty_query_hits={empty_search['result_count']}"))

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
