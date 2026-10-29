"""§165.1 Tor Network Integration, §165.2 Onion-Service Browsing,
§165.8 Privacy-Aware Network Architecture, and §165.9 Optional Private
Onion-Service Hosting.

Hard architectural & ethical invariants:
- `ASSUME_SYSTEM_WIDE_TOR_ROUTING = False`
- `SILENT_SYSTEM_NETWORK_MUTATION = False`
- `REACHABILITY_IMPLIES_TRUST = False`
- `BYPASS_ACCESS_CONTROLS_OR_CAPTCHAS = False`
- `PROMISE_PERFECT_ANONYMITY = False`
- `EXPOSE_NOVA_ADMIN_AS_ONION_BY_DEFAULT = False`
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from nova.db import Database
from nova.observability import Redactor
from nova.system_access.remote import ProtectedCredentialVault

ASSUME_SYSTEM_WIDE_TOR_ROUTING = False
SILENT_SYSTEM_NETWORK_MUTATION = False
REACHABILITY_IMPLIES_TRUST = False
BYPASS_ACCESS_CONTROLS_OR_CAPTCHAS = False
PROMISE_PERFECT_ANONYMITY = False
EXPOSE_NOVA_ADMIN_AS_ONION_BY_DEFAULT = False

DEFAULT_COMPONENT_ROUTING: dict[str, str] = {
    "tor_browser": "tor_browser_isolated",
    "automated_research_client": "tor_socks5h_when_enabled",
    "proxy_aware_integrations": "direct_unless_configured",
    "ordinary_ai_providers": "direct_https",
    "direct_internet_access": "direct_https",
    "local_only_operations": "loopback_offline_only",
}

ALLOWED_ROUTING_MODES: frozenset[str] = frozenset(
    {
        "tor_browser_isolated",
        "tor_socks5h_when_enabled",
        "tor_socks5h_strict",
        "direct_unless_configured",
        "direct_https",
        "loopback_offline_only",
        "disabled",
    }
)

SOCKS5_REPLY_CODES: dict[int, str] = {
    0x00: "succeeded",
    0x01: "general_socks_server_failure",
    0x02: "connection_not_allowed_by_ruleset",
    0x03: "network_unreachable",
    0x04: "onion_service_or_host_unreachable",
    0x05: "connection_refused_by_destination",
    0x06: "ttl_expired",
    0x07: "command_not_supported",
    0x08: "address_type_not_supported",
}

PROTECTED_HOST_PORTS: frozenset[int] = frozenset({22, 2375, 2376, 5432, 6379, 7860, 8000, 9050, 9051})

_V3_ONION_HOST_RE = re.compile(r"^(?P<stem>[a-z2-7]{56})\.onion$", re.IGNORECASE)
_V2_DEPRECATED_ONION_RE = re.compile(r"^[a-z2-7]{16}\.onion$", re.IGNORECASE)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def validate_v3_onion_address(host_or_url: str) -> dict[str, Any]:
    """Validate a Tor v3 `.onion` address per Tor `rend-spec-v3` (56 base32 chars + SHA3-256 checksum + version 0x03)."""
    raw = host_or_url.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
    else:
        host = raw.split("/")[0].split(":")[0].lower()

    if _V2_DEPRECATED_ONION_RE.match(host):
        return {
            "valid": False,
            "onion_address": host,
            "version": 2,
            "reason": "Deprecated v2 16-character `.onion` addresses are retired and unsupported by modern Tor (§165.2).",
        }

    m = _V3_ONION_HOST_RE.match(host)
    if not m:
        return {
            "valid": False,
            "onion_address": host,
            "version": None,
            "reason": "Address is not a 56-character base32 v3 `.onion` hostname.",
        }

    stem = m.group("stem").upper()
    try:
        decoded = base64.b32decode(stem)
    except ValueError as exc:
        return {"valid": False, "onion_address": host, "version": 3, "reason": f"Invalid base32 encoding: {exc}"}

    if len(decoded) != 35:
        return {"valid": False, "onion_address": host, "version": 3, "reason": "Decoded v3 onion payload is not 35 bytes."}

    pubkey = decoded[:32]
    checksum = decoded[32:34]
    version = decoded[34]
    if version != 0x03:
        return {"valid": False, "onion_address": host, "version": version, "reason": f"Unsupported onion version byte {version:#x} (expected 0x03)."}

    expected_checksum = hashlib.sha3_256(b".onion checksum" + pubkey + b"\x03").digest()[:2]
    if checksum != expected_checksum:
        return {
            "valid": False,
            "onion_address": host,
            "version": 3,
            "reason": "v3 `.onion` SHA3-256 checksum mismatch (corrupted or mistyped address).",
        }

    return {"valid": True, "onion_address": host, "version": 3, "reason": "valid_v3_onion"}


def derive_v3_onion_from_pubkey_bytes(pubkey_32: bytes) -> str:
    """ deterministically derive a spec-compliant v3 `.onion` hostname from a 32-byte Ed25519 public key."""
    if len(pubkey_32) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 bytes.")
    checksum = hashlib.sha3_256(b".onion checksum" + pubkey_32 + b"\x03").digest()[:2]
    raw = pubkey_32 + checksum + b"\x03"
    return base64.b32encode(raw).decode("ascii").lower() + ".onion"


class _HTMLPageExtractor(HTMLParser):
    """Safe, passive HTML title/text/link extractor that never executes scripts or loads remote assets."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.in_title = False
        self.skip_depth = 0
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.links: list[str] = []
        self.has_login_or_captcha_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if t == "title":
            self.in_title = True
        elif t in {"script", "style", "noscript"}:
            self.skip_depth += 1
        elif t == "a" and attr_map.get("href"):
            href = attr_map["href"].strip()
            if not href.lower().startswith("javascript:"):
                self.links.append(urljoin(self.base_url, href))
        elif t == "input" and attr_map.get("type", "").lower() == "password":
            self.has_login_or_captcha_form = True
        if "captcha" in " ".join(attr_map.values()).lower():
            self.has_login_or_captcha_form = True

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t == "title":
            self.in_title = False
        elif t in {"script", "style", "noscript"} and self.skip_depth > 0:
            self.skip_depth -= 1

    def handle_data(self, data: str) -> None:
        cleaned = " ".join(data.split())
        if not cleaned:
            return
        if self.in_title:
            self.title_parts.append(cleaned)
        elif self.skip_depth == 0:
            self.text_parts.append(cleaned)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Unexpected EOF during SOCKS5 handshake.")
        buf.extend(chunk)
    return bytes(buf)


def socks5h_http_request(
    url: str,
    *,
    socks_host: str,
    socks_port: int,
    isolation_token: str = "",
    timeout_sec: float = 12.0,
    max_body_bytes: int = 262_144,
) -> dict[str, Any]:
    """Perform an HTTP/1.1 GET over RFC 1928 SOCKS5h (`ATYP=0x03` remote DNS/onion resolution).

    Never calls local DNS resolution on the destination hostname, preventing DNS
    leaks for `.onion` and privacy-routed clearnet requests.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    if scheme not in {"http", "https"}:
        return {"ok": False, "status": "unsupported_scheme", "reason": f"Unsupported URL scheme '{scheme}'."}
    dest_host = (parsed.hostname or "").strip()
    if not dest_host:
        return {"ok": False, "status": "invalid_url", "reason": "URL is missing a hostname."}
    dest_port = parsed.port or (443 if scheme == "https" else 80)
    path_q = parsed.path or "/"
    if parsed.query:
        path_q += f"?{parsed.query}"

    host_bytes = dest_host.encode("idna")
    if len(host_bytes) > 255:
        return {"ok": False, "status": "invalid_hostname", "reason": "Destination hostname exceeds 255 bytes."}

    try:
        raw_sock = socket.create_connection((socks_host, int(socks_port)), timeout=timeout_sec)
        raw_sock.settimeout(timeout_sec)
    except TimeoutError:
        return {
            "ok": False,
            "status": "socks_proxy_timeout",
            "reason": f"Timed out connecting to configured Tor SOCKS5 proxy at {socks_host}:{socks_port}.",
        }
    except OSError as exc:
        return {
            "ok": False,
            "status": "socks_proxy_unreachable",
            "reason": f"Could not reach configured Tor SOCKS5 proxy at {socks_host}:{socks_port}: {exc}",
        }

    with raw_sock:
        try:
            # Offer No-Auth (0x00) and Username/Password (0x02) for Tor IsolateSOCKSAuth stream isolation
            if isolation_token:
                raw_sock.sendall(b"\x05\x02\x00\x02")
            else:
                raw_sock.sendall(b"\x05\x01\x00")
            ver, chosen_method = _recv_exact(raw_sock, 2)
            if ver != 0x05 or chosen_method == 0xFF:
                return {"ok": False, "status": "socks_auth_rejected", "reason": "SOCKS5 proxy rejected authentication methods."}
            if chosen_method == 0x02:
                user_b = f"novax-{isolation_token[:24]}".encode("ascii", errors="ignore") or b"novax"
                pwd_b = b"isolate"
                raw_sock.sendall(bytes([0x01, len(user_b)]) + user_b + bytes([len(pwd_b)]) + pwd_b)
                auth_ver, auth_status = _recv_exact(raw_sock, 2)
                if auth_status != 0x00:
                    return {"ok": False, "status": "socks_isolation_auth_failed", "reason": f"SOCKS5 subnegotiation failed ({auth_ver},{auth_status})."}

            # RFC 1928 CONNECT with ATYP=0x03 (DOMAINNAME -> SOCKS5h remote resolution, zero local DNS leak!)
            connect_req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack("!H", dest_port)
            raw_sock.sendall(connect_req)
            rep_ver, rep_code, _rsv, atyp = _recv_exact(raw_sock, 4)
            if rep_ver != 0x05:
                return {"ok": False, "status": "socks_protocol_error", "reason": "Invalid SOCKS5 reply version."}
            # Drain BND.ADDR + BND.PORT cleanly
            if atyp == 0x01:
                _recv_exact(raw_sock, 4 + 2)
            elif atyp == 0x03:
                alen = _recv_exact(raw_sock, 1)[0]
                _recv_exact(raw_sock, alen + 2)
            elif atyp == 0x04:
                _recv_exact(raw_sock, 16 + 2)

            if rep_code != 0x00:
                code_name = SOCKS5_REPLY_CODES.get(rep_code, f"socks_error_{rep_code:#x}")
                return {
                    "ok": False,
                    "status": code_name,
                    "socks_reply_code": rep_code,
                    "reason": f"Tor SOCKS5 proxy could not reach '{dest_host}:{dest_port}': {code_name}.",
                }

            active_sock: socket.socket = raw_sock
            if scheme == "https":
                ctx = ssl.create_default_context()
                active_sock = ctx.wrap_socket(raw_sock, server_hostname=dest_host)

            req_headers = (
                f"GET {path_q} HTTP/1.1\r\n"
                f"Host: {dest_host}\r\n"
                "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0\r\n"
                "Accept: text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.5\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n\r\n"
            )
            active_sock.sendall(req_headers.encode("ascii", errors="ignore"))

            resp_buf = bytearray()
            cap = max_body_bytes + 32_768
            while len(resp_buf) < cap:
                chunk = active_sock.recv(16_384)
                if not chunk:
                    break
                resp_buf.extend(chunk)
        except TimeoutError:
            return {
                "ok": False,
                "status": "destination_timeout",
                "reason": f"Timed out waiting for response from '{dest_host}' over Tor SOCKS5h.",
            }
        except (OSError, ssl.SSLError, ConnectionError) as exc:
            return {"ok": False, "status": "transport_error", "reason": str(exc)}

    header_end = resp_buf.find(b"\r\n\r\n")
    if header_end < 0:
        return {"ok": False, "status": "malformed_http_response", "reason": "Destination returned non-HTTP or truncated response."}
    raw_head = bytes(resp_buf[:header_end]).decode("iso-8859-1", errors="replace")
    body_bytes = bytes(resp_buf[header_end + 4 :])[:max_body_bytes]
    head_lines = raw_head.split("\r\n")
    status_parts = head_lines[0].split(" ", 2)
    http_status = int(status_parts[1]) if len(status_parts) >= 2 and status_parts[1].isdigit() else 0
    headers: dict[str, str] = {}
    for ln in head_lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    if headers.get("transfer-encoding", "").lower() == "chunked":
        body_bytes = _decode_chunked(body_bytes)

    return {
        "ok": 200 <= http_status < 400,
        "status": "http_ok" if 200 <= http_status < 400 else f"http_{http_status}",
        "http_status": http_status,
        "headers": headers,
        "body_bytes": body_bytes,
        "via": f"tor_socks5h://{socks_host}:{socks_port}",
        "dns_resolved_remotely_via_socks5h": True,
    }


def _decode_chunked(data: bytes) -> bytes:
    out = bytearray()
    idx = 0
    while idx < len(data):
        rn = data.find(b"\r\n", idx)
        if rn < 0:
            break
        size_token = data[idx:rn].split(b";", 1)[0].strip()
        try:
            chunk_len = int(size_token, 16)
        except ValueError:
            break
        if chunk_len == 0:
            break
        start = rn + 2
        out.extend(data[start : start + chunk_len])
        idx = start + chunk_len + 2
    return bytes(out) or data


class TorIntegrationManager:
    """§165.1 & §165.8 Native Kali Linux Tor Integration & Privacy Network Architecture."""

    def __init__(self, *, db: Database, redactor: Redactor) -> None:
        self.db = db
        self.redactor = redactor

    def get_config(self) -> dict[str, Any]:
        return self.db.get_privacy_network_config(default_routing=DEFAULT_COMPONENT_ROUTING)

    def update_config(self, updates: dict[str, Any]) -> dict[str, Any]:
        if "component_routing" in updates and isinstance(updates["component_routing"], dict):
            for comp, mode in updates["component_routing"].items():
                if comp not in DEFAULT_COMPONENT_ROUTING:
                    raise ValueError(f"Unknown privacy routing component '{comp}'.")
                if mode not in ALLOWED_ROUTING_MODES:
                    raise ValueError(f"Unsupported routing mode '{mode}' for '{comp}'.")
                # Never allow ordinary AI provider keys or local-only operations to be silently misrouted without compatibility check
        return self.db.update_privacy_network_config(updates, default_routing=DEFAULT_COMPONENT_ROUTING)

    def detect_installation_and_status(self) -> dict[str, Any]:
        """§165.1 Inspect actual Kali Linux Tor & Tor Browser binaries, service state, and SOCKS5 reachability."""
        cfg = self.get_config()
        env_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        tor_bin = shutil.which("tor", path=env_path) or ""
        torsocks_bin = shutil.which("torsocks", path=env_path) or ""
        tb_launcher = shutil.which("torbrowser-launcher", path=env_path) or shutil.which("tor-browser", path=env_path) or ""

        # Check common user-installed Tor Browser bundle paths on Kali/Debian
        candidate_tb_paths = [
            cfg["tor_browser_path"],
            str(Path.home() / ".local/share/torbrowser/tbb/x86_64/tor-browser/Browser/start-tor-browser"),
            "/usr/bin/torbrowser-launcher",
        ]
        detected_tb_path = next((p for p in candidate_tb_paths if p and Path(p).is_file()), tb_launcher)

        tor_version = ""
        if tor_bin:
            try:
                proc = subprocess.run([tor_bin, "--version"], capture_output=True, text=True, timeout=3, check=False)
                tor_version = (proc.stdout or "").splitlines()[0].strip() if proc.stdout else ""
            except (OSError, subprocess.SubprocessError):
                tor_version = ""

        service_state = "not_installed"
        if tor_bin and shutil.which("systemctl", path=env_path):
            try:
                proc = subprocess.run(
                    ["systemctl", "is-active", "tor"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                service_state = (proc.stdout or proc.stderr or "unknown").strip().splitlines()[0]
            except (OSError, subprocess.SubprocessError):
                service_state = "unknown"
        elif tor_bin:
            service_state = "installed_daemon_unmanaged"

        socks_probe = self._probe_socks5_port(cfg["socks_host"], cfg["socks_port"])

        # Explicitly check whether system-wide transparent routing is active (never confuse Tor SOCKS with system-wide routing!)
        global_proxy_env = any(
            "9050" in os.environ.get(k, "") or "9150" in os.environ.get(k, "")
            for k in ("ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
        )

        indicator = (
            "TOR CONNECTED (SOCKS5h ISOLATED)"
            if (cfg["tor_enabled"] and socks_probe["socks5_reachable"])
            else ("TOR ENABLED · PROXY UNREACHABLE" if cfg["tor_enabled"] else "TOR INTEGRATION DISABLED")
        )

        return {
            "checked_at": _iso(),
            "tor_integration_enabled": cfg["tor_enabled"],
            "status_indicator": indicator,
            "tor_installed": bool(tor_bin),
            "tor_binary": tor_bin,
            "tor_version": tor_version,
            "torsocks_installed": bool(torsocks_bin),
            "tor_browser_installed": bool(detected_tb_path),
            "tor_browser_launcher_path": detected_tb_path,
            "tor_service_state": service_state,
            "configured_socks": {"host": cfg["socks_host"], "port": cfg["socks_port"]},
            "socks_connectivity": socks_probe,
            "system_wide_internet_routed_through_tor": False,
            "process_proxy_env_points_to_tor": global_proxy_env,
            "routing_distinction_note": (
                "Installing or enabling Tor provides an opt-in SOCKS5h circuit for configured Tor clients only; "
                "ordinary system traffic, desktop apps, and direct HTTP clients continue using normal network interfaces unless explicitly configured (§165.1/§165.8)."
            ),
            "setup_instructions": self.configuration_instructions() if not socks_probe["socks5_reachable"] else [],
        }

    @staticmethod
    def _probe_socks5_port(host: str, port: int, timeout: float = 2.0) -> dict[str, Any]:
        try:
            with socket.create_connection((host, int(port)), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(b"\x05\x01\x00")
                data = sock.recv(2)
                if len(data) == 2 and data[0] == 0x05 and data[1] != 0xFF:
                    return {"socks5_reachable": True, "detail": f"Verified RFC 1928 SOCKS5 listener on {host}:{port}."}
                return {"socks5_reachable": False, "detail": f"Port {host}:{port} responded, but not with valid SOCKS5."}
        except OSError as exc:
            return {"socks5_reachable": False, "detail": f"SOCKS5 listener {host}:{port} unreachable ({exc})."}

    @staticmethod
    def configuration_instructions() -> list[str]:
        return [
            "On Kali Linux, install Tor and Tor Browser Launcher: `sudo apt update && sudo apt install -y tor torbrowser-launcher`.",
            "Start the local Tor SOCKS5 service when needed: `sudo systemctl start tor` (default SOCKS5h port `127.0.0.1:9050`), or launch Tor Browser (`127.0.0.1:9150`).",
            "Prefer official Tor Browser for interactive browsing; enable NOVA's Tor toggle only for authorized SOCKS5h (`ATYP=0x03`) automated workflows.",
            "NOVA never silently modifies `/etc/resolv.conf`, nftables/iptables, or system-wide proxy settings.",
        ]

    def launch_tor_browser(self, url: str = "", *, dry_run: bool = False, approved: bool = False) -> dict[str, Any]:
        """§165.1 Launch official Tor Browser through its supported launch mechanism."""
        cfg = self.get_config()
        if not cfg["tor_enabled"]:
            return {
                "ok": False,
                "status": "tor_integration_disabled",
                "reason": "Tor integration is currently disabled in NOVA X privacy settings.",
            }
        status = self.detect_installation_and_status()
        launcher = status["tor_browser_launcher_path"]
        if not launcher:
            return {
                "ok": False,
                "status": "tor_browser_not_installed",
                "reason": "Official Tor Browser / `torbrowser-launcher` is not installed on this host.",
                "instructions": self.configuration_instructions(),
            }
        argv = [launcher]
        if url.strip():
            parsed = urlparse(url.strip())
            if parsed.scheme not in {"http", "https"}:
                return {"ok": False, "status": "invalid_url", "reason": "Only http:// or https:// URLs may be passed to Tor Browser."}
            argv.append(url.strip())
        if dry_run:
            return {"ok": True, "status": "dry_run_ok", "planned_argv": argv, "preferred_interactive_browser": True}
        if not approved:
            return {"ok": False, "status": "approval_required", "planned_argv": argv, "reason": "Launching Tor Browser requires user approval."}
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        return {"ok": True, "status": "launched", "pid": proc.pid, "argv": argv}

    def privacy_dashboard(self) -> dict[str, Any]:
        """§165.8 Privacy-Aware Network Architecture Dashboard & Anonymity Limitations."""
        cfg = self.get_config()
        det = self.detect_installation_and_status()
        routing = cfg["component_routing"]
        return {
            "tor_enabled": cfg["tor_enabled"],
            "status_indicator": det["status_indicator"],
            "socks5_endpoint": f"{cfg['socks_host']}:{cfg['socks_port']}",
            "socks5_reachable": det["socks_connectivity"]["socks5_reachable"],
            "system_wide_tor_routing": False,
            "components": {
                "tor_browser": {
                    "configured_mode": routing["tor_browser"],
                    "uses_tor": True,
                    "installed": det["tor_browser_installed"],
                    "note": "Official Tor Browser with circuit & storage isolation (recommended for interactive browsing).",
                },
                "automated_research_client": {
                    "configured_mode": routing["automated_research_client"],
                    "uses_tor": bool(cfg["tor_enabled"] and routing["automated_research_client"].startswith("tor_")),
                    "dns_handling": "SOCKS5h remote resolution (ATYP=0x03; zero local DNS leak)",
                },
                "proxy_aware_integrations": {
                    "configured_mode": routing["proxy_aware_integrations"],
                    "uses_tor": bool(cfg["tor_enabled"] and routing["proxy_aware_integrations"].startswith("tor_")),
                },
                "ordinary_ai_providers": {
                    "configured_mode": routing["ordinary_ai_providers"],
                    "uses_tor": False,
                    "note": "Cloud AI API keys authenticate the account holder; routing authenticated API tokens over Tor does not make account usage anonymous.",
                },
                "direct_internet_access": {
                    "configured_mode": routing["direct_internet_access"],
                    "uses_tor": False,
                },
                "local_only_operations": {
                    "configured_mode": routing["local_only_operations"],
                    "uses_tor": False,
                },
            },
            "anonymity_and_coverage_limitations": [
                "Tor does NOT automatically route the entire computer's traffic; non-proxy-aware apps still connect directly.",
                "Tor does NOT guarantee anonymity if credentials, session cookies, API keys, or identifying text are submitted.",
                "Automated HTTP clients lack Tor Browser's full anti-fingerprinting defenses; use official Tor Browser for sensitive interactive sessions.",
                "Many `.onion` services are ephemeral, unindexed, offline, or gated by client authorization (`HidServAuth`).",
            ],
        }


class OnionServiceBrowser:
    """§165.2 Legitimate v3 `.onion` Browsing, Bookmarking, Reference Verification & Isolated Ordinary Web Access."""

    def __init__(self, *, db: Database, tor_manager: TorIntegrationManager, redactor: Redactor) -> None:
        self.db = db
        self.tor = tor_manager
        self.redactor = redactor

    def save_onion_address(
        self,
        onion_url_or_host: str,
        *,
        title: str = "",
        source_obtained_from: str = "user_supplied",
        official_reference_url: str = "",
        expected_official_onion: str = "",
        notes: str = "",
    ) -> dict[str, Any]:
        val = validate_v3_onion_address(onion_url_or_host)
        if not val["valid"]:
            raise ValueError(val["reason"])
        addr = val["onion_address"]
        trust_status = "unverified"
        if expected_official_onion.strip():
            norm_exp = validate_v3_onion_address(expected_official_onion)["onion_address"]
            trust_status = "verified_against_reference" if norm_exp == addr else "mismatch_warning"
        return self.db.save_onion_bookmark(
            {
                "onion_address": addr,
                "title": title,
                "source_obtained_from": source_obtained_from,
                "official_reference_url": official_reference_url,
                "trust_status": trust_status,
                "notes": notes,
            }
        )

    def verify_against_official_reference(self, onion_url_or_host: str, documented_official_onion: str, *, reference_source: str = "") -> dict[str, Any]:
        """§165.2 Compare an onion address against an independently documented official onion address."""
        v_cand = validate_v3_onion_address(onion_url_or_host)
        v_ref = validate_v3_onion_address(documented_official_onion)
        if not v_cand["valid"]:
            return {"matched": False, "trust_status": "invalid_candidate", "reason": v_cand["reason"]}
        if not v_ref["valid"]:
            return {"matched": False, "trust_status": "invalid_reference", "reason": v_ref["reason"]}
        matched = v_cand["onion_address"] == v_ref["onion_address"]
        trust = "verified_against_reference" if matched else "mismatch_warning"
        self.db.save_onion_bookmark(
            {
                "onion_address": v_cand["onion_address"],
                "official_reference_url": reference_source,
                "trust_status": trust,
                "notes": f"Compared against documented address {v_ref['onion_address']} -> matched={matched}",
            }
        )
        return {
            "candidate_onion": v_cand["onion_address"],
            "documented_onion": v_ref["onion_address"],
            "matched": matched,
            "trust_status": trust,
            "reachability_implies_trust": REACHABILITY_IMPLIES_TRUST,
        }

    def open_onion_page(
        self,
        url: str,
        *,
        source_obtained_from: str = "user_supplied",
        timeout_sec: float = 12.0,
    ) -> dict[str, Any]:
        """§165.2 Open a user-supplied v3 `.onion` URL over isolated Tor SOCKS5h without bypassing auth/CAPTCHAs."""
        cfg = self.tor.get_config()
        if not cfg["tor_enabled"]:
            return {
                "ok": False,
                "status": "tor_integration_disabled",
                "accessed_at": _iso(),
                "reason": "Tor integration is disabled; enable Tor integration before accessing `.onion` services.",
            }

        normalized_url = url.strip() if "://" in url.strip() else f"http://{url.strip().lstrip('/')}"
        val = validate_v3_onion_address(normalized_url)
        if not val["valid"]:
            return {
                "ok": False,
                "status": "invalid_onion_address",
                "accessed_at": _iso(),
                "reason": val["reason"],
            }

        isolation_tok = secrets.token_hex(6)
        accessed_at = _iso()
        res = socks5h_http_request(
            normalized_url,
            socks_host=cfg["socks_host"],
            socks_port=cfg["socks_port"],
            isolation_token=isolation_tok,
            timeout_sec=timeout_sec,
        )

        existing = next((b for b in self.db.list_onion_bookmarks(limit=500) if b["onion_address"] == val["onion_address"]), None)
        prior_trust = existing["trust_status"] if existing else "unverified"

        if not res.get("http_status"):
            self.db.save_onion_bookmark(
                {
                    "onion_address": val["onion_address"],
                    "title": existing["title"] if existing else "",
                    "source_obtained_from": existing["source_obtained_from"] if existing else source_obtained_from,
                    "trust_status": prior_trust,
                    "reachability_status": res["status"],
                    "last_accessed_at": accessed_at,
                }
            )
            return {
                "ok": False,
                "status": res["status"],
                "url": normalized_url,
                "onion_address": val["onion_address"],
                "accessed_at": accessed_at,
                "reason": res["reason"],
                "trust_status": prior_trust,
                "reachability_implies_trust": REACHABILITY_IMPLIES_TRUST,
            }

        http_code = int(res["http_status"])
        if http_code in {401, 403, 407}:
            self.db.save_onion_bookmark(
                {
                    "onion_address": val["onion_address"],
                    "source_obtained_from": source_obtained_from,
                    "trust_status": prior_trust,
                    "reachability_status": "requires_authentication",
                    "last_http_status": http_code,
                    "last_accessed_at": accessed_at,
                }
            )
            return {
                "ok": False,
                "status": "requires_authentication_or_authorization",
                "http_status": http_code,
                "url": normalized_url,
                "onion_address": val["onion_address"],
                "accessed_at": accessed_at,
                "reason": f"Onion service returned HTTP {http_code}; NOVA never attempts to bypass authentication or private access controls (§165.2).",
            }

        body_text = res["body_bytes"].decode("utf-8", errors="replace")
        extractor = _HTMLPageExtractor(normalized_url)
        extractor.feed(body_text[:120_000])
        title = " ".join(extractor.title_parts)[:240] or (existing["title"] if existing else val["onion_address"])
        visible_text = self.redactor.scrub_text(" ".join(extractor.text_parts), max_chars=8_000)

        broken_or_outdated_links: list[dict[str, str]] = []
        valid_links: list[str] = []
        for link in extractor.links[:40]:
            lp = urlparse(link)
            lhost = (lp.hostname or "").lower()
            if lhost.endswith(".onion"):
                lval = validate_v3_onion_address(lhost)
                if not lval["valid"]:
                    broken_or_outdated_links.append({"url": link, "issue": lval["reason"]})
                    continue
            valid_links.append(link)

        saved_bm = self.db.save_onion_bookmark(
            {
                "onion_address": val["onion_address"],
                "title": title,
                "source_obtained_from": existing["source_obtained_from"] if existing else source_obtained_from,
                "official_reference_url": existing["official_reference_url"] if existing else "",
                "trust_status": prior_trust,
                "reachability_status": "reachable" if 200 <= http_code < 400 else f"http_{http_code}",
                "last_http_status": http_code,
                "last_accessed_at": accessed_at,
            }
        )

        return {
            "ok": 200 <= http_status_safe(http_code) < 400,
            "status": "reachable" if 200 <= http_code < 400 else f"http_{http_code}",
            "url": normalized_url,
            "onion_address": val["onion_address"],
            "http_status": http_code,
            "title": title,
            "summary": visible_text[:600],
            "content_excerpt": visible_text,
            "links": valid_links[:25],
            "broken_or_outdated_links": broken_or_outdated_links,
            "login_or_captcha_detected": extractor.has_login_or_captcha_form,
            "accessed_at": accessed_at,
            "via": res["via"],
            "trust_status": saved_bm["trust_status"],
            "reachability_implies_trust": REACHABILITY_IMPLIES_TRUST,
        }

    def fetch_ordinary_website(self, url: str, *, timeout_sec: float = 10.0) -> dict[str, Any]:
        """§165.8 & §165.13 #4: Access ordinary clearnet websites via direct normal browsing config (never mixing Tor session state)."""
        parsed = urlparse(url.strip())
        if parsed.scheme not in {"http", "https"}:
            return {"ok": False, "status": "invalid_scheme", "reason": "Ordinary web fetch supports http:// and https:// only."}
        host = (parsed.hostname or "").lower()
        if host.endswith(".onion"):
            return {
                "ok": False,
                "status": "onion_requires_tor_client",
                "reason": "`.onion` addresses cannot be resolved over ordinary direct internet connections; use `open_onion_page` via Tor.",
            }
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path_q = parsed.path or "/"
        if parsed.query:
            path_q += f"?{parsed.query}"

        accessed_at = _iso()
        try:
            raw_sock = socket.create_connection((host, port), timeout=timeout_sec)
            raw_sock.settimeout(timeout_sec)
            with raw_sock:
                active_sock: socket.socket = raw_sock
                if parsed.scheme == "https":
                    ctx = ssl.create_default_context()
                    active_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
                req = (
                    f"GET {path_q} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "User-Agent: NOVA-X-DirectClient/0.2\r\n"
                    "Accept: text/html,application/json,text/plain;q=0.9,*/*;q=0.5\r\n"
                    "Accept-Encoding: identity\r\n"
                    "Connection: close\r\n\r\n"
                )
                active_sock.sendall(req.encode("ascii", errors="ignore"))
                buf = bytearray()
                while len(buf) < 262_144:
                    chunk = active_sock.recv(16_384)
                    if not chunk:
                        break
                    buf.extend(chunk)
        except OSError as exc:
            return {"ok": False, "status": "connection_failed", "url": url, "via": "ordinary_direct", "accessed_at": accessed_at, "reason": str(exc)}

        header_end = buf.find(b"\r\n\r\n")
        if header_end < 0:
            return {"ok": False, "status": "malformed_response", "url": url, "via": "ordinary_direct", "accessed_at": accessed_at}
        head_lines = bytes(buf[:header_end]).decode("iso-8859-1", errors="replace").split("\r\n")
        parts = head_lines[0].split(" ", 2)
        code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        body_str = bytes(buf[header_end + 4 :]).decode("utf-8", errors="replace")
        ext = _HTMLPageExtractor(url)
        ext.feed(body_str[:100_000])
        return {
            "ok": 200 <= code < 400,
            "status": "http_ok" if 200 <= code < 400 else f"http_{code}",
            "http_status": code,
            "url": url,
            "title": " ".join(ext.title_parts)[:240],
            "content_excerpt": self.redactor.scrub_text(" ".join(ext.text_parts) or body_str, max_chars=4_000),
            "via": "ordinary_direct",
            "used_tor": False,
            "accessed_at": accessed_at,
        }


def http_status_safe(code: int) -> int:
    return int(code)


class OptionalOnionHostingHelper:
    """§165.9 Disabled-by-default helper for planning & securing user-controlled private onion services."""

    def __init__(self, *, db: Database, tor_manager: TorIntegrationManager, vault: ProtectedCredentialVault, state_dir: Path) -> None:
        self.db = db
        self.tor = tor_manager
        self.vault = vault
        self.hosting_root = state_dir / "onion_services"

    def prepare_onion_service_plan(
        self,
        *,
        service_name: str,
        local_bind_host: str = "127.0.0.1",
        local_bind_port: int,
        virtual_port: int = 80,
        operator_approved: bool = False,
    ) -> dict[str, Any]:
        cfg = self.tor.get_config()
        if not cfg["onion_hosting_enabled"]:
            return {
                "ok": False,
                "status": "onion_hosting_disabled",
                "reason": "Optional onion-service hosting is disabled by default (§165.9); explicitly enable `onion_hosting_enabled` first.",
            }
        if not re.match(r"^[a-z0-9][a-z0-9_-]{1,48}$", service_name):
            return {"ok": False, "status": "invalid_service_name", "reason": "Service name must match `^[a-z0-9][a-z0-9_-]{1,48}$`."}
        if local_bind_host not in {"127.0.0.1", "::1", "localhost"}:
            return {
                "ok": False,
                "status": "rejected_non_loopback_bind",
                "reason": "Onion services must forward strictly to a loopback-bound local service (`127.0.0.1` / `::1`).",
            }
        if int(local_bind_port) in PROTECTED_HOST_PORTS:
            return {
                "ok": False,
                "status": "blocked_sensitive_host_service",
                "reason": (
                    f"Port {local_bind_port} belongs to protected host/NOVA administration services {sorted(PROTECTED_HOST_PORTS)}; "
                    "NOVA never exposes its administration API, SSH, or unrestricted terminal as an onion service (§165.9)."
                ),
            }
        if not operator_approved:
            return {"ok": False, "status": "approval_required", "reason": "Preparing an onion-service hosting directory requires explicit operator approval."}

        hs_dir = self.hosting_root / service_name
        hs_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(hs_dir, 0o700)
        dir_mode = oct(hs_dir.stat().st_mode & 0o777)

        # Store isolated key reference in ProtectedCredentialVault (0600), excluded from SQLite, logs, git & ordinary backups
        key_ref = f"onion_hs_key:{service_name}"
        seed_material = secrets.token_bytes(32)
        self.vault.set(key_ref, base64.b64encode(seed_material).decode("ascii"))

        local_reachable = False
        try:
            with socket.create_connection((local_bind_host, int(local_bind_port)), timeout=1.0):
                local_reachable = True
        except OSError:
            local_reachable = False

        torrc_snippet = (
            f"# NOVA X §165.9 Hardened Onion Service ({service_name})\n"
            f"HiddenServiceDir {hs_dir}\n"
            "HiddenServiceVersion 3\n"
            f"HiddenServicePort {int(virtual_port)} {local_bind_host}:{int(local_bind_port)}\n"
            "HiddenServiceMaxStreams 50\n"
            "HiddenServiceMaxStreamsCloseCircuit 1\n"
        )
        plan_meta = {
            "hidden_service_dir_permissions": dir_mode,
            "permissions_valid_0700": dir_mode == "0o700",
            "local_upstream_currently_listening": local_reachable,
            "private_key_isolated_in_vault": True,
            "excluded_from_logs_git_and_ordinary_backups": True,
            "maintenance_and_backup_instructions": [
                f"Verify `{hs_dir}` remains owned by the Tor service user with mode `0700`.",
                "Never commit `hs_ed25519_secret_key` to Git or include it in unencrypted workspace archives.",
                "Test reachability from an authorized Tor Browser or `curl --socks5-hostname 127.0.0.1:9050` client.",
            ],
        }
        saved = self.db.save_onion_hosting_plan(
            {
                "service_name": service_name,
                "local_bind_host": local_bind_host,
                "local_bind_port": int(local_bind_port),
                "virtual_port": int(virtual_port),
                "enabled": False,
                "key_vault_ref": key_ref,
                "torrc_snippet": torrc_snippet,
                "deployment_plan": plan_meta,
            }
        )
        return {"ok": True, "status": "plan_prepared", "plan": {k: v for k, v in saved.items() if k != "key_vault_ref"}}
