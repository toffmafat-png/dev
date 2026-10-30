"""§165.5 Threat Intelligence & Defensive Security Analysis,
§165.6 Organizational Exposure & Leak Monitoring, and
§165.7 Secure Download & File-Analysis Pipeline.

Hard security & ethical invariants:
- `COLLECT_OR_USE_STOLEN_CREDENTIALS = False`
- `CLAIM_BREACH_FROM_UNVERIFIED_POST = False`
- `AUTO_OPEN_EXECUTE_OR_INSTALL_DOWNLOADS = False`
- `LOAD_REMOTE_RESOURCES_DURING_STATIC_ANALYSIS = False`
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import shutil
import subprocess
import tarfile
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from nova.db import Database
from nova.observability import Redactor
from nova.privacy_intel.tor_network import (
    OnionServiceBrowser,
    TorIntegrationManager,
    socks5h_http_request,
    validate_v3_onion_address,
)

COLLECT_OR_USE_STOLEN_CREDENTIALS = False
CLAIM_BREACH_FROM_UNVERIFIED_POST = False
AUTO_OPEN_EXECUTE_OR_INSTALL_DOWNLOADS = False
LOAD_REMOTE_RESOURCES_DURING_STATIC_ANALYSIS = False

PROHIBITED_OFFENSIVE_OR_CONTRABAND_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        r"\b(?:buy|purchase|acquire|download|harvest|collect|distribute)\s+(?:stolen\s+)?(?:credentials?|combo\s*lists?|credit\s*cards?|fullz|ssn|breached\s+database|stealer\s+logs?)\b",
        "stolen_credentials_or_personal_records_prohibited",
    ),
    (
        r"\b(?:log\s*in|authenticate|stuff\s+credentials?|access\s+account)\s+(?:using|with)\s+(?:leaked|discovered|stolen|dumped)\b",
        "unauthorized_credential_use_prohibited",
    ),
    (
        r"\b(?:deploy\s+(?:ransomware|malware|wiper)|exploit\s+unauthorized|bypass\s+captcha\s+on\s+private\s+onion)\b",
        "offensive_compromise_or_access_bypass_prohibited",
    ),
)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:onion|com|net|org|io|gov|edu|ai|dev|xyz|ru|cn)\b", re.IGNORECASE)
_EMAIL_PII_RE = re.compile(r"\b([a-zA-Z0-9_.+-]{1,64})@([a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+)\b")

SECRET_EXPOSURE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pem_private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PRIVATE )?KEY-----")),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_personal_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{24,}\b")),
    ("generic_api_secret", re.compile(r"\b(?:sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{16,})\b")),
)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def check_request_ethics_guardrail(text: str) -> dict[str, Any]:
    """§165.5, §165.6 & §165.12 Enforce strict defensive-only, anti-contraband & anti-compromise policy."""
    for pat, code in PROHIBITED_OFFENSIVE_OR_CONTRABAND_PATTERNS:
        if re.search(pat, text, flags=re.IGNORECASE):
            return {
                "allowed": False,
                "violation_code": code,
                "reason": (
                    f"Request blocked by NOVA X §165.12 defensive security boundary (`{code}`): "
                    "NOVA never purchases, collects, uses, or distributes stolen credentials/breached databases, "
                    "logs into accounts with leaked credentials, bypasses private access controls, or deploys malware."
                ),
            }
    return {"allowed": True, "violation_code": "", "reason": "permitted_defensive_or_osint_operation"}


def minimize_pii_in_text(text: str) -> str:
    """§165.6 Minimize retention of exposed personal data while preserving domain-level exposure telemetry."""
    def _mask_email(match: re.Match[str]) -> str:
        local_part, domain = match.group(1), match.group(2)
        digest = hashlib.sha256(local_part.lower().encode("utf-8")).hexdigest()[:8]
        return f"<redacted-user-{digest}>@{domain.lower()}"

    scrubbed = _EMAIL_PII_RE.sub(_mask_email, text)
    # Scrub `email:password` / `user:password` style credential combo lines if accidentally present in a public paste
    scrubbed = re.sub(
        r"(<redacted-user-[0-9a-f]{8}>@[a-z0-9.-]+)\s*[:;|]\s*\S+",
        r"\1:<credential-value-discarded>",
        scrubbed,
        flags=re.IGNORECASE,
    )
    return scrubbed


def extract_structured_iocs(text: str) -> dict[str, list[str]]:
    """§165.5 Extract structured defensive IOCs (CVEs, public IPs, SHA-256, MD5, domains/onions)."""
    cves = sorted({m.group(0).upper() for m in _CVE_RE.finditer(text)})
    sha256s = sorted({m.group(0).lower() for m in _SHA256_RE.finditer(text)})
    # Avoid matching substrings of SHA-256 as MD5
    sha_joined = " ".join(sha256s)
    md5s = sorted({m.group(0).lower() for m in _MD5_RE.finditer(text) if m.group(0).lower() not in sha_joined})

    _rfc1918 = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    public_ips: set[str] = set()
    private_or_local_ips: set[str] = set()
    for m in _IPV4_RE.finditer(text):
        cand = m.group(0)
        try:
            ip_obj = ipaddress.IPv4Address(cand)
            if ip_obj.is_loopback or ip_obj.is_link_local or any(ip_obj in net for net in _rfc1918):
                private_or_local_ips.add(cand)
            else:
                public_ips.add(cand)
        except ValueError:
            continue

    domains = sorted({m.group(0).lower() for m in _DOMAIN_RE.finditer(text)})
    return {
        "cves": cves,
        "sha256": sha256s,
        "md5": md5s,
        "public_ips": sorted(public_ips),
        "local_ips": sorted(private_or_local_ips),
        "domains": domains,
    }


class ThreatIntelligenceAnalyzer:
    """§165.5 Defensive Threat Intelligence, Log IOC Correlation & Software CVE Tracking."""

    def __init__(self, *, db: Database, redactor: Redactor) -> None:
        self.db = db
        self.redactor = redactor

    def ingest_external_advisory(
        self,
        *,
        title: str,
        advisory_text: str,
        source_url: str,
        is_official_vendor_or_cert: bool = False,
        severity: str = "medium",
    ) -> dict[str, Any]:
        guard = check_request_ethics_guardrail(f"{title}\n{advisory_text}")
        if not guard["allowed"]:
            return {"ok": False, "status": "blocked_by_ethics_guardrail", **guard}

        sanitized = self.redactor.scrub_text(minimize_pii_in_text(advisory_text), max_chars=4_000)
        iocs = extract_structured_iocs(advisory_text)
        confidence = "verified_fact" if is_official_vendor_or_cert else "claim"
        remediation = self._build_remediation_guidance(iocs, finding_kind="advisory")

        saved = self.db.add_threat_intel_finding(
            {
                "finding_kind": "security_advisory",
                "source_classification": "external_report",
                "confidence_tier": confidence,
                "severity": severity,
                "asset_scope": ",".join(iocs["cves"][:5]),
                "indicators": iocs,
                "summary": f"{title}: {sanitized[:600]}",
                "remediation": remediation,
                "source_refs": [{"url": source_url, "ingested_at": _iso(), "official": is_official_vendor_or_cert}],
            }
        )
        return {"ok": True, "finding": saved}

    def analyze_supplied_logs(
        self,
        log_text: str,
        *,
        log_source_label: str = "supplied_host_log",
        watch_indicators: list[str] | None = None,
    ) -> dict[str, Any]:
        """§165.5 Analyze user-supplied logs and record verified local observations separately from external reports."""
        iocs = extract_structured_iocs(log_text)
        watch_set = {w.strip().lower() for w in (watch_indicators or []) if w.strip()}
        # Also correlate against IOCs from stored external advisories
        for prev in self.db.list_threat_intel_findings(limit=100):
            ind = prev.get("indicators") or {}
            for key in ("public_ips", "sha256", "domains", "cves"):
                for val in ind.get(key) or []:
                    watch_set.add(str(val).lower())

        observed_tokens = set(iocs["public_ips"] + iocs["sha256"] + iocs["md5"] + iocs["domains"] + [c.lower() for c in iocs["cves"]])
        matched_iocs = sorted(observed_tokens & watch_set)
        suspicious_auth_events = len(re.findall(r"\b(?:failed password|authentication failure|invalid user|segfault|unauthorized)\b", log_text, re.IGNORECASE))

        severity = "high" if matched_iocs else ("medium" if suspicious_auth_events >= 3 else "info")
        summary = (
            f"Local log inspection (`{log_source_label}`): matched {len(matched_iocs)} known IOC(s) "
            f"and {suspicious_auth_events} authentication/anomaly event(s)."
        )
        saved = self.db.add_threat_intel_finding(
            {
                "finding_kind": "local_log_analysis",
                "source_classification": "verified_local_observation",
                "confidence_tier": "verified_fact",
                "severity": severity,
                "asset_scope": log_source_label,
                "indicators": {**iocs, "matched_known_iocs": matched_iocs, "auth_anomaly_count": suspicious_auth_events},
                "summary": summary,
                "remediation": self._build_remediation_guidance(iocs, finding_kind="local_log", matched=matched_iocs),
                "source_refs": [{"local_source": log_source_label, "analyzed_at": _iso()}],
            }
        )
        return {
            "ok": True,
            "finding": saved,
            "matched_known_iocs": matched_iocs,
            "auth_anomaly_count": suspicious_auth_events,
            "separated_from_external_reports": True,
        }

    def check_software_versions(
        self,
        installed_versions: dict[str, str],
        *,
        advisory_rules: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """§165.5 Track installed software versions against supplied/known CVE advisory thresholds."""
        rules = list(advisory_rules or [])
        matches: list[dict[str, Any]] = []
        for pkg, cur_ver in installed_versions.items():
            pkg_l = pkg.strip().lower()
            for rule in rules:
                if str(rule.get("package", "")).strip().lower() == pkg_l:
                    fixed_ver = str(rule.get("fixed_version") or "")
                    if fixed_ver and _version_tuple(cur_ver) < _version_tuple(fixed_ver):
                        cve = str(rule.get("cve") or "ADVISORY")
                        matches.append(
                            {
                                "package": pkg,
                                "installed_version": cur_ver,
                                "fixed_version": fixed_ver,
                                "cve": cve,
                                "severity": str(rule.get("severity") or "high"),
                            }
                        )
        if matches:
            self.db.add_threat_intel_finding(
                {
                    "finding_kind": "vulnerable_software_version",
                    "source_classification": "verified_local_observation",
                    "confidence_tier": "verified_fact",
                    "severity": "high",
                    "asset_scope": "local_packages",
                    "indicators": {"vulnerable_packages": matches},
                    "summary": f"Detected {len(matches)} package(s) below patched advisory versions.",
                    "remediation": "Upgrade affected packages via `sudo apt update && sudo apt install --only-upgrade <pkg>` and restart dependent services.",
                    "source_refs": [{"checked_at": _iso()}],
                }
            )
        return {"checked_packages": len(installed_versions), "vulnerable_matches": matches}

    @staticmethod
    def _build_remediation_guidance(iocs: dict[str, list[str]], *, finding_kind: str, matched: list[str] | None = None) -> str:
        steps: list[str] = []
        if iocs.get("cves"):
            steps.append(f"Review vendor patches and mitigations for {', '.join(iocs['cves'][:5])}.")
        if matched:
            steps.append(f"Isolate affected host/session and investigate local telemetry hits: {', '.join(matched[:5])}.")
        if iocs.get("sha256") or iocs.get("md5"):
            steps.append("Verify local binaries against known-good package hashes without executing untrusted artifacts.")
        if not steps:
            steps.append(f"Retain `{finding_kind}` telemetry for defensive correlation and monitor official advisories.")
        return " ".join(steps)


def _version_tuple(ver: str) -> tuple[int, ...]:
    nums = [int(x) for x in re.findall(r"\d+", ver)[:6]]
    return tuple(nums or [0])


class OrganizationalExposureMonitor:
    """§165.6 Authorized Asset Exposure & Secret-Leak Monitoring (Zero Unverified Breach Claims, Zero Contraband)."""

    def __init__(self, *, db: Database, redactor: Redactor) -> None:
        self.db = db
        self.redactor = redactor

    def assess_authorized_exposure(
        self,
        *,
        organization_name: str,
        authorized_domains: list[str],
        operator_authorized: bool,
        external_posts_or_notices: list[dict[str, Any]] | None = None,
        local_scan_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        if not operator_authorized:
            return {
                "ok": False,
                "status": "authorization_required",
                "reason": "Organizational exposure monitoring operates strictly on user-owned or explicitly authorized assets (§165.6).",
            }

        domains_norm = [d.strip().lower() for d in authorized_domains if d.strip()]
        external_findings: list[dict[str, Any]] = []
        local_secret_findings: list[dict[str, Any]] = []

        for item in external_posts_or_notices or []:
            raw_text = str(item.get("text") or "")
            guard = check_request_ethics_guardrail(raw_text)
            if not guard["allowed"]:
                return {"ok": False, "status": "blocked_by_ethics_guardrail", **guard}

            src_url = str(item.get("source_url") or "external_mention")
            verified_notice = bool(item.get("is_official_disclosure", False))
            minimized = minimize_pii_in_text(raw_text)
            mentioned = [d for d in domains_norm if d in minimized.lower()]
            if not mentioned and organization_name.lower() not in minimized.lower():
                continue

            # §165.6: Never claim an organization is breached merely because an unverified post says so!
            confidence = "verified_fact" if verified_notice else "claim"
            breach_confirmed = bool(verified_notice)
            summary = (
                f"Official disclosure mentioning {', '.join(mentioned) or organization_name}: {minimized[:300]}"
                if verified_notice
                else (
                    f"UNVERIFIED external mention of {', '.join(mentioned) or organization_name} at `{src_url}` "
                    f"(breach NOT confirmed; requires independent local telemetry & official verification): {minimized[:300]}"
                )
            )
            rec = self.db.add_threat_intel_finding(
                {
                    "finding_kind": "org_exposure_mention",
                    "source_classification": "external_report",
                    "confidence_tier": confidence,
                    "severity": "high" if verified_notice else "medium",
                    "asset_scope": organization_name,
                    "indicators": {"matched_domains": mentioned, "breach_confirmed": breach_confirmed},
                    "summary": summary,
                    "remediation": (
                        "Correlate against local authentication/audit logs, verify whether referenced assets exist, "
                        "and rotate any demonstrably exposed credentials without interacting with extortion actors."
                    ),
                    "source_refs": [{"url": src_url, "official_disclosure": verified_notice}],
                }
            )
            external_findings.append({**rec, "breach_confirmed": breach_confirmed})

        for raw_p in local_scan_paths or []:
            p = Path(raw_p)
            targets = [p] if p.is_file() else (sorted(p.rglob("*"))[:80] if p.is_dir() else [])
            for fp in targets:
                if not fp.is_file() or fp.stat().st_size > 512_000:
                    continue
                content = fp.read_text(encoding="utf-8", errors="ignore")
                detected_kinds = [label for label, regex in SECRET_EXPOSURE_PATTERNS if regex.search(content)]
                if detected_kinds:
                    rec = self.db.add_threat_intel_finding(
                        {
                            "finding_kind": "exposed_repository_secret",
                            "source_classification": "verified_local_observation",
                            "confidence_tier": "verified_fact",
                            "severity": "high",
                            "asset_scope": organization_name,
                            "indicators": {"file": str(fp), "secret_types": detected_kinds},
                            "summary": f"Verified local secret pattern(s) {detected_kinds} in `{fp.name}` (secret values redacted).",
                            "remediation": "Immediately revoke/rotate the exposed key, purge it from git history, and move it into NOVA's 0600 ProtectedCredentialVault.",
                            "source_refs": [{"local_file": str(fp), "scanned_at": _iso()}],
                        }
                    )
                    local_secret_findings.append(rec)

        if external_findings or local_secret_findings:
            self.db.save_observation(
                {
                    "scope": "org_exposure_monitor",
                    "subject": organization_name,
                    "predicate": "exposure_assessment",
                    "value": (
                        f"{len(local_secret_findings)} verified local secret finding(s) and "
                        f"{len(external_findings)} external mention(s) recorded."
                    ),
                    "source": "verified_tool_output",
                    "evidence_ref": f"org_exposure:{organization_name}",
                }
            )

        return {
            "ok": True,
            "organization": organization_name,
            "authorized_domains": domains_norm,
            "verified_local_findings": local_secret_findings,
            "external_report_findings": external_findings,
            "claim_breach_from_unverified_post": CLAIM_BREACH_FROM_UNVERIFIED_POST,
            "pii_minimized": True,
        }


class SecureDownloadAndAnalysisPipeline:
    """§165.7 Quarantine-First Download & Static File-Analysis Pipeline (`AUTO_EXECUTE = False`)."""

    DEFAULT_MAX_BYTES = 25 * 1024 * 1024  # 25 MiB hard ceiling by default
    MAX_ARCHIVE_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
    MAX_ARCHIVE_MEMBERS = 200

    def __init__(
        self,
        *,
        db: Database,
        tor_manager: TorIntegrationManager,
        onion_browser: OnionServiceBrowser,
        state_dir: Path,
        redactor: Redactor,
    ) -> None:
        self.db = db
        self.tor = tor_manager
        self.onion_browser = onion_browser
        self.quarantine_root = state_dir / "quarantine"
        self.redactor = redactor

    def quarantine_and_analyze_bytes(
        self,
        data: bytes,
        *,
        original_filename: str,
        source_url: str = "local://supplied-bytes",
        via_network: str = "local_supplied",
        detached_signature_path: str = "",
        public_keyring_path: str = "",
        extract_archive_isolated: bool = False,
        max_bytes: int | None = None,
    ) -> dict[str, Any]:
        """§165.7 Quarantine untrusted bytes (`0700` dir, `0400` non-executable file), hash, identify, scan & statically analyze."""
        cap = int(max_bytes if max_bytes is not None else self.DEFAULT_MAX_BYTES)
        if len(data) > cap:
            return {
                "ok": False,
                "status": "exceeds_size_limit",
                "size_bytes": len(data),
                "max_bytes": cap,
                "auto_executed": False,
                "reason": f"Artifact size ({len(data)} bytes) exceeds configured safety limit ({cap} bytes).",
            }

        self.quarantine_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(self.quarantine_root, 0o700)

        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(original_filename).name)[:120] or "artifact.bin"
        qid = f"qdl-{uuid.uuid4().hex[:12]}"
        item_dir = self.quarantine_root / qid
        item_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(item_dir, 0o700)

        qfile = item_dir / f"{safe_name}.quarantined"
        qfile.write_bytes(data)
        # Non-executable read-only permissions (0400) so the OS cannot execute the quarantined file!
        os.chmod(qfile, 0o400)

        sha256_hex = hashlib.sha256(data).hexdigest()
        sha512_hex = hashlib.sha512(data).hexdigest()
        prior = self.db.find_quarantined_by_sha256(sha256_hex)
        duplicate_of = prior["id"] if prior else ""

        mime_info = self.detect_file_type(data, original_filename=safe_name, quarantined_path=qfile)
        sig_info = self._verify_detached_signature(qfile, detached_signature_path, public_keyring_path)
        clam_info = self._run_clamav_scan(qfile)
        archive_info, extracted_dir = self._inspect_and_optionally_extract_archive(
            qfile,
            mime_info["detected_mime"],
            item_dir=item_dir,
            extract_isolated=extract_archive_isolated,
        )
        static_report = self._static_content_analysis(data, detected_mime=mime_info["detected_mime"], original_filename=safe_name)
        static_report["file_type_check"] = mime_info
        static_report["archive_inspection"] = archive_info
        static_report["malware_scan"] = clam_info
        static_report["signature_verification"] = sig_info
        static_report["remote_resources_loaded"] = LOAD_REMOTE_RESOURCES_DURING_STATIC_ANALYSIS

        provenance = {
            "source_url": source_url,
            "via_network": via_network,
            "ingested_at": _iso(),
            "quarantine_dir_mode": oct(item_dir.stat().st_mode & 0o777),
            "quarantine_file_mode": oct(qfile.stat().st_mode & 0o777),
            "executable_bits_set": bool(qfile.stat().st_mode & 0o111),
        }

        saved = self.db.save_quarantined_download(
            {
                "id": qid,
                "source_url": source_url,
                "via_network": via_network,
                "original_filename": safe_name,
                "quarantine_path": str(qfile),
                "extracted_dir": extracted_dir,
                "size_bytes": len(data),
                "sha256": sha256_hex,
                "sha512": sha512_hex,
                "detected_mime": mime_info["detected_mime"],
                "signature_status": sig_info["status"],
                "clamav_status": clam_info["status"],
                "static_analysis": static_report,
                "duplicate_of_id": duplicate_of,
                "provenance": provenance,
            }
        )
        return {
            "ok": True,
            "status": "quarantined_and_analyzed",
            "auto_executed": False,
            "record": saved,
        }

    def download_and_quarantine_url(
        self,
        url: str,
        *,
        max_bytes: int | None = None,
        extract_archive_isolated: bool = False,
    ) -> dict[str, Any]:
        """§165.7 Fetch a remote file (via Tor SOCKS5h for `.onion`, or direct HTTP for clearnet) directly into quarantine."""
        cap = int(max_bytes if max_bytes is not None else self.DEFAULT_MAX_BYTES)
        parsed = urlparse(url.strip())
        host = (parsed.hostname or "").lower()
        filename = Path(parsed.path).name or "downloaded_artifact.bin"

        if host.endswith(".onion"):
            cfg = self.tor.get_config()
            if not cfg["tor_enabled"]:
                return {"ok": False, "status": "tor_integration_disabled", "auto_executed": False, "reason": "Tor is disabled; cannot download `.onion` artifact."}
            v = validate_v3_onion_address(host)
            if not v["valid"]:
                return {"ok": False, "status": "invalid_onion_address", "auto_executed": False, "reason": v["reason"]}
            res = socks5h_http_request(
                url.strip(),
                socks_host=cfg["socks_host"],
                socks_port=cfg["socks_port"],
                isolation_token="quarantine-dl",
                max_body_bytes=cap + 1,
            )
            if not res.get("ok"):
                return {"ok": False, "status": res.get("status", "download_failed"), "auto_executed": False, "reason": res.get("reason", "")}
            return self.quarantine_and_analyze_bytes(
                res["body_bytes"],
                original_filename=filename,
                source_url=url.strip(),
                via_network="tor_socks5h",
                extract_archive_isolated=extract_archive_isolated,
                max_bytes=cap,
            )

        # Ordinary clearnet byte download with hard cap
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path_q = parsed.path or "/"
        if parsed.query:
            path_q += f"?{parsed.query}"
        import socket
        import ssl

        try:
            with socket.create_connection((host, port), timeout=10.0) as raw_sock:
                raw_sock.settimeout(10.0)
                active_sock: socket.socket = raw_sock
                if parsed.scheme == "https":
                    active_sock = ssl.create_default_context().wrap_socket(raw_sock, server_hostname=host)
                req = f"GET {path_q} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NOVA-X-QuarantineFetcher/0.2\r\nConnection: close\r\n\r\n"
                active_sock.sendall(req.encode("ascii", errors="ignore"))
                buf = bytearray()
                while len(buf) < cap + 32_768:
                    chunk = active_sock.recv(16_384)
                    if not chunk:
                        break
                    buf.extend(chunk)
        except OSError as exc:
            return {"ok": False, "status": "download_failed", "auto_executed": False, "reason": str(exc)}

        sep = buf.find(b"\r\n\r\n")
        if sep < 0:
            return {"ok": False, "status": "malformed_http_response", "auto_executed": False}
        body = bytes(buf[sep + 4 :])
        return self.quarantine_and_analyze_bytes(
            body,
            original_filename=filename,
            source_url=url.strip(),
            via_network="ordinary_direct",
            extract_archive_isolated=extract_archive_isolated,
            max_bytes=cap,
        )

    @staticmethod
    def detect_file_type(data: bytes, *, original_filename: str, quarantined_path: Path | None = None) -> dict[str, Any]:
        """§165.7 Identify true file type from magic headers rather than trusting filename extensions."""
        head = data[:512]
        detected = "application/octet-stream"
        if head.startswith(b"%PDF-"):
            detected = "application/pdf"
        elif head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
            detected = "application/zip"
        elif head.startswith(b"\x1f\x8b\x08"):
            detected = "application/gzip"
        elif head.startswith(b"BZh"):
            detected = "application/x-bzip2"
        elif head.startswith(b"\xfd7zXZ\x00"):
            detected = "application/x-xz"
        elif len(head) >= 262 and head[257:262] == b"ustar":
            detected = "application/x-tar"
        elif head.startswith(b"\x7fELF"):
            detected = "application/x-executable-elf"
        elif head.startswith(b"MZ"):
            detected = "application/x-dosexec-pe"
        elif head.startswith(b"\x89PNG\r\n\x1a\n"):
            detected = "image/png"
        elif head.startswith(b"\xff\xd8\xff"):
            detected = "image/jpeg"
        elif head.startswith(b"SQLite format 3\x00"):
            detected = "application/vnd.sqlite3"
        elif head.startswith(b"#!"):
            detected = "text/x-script"
        else:
            # Optional `file --mime-type` enrichment when installed on Kali host
            file_bin = shutil.which("file")
            if file_bin and quarantined_path and quarantined_path.is_file():
                try:
                    proc = subprocess.run([file_bin, "--brief", "--mime-type", str(quarantined_path)], capture_output=True, text=True, timeout=3, check=False)
                    cand = (proc.stdout or "").strip()
                    if "/" in cand:
                        detected = cand
                except (OSError, subprocess.SubprocessError):
                    pass
            if detected == "application/octet-stream":
                try:
                    txt = head.decode("utf-8")
                    tl = txt.lstrip().lower()
                    if tl.startswith(("<!doctype html", "<html", "<head", "<body", "<script")):
                        detected = "text/html"
                    elif tl.startswith(("{", "[")):
                        detected = "application/json"
                    else:
                        detected = "text/plain"
                except UnicodeDecodeError:
                    pass

        ext = Path(original_filename).suffix.lower()
        executable_mimes = {"application/x-executable-elf", "application/x-dosexec-pe", "text/x-script"}
        benign_exts = {".pdf", ".txt", ".md", ".jpg", ".jpeg", ".png", ".csv", ".doc", ".docx"}
        extension_spoofed = bool(ext in benign_exts and detected in executable_mimes)
        return {
            "detected_mime": detected,
            "claimed_extension": ext,
            "extension_mismatch_or_spoof": extension_spoofed,
        }

    @staticmethod
    def _verify_detached_signature(target_file: Path, sig_path: str, keyring_path: str) -> dict[str, Any]:
        if not sig_path.strip():
            return {"status": "not_provided", "detail": "No detached cryptographic signature was supplied."}
        sp = Path(sig_path)
        if not sp.is_file():
            return {"status": "signature_file_missing", "detail": f"Signature path `{sig_path}` does not exist."}
        gpg_bin = shutil.which("gpg")
        if not gpg_bin:
            return {
                "status": "gpg_unavailable_unverified",
                "detail": "`gpg` binary is not installed on this host; detached signature could not be cryptographically verified.",
            }
        cmd = [gpg_bin, "--batch", "--no-tty"]
        if keyring_path.strip() and Path(keyring_path).is_file():
            cmd.extend(["--no-default-keyring", "--keyring", keyring_path.strip()])
        cmd.extend(["--verify", str(sp), str(target_file)])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
            ok = proc.returncode == 0
            return {
                "status": "verified_good_signature" if ok else "signature_verification_failed",
                "detail": ((proc.stderr or proc.stdout or "").strip()[:300]),
            }
        except (OSError, subprocess.SubprocessError) as exc:
            return {"status": "verification_error", "detail": str(exc)}

    @staticmethod
    def _run_clamav_scan(target_file: Path) -> dict[str, Any]:
        limitation = (
            "Malware-scanning limitation: signature/heuristic scanners (or static heuristics when ClamAV is absent) "
            "cannot guarantee a file is benign; novel, encrypted, or logic payloads may evade detection (§165.7)."
        )
        clam_bin = shutil.which("clamscan")
        if not clam_bin:
            return {
                "scanner": "clamscan",
                "scanner_installed": False,
                "status": "scanner_not_installed",
                "detail": "`clamscan` (ClamAV) is not installed on this host; install `clamav` on Kali Linux for signature scanning.",
                "limitations": limitation,
            }
        try:
            proc = subprocess.run(
                [clam_bin, "--no-summary", str(target_file)],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            status = "clean_by_signatures" if proc.returncode == 0 else ("infected_signature_match" if proc.returncode == 1 else "scan_error")
            return {
                "scanner": "clamscan",
                "scanner_installed": True,
                "status": status,
                "detail": (proc.stdout or proc.stderr or "").strip()[:400],
                "limitations": limitation,
            }
        except (OSError, subprocess.SubprocessError) as exc:
            return {"scanner": "clamscan", "scanner_installed": True, "status": "scan_error", "detail": str(exc), "limitations": limitation}

    def _inspect_and_optionally_extract_archive(
        self,
        qfile: Path,
        detected_mime: str,
        *,
        item_dir: Path,
        extract_isolated: bool,
    ) -> tuple[dict[str, Any], str]:
        is_zip = zipfile.is_zipfile(qfile)
        is_tar = False
        if not is_zip and detected_mime in {"application/gzip", "application/x-bzip2", "application/x-xz", "application/x-tar"}:
            is_tar = tarfile.is_tarfile(qfile)

        if not is_zip and not is_tar:
            return {"is_archive": False}, ""

        members: list[dict[str, Any]] = []
        unsafe_reasons: list[str] = []
        total_uncompressed = 0

        if is_zip:
            with zipfile.ZipFile(qfile, "r") as zf:
                infos = zf.infolist()
                if len(infos) > self.MAX_ARCHIVE_MEMBERS:
                    unsafe_reasons.append(f"Archive member count ({len(infos)}) exceeds {self.MAX_ARCHIVE_MEMBERS}.")
                for info in infos[: self.MAX_ARCHIVE_MEMBERS]:
                    name = info.filename
                    total_uncompressed += info.file_size
                    is_symlink = ((info.external_attr >> 16) & 0o170000) == 0o120000
                    if name.startswith("/") or ".." in Path(name).parts:
                        unsafe_reasons.append(f"Zip-Slip path traversal entry blocked: `{name}`.")
                    if is_symlink:
                        unsafe_reasons.append(f"Symlink archive entry blocked: `{name}`.")
                    members.append({"name": name, "size": info.file_size, "compressed": info.compress_size})
        else:
            with tarfile.open(qfile, "r:*") as tf:
                tmembers = tf.getmembers()
                if len(tmembers) > self.MAX_ARCHIVE_MEMBERS:
                    unsafe_reasons.append(f"Archive member count ({len(tmembers)}) exceeds {self.MAX_ARCHIVE_MEMBERS}.")
                for m in tmembers[: self.MAX_ARCHIVE_MEMBERS]:
                    total_uncompressed += m.size
                    if m.name.startswith("/") or ".." in Path(m.name).parts:
                        unsafe_reasons.append(f"Tar path traversal entry blocked: `{m.name}`.")
                    if m.issym() or m.islnk() or m.isdev():
                        unsafe_reasons.append(f"Unsafe link/device entry blocked: `{m.name}`.")
                    members.append({"name": m.name, "size": m.size})

        if total_uncompressed > self.MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            unsafe_reasons.append(
                f"Total uncompressed size ({total_uncompressed} B) exceeds bomb safety ceiling ({self.MAX_ARCHIVE_UNCOMPRESSED_BYTES} B)."
            )

        extracted_path = ""
        if extract_isolated and not unsafe_reasons:
            ext_root = (item_dir / "extracted_isolated").resolve()
            ext_root.mkdir(parents=True, mode=0o700, exist_ok=True)
            if is_zip:
                with zipfile.ZipFile(qfile, "r") as zf:
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        dest = (ext_root / info.filename).resolve()
                        if not str(dest).startswith(str(ext_root) + os.sep):
                            continue
                        dest.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                        dest.write_bytes(zf.read(info))
                        os.chmod(dest, 0o400)
            else:
                with tarfile.open(qfile, "r:*") as tf:
                    for m in tf.getmembers():
                        if not m.isfile():
                            continue
                        dest = (ext_root / m.name).resolve()
                        if not str(dest).startswith(str(ext_root) + os.sep):
                            continue
                        fobj = tf.extractfile(m)
                        if fobj is not None:
                            dest.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                            dest.write_bytes(fobj.read())
                            os.chmod(dest, 0o400)
            extracted_path = str(ext_root)

        return (
            {
                "is_archive": True,
                "archive_format": "zip" if is_zip else "tar",
                "member_count": len(members),
                "total_uncompressed_bytes": total_uncompressed,
                "safe_to_extract": len(unsafe_reasons) == 0,
                "unsafe_reasons": unsafe_reasons,
                "members_preview": members[:25],
            },
            extracted_path,
        )

    def _static_content_analysis(self, data: bytes, *, detected_mime: str, original_filename: str) -> dict[str, Any]:
        """§165.7 Passive text extraction & static risk-indicator analysis without executing code or loading remote URLs."""
        risk_indicators: list[str] = []
        extracted_text = ""
        isolated_remote_urls: list[str] = []

        if detected_mime == "application/pdf":
            raw_latin = data[:500_000].decode("latin-1", errors="ignore")
            for marker in ("/JavaScript", "/JS", "/OpenAction", "/Launch", "/EmbeddedFile", "/RichMedia"):
                if marker in raw_latin:
                    risk_indicators.append(f"pdf_active_content_marker:{marker}")
            isolated_remote_urls = sorted({m.group(0) for m in re.finditer(r"https?://[^\s)>'\"]+", raw_latin)})[:20]
            # Extract printable PDF literal strings `( ... )` safely
            literals = re.findall(r"\(([A-Za-z0-9 ,.:;_/-]{4,160})\)", raw_latin)
            extracted_text = " ".join(literals)[:2_000]
        elif detected_mime in {"text/html", "text/plain", "application/json", "text/x-script"}:
            txt = data[:300_000].decode("utf-8", errors="replace")
            isolated_remote_urls = sorted({m.group(0) for m in re.finditer(r"https?://[^\s<>'\"]+", txt)})[:25]
            if detected_mime == "text/html":
                if re.search(r"<script\b", txt, re.IGNORECASE):
                    risk_indicators.append("html_embedded_script_tag")
                if re.search(r"<iframe\b", txt, re.IGNORECASE):
                    risk_indicators.append("html_embedded_iframe")
            if re.search(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b", txt, re.IGNORECASE):
                risk_indicators.append("remote_pipe_to_shell_pattern")
            if re.search(r"\b(?:eval\s*\(|exec\s*\(|powershell\s+-enc|base64\s+-d)\b", txt, re.IGNORECASE):
                risk_indicators.append("obfuscated_or_dynamic_exec_pattern")
            extracted_text = self.redactor.scrub_text(txt, max_chars=2_000)
        elif detected_mime in {"application/x-executable-elf", "application/x-dosexec-pe"}:
            risk_indicators.append(f"native_binary_executable:{detected_mime}")
            strings_found = re.findall(rb"[ -~]{6,80}", data[:200_000])
            extracted_text = " | ".join(s.decode("ascii", errors="ignore") for s in strings_found[:30])[:1_500]

        return {
            "original_filename": original_filename,
            "risk_indicators": risk_indicators,
            "isolated_remote_references": isolated_remote_urls,
            "safe_text_preview": extracted_text[:800],
        }
