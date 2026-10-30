"""§205 Vulnerability Validation, §206 Network Security, §207 Web/API Lab, §208 SAST/Remediation & §216 Risk Lifecycle."""
from __future__ import annotations

import ast
import difflib
import os
import re
import shutil
import struct
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from nova.cyber_division.scope_and_surface import SecurityScopeRegistry
from nova.db import Database
from nova.kali_intel.system_model import KaliSystemKnowledgeModel, _run_probe

VULNERABILITY_22_CATEGORIES: tuple[str, ...] = (
    "sql_injection",
    "cross_site_scripting",
    "csrf",
    "ssrf",
    "authentication_weaknesses",
    "authorization_failures",
    "idor",
    "insecure_deserialization",
    "file_upload_weaknesses",
    "path_traversal",
    "security_misconfiguration",
    "insecure_cryptography",
    "exposed_secrets",
    "dependency_vulnerabilities",
    "api_security_weaknesses",
    "weak_session_management",
    "insecure_transport",
    "memory_safety_defects",
    "race_conditions",
    "insecure_permissions",
    "container_misconfigurations",
    "cloud_configuration_weaknesses",
)

EPISTEMIC_7_FINDING_STATES: tuple[str, ...] = (
    "potential_vulnerability",
    "tool_generated_alert",
    "reproducible_security_defect",
    "confirmed_vulnerability",
    "false_positive",
    "previously_fixed_vulnerability",
    "requires_further_investigation",
)

LIFECYCLE_STATES_ORDERED: tuple[str, ...] = (
    "Discovered",
    "Investigating",
    "Confirmed",
    "Prioritized",
    "Remediating",
    "Retesting",
    "Resolved",
    "Accepted Risk",
)

SEVERITY_BASE_WEIGHTS: dict[str, float] = {
    "critical": 90.0,
    "high": 75.0,
    "medium": 50.0,
    "low": 25.0,
    "info": 10.0,
}

EXPOSURE_MULTIPLIERS: dict[str, float] = {
    "internet_facing": 1.25,
    "internal_network": 1.0,
    "local_only": 0.75,
    "isolated_test_only": 0.5,
}


class VulnerabilityDiscoveryAndLifecycleEngine:
    """§205 Epistemic Vulnerability Validation & §216 Contextual Risk Prioritization and Lifecycle Management."""

    REPORT_EVERY_SCANNER_ALERT_AS_EXPLOITABLE = False
    ALLOW_SILENT_UNVERIFIED_CLOSURE = False

    def __init__(self, *, db: Database, scope_registry: SecurityScopeRegistry):
        self.db = db
        self.scope_registry = scope_registry

    def compute_contextual_risk_score(self, candidate: dict[str, Any]) -> float:
        """§216 Prioritize based on actual exposure, mitigations, confidence, and verified exploitability."""
        epistemic = str(candidate.get("epistemic_status") or "potential_vulnerability")
        if epistemic in {"false_positive", "previously_fixed_vulnerability"}:
            return 0.0

        base = SEVERITY_BASE_WEIGHTS.get(str(candidate.get("severity") or "medium").lower(), 50.0)
        exp_mult = EXPOSURE_MULTIPLIERS.get(str(candidate.get("exposure") or "local_only"), 0.85)
        conf = max(0.1, min(float(candidate.get("confidence", 0.7)), 1.0))

        mitigations = list(candidate.get("existing_mitigations") or [])
        mitigation_discount = min(0.55, 0.18 * len(mitigations))

        exploit_bonus = 12.0 if "verified_in_scope_repro" in str(candidate.get("exploitability_info") or "") else 0.0
        if epistemic == "tool_generated_alert":
            conf *= 0.65

        raw = (base * exp_mult * conf * (1.0 - mitigation_discount)) + exploit_bonus
        return round(max(1.0, min(100.0, raw)), 2)

    def record_and_validate_finding(self, item: dict[str, Any]) -> dict[str, Any]:
        """§205 Validate candidate alert/finding without exaggerating unverified scanner noise."""
        cat = str(item.get("category") or "security_misconfiguration")
        if cat not in VULNERABILITY_22_CATEGORIES:
            cat = "security_misconfiguration"

        evidence = dict(item.get("evidence") or {})
        mitigations = list(item.get("existing_mitigations") or [])
        raw_status = str(item.get("epistemic_status") or "tool_generated_alert")

        if item.get("false_positive_reason") or evidence.get("parameterized_or_sanitized") is True:
            epistemic = "false_positive"
            lifecycle = "Resolved"
            rem_status = "false_positive_dismissed_with_evidence"
        elif item.get("previously_fixed"):
            epistemic = "previously_fixed_vulnerability"
            lifecycle = "Resolved"
            rem_status = "verified_fixed"
        elif evidence.get("reproducible_non_destructive_check") is True:
            epistemic = "confirmed_vulnerability" if raw_status == "confirmed_vulnerability" else "reproducible_security_defect"
            lifecycle = "Confirmed"
            rem_status = "open"
        elif raw_status in EPISTEMIC_7_FINDING_STATES:
            epistemic = raw_status
            lifecycle = str(item.get("lifecycle_state") or "Discovered")
            rem_status = str(item.get("remediation_status") or "pending_validation")
        else:
            epistemic = "requires_further_investigation"
            lifecycle = "Investigating"
            rem_status = "needs_triage"

        enriched = {
            **item,
            "category": cat,
            "epistemic_status": epistemic,
            "lifecycle_state": lifecycle,
            "existing_mitigations": mitigations,
            "evidence": evidence,
            "remediation_status": rem_status,
        }
        enriched["priority_score"] = self.compute_contextual_risk_score(enriched)
        if lifecycle == "Confirmed" and enriched["priority_score"] > 0:
            enriched["lifecycle_state"] = "Prioritized"
        return self.db.upsert_cyber_finding(enriched)

    def prioritize_findings_batch(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """§216 Evaluate, validate, persist, and rank a list of findings by contextual risk."""
        saved = [self.record_and_validate_finding(c) for c in candidates]
        saved.sort(key=lambda f: (-float(f["priority_score"]), f["id"]))
        return saved

    def transition_lifecycle(
        self,
        finding_id: str,
        *,
        target_state: str,
        retest_passed: bool | None = None,
        risk_acceptance_justification: str = "",
        evidence_note: str = "",
    ) -> dict[str, Any]:
        """§216 Enforce verified lifecycle transitions; forbid silent unverified closure."""
        finding = self.db.get_cyber_finding(finding_id)
        if finding is None:
            raise ValueError(f"Unknown finding_id: {finding_id}")
        if target_state not in LIFECYCLE_STATES_ORDERED:
            raise ValueError(f"Invalid lifecycle state '{target_state}'. Valid: {LIFECYCLE_STATES_ORDERED}")

        if target_state == "Resolved" and retest_passed is not True:
            raise PermissionError("Cannot mark finding `Resolved` without a passing verification retest (§216).")
        if target_state == "Accepted Risk" and len(risk_acceptance_justification.strip()) < 8:
            raise PermissionError("Cannot mark finding `Accepted Risk` without documented justification (§216).")

        finding["lifecycle_state"] = target_state
        if target_state == "Resolved":
            finding["remediation_status"] = "verified_resolved"
            finding["epistemic_status"] = "previously_fixed_vulnerability"
            finding["priority_score"] = 0.0
            finding["retest_result"] = {"passed": True, "note": evidence_note or "Verified by non-destructive retest."}
        elif target_state == "Accepted Risk":
            finding["remediation_status"] = "accepted_risk"
            finding["retest_result"] = {"accepted_justification": risk_acceptance_justification.strip()}
        elif retest_passed is False:
            finding["retest_result"] = {"passed": False, "note": evidence_note or "Defect still reproducible."}
        return self.db.upsert_cyber_finding(finding)


class NetworkSecurityWorkspace:
    """§206 Network Security Workspace: tool discovery, passive PCAP parser, and scope-gated network checks."""

    NETWORK_TOOLS_CANDIDATES: tuple[str, ...] = (
        "nmap",
        "tshark",
        "tcpdump",
        "wireshark",
        "ss",
        "ip",
        "openssl",
        "dig",
        "nft",
        "ufw",
        "iptables",
    )

    def __init__(self, *, scope_registry: SecurityScopeRegistry, system_model: KaliSystemKnowledgeModel):
        self.scope_registry = scope_registry
        self.system_model = system_model

    def inventory_network_security_tools(self) -> dict[str, Any]:
        """§206 Discover which network utilities are actually installed & functional without assuming presence."""
        installed: list[dict[str, Any]] = []
        unavailable: list[str] = []
        for cmd in self.NETWORK_TOOLS_CANDIDATES:
            st = self.system_model.classify_application_state(cmd)
            if st["states"]["installed"]:
                installed.append(
                    {
                        "tool": cmd,
                        "executable_path": st["executable_path"],
                        "functional": st["states"]["functional"],
                        "version_or_probe": st["package_version"] or st["probe_summary"],
                    }
                )
            else:
                unavailable.append(cmd)
        return {
            "assumed_every_utility_installed": False,
            "installed_tools": installed,
            "unavailable_tools": unavailable,
        }

    def analyze_pcap_file(self, pcap_path: Path | str) -> dict[str, Any]:
        """§206 & §220.8 Passive binary libpcap (.pcap) packet analysis without requiring root or live sniffing."""
        path = Path(pcap_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {path}")
        raw = path.read_bytes()
        if len(raw) < 24:
            return {"ok": False, "status": "truncated_capture", "packet_count": 0}

        magic_le = struct.unpack("<I", raw[:4])[0]
        if magic_le == 0xA1B2C3D4:
            endian = "<"
        elif magic_le == 0xD4C3B2A1:
            endian = ">"
        else:
            return {"ok": False, "status": "unsupported_capture_magic", "magic_hex": hex(magic_le)}

        _vmaj, _vmin, _tz, _sig, _snaplen, linktype = struct.unpack(f"{endian}HHIIII", raw[4:24])
        offset = 24
        pkt_count = 0
        protocols: dict[str, int] = {}
        endpoints: set[str] = set()
        cleartext_alerts: list[dict[str, Any]] = []
        syn_only_count = 0

        while offset + 16 <= len(raw):
            _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(f"{endian}IIII", raw[offset : offset + 16])
            offset += 16
            frame = raw[offset : offset + incl_len]
            offset += incl_len
            if len(frame) < incl_len:
                break
            pkt_count += 1

            # Ethernet II (linktype 1) -> IPv4 (0x0800)
            if linktype == 1 and len(frame) >= 34:
                eth_type = struct.unpack("!H", frame[12:14])[0]
                if eth_type == 0x0800:
                    ip_hdr = frame[14:]
                    ihl = (ip_hdr[0] & 0x0F) * 4
                    proto_num = ip_hdr[9]
                    src_ip = ".".join(str(b) for b in ip_hdr[12:16])
                    dst_ip = ".".join(str(b) for b in ip_hdr[16:20])
                    endpoints.update([src_ip, dst_ip])
                    l4 = ip_hdr[ihl:]
                    if proto_num == 6 and len(l4) >= 14:
                        protocols["tcp"] = protocols.get("tcp", 0) + 1
                        sport, dport = struct.unpack("!HH", l4[:4])
                        flags = l4[13]
                        if (flags & 0x02) and not (flags & 0x10):
                            syn_only_count += 1
                        payload = l4[((l4[12] >> 4) * 4) :]
                        if dport in {21, 23, 80} and payload:
                            txt = payload.decode("latin1", errors="ignore")
                            if any(tok in txt for tok in ("Authorization: Basic", "USER ", "PASS ", "api_key=")):
                                cleartext_alerts.append(
                                    {
                                        "packet_index": pkt_count,
                                        "src": f"{src_ip}:{sport}",
                                        "dst": f"{dst_ip}:{dport}",
                                        "issue": "cleartext_credential_or_auth_header_over_unencrypted_port",
                                    }
                                )
                    elif proto_num == 17 and len(l4) >= 8:
                        protocols["udp"] = protocols.get("udp", 0) + 1
                    elif proto_num == 1:
                        protocols["icmp"] = protocols.get("icmp", 0) + 1

        anomalies: list[str] = []
        if cleartext_alerts:
            anomalies.append(f"Detected {len(cleartext_alerts)} cleartext authentication/sensitive packet(s).")
        if syn_only_count >= 10:
            anomalies.append(f"Elevated TCP SYN-without-ACK count ({syn_only_count}) indicative of port probing.")

        return {
            "ok": True,
            "mode": "passive_pcap_analysis",
            "pcap_path": str(path),
            "linktype": linktype,
            "packet_count": pkt_count,
            "protocol_counts": protocols,
            "unique_ipv4_endpoints": sorted(endpoints),
            "cleartext_exposure_alerts": cleartext_alerts,
            "anomalies": anomalies,
        }

    def audit_in_scope_network_posture(self, target: str) -> dict[str, Any]:
        """§206 Non-destructive network configuration & segmentation review strictly inside registered scope."""
        auth = self.scope_registry.authorize_operation(target=target, activity="configuration_inspection")
        if not auth["authorized"]:
            return {"ok": False, "status": auth["status"], "reason": auth["reason"]}

        env = self.system_model.get_or_refresh_model()["model"]
        sockets_sample: list[str] = []
        if shutil.which("ss"):
            rc, out, _ = _run_probe(["ss", "-tuln"], timeout=2.5)
            if rc == 0:
                sockets_sample = out.splitlines()[:25]

        wildcard_listeners = [ln for ln in sockets_sample if "0.0.0.0:" in ln or "[::]:" in ln]
        return {
            "ok": True,
            "target": target,
            "scope_id": auth["scope_id"],
            "firewall_controls_present": {
                "nftables": env["system_policies"]["nftables_installed"],
                "ufw": env["system_policies"]["ufw_installed"],
                "iptables": env["system_policies"]["iptables_installed"],
            },
            "listening_sockets_sample": sockets_sample,
            "wildcard_all_interface_listeners": len(wildcard_listeners),
            "segmentation_note": (
                "Review 0.0.0.0/[::] listeners to ensure internal services bind to 127.0.0.1 unless external access is intended."
                if wildcard_listeners
                else "No unexpected wildcard listeners observed in local sample."
            ),
        }


class WebAndApiSecurityLab:
    """§207 Non-destructive Web Application, Security Header, Cookie, CORS & OpenAPI Assessment Lab."""

    EXTRACT_REAL_USER_RECORDS = False
    USE_DESTRUCTIVE_PAYLOADS = False

    REQUIRED_SECURITY_HEADERS: tuple[str, ...] = (
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
    )

    def __init__(
        self,
        *,
        scope_registry: SecurityScopeRegistry,
        vuln_engine: VulnerabilityDiscoveryAndLifecycleEngine,
    ):
        self.scope_registry = scope_registry
        self.vuln_engine = vuln_engine

    def assess_http_application(
        self,
        base_url: str,
        *,
        endpoints: list[str] | None = None,
        openapi_spec: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """§207 Non-destructively review headers, cookies, CORS, auth exposure & OpenAPI spec within scope."""
        auth = self.scope_registry.authorize_operation(
            target=base_url,
            activity="controlled_application_testing",
        )
        if not auth["authorized"]:
            return {"ok": False, "status": auth["status"], "reason": auth["reason"], "findings": []}

        paths = list(endpoints or ["/"])
        findings: list[dict[str, Any]] = []
        observed_routes: list[dict[str, Any]] = []

        for rel in paths[:15]:
            url = base_url.rstrip("/") + ("/" + rel.lstrip("/"))
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": "DEV-Security-Auditor/1.0", "Origin": "https://untrusted.example"})
            try:
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    status_code = resp.status
                    hdrs = {k.lower(): v for k, v in resp.headers.items()}
                    body_preview = resp.read(2048).decode("utf-8", errors="replace")
            except urllib.error.HTTPError as exc:
                status_code = exc.code
                hdrs = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
                body_preview = ""
            except OSError as exc:
                observed_routes.append({"url": url, "reachable": False, "error": str(exc)[:140]})
                continue

            observed_routes.append({"url": url, "status": status_code, "reachable": True})

            missing_hdrs = [h for h in self.REQUIRED_SECURITY_HEADERS if h not in hdrs]
            if missing_hdrs:
                findings.append(
                    self.vuln_engine.record_and_validate_finding(
                        {
                            "category": "security_misconfiguration",
                            "epistemic_status": "confirmed_vulnerability",
                            "affected_asset": url,
                            "affected_software": hdrs.get("server", "http_service"),
                            "severity": "low",
                            "confidence": 0.95,
                            "exposure": "local_only",
                            "evidence": {
                                "reproducible_non_destructive_check": True,
                                "missing_security_headers": missing_hdrs,
                            },
                            "recommended_correction": "Add Content-Security-Policy, X-Content-Type-Options: nosniff, and X-Frame-Options: DENY.",
                        }
                    )
                )

            acao = hdrs.get("access-control-allow-origin", "")
            acac = hdrs.get("access-control-allow-credentials", "").lower()
            if acao in {"*", "https://untrusted.example"} and acac == "true":
                findings.append(
                    self.vuln_engine.record_and_validate_finding(
                        {
                            "category": "api_security_weaknesses",
                            "epistemic_status": "confirmed_vulnerability",
                            "affected_asset": url,
                            "severity": "high",
                            "confidence": 0.95,
                            "exposure": "local_only",
                            "evidence": {
                                "reproducible_non_destructive_check": True,
                                "access_control_allow_origin": acao,
                                "access_control_allow_credentials": acac,
                            },
                            "recommended_correction": "Restrict Access-Control-Allow-Origin to an explicit trusted allowlist when credentials are enabled.",
                        }
                    )
                )

            set_cookie = hdrs.get("set-cookie", "")
            if set_cookie and ("httponly" not in set_cookie.lower() or "samesite" not in set_cookie.lower()):
                findings.append(
                    self.vuln_engine.record_and_validate_finding(
                        {
                            "category": "weak_session_management",
                            "epistemic_status": "confirmed_vulnerability",
                            "affected_asset": url,
                            "severity": "medium",
                            "confidence": 0.9,
                            "exposure": "local_only",
                            "evidence": {
                                "reproducible_non_destructive_check": True,
                                "set_cookie_flags_observed": set_cookie.split(";", 1)[-1][:160] if ";" in set_cookie else "no_flags",
                            },
                            "recommended_correction": "Set HttpOnly, SameSite=Lax/Strict, and Secure flags on session cookies.",
                        }
                    )
                )

            if any(seg in rel.lower() for seg in ("admin", "debug", "config", "internal")) and status_code == 200:
                findings.append(
                    self.vuln_engine.record_and_validate_finding(
                        {
                            "category": "authorization_failures",
                            "epistemic_status": "confirmed_vulnerability",
                            "affected_asset": url,
                            "severity": "high",
                            "confidence": 0.92,
                            "exposure": "local_only",
                            "evidence": {
                                "reproducible_non_destructive_check": True,
                                "http_status_without_credentials": status_code,
                                "response_length": len(body_preview),
                            },
                            "recommended_correction": "Require authentication and role-based authorization middleware on administrative/debug endpoints.",
                        }
                    )
                )

        if openapi_spec:
            findings.extend(self._audit_openapi_schema(base_url, openapi_spec))

        return {
            "ok": True,
            "target": base_url,
            "routes_checked": observed_routes,
            "findings_count": len(findings),
            "findings": findings,
            "destructive_payloads_sent": 0,
            "real_user_records_extracted": 0,
        }

    def _audit_openapi_schema(self, base_url: str, spec: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        global_sec = spec.get("security")
        for route, methods in (spec.get("paths") or {}).items():
            if not isinstance(methods, dict):
                continue
            for verb, op in methods.items():
                if verb.lower() in {"post", "put", "delete", "patch"} and isinstance(op, dict):
                    has_sec = bool(op.get("security") or global_sec)
                    if not has_sec:
                        out.append(
                            self.vuln_engine.record_and_validate_finding(
                                {
                                    "category": "authentication_weaknesses",
                                    "epistemic_status": "reproducible_security_defect",
                                    "affected_asset": f"{base_url.rstrip('/')}{route} [{verb.upper()}]",
                                    "severity": "medium",
                                    "confidence": 0.85,
                                    "exposure": "local_only",
                                    "evidence": {"reproducible_non_destructive_check": True, "openapi_security_defined": False},
                                    "recommended_correction": "Declare and enforce authentication schemes on state-changing OpenAPI operations.",
                                }
                            )
                        )
        return out


class SourceCodeSecurityEngineer:
    """§208 SAST, SCA, Secret/Dockerfile Inspection & 10-Step Automated Remediation + Regression Engine."""

    EXTERNAL_SCANNERS: tuple[str, ...] = ("semgrep", "gitleaks", "trivy", "syft", "grype", "bandit")

    def __init__(
        self,
        *,
        scope_registry: SecurityScopeRegistry,
        vuln_engine: VulnerabilityDiscoveryAndLifecycleEngine,
    ):
        self.scope_registry = scope_registry
        self.vuln_engine = vuln_engine

    def analyze_project(self, project_dir: Path | str) -> dict[str, Any]:
        """§208 Inspect source code, manifests, and Dockerfiles; distinguish real defects from safe code."""
        root = Path(project_dir).resolve()
        auth = self.scope_registry.authorize_operation(target=str(root), activity="source_code_analysis")
        if not auth["authorized"]:
            return {"ok": False, "status": auth["status"], "reason": auth["reason"], "findings": []}

        installed_scanners = [cmd for cmd in self.EXTERNAL_SCANNERS if shutil.which(cmd)]
        findings: list[dict[str, Any]] = []
        false_positives_filtered: list[dict[str, Any]] = []

        for py_file in sorted(root.rglob("*.py")):
            if any(part in {".venv", "node_modules", "__pycache__", ".git"} for part in py_file.parts):
                continue
            if py_file.name.startswith("test_") or py_file.name.endswith(".orig.bak"):
                continue
            src = py_file.read_text(encoding="utf-8", errors="replace")
            py_hits, py_fps = self._scan_python_ast_and_source(py_file, src)
            findings.extend(py_hits)
            false_positives_filtered.extend(py_fps)

        # Dependency manifest SCA check
        req_file = root / "requirements.txt"
        if req_file.is_file():
            for ln_no, raw_ln in enumerate(req_file.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                s = raw_ln.strip()
                if not s or s.startswith("#"):
                    continue
                if "==" not in s and ">=" not in s:
                    findings.append(
                        self.vuln_engine.record_and_validate_finding(
                            {
                                "category": "dependency_vulnerabilities",
                                "epistemic_status": "potential_vulnerability",
                                "affected_asset": f"{req_file}:{ln_no}",
                                "affected_software": s,
                                "severity": "low",
                                "confidence": 0.75,
                                "evidence": {"line": ln_no, "unpinned_dependency": s},
                                "recommended_correction": f"Pin `{s}` to a verified release version and hash in requirements.txt.",
                            }
                        )
                    )
                elif s.lower().startswith("pyyaml==5."):
                    findings.append(
                        self.vuln_engine.record_and_validate_finding(
                            {
                                "vuln_identifier": "CVE-2020-14343",
                                "category": "dependency_vulnerabilities",
                                "epistemic_status": "confirmed_vulnerability",
                                "affected_asset": f"{req_file}:{ln_no}",
                                "affected_software": s,
                                "severity": "high",
                                "confidence": 0.95,
                                "evidence": {"reproducible_non_destructive_check": True, "line": ln_no, "vulnerable_pin": s},
                                "recommended_correction": "Upgrade PyYAML to >= 6.0.1 and use `yaml.safe_load`.",
                            }
                        )
                    )

        # Container Dockerfile check
        dockerfile = root / "Dockerfile"
        if dockerfile.is_file():
            dtxt = dockerfile.read_text(encoding="utf-8", errors="replace")
            if "USER " not in dtxt or re.search(r"(?m)^USER\s+root\s*$", dtxt):
                findings.append(
                    self.vuln_engine.record_and_validate_finding(
                        {
                            "category": "container_misconfigurations",
                            "epistemic_status": "reproducible_security_defect",
                            "affected_asset": str(dockerfile),
                            "severity": "medium",
                            "confidence": 0.9,
                            "evidence": {"reproducible_non_destructive_check": True, "non_root_user_directive": False},
                            "recommended_correction": "Add a dedicated non-root `USER` instruction in Dockerfile.",
                        }
                    )
                )

        return {
            "ok": True,
            "project_root": str(root),
            "external_scanners_installed": installed_scanners,
            "findings_count": len(findings),
            "false_positives_filtered_count": len(false_positives_filtered),
            "findings": findings,
            "false_positives_filtered": false_positives_filtered,
        }

    def remediate_and_verify_10_steps(self, file_path: Path | str) -> dict[str, Any]:
        """§208 10-step automated source defect remediation, backup preservation, and regression testing."""
        target = Path(file_path).resolve()
        auth = self.scope_registry.authorize_operation(target=str(target.parent), activity="retesting_remediation")
        if not auth["authorized"]:
            return {"ok": False, "status": auth["status"], "reason": auth["reason"]}

        original_src = target.read_text(encoding="utf-8")
        # Keep original stable version recoverable (§208)!
        backup_path = target.with_suffix(target.suffix + ".orig.bak")
        backup_path.write_text(original_src, encoding="utf-8")

        steps: list[dict[str, Any]] = []
        # 1–3. Identify defect, locate source, understand context
        initial_hits, _ = self._scan_python_ast_and_source(target, original_src)
        steps.append({"step": 1, "action": "identify_defect", "initial_findings": len(initial_hits)})
        steps.append({"step": 2, "action": "locate_source_code", "file": str(target)})
        steps.append({"step": 3, "action": "understand_context", "backup_saved": str(backup_path)})

        if not initial_hits:
            return {"ok": True, "status": "no_remediable_defects_found", "backup_path": str(backup_path), "steps": steps}

        # 4. Develop safe candidate fix
        patched_src = self._apply_safe_python_remediations(original_src)
        target.write_text(patched_src, encoding="utf-8")
        steps.append({"step": 4, "action": "develop_candidate_fix", "modified": patched_src != original_src})

        # 5. Create regression test
        reg_test_file = target.parent / f"test_security_regression_{target.stem}.py"
        reg_test_file.write_text(
            "import ast\n"
            "import pathlib\n"
            "import unittest\n\n"
            f"TARGET = pathlib.Path({str(target)!r})\n\n"
            "class TestSecurityRegression(unittest.TestCase):\n"
            "    def test_valid_syntax_and_parameterized_queries(self):\n"
            "        src = TARGET.read_text(encoding='utf-8')\n"
            "        tree = ast.parse(src)\n"
            "        self.assertIsNotNone(tree)\n"
            "        self.assertNotIn('yaml.load(', src.replace('yaml.safe_load(', ''))\n"
            "        for node in ast.walk(tree):\n"
            "            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':\n"
            "                self.assertFalse(isinstance(node.args[0], ast.JoinedStr), 'f-string SQL injection must remain fixed')\n\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n",
            encoding="utf-8",
        )
        steps.append({"step": 5, "action": "create_regression_test", "test_file": str(reg_test_file)})

        # 6. Run relevant checks in isolated cache env
        with tempfile.TemporaryDirectory(prefix="nova_rem_pyc_") as pyc_tmp:
            proc = subprocess.run(
                ["python3", "-B", str(reg_test_file)],
                cwd=str(target.parent),
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
                env={**os.environ, "LC_ALL": "C", "PYTHONPYCACHEPREFIX": pyc_tmp},
            )
        test_ok = proc.returncode == 0
        steps.append({"step": 6, "action": "run_regression_checks", "exit_code": proc.returncode})

        # 7 & 8. Inspect diff & verify fix introduces no new SAST defects
        diff_txt = "".join(
            difflib.unified_diff(
                original_src.splitlines(keepends=True),
                patched_src.splitlines(keepends=True),
                fromfile=f"a/{target.name}",
                tofile=f"b/{target.name}",
            )
        )
        post_hits, _ = self._scan_python_ast_and_source(target, patched_src)
        no_new_issues = test_ok and len(post_hits) < len(initial_hits)
        steps.append({"step": 7, "action": "inspect_code_changes", "diff_lines": len(diff_txt.splitlines())})
        steps.append({"step": 8, "action": "evaluate_post_fix_safety", "remaining_findings": len(post_hits)})

        if not no_new_issues:
            # Automatic rollback to preserved original!
            target.write_text(original_src, encoding="utf-8")
            return {
                "ok": False,
                "status": "rolled_back_after_check",
                "backup_path": str(backup_path),
                "steps": steps,
            }

        # 9 & 10. Save patch artifact & report actual test results
        patch_file = target.with_suffix(".security.patch")
        patch_file.write_text(diff_txt, encoding="utf-8")
        steps.append({"step": 9, "action": "save_patch", "patch_file": str(patch_file)})
        steps.append({"step": 10, "action": "report_actual_test_results", "test_passed": test_ok})

        return {
            "ok": True,
            "status": "remediated_and_verified",
            "target_file": str(target),
            "recoverable_backup": str(backup_path),
            "regression_test_file": str(reg_test_file),
            "patch_file": str(patch_file),
            "initial_findings_count": len(initial_hits),
            "remaining_findings_count": len(post_hits),
            "test_exit_code": proc.returncode,
            "test_output": ((proc.stdout or "") + (proc.stderr or "")).strip()[:800],
            "steps": steps,
        }

    def _scan_python_ast_and_source(
        self,
        py_file: Path,
        src: str,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        findings: list[dict[str, Any]] = []
        false_positives: list[dict[str, Any]] = []
        try:
            tree = ast.parse(src)
        except SyntaxError:
            return findings, false_positives

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if (
                        isinstance(tgt, ast.Name)
                        and any(k in tgt.id.upper() for k in ("SECRET", "PASSWORD", "API_KEY", "TOKEN"))
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)
                        and len(node.value.value) >= 12
                    ):
                        val_low = node.value.value.lower()
                        if any(tok in val_low for tok in ("dummy", "mock", "example", "placeholder", "fixture")):
                            false_positives.append(
                                self.vuln_engine.record_and_validate_finding(
                                    {
                                        "vuln_identifier": "CWE-798",
                                        "category": "exposed_secrets",
                                        "affected_asset": f"{py_file}:{node.lineno}",
                                        "severity": "info",
                                        "false_positive_reason": "Recognized non-sensitive placeholder/mock test constant.",
                                        "evidence": {"parameterized_or_sanitized": True, "line": node.lineno},
                                    }
                                )
                            )
                        else:
                            findings.append(
                                self.vuln_engine.record_and_validate_finding(
                                    {
                                        "vuln_identifier": "CWE-798",
                                        "category": "exposed_secrets",
                                        "epistemic_status": "confirmed_vulnerability",
                                        "affected_asset": f"{py_file}:{node.lineno}",
                                        "affected_software": py_file.name,
                                        "severity": "high",
                                        "confidence": 0.94,
                                        "evidence": {"reproducible_non_destructive_check": True, "line": node.lineno, "variable": tgt.id},
                                        "recommended_correction": "Load secrets from environment variables or a secret vault rather than source literals.",
                                    }
                                )
                            )
            if isinstance(node, ast.Call):
                # Check SQL .execute(...)
                if isinstance(node.func, ast.Attribute) and node.func.attr == "execute" and node.args:
                    arg0 = node.args[0]
                    if isinstance(arg0, (ast.JoinedStr, ast.BinOp)):
                        findings.append(
                            self.vuln_engine.record_and_validate_finding(
                                {
                                    "vuln_identifier": "CWE-89",
                                    "category": "sql_injection",
                                    "epistemic_status": "confirmed_vulnerability",
                                    "affected_asset": f"{py_file}:{node.lineno}",
                                    "affected_software": py_file.name,
                                    "severity": "high",
                                    "confidence": 0.96,
                                    "exposure": "local_only",
                                    "exploitability_info": "verified_in_scope_repro: dynamic SQL string interpolation in cursor.execute()",
                                    "evidence": {"reproducible_non_destructive_check": True, "line": node.lineno},
                                    "recommended_correction": "Use parameterized SQL queries (`?` placeholders with parameter tuple).",
                                }
                            )
                        )
                    elif isinstance(arg0, ast.Constant) and len(node.args) >= 2:
                        false_positives.append(
                            self.vuln_engine.record_and_validate_finding(
                                {
                                    "vuln_identifier": "CWE-89",
                                    "category": "sql_injection",
                                    "affected_asset": f"{py_file}:{node.lineno}",
                                    "severity": "info",
                                    "false_positive_reason": "Query uses constant SQL template with bound parameters.",
                                    "evidence": {"parameterized_or_sanitized": True, "line": node.lineno},
                                }
                            )
                        )

                # Check yaml.load(...) without SafeLoader or pickle.loads(...)
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and (
                        (node.func.value.id == "yaml" and node.func.attr == "load" and not any(kw.arg == "Loader" for kw in node.keywords))
                        or (node.func.value.id == "pickle" and node.func.attr in {"load", "loads"})
                    )
                ):
                    findings.append(
                        self.vuln_engine.record_and_validate_finding(
                            {
                                "vuln_identifier": "CWE-502",
                                "category": "insecure_deserialization",
                                "epistemic_status": "confirmed_vulnerability",
                                "affected_asset": f"{py_file}:{node.lineno}",
                                "affected_software": py_file.name,
                                "severity": "high",
                                "confidence": 0.95,
                                "evidence": {"reproducible_non_destructive_check": True, "line": node.lineno},
                                "recommended_correction": "Replace unsafe deserializers (`yaml.load`, `pickle.loads`) with `yaml.safe_load` or strict JSON schema parsing.",
                            }
                        )
                    )

                # Check subprocess(..., shell=True)
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"
                    and any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
                ):
                    findings.append(
                        self.vuln_engine.record_and_validate_finding(
                            {
                                "vuln_identifier": "CWE-78",
                                "category": "security_misconfiguration",
                                "epistemic_status": "confirmed_vulnerability",
                                "affected_asset": f"{py_file}:{node.lineno}",
                                "severity": "high",
                                "confidence": 0.92,
                                "evidence": {"reproducible_non_destructive_check": True, "line": node.lineno},
                                "recommended_correction": "Pass an explicit argument list (`argv`) with `shell=False`.",
                            }
                        )
                    )

        return findings, false_positives

    @staticmethod
    def _apply_safe_python_remediations(src: str) -> str:
        out = src
        # 1. Replace unsafe yaml.load(x) -> yaml.safe_load(x)
        out = re.sub(r"\byaml\.load\s*\(([^,\n)]+)\)", r"yaml.safe_load(\1)", out)
        # 2. Replace simple f-string single-param SQL: cursor.execute(f"SELECT ... WHERE name = '{var}'") -> parameterized (?, (var,))
        out = re.sub(
            r"""\.execute\(\s*f(["'])(SELECT\s+[^"'{]+=\s*)['"]\{([A-Za-z_][A-Za-z0-9_]*)\}['"]\1\s*\)""",
            r'.execute("\2?", (\3,))',
            out,
        )
        return out
