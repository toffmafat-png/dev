"""§203 Autonomous Security Scope Management & §204 Continuous Attack Surface Management."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import ssl
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from nova.db import Database
from nova.kali_intel.system_model import KaliSystemKnowledgeModel

SCOPE_10_CATEGORIES: tuple[str, ...] = (
    "local_vm",
    "owned_computer",
    "authorized_network_range",
    "development_environment",
    "test_application",
    "owned_domain",
    "registered_server",
    "authorized_cloud_account",
    "bug_bounty_asset",
    "vulnerable_training_environment",
)

STANDING_ROUTINE_ACTIVITIES: tuple[str, ...] = (
    "asset_inventory",
    "service_discovery",
    "configuration_inspection",
    "non_destructive_vulnerability_scanning",
    "source_code_analysis",
    "dependency_auditing",
    "security_configuration_checks",
    "controlled_application_testing",
    "evidence_collection",
    "report_generation",
    "retesting_remediation",
)

ATTACK_SURFACE_14_CATEGORIES: tuple[str, ...] = (
    "hosts",
    "network_interfaces",
    "open_services",
    "applications",
    "web_endpoints",
    "apis",
    "software_versions",
    "dns_records",
    "tls_configurations",
    "exposed_management_interfaces",
    "external_dependencies",
    "cloud_resources",
    "container_services",
    "technology_stacks",
)


def _extract_host_or_path(target: str) -> tuple[str, str]:
    """Return (normalized_host_or_ip_or_path, scheme_or_protocol)."""
    raw = (target or "").strip()
    if "://" in raw:
        parsed = urlparse(raw)
        return (parsed.hostname or raw).lower(), (parsed.scheme or "http").lower()
    if raw.startswith("/") or raw.startswith("./") or Path(raw).exists():
        try:
            return str(Path(raw).resolve()), "local_fs"
        except OSError:
            return raw, "local_fs"
    if ":" in raw and raw.count(":") == 1 and not raw.endswith("]"):
        host_part, _port = raw.split(":", 1)
        return host_part.lower(), "tcp"
    return raw.lower(), "tcp"


def _target_matches_pattern(candidate: str, pattern: str) -> bool:
    cand_norm, _ = _extract_host_or_path(candidate)
    pat_norm, _ = _extract_host_or_path(pattern)
    if not cand_norm or not pat_norm:
        return False
    if cand_norm == pat_norm:
        return True
    # Path prefix containment for authorized local directories
    if pat_norm.startswith("/") and cand_norm.startswith("/"):
        try:
            Path(cand_norm).relative_to(Path(pat_norm))
            return True
        except ValueError:
            pass
    # CIDR / IP matching
    try:
        net = ipaddress.ip_network(pat_norm, strict=False)
        ip_val = ipaddress.ip_address("127.0.0.1" if cand_norm == "localhost" else cand_norm)
        return ip_val in net
    except ValueError:
        pass
    # Subdomain wildcard e.g. *.lab.local
    return bool(pat_norm.startswith("*.") and cand_norm.endswith(pat_norm[1:]))


class SecurityScopeRegistry:
    """§203 Centralized security scope registry with standing authorization and anti-expansion enforcement."""

    ALLOW_SELF_SCOPE_EXPANSION = False

    def __init__(self, *, db: Database):
        self.db = db
        self._rate_buckets: dict[str, list[float]] = {}

    def register_scope(
        self,
        *,
        name: str,
        scope_category: str = "",
        category: str = "",
        targets: list[str],
        ownership_evidence: str = "",
        authorization_evidence: str = "",
        permitted_activities: list[str] | None = None,
        excluded_targets: list[str] | None = None,
        allowed_windows: list[str] | None = None,
        rate_limit_rpm: int = 120,
        permitted_protocols: list[str] | None = None,
        data_restrictions: dict[str, Any] | None = None,
        expires_at: str = "",
        reporting_requirements: str = "evidence_backed_markdown_and_json",
        caller_source: str = "operator",
        standing_authorization: bool = True,
        scope_id: str | None = None,
    ) -> dict[str, Any]:
        """§203 Register or update an explicit security testing scope (operator-only; models/tools cannot self-expand)."""
        if caller_source in {"tool", "model", "plugin", "downloaded_instruction"}:
            raise PermissionError(
                f"Blocked: `{caller_source}` is never permitted to create or expand a security scope (§203)."
            )
        cat = (scope_category or category).strip().lower()
        if cat not in SCOPE_10_CATEGORIES:
            raise ValueError(f"Unsupported scope_category '{cat}'. Valid: {SCOPE_10_CATEGORIES}")
        if not targets:
            raise ValueError("At least one target identifier is required.")
        evidence_str = (ownership_evidence or authorization_evidence).strip()
        if not evidence_str:
            raise ValueError("Ownership or documented authorization evidence is required.")

        acts = (
            list(permitted_activities)
            if permitted_activities is not None
            else (list(STANDING_ROUTINE_ACTIVITIES) if standing_authorization else ["asset_inventory"])
        )
        return self.db.upsert_cyber_scope(
            {
                "id": scope_id,
                "name": name.strip(),
                "scope_category": cat,
                "targets": [t.strip() for t in targets if t.strip()],
                "excluded_targets": [e.strip() for e in (excluded_targets or []) if e.strip()],
                "ownership_evidence": evidence_str,
                "permitted_activities": acts,
                "allowed_windows": allowed_windows or ["always"],
                "rate_limit_rpm": rate_limit_rpm,
                "permitted_protocols": permitted_protocols or ["tcp", "http", "https", "local_fs"],
                "data_restrictions": data_restrictions or {"extract_real_user_records": False, "destructive_payloads": False},
                "expires_at": expires_at,
                "reporting_requirements": reporting_requirements,
                "active": True,
            }
        )

    def authorize_operation(
        self,
        *,
        target: str,
        activity: str = "non_destructive_vulnerability_scanning",
        protocol: str = "",
        consume_rate_token: bool = True,
    ) -> dict[str, Any]:
        """§203 Enforce registered scope, exclusions, expiration, protocol, and rate limits automatically."""
        _, inferred_proto = _extract_host_or_path(target)
        proto = (protocol or inferred_proto or "tcp").lower()
        now_dt = datetime.now(UTC)

        scopes = self.db.list_cyber_scopes(active_only=True)
        for sc in scopes:
            # Explicit exclusions always take precedence!
            if any(_target_matches_pattern(target, excl) for excl in sc["excluded_targets"]):
                return {
                    "authorized": False,
                    "status": "paused_excluded_system",
                    "target": target,
                    "scope_id": sc["id"],
                    "requires_manual_prompt": False,
                    "reason": f"Target `{target}` matches excluded system list in scope `{sc['name']}`.",
                }

            if not any(_target_matches_pattern(target, pat) for pat in sc["targets"]):
                continue

            # Check expiration
            exp = sc.get("expires_at") or ""
            if exp:
                try:
                    exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
                    if exp_dt.tzinfo is None:
                        exp_dt = exp_dt.replace(tzinfo=UTC)
                    if now_dt >= exp_dt:
                        return {
                            "authorized": False,
                            "status": "paused_scope_expired",
                            "target": target,
                            "scope_id": sc["id"],
                            "requires_manual_prompt": True,
                            "reason": f"Scope `{sc['name']}` expired at {exp}.",
                        }
                except ValueError:
                    return {
                        "authorized": False,
                        "status": "invalid_scope_expiration",
                        "target": target,
                        "scope_id": sc["id"],
                        "requires_manual_prompt": True,
                        "reason": "Malformed scope expiration timestamp.",
                    }

            if activity not in sc["permitted_activities"]:
                return {
                    "authorized": False,
                    "status": "activity_not_in_standing_scope",
                    "target": target,
                    "scope_id": sc["id"],
                    "requires_manual_prompt": True,
                    "reason": f"Activity `{activity}` is not authorized under scope `{sc['name']}`.",
                }

            allowed_protos = [p.lower() for p in sc["permitted_protocols"]]
            if allowed_protos and proto not in allowed_protos:
                return {
                    "authorized": False,
                    "status": "protocol_not_permitted",
                    "target": target,
                    "scope_id": sc["id"],
                    "requires_manual_prompt": False,
                    "reason": f"Protocol `{proto}` is outside permitted protocols {allowed_protos}.",
                }

            if consume_rate_token and not self._allow_rate(sc["id"], int(sc["rate_limit_rpm"])):
                return {
                    "authorized": False,
                    "status": "rate_limited",
                    "target": target,
                    "scope_id": sc["id"],
                    "requires_manual_prompt": False,
                    "reason": f"Rate limit ({sc['rate_limit_rpm']} rpm) reached for scope `{sc['name']}`.",
                }

            standing_no_prompt = activity in STANDING_ROUTINE_ACTIVITIES
            return {
                "authorized": True,
                "status": "authorized_in_scope",
                "target": target,
                "scope_id": sc["id"],
                "scope_name": sc["name"],
                "standing_authorization": standing_no_prompt,
                "requires_manual_prompt": not standing_no_prompt,
                "rate_limit_rpm": sc["rate_limit_rpm"],
                "data_restrictions": sc["data_restrictions"],
            }

        return {
            "authorized": False,
            "status": "paused_out_of_scope",
            "target": target,
            "scope_id": "",
            "requires_manual_prompt": True,
            "reason": f"Target `{target}` is outside all registered security scopes; target paused.",
        }

    def partition_targets_by_scope(
        self,
        targets: list[str],
        *,
        activity: str = "asset_inventory",
    ) -> dict[str, Any]:
        """§203 Pause out-of-scope targets while continuing unrelated authorized work seamlessly."""
        authorized_targets: list[dict[str, Any]] = []
        paused_targets: list[dict[str, Any]] = []
        for t in targets:
            decision = self.authorize_operation(target=t, activity=activity, consume_rate_token=False)
            if decision["authorized"]:
                authorized_targets.append(decision)
            else:
                paused_targets.append(decision)
        return {
            "authorized_targets": authorized_targets,
            "paused_out_of_scope_targets": paused_targets,
            "continued_authorized_work": len(authorized_targets) > 0,
        }

    def _allow_rate(self, scope_id: str, rpm: int) -> bool:
        now_m = time.monotonic()
        bucket = [ts for ts in self._rate_buckets.get(scope_id, []) if now_m - ts < 60.0]
        if len(bucket) >= max(1, rpm):
            self._rate_buckets[scope_id] = bucket
            return False
        bucket.append(now_m)
        self._rate_buckets[scope_id] = bucket
        return True


class AttackSurfaceManager:
    """§204 Continuous Attack Surface Discovery, Scope Correlation, and Meaningful Delta Detection."""

    def __init__(
        self,
        *,
        db: Database,
        scope_registry: SecurityScopeRegistry,
        system_model: KaliSystemKnowledgeModel,
    ):
        self.db = db
        self.scope_registry = scope_registry
        self.system_model = system_model

    def assess_target_surface(
        self,
        target: str,
        *,
        ports_to_check: list[int] | None = None,
        endpoints_hint: list[str] | None = None,
    ) -> dict[str, Any]:
        """§204 Discover in-scope asset surface, correlate scope, and emit alerts ONLY on meaningful changes."""
        auth = self.scope_registry.authorize_operation(target=target, activity="asset_inventory")
        if not auth["authorized"]:
            return {
                "ok": False,
                "status": auth["status"],
                "reason": auth["reason"],
                "target": target,
            }

        host_or_path, proto = _extract_host_or_path(target)
        env = self.system_model.get_or_refresh_model()["model"]
        open_services: list[dict[str, Any]] = []
        tls_info: dict[str, Any] = {}
        dns_records: list[str] = []
        mgmt_interfaces: list[int] = []
        dependencies: list[str] = []

        if proto == "local_fs":
            p = Path(host_or_path)
            if (p / "requirements.txt").is_file():
                dependencies.extend(
                    ln.strip()
                    for ln in (p / "requirements.txt").read_text(encoding="utf-8", errors="replace").splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                )
            if (p / "package.json").is_file():
                try:
                    pj = json.loads((p / "package.json").read_text(encoding="utf-8"))
                    dependencies.extend(sorted(pj.get("dependencies", {}).keys()))
                except Exception:
                    pass
            asset_cat = "development_project"
        else:
            asset_cat = "network_or_web_asset"
            probe_ports = list(ports_to_check or ([int(urlparse(target).port)] if "://" in target and urlparse(target).port else []))
            for port in probe_ports[:16]:
                if self._tcp_port_open(host_or_path, port):
                    open_services.append({"port": port, "protocol": "tcp", "state": "open"})
                    if port in {22, 2375, 2376, 8080, 8443, 9090}:
                        mgmt_interfaces.append(port)
            try:
                addrs = sorted({info[4][0] for info in socket.getaddrinfo(host_or_path, None)})
                dns_records = addrs[:8]
            except OSError:
                dns_records = []
            if proto == "https":
                port = urlparse(target).port or 443
                tls_info = self._inspect_tls_peer(host_or_path, port)

        fingerprint_payload = {
            "host_or_path": host_or_path,
            "services": open_services,
            "endpoints": sorted(endpoints_hint or []),
            "dependencies": sorted(dependencies[:50]),
            "tls": tls_info,
        }
        fp_sha = hashlib.sha256(json.dumps(fingerprint_payload, sort_keys=True).encode()).hexdigest()
        asset_id = f"asset:{hashlib.sha256(host_or_path.encode()).hexdigest()[:14]}"

        saved = self.db.upsert_cyber_asset(
            {
                "asset_id": asset_id,
                "address_or_host": host_or_path,
                "category": asset_cat,
                "scope_id": auth["scope_id"],
                "scope_status": "authorized_in_scope",
                "services": open_services,
                "software_versions": env["development_environments"],
                "vulnerabilities": [],
                "confidence": 0.95,
                "fingerprint_sha256": fp_sha,
                "remediation_history": [],
                "metadata": {
                    "supported_surface_dimensions": list(ATTACK_SURFACE_14_CATEGORIES),
                    "network_interfaces_host": [i["name"] for i in env["network_interfaces"]],
                    "web_and_api_endpoints": sorted(endpoints_hint or []),
                    "dns_records": dns_records,
                    "tls_configuration": tls_info,
                    "exposed_management_interfaces": mgmt_interfaces,
                    "external_dependencies": dependencies[:40],
                    "container_services": env["container_runtimes"],
                },
            }
        )
        return {
            "ok": True,
            "asset": saved,
            "meaningful_change_alert": bool(saved.get("meaningful_change_detected")),
            "duplicate_unchanged_alert_suppressed": not bool(saved.get("meaningful_change_detected")),
        }

    @staticmethod
    def _tcp_port_open(host: str, port: int, timeout: float = 0.6) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    @staticmethod
    def _inspect_tls_peer(host: str, port: int) -> dict[str, Any]:
        ctx = ssl.create_default_context()
        try:
            with (
                socket.create_connection((host, port), timeout=1.5) as sock,
                ctx.wrap_socket(sock, server_hostname=host) as ssock,
            ):
                cert = ssock.getpeercert() or {}
                return {
                    "tls_version": ssock.version() or "",
                    "cipher": (ssock.cipher() or ("", "", 0))[0],
                    "notAfter": cert.get("notAfter", ""),
                }
        except OSError as exc:
            return {"reachable": False, "detail": str(exc)[:140]}
