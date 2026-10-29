"""§156 System Health, Observability & Network Monitoring,
§158 Persistent Problem-Solving & Multi-Source Troubleshooting, and
§159 Infrastructure & Environment Knowledge Engine.
"""
from __future__ import annotations

import re
import shutil
import socket
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nova.db import Database
from nova.observability import Redactor
from nova.resources import ResourceManager

INFRASTRUCTURE_CATEGORIES: frozenset[str] = frozenset(
    {
        "local_hardware_inventory",
        "driver_repair_history",
        "installed_toolchains",
        "service_topology",
        "network_interfaces",
        "registered_servers",
        "deployment_paths",
        "project_environments",
        "common_failure_fixes",
        "preferred_workflows",
        "storage_locations",
        "backup_locations",
        "monitoring_baselines",
    }
)

_DESTRUCTIVE_TROUBLESHOOT_PATTERNS = re.compile(
    r"(?i)(\brm\s+-rf\s+/|\bmkfs\.|\bdd\s+if=|\bchmod\s+-R\s+777\s+/|\bufw\s+disable\b|\bsetenforce\s+0\b|StrictHostKeyChecking=no)"
)
_PROMPT_INJECTION_PATTERNS = re.compile(
    r"(?i)(ignore\s+(?:all\s+)?previous\s+instructions|run\s+as\s+root\s+immediately|curl\s+[^|]+\|\s*(?:sudo\s+)?(?:ba)?sh)"
)
_SECRET_MATERIAL_PATTERNS = re.compile(
    r"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|sk-[A-Za-z0-9]{20,}|password\s*[:=]\s*\S+)",
    re.IGNORECASE,
)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _run_quick(argv: list[str], timeout: float = 3.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)


class SystemNetworkMonitor:
    """§156 Low-overhead 14-signal system/network observability and alert evaluation."""

    def __init__(
        self,
        *,
        db: Database,
        resource_manager: ResourceManager,
        workspace_path: Path,
        worker_status_fn: Callable[[], dict[str, Any]] | None = None,
        recording_status_fn: Callable[[], dict[str, Any]] | None = None,
        unreachable_servers_fn: Callable[[], list[str]] | None = None,
    ) -> None:
        self.db = db
        self.resource_manager = resource_manager
        self.workspace_path = workspace_path
        self._worker_status_fn = worker_status_fn
        self._recording_status_fn = recording_status_fn
        self._unreachable_servers_fn = unreachable_servers_fn

    def collect_snapshot(self) -> dict[str, Any]:
        t0 = time.monotonic()
        res = self.resource_manager.sample()

        # Swap pressure from /proc/meminfo
        swap_total_mb = 0.0
        swap_free_mb = 0.0
        try:
            for ln in Path("/proc/meminfo").read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = ln.replace(":", "").split()
                if len(parts) >= 2 and parts[1].isdigit():
                    if parts[0] == "SwapTotal":
                        swap_total_mb = int(parts[1]) / 1024.0
                    elif parts[0] == "SwapFree":
                        swap_free_mb = int(parts[1]) / 1024.0
        except OSError:
            pass
        swap_used_mb = max(0.0, swap_total_mb - swap_free_mb)
        swap_pct = round((swap_used_mb / swap_total_mb) * 100.0, 1) if swap_total_mb > 0 else 0.0

        # Storage health (read-only mount anomalies)
        ro_mounts: list[str] = []
        try:
            for ln in Path("/proc/mounts").read_text(encoding="utf-8", errors="ignore").splitlines():
                cols = ln.split()
                if len(cols) >= 4 and cols[1] in {"/", "/home"} and "ro," in (cols[3] + ","):
                    ro_mounts.append(cols[1])
        except OSError:
            pass

        # Thermal & battery
        max_temp_c: float | None = None
        if Path("/sys/class/thermal").is_dir():
            temps: list[float] = []
            for tz in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
                try:
                    raw = tz.read_text(encoding="utf-8").strip()
                    if raw.lstrip("-").isdigit():
                        temps.append(int(raw) / 1000.0)
                except OSError:
                    continue
            if temps:
                max_temp_c = round(max(temps), 1)

        power_states: list[dict[str, str]] = []
        if Path("/sys/class/power_supply").is_dir():
            for ps in sorted(Path("/sys/class/power_supply").iterdir()):
                try:
                    st = (ps / "status").read_text(encoding="utf-8").strip() if (ps / "status").exists() else "online"
                    cap = (ps / "capacity").read_text(encoding="utf-8").strip() if (ps / "capacity").exists() else ""
                    power_states.append({"name": ps.name, "status": st, "capacity": cap})
                except OSError:
                    continue

        # Failed user/system units (low overhead)
        failed_units: list[str] = []
        if shutil.which("systemctl"):
            rc, out, _ = _run_quick(["systemctl", "--user", "--failed", "--no-legend", "--plain"], timeout=2.0)
            if rc == 0 and out:
                failed_units = [ln.split()[0] for ln in out.splitlines() if ln.strip()][:10]

        # Network link state, default gateway & DNS config
        interfaces: dict[str, str] = {}
        if Path("/sys/class/net").is_dir():
            for n in sorted(Path("/sys/class/net").iterdir()):
                try:
                    interfaces[n.name] = (n / "operstate").read_text(encoding="utf-8").strip()
                except OSError:
                    interfaces[n.name] = "unknown"

        default_gw = self._read_default_gateway()
        dns_servers = self._read_dns_servers()
        localhost_resolves = self._check_local_dns()
        listening_ports = self._read_listening_tcp_ports()

        worker_state = self._worker_status_fn() if self._worker_status_fn else {"running": True}
        rec_state = self._recording_status_fn() if self._recording_status_fn else {"recording_active": False}

        disk = shutil.disk_usage(self.workspace_path)
        disk_used_pct = round(((disk.total - disk.free) / max(1, disk.total)) * 100.0, 1)
        disk_free_gb = round(disk.free / (1024**3), 2)
        cpu_pct = round((res.cpu_busy_ratio or 0.0) * 100.0, 1)

        return {
            "collected_at": _iso(),
            "collection_overhead_ms": round((time.monotonic() - t0) * 1000.0, 2),
            "cpu": {"cores": res.cpu_count, "load_1m": res.load_1m, "percent": cpu_pct},
            "memory": {
                "total_mb": res.memory_total_mb,
                "available_mb": res.memory_available_mb,
                "used_percent": round(((res.memory_total_mb - res.memory_available_mb) / max(1.0, float(res.memory_total_mb))) * 100.0, 1),
            },
            "swap": {"total_mb": round(swap_total_mb, 1), "used_mb": round(swap_used_mb, 1), "used_percent": swap_pct},
            "disk": {"free_gb": disk_free_gb, "used_percent": disk_used_pct, "unexpected_ro_mounts": ro_mounts},
            "thermal": {"max_temp_celsius": max_temp_c},
            "power": {"supplies": power_states},
            "services": {"failed_user_units": failed_units},
            "network": {
                "interfaces": interfaces,
                "default_gateway": default_gw,
                "dns_servers": dns_servers,
                "local_hostname_resolution_ok": localhost_resolves,
                "listening_tcp_ports": listening_ports,
            },
            "worker": worker_state,
            "recording": rec_state,
        }

    def configure_alert_rule(
        self,
        *,
        name: str,
        metric: str,
        operator: str,
        threshold: float,
        enabled: bool = True,
    ) -> dict[str, Any]:
        if operator not in {"lt", "gt", "eq"}:
            raise ValueError("operator must be 'lt', 'gt', or 'eq'")
        return self.db.save_observability_alert(
            {
                "name": name,
                "metric": metric,
                "comparator": operator,
                "threshold": threshold,
                "enabled": enabled,
            }
        )

    def evaluate_alerts(self, snapshot: dict[str, Any] | None = None) -> dict[str, Any]:
        snap = snapshot or self.collect_snapshot()
        unreachable = self._unreachable_servers_fn() if self._unreachable_servers_fn else []
        metrics: dict[str, float] = {
            "disk_free_gb": float(snap["disk"]["free_gb"]),
            "disk_used_percent": float(snap["disk"]["used_percent"]),
            "memory_used_percent": float(snap["memory"]["used_percent"]),
            "memory_available_mb": float(snap["memory"]["available_mb"]),
            "swap_used_percent": float(snap["swap"]["used_percent"]),
            "cpu_percent": float(snap["cpu"]["percent"]),
            "failed_services_count": float(len(snap["services"]["failed_user_units"])),
            "unreachable_servers_count": float(len(unreachable)),
        }

        triggered: list[dict[str, Any]] = []
        for rule in self.db.list_observability_alerts():
            if not rule["enabled"]:
                continue
            val = metrics.get(rule["metric"])
            if val is None:
                continue
            op = rule["comparator"]
            th = float(rule["threshold"])
            fired = (op in {"lt", "<", "<="} and val < th) or (op in {"gt", ">", ">="} and val > th) or (op in {"eq", "=="} and val == th)
            if fired:
                saved = self.db.save_observability_alert(
                    {
                        **rule,
                        "last_triggered_at": _iso(),
                    }
                )
                triggered.append(saved)

        return {"evaluated_at": _iso(), "metrics": metrics, "triggered_count": len(triggered), "triggered": triggered}

    @staticmethod
    def _read_default_gateway() -> str:
        try:
            for ln in Path("/proc/net/route").read_text(encoding="utf-8", errors="ignore").splitlines()[1:]:
                cols = ln.split()
                if len(cols) >= 3 and cols[1] == "00000000":
                    gw_hex = cols[2]
                    if len(gw_hex) == 8:
                        octets = [str(int(gw_hex[i : i + 2], 16)) for i in (6, 4, 2, 0)]
                        return ".".join(octets)
        except OSError:
            pass
        return ""

    @staticmethod
    def _read_dns_servers() -> list[str]:
        servers: list[str] = []
        try:
            for ln in Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="ignore").splitlines():
                ln = ln.strip()
                if ln.startswith("nameserver "):
                    servers.append(ln.split()[1])
        except OSError:
            pass
        return servers

    @staticmethod
    def _check_local_dns() -> bool:
        try:
            socket.getaddrinfo("localhost", None)
            return True
        except OSError:
            return False

    @staticmethod
    def _read_listening_tcp_ports() -> list[int]:
        ports: set[int] = set()
        for proc_file in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
            try:
                for ln in proc_file.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]:
                    cols = ln.split()
                    if len(cols) >= 4 and cols[3] == "0A":  # TCP_LISTEN
                        _, port_hex = cols[1].split(":")
                        ports.add(int(port_hex, 16))
            except (OSError, ValueError):
                continue
        return sorted(ports)[:50]


class InfrastructureKnowledgeEngine:
    """§159 Structured, TTL-revalidated environment knowledge separated from raw secrets."""

    def __init__(self, *, db: Database, redactor: Redactor) -> None:
        self.db = db
        self.redactor = redactor

    def record(
        self,
        *,
        category: str,
        key: str,
        title: str,
        value: dict[str, Any],
        source: str,
        ttl_seconds: int = 86400,
        verified_at: str | None = None,
    ) -> dict[str, Any]:
        if category not in INFRASTRUCTURE_CATEGORIES:
            raise ValueError(f"Unknown infrastructure knowledge category '{category}'.")
        serialized_check = str(value)
        if _SECRET_MATERIAL_PATTERNS.search(serialized_check):
            raise PermissionError(
                "Infrastructure Knowledge Engine refuses raw passwords, tokens, or private keys (§159); store secret material in SecretStore only."
            )
        scrubbed_val = self.redactor.scrub(value, max_chars=2000)
        ts = verified_at or _iso()
        saved = self.db.save_infrastructure_knowledge(
            {
                "category": category,
                "subject": title,
                "content": str(scrubbed_val),
                "source": source,
                "target_ref": key,
                "observed_at": ts,
                "revalidated_at": ts,
                "ttl_seconds": max(60, int(ttl_seconds)),
                "metadata": scrubbed_val if isinstance(scrubbed_val, dict) else {"data": scrubbed_val},
            }
        )
        return self._annotate_staleness(saved)

    def list_records(self, *, category: str = "", query: str = "") -> list[dict[str, Any]]:
        rows = self.db.list_infrastructure_knowledge(category=category, query=query)
        return [self._annotate_staleness(r) for r in rows]

    def export_records(self, *, category: str = "") -> dict[str, Any]:
        records = self.list_records(category=category)
        return {
            "exported_at": _iso(),
            "count": len(records),
            "categories": sorted({r["category"] for r in records}),
            "records": records,
        }

    def delete_record(self, record_id: str) -> bool:
        return self.db.delete_infrastructure_knowledge(record_id)

    @staticmethod
    def _annotate_staleness(rec: dict[str, Any]) -> dict[str, Any]:
        try:
            ver_dt = datetime.fromisoformat(rec["revalidated_at"])
            if ver_dt.tzinfo is None:
                ver_dt = ver_dt.replace(tzinfo=UTC)
            age_sec = max(0.0, (datetime.now(UTC) - ver_dt).total_seconds())
        except ValueError:
            age_sec = 999999.0
        needs_revalidation = age_sec > float(rec["ttl_seconds"])
        return {
            **rec,
            "age_seconds": round(age_sec, 2),
            "needs_revalidation": needs_revalidation,
        }


class PersistentTroubleshooter:
    """§158 Systematic Multi-Source Troubleshooting & Hypothesis Pivot Engine."""

    def __init__(self, *, infra_knowledge: InfrastructureKnowledgeEngine, redactor: Redactor) -> None:
        self.infra = infra_knowledge
        self.redactor = redactor

    @staticmethod
    def isolate_external_reference(raw_text: str, *, source_url: str = "") -> dict[str, Any]:
        """Treat external troubleshooting articles as untrusted reference data, NEVER executable policy."""
        flagged = bool(_PROMPT_INJECTION_PATTERNS.search(raw_text) or _DESTRUCTIVE_TROUBLESHOOT_PATTERNS.search(raw_text))
        sanitized_lines = [
            ln for ln in raw_text.splitlines()
            if not _PROMPT_INJECTION_PATTERNS.search(ln) and not _DESTRUCTIVE_TROUBLESHOOT_PATTERNS.search(ln)
        ]
        return {
            "trust_level": "untrusted_external_reference",
            "can_authorize_commands": False,
            "source_url": source_url,
            "unsafe_patterns_stripped": flagged,
            "sanitized_excerpt": "\n".join(sanitized_lines)[:1500],
        }

    def investigate_with_pivots(
        self,
        *,
        goal: str,
        hypotheses: list[dict[str, Any]],
        external_notes: str = "",
    ) -> dict[str, Any]:
        """Execute §158 persistent multi-source diagnostics:
        When an initial probe fails (missing tool, non-zero exit, disproven hypothesis),
        systematically pivot across permitted fallback probes and knowledge records while
        blocking reckless/destructive commands.
        """
        attempts: list[dict[str, Any]] = []
        rejected_hypotheses: list[dict[str, str]] = []
        confirmed_hypothesis: dict[str, Any] | None = None
        blocked_unsafe: list[dict[str, str]] = []

        for hyp in hypotheses:
            h_name = str(hyp.get("name") or "unnamed_hypothesis")
            probes: list[Any] = list(hyp.get("probes") or [])
            hyp_succeeded = False

            for probe in probes:
                if callable(probe):
                    res = probe()
                    ok = bool(res.get("ok"))
                    attempts.append({"hypothesis": h_name, "source": res.get("source", "callable_probe"), "ok": ok, "detail": res})
                    if ok:
                        hyp_succeeded = True
                        confirmed_hypothesis = {"name": h_name, "evidence": res}
                        break
                    continue

                argv = [str(x) for x in probe] if isinstance(probe, (list, tuple)) else [str(probe)]
                joined = " ".join(argv)
                if _DESTRUCTIVE_TROUBLESHOOT_PATTERNS.search(joined):
                    blocked_unsafe.append(
                        {
                            "hypothesis": h_name,
                            "command": joined,
                            "reason": "Blocked reckless/destructive command during troubleshooting (§158).",
                        }
                    )
                    continue

                bin_path = shutil.which(argv[0])
                if not bin_path and not Path(argv[0]).exists():
                    attempts.append(
                        {
                            "hypothesis": h_name,
                            "source": joined,
                            "ok": False,
                            "failure_kind": "tool_unavailable_pivoting",
                            "detail": f"Binary '{argv[0]}' not installed; pivoting to next permitted diagnostic source.",
                        }
                    )
                    continue

                rc, out, err = _run_quick(argv, timeout=4.0)
                ok = rc == 0 and bool(out or hyp.get("allow_empty_stdout"))
                attempts.append(
                    {
                        "hypothesis": h_name,
                        "source": joined,
                        "ok": ok,
                        "exit_code": rc,
                        "stdout": self.redactor.scrub_text(out, max_chars=500),
                        "stderr": self.redactor.scrub_text(err, max_chars=300),
                    }
                )
                if ok:
                    hyp_succeeded = True
                    confirmed_hypothesis = {
                        "name": h_name,
                        "verified_via": joined,
                        "evidence": self.redactor.scrub_text(out, max_chars=800),
                    }
                    break

            if hyp_succeeded:
                break
            rejected_hypotheses.append({"name": h_name, "reason": "All diagnostic probes for hypothesis failed or were disproven."})

        # Consult local Infrastructure Knowledge if command probes did not yet confirm
        prior_fixes = self.infra.list_records(category="common_failure_fixes", query=goal.split()[0] if goal.strip() else "")
        isolated_ext = self.isolate_external_reference(external_notes) if external_notes else None

        return {
            "goal": goal,
            "investigated_at": _iso(),
            "stopped_at_first_failure": False,
            "attempt_count": len(attempts),
            "attempts": attempts,
            "rejected_hypotheses": rejected_hypotheses,
            "blocked_unsafe_commands": blocked_unsafe,
            "confirmed_hypothesis": confirmed_hypothesis,
            "matching_infrastructure_knowledge": prior_fixes[:5],
            "isolated_external_reference": isolated_ext,
            "resolved": confirmed_hypothesis is not None,
        }
