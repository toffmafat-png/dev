"""§209 Vulnerability Research, §210 Reverse Engineering & Forensics, §211 Wireless/Hardware Lab, §212 DFIR & §213 Threat Knowledge."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import struct
import zipfile
from pathlib import Path
from typing import Any

from nova.db import Database, utc_now
from nova.kali_intel.system_model import KaliSystemKnowledgeModel, _run_probe
from nova.knowledge import KnowledgeStore

RESEARCH_EPISTEMIC_8_FIELDS: tuple[str, ...] = (
    "published_information",
    "confirmed_affected_versions",
    "suspected_affected_versions",
    "available_patches",
    "public_test_evidence",
    "unverified_claims",
    "mitigations",
    "remaining_uncertainties",
)

PROHIBITED_EXPLOIT_REQUEST_TERMS: tuple[str, ...] = (
    "weaponized exploit",
    "reverse shell payload",
    "credential stealer",
    "ransomware",
    "wiper payload",
    "bypass edr",
)

CURATED_SECURITY_FRAMEWORKS_SEED: tuple[dict[str, Any], ...] = (
    {
        "id": "kb-cwe-89",
        "identifier": "CWE-89",
        "title": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "cvss_score": 9.8,
        "cwe_id": "CWE-89",
        "sources": [
            {"name": "MITRE CWE-89", "url": "https://cwe.mitre.org/data/definitions/89.html"},
            {"name": "OWASP A03:2021 Injection", "url": "https://owasp.org/Top10/A03_2021-Injection/"},
            {"name": "NIST SP 800-53 SI-10", "url": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"},
        ],
        "dossier": {
            "published_information": "Constructing SQL statements via untrusted string concatenation allows query structure alteration.",
            "confirmed_affected_versions": ["Custom applications concatenating user input into SQL execute() calls"],
            "suspected_affected_versions": ["Legacy ORM raw-query wrappers without bound parameters"],
            "available_patches": ["Migrate all dynamic SQL statements to parameterized prepared statements (`?` / `$1`)."],
            "public_test_evidence": ["AST detection of f-string/percent-formatted SQL templates."],
            "unverified_claims": [],
            "mitigations": ["Parameterized queries", "Least-privilege DB roles", "Input type validation (NIST SI-10)"],
            "remaining_uncertainties": ["Dynamic identifier/column names still require strict allowlist validation."],
            "mitre_attack_defensive_mapping": "T1190 (Exploit Public-Facing Application) -> M1050/Application Isolation & Input Parameterization",
        },
    },
    {
        "id": "kb-cwe-502",
        "identifier": "CWE-502",
        "title": "Deserialization of Untrusted Data",
        "cvss_score": 8.8,
        "cwe_id": "CWE-502",
        "sources": [
            {"name": "MITRE CWE-502", "url": "https://cwe.mitre.org/data/definitions/502.html"},
            {"name": "OWASP A08:2021 Software and Data Integrity Failures", "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"},
        ],
        "dossier": {
            "published_information": "Unsafe object deserializers (`pickle.loads`, `yaml.load` without SafeLoader) instantiate arbitrary classes.",
            "confirmed_affected_versions": ["PyYAML `yaml.load()` without `SafeLoader`", "Python `pickle` on untrusted bytes"],
            "suspected_affected_versions": [],
            "available_patches": ["Use `yaml.safe_load()` or strict JSON/Pydantic schema parsing."],
            "public_test_evidence": ["Static AST inspection of unsafe loader calls."],
            "unverified_claims": [],
            "mitigations": ["Replace polymorphic binary serializers with JSON + strict schema validation"],
            "remaining_uncertainties": [],
            "mitre_attack_defensive_mapping": "T1059 -> Safe Data Parsing & Execution Prevention",
        },
    },
    {
        "id": "kb-cve-2024-6387",
        "identifier": "CVE-2024-6387",
        "title": "OpenSSH Server Signal Handler Race Condition (regreSSHion) — Defensive Advisory Summary",
        "cvss_score": 8.1,
        "cwe_id": "CWE-362",
        "sources": [
            {"name": "OpenSSH 9.8 Release Notes", "url": "https://www.openssh.com/txt/release-9.8"},
            {"name": "Debian Security Tracker CVE-2024-6387", "url": "https://security-tracker.debian.org/tracker/CVE-2024-6387"},
        ],
        "dossier": {
            "published_information": "Async-signal-unsafe calls inside sshd SIGALRM `GraceTime` handler in OpenSSH portable 8.5p1 through < 9.8p1 on glibc Linux.",
            "confirmed_affected_versions": ["OpenSSH >= 8.5p1, < 9.8p1 (glibc Linux builds without distro backport)"],
            "suspected_affected_versions": ["Unpatched custom source builds prior to 9.8p1"],
            "available_patches": ["Upgrade to OpenSSH 9.8p1+ or apply Debian/Kali security backport (`1:9.2p1-2+deb12u3`+ / current `openssh-server`)."],
            "public_test_evidence": ["Package version comparison via `dpkg-query -W openssh-server` and `LoginGraceTime` config review."],
            "unverified_claims": ["Unverified third-party claims of instant cross-architecture reliability."],
            "mitigations": ["Apply vendor `openssh-server` security update", "Restrict SSH management access via firewall/VPN", "Set `LoginGraceTime 0` only as temporary emergency mitigation (trade-off: connection slot exhaustion)"],
            "remaining_uncertainties": ["Exact exposure depends on distro backport patch level rather than upstream banner string alone."],
            "mitre_attack_defensive_mapping": "M1051 (Update Software) & M1035 (Limit Access to Resource Over Network)",
        },
    },
)


class SecurityKnowledgeAndResearchWorkbench:
    """§209 Vulnerability Research Workbench & §213 Structured Threat/Security Knowledge Base."""

    ALLOW_WEAPONIZED_EXPLOIT_GENERATION = False
    MAX_INGEST_BYTES_WITHOUT_OVERRIDE = 25 * 1024 * 1024  # 25 MB low-spec guard

    def __init__(
        self,
        *,
        db: Database,
        knowledge_store: KnowledgeStore | None = None,
    ):
        self.db = db
        self.knowledge_store = knowledge_store
        self._seeded = False

    def ensure_baseline_knowledge(self) -> None:
        if self._seeded:
            return
        for item in CURATED_SECURITY_FRAMEWORKS_SEED:
            self.ingest_security_advisory(item)
        self._seeded = True

    def check_storage_budget_before_ingest(self, payload_bytes: int, *, min_free_disk_gb: float = 1.0) -> dict[str, Any]:
        """§213 Never download/ingest enormous external databases unless storage & resource limits pass."""
        free_gb = round(shutil.disk_usage("/").free / (1024**3), 2)
        within_cap = payload_bytes <= self.MAX_INGEST_BYTES_WITHOUT_OVERRIDE and free_gb >= min_free_disk_gb
        return {
            "permitted": within_cap,
            "payload_bytes": payload_bytes,
            "max_single_ingest_bytes": self.MAX_INGEST_BYTES_WITHOUT_OVERRIDE,
            "host_free_disk_gb": free_gb,
        }

    def ingest_security_advisory(self, item: dict[str, Any]) -> dict[str, Any]:
        raw_size = len(str(item).encode("utf-8"))
        budget = self.check_storage_budget_before_ingest(raw_size)
        if not budget["permitted"]:
            return {"ok": False, "status": "blocked_by_storage_budget", "budget": budget}

        dos = dict(item.get("dossier") or {})
        for field_name in RESEARCH_EPISTEMIC_8_FIELDS:
            dos.setdefault(field_name, [] if field_name != "published_information" else "")

        saved = self.db.upsert_cyber_research_dossier(
            {
                "id": item.get("id") or f"cdos-{str(item.get('identifier') or 'adv').lower()}",
                "identifier": item.get("identifier") or "ADVISORY",
                "title": item.get("title") or "Security Advisory",
                "cvss_score": item.get("cvss_score"),
                "cwe_id": item.get("cwe_id") or "",
                "dossier": dos,
                "sources": item.get("sources") or [],
                "confidence": float(item.get("confidence", 0.9)),
            }
        )
        if self.knowledge_store is not None:
            try:
                self.knowledge_store.index_text(
                    f"cyber_kb:{saved['identifier']}",
                    f"{saved['identifier']} {saved['title']}\n{dos.get('published_information', '')}",
                    source="cyber_security_kb",
                    metadata={"cwe": saved["cwe_id"], "cvss": saved["cvss_score"]},
                )
            except Exception:
                pass
        return {"ok": True, "record": saved}

    def research_vulnerability(self, query_or_cve: str, *, patch_diff_text: str = "") -> dict[str, Any]:
        """§209 Research a published vulnerability/CWE with 8-way epistemic separation and patch-diff inspection."""
        q_low = (query_or_cve or "").strip().lower()
        for bad in PROHIBITED_EXPLOIT_REQUEST_TERMS:
            if bad in q_low:
                return {
                    "ok": False,
                    "status": "refused_weaponized_or_destructive_request",
                    "reason": "DEV's Vulnerability Research Workbench strictly supports defensive validation, root-cause analysis, and remediation—never weaponized exploits or credential theft (§209).",
                }

        self.ensure_baseline_knowledge()
        matches = self.db.list_cyber_research_dossiers(query=query_or_cve.strip(), limit=10)

        diff_summary: dict[str, Any] = {}
        if patch_diff_text.strip():
            added = [ln[1:].strip() for ln in patch_diff_text.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
            removed = [ln[1:].strip() for ln in patch_diff_text.splitlines() if ln.startswith("-") and not ln.startswith("---")]
            diff_summary = {
                "added_lines_count": len(added),
                "removed_lines_count": len(removed),
                "security_controls_added": [
                    ln for ln in added if any(tok in ln for tok in ("safe_load", "?", "hmac.compare_digest", "len(", "check"))
                ][:10],
            }

        primary = matches[0] if matches else {
            "identifier": query_or_cve.strip().upper(),
            "title": f"Structured Research Workspace Entry: {query_or_cve.strip()}",
            "cvss_score": None,
            "cwe_id": "",
            "confidence": 0.6,
            "sources": [{"name": "NVD / Debian Security Tracker reference", "url": "https://security-tracker.debian.org/"}],
            "dossier": {
                "published_information": "No cached offline advisory body; verify exact package backport status via official distro tracker.",
                "confirmed_affected_versions": [],
                "suspected_affected_versions": [],
                "available_patches": [],
                "public_test_evidence": [],
                "unverified_claims": ["Treat uncorroborated third-party PoC claims as unverified until reproduced in an isolated lab."],
                "mitigations": ["Check `apt-cache policy` and official vendor security advisories."],
                "remaining_uncertainties": ["Requires live vendor advisory correlation for exact version range."],
            },
        }
        return {
            "ok": True,
            "query": query_or_cve,
            "epistemic_fields_enforced": list(RESEARCH_EPISTEMIC_8_FIELDS),
            "weaponized_exploit_generated": False,
            "primary_dossier": primary,
            "related_dossiers_count": len(matches),
            "patch_diff_analysis": diff_summary,
        }


class ReverseEngineeringAndForensicsLab:
    """§210 Static Binary/APK/Artifact Inspection & Chain-of-Custody Forensics (NEVER executes samples)."""

    NEVER_EXECUTE_SUSPICIOUS_SAMPLES = True

    RE_AND_FORENSIC_TOOLS: tuple[str, ...] = (
        "ghidra",
        "radare2",
        "r2",
        "yara",
        "vol",
        "volatility3",
        "binwalk",
        "strings",
        "file",
        "readelf",
        "objdump",
        "clamscan",
        "apktool",
    )

    STATIC_SIGNATURE_RULES: tuple[tuple[str, str, re.Pattern[bytes]], ...] = (
        ("suspicious_shell_pipeline", "medium", re.compile(rb"(curl|wget)\s+https?://[^\s]+\s*\|\s*(ba)?sh")),
        ("encoded_exec_stage", "medium", re.compile(rb"base64\s+-d\b|exec\(\s*base64\.b64decode")),
        ("proc_mem_or_ptrace_ref", "low", re.compile(rb"/proc/self/mem|PTRACE_POKETEXT")),
        ("embedded_private_key_marker", "medium", re.compile(rb"BEGIN [A-Z ]*PRIVATE KEY")),
    )

    def __init__(self, *, workspace_dir: Path):
        self.workspace_dir = workspace_dir

    def inventory_re_and_forensic_tools(self) -> dict[str, Any]:
        installed = {cmd: shutil.which(cmd) for cmd in self.RE_AND_FORENSIC_TOOLS if shutil.which(cmd)}
        missing = [cmd for cmd in self.RE_AND_FORENSIC_TOOLS if not shutil.which(cmd)]
        return {"installed": installed, "unavailable": missing}

    def inspect_sample_statically(self, sample_path: Path | str) -> dict[str, Any]:
        """§210 & §220.9 Static file identification, SHA-256/512 hashing, metadata, strings & rule classification."""
        src = Path(sample_path).resolve()
        if not src.is_file():
            raise FileNotFoundError(f"Sample file not found: {src}")

        raw = src.read_bytes()
        sha256_before = hashlib.sha256(raw).hexdigest()
        sha512_before = hashlib.sha512(raw).hexdigest()

        file_kind, format_metadata = self._identify_magic_and_metadata(src, raw)
        ascii_strings = [m.group(0).decode("ascii", errors="ignore") for m in re.finditer(rb"[ -~]{5,120}", raw[:262_144])][:60]

        rule_matches: list[dict[str, str]] = []
        for rule_id, sev, pat in self.STATIC_SIGNATURE_RULES:
            if pat.search(raw):
                rule_matches.append({"rule_id": rule_id, "severity": sev})

        # Verify original file was preserved bit-for-bit untouched (§210)!
        sha256_after = hashlib.sha256(src.read_bytes()).hexdigest()

        return {
            "ok": True,
            "sample_path": str(src),
            "executed_on_host": False,
            "original_evidence_preserved": sha256_before == sha256_after,
            "size_bytes": len(raw),
            "hashes": {"sha256": sha256_before, "sha512": sha512_before},
            "file_type": file_kind,
            "format_metadata": format_metadata,
            "printable_strings_sample": ascii_strings[:25],
            "rule_classifications": rule_matches,
            "transformations_log": ["read_only_memory_buffer_inspection"],
            "uncertainties": [
                "Static analysis inspects on-disk bytes and headers only; runtime dynamic behavior is intentionally not executed on the host."
            ],
        }

    @staticmethod
    def _identify_magic_and_metadata(path: Path, raw: bytes) -> tuple[str, dict[str, Any]]:
        if raw.startswith(b"\x7fELF") and len(raw) >= 20:
            ei_class = "ELF64" if raw[4] == 2 else "ELF32"
            endian = "<" if raw[5] == 1 else ">"
            e_type, e_machine = struct.unpack(f"{endian}HH", raw[16:20])
            return "ELF_executable_or_shared_object", {"class": ei_class, "e_type": e_type, "e_machine": e_machine}
        if raw.startswith(b"MZ"):
            return "PE_windows_binary", {"mz_header": True}
        if raw.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    names = zf.namelist()
                    is_apk = "AndroidManifest.xml" in names or any(n.endswith(".dex") for n in names)
                    return ("Android_APK_archive" if is_apk else "ZIP_archive"), {"entry_count": len(names), "sample_entries": names[:15]}
            except zipfile.BadZipFile:
                return "corrupted_zip_container", {}
        if raw.startswith(b"%PDF-"):
            return "PDF_document", {"header": raw[:8].decode("ascii", errors="ignore")}
        if raw.startswith(b"SQLite format 3\x00"):
            return "SQLite3_database", {}
        if raw.startswith(b"#!"):
            shebang = raw.splitlines()[0][:80].decode("utf-8", errors="replace")
            return "script_text_executable", {"interpreter": shebang}
        return "generic_binary_or_text_artifact", {"extension": path.suffix}


class WirelessAndHardwareSecurityLab:
    """§211 Wireless, Bluetooth, USB & Driver Security Inspection (never conflating CLI presence with hardware support)."""

    CLAIM_HARDWARE_FEATURE_FROM_CLI_ALONE = False

    def __init__(self, *, system_model: KaliSystemKnowledgeModel):
        self.system_model = system_model

    def assess_wireless_and_hardware_capabilities(self) -> dict[str, Any]:
        """§211 Inspect physical wireless/Bluetooth/USB adapters vs installed CLI utilities truthfully."""
        env = self.system_model.get_or_refresh_model()["model"]
        net_ifaces = env["network_interfaces"]
        wireless_adapters: list[dict[str, Any]] = []

        for iface in net_ifaces:
            name = iface["name"]
            if iface.get("wireless"):
                drv_link = Path(f"/sys/class/net/{name}/device/driver")
                driver_name = drv_link.resolve().name if drv_link.exists() else "unknown"
                wireless_adapters.append(
                    {
                        "interface": name,
                        "operstate": iface["operstate"],
                        "driver": driver_name,
                        "physical_80211_present": True,
                    }
                )

        cli_tools = {
            cmd: bool(shutil.which(cmd))
            for cmd in ("iw", "rfkill", "aircrack-ng", "bluetoothctl", "lsusb", "lspci")
        }
        monitor_mode_hw_verified = False
        if wireless_adapters and cli_tools["iw"]:
            rc, out, _ = _run_probe(["iw", "list"], timeout=2.5)
            monitor_mode_hw_verified = rc == 0 and "* monitor" in out

        usb_devices_count = len(list(Path("/sys/bus/usb/devices").iterdir())) if Path("/sys/bus/usb/devices").is_dir() else 0

        return {
            "cli_utilities_present": cli_tools,
            "physical_wireless_adapters": wireless_adapters,
            "bluetooth_sysfs_present": Path("/sys/class/bluetooth").is_dir(),
            "usb_sysfs_entries": usb_devices_count,
            "monitor_mode_hardware_supported": monitor_mode_hw_verified,
            "hardware_capability_note": (
                "Verified physical 802.11 monitor capability via `iw list`."
                if monitor_mode_hw_verified
                else "No monitor-capable physical 802.11 adapter verified on this host (CLI tools alone do not imply wireless hardware support)."
            ),
        }


class IncidentResponseAssistant:
    """§212 Local DFIR Assistant: log triage, timeline builder, evidence preservation & policy-gated containment."""

    AUTO_DELETE_OR_KILL_WITHOUT_POLICY = False

    def __init__(self, *, db: Database, workspace_dir: Path):
        self.db = db
        self.workspace_dir = workspace_dir

    def investigate_incident(
        self,
        *,
        title: str,
        log_lines: list[str],
        baseline_Snapshot: dict[str, Any] | None = None,
        current_snapshot: dict[str, Any] | None = None,
        artifact_paths_to_preserve: list[str] | None = None,
        auto_containment_policy_approved: bool = False,
    ) -> dict[str, Any]:
        """§212 Separate confirmed evidence from suspected activity, preserve evidence, and build 6-phase checklist."""
        confirmed_evidence: list[dict[str, Any]] = []
        suspected_activity: list[dict[str, Any]] = []
        timeline: list[dict[str, Any]] = []

        for idx, raw_ln in enumerate(log_lines, start=1):
            ln = raw_ln.strip()
            if not ln:
                continue
            ts_match = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)", ln)
            ts = ts_match.group(1) if ts_match else f"line-{idx:04d}"

            if any(tok in ln.lower() for tok in ("accepted publickey", "sudo:", "authentication failure", "failed password", "checksum mismatch")):
                entry = {"timestamp": ts, "line": idx, "event": ln[:300], "classification": "confirmed_log_record"}
                confirmed_evidence.append(entry)
                timeline.append(entry)
            elif any(tok in ln.lower() for tok in ("unusual", "anomaly", "unexpected", "connection reset", "unknown user")):
                entry = {"timestamp": ts, "line": idx, "event": ln[:300], "classification": "suspected_requires_corroboration"}
                suspected_activity.append(entry)
                timeline.append(entry)

        # Baseline comparison (§212)
        if baseline_Snapshot and current_snapshot:
            for key in sorted(set(baseline_Snapshot) | set(current_snapshot)):
                if baseline_Snapshot.get(key) != current_snapshot.get(key):
                    confirmed_evidence.append(
                        {
                            "timestamp": utc_now(),
                            "event": f"Baseline drift on `{key}`: baseline={baseline_Snapshot.get(key)!r} -> current={current_snapshot.get(key)!r}",
                            "classification": "confirmed_baseline_drift",
                        }
                    )

        # Forensic evidence preservation (`0400` read-only copies + SHA-256)
        preserved: list[dict[str, Any]] = []
        vault_dir = self.workspace_dir / "forensic_preservation"
        for raw_p in artifact_paths_to_preserve or []:
            src = Path(raw_p).resolve()
            if not src.is_file():
                continue
            vault_dir.mkdir(parents=True, exist_ok=True)
            data = src.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            dest = vault_dir / f"{digest[:16]}_{src.name}.evidence"
            if not dest.exists():
                dest.write_bytes(data)
                os.chmod(dest, 0o400)
            preserved.append({"source": str(src), "preserved_copy": str(dest), "sha256": digest, "mode": "0400"})

        checklist = {
            "1_investigation": ["Review chronological timeline", "Correlate process, socket, and authentication logs"],
            "2_containment": ["Isolate affected service/credentials only with explicit operator/policy approval"],
            "3_preservation": [f"Preserved {len(preserved)} read-only SHA-256 forensic artifact(s)"],
            "4_remediation": ["Patch root-cause configuration or vulnerable dependency and rotate affected secrets"],
            "5_recovery": ["Restore from verified clean baseline and monitor post-recovery telemetry"],
            "6_lessons_learned": ["Convert confirmed IOC/log pattern into recurring regression & detection rule"],
        }

        severity = "high" if len(confirmed_evidence) >= 2 else ("medium" if confirmed_evidence or suspected_activity else "low")
        saved = self.db.upsert_cyber_incident_case(
            {
                "title": title,
                "severity": severity,
                "status": "investigating",
                "confirmed_evidence": confirmed_evidence,
                "suspected_activity": suspected_activity,
                "timeline": timeline,
                "checklist": checklist,
                "preserved_artifacts": preserved,
            }
        )
        return {
            "ok": True,
            "case": saved,
            "files_deleted_automatically": 0,
            "processes_terminated_automatically": 0,
            "response_policy_authorized_destructive_action": bool(auto_containment_policy_approved),
        }
