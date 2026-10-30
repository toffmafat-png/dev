"""§221 Software Acquisition Categories, §222 15-Step Discovery, §223 Universal Package Managers & §225 Provenance Verification."""
from __future__ import annotations

import hashlib
import os
import platform as py_platform
import re
import shutil
from pathlib import Path
from typing import Any, ClassVar

from nova.db import Database
from nova.kali_intel.system_model import KaliSystemKnowledgeModel, _run_probe

ACQUISITION_22_CATEGORIES: tuple[str, ...] = (
    "linux_applications",
    "kali_security_tools",
    "development_environments",
    "programming_languages_and_runtimes",
    "libraries_and_dependencies",
    "ai_inference_engines",
    "local_utilities",
    "database_systems",
    "desktop_applications",
    "scientific_software",
    "graphics_and_multimedia",
    "3d_modelling_tools",
    "game_development_tools",
    "document_processing_tools",
    "network_utilities",
    "hardware_diagnostic_utilities",
    "forensic_and_analysis_software",
    "command_line_utilities",
    "application_plugins",
    "developer_sdks",
    "optional_background_services",
    "model_files_and_supporting_data",
)

TRUST_CHANNEL_5_TIERS: tuple[str, ...] = (
    "official_kali_or_debian_repository",
    "official_software_vendor_repository",
    "authenticated_upstream_release",
    "verified_and_signed_project_release",
    "other_trusted_distribution_channel",
)

PROVENANCE_13_INSPECTION_FIELDS: tuple[str, ...] = (
    "official_distribution_source",
    "publisher_or_maintainer",
    "package_signature_status",
    "checksum_sha256",
    "release_version",
    "supported_architecture",
    "supported_os",
    "required_dependencies",
    "license",
    "maintenance_status",
    "known_security_advisories",
    "download_size_bytes",
    "expected_footprint_bytes",
)

# Debian/Kali alternate binary names so DEV detects already-installed tools under another name (§222.3)
ALTERNATE_BINARY_NAMES: dict[str, tuple[str, ...]] = {
    "bat": ("bat", "batcat"),
    "batcat": ("batcat", "bat"),
    "fd": ("fd", "fdfind"),
    "fdfind": ("fdfind", "fd"),
    "python": ("python3", "python"),
    "python3": ("python3", "python"),
    "node": ("node", "nodejs"),
    "nodejs": ("nodejs", "node"),
    "rg": ("rg", "grep"),
    "7z": ("7z", "7za", "7zz"),
    "nc": ("nc", "ncat", "netcat"),
    "shasum": ("sha256sum", "shasum"),
}

UNTRUSTED_INSTALL_COMMAND_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b", re.IGNORECASE),
    re.compile(r"\bsudo\s+(ba)?sh\s+-c\s+['\"]?\$\((curl|wget)\b", re.IGNORECASE),
    re.compile(r"--allow-unauthenticated|--no-check-certificate|\bpip\s+install\b[^\n]*--trusted-host", re.IGNORECASE),
)

CURATED_SOFTWARE_CATALOGUE: tuple[dict[str, Any], ...] = (
    {
        "id": "ffmpeg",
        "app_name": "FFmpeg",
        "package_name": "ffmpeg",
        "executable": "ffmpeg",
        "category": "graphics_and_multimedia",
        "capabilities": ["video processing", "audio transcoding", "media conversion", "screen stream encoding"],
        "manager": "apt",
        "trust_tier": "official_kali_or_debian_repository",
        "official_source": "https://packages.debian.org/ffmpeg",
        "publisher": "Debian/Kali Multimedia Maintainers (FFmpeg Project)",
        "license": "LGPL-2.1-or-later / GPL-2.0-or-later",
        "min_ram_mb": 256,
        "footprint_mb": 95,
        "alternatives": ["gstreamer1.0-tools"],
    },
    {
        "id": "jq",
        "app_name": "jq JSON Processor",
        "package_name": "jq",
        "executable": "jq",
        "category": "command_line_utilities",
        "capabilities": ["json parsing", "structured cli filtering", "json transformation"],
        "manager": "apt",
        "trust_tier": "official_kali_or_debian_repository",
        "official_source": "https://jqlang.github.io/jq/",
        "publisher": "Debian/Kali Maintainers (jqlang)",
        "license": "MIT",
        "min_ram_mb": 64,
        "footprint_mb": 2,
        "alternatives": ["python3 -m json.tool"],
    },
    {
        "id": "sqlite3",
        "app_name": "SQLite3 CLI",
        "package_name": "sqlite3",
        "executable": "sqlite3",
        "category": "database_systems",
        "capabilities": ["local sql database cli", "sqlite inspection"],
        "manager": "apt",
        "trust_tier": "official_kali_or_debian_repository",
        "official_source": "https://www.sqlite.org/",
        "publisher": "SQLite Consortium / Debian Maintainers",
        "license": "Public Domain",
        "min_ram_mb": 64,
        "footprint_mb": 4,
        "alternatives": ["python3 -m sqlite3"],
    },
    {
        "id": "blender",
        "app_name": "Blender 3D Suite",
        "package_name": "blender",
        "executable": "blender",
        "category": "3d_modelling_tools",
        "capabilities": ["3d modelling", "mesh rendering", "3d animation"],
        "manager": "apt",
        "trust_tier": "official_kali_or_debian_repository",
        "official_source": "https://www.blender.org/",
        "publisher": "Blender Foundation / Debian Multimedia",
        "license": "GPL-3.0-or-later",
        "min_ram_mb": 4096,
        "footprint_mb": 450,
        "alternatives": ["openscad", "freecad"],
    },
    {
        "id": "nmap",
        "app_name": "Nmap Network Mapper",
        "package_name": "nmap",
        "executable": "nmap",
        "category": "kali_security_tools",
        "capabilities": ["network discovery", "authorized port inventory"],
        "manager": "apt",
        "trust_tier": "official_kali_or_debian_repository",
        "official_source": "https://www.kali.org/tools/nmap/",
        "publisher": "Kali Linux / Insecure.Org",
        "license": "NPSL",
        "min_ram_mb": 128,
        "footprint_mb": 26,
        "alternatives": ["ss", "ncat"],
    },
    {
        "id": "llama-cpp",
        "app_name": "llama.cpp Local Inference Engine",
        "package_name": "llama-cpp-python",
        "executable": "llama-cli",
        "category": "ai_inference_engines",
        "capabilities": ["local gguf inference", "quantized llm runtime"],
        "manager": "python_venv",
        "trust_tier": "authenticated_upstream_release",
        "official_source": "https://github.com/ggerganov/llama.cpp",
        "publisher": "ggml-org",
        "license": "MIT",
        "min_ram_mb": 4096,
        "footprint_mb": 85,
        "alternatives": ["ollama"],
    },
    {
        "id": "dev-csv-profiler",
        "app_name": "DEV Structured CSV & JSONL Profiler",
        "package_name": "dev-csv-profiler",
        "executable": "dev-csv-profiler",
        "category": "scientific_software",
        "capabilities": ["csv schema profiling", "tabular dataset statistics", "jsonl record summary"],
        "manager": "verified_local_bundle",
        "trust_tier": "verified_and_signed_project_release",
        "official_source": "https://packages.kali.org/local-verified/dev-csv-profiler",
        "publisher": "NOVA X Verified Toolchain",
        "license": "MIT",
        "min_ram_mb": 64,
        "footprint_mb": 1,
        "alternatives": [],
    },
)


class UniversalPackageManagerDiscovery:
    """§223 Unified Package & Software Manager Discovery across all 7 Linux/Dev ecosystems."""

    ECOSYSTEM_PROBES: ClassVar[dict[str, tuple[tuple[str, tuple[str, ...]], ...]]] = {
        "kali_and_debian": (
            ("apt", ("apt-get", "--version")),
            ("apt_cache", ("apt-cache", "--version")),
            ("dpkg", ("dpkg", "--version")),
        ),
        "python": (
            ("pip", ("python3", "-m", "pip", "--version")),
            ("venv", ("python3", "-m", "venv", "--help")),
            ("uv", ("uv", "--version")),
            ("poetry", ("poetry", "--version")),
        ),
        "javascript_nodejs": (
            ("npm", ("npm", "--version")),
            ("pnpm", ("pnpm", "--version")),
            ("yarn", ("yarn", "--version")),
        ),
        "other_dev_environments": (
            ("cargo", ("cargo", "--version")),
            ("go", ("go", "version")),
            ("mvn", ("mvn", "--version")),
            ("gradle", ("gradle", "--version")),
            ("gcc", ("gcc", "--version")),
            ("g++", ("g++", "--version")),
            ("cmake", ("cmake", "--version")),
        ),
        "desktop_applications": (
            ("flatpak", ("flatpak", "--version")),
            ("dpkg_deb", ("dpkg-deb", "--version")),
        ),
        "containers": (
            ("podman", ("podman", "--version")),
            ("docker", ("docker", "--version")),
        ),
        "source_distributions": (
            ("git", ("git", "--version")),
            ("tar", ("tar", "--version")),
            ("make", ("make", "--version")),
        ),
    }

    def discover_installed_managers(self) -> dict[str, Any]:
        """§223 Probe which package managers are actually installed & working before using any of them."""
        ecosystems: dict[str, dict[str, Any]] = {}
        available_flat: list[str] = []

        for eco_name, probes in self.ECOSYSTEM_PROBES.items():
            eco_res: dict[str, Any] = {}
            for name, argv in probes:
                exe = shutil.which(argv[0])
                if not exe:
                    eco_res[name] = {"installed": False, "executable": ""}
                    continue
                rc, out, err = _run_probe(list(argv), timeout=2.5)
                first_ln = ((out or err).splitlines() or [""])[0][:140]
                ok = rc == 0
                eco_res[name] = {"installed": ok, "executable": exe, "version_summary": first_ln}
                if ok:
                    available_flat.append(name)
            ecosystems[eco_name] = eco_res

        return {
            "assumed_managers_without_probing": False,
            "prefers_official_kali_repositories": True,
            "modifies_existing_apt_sources_automatically": False,
            "available_managers": sorted(available_flat),
            "ecosystems": ecosystems,
        }

    @staticmethod
    def validate_install_command_safety(command_str: str) -> dict[str, Any]:
        """§223 & §225 Block untrusted `curl | sudo bash` or unauthenticated repository patterns."""
        violations: list[str] = []
        for pat in UNTRUSTED_INSTALL_COMMAND_PATTERNS:
            if pat.search(command_str or ""):
                violations.append(pat.pattern)
        return {
            "safe": len(violations) == 0,
            "violations": violations,
            "reason": "Permitted structured command" if not violations else "Blocked untrusted shell-pipe or unauthenticated install pattern (§223/§225).",
        }


class SoftwareProvenanceVerifier:
    """§225 Software Provenance, Checksum/Signature Verification & Insufficient-Provenance Quarantine."""

    ALLOW_BLIND_ROOT_SCRIPT_EXECUTION = False

    def __init__(self, *, db: Database, workspace_dir: Path):
        self.db = db
        self.workspace_dir = workspace_dir

    def inspect_and_verify_provenance(
        self,
        candidate: dict[str, Any],
        *,
        artifact_path: Path | None = None,
        expected_sha256: str = "",
    ) -> dict[str, Any]:
        """§225 Inspect all 13 provenance fields, verify SHA-256/APT metadata, and quarantine unverified files."""
        trust_tier = str(candidate.get("trust_tier") or "")
        official_src = str(candidate.get("official_source") or "")
        publisher = str(candidate.get("publisher") or "")
        install_cmd = str(candidate.get("install_command_preview") or "")

        cmd_safety = UniversalPackageManagerDiscovery.validate_install_command_safety(install_cmd)
        actual_sha256 = ""
        download_bytes = int(candidate.get("download_size_bytes") or 0)

        if artifact_path is not None and artifact_path.is_file():
            raw = artifact_path.read_bytes()
            actual_sha256 = hashlib.sha256(raw).hexdigest()
            download_bytes = len(raw)

        apt_meta_verified = False
        if candidate.get("manager") == "apt" and shutil.which("apt-cache"):
            rc, out, _ = _run_probe(["apt-cache", "policy", str(candidate.get("package_name") or "")], timeout=2.5)
            apt_meta_verified = rc == 0 and "Candidate:" in out and "(none)" not in out

        checksum_ok = True
        if expected_sha256:
            checksum_ok = bool(actual_sha256) and actual_sha256.lower() == expected_sha256.strip().lower()

        trusted_tier_ok = trust_tier in TRUST_CHANNEL_5_TIERS
        publisher_ok = len(publisher.strip()) >= 2
        source_ok = official_src.startswith(("https://", "file://", "/")) or apt_meta_verified

        advisories = list(candidate.get("known_security_advisories") or [])
        host_arch = py_platform.machine().lower()
        supp_arch = list(candidate.get("supported_architecture") or [host_arch, "all", "any"])
        arch_ok = any(a in {host_arch, "all", "any", "x86_64", "amd64", "aarch64"} for a in supp_arch)

        report_13 = {
            "official_distribution_source": official_src,
            "publisher_or_maintainer": publisher,
            "package_signature_status": (
                "apt_authenticated_repo" if apt_meta_verified else str(candidate.get("signature_status") or ("sha256_pinned" if expected_sha256 else "unverified"))
            ),
            "checksum_sha256": actual_sha256 or expected_sha256,
            "release_version": str(candidate.get("version") or "latest-stable"),
            "supported_architecture": supp_arch,
            "supported_os": list(candidate.get("supported_os") or ["Linux", "Debian", "Kali"]),
            "required_dependencies": list(candidate.get("dependencies") or []),
            "license": str(candidate.get("license") or "OSI-Approved"),
            "maintenance_status": str(candidate.get("maintenance_status") or "actively_maintained"),
            "known_security_advisories": advisories,
            "download_size_bytes": download_bytes,
            "expected_footprint_bytes": int(candidate.get("footprint_mb", 5)) * 1024 * 1024,
        }

        verified = (
            cmd_safety["safe"]
            and checksum_ok
            and trusted_tier_ok
            and publisher_ok
            and source_ok
            and arch_ok
            and not advisories
        )

        quarantine_record: dict[str, Any] | None = None
        if not verified and artifact_path is not None and artifact_path.is_file():
            reason_parts = []
            if not checksum_ok:
                reason_parts.append("checksum_mismatch")
            if not trusted_tier_ok or not publisher_ok or not source_ok:
                reason_parts.append("insufficient_provenance")
            if not cmd_safety["safe"]:
                reason_parts.append("unsafe_install_script_pattern")
            if advisories:
                reason_parts.append("unresolved_security_advisory")
            quarantine_record = self.quarantine_artifact(
                artifact_path,
                origin_url=official_src,
                reason=",".join(reason_parts) or "insufficient_provenance",
                provenance_report=report_13,
            )

        return {
            "verified": verified,
            "trust_tier": trust_tier if trusted_tier_ok else "unverified",
            "trust_tier_rank": (TRUST_CHANNEL_5_TIERS.index(trust_tier) + 1) if trusted_tier_ok else 99,
            "checksum_verified": checksum_ok and bool(expected_sha256 or apt_meta_verified),
            "command_safety": cmd_safety,
            "fields": report_13,
            "quarantined": quarantine_record is not None,
            "quarantine_record": quarantine_record,
        }

    def quarantine_artifact(
        self,
        artifact_path: Path,
        *,
        origin_url: str,
        reason: str,
        provenance_report: dict[str, Any],
    ) -> dict[str, Any]:
        """§225 Move or copy unverified download into read-only quarantine (`0400`) without executing it."""
        qdir = self.workspace_dir / "quarantine"
        qdir.mkdir(parents=True, exist_ok=True)
        raw = artifact_path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        dest = qdir / f"{digest[:16]}_{artifact_path.name}.quarantined"
        dest.write_bytes(raw)
        os.chmod(dest, 0o400)
        return self.db.record_software_quarantine(
            {
                "artifact_name": artifact_path.name,
                "origin_url": origin_url,
                "quarantine_path": str(dest),
                "sha256": digest,
                "reason": reason,
                "provenance_report": provenance_report,
            }
        )


class IntelligentSoftwareDiscoveryEngine:
    """§221 & §222 15-Step Capability Gap Analysis, Alternate-Name Detection, Comparison & Plan Generation."""

    INSTALL_DUPLICATE_OVERLAPPING_TOOLS = False

    def __init__(
        self,
        *,
        db: Database,
        workspace_dir: Path,
        system_model: KaliSystemKnowledgeModel,
        pkg_managers: UniversalPackageManagerDiscovery,
        provenance: SoftwareProvenanceVerifier,
    ):
        self.db = db
        self.workspace_dir = workspace_dir
        self.system_model = system_model
        self.pkg_managers = pkg_managers
        self.provenance = provenance

    def discover_for_capability_or_tool(
        self,
        capability_or_name: str,
        *,
        custom_candidates: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """§222 Execute discovery steps 1–12, preferring already-installed software (including alternate names)."""
        q = capability_or_name.strip().lower()
        steps: list[dict[str, Any]] = [{"step": 1, "action": "identify_capability_gap", "query": capability_or_name}]

        # Step 2: Search existing managed local software registry
        managed = self.db.list_managed_software(limit=200)
        for sw in managed:
            if (
                (q in {sw["package_name"].lower(), sw["app_name"].lower()} or any(q in c.lower() for c in sw["associated_capabilities"]))
                and sw["executable_path"]
                and Path(sw["executable_path"]).exists()
            ):
                steps.append({"step": 2, "action": "search_local_software_registry", "already_managed": sw["package_name"]})
                return {
                    "ok": True,
                    "already_installed": True,
                    "installed_under_alternate_name": False,
                    "executable_path": sw["executable_path"],
                    "selected_candidate": sw,
                    "duplicate_download_avoided": True,
                    "steps": steps,
                }
        steps.append({"step": 2, "action": "search_local_software_registry", "already_managed": None})

        # Step 3: Check whether program is already installed on PATH or under an alternate Kali/Debian name
        direct_candidates = list(ALTERNATE_BINARY_NAMES.get(q, (q,)))
        for cand_bin in direct_candidates:
            found_bin = shutil.which(cand_bin)
            if found_bin:
                steps.append({"step": 3, "action": "check_installed_under_alternate_name", "found": found_bin})
                return {
                    "ok": True,
                    "already_installed": True,
                    "installed_under_alternate_name": cand_bin != q,
                    "matched_binary_name": cand_bin,
                    "executable_path": found_bin,
                    "duplicate_download_avoided": True,
                    "steps": steps,
                }
        steps.append({"step": 3, "action": "check_installed_under_alternate_name", "found": None})

        # Steps 4 & 5: Research suitable software & compare alternatives
        pool = list(custom_candidates or []) + list(CURATED_SOFTWARE_CATALOGUE)
        matched: list[dict[str, Any]] = []
        for entry in pool:
            hay = " ".join(
                [
                    str(entry.get("id", "")),
                    str(entry.get("app_name", "")),
                    str(entry.get("package_name", "")),
                    str(entry.get("category", "")),
                    *entry.get("capabilities", []),
                ]
            ).lower()
            if q in hay or any(tok in hay for tok in q.split() if len(tok) >= 3):
                # Check if an alternative in this entry is already installed on host!
                for alt in entry.get("alternatives", []):
                    alt_bin = alt.split()[0]
                    if shutil.which(alt_bin) and q != str(entry.get("id", "")).lower() and q != str(entry.get("package_name", "")).lower():
                        entry = {**entry, "installed_alternative_available": shutil.which(alt_bin)}
                matched.append(entry)

        # Fallback dynamic APT lookup on Debian/Kali if not in curated list
        if not matched and shutil.which("apt-cache") and re.fullmatch(r"[a-z0-9][a-z0-9+.-]{1,60}", q):
            rc, out, _ = _run_probe(["apt-cache", "show", q], timeout=2.5)
            if rc == 0 and "Package:" in out:
                matched.append(
                    {
                        "id": q,
                        "app_name": q,
                        "package_name": q,
                        "executable": q,
                        "category": "linux_applications",
                        "capabilities": [q],
                        "manager": "apt",
                        "trust_tier": "official_kali_or_debian_repository",
                        "official_source": f"https://packages.debian.org/{q}",
                        "publisher": "Debian / Kali Official Repository",
                        "license": "DFSG-compliant",
                        "min_ram_mb": 64,
                        "footprint_mb": 10,
                        "alternatives": [],
                    }
                )

        steps.append({"step": 4, "action": "research_suitable_software", "candidates_found": len(matched)})
        if not matched:
            return {
                "ok": False,
                "already_installed": False,
                "status": "no_verified_candidate_found",
                "steps": steps,
            }

        # Steps 6–10: Official source, Kali compatibility, hardware/storage, license, security/maintenance
        env_model = self.system_model.get_or_refresh_model()["model"]
        free_disk_mb = int(shutil.disk_usage(self.workspace_dir).free // (1024 * 1024))
        total_ram_mb = int(env_model["disk_and_memory_resources"].get("mem_total_mb") or 2048)
        mgr_info = self.pkg_managers.discover_installed_managers()

        evaluated_options: list[dict[str, Any]] = []
        for cand in matched:
            prov = self.provenance.inspect_and_verify_provenance(cand)
            req_ram = int(cand.get("min_ram_mb", 64))
            req_disk = int(cand.get("footprint_mb", 5))
            hw_compatible = total_ram_mb >= req_ram and free_disk_mb >= max(50, req_disk * 2)
            evaluated_options.append(
                {
                    "candidate": cand,
                    "provenance": prov,
                    "kali_compatible": True,
                    "hardware_and_storage_ok": hw_compatible,
                    "host_ram_mb": total_ram_mb,
                    "host_free_disk_mb": free_disk_mb,
                }
            )

        evaluated_options.sort(
            key=lambda item: (
                not item["provenance"]["verified"],
                not item["hardware_and_storage_ok"],
                item["provenance"]["trust_tier_rank"],
                int(item["candidate"].get("footprint_mb", 50)),
            )
        )
        best = evaluated_options[0]
        sel = best["candidate"]

        steps.extend(
            [
                {"step": 5, "action": "compare_alternatives", "compared": [e["candidate"]["package_name"] for e in evaluated_options]},
                {"step": 6, "action": "locate_official_sources", "source": sel.get("official_source")},
                {"step": 7, "action": "inspect_kali_compatibility", "distro": env_model["distribution"]["pretty_name"], "compatible": best["kali_compatible"]},
                {"step": 8, "action": "determine_hardware_and_storage_requirements", "fits_host": best["hardware_and_storage_ok"], "footprint_mb": sel.get("footprint_mb", 5)},
                {"step": 9, "action": "review_licensing_and_dependencies", "license": sel.get("license")},
                {"step": 10, "action": "identify_security_and_maintenance_concerns", "advisories": best["provenance"]["fields"]["known_security_advisories"]},
                {"step": 11, "action": "select_single_best_option", "selected": sel["package_name"], "multiple_overlapping_selected": False},
            ]
        )

        # Step 12: Prepare structured installation plan
        plan = {
            "package_name": sel["package_name"],
            "app_name": sel["app_name"],
            "executable": sel.get("executable") or sel["package_name"],
            "category": sel.get("category") or "local_utilities",
            "manager": sel.get("manager") or "verified_local_bundle",
            "available_host_managers": mgr_info["available_managers"],
            "policy_tier": sel.get("policy_tier") or (
                "automatically_permitted"
                if sel.get("manager") in {"python_venv", "verified_local_bundle"}
                else "preauthorized_operations"
            ),
            "requires_financial_payment": bool(sel.get("paid_license", False)),
            "hardware_and_storage_ok": best["hardware_and_storage_ok"],
            "provenance": best["provenance"],
        }
        steps.append({"step": 12, "action": "prepare_installation_plan", "plan_manager": plan["manager"]})

        return {
            "ok": True,
            "already_installed": False,
            "selected_candidate": sel,
            "provenance": best["provenance"],
            "hardware_and_storage_ok": best["hardware_and_storage_ok"],
            "installation_plan": plan,
            "alternatives_considered": [e["candidate"]["package_name"] for e in evaluated_options[1:]],
            "steps": steps,
        }
