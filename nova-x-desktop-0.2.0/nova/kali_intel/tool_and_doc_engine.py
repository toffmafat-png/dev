"""§182 Kali Tool Intelligence, §183 13-Step Tool Selection/Execution, §184 5-Priority Docs & §191 Knowledge Engine."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
from pathlib import Path
from typing import Any

from nova.db import Database
from nova.kali_intel.system_model import KaliPackageIntelligence, KaliSystemKnowledgeModel, _run_probe
from nova.knowledge import KnowledgeStore

KALI_TOOLS_CATALOGUE_URL = "https://www.kali.org/tools/all-tools/"

REQUIRED_20_TOOL_PROFILE_FIELDS: tuple[str, ...] = (
    "name",
    "description",
    "purpose",
    "package_information",
    "executable_path",
    "version",
    "installation_status",
    "dependencies",
    "available_help_options",
    "man_page_references",
    "official_documentation",
    "upstream_documentation",
    "configuration_information",
    "supported_input_formats",
    "output_formats",
    "resource_requirements",
    "compatibility_information",
    "permission_requirements",
    "known_limitations",
    "usage_examples",
)

DOC_PRIORITY_TIERS: dict[int, dict[str, Any]] = {
    1: {"label": "official_local_documentation", "reliability": "official_verified", "authoritative": True},
    2: {"label": "official_kali_documentation", "reliability": "official_verified", "authoritative": True},
    3: {"label": "upstream_project_documentation", "reliability": "upstream_verified", "authoritative": True},
    4: {"label": "trusted_educational_resources", "reliability": "curated_educational", "authoritative": True},
    5: {"label": "community_knowledge", "reliability": "community_unverified", "authoritative": False},
}

# Reference metadata aligned with https://www.kali.org/tools/all-tools/ — never treated as installed without live host probe!
REFERENCE_KALI_CATALOGUE: dict[str, dict[str, Any]] = {
    "tcpdump": {
        "category": "sniffing-spoofing",
        "package": "tcpdump",
        "command": "tcpdump",
        "description": "Command-line packet analyzer for capturing and inspecting network traffic.",
        "purpose": "Capture and filter live network packets or read/write libpcap (.pcap) captures.",
        "protocols": ["ethernet", "ipv4", "ipv6", "tcp", "udp", "icmp", "arp", "dns"],
        "hardware": ["network_interface"],
        "inputs": ["pcap", "live_interface"],
        "outputs": ["pcap", "text_stdout"],
        "related": ["tshark", "wireshark", "ss", "ip"],
        "use_cases": ["inspect network traffic", "packet capture", "protocol troubleshooting", "filter tcp port"],
        "permissions": "Reading live interfaces requires CAP_NET_RAW / root; reading existing .pcap files works unprivileged.",
        "limitations": "Does not perform full deep application-layer GUI dissection like Wireshark.",
        "upstream": "https://www.tcpdump.org/",
        "kali_doc": "https://www.kali.org/tools/tcpdump/",
        "examples": ["tcpdump -r capture.pcap -nn -c 20", "tcpdump --version"],
        "ram_mb": 32,
    },
    "wireshark": {
        "category": "sniffing-spoofing",
        "package": "wireshark",
        "command": "wireshark",
        "description": "Interactive graphical network protocol analyzer.",
        "purpose": "Deep multi-layer packet inspection, stream reconstruction, and protocol analysis.",
        "protocols": ["ethernet", "ipv4", "ipv6", "tcp", "udp", "tls", "http", "dns", "quic"],
        "hardware": ["network_interface", "display_server"],
        "inputs": ["pcap", "pcapng"],
        "outputs": ["pcapng", "json", "csv", "pdml"],
        "related": ["tshark", "tcpdump"],
        "use_cases": ["inspect network traffic", "gui packet analysis", "follow tcp stream", "analyze pcap"],
        "permissions": "Requires wireshark group membership or dumpcap capabilities for live capture; .pcap analysis is unprivileged.",
        "limitations": "Requires graphical desktop session and higher RAM on multi-gigabyte captures.",
        "upstream": "https://www.wireshark.org/docs/",
        "kali_doc": "https://www.kali.org/tools/wireshark/",
        "examples": ["wireshark -r sample.pcapng"],
        "ram_mb": 512,
    },
    "tshark": {
        "category": "sniffing-spoofing",
        "package": "tshark",
        "command": "tshark",
        "description": "Terminal-oriented Wireshark packet analyzer and protocol dissector.",
        "purpose": "Headless deep packet dissection, field extraction, and JSON/CSV export from PCAPs.",
        "protocols": ["ethernet", "ipv4", "ipv6", "tcp", "udp", "tls", "http", "dns"],
        "hardware": ["network_interface"],
        "inputs": ["pcap", "pcapng"],
        "outputs": ["json", "ek", "pdml", "psml", "fields_csv", "pcapng"],
        "related": ["wireshark", "tcpdump"],
        "use_cases": ["inspect network traffic", "automated pcap analysis", "extract protocol fields"],
        "permissions": "Unprivileged for .pcap/.pcapng analysis; dumpcap privileges needed for live capture.",
        "limitations": "Large JSON exports can consume significant memory without packet count bounds.",
        "upstream": "https://www.wireshark.org/docs/man-pages/tshark.html",
        "kali_doc": "https://www.kali.org/tools/wireshark/#tshark",
        "examples": ["tshark -r capture.pcap -T json -c 25"],
        "ram_mb": 192,
    },
    "ss": {
        "category": "information-gathering",
        "package": "iproute2",
        "command": "ss",
        "description": "Socket statistics utility from iproute2 for inspecting active local TCP/UDP/UNIX sockets.",
        "purpose": "Inspect listening ports, established network connections, and owning local processes.",
        "protocols": ["tcp", "udp", "unix", "raw", "netlink"],
        "hardware": [],
        "inputs": ["kernel_netlink"],
        "outputs": ["text_stdout"],
        "related": ["ip", "tcpdump", "lsof"],
        "use_cases": ["inspect network traffic", "list open ports", "diagnose connection problem", "active sockets"],
        "permissions": "Unprivileged for socket listing; process names of other UIDs require elevated privileges.",
        "limitations": "Shows socket endpoints and counters rather than packet payloads.",
        "upstream": "https://wiki.linuxfoundation.org/networking/iproute2",
        "kali_doc": "https://www.kali.org/tools/iproute2/",
        "examples": ["ss -tuln", "ss -s"],
        "ram_mb": 16,
    },
    "ip": {
        "category": "information-gathering",
        "package": "iproute2",
        "command": "ip",
        "description": "Linux iproute2 routing, network device, interface, and tunnel configuration/inspection tool.",
        "purpose": "Inspect IP addresses, link state, routing tables, and ARP/neighbor caches.",
        "protocols": ["ipv4", "ipv6", "arp", "ethernet", "vlan"],
        "hardware": ["network_interface"],
        "inputs": ["kernel_netlink"],
        "outputs": ["text_stdout", "json"],
        "related": ["ss", "iw", "tcpdump"],
        "use_cases": ["inspect network interfaces", "diagnose connection problem", "check routing table", "inspect network traffic"],
        "permissions": "Read-only `ip addr` / `ip route` works unprivileged; link/route mutation requires CAP_NET_ADMIN.",
        "limitations": "Configuration changes are non-persistent across reboot unless saved in NetworkManager/systemd-networkd.",
        "upstream": "https://wiki.linuxfoundation.org/networking/iproute2",
        "kali_doc": "https://www.kali.org/tools/iproute2/",
        "examples": ["ip -br addr", "ip route show"],
        "ram_mb": 16,
    },
    "nmap": {
        "category": "information-gathering",
        "package": "nmap",
        "command": "nmap",
        "description": "Network exploration tool and security / port scanner for authorized assessments.",
        "purpose": "Discover hosts, open ports, and service versions within authorized lab or owned network scopes.",
        "protocols": ["tcp", "udp", "icmp", "sctp", "http", "tls"],
        "hardware": ["network_interface"],
        "inputs": ["target_spec", "nmap_target_list"],
        "outputs": ["text_stdout", "xml", "gnmap"],
        "related": ["ncat", "ss", "tcpdump"],
        "use_cases": ["authorized port scan", "service discovery", "vulnerability assessment", "network inventory"],
        "permissions": "TCP connect scan (-sT) runs unprivileged; SYN scan (-sS) and OS fingerprinting require root/CAP_NET_RAW.",
        "limitations": "Must only be run against owned systems, local labs, or explicitly authorized targets.",
        "upstream": "https://nmap.org/book/man.html",
        "kali_doc": "https://www.kali.org/tools/nmap/",
        "examples": ["nmap --version", "nmap -sT -p 80,443 127.0.0.1"],
        "ram_mb": 64,
    },
    "openssl": {
        "category": "cryptography",
        "package": "openssl",
        "command": "openssl",
        "description": "Cryptography and TLS/SSL toolkit for certificates, digests, ciphers, and TLS handshakes.",
        "purpose": "Inspect X.509 certificates, compute cryptographic hashes, and diagnose TLS endpoints.",
        "protocols": ["tls", "x509", "pkcs12", "ocsp"],
        "hardware": [],
        "inputs": ["pem", "der", "binary_file"],
        "outputs": ["pem", "der", "hex_digest", "text_stdout"],
        "related": ["curl", "gpg", "ssh-keygen"],
        "use_cases": ["inspect tls certificate", "cryptography", "compute sha256 digest", "diagnose tls"],
        "permissions": "Runs unprivileged as standard user.",
        "limitations": "Low-level CLI subcommands require exact flag syntax per OpenSSL 3.x series.",
        "upstream": "https://docs.openssl.org/",
        "kali_doc": "https://www.kali.org/tools/openssl/",
        "examples": ["openssl version", "openssl dgst -sha256 README.md"],
        "ram_mb": 24,
    },
    "tor": {
        "category": "anonymity-privacy",
        "package": "tor",
        "command": "tor",
        "description": "Connection-based low-latency anonymous communication system (SOCKS5h & onion routing).",
        "purpose": "Provide application-scoped SOCKS5h privacy transport and authorized onion service connectivity.",
        "protocols": ["tor", "socks5", "tcp"],
        "hardware": [],
        "inputs": ["torrc"],
        "outputs": ["socks_listener", "log_stdout"],
        "related": ["torsocks", "curl"],
        "use_cases": ["privacy transport", "onion research", "verify torrc"],
        "permissions": "Daemon service managed via systemd or unprivileged user instance on custom ports.",
        "limitations": "Application-scoped SOCKS proxy only; does not automatically anonymize all OS UDP/TCP traffic.",
        "upstream": "https://2019.www.torproject.org/docs/tor-manual.html.en",
        "kali_doc": "https://www.kali.org/tools/tor/",
        "examples": ["tor --version"],
        "ram_mb": 96,
    },
    "sqlite3": {
        "category": "database-assessment",
        "package": "sqlite3",
        "command": "sqlite3",
        "description": "Command-line interface for SQLite 3 relational databases.",
        "purpose": "Inspect schemas, run SQL queries, and export CSV/JSON from SQLite databases.",
        "protocols": ["sql"],
        "hardware": [],
        "inputs": ["sqlite3", "sql"],
        "outputs": ["json", "csv", "sql", "text_stdout"],
        "related": ["python3", "jq"],
        "use_cases": ["inspect database", "query sqlite", "forensic artifact sqlite inspection"],
        "permissions": "Standard file read/write permissions on target .sqlite3 file.",
        "limitations": "Embedded single-file RDBMS; concurrent heavy writers share file locks.",
        "upstream": "https://www.sqlite.org/cli.html",
        "kali_doc": "https://www.kali.org/docs/",
        "examples": ["sqlite3 --version"],
        "ram_mb": 24,
    },
    "binwalk": {
        "category": "reverse-engineering",
        "package": "binwalk",
        "command": "binwalk",
        "description": "Firmware and binary image signature analysis and extraction utility.",
        "purpose": "Identify embedded file systems, headers, and compressed archives inside firmware binaries.",
        "protocols": [],
        "hardware": [],
        "inputs": ["bin", "img", "elf", "firmware"],
        "outputs": ["text_stdout", "extracted_files"],
        "related": ["strings", "objdump", "radare2"],
        "use_cases": ["firmware analysis", "reverse engineering", "binary inspection"],
        "permissions": "Unprivileged; extraction (-e) should always run in an isolated quarantine directory.",
        "limitations": "Recursive extraction of untrusted images must remain sandboxed against path traversal.",
        "upstream": "https://github.com/ReFirmLabs/binwalk",
        "kali_doc": "https://www.kali.org/tools/binwalk/",
        "examples": ["binwalk --help"],
        "ram_mb": 128,
    },
    "apktool": {
        "category": "reverse-engineering",
        "package": "apktool",
        "command": "apktool",
        "description": "Tool for reverse engineering 3rd-party, closed, binary Android APK resources.",
        "purpose": "Decode AndroidManifest.xml, resources, and smali bytecode from authorized APK files.",
        "protocols": [],
        "hardware": [],
        "inputs": ["apk"],
        "outputs": ["smali_dir", "xml"],
        "related": ["jadx", "unzip", "strings"],
        "use_cases": ["examine android application package", "apk inspection", "mobile security lab"],
        "permissions": "Unprivileged; requires Java runtime.",
        "limitations": "Decompiles to smali rather than high-level Java source (pair with jadx when installed).",
        "upstream": "https://apktool.org/docs/the-basics/intro",
        "kali_doc": "https://www.kali.org/tools/apktool/",
        "examples": ["apktool --version"],
        "ram_mb": 512,
    },
}

_HELP_FLAG_RE = re.compile(r"(?<!\w)(-[A-Za-z0-9]|--[A-Za-z0-9][A-Za-z0-9\-]*)")


def parse_help_flags(help_text: str) -> list[str]:
    found: list[str] = []
    for match in _HELP_FLAG_RE.finditer(help_text or ""):
        flag = match.group(1)
        if flag not in found:
            found.append(flag)
        if len(found) >= 60:
            break
    return found


class AutomaticDocumentationEngine:
    """§184 5-Priority Documentation Retrieval & §191 Incremental Local Kali Knowledge Engine."""

    def __init__(
        self,
        *,
        db: Database,
        system_model: KaliSystemKnowledgeModel,
        knowledge_store: KnowledgeStore | None = None,
    ):
        self.db = db
        self.system_model = system_model
        self.knowledge_store = knowledge_store

    def retrieve_prioritized_documentation(self, tool_or_command: str) -> dict[str, Any]:
        """§184 Retrieve and rank documentation across Priorities 1–5, anchored in actual host versions."""
        target = tool_or_command.strip()
        if not re.fullmatch(r"[A-Za-z0-9._+\-]+", target):
            raise ValueError("Invalid tool or command identifier.")

        env_info = self.system_model.get_or_refresh_model()["model"]
        distro_ver = env_info["distribution"].get("version") or env_info["distribution"].get("pretty_name", "")
        kernel_rel = env_info["kernel_and_architecture"].get("release", "")
        state = self.system_model.classify_application_state(target)
        exe = state["executable_path"]
        version_ctx = f"tool={state.get('package_version') or state.get('probe_summary') or 'uninstalled'} | distro={distro_ver} | kernel={kernel_rel}"

        sources: list[dict[str, Any]] = []

        # Priority 1 — Official local documentation (man, --help, /usr/share/doc)
        man_excerpt = ""
        if shutil.which("man"):
            rc, mout, _ = _run_probe(["man", "-P", "cat", target], timeout=3.0)
            if rc == 0 and mout:
                man_excerpt = mout[:2500]
                doc_rec = self._index_doc(
                    doc_key=f"p1:man:{target}",
                    title=f"Local man page: {target}(1)",
                    topic=target,
                    priority_tier=1,
                    source_kind="local_man_page",
                    source_ref=f"man://{target}",
                    version_context=version_ctx,
                    license_note="Installed system manual page",
                    content=man_excerpt,
                )
                sources.append(doc_rec)

        help_excerpt = ""
        help_flags: list[str] = []
        if exe:
            for hflag in ("--help", "-h"):
                rc, hout, herr = _run_probe([exe, hflag], timeout=2.5)
                combined = (hout or herr).strip()
                if combined and "not found" not in combined[:80].lower():
                    help_excerpt = combined[:2500]
                    help_flags = parse_help_flags(combined)
                    doc_rec = self._index_doc(
                        doc_key=f"p1:help:{target}",
                        title=f"Built-in CLI help: {target} {hflag}",
                        topic=target,
                        priority_tier=1,
                        source_kind="local_cli_help",
                        source_ref=f"{exe} {hflag}",
                        version_context=version_ctx,
                        license_note="Installed binary --help output",
                        content=help_excerpt,
                    )
                    sources.append(doc_rec)
                    break

        doc_dir = Path("/usr/share/doc") / target
        if doc_dir.is_dir():
            for readme in sorted(doc_dir.glob("README*"))[:1]:
                try:
                    rtxt = readme.read_text(encoding="utf-8", errors="replace")[:1800]
                    sources.append(
                        self._index_doc(
                            doc_key=f"p1:readme:{target}",
                            title=f"Installed package README: {readme.name}",
                            topic=target,
                            priority_tier=1,
                            source_kind="installed_readme",
                            source_ref=str(readme),
                            version_context=version_ctx,
                            license_note=str(doc_dir / "copyright"),
                            content=rtxt,
                        )
                    )
                except OSError:
                    pass

        # Priority 2 — Official Kali documentation & package metadata
        cat_meta = REFERENCE_KALI_CATALOGUE.get(target.lower(), {})
        kali_url = cat_meta.get("kali_doc") or f"https://www.kali.org/tools/{target.lower()}/"
        apt_desc = ""
        if shutil.which("apt-cache"):
            rc, aout, _ = _run_probe(["apt-cache", "show", cat_meta.get("package", target)], timeout=2.5)
            if rc == 0 and aout:
                apt_desc = aout[:1800]
        p2_content = apt_desc or cat_meta.get("description") or f"Official Kali Tools reference pointer: {kali_url}"
        sources.append(
            self._index_doc(
                doc_key=f"p2:kali:{target}",
                title=f"Official Kali Documentation & Package Metadata: {target}",
                topic=target,
                priority_tier=2,
                source_kind="official_kali_docs",
                source_ref=kali_url,
                version_context=version_ctx,
                license_note="Offensive Security / Kali Linux Documentation attribution",
                content=p2_content,
            )
        )

        # Priority 3 — Upstream project documentation
        upstream_url = cat_meta.get("upstream", "")
        if not upstream_url and apt_desc:
            for ln in apt_desc.splitlines():
                if ln.startswith("Homepage:"):
                    upstream_url = ln.split(":", 1)[1].strip()
                    break
        if upstream_url:
            sources.append(
                self._index_doc(
                    doc_key=f"p3:upstream:{target}",
                    title=f"Upstream Project Documentation: {target}",
                    topic=target,
                    priority_tier=3,
                    source_kind="upstream_documentation",
                    source_ref=upstream_url,
                    version_context=version_ctx,
                    license_note="Upstream project license & attribution",
                    content=f"Upstream canonical manual and release compatibility reference: {upstream_url}",
                )
            )

        # Priority 4 — Trusted educational resources (Kali Training / Kali Linux Revealed)
        sources.append(
            self._index_doc(
                doc_key=f"p4:edu:{target}",
                title=f"Kali Training & Kali Linux Revealed Reference: {target}",
                topic=target,
                priority_tier=4,
                source_kind="trusted_educational",
                source_ref="https://kali.training/",
                version_context=version_ctx,
                license_note="Pointer only — respects Kali Training / Kali Linux Revealed license",
                content=f"Educational foundation for {target}: consult Kali Linux Revealed and official Kali Training exercises.",
            )
        )

        # Priority 5 — Stored community notes (explicitly non-authoritative)
        comm_hits = [
            d
            for d in self.db.search_kali_knowledge_docs(tool_or_topic=target, max_priority_tier=5, limit=5)
            if d.get("priority_tier") == 5
        ]
        sources.extend(comm_hits)

        sources_sorted = sorted(sources, key=lambda d: int(d.get("priority_tier", 5)))
        return {
            "tool": target,
            "installed": state["states"]["installed"],
            "version_context": version_ctx,
            "priority_hierarchy": DOC_PRIORITY_TIERS,
            "verified_help_flags": help_flags,
            "has_local_man_page": bool(man_excerpt),
            "has_local_cli_help": bool(help_excerpt),
            "conflict_resolution_policy": "prioritize_current_official_docs_and_reproducible_local_results_over_community_posts",
            "sources": sources_sorted,
        }

    def ingest_custom_or_community_note(
        self,
        *,
        doc_key: str,
        title: str,
        topic: str,
        content: str,
        priority_tier: int = 5,
        source_ref: str = "",
        version_context: str = "",
        license_note: str = "User troubleshooting note / public reference",
    ) -> dict[str, Any]:
        return self._index_doc(
            doc_key=doc_key,
            title=title,
            topic=topic,
            priority_tier=priority_tier,
            source_kind="community_or_user_note" if priority_tier == 5 else "curated_doc",
            source_ref=source_ref,
            version_context=version_context,
            license_note=license_note,
            content=content,
        )

    def _index_doc(
        self,
        *,
        doc_key: str,
        title: str,
        topic: str,
        priority_tier: int,
        source_kind: str,
        source_ref: str,
        version_context: str,
        license_note: str,
        content: str,
    ) -> dict[str, Any]:
        tier_meta = DOC_PRIORITY_TIERS.get(priority_tier, DOC_PRIORITY_TIERS[5])
        sha = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
        saved = self.db.upsert_kali_knowledge_doc(
            {
                "doc_key": doc_key,
                "title": title,
                "tool_or_topic": topic,
                "priority_tier": priority_tier,
                "source_kind": source_kind,
                "source_ref": source_ref,
                "reliability": tier_meta["reliability"],
                "version_context": version_context,
                "license_note": license_note,
                "content_sha256": sha,
                "content_excerpt": content[:6000],
                "metadata": {"authoritative": tier_meta["authoritative"], "tier_label": tier_meta["label"]},
            }
        )
        if not saved.get("incremental_unchanged") and self.knowledge_store is not None:
            try:
                self.knowledge_store.index_text(
                    doc_key,
                    f"{title}\n{content[:4000]}",
                    source=source_ref or source_kind,
                    metadata={"topic": topic, "priority_tier": priority_tier, "reliability": tier_meta["reliability"]},
                )
            except Exception:
                pass
        return saved


class KaliToolIntelligenceEngine:
    """§182 Comprehensive Kali Tool Knowledge Base building verified 20-field tool profiles."""

    def __init__(
        self,
        *,
        db: Database,
        system_model: KaliSystemKnowledgeModel,
        package_intel: KaliPackageIntelligence,
        doc_engine: AutomaticDocumentationEngine,
    ):
        self.db = db
        self.system_model = system_model
        self.package_intel = package_intel
        self.doc_engine = doc_engine

    def build_tool_profile(self, tool_name: str, *, persist: bool = True) -> dict[str, Any]:
        """§182 Build all 20 required profile fields grounded in live host inspection (never assuming installation)."""
        key = tool_name.strip().lower()
        if not re.fullmatch(r"[a-z0-9._+\-]+", key):
            raise ValueError("Invalid tool name.")

        cat_meta = REFERENCE_KALI_CATALOGUE.get(key, {})
        cmd = str(cat_meta.get("command") or key)
        pkg_report = self.package_intel.inspect_package(cmd)
        state = pkg_report["lifecycle"]
        docs = self.doc_engine.retrieve_prioritized_documentation(cmd)

        exe_path = state["executable_path"]
        version_str = state["package_version"] or state["probe_summary"] or "not_installed"
        install_status = state["primary_state"]

        # Config files actually present or documented
        cfg_paths = [
            str(p)
            for p in (Path(f"/etc/{cmd}"), Path(f"/etc/{cmd}.conf"), Path.home() / f".{cmd}rc", Path.home() / ".config" / cmd)
            if p.exists()
        ]

        description = cat_meta.get("description") or (
            f"Installed Linux/Kali utility at {exe_path}" if exe_path else f"Uninstalled tool '{tool_name}' (not present in local $PATH)."
        )
        purpose = cat_meta.get("purpose") or (
            state["probe_summary"] if state["probe_summary"] else f"Command-line or package utility '{cmd}'."
        )

        profile_20: dict[str, Any] = {
            "name": key,
            "description": description,
            "purpose": purpose,
            "package_information": {
                "package_name": pkg_report["providing_package"] or cat_meta.get("package", ""),
                "candidate_version": pkg_report["candidate_version"],
                "origin": pkg_report["package_origin"],
                "catalogue_reference": KALI_TOOLS_CATALOGUE_URL,
            },
            "executable_path": exe_path,
            "version": version_str,
            "installation_status": install_status,
            "dependencies": pkg_report["dependencies"],
            "available_help_options": docs["verified_help_flags"],
            "man_page_references": [s["source_ref"] for s in docs["sources"] if s.get("source_kind") == "local_man_page"]
            or ([f"man {cmd}"] if docs["has_local_man_page"] else []),
            "official_documentation": cat_meta.get("kali_doc") or f"https://www.kali.org/tools/{key}/",
            "upstream_documentation": cat_meta.get("upstream")
            or next((s["source_ref"] for s in docs["sources"] if s.get("priority_tier") == 3), ""),
            "configuration_information": {
                "detected_config_paths": cfg_paths,
                "configured": state["states"]["configured"],
            },
            "supported_input_formats": list(cat_meta.get("inputs") or ["stdin", "cli_args"]),
            "output_formats": list(cat_meta.get("outputs") or ["text_stdout"]),
            "resource_requirements": {
                "estimated_ram_mb": int(cat_meta.get("ram_mb") or 32),
                "required_hardware": list(cat_meta.get("hardware") or []),
                "low_spec_friendly": int(cat_meta.get("ram_mb") or 32) <= 256,
            },
            "compatibility_information": {
                "architecture": pkg_report["host_architecture"],
                "supported_protocols": list(cat_meta.get("protocols") or []),
                "related_tools": list(cat_meta.get("related") or []),
                "category": cat_meta.get("category", "system-utility"),
            },
            "permission_requirements": cat_meta.get("permissions")
            or "Standard user permissions unless inspecting raw devices or privileged kernel interfaces.",
            "known_limitations": cat_meta.get("limitations")
            or ("Tool is currently NOT installed on this system." if not state["states"]["installed"] else "Verify flags via --help for this installed version."),
            "usage_examples": list(cat_meta.get("examples") or ([f"{cmd} --help"] if exe_path else [])),
        }

        if persist:
            self.db.upsert_kali_tool_profile(
                {
                    "tool_key": key,
                    "name": key,
                    "command_name": cmd,
                    "package_name": profile_20["package_information"]["package_name"],
                    "category": profile_20["compatibility_information"]["category"],
                    "installation_status": install_status,
                    "executable_path": exe_path,
                    "version": version_str,
                    "integration_method": "documented_cli",
                    "tested_compatibility": bool(state["states"]["functional"]),
                    "profile": profile_20,
                }
            )
        return profile_20

    def search_tools_for_objective(
        self,
        problem_or_query: str,
        *,
        category: str = "",
        protocol: str = "",
        input_format: str = "",
        installed_only: bool = False,
    ) -> dict[str, Any]:
        """§182 Discover and compare tools by natural-language objective, protocol, format, or category."""
        q_lower = (problem_or_query or "").strip().lower()
        tokens = [t for t in re.findall(r"[a-z0-9_+\-]+", q_lower) if len(t) >= 2]

        candidate_keys = set(REFERENCE_KALI_CATALOGUE.keys())
        # Also include any already-learned/stored profiles + matching live $PATH utilities!
        for saved in self.db.list_kali_tool_profiles(limit=200):
            candidate_keys.add(saved["tool_key"])
        for raw_dir in os.environ.get("PATH", "").split(os.pathsep):
            p = Path(raw_dir)
            if not p.is_dir():
                continue
            try:
                for child in p.iterdir():
                    cname = child.name.lower()
                    if any(tok in cname for tok in tokens) and os.access(child, os.X_OK):
                        candidate_keys.add(cname)
            except OSError:
                continue

        scored: list[tuple[int, dict[str, Any]]] = []
        for tkey in sorted(candidate_keys):
            meta = REFERENCE_KALI_CATALOGUE.get(tkey, {})
            if category and meta.get("category", "").lower() != category.strip().lower():
                continue
            if protocol and protocol.lower() not in [p.lower() for p in meta.get("protocols", [])]:
                continue
            if input_format and input_format.lower() not in [f.lower() for f in meta.get("inputs", [])]:
                continue

            haystack = " ".join(
                [
                    tkey,
                    str(meta.get("category", "")),
                    str(meta.get("description", "")),
                    str(meta.get("purpose", "")),
                    " ".join(meta.get("protocols", [])),
                    " ".join(meta.get("use_cases", [])),
                    " ".join(meta.get("inputs", [])),
                    " ".join(meta.get("outputs", [])),
                ]
            ).lower()

            score = 0
            if q_lower and q_lower in haystack:
                score += 8
            for tok in tokens:
                if tok == tkey:
                    score += 10
                elif tok in haystack:
                    score += 2
            if not tokens:
                score = 1
            if score <= 0:
                continue

            prof = self.build_tool_profile(tkey, persist=True)
            is_installed = prof["installation_status"] in {"installed", "configured", "running", "functional"}
            if installed_only and not is_installed:
                continue
            # Prefer actually installed & low-resource tools (§182 & §183)!
            if is_installed:
                score += 6
            if prof["resource_requirements"]["low_spec_friendly"]:
                score += 1
            scored.append((score, prof))

        scored.sort(key=lambda item: (-item[0], item[1]["name"]))
        matches = [item[1] for item in scored[:12]]
        installed_matches = [m for m in matches if m["executable_path"]]
        uninstalled_matches = [m for m in matches if not m["executable_path"]]

        recommended = installed_matches[0] if installed_matches else (matches[0] if matches else None)
        comparison = [
            {
                "name": m["name"],
                "installed": bool(m["executable_path"]),
                "status": m["installation_status"],
                "executable_path": m["executable_path"],
                "estimated_ram_mb": m["resource_requirements"]["estimated_ram_mb"],
                "purpose": m["purpose"],
                "limitations": m["known_limitations"],
            }
            for m in matches[:6]
        ]
        return {
            "objective": problem_or_query,
            "catalogue_reference": KALI_TOOLS_CATALOGUE_URL,
            "assumed_all_kali_tools_installed": False,
            "total_matches": len(matches),
            "installed_candidates_count": len(installed_matches),
            "uninstalled_candidates_count": len(uninstalled_matches),
            "recommended_tool": recommended["name"] if recommended else None,
            "recommendation_rationale": (
                f"Selected '{recommended['name']}' because it is already installed ({recommended['executable_path']}) and fits local resource/permission bounds."
                if recommended and recommended["executable_path"]
                else (
                    f"No matching tool is currently installed; '{recommended['name']}' is the closest selective Kali package candidate."
                    if recommended
                    else "No matching tool found in local system or reference catalogue."
                )
            ),
            "comparison": comparison,
            "profiles": matches,
        }


class IntelligentToolSelectorAndExecutor:
    """§183 13-step Intelligent Tool Discovery, Option Verification, and Permission-Gated Execution."""

    NEVER_INVENT_FLAGS_OR_RESULTS = True

    def __init__(
        self,
        *,
        db: Database,
        tool_engine: KaliToolIntelligenceEngine,
        doc_engine: AutomaticDocumentationEngine,
        autonomy_policy: Any,
        cognition: Any | None = None,
    ):
        self.db = db
        self.tool_engine = tool_engine
        self.doc_engine = doc_engine
        self.autonomy_policy = autonomy_policy
        self.cognition = cognition

    def execute_13_step_objective(
        self,
        objective: str,
        *,
        explicit_argv: list[str] | None = None,
        approved: bool = False,
        cwd: Path | None = None,
    ) -> dict[str, Any]:
        """§183 Execute the full 13-step discovery -> flag-check -> permission-gated run -> output verification loop."""
        steps: list[dict[str, Any]] = []

        # 1. Understand the task
        steps.append({"step": 1, "name": "understand_task", "objective": objective[:300]})

        # 2 & 3. Search local registry & inspect installed applications/commands
        discovery = self.tool_engine.search_tools_for_objective(objective)
        installed_profiles = [p for p in discovery["profiles"] if p["executable_path"]]
        steps.append(
            {
                "step": 2,
                "name": "search_local_registry",
                "candidates_found": discovery["total_matches"],
            }
        )
        steps.append(
            {
                "step": 3,
                "name": "inspect_installed_commands",
                "installed_commands": [p["name"] for p in installed_profiles],
            }
        )

        selected_profile: dict[str, Any] | None = None
        if explicit_argv:
            cmd0 = Path(explicit_argv[0]).name
            selected_profile = self.tool_engine.build_tool_profile(cmd0, persist=True)
        elif installed_profiles:
            selected_profile = installed_profiles[0]
        elif discovery["profiles"]:
            selected_profile = discovery["profiles"][0]

        if selected_profile is None or not selected_profile["executable_path"]:
            missing_name = selected_profile["name"] if selected_profile else (explicit_argv[0] if explicit_argv else "unknown")
            steps.append({"step": 4, "name": "tool_unavailable", "missing_tool": missing_name})
            return {
                "ok": False,
                "status": "tool_not_installed",
                "missing_tool": missing_name,
                "invented_result": False,
                "steps": steps,
                "recommendation": discovery["recommendation_rationale"],
            }

        cmd_name = selected_profile["name"]
        exe_path = selected_profile["executable_path"]

        # 4 & 5. Read local help documentation & official tool documentation
        doc_bundle = self.doc_engine.retrieve_prioritized_documentation(cmd_name)
        verified_flags = set(doc_bundle["verified_help_flags"])
        steps.append(
            {
                "step": 4,
                "name": "read_local_help_documentation",
                "verified_flag_count": len(verified_flags),
            }
        )
        steps.append(
            {
                "step": 5,
                "name": "search_official_documentation",
                "official_doc": selected_profile["official_documentation"],
            }
        )

        # 6. Compare suitable tools (preferring installed tools, avoiding redundant installs)
        steps.append(
            {
                "step": 6,
                "name": "compare_suitable_tools",
                "comparison": discovery["comparison"][:4],
                "avoided_redundant_install": True,
            }
        )

        # Construct safe argv without ever inventing unsupported CLI flags!
        if explicit_argv:
            argv = [exe_path, *explicit_argv[1:]]
            supplied_flags = [arg.split("=", 1)[0] for arg in explicit_argv[1:] if arg.startswith("-")]
            unverified_flags = [fl for fl in supplied_flags if verified_flags and fl not in verified_flags]
            if unverified_flags:
                return {
                    "ok": False,
                    "status": "rejected_unverified_cli_option",
                    "selected_tool": cmd_name,
                    "unverified_flags": unverified_flags,
                    "verified_help_flags_sample": sorted(verified_flags)[:25],
                    "steps": steps,
                }
        else:
            default_flag = "--version" if "--version" in verified_flags else ("-V" if "-V" in verified_flags else "--help")
            argv = [exe_path, default_flag]

        # 7, 8 & 9. Check prerequisites/permissions, select tool, construct plan
        is_mutating = any(tok in {"install", "remove", "purge", "delete", "-w", "flush"} for tok in argv[1:])
        requires_gate = is_mutating and not approved
        steps.append(
            {
                "step": 7,
                "name": "check_prerequisites_and_permissions",
                "mutating": is_mutating,
                "approval_satisfied": not requires_gate,
            }
        )
        steps.append({"step": 8, "name": "select_most_appropriate_tool", "selected": cmd_name, "executable": exe_path})
        steps.append({"step": 9, "name": "construct_structured_execution_plan", "argv": argv})

        if requires_gate:
            return {
                "ok": False,
                "status": "approval_required",
                "selected_tool": cmd_name,
                "planned_argv": argv,
                "steps": steps,
            }

        # 10 & 11. Execute through local permission-controlled gateway & inspect actual output
        try:
            import subprocess

            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=8.0,
                cwd=str(cwd) if cwd else None,
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            )
            rc = proc.returncode
            stdout = (proc.stdout or "").strip()[:4000]
            stderr = (proc.stderr or "").strip()[:2000]
        except (OSError, subprocess.SubprocessError) as exc:
            rc, stdout, stderr = 1, "", str(exc)

        succeeded = rc == 0
        steps.append({"step": 10, "name": "execute_via_permission_gateway", "exit_code": rc})
        steps.append(
            {
                "step": 11,
                "name": "inspect_actual_output",
                "stdout_chars": len(stdout),
                "stderr_chars": len(stderr),
            }
        )

        # 12 & 13. Explain results & save findings / procedure candidate
        explanation = (
            f"Executed '{cmd_name}' ({' '.join(argv)}) with exit code {rc}. "
            + (f"Output headline: {(stdout or stderr).splitlines()[0][:180]}" if (stdout or stderr) else "Command produced empty output.")
        )
        steps.append({"step": 12, "name": "explain_results", "summary": explanation})

        saved_doc = self.doc_engine.ingest_custom_or_community_note(
            doc_key=f"proc:{cmd_name}:{hashlib.sha256(' '.join(argv).encode()).hexdigest()[:10]}",
            title=f"Validated execution procedure for {cmd_name}",
            topic=cmd_name,
            content=f"Objective: {objective}\nArgv: {argv}\nExit: {rc}\nOutput: {(stdout or stderr)[:600]}",
            priority_tier=1 if succeeded else 5,
            source_ref=exe_path,
        )
        steps.append({"step": 13, "name": "save_findings_and_procedure", "doc_key": saved_doc["doc_key"]})

        return {
            "ok": succeeded,
            "status": "completed" if succeeded else "command_failed",
            "selected_tool": cmd_name,
            "executable_path": exe_path,
            "argv": argv,
            "exit_code": rc,
            "stdout": stdout,
            "stderr": stderr,
            "explanation": explanation,
            "steps": steps,
        }
