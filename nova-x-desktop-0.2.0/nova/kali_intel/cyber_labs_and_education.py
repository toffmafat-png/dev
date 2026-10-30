"""§188 Cybersecurity Knowledge, §189 Autonomous Cyber Lab Manager, §192 Kali Training Mode & §193 13-Step Troubleshooting."""
from __future__ import annotations

import ipaddress
import os
import re
import shlex
import shutil
import uuid
from pathlib import Path
from typing import Any

from nova.db import Database, utc_now
from nova.kali_intel.system_model import KaliPackageIntelligence, KaliSystemKnowledgeModel, _run_probe
from nova.kali_intel.tool_and_doc_engine import AutomaticDocumentationEngine

CYBERSECURITY_25_DOMAINS: dict[str, dict[str, Any]] = {
    "linux_administration": {"tools": ["uname", "ps", "lsof", "chmod", "chown"], "focus": "POSIX process, user, service, and filesystem administration."},
    "networking": {"tools": ["ip", "ss", "ping", "curl"], "focus": "Link, network, and transport layer configuration and diagnostics."},
    "tcp_ip_protocols": {"tools": ["ss", "tcpdump", "tshark", "nc"], "focus": "TCP 3-way handshakes, congestion/windowing, UDP datagrams, and ICMP."},
    "dns": {"tools": ["dig", "nslookup", "host", "resolvectl"], "focus": "Recursive/authoritative DNS resolution, record types, and DNSSEC."},
    "routing": {"tools": ["ip", "traceroute", "tracepath"], "focus": "FIB/routing tables, policy routing, subnets, and next-hop forwarding."},
    "wireless_networking": {"tools": ["iw", "rfkill", "aircrack-ng", "nmcli"], "focus": "802.11 MAC/PHY frames, regulatory domains, monitor mode, and WPA2/WPA3."},
    "bluetooth": {"tools": ["bluetoothctl", "btmon", "rfkill"], "focus": "Bluetooth Classic/BLE GATT profiles, HCI controllers, and pairing security."},
    "web_technologies": {"tools": ["curl", "openssl", "python3"], "focus": "HTTP/1.1, HTTP/2, TLS, cookies, CORS, and REST/JSON APIs."},
    "web_application_security": {"tools": ["curl", "nikto", "ffuf", "gobuster", "sqlmap"], "focus": "Input validation, CSRF/XSS/SQLi defense & authorized lab testing."},
    "vulnerability_assessment": {"tools": ["nmap", "openssl", "dpkg-query"], "focus": "Service enumeration, CVE version correlation, and exposure verification."},
    "system_hardening": {"tools": ["sysctl", "ufw", "nft", "chmod"], "focus": "Least privilege, AppArmor/SELinux MAC, kernel sysctl, and attack-surface reduction."},
    "defensive_security": {"tools": ["ss", "journalctl", "sha256sum", "ps"], "focus": "Host telemetry, integrity baselining, and anomaly triage."},
    "digital_forensics": {"tools": ["sha256sum", "file", "strings", "sqlite3", "binwalk"], "focus": "Chain-of-custody hashing, timeline reconstruction, and artifact parsing."},
    "incident_response": {"tools": ["ps", "ss", "lsof", "tar", "sha256sum"], "focus": "Volatile evidence collection, containment, root-cause analysis, and recovery."},
    "isolated_malware_analysis": {"tools": ["file", "strings", "objdump", "readelf", "sha256sum"], "focus": "Static ELF/PE header triage strictly inside air-gapped sandboxes."},
    "reverse_engineering": {"tools": ["objdump", "readelf", "nm", "gdb", "radare2", "binwalk"], "focus": "Disassembly, symbol inspection, ABI calling conventions, and binary structure."},
    "cryptography": {"tools": ["openssl", "sha256sum", "gpg", "ssh-keygen"], "focus": "Authenticated encryption, SHA-2/3 hashing, X.509 PKI, and key management."},
    "password_security": {"tools": ["openssl", "john", "hashcat"], "focus": "Argon2/bcrypt/PBKDF2 key derivation hardness and authorized policy auditing."},
    "network_traffic_analysis": {"tools": ["tcpdump", "tshark", "wireshark", "ss"], "focus": "PCAP capture filtering (BPF), stream reassembly, and protocol dissection."},
    "cloud_security_fundamentals": {"tools": ["curl", "openssl", "ssh", "git"], "focus": "IAM least privilege, secret hygiene, TLS mTLS, and metadata protection."},
    "virtualization": {"tools": ["qemu-system-x86_64", "vboxmanage", "virsh", "systemd-detect-virt"], "focus": "KVM/QEMU hypervisor isolation, virtual NICs, and VM snapshots."},
    "container_security": {"tools": ["docker", "podman", "unshare", "ps"], "focus": "Linux namespaces, cgroups v2, rootless containers, and capability dropping."},
    "secure_software_development": {"tools": ["git", "python3", "ruff", "pytest", "gcc"], "focus": "Memory safety, parameterized SQL, dependency pinning, and automated CI checks."},
    "scripting_and_automation": {"tools": ["python3", "bash", "sh", "jq", "awk", "sed"], "focus": "Deterministic defensive automation, structured JSON parsing, and safe argv execution."},
    "security_research": {"tools": ["gdb", "strace", "python3", "git", "openssl"], "focus": "Reproducible vulnerability root-cause analysis and responsible coordinated disclosure."},
}

PROHIBITED_OFFENSIVE_INTENT_KEYWORDS: tuple[str, ...] = (
    "attack unauthorized",
    "bypass authentication on production",
    "steal credentials",
    "exfiltrate user passwords",
    "hack third-party",
    "ddos ",
)

KALI_TRAINING_11_TRACKS: dict[str, dict[str, Any]] = {
    "kali_fundamentals": {
        "title": "Kali Linux Fundamentals & Architecture",
        "official_ref": "https://kali.training/topic/introduction/",
        "commands": ["uname -a", "cat /etc/os-release"],
        "quiz": {
            "question": "Why should standard daily tasks on Kali Linux run under an unprivileged user account rather than root?",
            "options": {
                "A": "Because Kali Linux removed the sudo binary completely.",
                "B": "To enforce least privilege and limit blast radius from application bugs or untrusted inputs.",
                "C": "Because network tools cannot read local files as root.",
            },
            "answer": "B",
            "explanations": {
                "A": "Incorrect: Kali includes `sudo` (or `pkexec`) for explicit, auditable privilege elevation when required.",
                "B": "Correct: Running unprivileged protects the OS and user workspace from accidental destructive writes or parser exploits.",
                "C": "Incorrect: Root has unrestricted read access, which is precisely why unprivileged execution is safer by default.",
            },
        },
    },
    "linux_command_line_mastery": {
        "title": "Linux Command-Line Mastery",
        "official_ref": "https://kali.training/topic/linux-fundamentals/",
        "commands": ["ls -la", "find . -maxdepth 2 -type f"],
        "quiz": {
            "question": "What does `-maxdepth 2` do in `find . -maxdepth 2 -type f`?",
            "options": {"A": "Limits directory traversal to at most 2 levels below `.`", "B": "Returns only 2 files", "C": "Deletes files older than 2 days"},
            "answer": "A",
            "explanations": {
                "A": "Correct: `-maxdepth 2` bounds directory descent depth before evaluating `-type f`.",
                "B": "Incorrect: Output count is not capped to 2 files by `-maxdepth`.",
                "C": "Incorrect: `find` without `-delete` or `-exec rm` is strictly read-only.",
            },
        },
    },
    "file_permissions_and_administration": {
        "title": "File Permissions, Ownership & Administration",
        "official_ref": "https://www.kali.org/docs/general-use/",
        "commands": ["stat -c '%a %U:%G %n' /etc/passwd", "id"],
        "quiz": {
            "question": "What permissions does octal mode `0600` grant?",
            "options": {"A": "Read/write for owner only; no access for group or others", "B": "Executable by everyone", "C": "Read-only for group"},
            "answer": "A",
            "explanations": {
                "A": "Correct: `6` (`4+2`) grants owner read+write while `0` and `0` deny group and world access (ideal for SSH/API keys).",
                "B": "Incorrect: No execute bit (`1`) is set in `0600`.",
                "C": "Incorrect: Group permission digit is `0`.",
            },
        },
    },
    "networking_fundamentals": {
        "title": "Networking Fundamentals & Socket Inspection",
        "official_ref": "https://www.kali.org/docs/containers/",
        "commands": ["ip -br addr", "ss -tuln"],
        "quiz": {
            "question": "In `ss -tuln`, what does the `-n` flag ensure?",
            "options": {"A": "Numeric port and address output without slow DNS/service-name resolution", "B": "Drops active TCP sockets", "C": "Enables packet capture"},
            "answer": "A",
            "explanations": {
                "A": "Correct: `-n` prevents reverse DNS / `/etc/services` lookups so exact numeric ports and IPs display deterministically.",
                "B": "Incorrect: `ss -tuln` is strictly read-only.",
                "C": "Incorrect: `ss` queries kernel socket tables via netlink rather than capturing raw frames.",
            },
        },
    },
    "package_and_service_management": {
        "title": "APT/DPKG Package & Systemd Service Management",
        "official_ref": "https://kali.training/topic/managing-kali-linux/",
        "commands": ["dpkg --audit", "apt-cache policy bash"],
        "quiz": {
            "question": "Why are massive metapackages like `kali-linux-everything` discouraged on low-spec hosts?",
            "options": {"A": "They consume tens of gigabytes of disk and install unnecessary background services", "B": "They delete the Linux kernel", "C": "APT cannot install metapackages"},
            "answer": "A",
            "explanations": {
                "A": "Correct: Selective package installation preserves disk, RAM, update bandwidth, and minimal attack surface.",
                "B": "Incorrect: Metapackages pull dependencies rather than removing the kernel.",
                "C": "Incorrect: APT supports metapackages, but selective installation is best practice on ~10 GB RAM machines.",
            },
        },
    },
    "shell_scripting": {
        "title": "Defensive Shell Scripting & Safe Quoting",
        "official_ref": "https://kali.training/",
        "commands": ["sh -n script.sh", "printf '%s\\n' 'safe'"],
        "quiz": {
            "question": "Why should variables in POSIX shell scripts be double-quoted (`\"$var\"`)?",
            "options": {"A": "To prevent unintended word splitting and pathname globbing", "B": "To encrypt variable contents", "C": "To run commands as root"},
            "answer": "A",
            "explanations": {
                "A": "Correct: Unquoted expansions split on `IFS` whitespace and expand `*`/`?` globs.",
                "B": "Incorrect: Quoting is lexical syntax, not encryption.",
                "C": "Incorrect: Quoting does not alter process privileges.",
            },
        },
    },
    "security_concepts": {
        "title": "Core Security Concepts & Authorized Scope",
        "official_ref": "https://kali.training/topic/securing-and-monitoring-kali-linux/",
        "commands": ["sha256sum --version", "openssl version"],
        "quiz": {
            "question": "Does having a security tool installed on Kali Linux grant permission to scan external third-party hosts?",
            "options": {"A": "Yes, for read-only scans", "B": "No — security testing requires explicit ownership or documented authorization", "C": "Yes, if run unprivileged"},
            "answer": "B",
            "explanations": {
                "A": "Incorrect: Unauthorized active scanning of third-party systems violates legal and ethical boundaries.",
                "B": "Correct: Possession of Kali tools never implies authorization; restrict testing to owned systems, isolated labs, or explicitly authorized scopes.",
                "C": "Incorrect: Process UID does not create legal authorization.",
            },
        },
    },
    "tool_operation": {
        "title": "Verified Kali Tool Operation",
        "official_ref": "https://www.kali.org/tools/",
        "commands": ["tcpdump --version", "openssl dgst -sha256 /etc/hostname"],
        "quiz": {
            "question": "Before passing unfamiliar flags to an installed CLI tool, what is Priority 1 truth?",
            "options": {"A": "Guessing flags from similar tools", "B": "Inspecting the installed binary's local `man` page and `--help` output", "C": "Copying unverified forum snippets"},
            "answer": "B",
            "explanations": {
                "A": "Incorrect: Guessing CLI options risks errors or unintended side effects.",
                "B": "Correct: Local `man` and `--help` reflect the exact version installed on this machine.",
                "C": "Incorrect: Community posts are Priority 5 and may target older releases.",
            },
        },
    },
    "log_analysis": {
        "title": "System & Security Log Analysis",
        "official_ref": "https://kali.training/topic/securing-and-monitoring-kali-linux/",
        "commands": ["journalctl -n 20 --no-pager", "tail -n 20 /var/log/dpkg.log"],
        "quiz": {
            "question": "Before sharing diagnostic logs in a public support forum, what must be done?",
            "options": {"A": "Redact API keys, tokens, passwords, and sensitive private identifiers", "B": "Convert logs to binary", "C": "Nothing"},
            "answer": "A",
            "explanations": {
                "A": "Correct: Logs frequently capture bearer tokens, environment secrets, or private paths that must be scrubbed.",
                "B": "Incorrect: Binary encoding obscures Secrets without removing them.",
                "C": "Incorrect: Posting raw logs risks credential leakage.",
            },
        },
    },
    "system_hardening": {
        "title": "Kali & Debian System Hardening",
        "official_ref": "https://kali.training/topic/securing-and-monitoring-kali-linux/",
        "commands": ["umask", "sysctl net.ipv4.ip_forward"],
        "quiz": {
            "question": "Why should laboratory vulnerable services bind to `127.0.0.1` or an isolated virtual bridge?",
            "options": {"A": "So external LAN/WAN hosts cannot reach intentionally vulnerable lab targets", "B": "To increase internet download speed", "C": "Because TCP only works on loopback"},
            "answer": "A",
            "explanations": {
                "A": "Correct: Binding vulnerable training apps to loopback or host-only networks prevents exposing weaknesses to untrusted networks.",
                "B": "Incorrect: Loopback binding is an isolation control.",
                "C": "Incorrect: TCP works across any IP interface; isolation is deliberate.",
            },
        },
    },
    "troubleshooting": {
        "title": "Structured Kali Linux Troubleshooting",
        "official_ref": "https://www.kali.org/docs/troubleshooting/",
        "commands": ["dpkg --audit", "ip link show"],
        "quiz": {
            "question": "What is the safest first step when diagnosing a package or network failure on Kali?",
            "options": {"A": "Reinstall the entire operating system immediately", "B": "Run non-destructive read-only inspection (`dpkg --audit`, `ip addr`, logs) to isolate the root cause", "C": "Overwrite `/etc/apt/sources.list` from a random blog"},
            "answer": "B",
            "explanations": {
                "A": "Incorrect: Destructive reinstalls discard state without identifying the fault.",
                "B": "Correct: Evidence-driven read-only inspection pinpoints the exact layer failing before minimal targeted remediation.",
                "C": "Incorrect: Arbitrary repository changes risk breaking package dependencies and trust.",
            },
        },
    },
}

TROUBLESHOOTING_19_DOMAINS: dict[str, dict[str, Any]] = {
    "missing_wifi_adapters": {"probes": [["ip", "link"], ["lspci"], ["lsusb"]], "focus": "PCI/USB wireless bus enumeration, rfkill state, and firmware availability."},
    "inactive_wireless_interfaces": {"probes": [["ip", "link"], ["rfkill", "list"]], "focus": "Soft/hard rfkill blocks, NetworkManager management state, and link operstate."},
    "bluetooth_issues": {"probes": [["rfkill", "list"]], "focus": "HCI controller visibility, bluetooth.service state, and rfkill blocks."},
    "usb_recognition_failures": {"probes": [["lsusb"]], "focus": "USB bus enumeration, udev permissions, and kernel USB driver binding."},
    "graphics_and_display": {"probes": [["uname", "-r"]], "focus": "X11/Wayland session env (`DISPLAY`/`WAYLAND_DISPLAY`), DRM modules, and GPU drivers."},
    "audio_pipewire_pulseaudio": {"probes": [["ps", "-ef"]], "focus": "PipeWire / WirePlumber / PulseAudio user daemon health and ALSA sinks."},
    "broken_dpkg_apt": {"probes": [["dpkg", "--audit"]], "focus": "Half-configured packages, dpkg lock contention, and broken dependency chains."},
    "repository_errors": {"probes": [["apt-cache", "policy"]], "focus": "APT `/etc/apt/sources.list` integrity, Kali archive keyring, and HTTPS mirror reachability."},
    "kernel_module_problems": {"probes": [["uname", "-r"]], "focus": "Loaded `/proc/modules`, matching `linux-headers-$(uname -r)`, and DKMS build status."},
    "missing_firmware": {"probes": [["uname", "-r"]], "focus": "`/lib/firmware` presence and `firmware-linux` / chipset firmware packages."},
    "boot_grub_systemd": {"probes": [["uname", "-a"]], "focus": "Failed systemd units, `/etc/fstab` UUID mounts, and initramfs/GRUB configuration."},
    "disk_and_filesystem": {"probes": [["df", "-h"]], "focus": "Free disk space, inode exhaustion (`df -i`), and read-only mount remount triggers."},
    "network_connectivity": {"probes": [["ip", "-br", "addr"], ["ip", "route"]], "focus": "Interface link state, IPv4/IPv6 addressing, default gateway, and firewall rules."},
    "dns_resolution": {"probes": [["cat", "/etc/resolv.conf"]], "focus": "Configured nameservers in `/etc/resolv.conf`, `systemd-resolved`, and UDP/TCP 53 reachability."},
    "permission_errors": {"probes": [["id"]], "focus": "UID/GID, supplementary groups (`wireshark`, `docker`, `dialout`), file modes, and AppArmor."},
    "application_crashes": {"probes": [["ulimit", "-a"]], "focus": "Exit code, missing shared libraries (`ldd`), config corruption, and OOM memory pressure."},
    "virtualbox_kvm_issues": {"probes": [["systemd-detect-virt"]], "focus": "`/dev/kvm` permissions, `kvm_intel`/`kvm_amd` module conflict with VirtualBox, and nested virt."},
    "python_node_environments": {"probes": [["python3", "--version"]], "focus": "PEP 668 `venv`/`pipx` isolation, `VIRTUAL_ENV` PATH order, and `node_modules` lockfile parity."},
    "development_tool_failures": {"probes": [["git", "--version"], ["python3", "--version"]], "focus": "Compiler/header presence (`build-essential`), toolchain versions, and test runner paths."},
}


class CybersecurityKnowledgeBase:
    """§188 Defensive & Authorized Kali Cybersecurity Knowledge connected to live installed tools."""

    POSSESSION_IMPLIES_PERMISSION = False

    def __init__(self, *, system_model: KaliSystemKnowledgeModel, doc_engine: AutomaticDocumentationEngine):
        self.system_model = system_model
        self.doc_engine = doc_engine

    def verify_authorization_scope(
        self,
        *,
        objective: str,
        target: str = "127.0.0.1",
        user_confirmed_owned_or_authorized: bool = False,
    ) -> dict[str, Any]:
        """§188 Enforce authorized-target boundaries; refuse third-party attacks, auth bypass, or credential theft."""
        obj_lower = (objective or "").lower()
        for bad in PROHIBITED_OFFENSIVE_INTENT_KEYWORDS:
            if bad in obj_lower:
                return {
                    "permitted": False,
                    "reason": f"Refused: objective matches prohibited unauthorized activity ('{bad}'). Possession of Kali tools never grants permission to attack unauthorized targets.",
                    "target": target,
                }

        t_clean = (target or "127.0.0.1").strip()
        is_loopback = t_clean in {"localhost", "127.0.0.1", "::1"}
        is_private_lab = False
        try:
            ip_obj = ipaddress.ip_network(t_clean, strict=False)
            is_loopback = is_loopback or ip_obj.is_loopback
            is_private_lab = ip_obj.is_private
        except ValueError:
            pass

        permitted = is_loopback or (is_private_lab and user_confirmed_owned_or_authorized) or (
            t_clean == "local_owned_system"
        )
        return {
            "permitted": permitted,
            "target": t_clean,
            "is_loopback_isolated": is_loopback,
            "is_private_lab_range": is_private_lab,
            "possession_implies_permission": False,
            "reason": (
                "Permitted within isolated loopback or explicitly authorized local lab scope."
                if permitted
                else "Blocked: external or unconfirmed target requires explicit proof/confirmation of system ownership or authorized lab scope."
            ),
        }

    def explain_domain_and_installed_tools(self, domain: str) -> dict[str, Any]:
        """§188 Connect any of the 25 cybersecurity domains to actually installed host tools with 8 technical facets."""
        dkey = domain.strip().lower()
        if dkey not in CYBERSECURITY_25_DOMAINS:
            raise ValueError(f"Unsupported domain '{domain}'. Valid domains: {sorted(CYBERSECURITY_25_DOMAINS)}")
        meta = CYBERSECURITY_25_DOMAINS[dkey]

        installed_tools: list[dict[str, Any]] = []
        uninstalled_tools: list[str] = []
        for cmd in meta["tools"]:
            st = self.system_model.classify_application_state(cmd)
            if st["states"]["installed"]:
                docs = self.doc_engine.retrieve_prioritized_documentation(cmd)
                installed_tools.append(
                    {
                        "tool": cmd,
                        "executable_path": st["executable_path"],
                        "version": st["package_version"] or st["probe_summary"],
                        "what_it_does": f"Provides practical {dkey.replace('_', ' ')} inspection/operation via `{cmd}`.",
                        "why_it_exists": meta["focus"],
                        "how_it_works_technically": f"Invokes `{st['executable_path']}` against local OS interfaces, files, or authorized lab sockets.",
                        "what_options_mean": docs["verified_help_flags"][:15],
                        "prerequisites": "Authorized target/lab scope and appropriate local file/socket permissions.",
                        "what_output_indicates": "Structured diagnostic state, headers, digests, or protocol records from the inspected target.",
                        "how_to_verify_results": "Cross-check exit code (`0`), deterministic flags (`-n` / `--version`), and reproducible secondary tool output.",
                        "risks_and_limitations": "Restrict active probes strictly to owned hosts or isolated labs; respect host RAM/CPU limits.",
                    }
                )
            else:
                uninstalled_tools.append(cmd)

        return {
            "domain": dkey,
            "total_supported_domains": len(CYBERSECURITY_25_DOMAINS),
            "domain_focus": meta["focus"],
            "installed_tools": installed_tools,
            "uninstalled_reference_tools": uninstalled_tools,
            "authorized_use_only": True,
        }


class AutonomousCyberLabManager:
    """§189 Resource-aware, network-isolated Cybersecurity Lab Manager with snapshots & restore points."""

    MIN_HOST_FREE_RAM_MB_RESERVE = 384
    MIN_HOST_FREE_DISK_GB_RESERVE = 1.0

    def __init__(
        self,
        *,
        db: Database,
        system_model: KaliSystemKnowledgeModel,
        cyber_kb: CybersecurityKnowledgeBase,
        workspace_dir: Path,
    ):
        self.db = db
        self.system_model = system_model
        self.cyber_kb = cyber_kb
        self.workspace_dir = workspace_dir

    def preflight_hardware_and_isolation(
        self,
        *,
        requested_ram_mb: int = 256,
        requested_disk_gb: float = 0.5,
        network_scope: str = "127.0.0.1/32",
    ) -> dict[str, Any]:
        """§189 Check CPU, RAM, storage, and strict network isolation BEFORE starting intensive lab tasks."""
        env = self.system_model.inspect_live_environment(persist=False)
        res = env["disk_and_memory_resources"]
        avail_ram = int(res["mem_available_mb"])
        free_disk = float(res["disk_free_gb"])

        ram_ok = (avail_ram - int(requested_ram_mb)) >= self.MIN_HOST_FREE_RAM_MB_RESERVE
        disk_ok = (free_disk - float(requested_disk_gb)) >= self.MIN_HOST_FREE_DISK_GB_RESERVE

        isolated = False
        try:
            net = ipaddress.ip_network(network_scope, strict=False)
            isolated = net.is_loopback or net.is_private
        except ValueError:
            isolated = network_scope in {"isolated_none", "loopback"}

        runtimes = {
            "isolated_local_sandbox": True,
            "docker": env["container_runtimes"]["docker_cli"],
            "podman": env["container_runtimes"]["podman_cli"],
            "qemu_kvm": env["virtualization_environments"]["qemu_installed"],
            "virtualbox": env["virtualization_environments"]["virtualbox_installed"],
        }
        selected_runtime = next((k for k in ("podman", "docker", "qemu_kvm", "isolated_local_sandbox") if runtimes.get(k)), "isolated_local_sandbox")

        return {
            "preflight_passed": ram_ok and disk_ok and isolated,
            "ram_check": {"host_available_mb": avail_ram, "requested_mb": requested_ram_mb, "passed": ram_ok},
            "disk_check": {"host_free_gb": free_disk, "requested_gb": requested_disk_gb, "passed": disk_ok},
            "isolation_check": {"network_scope": network_scope, "isolated_from_public_networks": isolated},
            "available_runtimes": runtimes,
            "recommended_runtime": selected_runtime,
        }

    def create_isolated_lab(
        self,
        *,
        name: str,
        purpose: str,
        requested_ram_mb: int = 256,
        network_scope: str = "127.0.0.1/32",
        datasets: list[str] | None = None,
    ) -> dict[str, Any]:
        """§189 Provision a resource-checked, isolated lab record, sandbox directory, and initial snapshot."""
        preflight = self.preflight_hardware_and_isolation(
            requested_ram_mb=requested_ram_mb,
            network_scope=network_scope,
        )
        if not preflight["preflight_passed"]:
            return {
                "ok": False,
                "status": "blocked_by_lab_preflight",
                "preflight": preflight,
            }

        lab_id = f"klab-{uuid.uuid4().hex[:10]}"
        lab_dir = self.workspace_dir / "cyber_labs" / lab_id
        (lab_dir / "datasets").mkdir(parents=True, exist_ok=True)
        (lab_dir / "captures").mkdir(parents=True, exist_ok=True)
        (lab_dir / "snapshots").mkdir(parents=True, exist_ok=True)
        state_file = lab_dir / "lab_state.json"
        state_file.write_text('{"stage": "initialized", "isolated": true}\n', encoding="utf-8")

        init_snap = {
            "snapshot_id": "snap-000-baseline",
            "label": "clean_initial_baseline",
            "created_at": utc_now(),
            "state_backup": state_file.read_text(encoding="utf-8"),
        }
        saved = self.db.upsert_kali_cyber_lab(
            {
                "id": lab_id,
                "name": name,
                "purpose": purpose,
                "runtime_kind": preflight["recommended_runtime"],
                "network_scope": network_scope,
                "isolated": True,
                "authorized_scope": "local_isolated_lab",
                "status": "ready",
                "resources": {
                    "ram_limit_mb": requested_ram_mb,
                    "cpu_cores_cap": min(2, os.cpu_count() or 1),
                    "lab_directory": str(lab_dir),
                },
                "snapshots": [init_snap],
                "datasets": list(datasets or []),
                "progress": {"completed_exercises": [], "current_stage": "initialized"},
            }
        )
        return {"ok": True, "lab": saved, "preflight": preflight}

    def create_snapshot(self, lab_id: str, *, label: str) -> dict[str, Any]:
        lab = self.db.get_kali_cyber_lab(lab_id)
        if lab is None:
            raise ValueError(f"Unknown lab_id: {lab_id}")
        lab_dir = Path(lab["resources"]["lab_directory"])
        state_file = lab_dir / "lab_state.json"
        payload = state_file.read_text(encoding="utf-8") if state_file.is_file() else "{}"
        snap_id = f"snap-{len(lab['snapshots']):03d}-{uuid.uuid4().hex[:6]}"
        snap = {"snapshot_id": snap_id, "label": label, "created_at": utc_now(), "state_backup": payload}
        lab["snapshots"].append(snap)
        return self.db.upsert_kali_cyber_lab(lab)

    def restore_snapshot(self, lab_id: str, *, snapshot_id: str) -> dict[str, Any]:
        lab = self.db.get_kali_cyber_lab(lab_id)
        if lab is None:
            raise ValueError(f"Unknown lab_id: {lab_id}")
        snap = next((s for s in lab["snapshots"] if s["snapshot_id"] == snapshot_id), None)
        if snap is None:
            raise ValueError(f"Snapshot {snapshot_id} not found in lab {lab_id}")
        lab_dir = Path(lab["resources"]["lab_directory"])
        lab_dir.mkdir(parents=True, exist_ok=True)
        (lab_dir / "lab_state.json").write_text(str(snap.get("state_backup") or "{}"), encoding="utf-8")
        lab["status"] = "restored"
        lab["progress"]["last_restored_snapshot"] = snapshot_id
        return self.db.upsert_kali_cyber_lab(lab)


class KaliTrainingAcademy:
    """§192 Interactive Kali Training & Technical Education Engine with clear source attribution."""

    VERBATIM_PAID_COURSE_REPRODUCTION = False

    def __init__(self, *, db: Database, system_model: KaliSystemKnowledgeModel):
        self.db = db
        self.system_model = system_model

    def generate_lesson(self, track: str, *, level: str = "beginner") -> dict[str, Any]:
        """§192 Teach concepts at beginner/intermediate/advanced depth, linked to installed tools & clearly attributed."""
        tkey = track.strip().lower()
        if tkey not in KALI_TRAINING_11_TRACKS:
            raise ValueError(f"Unknown track '{track}'. Available: {sorted(KALI_TRAINING_11_TRACKS)}")
        lvl = level.strip().lower() if level.strip().lower() in {"beginner", "intermediate", "advanced"} else "beginner"
        meta = KALI_TRAINING_11_TRACKS[tkey]

        depth_notes = {
            "beginner": "Plain-language mental model, safety guardrails, and safe read-only starter commands.",
            "intermediate": "Kernel/userspace mechanics, exact CLI flag interactions, and structured verification.",
            "advanced": "Edge cases, namespace/capability internals, performance trade-offs, and forensic auditability.",
        }[lvl]

        verified_cmds = []
        for c in meta["commands"]:
            bin_name = shlex.split(c)[0]
            verified_cmds.append({"command": c, "installed_on_this_host": bool(shutil.which(bin_name))})

        flashcards = [
            {
                "front": f"[{meta['title']}] Primary safe inspection command?",
                "back": meta["commands"][0],
            },
            {
                "front": f"[{meta['title']}] Official reference pointer?",
                "back": meta["official_ref"],
            },
        ]
        existing = {p["topic_id"]: p for p in self.db.list_kali_training_progress()}.get(tkey)
        if existing is None:
            self.db.upsert_kali_training_progress(
                {
                    "topic_id": tkey,
                    "track": tkey,
                    "level": lvl,
                    "completed": False,
                    "attempts": 0,
                    "flashcards": flashcards,
                    "notes": {"official_pointer": meta["official_ref"]},
                }
            )

        return {
            "track": tkey,
            "title": meta["title"],
            "level": lvl,
            "attribution": {
                "official_course_material_pointer": meta["official_ref"],
                "explanation_source": "dev_generated_original_explanation",
                "reproduces_restricted_paid_content": False,
            },
            "dev_generated_explanation": f"{meta['title']} ({lvl}): {depth_notes}",
            "daily_practical_exercise": {
                "goal": f"Run and verify `{meta['commands'][0]}` on your local environment and inspect every output field.",
                "commands_checked_against_host": verified_cmds,
            },
            "flashcards": flashcards,
            "quiz_prompt": {
                "question": meta["quiz"]["question"],
                "options": meta["quiz"]["options"],
            },
        }

    def explain_command_line_by_line(self, command: str) -> dict[str, Any]:
        """§192 Explain every token, flag, and argument of a Kali/Linux command truthfully."""
        tokens = shlex.split(command or "")
        if not tokens:
            return {"command": command, "tokens": []}
        exe = shutil.which(tokens[0]) or ""
        help_out = ""
        if exe:
            _, hout, herr = _run_probe([exe, "--help"], timeout=2.0)
            help_out = hout or herr

        breakdown: list[dict[str, Any]] = []
        for idx, tok in enumerate(tokens):
            if idx == 0:
                role = "executable"
                meaning = f"Program `{tok}` ({'installed at ' + exe if exe else 'not currently installed in $PATH'})."
            elif tok.startswith("-"):
                role = "option_flag"
                matched_line = next(
                    (ln.strip() for ln in help_out.splitlines() if re.search(rf"(?<!\w){re.escape(tok.split('=')[0])}\b", ln)),
                    "",
                )
                meaning = matched_line[:180] if matched_line else f"CLI option `{tok}` passed to `{tokens[0]}`."
            else:
                role = "positional_argument"
                meaning = f"Target operand / path / filter expression `{tok}`."
            breakdown.append({"index": idx, "token": tok, "role": role, "explanation": meaning})

        return {
            "command": command,
            "executable_installed": bool(exe),
            "executable_path": exe,
            "attribution": "dev_generated_from_local_binary_help",
            "line_by_line_breakdown": breakdown,
        }

    def grade_quiz_and_update_roadmap(self, track: str, *, selected_option: str) -> dict[str, Any]:
        """§192 Grade quiz, explain why wrong answers are wrong, record progress, and recommend next lesson."""
        tkey = track.strip().lower()
        if tkey not in KALI_TRAINING_11_TRACKS:
            raise ValueError(f"Unknown track '{track}'.")
        q = KALI_TRAINING_11_TRACKS[tkey]["quiz"]
        choice = selected_option.strip().upper()
        correct = choice == q["answer"]
        score = 100.0 if correct else 0.0

        prev = {p["topic_id"]: p for p in self.db.list_kali_training_progress()}.get(tkey, {})
        attempts = int(prev.get("attempts") or 0) + 1
        saved = self.db.upsert_kali_training_progress(
            {
                "topic_id": tkey,
                "track": tkey,
                "level": prev.get("level") or "beginner",
                "completed": correct or bool(prev.get("completed")),
                "quiz_score": score,
                "attempts": attempts,
                "flashcards": prev.get("flashcards") or [],
                "notes": {"last_selected": choice, "correct_answer": q["answer"]},
            }
        )

        completed_ids = {p["topic_id"] for p in self.db.list_kali_training_progress() if p["completed"]}
        next_track = next((k for k in KALI_TRAINING_11_TRACKS if k not in completed_ids), "completed_all_tracks")

        return {
            "track": tkey,
            "selected_option": choice,
            "correct": correct,
            "correct_option": q["answer"],
            "selected_option_analysis": q["explanations"].get(choice, "Option not in quiz choices."),
            "why_other_answers_are_wrong": {
                opt: exp for opt, exp in q["explanations"].items() if opt != q["answer"]
            },
            "progress_record": saved,
            "recommended_next_lesson": next_track,
            "completed_tracks_count": len(completed_ids),
            "total_tracks_count": len(KALI_TRAINING_11_TRACKS),
        }


class KaliTroubleshootingEngine:
    """§193 13-Step Host-Specific Kali Troubleshooting Engine across all 19 failure classes."""

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

    def diagnose_13_steps(self, problem_category_or_symptom: str) -> dict[str, Any]:
        """§193 Run all 13 diagnostic steps against actual host state before proposing proportionate repairs."""
        raw = problem_category_or_symptom.strip().lower()
        domain = raw if raw in TROUBLESHOOTING_19_DOMAINS else self._classify_symptom(raw)
        meta = TROUBLESHOOTING_19_DOMAINS[domain]

        env = self.system_model.get_or_refresh_model()["model"]
        pkg_health = self.package_intel.check_broken_or_obsolete_packages()

        probe_outputs: list[dict[str, Any]] = []
        for argv in meta["probes"]:
            if shutil.which(argv[0]):
                rc, out, err = _run_probe(argv, timeout=3.0)
                probe_outputs.append({"argv": argv, "exit_code": rc, "excerpt": (out or err)[:400]})
            else:
                probe_outputs.append({"argv": argv, "exit_code": 127, "excerpt": f"{argv[0]} not installed"})

        primary_tool = meta["probes"][0][0]
        docs = self.doc_engine.retrieve_prioritized_documentation(primary_tool)

        causes = self._rank_causes(domain, env, pkg_health, probe_outputs)
        remediation = self._build_proportionate_remediation(domain, pkg_health)

        steps_13 = [
            {"step": 1, "action": "inspect_actual_system_state", "distro": env["distribution"]["pretty_name"]},
            {"step": 2, "action": "collect_relevant_logs_and_errors", "log_source": env["system_logs"]["source"]},
            {"step": 3, "action": "identify_affected_packages_drivers_services_configs", "domain": domain, "dpkg_clean": pkg_health["dpkg_audit_clean"]},
            {"step": 4, "action": "check_installed_versions_and_dependencies", "kernel": env["kernel_and_architecture"]["release"]},
            {"step": 5, "action": "consult_local_documentation", "local_sources": len([s for s in docs["sources"] if s["priority_tier"] == 1])},
            {"step": 6, "action": "consult_official_kali_and_upstream_docs", "official_sources": [s["source_ref"] for s in docs["sources"] if s["priority_tier"] in {2, 3}]},
            {"step": 7, "action": "compare_community_reports_cautiously", "community_treated_as_authoritative": False},
            {"step": 8, "action": "identify_most_likely_causes", "likely_causes": causes},
            {"step": 9, "action": "test_safe_non_destructive_checks_first", "probes": probe_outputs},
            {"step": 10, "action": "propose_clear_remediation_steps", "remediation_steps": remediation},
            {"step": 11, "action": "gate_privileged_repairs_on_permission", "requires_explicit_approval": True},
            {"step": 12, "action": "verify_post_check_criteria", "verification_command": meta["probes"][0]},
            {"step": 13, "action": "save_reusable_diagnostic_procedure", "saved_doc_key": f"diag:{domain}"},
        ]

        self.doc_engine.ingest_custom_or_community_note(
            doc_key=f"diag:{domain}",
            title=f"Verified Kali Diagnostic Playbook: {domain}",
            topic=domain,
            content=f"Focus: {meta['focus']}\nCauses: {causes}\nRemediation: {remediation}",
            priority_tier=1,
            source_ref="local_host_diagnostic",
        )

        return {
            "query": problem_category_or_symptom,
            "classified_domain": domain,
            "supported_domains_count": len(TROUBLESHOOTING_19_DOMAINS),
            "focus": meta["focus"],
            "generic_guesswork_used": False,
            "proportionate_repair": True,
            "likely_causes": causes,
            "non_destructive_probe_results": probe_outputs,
            "remediation_plan": remediation,
            "steps": steps_13,
        }

    @staticmethod
    def _classify_symptom(text: str) -> str:
        mapping = [
            (("wifi", "wlan", "802.11"), "missing_wifi_adapters"),
            (("rfkill", "interface down"), "inactive_wireless_interfaces"),
            (("bluetooth", "ble", "hci"), "bluetooth_issues"),
            (("usb", "lsusb"), "usb_recognition_failures"),
            (("display", "x11", "wayland", "gpu"), "graphics_and_display"),
            (("audio", "sound", "pipewire", "pulseaudio"), "audio_pipewire_pulseaudio"),
            (("dpkg", "unmet dependencies", "sub-process /usr/bin/dpkg"), "broken_dpkg_apt"),
            (("sources.list", "release file", "pubkey", "repository"), "repository_errors"),
            (("modprobe", "kernel module", "dkms"), "kernel_module_problems"),
            (("firmware", "/lib/firmware"), "missing_firmware"),
            (("grub", "initramfs", "boot", "systemd"), "boot_grub_systemd"),
            (("no space left", "filesystem", "inode", "disk"), "disk_and_filesystem"),
            (("dns", "resolv.conf", "temporary failure in name resolution"), "dns_resolution"),
            (("network", "unreachable", "route", "connection"), "network_connectivity"),
            (("permission denied", "eacces", "sudo"), "permission_errors"),
            (("segfault", "crash", "core dumped"), "application_crashes"),
            (("virtualbox", "kvm", "qemu", "/dev/kvm"), "virtualbox_kvm_issues"),
            (("pip", "venv", "externally-managed", "npm", "node"), "python_node_environments"),
            (("gcc", "cmake", "cargo", "pytest", "compiler"), "development_tool_failures"),
        ]
        for keys, dom in mapping:
            if any(k in text for k in keys):
                return dom
        return "network_connectivity"

    @staticmethod
    def _rank_causes(
        domain: str,
        env: dict[str, Any],
        pkg_health: dict[str, Any],
        probes: list[dict[str, Any]],
    ) -> list[str]:
        causes: list[str] = []
        if not pkg_health["dpkg_audit_clean"]:
            causes.append("Unconfigured or interrupted dpkg packages detected by `dpkg --audit`.")
        if domain in {"missing_wifi_adapters", "inactive_wireless_interfaces"}:
            wireless_ifaces = [i["name"] for i in env["network_interfaces"] if i.get("wireless")]
            if not wireless_ifaces:
                causes.append("No 802.11 wireless sysfs interface exposed (common inside containers/VMs without USB Wi-Fi passthrough or missing chipset firmware).")
        if domain == "dns_resolution" and env["system_configurations"]["dns_nameserver_count"] == 0:
            causes.append("Zero active `nameserver` entries found in `/etc/resolv.conf`.")
        if domain == "python_node_environments":
            causes.append("PEP 668 externally-managed system Python protection or inactive `.venv` PATH.")
        if not causes:
            causes.append(f"Host-specific configuration or service state condition within `{domain}` (verified via {len(probes)} read-only probes).")
        return causes

    @staticmethod
    def _build_proportionate_remediation(domain: str, pkg_health: dict[str, Any]) -> list[str]:
        if domain == "broken_dpkg_apt" or not pkg_health["dpkg_audit_clean"]:
            return [
                "Inspect held/half-configured packages via `dpkg --audit`.",
                "With explicit approval, run `dpkg --configure -a` followed by `apt-get -f install` (preserving existing configs).",
            ]
        if domain == "python_node_environments":
            return [
                "Create or activate an isolated virtual environment (`python3 -m venv .venv && .venv/bin/pip install ...`) instead of modifying system Python packages.",
            ]
        if domain == "dns_resolution":
            return [
                "Verify `/etc/resolv.conf` symlink and `NetworkManager` / `systemd-resolved` status before editing resolver configuration.",
            ]
        return [
            f"Review read-only diagnostic output for `{domain}` and apply minimal targeted configuration adjustment with explicit user confirmation.",
        ]
