"""§181 Deep Kali Linux System Knowledge & §190 Kali Tool Compatibility and Package Intelligence."""
from __future__ import annotations

import grp
import hashlib
import os
import platform as py_platform
import pwd
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from nova.db import Database
from nova.observability import Redactor

APPLICATION_LIFECYCLE_STATES: tuple[str, ...] = (
    "installed",
    "available",
    "configured",
    "running",
    "functional",
    "unavailable",
)

KALI_SYSTEM_DIMENSIONS: tuple[str, ...] = (
    "distribution",
    "kernel_and_architecture",
    "desktop_environment",
    "installed_applications",
    "cli_utilities",
    "installed_kali_tools",
    "package_dependencies",
    "repositories_and_sources",
    "kernel_modules",
    "hardware_and_drivers",
    "running_services",
    "environment_variables",
    "network_interfaces",
    "system_configurations",
    "development_environments",
    "system_logs",
    "user_permissions",
    "disk_and_memory_resources",
    "virtualization_environments",
    "container_runtimes",
    "system_policies",
)

MASSIVE_KALI_METAPACKAGES: frozenset[str] = frozenset(
    {
        "kali-linux-everything",
        "kali-linux-large",
        "kali-tools-all",
        "kali-linux-full",
    }
)

SAFE_ENV_KEYS: tuple[str, ...] = (
    "SHELL",
    "LANG",
    "LC_ALL",
    "TERM",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "DESKTOP_SESSION",
    "WAYLAND_DISPLAY",
    "DISPLAY",
    "VIRTUAL_ENV",
    "USER",
    "LOGNAME",
)

# Representative Kali tool commands used to intersect live $PATH/dpkg state without ever assuming presence.
KNOWN_KALI_TOOL_COMMANDS: tuple[str, ...] = (
    "nmap",
    "tcpdump",
    "tshark",
    "wireshark",
    "ss",
    "ip",
    "nc",
    "ncat",
    "curl",
    "openssl",
    "dig",
    "whois",
    "tor",
    "torsocks",
    "ssh",
    "scp",
    "rsync",
    "nikto",
    "gobuster",
    "ffuf",
    "sqlmap",
    "john",
    "hashcat",
    "hydra",
    "aircrack-ng",
    "iw",
    "rfkill",
    "binwalk",
    "radare2",
    "r2",
    "gdb",
    "objdump",
    "strings",
    "strace",
    "lsof",
    "sqlite3",
    "jq",
    "git",
    "python3",
)


def _run_probe(argv: list[str], *, timeout: float = 4.0) -> tuple[int, str, str]:
    """Run a read-only argv probe with no shell, bounded timeout, and sanitized locale."""
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)


def _parse_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    info: dict[str, str] = {}
    if not path.is_file():
        return info
    try:
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return info


def _dpkg_status_fingerprint(status_path: Path = Path("/var/lib/dpkg/status")) -> str:
    try:
        st = status_path.stat()
        return hashlib.sha256(f"{st.st_mtime_ns}:{st.st_size}".encode()).hexdigest()[:24]
    except OSError:
        return "no-dpkg-status"


class KaliSystemKnowledgeModel:
    """§181 Continuously builds and updates a structured local knowledge model of the Kali/Linux host."""

    def __init__(self, *, db: Database, redactor: Redactor | None = None):
        self.db = db
        self.redactor = redactor or Redactor()
        self._last_fingerprint: str = ""

    def inspect_live_environment(self, *, persist: bool = True) -> dict[str, Any]:
        """Inspect all 21 required §181 system dimensions directly from the live OS."""
        os_rel = _parse_os_release()
        debian_ver = ""
        deb_file = Path("/etc/debian_version")
        if deb_file.is_file():
            try:
                debian_ver = deb_file.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                pass

        uname = py_platform.uname()
        distro_id = os_rel.get("ID", "linux").lower()
        is_kali = distro_id == "kali" or "kali" in os_rel.get("PRETTY_NAME", "").lower()

        # 1–3. Distro, Kernel/Arch, Desktop Environment
        distribution = {
            "id": distro_id,
            "name": os_rel.get("NAME", uname.system),
            "pretty_name": os_rel.get("PRETTY_NAME", uname.system),
            "version": os_rel.get("VERSION", os_rel.get("VERSION_ID", debian_ver)),
            "version_id": os_rel.get("VERSION_ID", ""),
            "id_like": os_rel.get("ID_LIKE", ""),
            "debian_base_version": debian_ver,
            "is_kali_linux": is_kali,
        }
        kernel_and_arch = {
            "system": uname.system,
            "release": uname.release,
            "version": uname.version,
            "architecture": uname.machine,
            "dpkg_architecture": _run_probe(["dpkg", "--print-architecture"])[1] if shutil.which("dpkg") else uname.machine,
        }
        desktop_env = {
            "current_desktop": os.environ.get("XDG_CURRENT_DESKTOP", ""),
            "desktop_session": os.environ.get("DESKTOP_SESSION", ""),
            "session_type": os.environ.get("XDG_SESSION_TYPE", "headless" if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) else "graphical"),
            "display": bool(os.environ.get("DISPLAY")),
            "wayland": bool(os.environ.get("WAYLAND_DISPLAY")),
        }

        # 4–6. Desktop Apps, CLI Utilities & Installed Kali Tools
        desktop_apps = self._scan_desktop_entries()
        cli_utils = self._scan_path_executables(limit=250)
        installed_kali_tools = [cmd for cmd in KNOWN_KALI_TOOL_COMMANDS if shutil.which(cmd) is not None]

        # 7–8. Package count/dependencies sample & APT Repositories
        dpkg_count = self._count_dpkg_installed()
        repos = self._scan_apt_repositories()

        # 9–10. Kernel modules & Hardware/Drivers
        kmods = self._read_kernel_modules(limit=60)
        hw = self._inspect_hardware_and_drivers()

        # 11–14. Running services, Safe Env, Network Interfaces & System Configs
        services = self._inspect_running_services(limit=40)
        env_summary = {
            k: str(self.redactor.scrub_text(os.environ[k]))
            for k in SAFE_ENV_KEYS
            if k in os.environ
        }
        env_summary["path_dir_count"] = len([p for p in os.environ.get("PATH", "").split(os.pathsep) if p])
        net_ifaces = self._inspect_network_interfaces()
        sys_configs = self._inspect_system_configurations()

        # 15–18. Dev Environments, System Logs, User Permissions, Disk & RAM
        dev_envs = self._inspect_development_environments()
        logs_summary = self._inspect_system_logs()
        perms = self._inspect_user_permissions()
        resources = self._inspect_disk_and_memory()

        # 19–21. Virtualization, Container Runtimes & System Policies
        virt = self._inspect_virtualization()
        containers = self._inspect_container_runtimes()
        policies = self._inspect_system_policies()

        dpkg_fp = _dpkg_status_fingerprint()
        self._last_fingerprint = dpkg_fp

        snapshot: dict[str, Any] = {
            "dimensions_covered": list(KALI_SYSTEM_DIMENSIONS),
            "dpkg_fingerprint": dpkg_fp,
            "distribution": distribution,
            "kernel_and_architecture": kernel_and_arch,
            "desktop_environment": desktop_env,
            "installed_applications": {"count": len(desktop_apps), "items": desktop_apps[:60]},
            "cli_utilities": {"sampled_count": len(cli_utils), "sample": cli_utils[:80]},
            "installed_kali_tools": {"count": len(installed_kali_tools), "commands": installed_kali_tools},
            "package_dependencies": {"dpkg_installed_packages": dpkg_count, "dpkg_available": bool(shutil.which("dpkg-query"))},
            "repositories_and_sources": repos,
            "kernel_modules": {"loaded_count": len(kmods), "sample": kmods[:40]},
            "hardware_and_drivers": hw,
            "running_services": services,
            "environment_variables": env_summary,
            "network_interfaces": net_ifaces,
            "system_configurations": sys_configs,
            "development_environments": dev_envs,
            "system_logs": logs_summary,
            "user_permissions": perms,
            "disk_and_memory_resources": resources,
            "virtualization_environments": virt,
            "container_runtimes": containers,
            "system_policies": policies,
        }

        if persist:
            self.db.save_kali_system_snapshot(
                {
                    "distro_id": distribution["id"],
                    "distro_version": distribution["version"],
                    "kernel_release": kernel_and_arch["release"],
                    "architecture": kernel_and_arch["architecture"],
                    "dpkg_fingerprint": dpkg_fp,
                    "snapshot": snapshot,
                }
            )
        return snapshot

    def get_or_refresh_model(self, *, force_refresh: bool = False) -> dict[str, Any]:
        """Return latest model, refreshing automatically when dpkg state changed."""
        latest = self.db.latest_kali_system_snapshot()
        current_fp = _dpkg_status_fingerprint()
        if force_refresh or latest is None or latest.get("dpkg_fingerprint") != current_fp:
            fresh = self.inspect_live_environment(persist=True)
            return {"refreshed": True, "reason": "forced_or_package_state_changed", "model": fresh}
        return {"refreshed": False, "reason": "dpkg_fingerprint_unchanged", "model": latest["snapshot"]}

    def classify_application_state(self, command_or_pkg: str) -> dict[str, Any]:
        """§181 Distinguish installed, available, configured, running, functional, and unavailable."""
        target = command_or_pkg.strip()
        if not target or not re.fullmatch(r"[A-Za-z0-9._+\-]+", target):
            return {
                "target": target,
                "primary_state": "unavailable",
                "states": {s: (s == "unavailable") for s in APPLICATION_LIFECYCLE_STATES},
                "reason": "invalid_identifier",
            }
        exe_path = shutil.which(target) or ""
        installed = bool(exe_path)
        pkg_version = ""
        if shutil.which("dpkg-query"):
            rc, out, _ = _run_probe(["dpkg-query", "-W", "-f=${Status}|${Version}", target])
            if rc == 0 and "install ok installed" in out:
                installed = True
                pkg_version = out.split("|", 1)[1] if "|" in out else ""

        available_in_repo = installed
        if not available_in_repo and shutil.which("apt-cache"):
            rc, out, _ = _run_probe(["apt-cache", "policy", target])
            if rc == 0 and "Candidate:" in out and "Candidate: (none)" not in out:
                available_in_repo = True

        config_candidates = [
            Path(f"/etc/{target}"),
            Path(f"/etc/{target}.conf"),
            Path.home() / ".config" / target,
        ]
        configured = installed and (any(p.exists() for p in config_candidates) or bool(exe_path))

        running = self._is_process_running(Path(exe_path).name if exe_path else target)

        functional = False
        probe_output = ""
        if exe_path:
            for flag in ("--version", "-V", "--help"):
                rc, out, err = _run_probe([exe_path, flag], timeout=2.5)
                combined = (out or err).splitlines()
                if rc == 0 or (combined and "not found" not in combined[0].lower()):
                    functional = True
                    probe_output = combined[0][:160] if combined else "ok"
                    break

        unavailable = not installed and not available_in_repo
        if running and functional:
            primary = "running"
        elif functional:
            primary = "functional"
        elif configured and installed:
            primary = "configured"
        elif installed:
            primary = "installed"
        elif available_in_repo:
            primary = "available"
        else:
            primary = "unavailable"

        return {
            "target": target,
            "executable_path": exe_path,
            "package_version": pkg_version,
            "probe_summary": probe_output,
            "primary_state": primary,
            "states": {
                "installed": installed,
                "available": available_in_repo,
                "configured": configured,
                "running": running,
                "functional": functional,
                "unavailable": unavailable,
            },
        }

    @staticmethod
    def _scan_desktop_entries() -> list[dict[str, str]]:
        dirs = [Path("/usr/share/applications"), Path.home() / ".local/share/applications"]
        apps: list[dict[str, str]] = []
        for d in dirs:
            if not d.is_dir():
                continue
            for entry in sorted(d.glob("*.desktop"))[:80]:
                name = ""
                exec_cmd = ""
                categories = ""
                try:
                    for ln in entry.read_text(encoding="utf-8", errors="replace").splitlines():
                        if ln.startswith("Name=") and not name:
                            name = ln.split("=", 1)[1].strip()
                        elif ln.startswith("Exec=") and not exec_cmd:
                            exec_cmd = ln.split("=", 1)[1].strip()
                        elif ln.startswith("Categories=") and not categories:
                            categories = ln.split("=", 1)[1].strip()
                except OSError:
                    continue
                if name:
                    apps.append({"desktop_id": entry.name, "name": name, "exec": exec_cmd, "categories": categories})
        return apps

    @staticmethod
    def _scan_path_executables(limit: int = 250) -> list[str]:
        found: set[str] = set()
        for raw_dir in os.environ.get("PATH", "").split(os.pathsep):
            if not raw_dir:
                continue
            p = Path(raw_dir)
            if not p.is_dir():
                continue
            try:
                for child in p.iterdir():
                    if child.is_file() and os.access(child, os.X_OK):
                        found.add(child.name)
                        if len(found) >= limit:
                            return sorted(found)
            except OSError:
                continue
        return sorted(found)

    @staticmethod
    def _count_dpkg_installed() -> int:
        status = Path("/var/lib/dpkg/status")
        if not status.is_file():
            return 0
        try:
            text = status.read_text(encoding="utf-8", errors="replace")
            return text.count("Status: install ok installed")
        except OSError:
            return 0

    @staticmethod
    def _scan_apt_repositories() -> dict[str, Any]:
        entries: list[str] = []
        sources_files = [Path("/etc/apt/sources.list")]
        sources_d = Path("/etc/apt/sources.list.d")
        if sources_d.is_dir():
            sources_files.extend(sorted(sources_d.glob("*.list")))
            sources_files.extend(sorted(sources_d.glob("*.sources")))
        for sf in sources_files:
            if not sf.is_file():
                continue
            try:
                for ln in sf.read_text(encoding="utf-8", errors="replace").splitlines():
                    s = ln.strip()
                    if s and not s.startswith("#") and (s.startswith(("deb ", "deb-src ", "URIs:"))):
                        entries.append(f"{sf.name}: {s[:200]}")
            except OSError:
                continue
        has_kali_repo = any("kali.org" in e.lower() for e in entries)
        return {"source_count": len(entries), "has_official_kali_repo": has_kali_repo, "sources": entries[:30]}

    @staticmethod
    def _read_kernel_modules(limit: int = 60) -> list[str]:
        mods = Path("/proc/modules")
        if not mods.is_file():
            return []
        try:
            return [ln.split()[0] for ln in mods.read_text(encoding="utf-8", errors="replace").splitlines()[:limit] if ln.strip()]
        except OSError:
            return []

    @staticmethod
    def _inspect_hardware_and_drivers() -> dict[str, Any]:
        cpu_model = ""
        cpu_cores = os.cpu_count() or 1
        try:
            for ln in Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace").splitlines():
                if ln.lower().startswith("model name") and ":" in ln:
                    cpu_model = ln.split(":", 1)[1].strip()
                    break
        except OSError:
            pass
        pci_devices: list[str] = []
        if shutil.which("lspci"):
            rc, out, _ = _run_probe(["lspci"], timeout=3.0)
            if rc == 0:
                pci_devices = out.splitlines()[:25]
        return {"cpu_cores": cpu_cores, "cpu_model": cpu_model or py_platform.processor(), "pci_sample": pci_devices}

    @staticmethod
    def _inspect_running_services(limit: int = 40) -> dict[str, Any]:
        if shutil.which("systemctl"):
            rc, out, _ = _run_probe(
                ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"],
                timeout=3.0,
            )
            if rc == 0 and out:
                names = [ln.split()[0] for ln in out.splitlines()[:limit] if ln.strip()]
                return {"source": "systemctl", "running_count": len(names), "services": names}
        daemons: list[str] = []
        proc_root = Path("/proc")
        if proc_root.is_dir():
            for p in proc_root.iterdir():
                if not p.name.isdigit():
                    continue
                try:
                    comm = (p / "comm").read_text(encoding="utf-8", errors="replace").strip()
                    if comm and comm not in daemons:
                        daemons.append(comm)
                except OSError:
                    continue
                if len(daemons) >= limit:
                    break
        return {"source": "proc_comm", "running_count": len(daemons), "services": daemons}

    @staticmethod
    def _inspect_network_interfaces() -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        net_dir = Path("/sys/class/net")
        if not net_dir.is_dir():
            return out
        for iface in sorted(net_dir.iterdir(), key=lambda p: p.name):
            try:
                oper = (iface / "operstate").read_text(encoding="utf-8").strip()
            except OSError:
                oper = "unknown"
            is_wireless = (iface / "wireless").exists()
            out.append({"name": iface.name, "operstate": oper, "wireless": is_wireless})
        return out

    @staticmethod
    def _inspect_system_configurations() -> dict[str, Any]:
        nameservers = 0
        resolv = Path("/etc/resolv.conf")
        if resolv.is_file():
            try:
                nameservers = sum(
                    1
                    for ln in resolv.read_text(encoding="utf-8", errors="replace").splitlines()
                    if ln.strip().startswith("nameserver ")
                )
            except OSError:
                pass
        ip_forward = ""
        ipf = Path("/proc/sys/net/ipv4/ip_forward")
        if ipf.is_file():
            try:
                ip_forward = ipf.read_text(encoding="utf-8").strip()
            except OSError:
                pass
        return {"dns_nameserver_count": nameservers, "ipv4_forward": ip_forward}

    @staticmethod
    def _inspect_development_environments() -> dict[str, str]:
        probes = {
            "python3": ["python3", "--version"],
            "node": ["node", "--version"],
            "npm": ["npm", "--version"],
            "gcc": ["gcc", "--version"],
            "clang": ["clang", "--version"],
            "rustc": ["rustc", "--version"],
            "go": ["go", "version"],
            "java": ["java", "-version"],
            "git": ["git", "--version"],
            "sqlite3": ["sqlite3", "--version"],
            "cmake": ["cmake", "--version"],
        }
        detected: dict[str, str] = {}
        for name, argv in probes.items():
            if shutil.which(argv[0]):
                rc, out, err = _run_probe(argv, timeout=2.5)
                first = ((out or err).splitlines() or [""])[0].strip()
                if rc == 0 and first:
                    detected[name] = first[:120]
        return detected

    def _inspect_system_logs(self) -> dict[str, Any]:
        dpkg_log = Path("/var/log/dpkg.log")
        if dpkg_log.is_file() and os.access(dpkg_log, os.R_OK):
            try:
                lines = dpkg_log.read_text(encoding="utf-8", errors="replace").splitlines()[-15:]
                return {
                    "source": "/var/log/dpkg.log",
                    "recent_lines": [self.redactor.scrub_text(ln[:200]) for ln in lines],
                }
            except OSError:
                pass
        return {"source": "unavailable_or_restricted", "recent_lines": []}

    @staticmethod
    def _inspect_user_permissions() -> dict[str, Any]:
        uid = os.getuid() if hasattr(os, "getuid") else 1000
        gid = os.getgid() if hasattr(os, "getgid") else 1000
        try:
            username = pwd.getpwuid(uid).pw_name
        except KeyError:
            username = os.environ.get("USER", "unknown")
        groups: list[str] = []
        try:
            for g in os.getgroups():
                try:
                    groups.append(grp.getgrgid(g).gr_name)
                except KeyError:
                    groups.append(str(g))
        except OSError:
            pass
        return {
            "uid": uid,
            "gid": gid,
            "username": username,
            "is_root": uid == 0,
            "groups": sorted(set(groups)),
            "pkexec_available": bool(shutil.which("pkexec")),
            "sudo_available": bool(shutil.which("sudo")),
        }

    @staticmethod
    def _inspect_disk_and_memory() -> dict[str, Any]:
        mem_total_mb = 0
        mem_avail_mb = 0
        try:
            for ln in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
                if ln.startswith("MemTotal:"):
                    mem_total_mb = int(ln.split()[1]) // 1024
                elif ln.startswith("MemAvailable:"):
                    mem_avail_mb = int(ln.split()[1]) // 1024
        except OSError:
            pass
        du = shutil.disk_usage("/")
        return {
            "mem_total_mb": mem_total_mb,
            "mem_available_mb": mem_avail_mb,
            "disk_total_gb": round(du.total / (1024**3), 2),
            "disk_free_gb": round(du.free / (1024**3), 2),
        }

    @staticmethod
    def _inspect_virtualization() -> dict[str, Any]:
        virt_type = "none"
        if shutil.which("systemd-detect-virt"):
            rc, out, _ = _run_probe(["systemd-detect-virt"], timeout=2.0)
            if rc == 0 and out:
                virt_type = out
        return {
            "detected_environment": virt_type,
            "kvm_device_present": Path("/dev/kvm").exists(),
            "qemu_installed": bool(shutil.which("qemu-system-x86_64")),
            "virtualbox_installed": bool(shutil.which("vboxmanage")),
            "libvirt_virsh_installed": bool(shutil.which("virsh")),
        }

    @staticmethod
    def _inspect_container_runtimes() -> dict[str, Any]:
        return {
            "inside_container": Path("/.dockerenv").exists() or Path("/run/.containerenv").exists(),
            "docker_cli": bool(shutil.which("docker")),
            "podman_cli": bool(shutil.which("podman")),
            "lxc_cli": bool(shutil.which("lxc-ls") or shutil.which("lxc")),
        }

    @staticmethod
    def _inspect_system_policies() -> dict[str, Any]:
        cur_umask = os.umask(0o022)
        os.umask(cur_umask)
        return {
            "apparmor_loaded": Path("/sys/module/apparmor").exists(),
            "selinux_fs": Path("/sys/fs/selinux").exists(),
            "umask_octal": oct(cur_umask),
            "nftables_installed": bool(shutil.which("nft")),
            "iptables_installed": bool(shutil.which("iptables")),
            "ufw_installed": bool(shutil.which("ufw")),
        }

    @staticmethod
    def _is_process_running(comm_name: str) -> bool:
        proc_root = Path("/proc")
        if not proc_root.is_dir():
            return False
        for p in proc_root.iterdir():
            if not p.name.isdigit():
                continue
            try:
                if (p / "comm").read_text(encoding="utf-8", errors="replace").strip() == comm_name:
                    return True
            except OSError:
                continue
        return False


class KaliPackageIntelligence:
    """§190 Package & dependency intelligence across APT, DPKG, pip, npm, git & containers."""

    SILENT_REPO_REPLACEMENT_ALLOWED = False
    ALLOW_INDISCRIMINATE_FULL_INSTALL = False

    def __init__(self, *, system_model: KaliSystemKnowledgeModel):
        self.system_model = system_model

    def inspect_package(self, package_or_command: str) -> dict[str, Any]:
        target = package_or_command.strip()
        if not re.fullmatch(r"[A-Za-z0-9._+\-]+", target):
            raise ValueError("Invalid package or command name.")

        is_massive_meta = target.lower() in MASSIVE_KALI_METAPACKAGES
        state = self.system_model.classify_application_state(target)
        arch = _run_probe(["dpkg", "--print-architecture"])[1] if shutil.which("dpkg") else py_platform.machine()

        providing_pkg = ""
        exe = state["executable_path"]
        if exe and shutil.which("dpkg"):
            rc, out, _ = _run_probe(["dpkg", "-S", exe])
            if rc == 0 and ":" in out:
                providing_pkg = out.split(":", 1)[0].strip()
            else:
                real_exe = str(Path(exe).resolve())
                rc2, out2, _ = _run_probe(["dpkg", "-S", real_exe])
                if rc2 == 0 and ":" in out2:
                    providing_pkg = out2.split(":", 1)[0].strip()

        candidate_version = ""
        origin_summary = ""
        if shutil.which("apt-cache"):
            rc, pol_out, _ = _run_probe(["apt-cache", "policy", providing_pkg or target])
            if rc == 0 and pol_out:
                for ln in pol_out.splitlines():
                    s = ln.strip()
                    if s.startswith("Candidate:"):
                        candidate_version = s.split(":", 1)[1].strip()
                    elif s.startswith(("500 http", "500 https", "100 /var/lib/dpkg")):
                        origin_summary = origin_summary or s[:180]

        dependencies: list[str] = []
        missing_dependencies: list[str] = []
        if shutil.which("apt-cache"):
            rc, dep_out, _ = _run_probe(["apt-cache", "depends", providing_pkg or target])
            if rc == 0:
                for ln in dep_out.splitlines():
                    s = ln.strip()
                    if s.startswith("Depends:"):
                        dep_pkg = s.split(":", 1)[1].strip().strip("<>")
                        dependencies.append(dep_pkg)
                        if shutil.which("dpkg-query"):
                            drc, dout, _ = _run_probe(["dpkg-query", "-W", "-f=${Status}", dep_pkg])
                            if drc != 0 or "install ok installed" not in dout:
                                missing_dependencies.append(dep_pkg)

        recommendation = (
            "Discouraged on low-spec hardware: massive Kali metapackage; install only the specific selective tool package needed."
            if is_massive_meta
            else (
                "Already installed and functional; no package installation required."
                if state["states"]["functional"]
                else f"Selective installation command (requires explicit approval): apt-get install --no-install-recommends {providing_pkg or target}"
            )
        )

        return {
            "query": target,
            "providing_package": providing_pkg or (target if state["states"]["installed"] or state["states"]["available"] else ""),
            "host_architecture": arch,
            "lifecycle": state,
            "candidate_version": candidate_version,
            "package_origin": origin_summary,
            "dependencies": dependencies[:30],
            "missing_dependencies": missing_dependencies[:20],
            "is_massive_metapackage": is_massive_meta,
            "selective_low_spec_recommendation": recommendation,
            "prepared_install_argv": (
                []
                if is_massive_meta
                else ["apt-get", "install", "-y", "--no-install-recommends", providing_pkg or target]
            ),
            "requires_approval": True,
            "silent_repo_mutation": False,
        }

    def check_broken_or_obsolete_packages(self) -> dict[str, Any]:
        audit_issues: list[str] = []
        if shutil.which("dpkg"):
            _rc, out, _ = _run_probe(["dpkg", "--audit"])
            if out:
                audit_issues = out.splitlines()[:25]
        return {
            "dpkg_audit_clean": len(audit_issues) == 0,
            "broken_or_unconfigured": audit_issues,
            "ecosystems_available": {
                "apt": bool(shutil.which("apt-get")),
                "dpkg": bool(shutil.which("dpkg")),
                "pip": bool(shutil.which("pip") or shutil.which("pip3")),
                "npm": bool(shutil.which("npm")),
                "git": bool(shutil.which("git")),
                "docker": bool(shutil.which("docker")),
                "podman": bool(shutil.which("podman")),
            },
        }
