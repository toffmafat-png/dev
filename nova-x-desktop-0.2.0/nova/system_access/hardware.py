"""§149 Universal System & Hardware Access, §150 Driver & Firmware Intelligence,
and §151 Hardware Control & Device Operations.

Inspects actual Linux interfaces (`/proc`, `/sys`, `lsblk`, `ip`, `lspci`,
`lsusb`, `lsmod`, `dmesg`, `udevadm`, `aplay`, `xrandr`, etc.) without fragile
assumptions, distinguishing:
- `detected`, `active`, `supported`, `error`, `restricted_access`, and `unexposed`
- ordinary user privileges, hardware-group permissions, administrative privileges,
  and operations unexposed by the OS/virtualization boundary.
"""
from __future__ import annotations

import grp
import json
import os
import platform
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nova.db import Database
from nova.system_access.privilege import PrivilegedHelperClient

# §150 Step 8: Explicit 5-layer driver/firmware/interface taxonomy.
DEVICE_LAYER_TAXONOMY: dict[str, str] = {
    "kernel_driver": "In-kernel subsystem code (built-in or modular) binding to a bus device ID via the Linux driver model to manage interrupts, DMA, and registers.",
    "kernel_module": "Dynamically loadable `.ko` object (`/lib/modules/$(uname -r)`) inserted or removed at runtime via `modprobe`.",
    "firmware_package": "Binary/microcode blob under `/lib/firmware` uploaded onto hardware (Wi-Fi, GPU, Bluetooth, NIC) by a kernel driver during device initialization.",
    "userspace_driver": "Unprivileged or group-scoped daemon/library (e.g., PipeWire/ALSA plugins, libusb/SANE scanners, Mesa Vulkan/OpenGL ICDs) communicating over `/dev` nodes.",
    "application_device_interface": "High-level OS/session API exposed to applications (POSIX sockets, V4L2 `/dev/video*`, PipeWire/XDG portals, DRM/KMS, Evdev/libinput).",
}

# Known Debian/Kali firmware packages indexed by common kernel firmware prefixes.
KNOWN_FIRMWARE_PACKAGES: dict[str, dict[str, str]] = {
    "iwlwifi": {"package": "firmware-iwlwifi", "class": "network", "vendor": "Intel Wireless"},
    "rtlwifi": {"package": "firmware-realtek", "class": "network", "vendor": "Realtek"},
    "rtl_nic": {"package": "firmware-realtek", "class": "network", "vendor": "Realtek Ethernet"},
    "rtl_bt": {"package": "firmware-realtek", "class": "bluetooth", "vendor": "Realtek Bluetooth"},
    "ath10k": {"package": "firmware-atheros", "class": "network", "vendor": "Qualcomm Atheros"},
    "brcm": {"package": "firmware-brcm80211", "class": "network", "vendor": "Broadcom"},
    "amdgpu": {"package": "firmware-amd-graphics", "class": "graphics", "vendor": "AMD"},
    "radeon": {"package": "firmware-amd-graphics", "class": "graphics", "vendor": "AMD"},
    "i915": {"package": "firmware-misc-nonfree", "class": "graphics", "vendor": "Intel Graphics"},
    "nvidia": {"package": "firmware-misc-nonfree", "class": "graphics", "vendor": "NVIDIA"},
    "sof": {"package": "firmware-sof-signed", "class": "audio", "vendor": "Sound Open Firmware"},
}


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _read_text_safe(path: Path, max_chars: int = 8192) -> tuple[str, str]:
    """Return `(content, access_state)` where `access_state` is `ok`, `restricted`, or `missing`."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:max_chars].strip(), "ok"
    except PermissionError:
        return "", "restricted"
    except OSError:
        return "", "missing"


def _run_probe(argv: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    env = {**os.environ, "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False, env=env)
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)


def _user_groups() -> set[str]:
    names: set[str] = set()
    try:
        for gid in os.getgroups():
            try:
                names.add(grp.getgrgid(gid).gr_name)
            except KeyError:
                continue
    except OSError:
        pass
    return names


@dataclass
class HardwareDeviceRecord:
    device_id: str
    name: str
    device_type: str
    manufacturer: str = ""
    driver: str = ""
    kernel_module: str = ""
    firmware_info: str = ""
    privilege_tier: str = "ordinary_user"  # ordinary_user | hardware_group | administrative | unexposed_by_os
    required_permission: str = "user_read"
    status_category: str = "detected"  # active | detected | supported | error | restricted_access | unexposed
    diagnostic_summary: str = ""
    supported_operations: tuple[str, ...] = ("inspect_status",)
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "name": self.name,
            "device_type": self.device_type,
            "manufacturer": self.manufacturer,
            "driver": self.driver,
            "kernel_module": self.kernel_module,
            "firmware_info": self.firmware_info,
            "privilege_tier": self.privilege_tier,
            "required_permission": self.required_permission,
            "status_category": self.status_category,
            "diagnostic_summary": self.diagnostic_summary,
            "supported_operations": list(self.supported_operations),
            "attributes": dict(self.attributes),
        }


class HardwareInventoryEngine:
    """§149 Comprehensive, honest Linux hardware discovery & searchable Hardware Explorer."""

    def __init__(self, *, db: Database) -> None:
        self.db = db
        self._last_snapshot: dict[str, Any] | None = None

    def discover(self, *, refresh: bool = True) -> dict[str, Any]:
        if self._last_snapshot is not None and not refresh:
            return self._last_snapshot

        groups = _user_groups()
        devices: list[HardwareDeviceRecord] = []

        # 1. CPU, memory, cache & topology
        devices.extend(self._probe_cpu_and_memory())
        # 2. Motherboard, BIOS/UEFI & firmware
        devices.extend(self._probe_motherboard_firmware())
        # 3. PCI / PCIe
        devices.extend(self._probe_pci())
        # 4. USB controllers & attached devices
        devices.extend(self._probe_usb())
        # 5–6. Storage devices & SATA/NVMe/SCSI controllers
        devices.extend(self._probe_storage())
        # 7–8. Graphics & displays
        devices.extend(self._probe_graphics_displays(groups))
        # 9. Ethernet, Wi-Fi & interface statistics
        devices.extend(self._probe_network_interfaces())
        # 10. Bluetooth
        devices.extend(self._probe_bluetooth())
        # 11. Audio devices
        devices.extend(self._probe_audio(groups))
        # 12. Cameras & V4L2 capture
        devices.extend(self._probe_cameras(groups))
        # 13. Input devices (keyboard, mouse, touchpad)
        devices.extend(self._probe_input(groups))
        # 14. Battery, charging, thermal & power sensors
        devices.extend(self._probe_power_thermal())
        # 16. Serial, TTY & GPIO interfaces
        devices.extend(self._probe_serial_gpio(groups))
        # 17. Virtualization & virtual hardware
        devices.extend(self._probe_virtualization())

        loaded_modules = self.enumerate_kernel_modules()
        kernel_log_probe = self.inspect_kernel_firmware_errors()

        counts_by_status: dict[str, int] = {}
        counts_by_type: dict[str, int] = {}
        for dev in devices:
            counts_by_status[dev.status_category] = counts_by_status.get(dev.status_category, 0) + 1
            counts_by_type[dev.device_type] = counts_by_type.get(dev.device_type, 0) + 1

        snapshot = {
            "collected_at": _iso(),
            "kernel_release": platform.release(),
            "architecture": platform.machine(),
            "effective_uid": os.geteuid() if hasattr(os, "geteuid") else -1,
            "user_groups": sorted(groups),
            "device_count": len(devices),
            "counts_by_status": counts_by_status,
            "counts_by_type": counts_by_type,
            "loaded_kernel_modules": loaded_modules,
            "kernel_firmware_probe": kernel_log_probe,
            "devices": [d.to_dict() for d in devices],
        }
        self._last_snapshot = snapshot
        return snapshot

    def search(
        self,
        query: str = "",
        *,
        device_type: str = "",
        status_category: str = "",
        refresh: bool = False,
    ) -> dict[str, Any]:
        snap = self.discover(refresh=refresh)
        q = query.strip().lower()
        dtype = device_type.strip().lower()
        scat = status_category.strip().lower()
        matched: list[dict[str, Any]] = []
        for dev in snap["devices"]:
            if dtype and dev["device_type"].lower() != dtype:
                continue
            if scat and dev["status_category"].lower() != scat:
                continue
            if q:
                hay = " ".join(
                    [
                        dev["device_id"],
                        dev["name"],
                        dev["device_type"],
                        dev["manufacturer"],
                        dev["driver"],
                        dev["kernel_module"],
                        dev["diagnostic_summary"],
                    ]
                ).lower()
                if q not in hay:
                    continue
            matched.append(dev)
        return {
            "query": query,
            "device_type": device_type,
            "status_category": status_category,
            "total_discovered": snap["device_count"],
            "match_count": len(matched),
            "results": matched,
        }

    def _probe_cpu_and_memory(self) -> list[HardwareDeviceRecord]:
        out: list[HardwareDeviceRecord] = []
        cpu_txt, _ = _read_text_safe(Path("/proc/cpuinfo"), max_chars=32_000)
        model_name = platform.processor() or "Processor"
        vendor = ""
        logical_cores = os.cpu_count() or 1
        cache_size = ""
        flags: list[str] = []
        for ln in cpu_txt.splitlines():
            if ":" not in ln:
                continue
            k, v = [p.strip() for p in ln.split(":", 1)]
            if k == "model name" and v:
                model_name = v
            elif k == "vendor_id" and v:
                vendor = v
            elif k == "cache size" and v:
                cache_size = v
            elif k == "flags" and v and not flags:
                flags = v.split()[:25]

        l1_l3_caches: list[str] = []
        cpu0_cache = Path("/sys/devices/system/cpu/cpu0/cache")
        if cpu0_cache.is_dir():
            for idx_dir in sorted(cpu0_cache.glob("index*")):
                lvl, _ = _read_text_safe(idx_dir / "level")
                sz, _ = _read_text_safe(idx_dir / "size")
                ctype, _ = _read_text_safe(idx_dir / "type")
                if lvl and sz:
                    l1_l3_caches.append(f"L{lvl}-{ctype}:{sz}")

        out.append(
            HardwareDeviceRecord(
                device_id="cpu:0",
                name=model_name,
                device_type="cpu",
                manufacturer=vendor,
                driver="linux-cpufreq",
                status_category="active",
                diagnostic_summary=f"{logical_cores} logical core(s); cache={', '.join(l1_l3_caches) or cache_size or 'unreported'}",
                supported_operations=("inspect_status", "read_sensors"),
                attributes={"logical_cores": logical_cores, "caches": l1_l3_caches, "sample_flags": flags[:12]},
            )
        )

        mem_txt, _ = _read_text_safe(Path("/proc/meminfo"))
        mem_kv: dict[str, int] = {}
        for ln in mem_txt.splitlines():
            parts = ln.replace(":", "").split()
            if len(parts) >= 2 and parts[1].isdigit():
                mem_kv[parts[0]] = int(parts[1])
        total_mb = mem_kv.get("MemTotal", 0) // 1024
        avail_mb = mem_kv.get("MemAvailable", 0) // 1024
        out.append(
            HardwareDeviceRecord(
                device_id="memory:system_ram",
                name=f"System Memory ({total_mb} MB)",
                device_type="memory",
                status_category="active",
                diagnostic_summary=f"Total={total_mb} MB, Available={avail_mb} MB, SwapTotal={mem_kv.get('SwapTotal', 0) // 1024} MB",
                supported_operations=("inspect_status", "read_sensors"),
                attributes={"total_mb": total_mb, "available_mb": avail_mb, "swap_total_mb": mem_kv.get("SwapTotal", 0) // 1024},
            )
        )
        return out

    def _probe_motherboard_firmware(self) -> list[HardwareDeviceRecord]:
        dmi = Path("/sys/devices/virtual/dmi/id")
        efi = Path("/sys/firmware/efi")
        boot_mode = "UEFI" if efi.exists() else "BIOS_or_VirtualFirmware"
        if dmi.is_dir():
            board_vendor, st1 = _read_text_safe(dmi / "board_vendor")
            board_name, _ = _read_text_safe(dmi / "board_name")
            bios_ver, st2 = _read_text_safe(dmi / "bios_version")
            if st1 == "restricted" or st2 == "restricted":
                return [
                    HardwareDeviceRecord(
                        device_id="firmware:dmi",
                        name="Motherboard / SMBIOS Firmware",
                        device_type="firmware",
                        privilege_tier="administrative",
                        required_permission="root_or_dmi_read",
                        status_category="restricted_access",
                        diagnostic_summary=f"Boot interface={boot_mode}; detailed DMI serial/table attributes restricted to root.",
                    )
                ]
            return [
                HardwareDeviceRecord(
                    device_id="firmware:dmi",
                    name=f"{board_vendor} {board_name}".strip() or "System Board & Firmware",
                    device_type="firmware",
                    manufacturer=board_vendor,
                    firmware_info=f"{boot_mode} {bios_ver}".strip(),
                    status_category="active",
                    diagnostic_summary=f"Firmware mode={boot_mode}, BIOS/UEFI version={bios_ver or 'unknown'}",
                )
            ]
        return [
            HardwareDeviceRecord(
                device_id="firmware:platform",
                name="System Firmware / SMBIOS",
                device_type="firmware",
                privilege_tier="unexposed_by_os",
                status_category="unexposed",
                firmware_info=boot_mode,
                diagnostic_summary="DMI sysfs table is not exposed by this kernel/container environment.",
            )
        ]

    def _probe_pci(self) -> list[HardwareDeviceRecord]:
        out: list[HardwareDeviceRecord] = []
        pci_root = Path("/sys/bus/pci/devices")
        if pci_root.is_dir():
            for dev_dir in sorted(pci_root.iterdir())[:40]:
                ven, _ = _read_text_safe(dev_dir / "vendor")
                did, _ = _read_text_safe(dev_dir / "device")
                cls_code, _ = _read_text_safe(dev_dir / "class")
                drv = ""
                drv_link = dev_dir / "driver"
                if drv_link.is_symlink():
                    drv = Path(os.readlink(drv_link)).name
                out.append(
                    HardwareDeviceRecord(
                        device_id=f"pci:{dev_dir.name}",
                        name=f"PCI Device {ven}:{did} ({cls_code})",
                        device_type="pci",
                        manufacturer=ven,
                        driver=drv,
                        kernel_module=drv,
                        status_category="active" if drv else "detected",
                        diagnostic_summary=f"BDF={dev_dir.name}, driver={drv or 'unbound'}",
                        supported_operations=("inspect_status", "read_logs"),
                    )
                )
        elif shutil.which("lspci"):
            rc, stdout, _ = _run_probe(["lspci", "-k"])
            if rc == 0 and stdout:
                for ln in stdout.splitlines()[:30]:
                    if not ln.startswith("\t") and " " in ln:
                        bdf, desc = ln.split(" ", 1)
                        out.append(
                            HardwareDeviceRecord(
                                device_id=f"pci:{bdf}",
                                name=desc.strip(),
                                device_type="pci",
                                status_category="detected",
                                diagnostic_summary=f"Discovered via lspci ({bdf})",
                            )
                        )
        if not out:
            out.append(
                HardwareDeviceRecord(
                    device_id="pci:bus",
                    name="PCI / PCIe Bus",
                    device_type="pci",
                    privilege_tier="unexposed_by_os",
                    status_category="unexposed",
                    diagnostic_summary="No `/sys/bus/pci/devices` entries or `lspci` bus exposed in this environment.",
                )
            )
        return out

    def _probe_usb(self) -> list[HardwareDeviceRecord]:
        out: list[HardwareDeviceRecord] = []
        usb_root = Path("/sys/bus/usb/devices")
        if usb_root.is_dir():
            for dev_dir in sorted(usb_root.iterdir())[:30]:
                prod, _ = _read_text_safe(dev_dir / "product")
                mfg, _ = _read_text_safe(dev_dir / "manufacturer")
                vid, _ = _read_text_safe(dev_dir / "idVendor")
                pid, _ = _read_text_safe(dev_dir / "idProduct")
                if not (vid or prod):
                    continue
                drv = Path(os.readlink(dev_dir / "driver")).name if (dev_dir / "driver").is_symlink() else "usb"
                out.append(
                    HardwareDeviceRecord(
                        device_id=f"usb:{dev_dir.name}",
                        name=prod or f"USB {vid}:{pid}",
                        device_type="usb",
                        manufacturer=mfg,
                        driver=drv,
                        kernel_module=drv,
                        status_category="active",
                        diagnostic_summary=f"USB ID {vid}:{pid} on {dev_dir.name}",
                    )
                )
        if not out:
            out.append(
                HardwareDeviceRecord(
                    device_id="usb:bus",
                    name="USB Bus Enumeration",
                    device_type="usb",
                    privilege_tier="unexposed_by_os",
                    status_category="unexposed",
                    diagnostic_summary="No USB host controllers exposed under `/sys/bus/usb/devices`.",
                )
            )
        return out

    def _probe_storage(self) -> list[HardwareDeviceRecord]:
        out: list[HardwareDeviceRecord] = []
        if shutil.which("lsblk"):
            rc, stdout, _ = _run_probe(["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,MODEL,TRAN"])
            if rc == 0 and stdout:
                try:
                    parsed = json.loads(stdout)
                    for blk in parsed.get("blockdevices") or []:
                        bname = str(blk.get("name") or "disk")
                        if bname.startswith("loop"):
                            continue
                        tran = str(blk.get("tran") or "block")
                        model = str(blk.get("model") or "").strip()
                        size = str(blk.get("size") or "")
                        out.append(
                            HardwareDeviceRecord(
                                device_id=f"storage:{bname}",
                                name=f"{model or bname} ({size})".strip(),
                                device_type="storage",
                                driver=tran,
                                status_category="active",
                                diagnostic_summary=f"Block device /dev/{bname}, size={size}, transport={tran}",
                                supported_operations=("inspect_status", "diagnostic_test"),
                                attributes=blk,
                            )
                        )
                except ValueError:
                    pass
        for scsi in sorted(Path("/sys/class/scsi_host").glob("host*"))[:8] if Path("/sys/class/scsi_host").is_dir() else []:
            proc_name, _ = _read_text_safe(scsi / "proc_name")
            state, _ = _read_text_safe(scsi / "state")
            out.append(
                HardwareDeviceRecord(
                    device_id=f"storage_ctrl:{scsi.name}",
                    name=f"SCSI/SATA Storage Host {scsi.name}",
                    device_type="storage_controller",
                    driver=proc_name or "scsi_mod",
                    kernel_module=proc_name or "scsi_mod",
                    status_category="active" if state in {"running", ""} else "detected",
                    diagnostic_summary=f"Controller driver={proc_name or 'scsi'}, state={state or 'online'}",
                )
            )
        return out

    def _probe_graphics_displays(self, groups: set[str]) -> list[HardwareDeviceRecord]:
        out: list[HardwareDeviceRecord] = []
        drm = Path("/sys/class/drm")
        if drm.is_dir():
            for card in sorted(drm.glob("card[0-9]*")):
                if "-" in card.name:
                    status, _ = _read_text_safe(card / "status")
                    out.append(
                        HardwareDeviceRecord(
                            device_id=f"display:{card.name}",
                            name=f"Display Output {card.name}",
                            device_type="display",
                            status_category="active" if status == "connected" else "detected",
                            diagnostic_summary=f"Connector status={status or 'unknown'}",
                        )
                    )
                else:
                    drv = Path(os.readlink(card / "device" / "driver")).name if (card / "device" / "driver").is_symlink() else ""
                    perm_ok = ("video" in groups or "render" in groups or os.access(f"/dev/dri/{card.name}", os.R_OK))
                    out.append(
                        HardwareDeviceRecord(
                            device_id=f"gpu:{card.name}",
                            name=f"DRM Graphics Adapter {card.name}",
                            device_type="graphics",
                            driver=drv,
                            kernel_module=drv,
                            privilege_tier="ordinary_user" if perm_ok else "hardware_group",
                            required_permission="video/render group",
                            status_category="active" if drv else "detected",
                            diagnostic_summary=f"DRM card={card.name}, driver={drv or 'software'}",
                        )
                    )
        if not out:
            disp_env = os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY") or ""
            out.append(
                HardwareDeviceRecord(
                    device_id="gpu:software_or_headless",
                    name="Graphics & Display Subsystem",
                    device_type="graphics",
                    driver="software_rasterizer",
                    status_category="active" if disp_env else "unexposed",
                    diagnostic_summary=(
                        f"Session display={disp_env}; no dedicated `/sys/class/drm` GPU exposed."
                        if disp_env
                        else "Headless/container environment without dedicated GPU or physical display connector."
                    ),
                )
            )
        return out

    def _probe_network_interfaces(self) -> list[HardwareDeviceRecord]:
        out: list[HardwareDeviceRecord] = []
        stats_map = self._parse_proc_net_dev()
        net_root = Path("/sys/class/net")
        if net_root.is_dir():
            for iface_dir in sorted(net_root.iterdir()):
                ifname = iface_dir.name
                oper, _ = _read_text_safe(iface_dir / "operstate")
                mac, st_mac = _read_text_safe(iface_dir / "address")
                is_wireless = (iface_dir / "wireless").exists()
                drv = ""
                if (iface_dir / "device" / "driver").is_symlink():
                    drv = Path(os.readlink(iface_dir / "device" / "driver")).name
                st = stats_map.get(ifname, {})
                is_up = oper in {"up", "unknown"} and (ifname == "lo" or st.get("rx_bytes", 0) >= 0)
                out.append(
                    HardwareDeviceRecord(
                        device_id=f"net:{ifname}",
                        name=f"{'Wireless' if is_wireless else 'Network'} Interface {ifname}",
                        device_type="wireless" if is_wireless else "network",
                        driver=drv or ("loopback" if ifname == "lo" else "virtual_net"),
                        kernel_module=drv,
                        privilege_tier="ordinary_user",
                        required_permission="user_read (cap_net_admin to toggle)",
                        status_category="active" if is_up and oper != "down" else "detected",
                        diagnostic_summary=f"operstate={oper or 'unknown'}, rx_bytes={st.get('rx_bytes', 0)}, tx_bytes={st.get('tx_bytes', 0)}",
                        supported_operations=("inspect_status", "interface_stats", "check_connectivity", "toggle_interface"),
                        attributes={"operstate": oper, "mac": mac if st_mac == "ok" else "", **st},
                    )
                )
        return out

    @staticmethod
    def _parse_proc_net_dev() -> dict[str, dict[str, int]]:
        txt, _ = _read_text_safe(Path("/proc/net/dev"), max_chars=16_000)
        stats: dict[str, dict[str, int]] = {}
        for ln in txt.splitlines()[2:]:
            if ":" not in ln:
                continue
            iface, rest = ln.split(":", 1)
            cols = rest.split()
            if len(cols) >= 10:
                stats[iface.strip()] = {
                    "rx_bytes": int(cols[0]),
                    "rx_packets": int(cols[1]),
                    "rx_errors": int(cols[2]),
                    "tx_bytes": int(cols[8]),
                    "tx_packets": int(cols[9]),
                    "tx_errors": int(cols[10]) if len(cols) > 10 else 0,
                }
        return stats

    def _probe_bluetooth(self) -> list[HardwareDeviceRecord]:
        bt_root = Path("/sys/class/bluetooth")
        if bt_root.is_dir() and any(bt_root.iterdir()):
            out = []
            for hci in sorted(bt_root.iterdir()):
                drv = Path(os.readlink(hci / "device" / "driver")).name if (hci / "device" / "driver").is_symlink() else "btusb"
                out.append(
                    HardwareDeviceRecord(
                        device_id=f"bluetooth:{hci.name}",
                        name=f"Bluetooth Adapter {hci.name}",
                        device_type="bluetooth",
                        driver=drv,
                        kernel_module=drv,
                        status_category="active",
                        diagnostic_summary=f"HCI controller {hci.name}",
                    )
                )
            return out
        return [
            HardwareDeviceRecord(
                device_id="bluetooth:none",
                name="Bluetooth Subsystem",
                device_type="bluetooth",
                status_category="unexposed",
                diagnostic_summary="No Bluetooth HCI controller detected under `/sys/class/bluetooth`.",
            )
        ]

    def _probe_audio(self, groups: set[str]) -> list[HardwareDeviceRecord]:
        cards_txt, _ = _read_text_safe(Path("/proc/asound/cards"))
        if cards_txt and "no soundcards" not in cards_txt.lower():
            return [
                HardwareDeviceRecord(
                    device_id="audio:alsa",
                    name="ALSA / PipeWire Audio Subsystem",
                    device_type="audio",
                    driver="snd",
                    privilege_tier="ordinary_user" if "audio" in groups else "hardware_group",
                    required_permission="audio group / session seat",
                    status_category="active",
                    diagnostic_summary=cards_txt.splitlines()[0][:180],
                    supported_operations=("inspect_status", "manage_audio"),
                )
            ]
        return [
            HardwareDeviceRecord(
                device_id="audio:none",
                name="Audio Subsystem",
                device_type="audio",
                status_category="unexposed",
                diagnostic_summary="No hardware ALSA soundcards exposed (`/proc/asound/cards`).",
            )
        ]

    def _probe_cameras(self, groups: set[str]) -> list[HardwareDeviceRecord]:
        v4l = Path("/sys/class/video4linux")
        if v4l.is_dir() and any(v4l.iterdir()):
            out = []
            for vdev in sorted(v4l.iterdir()):
                vname, _ = _read_text_safe(vdev / "name")
                devnode = Path("/dev") / vdev.name
                accessible = devnode.exists() and os.access(devnode, os.R_OK)
                out.append(
                    HardwareDeviceRecord(
                        device_id=f"camera:{vdev.name}",
                        name=vname or f"Video Capture {vdev.name}",
                        device_type="camera",
                        driver="uvcvideo",
                        privilege_tier="ordinary_user" if accessible else "hardware_group",
                        required_permission="video group",
                        status_category="active" if accessible else "restricted_access",
                        diagnostic_summary=f"V4L2 node /dev/{vdev.name} (readable={accessible})",
                    )
                )
            return out
        return [
            HardwareDeviceRecord(
                device_id="camera:none",
                name="Video Capture (V4L2)",
                device_type="camera",
                status_category="unexposed",
                diagnostic_summary="No `/sys/class/video4linux` capture devices present.",
            )
        ]

    def _probe_input(self, groups: set[str]) -> list[HardwareDeviceRecord]:
        inp_txt, _ = _read_text_safe(Path("/proc/bus/input/devices"))
        out: list[HardwareDeviceRecord] = []
        for idx, block in enumerate([b for b in inp_txt.split("\n\n") if b.strip()][:10]):
            m_name = re.search(r'N: Name="([^"]+)"', block)
            dev_name = m_name.group(1) if m_name else f"Input Device {idx}"
            out.append(
                HardwareDeviceRecord(
                    device_id=f"input:event{idx}",
                    name=dev_name,
                    device_type="input",
                    driver="evdev",
                    privilege_tier="ordinary_user" if "input" in groups else "hardware_group",
                    required_permission="session seat or input group for raw evdev",
                    status_category="active",
                    diagnostic_summary=f"Input device registered in `/proc/bus/input/devices` ({dev_name})",
                )
            )
        if not out:
            out.append(
                HardwareDeviceRecord(
                    device_id="input:virtual",
                    name="Input Subsystem",
                    device_type="input",
                    status_category="detected",
                    diagnostic_summary="No discrete physical `/proc/bus/input/devices` entries listed.",
                )
            )
        return out

    def _probe_power_thermal(self) -> list[HardwareDeviceRecord]:
        out: list[HardwareDeviceRecord] = []
        ps_root = Path("/sys/class/power_supply")
        if ps_root.is_dir():
            for ps in sorted(ps_root.iterdir()):
                ptype, _ = _read_text_safe(ps / "type")
                cap, _ = _read_text_safe(ps / "capacity")
                status, _ = _read_text_safe(ps / "status")
                out.append(
                    HardwareDeviceRecord(
                        device_id=f"power:{ps.name}",
                        name=f"Power Supply {ps.name} ({ptype or 'power'})",
                        device_type="power",
                        status_category="active",
                        diagnostic_summary=f"status={status or 'online'}, capacity={cap + '%' if cap else 'n/a'}",
                        supported_operations=("inspect_status", "read_sensors"),
                        attributes={"type": ptype, "capacity": cap, "status": status},
                    )
                )
        th_root = Path("/sys/class/thermal")
        if th_root.is_dir():
            for tz in sorted(th_root.glob("thermal_zone*"))[:8]:
                ttype, _ = _read_text_safe(tz / "type")
                temp_raw, _ = _read_text_safe(tz / "temp")
                temp_c = round(int(temp_raw) / 1000.0, 1) if temp_raw.lstrip("-").isdigit() else None
                out.append(
                    HardwareDeviceRecord(
                        device_id=f"thermal:{tz.name}",
                        name=f"Thermal Sensor {ttype or tz.name}",
                        device_type="thermal",
                        status_category="active",
                        diagnostic_summary=f"temp={temp_c}°C" if temp_c is not None else "thermal zone detected",
                        supported_operations=("inspect_status", "read_sensors"),
                        attributes={"temp_celsius": temp_c, "zone": tz.name},
                    )
                )
        return out

    def _probe_serial_gpio(self, groups: set[str]) -> list[HardwareDeviceRecord]:
        out: list[HardwareDeviceRecord] = []
        tty_root = Path("/sys/class/tty")
        if tty_root.is_dir():
            hw_ttys = [p.name for p in sorted(tty_root.glob("ttyS*"))[:4]] + [p.name for p in sorted(tty_root.glob("ttyUSB*"))[:4]]
            if hw_ttys:
                out.append(
                    HardwareDeviceRecord(
                        device_id="serial:uart",
                        name=f"Serial / UART Ports ({', '.join(hw_ttys)})",
                        device_type="serial",
                        driver="serial8250",
                        privilege_tier="ordinary_user" if "dialout" in groups else "hardware_group",
                        required_permission="dialout group",
                        status_category="detected",
                        diagnostic_summary=f"Exposed serial nodes: {', '.join(hw_ttys)}",
                    )
                )
        if Path("/sys/class/gpio").is_dir():
            out.append(
                HardwareDeviceRecord(
                    device_id="gpio:sysfs",
                    name="GPIO Interface",
                    device_type="gpio",
                    privilege_tier="hardware_group",
                    required_permission="gpio group or root",
                    status_category="supported",
                    diagnostic_summary="GPIO sysfs class present.",
                )
            )
        return out

    def _probe_virtualization(self) -> list[HardwareDeviceRecord]:
        cpu_txt, _ = _read_text_safe(Path("/proc/cpuinfo"), max_chars=8000)
        is_hypervisor = "hypervisor" in cpu_txt
        virtio_devs = list(Path("/sys/bus/virtio/devices").iterdir()) if Path("/sys/bus/virtio/devices").is_dir() else []
        return [
            HardwareDeviceRecord(
                device_id="virt:environment",
                name="Virtualization & Container Topology",
                device_type="virtualization",
                driver="virtio" if virtio_devs else ("hypervisor_guest" if is_hypervisor else "bare_metal_or_container"),
                status_category="active" if (is_hypervisor or virtio_devs) else "detected",
                diagnostic_summary=f"hypervisor_flag={is_hypervisor}, virtio_devices={len(virtio_devs)}",
                attributes={"hypervisor_cpu_flag": is_hypervisor, "virtio_device_count": len(virtio_devs)},
            )
        ]

    @staticmethod
    def enumerate_kernel_modules() -> dict[str, Any]:
        txt, access = _read_text_safe(Path("/proc/modules"), max_chars=64_000)
        modules: list[dict[str, Any]] = []
        if access == "ok" and txt:
            for ln in txt.splitlines()[:120]:
                parts = ln.split()
                if len(parts) >= 3:
                    modules.append({"name": parts[0], "size_bytes": int(parts[1]) if parts[1].isdigit() else 0, "instances": int(parts[2]) if parts[2].isdigit() else 0})
            return {"source": "/proc/modules", "access": "ok", "count": len(modules), "modules": modules}
        sys_mod = Path("/sys/module")
        if sys_mod.is_dir():
            names = [p.name for p in sorted(sys_mod.iterdir()) if p.is_dir()][:120]
            return {
                "source": "/sys/module",
                "access": "ok",
                "count": len(names),
                "modules": [{"name": n, "size_bytes": 0, "instances": 1} for n in names],
            }
        return {"source": "unavailable", "access": access, "count": 0, "modules": []}

    @staticmethod
    def inspect_kernel_firmware_errors(extra_log_lines: list[str] | None = None) -> dict[str, Any]:
        lines: list[str] = list(extra_log_lines or [])
        access = "provided_evidence" if lines else "unprobed"
        if shutil.which("dmesg"):
            rc, out, err = _run_probe(["dmesg", "--nopager"], timeout=3.0)
            if rc == 0 and out:
                lines.extend(out.splitlines()[-400:])
                access = "ok"
            elif "operation not permitted" in err.lower() or rc != 0:
                access = "restricted_dmesg_sysctl"

        firmware_failures: list[dict[str, str]] = []
        driver_errors: list[dict[str, str]] = []
        fw_re = re.compile(r"(?i)(?:direct firmware load for|firmware: failed to load)\s+([^\s]+)")
        err_re = re.compile(r"(?i)\b(probe of [^\s]+ failed with error -?\d+|device descriptor read/64, error -?\d+|iommu.*fault)\b")
        for ln in lines:
            m_fw = fw_re.search(ln)
            if m_fw:
                blob = m_fw.group(1)
                prefix = blob.split("/")[0].split("-")[0].lower()
                pkg_meta = KNOWN_FIRMWARE_PACKAGES.get(prefix, {})
                firmware_failures.append(
                    {
                        "firmware_blob": blob,
                        "candidate_package": pkg_meta.get("package", ""),
                        "device_class": pkg_meta.get("class", "unknown"),
                        "log_line": ln.strip()[:260],
                    }
                )
            elif err_re.search(ln):
                driver_errors.append({"log_line": ln.strip()[:260]})
        return {
            "kernel_log_access": access,
            "missing_firmware": firmware_failures,
            "driver_init_errors": driver_errors,
        }


class DriverIntelligenceEngine:
    """§150 12-Step Driver & Firmware Diagnostics, Repair Proposal, and Post-Change Verification."""

    def __init__(
        self,
        *,
        db: Database,
        inventory: HardwareInventoryEngine,
        privileged_client: PrivilegedHelperClient,
    ) -> None:
        self.db = db
        self.inventory = inventory
        self.privileged = privileged_client

    def explain_taxonomy(self) -> dict[str, str]:
        return dict(DEVICE_LAYER_TAXONOMY)

    def diagnose(
        self,
        *,
        device_id: str = "",
        diagnostic_evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run the §150 evidence-first diagnostic workflow without jumping to unverified assumptions."""
        snap = self.inventory.discover(refresh=False)
        ev = dict(diagnostic_evidence or {})
        extra_logs = [str(x) for x in (ev.get("kernel_logs") or [])]
        kprobe = self.inventory.inspect_kernel_firmware_errors(extra_log_lines=extra_logs)

        target_dev: dict[str, Any] | None = None
        if device_id:
            target_dev = next((d for d in snap["devices"] if d["device_id"] == device_id), None)
        if target_dev is None and ev.get("simulated_device"):
            sdev = dict(ev["simulated_device"])
            target_dev = {
                "device_id": str(sdev.get("device_id") or "pci:0000:03:00.0"),
                "name": str(sdev.get("name") or "Wireless Network Controller"),
                "device_type": str(sdev.get("device_type") or "wireless"),
                "driver": str(sdev.get("driver") or ""),
                "kernel_module": str(sdev.get("kernel_module") or ""),
                "status_category": str(sdev.get("status_category") or "error"),
            }

        findings: list[dict[str, Any]] = []
        candidate_repairs: list[dict[str, Any]] = []

        target_dtype = str(target_dev.get("device_type") or "").lower() if target_dev else ""
        compatible_classes = (
            {target_dtype, "network"}
            if target_dtype in {"wireless", "network"}
            else ({target_dtype} if target_dtype else set())
        )
        relevant_firmware = [
            fw
            for fw in kprobe["missing_firmware"]
            if extra_logs or not compatible_classes or fw["device_class"] in compatible_classes
        ]

        # Evidence check 1: Missing firmware blobs in kernel ring buffer / collected logs
        for fw in relevant_firmware:
            pkg = fw["candidate_package"]
            pkg_available = self._check_apt_package_known(pkg) if pkg else False
            findings.append(
                {
                    "kind": "missing_firmware_evidence",
                    "layer": "firmware_package",
                    "firmware_blob": fw["firmware_blob"],
                    "log_evidence": fw["log_line"],
                    "candidate_package": pkg,
                    "package_in_local_cache": pkg_available,
                }
            )
            if pkg:
                candidate_repairs.append(
                    {
                        "action_id": f"install_firmware:{pkg}",
                        "helper_operation": "package.apt_install_firmware",
                        "params": {"package": pkg},
                        "layer": "firmware_package",
                        "risk_level": "high",
                        "reversible": True,
                        "recovery_path": f"`apt-get remove {pkg}` and reload driver module if device initialization regresses.",
                        "rationale": f"Kernel log explicitly reported failed firmware load `{fw['firmware_blob']}` matching `{pkg}` on kernel {snap['kernel_release']}.",
                    }
                )

        # Evidence check 2: Device present with unbound driver vs service/permissions issue
        if target_dev is not None:
            drv = str(target_dev.get("driver") or "")
            expected_mod = str(ev.get("expected_module") or target_dev.get("kernel_module") or "")
            loaded_names = {m["name"] for m in snap["loaded_kernel_modules"]["modules"]}
            if not drv and expected_mod:
                is_loaded = expected_mod in loaded_names
                findings.append(
                    {
                        "kind": "unbound_kernel_module",
                        "layer": "kernel_module",
                        "device_id": target_dev["device_id"],
                        "expected_module": expected_mod,
                        "currently_loaded": is_loaded,
                    }
                )
                candidate_repairs.append(
                    {
                        "action_id": f"modprobe:{expected_mod}",
                        "helper_operation": "driver.modprobe_load",
                        "params": {"module": expected_mod},
                        "layer": "kernel_module",
                        "risk_level": "medium",
                        "reversible": True,
                        "recovery_path": f"Unload module cleanly with `modprobe -r {expected_mod}`.",
                        "rationale": f"Device `{target_dev['device_id']}` has no bound driver and module `{expected_mod}` is not bound.",
                    }
                )
            elif drv and not relevant_firmware and not kprobe["driver_init_errors"]:
                findings.append(
                    {
                        "kind": "driver_bound_check_userspace_or_permissions",
                        "layer": "application_device_interface",
                        "device_id": target_dev["device_id"],
                        "driver": drv,
                        "note": "Driver is already bound and no missing-firmware error was observed; inspect userspace permissions/services before touching kernel modules.",
                    }
                )

        return {
            "diagnosed_at": _iso(),
            "kernel_release": snap["kernel_release"],
            "target_device": target_dev,
            "kernel_log_access": kprobe["kernel_log_access"],
            "loaded_module_count": snap["loaded_kernel_modules"]["count"],
            "findings": findings,
            "candidate_repairs": candidate_repairs,
            "layer_taxonomy": DEVICE_LAYER_TAXONOMY,
            "evidence_sufficient_for_driver_change": bool(candidate_repairs),
        }

    def apply_and_verify_repair(
        self,
        *,
        device_id: str,
        device_class: str,
        issue_summary: str,
        helper_operation: str,
        params: dict[str, Any],
        recovery_path: str,
        operator_approved: bool = False,
        dry_run: bool = False,
        post_verify_fn: Callable[[], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """§150 Steps 10–12: Apply authorized repair AND verify real post-change device state."""
        exec_res = self.privileged.request(
            helper_operation,
            params,
            requester="user_ui" if operator_approved else "ai_model",
            operator_approved=operator_approved,
            dry_run=dry_run,
        )

        if dry_run or not exec_res.get("ok"):
            saved = self.db.save_driver_repair(
                {
                    "device_id": device_id,
                    "device_class": device_class,
                    "issue_summary": issue_summary,
                    "proposed_action": f"{helper_operation}({params})",
                    "risk_level": str(exec_res.get("risk_level") or "medium"),
                    "recovery_path": recovery_path,
                    "applied": False,
                    "verified_functional": False,
                    "status": str(exec_res.get("status") or "not_applied"),
                    "evidence": {"helper_result": exec_res},
                }
            )
            return saved

        # Never claim fixed merely because command returned 0: verify actual device functionality!
        if post_verify_fn is not None:
            verification = post_verify_fn()
        else:
            refreshed = self.inventory.search(device_id, refresh=True)
            dev_now = refreshed["results"][0] if refreshed["results"] else {}
            verification = {
                "functional": dev_now.get("status_category") == "active" and bool(dev_now.get("driver")),
                "observed_device": dev_now,
            }

        verified_ok = bool(verification.get("functional"))
        saved = self.db.save_driver_repair(
            {
                "device_id": device_id,
                "device_class": device_class,
                "issue_summary": issue_summary,
                "proposed_action": f"{helper_operation}({params})",
                "risk_level": "medium",
                "recovery_path": recovery_path,
                "applied": True,
                "verified_functional": verified_ok,
                "status": "verified_fixed" if verified_ok else "applied_unverified_or_still_failing",
                "evidence": {"helper_result": exec_res, "post_verification": verification},
            }
        )
        return saved

    @staticmethod
    def _check_apt_package_known(package_name: str) -> bool:
        if not package_name or not shutil.which("apt-cache"):
            return False
        rc, out, _ = _run_probe(["apt-cache", "policy", package_name], timeout=3.0)
        return rc == 0 and "Candidate:" in out and "Candidate: (none)" not in out


class DeviceOperationsController:
    """§151 Unified Hardware Control & Device Operations with Dry-Run and Consequence Guards."""

    FORBIDDEN_DESTRUCTIVE_TARGETS: frozenset[str] = frozenset(
        {"storage_controller_reset", "detach_root_disk", "flash_motherboard_bios"}
    )

    def __init__(
        self,
        *,
        inventory: HardwareInventoryEngine,
        privileged_client: PrivilegedHelperClient,
        permission_check: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        self.inventory = inventory
        self.privileged = privileged_client
        self._permission_check = permission_check
        self._baseline_device_ids: set[str] = set()

    def execute_operation(
        self,
        device_id: str,
        operation: str,
        *,
        params: dict[str, Any] | None = None,
        dry_run: bool = False,
        operator_approved: bool = False,
    ) -> dict[str, Any]:
        opts = dict(params or {})
        if operation in self.FORBIDDEN_DESTRUCTIVE_TARGETS:
            return {
                "ok": False,
                "status": "blocked_critical_hardware",
                "reason": f"Operation '{operation}' risks storage corruption or unrecoverable hardware state and is blocked.",
            }

        snap = self.inventory.discover(refresh=True)
        dev = next((d for d in snap["devices"] if d["device_id"] == device_id), None)
        if dev is None:
            return {"ok": False, "status": "device_not_found", "reason": f"Device '{device_id}' was not found in current inventory."}

        if operation not in dev["supported_operations"]:
            return {
                "ok": False,
                "status": "operation_not_supported",
                "reason": f"Device '{device_id}' supports {dev['supported_operations']}, not '{operation}'.",
            }

        if operation == "inspect_status":
            return {"ok": True, "status": "ok", "dry_run": dry_run, "device": dev}

        if operation == "read_sensors":
            return {"ok": True, "status": "ok", "dry_run": dry_run, "device_id": device_id, "readings": dev["attributes"]}

        if operation == "interface_stats":
            iface = device_id.removeprefix("net:")
            stats = self.inventory._parse_proc_net_dev().get(iface, {})
            return {"ok": True, "status": "ok", "dry_run": dry_run, "interface": iface, "statistics": stats}

        if operation == "check_connectivity":
            iface = device_id.removeprefix("net:")
            oper = dev["attributes"].get("operstate", "unknown")
            routes_txt, _ = _read_text_safe(Path("/proc/net/route"))
            has_route = iface in routes_txt
            return {
                "ok": True,
                "status": "ok",
                "dry_run": dry_run,
                "interface": iface,
                "operstate": oper,
                "in_routing_table": has_route,
            }

        if operation == "toggle_interface":
            iface = device_id.removeprefix("net:")
            target_state = str(opts.get("state") or "up").lower()
            routes_txt, _ = _read_text_safe(Path("/proc/net/route"))
            is_default_route = any(ln.startswith(f"{iface}\t00000000") for ln in routes_txt.splitlines())
            if target_state == "down" and (iface == "lo" or is_default_route) and not dry_run and not operator_approved:
                return {
                    "ok": False,
                    "status": "blocked_active_primary_connection",
                    "consequence_warning": f"Interface '{iface}' carries loopback or the active default route; disabling it drops system connectivity.",
                }
            return self.privileged.request(
                "network.interface_toggle",
                {"interface": iface, "state": target_state},
                requester="user_ui" if operator_approved else "ai_model",
                operator_approved=operator_approved,
                dry_run=dry_run,
            )

        if operation == "diagnostic_test":
            return {
                "ok": True,
                "status": "ok",
                "dry_run": dry_run,
                "device_id": device_id,
                "diagnostic": dev["diagnostic_summary"],
            }

        return {"ok": False, "status": "unimplemented_operation", "reason": f"Operation '{operation}' has no handler."}

    def restart_user_service(self, unit_name: str, *, dry_run: bool = False, approved: bool = False) -> dict[str, Any]:
        clean = unit_name.strip()
        if not re.match(r"^[A-Za-z0-9._@-]+\.service$", clean):
            return {"ok": False, "status": "invalid_unit", "reason": "Must specify a valid `<name>.service` unit."}
        if dry_run:
            return {"ok": True, "status": "dry_run_ok", "dry_run": True, "planned_argv": ["systemctl", "--user", "restart", clean]}
        if not approved:
            return {"ok": False, "status": "approval_required", "reason": f"Restarting user service '{clean}' requires approval."}
        rc, out, err = _run_probe(["systemctl", "--user", "restart", clean], timeout=10.0)
        return {"ok": rc == 0, "status": "succeeded" if rc == 0 else "failed", "exit_code": rc, "stdout": out, "stderr": err}

    def detect_device_changes(self) -> dict[str, Any]:
        snap = self.inventory.discover(refresh=True)
        current_ids = {d["device_id"] for d in snap["devices"]}
        if not self._baseline_device_ids:
            self._baseline_device_ids = set(current_ids)
            return {"connected": [], "disconnected": [], "total_tracked": len(current_ids)}
        added = sorted(current_ids - self._baseline_device_ids)
        removed = sorted(self._baseline_device_ids - current_ids)
        self._baseline_device_ids = set(current_ids)
        return {"connected": added, "disconnected": removed, "total_tracked": len(current_ids)}
