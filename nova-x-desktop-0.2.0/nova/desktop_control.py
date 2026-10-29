"""§10 Application and Linux desktop control layer.

Provides modular, optional interaction with the logged-in Kali Linux graphical
session while enforcing:
- Preference for official Linux desktop APIs (`xdg-open`, EWMH `wmctrl`, D-Bus,
  AT-SPI2 accessibility) over fragile raw screen coordinates.
- Detection of locked, headless, or disconnected graphical sessions.
- Explicit separation of `execution_locality="local_desktop"` vs `"cloud"`.
- Central authorization through NOVA X's `AutonomyPolicy`.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nova.tools.registry import ToolDefinition, ToolOutcome

PREFER_ACCESSIBILITY_APIS = True
RAW_SCREEN_COORDINATES_DEFAULT = False

# Curated non-administrative desktop executables eligible for structured launch
# once authorized by the central policy.
DEFAULT_APPROVED_DESKTOP_APPS: frozenset[str] = frozenset(
    {
        "xdg-open",
        "code",
        "codium",
        "gedit",
        "mousepad",
        "kate",
        "thunar",
        "nautilus",
        "dolphin",
        "evince",
        "okular",
        "firefox",
        "chromium",
        "vlc",
        "mpv",
        "gimp",
        "inkscape",
        "blender",
        "openscad",
        "freecad",
        "libreoffice",
    }
)


@dataclass
class DesktopSessionState:
    display_server: str
    has_graphical_session: bool
    session_locked: bool
    accessibility_bus_available: bool
    available_Adapters: tuple[str, ...]
    detail: str

    @property
    def interactive_ready(self) -> bool:
        return self.has_graphical_session and not self.session_locked

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_locality": "local_desktop",
            "display_server": self.display_server,
            "has_graphical_session": self.has_graphical_session,
            "session_locked": self.session_locked,
            "interactive_ready": self.has_graphical_session and not self.session_locked,
            "accessibility_bus_available": self.accessibility_bus_available,
            "available_adapters": list(self.available_Adapters),
            "prefer_accessibility_apis": PREFER_ACCESSIBILITY_APIS,
            "raw_screen_coordinates_default": RAW_SCREEN_COORDINATES_DEFAULT,
            "detail": self.detail,
        }


class LinuxDesktopController:
    """§10 Modular controller for authorized local Linux desktop operations."""

    def __init__(
        self,
        *,
        workspace_root_fn: Callable[[], Path],
        permission_check: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
        approved_apps: set[str] | None = None,
    ) -> None:
        self._workspace_root_fn = workspace_root_fn
        self._permission_check = permission_check
        self.approved_apps = set(approved_apps or DEFAULT_APPROVED_DESKTOP_APPS)

    def inspect_session(self) -> DesktopSessionState:
        wayland = bool(os.environ.get("WAYLAND_DISPLAY"))
        x11 = bool(os.environ.get("DISPLAY"))
        session_type = os.environ.get("XDG_SESSION_TYPE", "").strip().lower()
        if wayland:
            display_server = "wayland"
        elif x11:
            display_server = "x11"
        elif session_type in {"wayland", "x11"}:
            display_server = session_type
        else:
            display_server = "headless"

        has_gui = wayland or x11
        locked = self._detect_session_lock() if has_gui else False
        atspi = bool(os.environ.get("AT_SPI_BUS_ADDRESS")) or bool(shutil.which("gdbus") and has_gui)

        adapters: list[str] = []
        for tool in ("xdg-open", "gdbus", "wmctrl", "xdotool", "notify-send", "loginctl"):
            if shutil.which(tool):
                adapters.append(tool)

        if not has_gui:
            detail = "No active X11/Wayland graphical session detected; GUI actions remain disabled while CLI/headless tools stay available."
        elif locked:
            detail = "Desktop session is currently locked; interactive GUI actions are suspended."
        else:
            detail = f"Active {display_server} session ready via {', '.join(adapters) or 'Qt native shell'}."

        return DesktopSessionState(
            display_server=display_server,
            has_graphical_session=has_gui,
            session_locked=locked,
            accessibility_bus_available=atspi,
            available_Adapters=tuple(adapters),
            detail=detail,
        )

    @staticmethod
    def _detect_session_lock() -> bool:
        session_id = os.environ.get("XDG_SESSION_ID", "").strip()
        loginctl = shutil.which("loginctl")
        if session_id and loginctl:
            try:
                proc = subprocess.run(
                    [loginctl, "show-session", session_id, "-p", "LockedHint", "--value"],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False,
                )
                if proc.returncode == 0 and proc.stdout.strip().lower() == "yes":
                    return True
            except OSError:
                pass
        return os.environ.get("NOVA_SIMULATE_SESSION_LOCKED", "").strip() == "1"

    def list_windows(self) -> dict[str, Any]:
        session = self.inspect_session()
        if not session.has_graphical_session:
            return {"ok": False, "execution_locality": "local_desktop", "windows": [], "reason": "no_graphical_session"}
        if session.session_locked:
            return {"ok": False, "execution_locality": "local_desktop", "windows": [], "reason": "session_locked"}
        wmctrl = shutil.which("wmctrl")
        if not wmctrl:
            return {
                "ok": False,
                "execution_locality": "local_desktop",
                "windows": [],
                "reason": "wmctrl_not_installed",
                "detail": "Install `wmctrl` for EWMH window enumeration on X11/XWayland.",
            }
        proc = subprocess.run([wmctrl, "-l"], capture_output=True, text=True, timeout=4, check=False)
        windows = []
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                parts = line.split(None, 3)
                if len(parts) >= 4:
                    windows.append({"window_id": parts[0], "desktop": parts[1], "host": parts[2], "title": parts[3]})
        return {"ok": proc.returncode == 0, "execution_locality": "local_desktop", "windows": windows}

    def focus_window(self, title_substring: str, *, approved: bool = False) -> dict[str, Any]:
        session = self.inspect_session()
        if not session.has_graphical_session or session.session_locked:
            return {
                "ok": False,
                "execution_locality": "local_desktop",
                "reason": "session_locked" if session.session_locked else "no_graphical_session",
            }
        if not approved and self._permission_check is not None:
            decision = self._permission_check("desktop.focus_window", {"title": title_substring})
            if decision.get("action") in {"deny", "approval_required"} and not decision.get("approved", False):
                return {"ok": False, "execution_locality": "local_desktop", "reason": "approval_required", "policy": decision}
        wmctrl = shutil.which("wmctrl")
        if not wmctrl:
            return {"ok": False, "execution_locality": "local_desktop", "reason": "wmctrl_not_installed"}
        proc = subprocess.run([wmctrl, "-a", title_substring], capture_output=True, text=True, timeout=4, check=False)
        return {"ok": proc.returncode == 0, "execution_locality": "local_desktop", "focused_query": title_substring}

    def open_in_default_app(self, rel_path: str, *, approved: bool = False) -> dict[str, Any]:
        ws = Path(self._workspace_root_fn()).resolve()
        target = (ws / rel_path).resolve()
        if not target.is_relative_to(ws):
            raise PermissionError("Target file must remain inside an approved workspace directory.")
        if not target.exists():
            return {"ok": False, "execution_locality": "local_desktop", "reason": "file_not_found", "path": str(target)}
        session = self.inspect_session()
        if not session.has_graphical_session or session.session_locked:
            return {
                "ok": False,
                "execution_locality": "local_desktop",
                "reason": "session_locked" if session.session_locked else "no_graphical_session",
                "path": str(target),
            }
        if not approved:
            return {"ok": False, "execution_locality": "local_desktop", "reason": "approval_required", "path": str(target)}
        opener = shutil.which("xdg-open")
        if not opener:
            return {"ok": False, "execution_locality": "local_desktop", "reason": "xdg_open_not_installed"}
        proc = subprocess.Popen([opener, str(target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"ok": True, "execution_locality": "local_desktop", "pid": proc.pid, "opened": str(target)}

    def launch_approved_application(self, app_name: str, args: list[str] | None = None, *, approved: bool = False) -> dict[str, Any]:
        clean_name = Path(app_name.strip()).name
        if clean_name not in self.approved_apps:
            return {
                "ok": False,
                "execution_locality": "local_desktop",
                "reason": "application_not_in_approved_list",
                "application": clean_name,
            }
        binary = shutil.which(clean_name)
        if not binary:
            return {"ok": False, "execution_locality": "local_desktop", "reason": "application_not_installed", "application": clean_name}
        session = self.inspect_session()
        if not session.has_graphical_session or session.session_locked:
            return {
                "ok": False,
                "execution_locality": "local_desktop",
                "reason": "session_locked" if session.session_locked else "no_graphical_session",
                "application": clean_name,
            }
        if not approved:
            return {"ok": False, "execution_locality": "local_desktop", "reason": "approval_required", "application": clean_name}
        safe_args = [str(a) for a in (args or [])[:8]]
        proc = subprocess.Popen([binary, *safe_args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"ok": True, "execution_locality": "local_desktop", "application": clean_name, "pid": proc.pid}


class _EmptyArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _DesktopOpenInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rel_path: str = Field(min_length=1, max_length=300, description="Workspace-relative path to open")


def build_desktop_control_tools(controller: LinuxDesktopController) -> list[ToolDefinition]:
    """Register §10 session inspection & approval-gated file-open tools into the central ToolRegistry."""

    async def _inspect(_args: _EmptyArgs, _approved: bool) -> ToolOutcome:
        state = controller.inspect_session().to_dict()
        return ToolOutcome(status="success", summary=state["detail"], data=state)

    async def _open(args: _DesktopOpenInput, approved: bool) -> ToolOutcome:
        try:
            res = controller.open_in_default_app(args.rel_path, approved=approved)
        except PermissionError as exc:
            return ToolOutcome(status="error", summary=str(exc), data={"ok": False, "reason": "permission_denied"})
        if res.get("reason") == "approval_required":
            return ToolOutcome(
                status="approval_required",
                summary=f"Opening '{args.rel_path}' in a desktop application requires operator approval.",
                data=res,
            )
        if not res.get("ok"):
            return ToolOutcome(status="error", summary=f"Desktop open unavailable: {res.get('reason')}", data=res)
        return ToolOutcome(status="success", summary=f"Opened {args.rel_path} on local desktop.", data=res)

    return [
        ToolDefinition(
            name="desktop.inspect_session",
            description="Inspect local Kali Linux graphical session, lock state, and available accessibility/window adapters.",
            parameters=_EmptyArgs.model_json_schema(),
            input_model=_EmptyArgs,
            handler=_inspect,
            permission="desktop.read",
            category="desktop",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="desktop.open_file",
            description="Open a workspace file in its default local desktop application (approval-gated).",
            parameters=_DesktopOpenInput.model_json_schema(),
            input_model=_DesktopOpenInput,
            handler=_open,
            permission="desktop.open",
            category="desktop",
            autonomy_class="approval_required",
        ),
    ]
