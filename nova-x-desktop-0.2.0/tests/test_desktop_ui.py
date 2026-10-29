from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PySide6 = pytest.importorskip("PySide6")
from PySide6.QtWidgets import QApplication

from nova.desktop.app import NovaWindow, UiBridge
from nova.desktop.runtime import DesktopRuntime


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def test_native_qt_window_builds_all_staged_pages(qapp, tmp_path, monkeypatch):
    data = tmp_path / "state"
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("NOVA_DESKTOP_MODE", "1")
    monkeypatch.setenv("NOVA_DATA_DIR", str(data))
    monkeypatch.setenv("NOVA_DB_PATH", str(data / "nova.sqlite3"))
    monkeypatch.setenv("NOVA_WORKSPACE_DIR", str(workspace))
    bridge = UiBridge()
    runtime = DesktopRuntime(output_callback=lambda stream, text: bridge.command_output.emit(stream, text))
    window = NovaWindow(runtime, bridge)
    try:
        window.show()
        qapp.processEvents()
        assert len(window.pages) == 8
        assert window.stack.count() == 8
        assert set(window.pages) == {"chat", "tasks", "commands", "history", "workspaces", "models", "permissions", "diagnostics"}
        assert window.emergency_button.isVisible()
        assert window.pages["commands"] is not None
    finally:
        window.close()
        if not runtime.closed:
            runtime.close()
