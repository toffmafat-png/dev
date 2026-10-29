from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# PySide6 can be installed but still fail to import when the host lacks the
# system graphics libraries Qt links against (libGL/libEGL), which is common in
# containers and CI. `importorskip` alone only covers a *missing* package and
# would abort collection for the whole suite, so every Qt import failure is
# turned into a skip for this module instead.
_QT_IMPORT_ERROR = ""
try:  # pragma: no cover - depends on host graphics stack
    import PySide6  # noqa: F401  # imported to probe availability, not used directly
    from PySide6.QtWidgets import QApplication

    from nova.desktop.app import NovaWindow, UiBridge
    from nova.desktop.runtime import DesktopRuntime
except ImportError as exc:  # pragma: no cover - depends on host graphics stack
    _QT_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"
    pytest.skip(
        f"PySide6/Qt is unavailable on this host ({_QT_IMPORT_ERROR}); "
        "skipping native desktop UI tests.",
        allow_module_level=True,
    )


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
        assert len(window.pages) == 9
        assert window.stack.count() == 9
        assert set(window.pages) == {
            "chat",
            "studio",
            "tasks",
            "commands",
            "history",
            "workspaces",
            "models",
            "permissions",
            "diagnostics",
        }
        assert window.emergency_button.isVisible()
        assert window.pages["commands"] is not None
        assert window.pages["studio"] is not None

        # Switch to the §146 Creation studio page and verify real recognition & non-fabricated state.
        window._show_page("studio")
        qapp.processEvents()
        assert "IDLE" in window.studio_progress_pill.text()
        assert "Installed host tools" in window.studio_tools_box.toPlainText()
        window.studio_prompt.setPlainText("Create a 3D parametric model of a sensor bracket")
        qapp.processEvents()
        assert "3d" in window.studio_artifact_badge.text()
    finally:
        window.close()
        if not runtime.closed:
            runtime.close()
