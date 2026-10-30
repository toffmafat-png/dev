"""Native PySide6 desktop UI for the local NOVA X runtime."""
from __future__ import annotations

import asyncio
import os
import shlex
import sys
from typing import Any

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from nova import __version__
from nova.desktop.policy import DEFAULT_TRUSTED_PREFIXES, redact_text
from nova.desktop.runtime import DesktopRuntime
from nova.desktop.secrets import SECRET_ENV_NAMES
from nova.model_providers import PROVIDER_CATALOG
from nova.tools.registry import ToolOutcome

THEME = """
QMainWindow, QWidget { background: #0a1020; color: #e5eaf3; font-family: Inter, 'Noto Sans', sans-serif; font-size: 10pt; }
QFrame#sidebar { background: #0e1729; border: 1px solid #1b2940; border-radius: 16px; }
QFrame#card { background: #101b2e; border: 1px solid #1d2b43; border-radius: 14px; }
QFrame#subcard { background: #0c1526; border: 1px solid #1a2940; border-radius: 11px; }
QLabel#brand { color: #f0f5ff; font-size: 17pt; font-weight: 800; letter-spacing: 1px; }
QLabel#eyebrow { color: #38d6c5; font-size: 8pt; font-weight: 700; letter-spacing: 1.4px; }
QLabel#muted { color: #91a0b7; }
QLabel#pageTitle { color: #f1f5fb; font-size: 20pt; font-weight: 750; }
QLabel#sectionTitle { color: #eef4ff; font-size: 12pt; font-weight: 700; }
QLabel#statusPill { color: #b8c6d9; background: #17253a; border: 1px solid #283b56; border-radius: 9px; padding: 5px 9px; }
QLabel#statusGood { color: #8ce2c5; background: #0d2a2a; border: 1px solid #1b5a50; border-radius: 9px; padding: 5px 9px; }
QLabel#statusWarn { color: #ffd27a; background: #302613; border: 1px solid #735520; border-radius: 9px; padding: 5px 9px; }
QLabel#statusBad { color: #ffaaa6; background: #321b24; border: 1px solid #743442; border-radius: 9px; padding: 5px 9px; }
QLineEdit, QPlainTextEdit, QComboBox, QSpinBox, QListWidget, QTableWidget { background: #0b1424; border: 1px solid #263650; border-radius: 9px; padding: 8px; selection-background-color: #1a686b; color: #e5eaf3; }
QPlainTextEdit { padding: 10px; }
QComboBox::drop-down { border: 0; width: 22px; }
QComboBox QAbstractItemView { background: #101b2e; selection-background-color: #1a686b; border: 1px solid #263650; }
QPushButton { color: #e9f0fb; background: #18253a; border: 1px solid #2b3e59; border-radius: 9px; padding: 9px 13px; font-weight: 650; }
QPushButton:hover { background: #20334d; border-color: #3b5979; }
QPushButton:disabled { color: #65738a; background: #111a2a; border-color: #1b2738; }
QPushButton[primary="true"] { color: #061a1c; background: #45dfcb; border-color: #45dfcb; }
QPushButton[primary="true"]:hover { background: #6cebd9; }
QPushButton[danger="true"] { color: #ffb8b6; background: #321b24; border-color: #743442; }
QPushButton[danger="true"]:hover { background: #48202b; }
QPushButton[quiet="true"] { background: transparent; border-color: transparent; color: #a8b6ca; text-align: left; }
QPushButton[quiet="true"]:checked { background: #17303a; border-color: #22545a; color: #8de9de; }
QCheckBox { spacing: 8px; color: #c8d3e2; }
QCheckBox::indicator { width: 16px; height: 16px; }
QHeaderView::section { background: #142037; color: #91a0b7; border: none; padding: 7px; font-weight: 650; }
QTableWidget { gridline-color: #1c2b42; }
QScrollBar:vertical { background: #0b1424; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: #30435d; min-height: 24px; border-radius: 4px; }
QSplitter::handle { background: #1b2940; }
QToolTip { background: #18253a; color: #e5eaf3; border: 1px solid #30435d; padding: 4px; }
"""


class UiBridge(QObject):
    completed = Signal(str, bool, object)
    command_output = Signal(str, str)


def _label(text: str, object_name: str | None = None, *, word_wrap: bool = False) -> QLabel:
    item = QLabel(text)
    if object_name:
        item.setObjectName(object_name)
    item.setWordWrap(word_wrap)
    return item


def _card(parent_layout: QVBoxLayout | QHBoxLayout | None = None, object_name: str = "card") -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName(object_name)
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(10)
    if parent_layout is not None:
        parent_layout.addWidget(frame)
    return frame, layout


def _page_header(title: str, subtitle: str, action: QWidget | None = None) -> QWidget:
    widget = QWidget()
    layout = QHBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 0)
    text = QVBoxLayout()
    text.setSpacing(3)
    text.addWidget(_label(title, "pageTitle"))
    text.addWidget(_label(subtitle, "muted", word_wrap=True))
    layout.addLayout(text, 1)
    if action is not None:
        layout.addWidget(action, 0, Qt.AlignmentFlag.AlignTop)
    return widget


def _scrollable(content: QWidget) -> QScrollArea:
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QFrame.Shape.NoFrame)
    area.setWidget(content)
    return area


def _read_only_text(min_height: int = 120) -> QPlainTextEdit:
    box = QPlainTextEdit()
    box.setReadOnly(True)
    box.setMinimumHeight(min_height)
    box.setMaximumBlockCount(6000)
    return box


class NovaWindow(QMainWindow):
    def __init__(self, runtime: DesktopRuntime, bridge: UiBridge):
        super().__init__()
        self.runtime = runtime
        self.bridge = bridge
        self._pending: dict[str, Any] = {}
        self._current_task_id = ""
        self._current_conversation_id = ""
        self._selected_profile_id = ""
        self._selected_creation_project_id = ""
        self._command_request: dict[str, Any] | None = None
        self._is_refreshing_tasks = False
        self.setWindowTitle("NOVA X — Local Desktop Assistant")
        self.setMinimumSize(1050, 700)
        self.resize(1360, 880)
        self.setStyleSheet(THEME)
        self.bridge.completed.connect(self._on_completed)
        self.bridge.command_output.connect(self._on_command_output)
        self._build_ui()
        self._refresh_status()
        self._load_conversations()
        self._refresh_studio()
        self._refresh_tasks()
        self._refresh_models()
        self._refresh_history()
        self._refresh_workspaces()
        self._refresh_permissions()
        self._refresh_diagnostics()
        self._timer = QTimer(self)
        self._timer.setInterval(1800)
        self._timer.timeout.connect(self._background_refresh)
        self._timer.start()

    def _build_ui(self) -> None:
        outer = QWidget()
        root = QHBoxLayout(outer)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(12)
        self.setCentralWidget(outer)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(226)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(15, 17, 15, 15)
        side.setSpacing(9)
        side.addWidget(_label("NOVA X", "brand"))
        side.addWidget(_label("LOCAL DESKTOP ASSISTANT", "eyebrow"))
        self.sidebar_status = _label("Starting local runtime…", "statusPill", word_wrap=True)
        side.addWidget(self.sidebar_status)
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: #1b2940")
        side.addWidget(line)
        self.nav_buttons: dict[str, QPushButton] = {}
        nav_items = [
            ("chat", "Chat"),
            ("studio", "Creation studio"),
            ("control_center", "OS control center"),
            ("infrastructure", "Hardware & servers"),
            ("privacy_intel", "Tor & OSINT"),
            ("tasks", "Tasks & plans"),
            ("commands", "Local commands"),
            ("history", "Command history"),
            ("workspaces", "Workspace access"),
            ("models", "Models & credentials"),
            ("permissions", "Permissions"),
            ("diagnostics", "Diagnostics"),
        ]
        for key, title in nav_items:
            button = QPushButton(title)
            button.setCheckable(True)
            button.setProperty("quiet", True)
            button.clicked.connect(lambda checked=False, page=key: self._show_page(page))
            side.addWidget(button)
            self.nav_buttons[key] = button
        side.addStretch(1)
        side.addWidget(_label("Scoped access · user privileges · local SQLite", "muted", word_wrap=True))
        side.addWidget(_label(f"Version {__version__}", "muted"))
        root.addWidget(sidebar)

        right = QVBoxLayout()
        right.setContentsMargins(2, 0, 0, 0)
        right.setSpacing(10)
        topbar = QHBoxLayout()
        self.top_status = _label("Offline-first · waiting for setup", "statusPill")
        topbar.addWidget(self.top_status)
        topbar.addStretch(1)
        self.emergency_button = QPushButton("Emergency stop")
        self.emergency_button.setProperty("danger", True)
        self.emergency_button.clicked.connect(self._emergency_stop)
        topbar.addWidget(self.emergency_button)
        right.addLayout(topbar)

        self.stack = QStackedWidget()
        self.pages: dict[str, QWidget] = {}
        builders = [
            ("chat", self._build_chat_page),
            ("studio", self._build_studio_page),
            ("control_center", self._build_control_center_page),
            ("infrastructure", self._build_infrastructure_page),
            ("privacy_intel", self._build_privacy_intel_page),
            ("tasks", self._build_tasks_page),
            ("commands", self._build_commands_page),
            ("history", self._build_history_page),
            ("workspaces", self._build_workspaces_page),
            ("models", self._build_models_page),
            ("permissions", self._build_permissions_page),
            ("diagnostics", self._build_diagnostics_page),
        ]
        for key, builder in builders:
            page = builder()
            self.pages[key] = page
            self.stack.addWidget(page)
        right.addWidget(self.stack, 1)
        root.addLayout(right, 1)
        self._show_page("chat")

    def _show_page(self, key: str) -> None:
        page = self.pages.get(key)
        if page is None:
            return
        self.stack.setCurrentWidget(page)
        for name, button in self.nav_buttons.items():
            button.setChecked(name == key)
        if key == "tasks":
            self._refresh_tasks()
        elif key == "studio":
            self._refresh_studio()
        elif key == "control_center":
            self._refresh_control_center()
        elif key == "infrastructure":
            self._refresh_infrastructure()
        elif key == "privacy_intel":
            self._refresh_privacy_intel()
        elif key == "history":
            self._refresh_history()
        elif key == "models":
            self._refresh_models()
        elif key == "workspaces":
            self._refresh_workspaces()
        elif key == "permissions":
            self._refresh_permissions()
        elif key == "diagnostics":
            self._refresh_diagnostics()

    def _build_chat_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        toolbar = QWidget()
        tool_layout = QHBoxLayout(toolbar)
        tool_layout.setContentsMargins(0, 0, 0, 0)
        tool_layout.addWidget(_label("Conversation", "muted"))
        self.conversation_combo = QComboBox()
        self.conversation_combo.setMinimumWidth(250)
        self.conversation_combo.currentIndexChanged.connect(self._select_conversation)
        tool_layout.addWidget(self.conversation_combo, 1)
        new_chat = QPushButton("New chat")
        new_chat.clicked.connect(self._new_conversation)
        tool_layout.addWidget(new_chat)
        layout.addWidget(_page_header("Chat", "Cloud inference is optional and only called when you send a message. Chat itself has no action tools."))
        layout.addWidget(toolbar)
        _, transcript_layout = _card(layout)
        self.chat_transcript = _read_only_text(300)
        self.chat_transcript.setMinimumHeight(370)
        transcript_layout.addWidget(self.chat_transcript)
        info = _label("For file access or local command execution, create a task. Task actions use the separate permission and approval controls.", "muted", word_wrap=True)
        layout.addWidget(info)
        _, composer_layout = _card(layout)
        self.chat_input = QPlainTextEdit()
        self.chat_input.setPlaceholderText("Ask a question…")
        self.chat_input.setMaximumHeight(100)
        composer_layout.addWidget(self.chat_input)
        controls = QHBoxLayout()
        controls.addWidget(_label("Mode", "muted"))
        self.chat_mode = self._mode_combo()
        controls.addWidget(self.chat_mode)
        controls.addStretch(1)
        self.chat_send = QPushButton("Send message")
        self.chat_send.setProperty("primary", True)
        self.chat_send.clicked.connect(self._send_chat)
        controls.addWidget(self.chat_send)
        composer_layout.addLayout(controls)
        self.chat_feedback = _label("Messages are saved in the local SQLite database.", "muted", word_wrap=True)
        layout.addWidget(self.chat_feedback)
        return page

    def _build_tasks_page(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(12)
        outer.addWidget(_page_header("Tasks & plans", "A task may use selected workspace files and registered tools. Plan review is enabled by default; operations use exact tool permissions."))
        _, create_layout = _card(outer)
        create_layout.addWidget(_label("Start a task", "sectionTitle"))
        self.task_objective = QPlainTextEdit()
        self.task_objective.setPlaceholderText("Describe one bounded outcome. Example: summarize the README in the selected workspace.")
        self.task_objective.setMaximumHeight(75)
        create_layout.addWidget(self.task_objective)
        create_controls = QHBoxLayout()
        self.task_mode = self._mode_combo()
        create_controls.addWidget(_label("Inference mode", "muted"))
        create_controls.addWidget(self.task_mode)
        self.task_review = QCheckBox("Review plan before tools run")
        self.task_review.setChecked(True)
        create_controls.addWidget(self.task_review)
        create_controls.addStretch(1)
        self.task_create_button = QPushButton("Create task")
        self.task_create_button.setProperty("primary", True)
        self.task_create_button.clicked.connect(self._create_task)
        create_controls.addWidget(self.task_create_button)
        create_layout.addLayout(create_controls)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.task_table = QTableWidget(0, 3)
        self.task_table.setHorizontalHeaderLabels(["Objective", "State", "Updated"])
        self.task_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.task_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.task_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.task_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.task_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.task_table.itemSelectionChanged.connect(self._task_selected)
        splitter.addWidget(self.task_table)

        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(9)
        _, summary_layout = _card(detail_layout)
        summary_layout.addWidget(_label("Selected task", "sectionTitle"))
        self.task_summary = _label("Select a task to inspect its plan, approvals, and actual results.", "muted", word_wrap=True)
        summary_layout.addWidget(self.task_summary)
        _, plan_layout = _card(detail_layout)
        plan_layout.addWidget(_label("Plan (one step per line)", "sectionTitle"))
        self.plan_editor = QPlainTextEdit()
        self.plan_editor.setMaximumHeight(110)
        plan_layout.addWidget(self.plan_editor)
        self.save_plan_button = QPushButton("Save edited plan")
        self.save_plan_button.clicked.connect(self._save_task_plan)
        plan_layout.addWidget(self.save_plan_button, 0, Qt.AlignmentFlag.AlignRight)
        _, approval_layout = _card(detail_layout, "subcard")
        approval_layout.addWidget(_label("Approval / review", "sectionTitle"))
        self.task_approval = _label("No pending approval.", "muted", word_wrap=True)
        approval_layout.addWidget(self.task_approval)
        approvals = QHBoxLayout()
        self.task_approve_button = QPushButton("Approve")
        self.task_approve_button.setProperty("primary", True)
        self.task_approve_button.clicked.connect(lambda: self._task_decision(True))
        self.task_decline_button = QPushButton("Decline")
        self.task_decline_button.setProperty("danger", True)
        self.task_decline_button.clicked.connect(lambda: self._task_decision(False))
        approvals.addWidget(self.task_approve_button)
        approvals.addWidget(self.task_decline_button)
        approval_layout.addLayout(approvals)
        actions = QHBoxLayout()
        self.task_pause_button = QPushButton("Pause")
        self.task_pause_button.clicked.connect(self._pause_task)
        self.task_resume_button = QPushButton("Resume")
        self.task_resume_button.clicked.connect(self._resume_task)
        self.task_cancel_button = QPushButton("Cancel")
        self.task_cancel_button.setProperty("danger", True)
        self.task_cancel_button.clicked.connect(self._cancel_task)
        actions.addWidget(self.task_pause_button)
        actions.addWidget(self.task_resume_button)
        actions.addWidget(self.task_cancel_button)
        detail_layout.addLayout(actions)
        _, events_layout = _card(detail_layout)
        events_layout.addWidget(_label("Execution timeline & evidence", "sectionTitle"))
        self.task_events = _read_only_text(170)
        self.task_events.setMinimumHeight(165)
        events_layout.addWidget(self.task_events)
        splitter.addWidget(detail)
        splitter.setSizes([380, 570])
        outer.addWidget(splitter, 1)
        return page

    def _build_commands_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        layout.addWidget(_page_header("Local commands", "Structured argv runs without a shell by default. Untrusted, destructive, network, or security-sensitive commands need fresh approval."))
        _, form = _card(layout)
        form.addWidget(_label("Command input", "sectionTitle"))
        self.command_input = QPlainTextEdit()
        self.command_input.setPlaceholderText("Example: ls -la   (arguments are parsed, then passed directly to the executable)")
        self.command_input.setMaximumHeight(85)
        form.addWidget(self.command_input)
        row = QHBoxLayout()
        self.command_shell = QCheckBox("Run as user-authored Bash script (always asks first)")
        row.addWidget(self.command_shell)
        row.addStretch(1)
        row.addWidget(_label("Working directory", "muted"))
        self.command_cwd = QComboBox()
        self.command_cwd.setMinimumWidth(300)
        row.addWidget(self.command_cwd)
        row.addWidget(_label("Timeout", "muted"))
        self.command_timeout = QSpinBox()
        self.command_timeout.setRange(1, 600)
        self.command_timeout.setValue(120)
        self.command_timeout.setSuffix(" s")
        row.addWidget(self.command_timeout)
        form.addLayout(row)
        buttons = QHBoxLayout()
        self.run_command_button = QPushButton("Run command")
        self.run_command_button.setProperty("primary", True)
        self.run_command_button.clicked.connect(self._run_command)
        self.stop_command_button = QPushButton("Stop active command")
        self.stop_command_button.setProperty("danger", True)
        self.stop_command_button.clicked.connect(self._stop_commands)
        buttons.addWidget(self.run_command_button)
        buttons.addWidget(self.stop_command_button)
        buttons.addStretch(1)
        form.addLayout(buttons)
        _, output = _card(layout)
        output.addWidget(_label("Live stdout / stderr (redacted)", "sectionTitle"))
        self.command_output = _read_only_text(300)
        self.command_output.setMinimumHeight(330)
        output.addWidget(self.command_output)
        self.command_status = _label("Commands run with the logged-in user's normal privileges. Output and status are saved locally.", "muted", word_wrap=True)
        layout.addWidget(self.command_status)
        return page

    def _build_history_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        layout.addWidget(_page_header("Command history", "History is local to this account. Secrets are redacted from saved arguments and output; logs are permission-restricted."))
        _, search_layout = _card(layout)
        row = QHBoxLayout()
        self.history_search = QLineEdit()
        self.history_search.setPlaceholderText("Filter by program, workspace, or output…")
        self.history_search.returnPressed.connect(self._refresh_history)
        search_button = QPushButton("Search")
        search_button.clicked.connect(self._refresh_history)
        clear_button = QPushButton("Clear history")
        clear_button.setProperty("danger", True)
        clear_button.clicked.connect(self._clear_history)
        row.addWidget(self.history_search, 1)
        row.addWidget(search_button)
        row.addWidget(clear_button)
        search_layout.addLayout(row)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.history_table = QTableWidget(0, 6)
        self.history_table.setHorizontalHeaderLabels(["Started", "Program", "Arguments", "Directory", "Status", "Exit"])
        self.history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.history_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.history_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history_table.itemSelectionChanged.connect(self._history_selected)
        splitter.addWidget(self.history_table)
        self.history_output = _read_only_text(150)
        splitter.addWidget(self.history_output)
        splitter.setSizes([420, 200])
        layout.addWidget(splitter, 1)
        return page

    def _build_workspaces_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        layout.addWidget(_page_header("Workspace access", "Only listed directories are eligible for routine command pre-authorization. NOVA does not scan unrelated folders."))
        _, card = _card(layout)
        card.addWidget(_label("Authorized directories", "sectionTitle"))
        self.workspace_list = QListWidget()
        self.workspace_list.setMinimumHeight(260)
        card.addWidget(self.workspace_list)
        buttons = QHBoxLayout()
        add_button = QPushButton("Add directory…")
        add_button.clicked.connect(self._add_workspace)
        remove_button = QPushButton("Remove selected")
        remove_button.clicked.connect(self._remove_workspace)
        set_active = QPushButton("Use selected as active")
        set_active.setProperty("primary", True)
        set_active.clicked.connect(self._set_active_workspace)
        buttons.addWidget(add_button)
        buttons.addWidget(remove_button)
        buttons.addStretch(1)
        buttons.addWidget(set_active)
        card.addLayout(buttons)
        self.workspace_detail = _label("Workspace paths are stored locally as settings. Existing files are not copied or moved.", "muted", word_wrap=True)
        layout.addWidget(self.workspace_detail)
        return page

    def _build_models_page(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(12)
        outer.addWidget(_page_header("Models & credentials", "Optional official provider APIs. Keys are stored only in Linux Secret Service; this screen never displays them."))
        splitter = QSplitter(Qt.Orientation.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        _, profiles_layout = _card(left_layout)
        profiles_layout.addWidget(_label("Configured profiles", "sectionTitle"))
        self.profile_list = QListWidget()
        self.profile_list.currentItemChanged.connect(self._profile_selected)
        profiles_layout.addWidget(self.profile_list, 1)
        profile_buttons = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh_models)
        make_default = QPushButton("Set default")
        make_default.clicked.connect(self._set_default_profile)
        profile_buttons.addWidget(refresh)
        profile_buttons.addWidget(make_default)
        profiles_layout.addLayout(profile_buttons)
        self.profile_status = _label("Select a profile to inspect its configuration and test status.", "muted", word_wrap=True)
        profiles_layout.addWidget(self.profile_status)
        test_row = QHBoxLayout()
        self.test_connection_button = QPushButton("Test connection · 1 request")
        self.test_connection_button.clicked.connect(self._test_connection)
        self.eval_tools_button = QPushButton("Validate tools · up to 3 requests")
        self.eval_tools_button.clicked.connect(self._evaluate_profile)
        test_row.addWidget(self.test_connection_button)
        test_row.addWidget(self.eval_tools_button)
        profiles_layout.addLayout(test_row)
        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        _, create_layout = _card(right_layout)
        create_layout.addWidget(_label("Add a model profile", "sectionTitle"))
        form = QFormLayout()
        self.provider_combo = QComboBox()
        for key, item in PROVIDER_CATALOG.items():
            if key in SECRET_ENV_NAMES:
                self.provider_combo.addItem(item["label"], key)
        self.provider_combo.currentIndexChanged.connect(self._provider_changed)
        self.profile_name = QLineEdit()
        self.profile_name.setPlaceholderText("Optional display name")
        self.base_url = QLineEdit()
        self.model_id = QLineEdit()
        self.model_id.setPlaceholderText("Exact model ID visible to your provider account")
        self.api_key = QLineEdit()
        self.api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key.setPlaceholderText("Optional; stored in Secret Service, never in SQLite")
        self.profile_tools = QCheckBox("Request tool calling (usable only after synthetic validation)")
        self.profile_tools.setChecked(True)
        self.profile_default = QCheckBox("Make this the default model profile")
        self.profile_default.setChecked(True)
        form.addRow("Provider", self.provider_combo)
        form.addRow("Profile name", self.profile_name)
        form.addRow("Official API endpoint", self.base_url)
        form.addRow("Model ID", self.model_id)
        form.addRow("API key", self.api_key)
        create_layout.addLayout(form)
        create_layout.addWidget(self.profile_tools)
        create_layout.addWidget(self.profile_default)
        self.provider_note = _label("Select a provider to view its adapter notes.", "muted", word_wrap=True)
        create_layout.addWidget(self.provider_note)
        self.secret_note = _label("Checking Secret Service…", "muted", word_wrap=True)
        create_layout.addWidget(self.secret_note)
        self.delete_key_button = QPushButton("Delete saved key for this provider")
        self.delete_key_button.clicked.connect(self._delete_provider_key)
        create_layout.addWidget(self.delete_key_button, 0, Qt.AlignmentFlag.AlignRight)
        self.save_profile_button = QPushButton("Save profile")
        self.save_profile_button.setProperty("primary", True)
        self.save_profile_button.clicked.connect(self._save_profile)
        create_layout.addWidget(self.save_profile_button, 0, Qt.AlignmentFlag.AlignRight)
        _, notice = _card(right_layout, "subcard")
        notice.addWidget(_label("Cloud Privacy Gateway & Offline Queue (§1–§11)", "sectionTitle"))
        self.gateway_privacy_summary = _label(
            "Local OS hosts all memory, tasks, and tools. Outbound cloud calls enforce context minimization, secret redaction, and secret-free transmission logging.",
            "muted",
            word_wrap=True,
        )
        notice.addWidget(self.gateway_privacy_summary)
        splitter.addWidget(right)
        splitter.setSizes([490, 580])
        outer.addWidget(splitter, 1)
        self._provider_changed()
        return page

    def _build_permissions_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        layout.addWidget(_page_header("Permissions", "Single-user Kali Linux autonomy & persistent permissions. Routine authorized scopes run without repeated approval dialogs while material safeguards stay active."))
        _, personal_layout = _card(layout)
        personal_layout.addWidget(_label("Personal-Use Security & Autonomy Policy (Sections 1–7)", "sectionTitle"))
        personal_row = QHBoxLayout()
        self.personal_mode_combo = QComboBox()
        for mode_id, mode_desc in (
            ("balanced", "Balanced — Scoped routine automation + explicit persistent grants"),
            ("personal_power_user", "Personal Power User — Automatic dev/CLI/test/git/build in owned workspaces"),
            ("cyber_lab_research", "Cyber Lab Research — Power-user + persistent authorized lab security testing"),
            ("strict_review", "Strict Review — Fresh approval for non-trivial mutations"),
        ):
            self.personal_mode_combo.addItem(mode_desc, mode_id)
        personal_row.addWidget(self.personal_mode_combo, 1)
        save_personal = QPushButton("Save personal mode")
        save_personal.setProperty("primary", True)
        save_personal.clicked.connect(self._save_personal_policy_mode)
        personal_row.addWidget(save_personal)
        personal_layout.addLayout(personal_row)
        self.personal_policy_summary = _label("Loading single-user personal policy…", "muted", word_wrap=True)
        personal_layout.addWidget(self.personal_policy_summary)
        _, level_layout = _card(layout)
        level_layout.addWidget(_label("Autonomy level", "sectionTitle"))
        level_row = QHBoxLayout()
        self.autonomy_combo = QComboBox()
        for item in self.runtime.autonomy_policy.get()["levels"]:
            self.autonomy_combo.addItem(f"{item['name']} — {item['description']}", item["id"])
        level_row.addWidget(self.autonomy_combo, 1)
        save_level = QPushButton("Save level")
        save_level.setProperty("primary", True)
        save_level.clicked.connect(self._save_autonomy)
        level_row.addWidget(save_level)
        level_layout.addLayout(level_row)
        _, prefixes_layout = _card(layout)
        prefixes_layout.addWidget(_label("Persistently trusted argv prefixes", "sectionTitle"))
        self.prefixes_editor = QPlainTextEdit()
        self.prefixes_editor.setPlaceholderText("One exact token prefix per line, for example:\ngit status\nls")
        self.prefixes_editor.setMinimumHeight(180)
        prefixes_layout.addWidget(self.prefixes_editor)
        prefixes_layout.addWidget(_label("Each saved prefix applies only inside a selected workspace and matches complete argv tokens (not a shell pattern). Shells, interpreters/build runners, privilege wrappers, package/network/security tools, and destructive/admin operations cannot be pre-authorized. Add only commands you understand.", "muted", word_wrap=True))
        save_prefixes = QPushButton("Save trusted prefixes")
        save_prefixes.setProperty("primary", True)
        save_prefixes.clicked.connect(self._save_prefixes)
        prefixes_layout.addWidget(save_prefixes, 0, Qt.AlignmentFlag.AlignRight)
        _, tools_layout = _card(layout)
        tools_layout.addWidget(_label("Registered tools and classes", "sectionTitle"))
        self.tool_classification = _read_only_text(120)
        tools_layout.addWidget(self.tool_classification)
        layout.addStretch(1)
        return page

    def _build_diagnostics_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        refresh = QPushButton("Refresh diagnostics")
        refresh.clicked.connect(self._refresh_diagnostics)
        layout.addWidget(_page_header("Diagnostics", "Read-only local checks. No provider request is made here.", refresh))
        _, diagnostic_layout = _card(layout)
        self.diagnostic_output = _read_only_text(360)
        self.diagnostic_output.setMinimumHeight(390)
        diagnostic_layout.addWidget(self.diagnostic_output)
        _, roadmap_layout = _card(layout, "subcard")
        roadmap_layout.addWidget(_label("Current delivery boundary", "sectionTitle"))
        roadmap_layout.addWidget(_label("Implemented here: native Qt shell, local SQLite tasks/history, scoped workspaces, structured process execution, cancellation, approval gates, optional provider adapters, keyring storage, and CLI. Not implemented in this increment: always-on background daemon, desktop automation, voice/microphone, autonomous self-evolution, or a persistent service. Tasks stop when the app closes; diagnostics and settings do not send network traffic.", "muted", word_wrap=True))
        layout.addStretch(1)
        return page

    @staticmethod
    def _mode_combo() -> QComboBox:
        combo = QComboBox()
        for value, title in [
            ("fast", "Fast"),
            ("balanced", "Balanced"),
            ("frontier_fusion", "Frontier Fusion"),
            ("maximum_intelligence", "Maximum Intelligence"),
        ]:
            combo.addItem(title, value)
        combo.setCurrentIndex(1)
        return combo

    def _dispatch(self, key: str, coroutine) -> None:
        if key in self._pending:
            return
        self._pending[key] = True
        future = self.runtime.async_service.submit(coroutine)

        def finished(item):
            try:
                result = item.result()
            except Exception as exc:
                detail = str(exc) if isinstance(exc, (ValueError, KeyError, TimeoutError)) else f"Operation failed safely ({type(exc).__name__})."
                self.bridge.completed.emit(key, False, redact_text(detail))
            else:
                self.bridge.completed.emit(key, True, result)
        future.add_done_callback(finished)

    def _on_completed(self, key: str, ok: bool, result: Any) -> None:
        self._pending.pop(key, None)
        if not ok:
            self._show_error(str(result))
            if key == "chat":
                self.chat_send.setEnabled(True)
                self.chat_feedback.setText("The request did not complete. Check provider setup and diagnostics.")
                self._refresh_chat()
            elif key == "task_create":
                self.task_create_button.setEnabled(True)
            elif key.startswith("command"):
                self.run_command_button.setEnabled(True)
                self.command_status.setText(str(result))
            elif key == "profile_save":
                self.save_profile_button.setEnabled(True)
                self.api_key.clear()
            elif key == "credential_delete":
                self.delete_key_button.setEnabled(True)
            elif key == "model_test":
                self.test_connection_button.setEnabled(True)
            elif key == "model_eval":
                self.eval_tools_button.setEnabled(True)
            elif key == "emergency_stop":
                self.emergency_button.setEnabled(True)
            elif key in {"studio_build", "studio_continue", "studio_package"}:
                self.studio_build_button.setEnabled(True)
                self.studio_continue_button.setEnabled(True)
                self.studio_package_button.setEnabled(True)
                self.studio_progress_pill.setText("FAILED · check error log")
                self.studio_errors_box.setPlainText(str(result))
            return

        if key == "chat":
            self.chat_send.setEnabled(True)
            self._current_conversation_id = result.get("conversation_id", self._current_conversation_id)
            intelligence = result.get("intelligence", {})
            mode = intelligence.get("mode_effective", intelligence.get("mode_requested", "balanced"))
            strategy = intelligence.get("strategy", "single model")
            self.chat_feedback.setText(f"Completed · {mode} · {strategy}. Usage/cost can be incomplete; see provider status before relying on it.")
            self._load_conversations()
            self._select_conversation_by_id(self._current_conversation_id)
            self._refresh_chat()
            self._refresh_status()
        elif key == "task_create":
            self.task_create_button.setEnabled(True)
            self.task_objective.clear()
            self._refresh_tasks()
            self._select_task(result.get("id", ""))
            self._show_page("tasks")
        elif key == "task_action":
            self._refresh_tasks()
            self._refresh_selected_task()
        elif key == "command_preflight":
            self.run_command_button.setEnabled(True)
            self._handle_command_preflight(result)
        elif key == "command_execute":
            self.run_command_button.setEnabled(True)
            self.command_status.setText(f"{result.status.upper()}: {result.summary}")
            self._refresh_history()
            self._refresh_status()
            if result.status != "success":
                self._show_error(result.summary)
        elif key == "stop_command":
            self.command_status.setText("Stop signal sent to active local process.")
        elif key == "emergency_stop":
            self.emergency_button.setEnabled(True)
            self._refresh_tasks()
            self._refresh_selected_task()
            self.command_status.setText(f"Emergency stop complete: {len(result.get('stopped_tasks', []))} task(s), {len(result.get('stopped_commands', []))} command(s).")
        elif key == "profile_save":
            self.save_profile_button.setEnabled(True)
            self.api_key.clear()
            self.profile_name.clear()
            self.model_id.clear()
            self._refresh_models()
            self._refresh_status()
            self._show_info(f"Profile saved. Status: {result.get('status', 'configured')}. No inference request was sent.")
        elif key == "credential_delete":
            self.delete_key_button.setEnabled(True)
            self._refresh_models()
            self._show_info("Credential removed from Secret Service. Profiles using that provider are no longer configured unless another accepted credential source is deliberately set." if result else "No saved key was present for that provider.")
        elif key == "model_test":
            self.test_connection_button.setEnabled(True)
            self._refresh_models()
            self._show_info(f"Connection test status: {result.get('status', 'unknown')} · {result.get('latency_ms', '—')} ms. {result.get('warning', '')}")
        elif key == "model_eval":
            self.eval_tools_button.setEnabled(True)
            self._refresh_models()
            self._show_info(f"Synthetic evaluation: {result.get('status')} · {result.get('score')}% · {result.get('provider_requests')} provider request(s). The test function was proposed, not executed.")
        elif key == "chat_new":
            self._current_conversation_id = str(result)
            self._load_conversations()
            self._select_conversation_by_id(self._current_conversation_id)
            self._refresh_chat()
        elif key == "studio_build":
            self.studio_build_button.setEnabled(True)
            self._selected_creation_project_id = str(result.get("project_id", ""))
            self.studio_progress_pill.setText(
                f"{str(result.get('status', 'done')).upper()} · v{result.get('version', 1)} · QA {result.get('qa', {}).get('quality_score', 0.0)}"
            )
            self._refresh_studio()
            self._studio_render_project(self._selected_creation_project_id)
        elif key == "studio_continue":
            self.studio_continue_button.setEnabled(True)
            ver = result.get("version") or result.get("retained_version") or 1
            reverted = " (reverted regression)" if result.get("reverted_regression") else ""
            self.studio_progress_pill.setText(f"UPDATED v{ver}{reverted} · QA {result.get('qa', {}).get('quality_score', 0.0)}")
            self._refresh_studio()
            self._studio_render_project(self._selected_creation_project_id)
        elif key == "studio_package":
            self.studio_package_button.setEnabled(True)
            if result.get("packaged"):
                self.studio_progress_pill.setText(f"PACKAGED · {result.get('included_file_count', 0)} file(s)")
                self._show_info(f"Handover archive created:\n{result.get('archive_path')}")
            else:
                self.studio_progress_pill.setText("PACKAGE FAILED")
            self._refresh_studio()
            self._studio_render_project(self._selected_creation_project_id)

    def _show_error(self, text: str) -> None:
        QMessageBox.warning(self, "NOVA X", text[:1800])

    def _show_info(self, text: str) -> None:
        QMessageBox.information(self, "NOVA X", text[:1800])

    def _background_refresh(self) -> None:
        self._refresh_status()
        if self.stack.currentWidget() == self.pages.get("tasks"):
            self._refresh_tasks()
            self._refresh_selected_task()
        elif self.stack.currentWidget() == self.pages.get("commands"):
            self._refresh_status()

    def _refresh_status(self) -> None:
        try:
            profiles = self.runtime.model_manager.list_profiles()
            available = sum(bool(item.get("available")) for item in profiles)
            configured = sum(bool(item.get("configured")) for item in profiles)
            self.sidebar_status.setText(f"Local runtime ready · {available} model(s) available")
            self.sidebar_status.setObjectName("statusGood" if available else "statusPill")
            self.sidebar_status.style().unpolish(self.sidebar_status)
            self.sidebar_status.style().polish(self.sidebar_status)
            self.top_status.setText(f"Local SQLite · {configured} configured / {available} available · no web server")
        except Exception:
            self.sidebar_status.setText("Local runtime · setup needs attention")
            self.top_status.setText("Local runtime · check Diagnostics")

    def _load_conversations(self) -> None:
        if not hasattr(self, "conversation_combo"):
            return
        conversations = self.runtime.database.list_conversations(100)
        current = self._current_conversation_id
        self.conversation_combo.blockSignals(True)
        self.conversation_combo.clear()
        for item in conversations:
            self.conversation_combo.addItem(item.get("title", "Conversation")[:80], item["id"])
        self.conversation_combo.blockSignals(False)
        self._select_conversation_by_id(current or (conversations[0]["id"] if conversations else ""))

    def _select_conversation_by_id(self, conversation_id: str) -> None:
        if not hasattr(self, "conversation_combo"):
            return
        index = self.conversation_combo.findData(conversation_id)
        if index >= 0:
            self.conversation_combo.setCurrentIndex(index)
            self._current_conversation_id = conversation_id

    def _select_conversation(self, index: int) -> None:
        if index < 0:
            return
        conversation_id = self.conversation_combo.currentData()
        if conversation_id:
            self._current_conversation_id = str(conversation_id)
            self._refresh_chat()

    def _new_conversation(self) -> None:
        try:
            conversation_id = self.runtime.database.create_conversation()
        except Exception as exc:
            self._show_error(f"Could not create a local conversation ({type(exc).__name__}).")
            return
        self._current_conversation_id = conversation_id
        self._load_conversations()
        self._select_conversation_by_id(conversation_id)
        self._refresh_chat()

    def _refresh_chat(self) -> None:
        if not hasattr(self, "chat_transcript"):
            return
        if not self._current_conversation_id:
            self.chat_transcript.setPlainText("Start a new conversation or send a message.\n\nChat does not have permission to execute tools.")
            return
        try:
            messages = self.runtime.database.get_messages(self._current_conversation_id, 100)
        except KeyError:
            messages = []
        lines = []
        for item in messages:
            role = "YOU" if item["role"] == "user" else "NOVA X"
            lines.append(f"{role}\n{item['content']}\n")
        self.chat_transcript.setPlainText("\n────────────────────────────────────────\n".join(lines) if lines else "No messages yet. Ask a question below.")
        scrollbar = self.chat_transcript.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _send_chat(self) -> None:
        text = self.chat_input.toPlainText().strip()
        if not text:
            return
        mode = str(self.chat_mode.currentData() or "balanced")
        self.chat_input.clear()
        self.chat_send.setEnabled(False)
        self.chat_feedback.setText("Waiting for the configured provider… no local tools are available in chat.")
        self._dispatch("chat", self.runtime.chat(text, self._current_conversation_id or None, mode))

    def _create_task(self) -> None:
        objective = self.task_objective.toPlainText().strip()
        if not objective:
            self._show_error("Describe a bounded task before starting.")
            return
        self.task_create_button.setEnabled(False)
        self._dispatch("task_create", self.runtime.create_task_async(
            objective,
            review_plan=self.task_review.isChecked(),
            mode=str(self.task_mode.currentData() or "balanced"),
        ))

    def _refresh_tasks(self) -> None:
        if not hasattr(self, "task_table") or self._is_refreshing_tasks:
            return
        self._is_refreshing_tasks = True
        try:
            tasks = self.runtime.list_tasks(120)
            selected = self._current_task_id
            self.task_table.blockSignals(True)
            self.task_table.setRowCount(0)
            for task in tasks:
                row = self.task_table.rowCount()
                self.task_table.insertRow(row)
                title = str(task.get("objective", "" )).replace("\n", " ")[:86]
                item = QTableWidgetItem(title)
                item.setData(Qt.ItemDataRole.UserRole, task["id"])
                self.task_table.setItem(row, 0, item)
                self.task_table.setItem(row, 1, QTableWidgetItem(str(task.get("state", "unknown"))))
                updated = str(task.get("updated_at", ""))[:19].replace("T", " ")
                self.task_table.setItem(row, 2, QTableWidgetItem(updated))
                if task["id"] == selected:
                    self.task_table.selectRow(row)
            self.task_table.blockSignals(False)
            if selected:
                self._select_task(selected)
            elif tasks:
                self._select_task(tasks[0]["id"])
            else:
                self._current_task_id = ""
                self.task_summary.setText("No tasks yet. Start with a bounded objective above.")
                self.task_approval.setText("No pending approval.")
                self.task_events.clear()
                self.plan_editor.clear()
                self._set_task_buttons(None)
        finally:
            self.task_table.blockSignals(False)
            self._is_refreshing_tasks = False

    def _task_selected(self) -> None:
        selected = self.task_table.selectedItems()
        if selected:
            task_id = selected[0].data(Qt.ItemDataRole.UserRole)
            if task_id:
                self._select_task(str(task_id))

    def _select_task(self, task_id: str) -> None:
        if not task_id:
            return
        self._current_task_id = task_id
        for row in range(self.task_table.rowCount()):
            item = self.task_table.item(row, 0)
            if item and item.data(Qt.ItemDataRole.UserRole) == task_id:
                self.task_table.selectRow(row)
                break
        self._refresh_selected_task()

    def _refresh_selected_task(self) -> None:
        if not self._current_task_id or not hasattr(self, "task_summary"):
            return
        task = self.runtime.get_task(self._current_task_id)
        if not task:
            return
        plan = task.get("plan")
        if isinstance(plan, dict):
            lines = plan.get("steps", [])
            plan_text = "\n".join(str(item) for item in lines)
        elif isinstance(plan, list):
            plan_text = "\n".join(str(item) for item in plan)
        else:
            plan_text = ""
        if self.plan_editor.toPlainText() != plan_text and not self.plan_editor.hasFocus():
            self.plan_editor.setPlainText(plan_text)
        summary = (
            f"{task.get('state', 'unknown').upper()} · {task.get('objective', '')}\n"
            f"Mode: {task.get('intelligence_mode', 'balanced')} · tool calls: {task.get('tool_call_count', 0)} · provider requests: {task.get('request_count', 0)}\n"
            f"Verification: {task.get('verification', 'unverified')} — {task.get('verification_note', '')}"
        )
        if task.get("result"):
            summary += f"\n\nResult: {task['result']}"
        if task.get("error"):
            summary += f"\n\nError: {task['error']}"
        self.task_summary.setText(summary[:5000])
        checkpoint = task.get("checkpoint") or {}
        waiting_kind = checkpoint.get("waiting_kind")
        pending_summary = (checkpoint.get("pending_approval_summary") or {}).get("summary", "")
        if waiting_kind == "plan_review":
            self.task_approval.setText("PLAN REVIEW REQUIRED\n\nReview or edit the plan above. Approving permits the task to continue into tool execution; later consequential operations may still need separate approval.")
        elif waiting_kind == "tool":
            self.task_approval.setText("TOOL APPROVAL REQUIRED\n\n" + (pending_summary or "Review the exact tool operation in the timeline."))
        else:
            self.task_approval.setText("No pending approval.")
        events = task.get("events", [])
        event_lines = []
        for event in events:
            stamp = str(event.get("created_at", ""))[:19].replace("T", " ")
            event_lines.append(f"[{stamp}] {str(event.get('kind', 'event')).upper()}: {event.get('message', '')}")
        for tool_result in (checkpoint.get("tool_results") or [])[-12:]:
            payload = tool_result if isinstance(tool_result, dict) else {}
            data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
            output = str(data.get("stdout", ""))
            error_output = str(data.get("stderr", ""))
            event_lines.append(f"\n[{payload.get('tool', 'tool')}] {payload.get('status', 'unknown')}: {payload.get('summary', '')}")
            if data:
                event_lines.append(f"exit={data.get('exit_code')} · cwd={data.get('cwd', '')} · {data.get('duration_seconds', 0)}s")
            if output:
                event_lines.append("stdout:\n" + output[-6000:])
            if error_output:
                event_lines.append("stderr:\n" + error_output[-3000:])
        self.task_events.setPlainText("\n".join(event_lines) or "No execution events yet.")
        self.task_events.verticalScrollBar().setValue(self.task_events.verticalScrollBar().maximum())
        self._set_task_buttons(task)

    def _set_task_buttons(self, task: dict[str, Any] | None) -> None:
        state = task.get("state") if task else None
        waiting = bool(task and state == "waiting_approval")
        self.task_approve_button.setEnabled(waiting)
        self.task_decline_button.setEnabled(waiting)
        self.task_pause_button.setEnabled(bool(task and state not in {"paused", "waiting_approval", "completed", "failed", "cancelled"}))
        self.task_resume_button.setEnabled(bool(task and state == "paused"))
        self.task_cancel_button.setEnabled(bool(task and state not in {"completed", "failed", "cancelled"}))
        self.save_plan_button.setEnabled(bool(task and state in {"paused", "waiting_approval"} and task.get("checkpoint", {}).get("waiting_kind") != "tool"))

    def _task_decision(self, approved: bool) -> None:
        if not self._current_task_id:
            return
        task = self.runtime.get_task(self._current_task_id) or {}
        checkpoint = task.get("checkpoint") or {}
        if approved:
            title = "Approve this plan?" if checkpoint.get("waiting_kind") == "plan_review" else "Approve this tool operation?"
            if QMessageBox.question(self, "NOVA X approval", f"{title}\n\n{self.task_approval.text()}\n\nApproval does not grant permanent permission.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
                return
        self._dispatch("task_action", self.runtime.approve_task(self._current_task_id, approved))

    def _pause_task(self) -> None:
        if self._current_task_id:
            self._dispatch("task_action", self.runtime.pause_task(self._current_task_id))

    def _resume_task(self) -> None:
        if self._current_task_id:
            self._dispatch("task_action", self.runtime.resume_task(self._current_task_id))

    def _cancel_task(self) -> None:
        if self._current_task_id and QMessageBox.question(self, "Cancel task", "Cancel the selected task and terminate its active child process?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self._dispatch("task_action", self.runtime.cancel_task(self._current_task_id))

    def _save_task_plan(self) -> None:
        if not self._current_task_id:
            return
        steps = [line.strip() for line in self.plan_editor.toPlainText().splitlines() if line.strip()]
        if not steps:
            self._show_error("A task plan needs at least one non-empty step.")
            return
        if len(steps) > 8:
            self._show_error("A task plan can contain no more than eight steps.")
            return
        task = self.runtime.get_task(self._current_task_id)
        if not task:
            return
        plan = {"summary": (task.get("plan") or {}).get("summary", "User-edited plan"), "steps": steps}
        checkpoint = task.get("checkpoint") or {}
        checkpoint["plan"] = plan
        try:
            self.runtime.database.update_task(self._current_task_id, plan=plan, checkpoint=checkpoint)
            self.runtime.database.add_event(self._current_task_id, "plan", "Plan edited by the user in the native desktop.", {"steps": steps})
            self._refresh_selected_task()
        except Exception as exc:
            self._show_error(f"Could not save the plan ({type(exc).__name__}).")

    def _build_command_argv(self) -> list[str] | None:
        raw = self.command_input.toPlainText().strip()
        if not raw:
            return None
        try:
            args = shlex.split(raw, posix=True)
        except ValueError as exc:
            self._show_error(f"Command arguments contain invalid quoting: {exc}")
            return None
        return args or None

    def _run_command(self) -> None:
        raw = self.command_input.toPlainText().strip()
        if not raw:
            self._show_error("Enter a command or script first.")
            return
        cwd = str(self.command_cwd.currentData() or self.runtime.active_workspace())
        timeout = self.command_timeout.value()
        self.command_output.clear()
        self.command_status.setText("Starting process…")
        self.run_command_button.setEnabled(False)
        if self.command_shell.isChecked():
            request = {"kind": "shell", "script": raw, "cwd": cwd, "timeout": timeout}
            self._dispatch("command_preflight", self.runtime.run_shell(raw, cwd, timeout, approved=False))
        else:
            argv = self._build_command_argv()
            if not argv:
                self.run_command_button.setEnabled(True)
                return
            request = {"kind": "argv", "argv": argv, "cwd": cwd, "timeout": timeout}
            self._dispatch("command_preflight", self.runtime.run_command(argv, cwd, timeout, approved=False))
        self._command_request = request

    def _handle_command_preflight(self, outcome: ToolOutcome) -> None:
        request = self._command_request
        if not request:
            self.command_status.setText(outcome.summary)
            return
        if outcome.status == "approval_required":
            answer = QMessageBox.question(
                self,
                "Review command before running",
                outcome.summary + "\n\nNOVA will run this once only after your confirmation. No sudo password is collected.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if answer == QMessageBox.StandardButton.Yes:
                if request["kind"] == "shell":
                    self._dispatch("command_execute", self.runtime.run_shell(request["script"], request["cwd"], request["timeout"], approved=True))
                else:
                    self._dispatch("command_execute", self.runtime.run_command(request["argv"], request["cwd"], request["timeout"], approved=True))
                return
            self.command_status.setText("Declined. No command was run.")
            return
        self.command_status.setText(f"{outcome.status.upper()}: {outcome.summary}")
        if outcome.status == "success" or outcome.status == "error":
            self._refresh_history()
        if outcome.status != "success":
            self._show_error(outcome.summary)

    def _on_command_output(self, stream_name: str, text: str) -> None:
        if not hasattr(self, "command_output"):
            return
        prefix = "" if stream_name == "stdout" else "[stderr] "
        cursor = self.command_output.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.insertText(prefix + text)
        self.command_output.setTextCursor(cursor)
        self.command_output.ensureCursorVisible()

    def _stop_commands(self) -> None:
        active = list(self.runtime.runner.active_processes())
        if not active:
            self.command_status.setText("No active local process.")
            return
        async def stop_all():
            results = []
            for command_id in active:
                results.append(await self.runtime.runner.stop(command_id))
            return results
        self._dispatch("stop_command", stop_all())

    def _refresh_history(self) -> None:
        if not hasattr(self, "history_table"):
            return
        rows = self.runtime.command_history(self.history_search.text() if hasattr(self, "history_search") else "", 200)
        self.history_table.setRowCount(0)
        for row_data in rows:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            args = row_data.get("arguments", [])
            values = [
                str(row_data.get("started_at", ""))[:19].replace("T", " "),
                str(row_data.get("program", "")),
                shlex.join([str(item) for item in args])[:600],
                str(row_data.get("cwd", "")),
                str(row_data.get("status", "")),
                str(row_data.get("exit_code", "")),
            ]
            for col, value in enumerate(values):
                cell = QTableWidgetItem(value)
                if col == 0:
                    cell.setData(Qt.ItemDataRole.UserRole, row_data)
                self.history_table.setItem(row, col, cell)
        self.history_output.setPlainText("Select a history record to inspect its redacted stdout/stderr and log location.")

    def _history_selected(self) -> None:
        selected = self.history_table.selectedItems()
        if not selected:
            return
        row_data = selected[0].data(Qt.ItemDataRole.UserRole)
        if not isinstance(row_data, dict):
            return
        text = (
            f"Program: {row_data.get('program')} {shlex.join(row_data.get('arguments', []))}\n"
            f"Working directory: {row_data.get('cwd')}\n"
            f"Status: {row_data.get('status')} · exit {row_data.get('exit_code')} · {row_data.get('duration_seconds')} s\n"
            f"Log: {row_data.get('log_path') or 'unavailable'}\n\n[stdout]\n{row_data.get('stdout', '')}\n\n[stderr]\n{row_data.get('stderr', '')}"
        )
        self.history_output.setPlainText(text)

    def _clear_history(self) -> None:
        if QMessageBox.question(self, "Clear command history", "Delete all local command history records and their NOVA-owned log files? This does not undo commands or delete files touched by commands.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        deleted = self.runtime.clear_command_history()
        self._refresh_history()
        self._show_info(f"Deleted {deleted} local history record(s) and their logs. No command effects were undone.")

    def _refresh_workspaces(self) -> None:
        if not hasattr(self, "workspace_list"):
            return
        roots = self.runtime.workspace_roots()
        active = self.runtime.active_workspace()
        self.workspace_list.clear()
        for root in roots:
            marker = "  · active" if root == active else ""
            item = QListWidgetItem(root + marker)
            item.setData(Qt.ItemDataRole.UserRole, root)
            self.workspace_list.addItem(item)
        self.workspace_detail.setText(f"Active workspace: {active}\nRoutine command prefixes are only auto-allowed inside a selected scope. File access is bounded by the existing workspace tools.")
        if hasattr(self, "command_cwd"):
            self.command_cwd.blockSignals(True)
            self.command_cwd.clear()
            for root in roots:
                self.command_cwd.addItem(root, root)
            active_index = self.command_cwd.findData(active)
            if active_index >= 0:
                self.command_cwd.setCurrentIndex(active_index)
            self.command_cwd.blockSignals(False)

    def _add_workspace(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Choose an authorized workspace directory", os.path.expanduser("~"))
        if not selected:
            return
        roots = self.runtime.workspace_roots()
        if selected not in roots:
            roots.append(selected)
        try:
            self.runtime.set_workspace_roots(roots, active=selected)
            self._refresh_workspaces()
            self._refresh_permissions()
        except Exception as exc:
            self._show_error(f"Could not add that workspace ({type(exc).__name__}).")

    def _remove_workspace(self) -> None:
        selected = self.workspace_list.currentItem()
        if not selected:
            return
        roots = self.runtime.workspace_roots()
        root = str(selected.data(Qt.ItemDataRole.UserRole))
        roots = [item for item in roots if item != root]
        if not roots:
            self._show_error("Keep at least one authorized workspace directory.")
            return
        active = self.runtime.active_workspace()
        if active == root:
            active = roots[0]
        self.runtime.set_workspace_roots(roots, active=active)
        self._refresh_workspaces()
        self._refresh_permissions()

    def _set_active_workspace(self) -> None:
        selected = self.workspace_list.currentItem()
        if not selected:
            return
        root = str(selected.data(Qt.ItemDataRole.UserRole))
        try:
            self.runtime.set_workspace_roots(self.runtime.workspace_roots(), active=root)
            self._refresh_workspaces()
            self._refresh_status()
        except Exception as exc:
            self._show_error(f"Could not select workspace ({type(exc).__name__}).")

    def _provider_changed(self) -> None:
        if not hasattr(self, "provider_combo"):
            return
        provider = self.provider_combo.currentData()
        item = PROVIDER_CATALOG.get(provider, {})
        self.base_url.setText(item.get("default_base_url", ""))
        self.provider_note.setText(item.get("note", ""))
        backend = self.runtime.secret_store.backend_status()
        self.secret_note.setText(backend["detail"])
        self.api_key.setEnabled(bool(backend["available"]))

    def _refresh_models(self) -> None:
        if not hasattr(self, "profile_list"):
            return
        profiles = self.runtime.model_manager.list_profiles()
        selected = self._selected_profile_id
        self.profile_list.blockSignals(True)
        self.profile_list.clear()
        for profile in profiles:
            status = profile.get("status", "unknown")
            icon = "●" if profile.get("available") else ("◷" if profile.get("configured") else "○")
            title = f"{icon}  {profile.get('name', profile.get('model_id', 'Model'))}  ·  {status}"
            item = QListWidgetItem(title)
            item.setData(Qt.ItemDataRole.UserRole, profile["id"])
            item.setToolTip(f"{profile.get('provider_label')} · {profile.get('model_id')}\nCredential reference: {profile.get('api_key_env')} (value hidden)")
            self.profile_list.addItem(item)
            if profile["id"] == selected:
                self.profile_list.setCurrentItem(item)
        self.profile_list.blockSignals(False)
        if self.profile_list.currentItem():
            self._profile_selected(self.profile_list.currentItem(), None)
        else:
            self.profile_status.setText(f"{len(profiles)} profile(s). No provider request is made by refreshing this list.")
        backend = self.runtime.secret_store.backend_status()
        self.secret_note.setText(backend["detail"])
        self.api_key.setEnabled(bool(backend["available"]))
        if hasattr(self, "gateway_privacy_summary") and hasattr(self.runtime, "hybrid_cloud"):
            txms = self.runtime.hybrid_cloud.db.list_cloud_transmissions(limit=5)
            queued_n = len(self.runtime.hybrid_cloud.db.list_offline_cloud_tasks(status="queued_waiting_cloud", limit=50))
            local_projs = len([p for p in self.runtime.hybrid_cloud.db.list_local_only_projects() if p.get("local_only")])
            last_txm = (
                f"Latest outbound ledger: {txms[0]['provider_type']} ({txms[0]['decision']}, files={len(txms[0]['included_files'])})"
                if txms
                else "No external cloud model transmissions logged yet."
            )
            self.gateway_privacy_summary.setText(
                f"Offline cloud queue: {queued_n} waiting · Local-only projects: {local_projs}\n{last_txm}"
            )
        self._refresh_status()

    def _profile_selected(self, current: QListWidgetItem | None, _previous: QListWidgetItem | None) -> None:
        if not current:
            return
        self._selected_profile_id = str(current.data(Qt.ItemDataRole.UserRole) or "")
        profile = self.runtime.model_manager.get_profile(self._selected_profile_id)
        if not profile:
            return
        summary = (
            f"{profile.get('provider_label')} · {profile.get('model_id')}\n"
            f"Status: {profile.get('status')} · configured: {profile.get('configured')} · connected: {profile.get('connected')} · "
            f"available: {profile.get('available')} · tested: {profile.get('tested')} · actually_used: {profile.get('actually_used')}\n"
            f"Capabilities: {', '.join(profile.get('capabilities', []))} · tools test: {profile.get('tools_test_status', 'untested')}\n"
            f"Credential reference: {profile.get('api_key_env')} (secret value not shown)"
        )
        self.profile_status.setText(summary)
        managed = profile.get("managed", True)
        self.test_connection_button.setEnabled(bool(managed and profile.get("configured")))
        self.eval_tools_button.setEnabled(bool(managed and profile.get("configured")))

    def _delete_provider_key(self) -> None:
        if not self.runtime.secret_store.backend_status()["available"]:
            self._show_error("Secret Service is unavailable; no keyring credential can be deleted from this app.")
            return
        provider = str(self.provider_combo.currentData() or "")
        selected = self.profile_list.currentItem()
        if selected:
            profile = self.runtime.model_manager.get_profile(str(selected.data(Qt.ItemDataRole.UserRole)))
            if profile and profile.get("provider_type") in SECRET_ENV_NAMES:
                provider = str(profile["provider_type"])
        provider_name = PROVIDER_CATALOG.get(provider, {}).get("label", provider)
        if QMessageBox.question(self, "Delete provider credential", f"Delete the shared saved key for {provider_name} from Secret Service? Every local profile using that credential reference will stop working until you save a key again.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        self.delete_key_button.setEnabled(False)
        async def remove():
            return await asyncio.to_thread(self.runtime.delete_provider_key, provider)
        self._dispatch("credential_delete", remove())

    def _save_profile(self) -> None:
        provider = str(self.provider_combo.currentData() or "")
        model_id = self.model_id.text().strip()
        if not model_id:
            self._show_error("Enter the exact model ID for the selected provider account. NOVA does not assume model access.")
            return
        if provider not in SECRET_ENV_NAMES:
            self._show_error("No approved credential mapping exists for this provider.")
            return
        key = self.api_key.text()
        if key and not self.runtime.secret_store.backend_status()["available"]:
            self._show_error("Linux Secret Service is unavailable. The key will not be stored in plaintext or SQLite.")
            return
        data = {
            "name": self.profile_name.text().strip() or f"{PROVIDER_CATALOG[provider]['label']} · {model_id}",
            "provider_type": provider,
            "base_url": self.base_url.text().strip(),
            "model_id": model_id,
            "capabilities": ["chat", *( ["tools"] if self.profile_tools.isChecked() else [] )],
            "is_default": self.profile_default.isChecked(),
        }
        if QMessageBox.question(self, "Save model profile", "Save provider endpoint/model metadata locally and the API key (if entered) only to Secret Service? This sends no network request.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        self.save_profile_button.setEnabled(False)
        async def save():
            return await asyncio.to_thread(self.runtime.save_provider_profile, data, key)
        self._dispatch("profile_save", save())

    def _set_default_profile(self) -> None:
        if not self._selected_profile_id:
            self._show_error("Select a model profile first.")
            return
        try:
            profile = self.runtime.model_manager.set_default(self._selected_profile_id)
            self._refresh_models()
            self._show_info(f"Default model profile set to {profile.get('name', profile.get('model_id')) if profile else 'selected profile'}.")
        except Exception as exc:
            self._show_error(f"Could not set the default profile ({type(exc).__name__}).")

    def _test_connection(self) -> None:
        if not self._selected_profile_id:
            return
        if QMessageBox.question(self, "Test provider connection", "Send one small test prompt to the selected official provider API? This makes a real network request and may be billable. The test does not execute tools.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        self.test_connection_button.setEnabled(False)
        self._dispatch("model_test", self.runtime.model_manager.test_connection(self._selected_profile_id))

    def _evaluate_profile(self) -> None:
        if not self._selected_profile_id:
            return
        if QMessageBox.question(self, "Validate tool calling", "Run up to three small inference tests (instruction following, JSON, and a synthetic function-call proposal)? Requests may be billable. The function call is never executed.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        self.eval_tools_button.setEnabled(False)
        self._dispatch("model_eval", self.runtime.model_manager.evaluate(self._selected_profile_id))

    def _refresh_permissions(self) -> None:
        if not hasattr(self, "prefixes_editor"):
            return
        policy = self.runtime.get_permission_settings()
        index = self.autonomy_combo.findData(policy.get("level", "routine"))
        if index >= 0:
            self.autonomy_combo.setCurrentIndex(index)
        prefixes = policy.get("trusted_command_prefixes", DEFAULT_TRUSTED_PREFIXES)
        self.prefixes_editor.setPlainText("\n".join(shlex.join(item) for item in prefixes))
        if hasattr(self, "personal_mode_combo") and hasattr(self.runtime, "personal_policy"):
            pp_stat = self.runtime.personal_policy.status_summary()
            p_idx = self.personal_mode_combo.findData(pp_stat.get("profile_mode", "balanced"))
            if p_idx >= 0:
                self.personal_mode_combo.setCurrentIndex(p_idx)
            self.personal_policy_summary.setText(
                f"Deployment: {pp_stat['deployment_model']} · Active persistent grants: {pp_stat['active_persistent_grants_count']} "
                f"(cyber labs: {pp_stat['cyber_lab_grants_count']}) · External transfers logged: {pp_stat['external_transfers_logged_count']} "
                f"· Strict OWASP mandatory: {pp_stat['strict_owasp_checklist_mandatory']}"
            )
        tools = self.runtime.registry.all_tools()
        rows = []
        for item in tools:
            rows.append(f"{item['name']} · {item['category']} · autonomy_class={item['autonomy_class']}\n  {item['permission']}")
        self.tool_classification.setPlainText("\n\n".join(rows))

    def _save_personal_policy_mode(self) -> None:
        if not hasattr(self.runtime, "personal_policy"):
            return
        mode = str(self.personal_mode_combo.currentData() or "balanced")
        try:
            self.runtime.personal_policy.autonomy.configure_policy(profile_mode=mode)
            self._refresh_permissions()
            self._show_info(f"Personal-use security & autonomy mode updated to '{mode}'.")
        except Exception as exc:
            self._show_error(f"Could not save personal policy mode ({type(exc).__name__}: {exc}).")

    def _save_autonomy(self) -> None:
        level = str(self.autonomy_combo.currentData() or "routine")
        try:
            self.runtime.update_autonomy(level)
            self._show_info(f"Autonomy level saved: {level}. Registered tool boundaries and command-specific gates remain in force.")
        except Exception as exc:
            self._show_error(f"Could not save the autonomy level ({type(exc).__name__}).")

    def _save_prefixes(self) -> None:
        raw = [line.strip() for line in self.prefixes_editor.toPlainText().splitlines() if line.strip() and not line.strip().startswith("#")]
        try:
            prefixes = self.runtime.set_trusted_prefixes(raw)
        except Exception as exc:
            self._show_error(str(exc))
            return
        self._refresh_permissions()
        self._show_info(f"Saved {len(prefixes)} exact command prefix(es). Changes apply only inside the selected workspace scope; restricted operations still ask every time.")

    def _refresh_diagnostics(self) -> None:
        if not hasattr(self, "diagnostic_output"):
            return
        details = self.runtime.diagnostics()
        lines = ["NOVA X LOCAL DIAGNOSTICS", "Read-only · no provider request · no network service", ""]
        for item in details.get("checks", []):
            lines.append(f"{item['status'].upper():<10} {item['name']}\n           {item['detail']}")
        lines.append("")
        lines.append(f"Database: {details.get('database_path')}")
        lines.append(f"Workspace roots: {', '.join(details.get('workspace_roots', []))}")
        self.diagnostic_output.setPlainText("\n".join(lines))

    # ---------------------------------------- §146 Universal Creation Studio UI

    def _build_studio_page(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        layout.addWidget(
            _page_header(
                "Creation studio",
                "Turn natural-language specifications into tested, inspectable software, designs, media, 3D models, data studies, games, and documents.",
            )
        )

        # Top row: Prompt, Artifact recognition, Templates, Model selection, Resource & Build status
        _, prompt_card = _card(layout)
        top_meta = QHBoxLayout()
        self.studio_artifact_badge = _label("Artifact: awaiting prompt", "statusPill")
        self.studio_resource_badge = _label("Resources: probing…", "statusPill")
        self.studio_progress_pill = _label("IDLE · no build running", "statusPill")
        top_meta.addWidget(self.studio_artifact_badge)
        top_meta.addWidget(self.studio_resource_badge)
        top_meta.addStretch(1)
        top_meta.addWidget(self.studio_progress_pill)
        prompt_card.addLayout(top_meta)

        self.studio_prompt = QPlainTextEdit()
        self.studio_prompt.setPlaceholderText(
            "Describe the digital product or technical artifact to create (e.g., 'Build a desktop task utility, test it, and package its source')…"
        )
        self.studio_prompt.setMaximumHeight(92)
        self.studio_prompt.textChanged.connect(self._studio_recognize)
        prompt_card.addWidget(self.studio_prompt)

        selectors = QHBoxLayout()
        selectors.addWidget(_label("Template / Blueprint", "muted"))
        self.studio_template_combo = QComboBox()
        self.studio_template_combo.addItem("Auto-detect from request", "")
        for dom in ("software", "visual_design", "media", "3d", "game", "web_mobile", "database", "ml", "simulation", "engineering", "education", "business", "document", "integration"):
            self.studio_template_combo.addItem(f"Domain: {dom}", dom)
        selectors.addWidget(self.studio_template_combo, 1)

        selectors.addWidget(_label("Model / Provider", "muted"))
        self.studio_model_combo = QComboBox()
        self.studio_model_combo.addItem("Local deterministic studio (zero API cost)", "")
        selectors.addWidget(self.studio_model_combo, 1)

        self.studio_package_check = QCheckBox("Package handover archive")
        self.studio_package_check.setChecked(True)
        selectors.addWidget(self.studio_package_check)

        self.studio_build_button = QPushButton("Create & verify deliverable")
        self.studio_build_button.setProperty("primary", True)
        self.studio_build_button.clicked.connect(self._studio_build)
        selectors.addWidget(self.studio_build_button)
        prompt_card.addLayout(selectors)

        # Middle splitter: Projects + Tool Discovery + Plan on left; Files + QA + Preview + Revisions + Errors on right
        split = QSplitter(Qt.Orientation.Horizontal)

        left_widget = QWidget()
        left_col = QVBoxLayout(left_widget)
        left_col.setContentsMargins(0, 0, 0, 0)
        left_col.setSpacing(10)
        _, proj_card = _card(left_col)
        proj_card.addWidget(_label("Studio projects", "sectionTitle"))
        self.studio_projects_list = QListWidget()
        self.studio_projects_list.setMinimumHeight(130)
        self.studio_projects_list.currentRowChanged.connect(self._studio_select_project)
        proj_card.addWidget(self.studio_projects_list)

        _, tools_card = _card(left_col)
        tools_card.addWidget(_label("Available host tools & task plan", "sectionTitle"))
        self.studio_tools_box = _read_only_text(90)
        tools_card.addWidget(self.studio_tools_box)
        self.studio_plan_box = _read_only_text(90)
        tools_card.addWidget(self.studio_plan_box)
        split.addWidget(left_widget)

        right_widget = QWidget()
        right_col = QVBoxLayout(right_widget)
        right_col.setContentsMargins(0, 0, 0, 0)
        right_col.setSpacing(10)
        _, files_card = _card(right_col)
        files_card.addWidget(_label("Project files, preview & QA results", "sectionTitle"))
        self.studio_files_table = QTableWidget(0, 3)
        self.studio_files_table.setHorizontalHeaderLabels(["Path", "Category", "Bytes"])
        self.studio_files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.studio_files_table.setMinimumHeight(130)
        files_card.addWidget(self.studio_files_table)

        self.studio_preview_box = _read_only_text(80)
        files_card.addWidget(self.studio_preview_box)
        self.studio_tests_box = _read_only_text(90)
        files_card.addWidget(self.studio_tests_box)

        _, rev_card = _card(right_col)
        rev_card.addWidget(_label("Continue editing, revisions, packaging & limitations", "sectionTitle"))
        cont_row = QHBoxLayout()
        self.studio_continue_input = QLineEdit()
        self.studio_continue_input.setPlaceholderText("Refinement note or checkpoint continuation instruction…")
        cont_row.addWidget(self.studio_continue_input, 1)
        self.studio_continue_button = QPushButton("Continue editing")
        self.studio_continue_button.clicked.connect(self._studio_continue)
        cont_row.addWidget(self.studio_continue_button)
        self.studio_compare_button = QPushButton("Compare revisions")
        self.studio_compare_button.clicked.connect(self._studio_compare)
        cont_row.addWidget(self.studio_compare_button)
        self.studio_package_button = QPushButton("Export handover")
        self.studio_package_button.clicked.connect(self._studio_package)
        cont_row.addWidget(self.studio_package_button)
        self.studio_blueprint_button = QPushButton("Save blueprint")
        self.studio_blueprint_button.clicked.connect(self._studio_save_blueprint)
        cont_row.addWidget(self.studio_blueprint_button)
        rev_card.addLayout(cont_row)

        self.studio_diff_box = _read_only_text(70)
        rev_card.addWidget(self.studio_diff_box)
        self.studio_errors_box = _read_only_text(70)
        rev_card.addWidget(self.studio_errors_box)
        split.addWidget(right_widget)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 3)
        layout.addWidget(split, 1)
        return _scrollable(content)

    def _refresh_studio(self) -> None:
        if not hasattr(self, "studio_tools_box"):
            return
        snap = self.runtime.creation_studio_snapshot()
        budget = snap.get("resource_budget", {})
        sample = budget.get("sample") or {}
        self.studio_resource_badge.setText(
            f"Pressure: {budget.get('pressure', 'normal')} · RAM free ~{sample.get('memory_available_mb', 0)} MB"
        )
        installed = snap.get("installed_tools", [])
        missing = snap.get("missing_optional_tools", [])
        self.studio_tools_box.setPlainText(
            f"Installed host tools ({len(installed)}): {', '.join(installed) or 'Python stdlib'}\n"
            f"Supported formats ({len(snap.get('processable_formats', []))}): {', '.join(snap.get('processable_formats', [])[:14])}\n"
            f"Optional uninstalled tools: {', '.join(missing[:6]) or 'none'}"
        )

        self.studio_model_combo.blockSignals(True)
        current_model = self.studio_model_combo.currentData()
        self.studio_model_combo.clear()
        self.studio_model_combo.addItem("Local deterministic studio (zero API cost)", "")
        for prof in snap.get("models", []):
            state = "ready" if prof.get("available") else "unconfigured"
            self.studio_model_combo.addItem(f"{prof.get('name')} ({state})", prof.get("id"))
        idx = self.studio_model_combo.findData(current_model)
        if idx >= 0:
            self.studio_model_combo.setCurrentIndex(idx)
        self.studio_model_combo.blockSignals(False)

        projects = snap.get("projects", [])
        self.studio_projects_list.blockSignals(True)
        self.studio_projects_list.clear()
        selected_row = -1
        for row_idx, proj in enumerate(projects):
            item = QListWidgetItem(f"{proj['name']} [{proj['domain']}] · v{proj['current_version']} · {proj['status']}")
            item.setData(Qt.ItemDataRole.UserRole, proj["id"])
            self.studio_projects_list.addItem(item)
            if proj["id"] == self._selected_creation_project_id:
                selected_row = row_idx
        if selected_row >= 0:
            self.studio_projects_list.setCurrentRow(selected_row)
        self.studio_projects_list.blockSignals(False)

    def _studio_recognize(self) -> None:
        raw = self.studio_prompt.toPlainText().strip()
        if not raw:
            self.studio_artifact_badge.setText("Artifact: awaiting prompt")
            self.studio_plan_box.setPlainText("Enter a creation request to preview recognized artifact domain and milestones.")
            return
        intent = self.runtime.recognize_creation_intent(raw)
        self.studio_artifact_badge.setText(f"Artifact: {intent['domain']} / {intent['artifact_type']}")
        plan_lines = ["Recognized milestones:", *[f"  {m}" for m in intent.get("milestones", [])]]
        if intent.get("unmet_external_capabilities"):
            plan_lines.append("\nUnmet external capabilities (will report honestly):")
            plan_lines.extend(f"  - {u}" for u in intent["unmet_external_capabilities"])
        self.studio_plan_box.setPlainText("\n".join(plan_lines))

    def _studio_build(self) -> None:
        prompt = self.studio_prompt.toPlainText().strip()
        if not prompt:
            self._show_error("Describe the digital product or artifact you want NOVA X to build.")
            return
        domain_override = str(self.studio_template_combo.currentData() or "")
        self.studio_build_button.setEnabled(False)
        self.studio_progress_pill.setText("BUILDING & VERIFYING…")
        self._dispatch(
            "studio_build",
            self.runtime.create_deliverable(
                prompt,
                domain_override=domain_override,
                package=self.studio_package_check.isChecked(),
            ),
        )

    def _studio_select_project(self, row: int) -> None:
        if row < 0:
            return
        item = self.studio_projects_list.item(row)
        if item is not None:
            pid = str(item.data(Qt.ItemDataRole.UserRole) or "")
            if pid:
                self._selected_creation_project_id = pid
                self._studio_render_project(pid)

    def _studio_render_project(self, project_id: str) -> None:
        if not project_id:
            return
        opened = self.runtime.open_creation_project(project_id)
        if not opened:
            return
        explorer = opened.get("explorer") or {}
        files = explorer.get("files") or []
        self.studio_files_table.setRowCount(len(files))
        for r_idx, fmeta in enumerate(files):
            self.studio_files_table.setItem(r_idx, 0, QTableWidgetItem(str(fmeta.get("path", ""))))
            self.studio_files_table.setItem(r_idx, 1, QTableWidgetItem(str(fmeta.get("category", ""))))
            self.studio_files_table.setItem(r_idx, 2, QTableWidgetItem(str(fmeta.get("size_bytes", 0))))

        report = opened.get("latest_report") or {}
        qa = report.get("qa") or {}
        pkg = report.get("package") or {}
        self.studio_preview_box.setPlainText(
            f"Workspace: {opened.get('project_dir')}\n"
            f"Primary outputs: {', '.join(report.get('primary_artifacts', [])) or 'none'}\n"
            f"Handover archive: {pkg.get('archive_path', 'not packaged')}"
        )
        checks_lines = [
            f"QA Passed: {qa.get('passed', False)} · Score: {qa.get('quality_score', 0.0)} ({qa.get('passed_checks', 0)}/{qa.get('total_checks', 0)} checks)"
        ]
        for chk in (qa.get("checks") or [])[:12]:
            mark = "PASS" if chk.get("passed") else "FAIL"
            checks_lines.append(f"  [{mark}] {chk.get('name')}: {chk.get('detail')}")
        self.studio_tests_box.setPlainText("\n".join(checks_lines))
        issues = opened.get("known_issues") or []
        self.studio_errors_box.setPlainText("\n".join(f"- {lim}" for lim in issues) or "No unresolved defects; host toolchain bounds noted in project spec.")

    def _studio_continue(self) -> None:
        if not self._selected_creation_project_id:
            self._show_error("Select a project first.")
            return
        note = self.studio_continue_input.text().strip()
        self.studio_continue_button.setEnabled(False)
        self.studio_progress_pill.setText("CONTINUING & RE-TESTING…")
        self._dispatch(
            "studio_continue",
            self.runtime.continue_creation_project(self._selected_creation_project_id, note),
        )
        self.studio_continue_input.clear()

    def _studio_package(self) -> None:
        if not self._selected_creation_project_id:
            self._show_error("Select a project first.")
            return
        self.studio_package_button.setEnabled(False)
        self.studio_progress_pill.setText("PACKAGING HANDOVER…")
        self._dispatch("studio_package", self.runtime.package_creation_project(self._selected_creation_project_id))

    def _studio_compare(self) -> None:
        if not self._selected_creation_project_id:
            self._show_error("Select a project first.")
            return
        cmp_res = self.runtime.compare_creation_revisions(self._selected_creation_project_id)
        if not cmp_res.get("comparable"):
            self.studio_diff_box.setPlainText(f"Comparison status: {cmp_res.get('reason', 'needs >= 2 revisions')}")
            return
        lines = [
            f"Compared v{cmp_res['version_a']} -> v{cmp_res['version_b']} · QA delta: {cmp_res['score_delta']:+.4f}",
            *[f"  {c['change'].upper()}: {c['path']}" for c in cmp_res.get("changed_files", [])[:15]],
        ]
        for rel_p, diff_txt in list((cmp_res.get("diffs") or {}).items())[:2]:
            lines.append(f"\n--- Diff: {rel_p} ---\n{diff_txt[:1200]}")
        self.studio_diff_box.setPlainText("\n".join(lines))

    def _studio_save_blueprint(self) -> None:
        if not self._selected_creation_project_id:
            self._show_error("Select a verified project first.")
            return
        try:
            bp = self.runtime.create_blueprint_from_project(self._selected_creation_project_id)
            self._show_info(f"Saved credential-scrubbed blueprint '{bp['name']}' ({bp['id']} v{bp['version']}).")
            self._refresh_studio()
        except Exception as exc:
            self._show_error(str(exc))

    # ---------------------------------------- §22 Unified OS Control Center

    def _build_control_center_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        head_card, head = _card()
        head_row = QHBoxLayout()
        head_row.addWidget(_label("Unified OS Control Center (§3–§22)", "title"))
        head_row.addStretch(1)
        self.cc_worker_pill = _label("Worker: checking…", "statusPill")
        head_row.addWidget(self.cc_worker_pill)
        self.cc_refresh_btn = QPushButton("Refresh")
        self.cc_refresh_btn.setProperty("quiet", True)
        self.cc_refresh_btn.clicked.connect(self._refresh_control_center)
        head_row.addWidget(self.cc_refresh_btn)
        head.addLayout(head_row)
        head.addWidget(
            _label(
                "One interface over shared memory & FTS5 search, plugins/MCP integrations, voice/visual modalities, "
                "desktop session control, background worker status, and isolated self-improvement experiments.",
                "muted",
                word_wrap=True,
            )
        )
        layout.addWidget(head_card)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_card, left = _card()
        mem_top = QHBoxLayout()
        mem_top.addWidget(_label("Shared Memory & FTS5 Search (§14)", "sectionTitle"))
        mem_top.addStretch(1)
        self.cc_memory_enabled_check = QCheckBox("Memory enabled")
        self.cc_memory_enabled_check.setChecked(True)
        self.cc_memory_enabled_check.toggled.connect(self._cc_toggle_memory)
        mem_top.addWidget(self.cc_memory_enabled_check)
        left.addLayout(mem_top)

        search_row = QHBoxLayout()
        self.cc_memory_query = QLineEdit()
        self.cc_memory_query.setPlaceholderText("Search FTS5 memory & indexed documents…")
        search_btn = QPushButton("Search")
        search_btn.clicked.connect(self._cc_search_memory)
        search_row.addWidget(self.cc_memory_query, 1)
        search_row.addWidget(search_btn)
        left.addLayout(search_row)

        self.cc_memory_box = QPlainTextEdit()
        self.cc_memory_box.setReadOnly(True)
        left.addWidget(self.cc_memory_box, 1)

        add_row = QHBoxLayout()
        self.cc_note_subject = QLineEdit()
        self.cc_note_subject.setPlaceholderText("Preference / context title")
        self.cc_note_body = QLineEdit()
        self.cc_note_body.setPlaceholderText("Approved preference or note (secrets rejected)")
        save_mem_btn = QPushButton("Save note")
        save_mem_btn.clicked.connect(self._cc_save_preference)
        add_row.addWidget(self.cc_note_subject, 1)
        add_row.addWidget(self.cc_note_body, 2)
        add_row.addWidget(save_mem_btn)
        left.addLayout(add_row)
        splitter.addWidget(left_card)

        right_card, right = _card()
        right.addWidget(_label("Plugins, MCP, Desktop Session & Multimodal (§10–§16)", "sectionTitle"))
        self.cc_ecosystem_box = QPlainTextEdit()
        self.cc_ecosystem_box.setReadOnly(True)
        self.cc_ecosystem_box.setMaximumHeight(175)
        right.addWidget(self.cc_ecosystem_box)

        ptt_row = QHBoxLayout()
        self.cc_ptt_input = QLineEdit()
        self.cc_ptt_input.setPlaceholderText("Push-to-talk / voice loopback test phrase…")
        ptt_btn = QPushButton("Push-to-talk check")
        ptt_btn.setProperty("quiet", True)
        ptt_btn.clicked.connect(self._cc_push_to_talk_check)
        ptt_row.addWidget(self.cc_ptt_input, 1)
        ptt_row.addWidget(ptt_btn)
        right.addLayout(ptt_row)

        right.addWidget(_label("Architecture, Worker & Self-Improvement (§17, §20)", "sectionTitle"))
        self.cc_system_box = QPlainTextEdit()
        self.cc_system_box.setReadOnly(True)
        right.addWidget(self.cc_system_box, 1)
        splitter.addWidget(right_card)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)
        return page

    def _refresh_control_center(self) -> None:
        snap = self.runtime.control_center_snapshot()
        worker = snap["worker"]
        self.cc_worker_pill.setText(f"Worker: {worker['status'].upper()}")
        mem = snap["memory"]
        self.cc_memory_enabled_check.blockSignals(True)
        self.cc_memory_enabled_check.setChecked(bool(mem["memory_enabled"]))
        self.cc_memory_enabled_check.blockSignals(False)

        mem_lines = [
            f"FTS5: {mem['fts5_available']} · Retention/category: {mem['retention_per_category']} · Stored entries: {len(mem['entries'])}",
            *[
                f"- [{e['category']}] {e['subject']} ({'verified' if e['verified_fact'] else e['provenance']}): {e['content'][:110]}"
                for e in mem["entries"][:15]
            ],
        ]
        self.cc_memory_box.setPlainText("\n".join(mem_lines))

        ds = snap["desktop_session"]
        voice = snap["voice"]
        visual = snap["visual"]
        eco_lines = [
            f"Desktop session: {ds['display_server']} (interactive_ready={ds['interactive_ready']}, adapters={', '.join(ds['available_adapters']) or 'none'})",
            f"Voice modality: enabled={voice.get('enabled')}, mic_active={voice.get('microphone_active')}, speaker_id_privileged=False",
            f"Visual modality: capture_available={visual.get('capture_available')}, ocr_available={visual.get('ocr_available')}, continuous=False",
            f"Plugins installed: {len(snap['plugins'])} · Integrations: {len(snap['integrations'])} · MCP servers: {len(snap['mcp_servers'])}",
        ]
        for plg in snap["plugins"][:6]:
            eco_lines.append(f"  • Plugin {plg.get('name')} ({plg.get('version')}) — enabled={plg.get('enabled')}")
        self.cc_ecosystem_box.setPlainText("\n".join(eco_lines))

        exps = snap["experiments"]
        arch_mods = snap["architecture"]["modules"]
        sys_lines = [
            f"12 Unified Modules Active · Non-root={not snap['architecture']['running_as_root']} · Resource pressure={snap['resources']['pressure']}",
            f"Background note: {worker['honesty_note']}",
            f"Scheduled goals: {len(snap['goals'])} · Self-improvement experiments: {len(exps)} (auto_overwrite_stable=False)",
            *[f"  • {k}: {v['module']}" for k, v in list(arch_mods.items())[:6]],
        ]
        self.cc_system_box.setPlainText("\n".join(sys_lines))

    def _cc_toggle_memory(self, checked: bool) -> None:
        self.runtime.platform.memory.set_enabled(bool(checked))
        self._refresh_control_center()

    def _cc_search_memory(self) -> None:
        q = self.cc_memory_query.text().strip()
        if not q:
            self._refresh_control_center()
            return
        res = self.runtime.platform.memory.retrieve_relevant_context(q, max_chars=2_000, limit=8)
        self.cc_memory_box.setPlainText(res["formatted_context"] or "No matching FTS5 memory or document chunks.")

    def _cc_save_preference(self) -> None:
        subj = self.cc_note_subject.text().strip()
        body = self.cc_note_body.text().strip()
        if not subj or not body:
            self._show_error("Provide both a preference title and content.")
            return
        try:
            self.runtime.platform.memory.store(
                category="user_preferences",
                subject=subj,
                content=body,
                provenance="user_approved_preference",
                evidence_verified=True,
            )
            self.cc_note_subject.clear()
            self.cc_note_body.clear()
            self._refresh_control_center()
        except Exception as exc:
            self._show_error(str(exc))

    def _cc_push_to_talk_check(self) -> None:
        phrase = self.cc_ptt_input.text().strip() or "Check system diagnostics"
        status = self.runtime.platform.voice.status()
        self.cc_system_box.appendPlainText(
            f"\n[Voice Push-to-Talk] Typed fallback ready for '{phrase[:80]}' · mic_enabled={status.get('enabled')} · speaker_auth_allowed=False"
        )

    def _build_infrastructure_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(
            _page_header(
                "Hardware, Screen Studio, Resilience & Authorized Servers",
                "Real Linux hardware explorer (§149), driver intelligence (§150), visible segmented screen studio (§155), startup/recovery controls (§153–§154), and pinned-key OpenSSH servers (§157).",
            )
        )

        top_bar = QHBoxLayout()
        self.infra_rec_pill = _label("Recording: IDLE", "statusPill")
        top_bar.addWidget(self.infra_rec_pill)
        self.infra_recovery_pill = _label("Safe Recovery: OFF", "statusPill")
        top_bar.addWidget(self.infra_recovery_pill)
        top_bar.addStretch(1)
        shot_btn = QPushButton("Capture screenshot")
        shot_btn.clicked.connect(self._infra_capture_screenshot)
        top_bar.addWidget(shot_btn)
        self.infra_rec_toggle_btn = QPushButton("Start segmented recording")
        self.infra_rec_toggle_btn.setProperty("primary", True)
        self.infra_rec_toggle_btn.clicked.connect(self._infra_toggle_recording)
        top_bar.addWidget(self.infra_rec_toggle_btn)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._refresh_infrastructure)
        top_bar.addWidget(refresh_btn)
        layout.addLayout(top_bar)

        _, hw_card = _card(layout)
        search_row = QHBoxLayout()
        self.infra_hw_search = QLineEdit()
        self.infra_hw_search.setPlaceholderText("Filter Hardware Explorer by device ID, bus, driver, or status…")
        self.infra_hw_search.returnPressed.connect(self._refresh_infrastructure)
        search_row.addWidget(self.infra_hw_search, 1)
        diag_btn = QPushButton("Run driver & firmware check")
        diag_btn.clicked.connect(self._infra_diagnose_drivers)
        search_row.addWidget(diag_btn)
        kali_btn = QPushButton("Kali Intelligence probe (§181–§200)")
        kali_btn.clicked.connect(self._infra_kali_probe)
        search_row.addWidget(kali_btn)
        hw_card.addLayout(search_row)
        self.infra_hw_box = _read_only_text(170)
        hw_card.addWidget(self.infra_hw_box)

        _, ops_card = _card(layout)
        ops_card.addWidget(_label("Observability, Startup Disclosures & Registered OpenSSH Servers", "sectionTitle"))
        self.infra_ops_box = _read_only_text(180)
        ops_card.addWidget(self.infra_ops_box)
        return page

    def _refresh_infrastructure(self) -> None:
        query = self.infra_hw_search.text().strip() if hasattr(self, "infra_hw_search") else ""
        snap = self.runtime.infrastructure_snapshot(query)
        ind = snap["recording_session"]["active_indicator"]
        if ind.get("recording_active"):
            self.infra_rec_pill.setText(f"Recording: {ind.get('badge_text', '● REC')}")
            self.infra_rec_toggle_btn.setText("Stop recording")
        else:
            self.infra_rec_pill.setText("Recording: IDLE")
            self.infra_rec_toggle_btn.setText("Start segmented recording")

        spol = snap["startup_policy"]
        self.infra_recovery_pill.setText(
            f"Safe Recovery: {'ON (automations paused)' if spol.get('safe_recovery_mode') else 'OFF'}"
        )

        hw = snap["hardware"]
        hw_lines = [
            f"Discovered {hw['total_discovered']} Linux hardware/subsystem records ({hw['match_count']} shown):",
            *[
                f"  • [{d['status_category'].upper()}] {d['device_id']} — {d['name']} | driver={d['driver'] or 'none'} | tier={d['privilege_tier']}"
                for d in hw["results"][:18]
            ],
        ]
        self.infra_hw_box.setPlainText("\n".join(hw_lines))

        obs = snap["observability"]
        srvs = snap["servers"]
        ops_lines = [
            f"Telemetry ({obs['collection_overhead_ms']} ms): CPU load_1m={obs['cpu']['load_1m']} · RAM avail={obs['memory']['available_mb']} MB · Disk free={obs['disk']['free_gb']} GB · Alerts={snap['alerts']['triggered_count']}",
            f"Privileged Helper: pkexec_available={snap['privileged']['pkexec_available']} · allowlisted_ops={len(snap['privileged']['defined_operations'])} · root_ui=False",
            f"Startup Policy ({spol['current_user']}): auto_restore_tasks={spol['policy']['auto_restore_interrupted_tasks']} · user_worker_login={spol['policy']['start_user_worker_at_login']}",
            f"Registered SSH Servers ({len(srvs)}): " + (", ".join(f"{s['alias']} ({s['hostname']}:{s['port']} · {s['connection_health']})" for s in srvs) or "none configured"),
            f"Screen Studio Recordings: {len(snap['recordings'])} saved session(s) · session_type={snap['recording_session']['session_type']}",
            f"Kali Intelligence (§181–§200): profiles={self.runtime.kali_intel.status_summary()['indexed_tool_and_app_profiles']} · docs={self.runtime.kali_intel.status_summary()['indexed_knowledge_documents']} · labs={self.runtime.kali_intel.status_summary()['managed_cyber_labs']}",
            f"Cybersecurity Division (§201–§220): scopes={self.runtime.cyber_division.status_summary()['active_scopes']} · findings={self.runtime.cyber_division.status_summary()['tracked_findings']} · factory_tools={self.runtime.cyber_division.status_summary()['generated_defensive_tools']}",
            f"Software Acquisition & Migration (§221–§235): managed_sw={self.runtime.acquisition_migration.status_summary()['managed_software_count']} · env_profiles={self.runtime.acquisition_migration.status_summary()['environment_profiles_count']} · verified_backups={self.runtime.acquisition_migration.status_summary()['verified_migration_packages_count']}",
            f"General Intelligence (§236–§260): subsystems={self.runtime.general_intelligence.status_summary()['cognitive_subsystems_count']} · memories={self.runtime.general_intelligence.status_summary()['multilayer_memories_count']} · skills={self.runtime.general_intelligence.status_summary()['validated_acquired_skills_count']} · nodes={self.runtime.general_intelligence.status_summary()['registered_distributed_nodes_count']}",
        ]
        self.infra_ops_box.setPlainText("\n".join(ops_lines))

    def _infra_kali_probe(self) -> None:
        q = self.infra_hw_search.text().strip() or "inspect network traffic"
        sys_res = self.runtime.kali_intel.system_model.get_or_refresh_model()
        search_res = self.runtime.kali_intel.tool_engine.search_tools_for_objective(q)
        self.infra_hw_box.appendPlainText(
            f"\n[Kali Intelligence · {sys_res['model']['distribution']['pretty_name']}] "
            f"objective='{q}' -> recommended={search_res['recommended_tool']} "
            f"(installed_matches={search_res['installed_candidates_count']})"
        )

    def _infra_diagnose_drivers(self) -> None:
        q = self.infra_hw_search.text().strip()
        diag = self.runtime.system_access.drivers.diagnose(device_id=q)
        self.infra_hw_box.appendPlainText(
            f"\n[Driver Intelligence · kernel {diag['kernel_release']}] "
            f"loaded_modules={diag['loaded_module_count']} · log_access={diag['kernel_log_access']} · "
            f"findings={len(diag['findings'])} · candidate_repairs={len(diag['candidate_repairs'])}"
        )

    def _infra_capture_screenshot(self) -> None:
        shot = self.runtime.system_access.recording_studio.capture_screenshot(capture_mode="full_screen")
        self.infra_ops_box.appendPlainText(
            f"\n[Screenshot] Saved {shot['path']} ({shot['size_bytes']} bytes via {shot['capture_backend']})."
        )

    def _infra_toggle_recording(self) -> None:
        studio = self.runtime.system_access.recording_studio
        ind = studio.get_indicator_state()
        if ind.get("recording_active") and ind.get("active_recording_id"):
            studio.stop_recording(str(ind["active_recording_id"]))
        else:
            studio.start_recording(title="Desktop Studio Capture", fps=10, user_initiated=True)
        self._refresh_infrastructure()

    def _build_privacy_intel_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(
            _page_header(
                "Tor Network, Legitimate .onion Research & Defensive OSINT (§165)",
                "Isolated Tor SOCKS5h routing (§165.1), v3 .onion verification (§165.2), 11-category unified search (§165.3), 12-step research assistant (§165.4), defensive threat intel (§165.5–§165.6), and 0400 file quarantine (§165.7).",
            )
        )

        top_bar = QHBoxLayout()
        self.priv_tor_pill = _label("TOR INTEGRATION DISABLED", "statusPill")
        top_bar.addWidget(self.priv_tor_pill)
        self.priv_monitor_pill = _label("Monitors: 0", "statusPill")
        top_bar.addWidget(self.priv_monitor_pill)
        top_bar.addStretch(1)
        self.priv_toggle_tor_btn = QPushButton("Enable Tor integration")
        self.priv_toggle_tor_btn.setProperty("primary", True)
        self.priv_toggle_tor_btn.clicked.connect(self._priv_toggle_tor)
        top_bar.addWidget(self.priv_toggle_tor_btn)
        tb_btn = QPushButton("Launch Tor Browser")
        tb_btn.clicked.connect(self._priv_launch_tor_browser)
        top_bar.addWidget(tb_btn)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._refresh_privacy_intel)
        top_bar.addWidget(refresh_btn)
        layout.addLayout(top_bar)

        _, net_card = _card(layout)
        net_card.addWidget(_label("Privacy-Aware Network Routing Dashboard & Anonymity Disclosures (§165.8)", "sectionTitle"))
        self.priv_dashboard_box = _read_only_text(145)
        net_card.addWidget(self.priv_dashboard_box)

        _, res_card = _card(layout)
        q_row = QHBoxLayout()
        self.priv_research_input = QLineEdit()
        self.priv_research_input.setPlaceholderText("Enter OSINT / CVE / authorized v3 .onion research question…")
        self.priv_research_input.returnPressed.connect(self._priv_run_research)
        q_row.addWidget(self.priv_research_input, 1)
        run_res_btn = QPushButton("Run 12-step research")
        run_res_btn.clicked.connect(self._priv_run_research)
        q_row.addWidget(run_res_btn)
        res_card.addLayout(q_row)
        self.priv_intel_box = _read_only_text(185)
        res_card.addWidget(self.priv_intel_box)
        return page

    def _refresh_privacy_intel(self) -> None:
        snap = self.runtime.privacy_intel_snapshot()
        tstat = snap["tor_status"]
        dash = snap["privacy_dashboard"]
        mons = snap["research_monitors"]

        self.priv_tor_pill.setText(tstat["status_indicator"])
        self.priv_toggle_tor_btn.setText(
            "Disable Tor integration" if tstat["tor_integration_enabled"] else "Enable Tor integration"
        )
        self.priv_monitor_pill.setText(
            f"Monitors: {mons['enabled_count']}/{mons['monitor_count']} · Scheduler={'ACTIVE' if mons['continuous_monitoring_active'] else 'STOPPED'}"
        )

        comp_lines = [
            f"Tor Binary: {'installed (' + tstat['tor_binary'] + ')' if tstat['tor_installed'] else 'not installed'} · Service={tstat['tor_service_state']} · SOCKS5h={dash['socks5_endpoint']} ({'reachable' if dash['socks5_reachable'] else 'unreachable'}) · System-wide Tor={dash['system_wide_tor_routing']}",
            *[
                f"  • {cname}: mode={cdata['configured_mode']} | uses_tor={cdata['uses_tor']}"
                for cname, cdata in dash["components"].items()
            ],
            f"Limitation: {dash['anonymity_and_coverage_limitations'][0]}",
        ]
        self.priv_dashboard_box.setPlainText("\n".join(comp_lines))

        intel_lines = [
            f"Saved v3 .onion Bookmarks: {snap['onion_bookmarks_count']} · Onion Hosting Enabled: {snap['onion_hosting_enabled']} (admin API exposure blocked)",
            f"Defensive Threat Findings: {snap['threat_findings_count']} (external claims strictly separated from verified local observations)",
            f"Quarantined Downloads: {snap['quarantined_downloads_count']} (0700 dir / 0400 non-executable; auto_executed=False)",
            f"Monitor Honesty Note: {mons['honest_scheduler_disclosure']}",
        ]
        if tstat["setup_instructions"]:
            intel_lines.append("Kali Setup Hint: " + tstat["setup_instructions"][0])
        self.priv_intel_box.setPlainText("\n".join(intel_lines))

    def _priv_toggle_tor(self) -> None:
        cur = self.runtime.privacy_intel.tor.get_config()["tor_enabled"]
        self.runtime.privacy_intel.tor.update_config({"tor_enabled": not cur})
        self._refresh_privacy_intel()

    def _priv_launch_tor_browser(self) -> None:
        res = self.runtime.privacy_intel.tor.launch_tor_browser(approved=True)
        self.priv_intel_box.appendPlainText(
            f"\n[Tor Browser] status={res['status']} — {res.get('reason') or res.get('argv')}"
        )

    def _priv_run_research(self) -> None:
        q = self.priv_research_input.text().strip()
        if not q:
            self._show_error("Enter a research question first.")
            return
        guard = self.runtime.privacy_intel.check_ethics(q)
        if not guard["allowed"]:
            self._show_error(guard["reason"])
            return
        rep = self.runtime.privacy_intel.research_assistant.conduct_research(q)
        ep = rep["epistemic_separation"]
        self.priv_intel_box.setPlainText(
            f"Report {rep['report_id']} saved to KnowledgeStore ({rep['knowledge_base_doc_id']})\n"
            f"Verified Facts ({len(ep['verified_facts'])}) · Unverified Claims ({len(ep['claims'])}) · "
            f"Contradictions ({len(rep['contradictions'])}) · Scam/Risk Flags ({len(rep['scam_and_unsupported_flags'])})\n\n"
            + rep["markdown_report"][:2400]
        )

    def _emergency_stop(self) -> None:
        if QMessageBox.question(self, "Emergency stop", "Cancel all active tasks and terminate active NOVA child processes? This does not undo changes already made.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        self.emergency_button.setEnabled(False)
        async def stop_all():
            result = await self.runtime.emergency_stop()
            return result
        self._dispatch("emergency_stop", stop_all())

    def closeEvent(self, event) -> None:
        active_tasks = [item for item in self.runtime.list_tasks(200) if item.get("state") not in {"completed", "failed", "cancelled", "paused"}]
        active_commands = self.runtime.runner.active_processes()
        if active_tasks or active_commands:
            answer = QMessageBox.question(self, "Close NOVA X", "Active tasks/commands will be stopped when NOVA closes. Close now?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        self._timer.stop()
        self.runtime.close()
        event.accept()


def launch() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("NOVA X")
    app.setOrganizationName("NOVA X")
    app.setStyle("Fusion")
    bridge = UiBridge()
    try:
        runtime = DesktopRuntime(output_callback=lambda stream, text: bridge.command_output.emit(stream, text))
    except Exception as exc:
        QMessageBox.critical(None, "NOVA X could not start", f"Local initialization failed safely ({type(exc).__name__}).\n\nCheck file permissions and the SQLite diagnostics, then retry.")
        return 1
    window = NovaWindow(runtime, bridge)
    window.show()
    result = app.exec()
    if not runtime.closed:
        runtime.close()
    return int(result)
