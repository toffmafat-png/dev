# NOVA X Native Kali/Linux Desktop

## Status and scope

This is a **native PySide6/Qt desktop application**, backed by local Python services and SQLite. It is separate from the existing FastAPI browser dashboard. The native app does not launch a browser, Gradio, or Streamlit, and it does not start a network listener.

The first complete desktop increment includes:

- Chat and bounded task creation using the existing provider orchestrator, task planner, evidence review, durable checkpoints, and SQLite transcript/task history.
- A task list, editable plan, execution timeline, actual tool results, approval/decline, pause, resume, cancel, and emergency stop.
- Structured local process execution with real stdout/stderr/exit code, bounded output/timeouts, process-group termination, and command history. Agent calls pass program and argument tokens separately; they are never concatenated into a shell command. Agent-mediated shells, interpreters/build runners, direct file readers/scanners/mutators, Git commands, and command wrappers that could invoke them indirectly are disabled in this increment; use the bounded workspace tools for file content. A separate opt-in Bash input is only for text typed by the user and asks for fresh confirmation.
- Explicit workspace roots and one active workspace for the bounded file tools. Workspace agent tools reject credential/private-key paths (including `.env`, `.ssh`, `.aws`, `.kube`, and common key/credential names); they do not walk unrelated directories.
- Persistent exact-token command prefixes inside selected workspace directories. The default list is intentionally narrow. Interpreters/build runners, destructive/admin, privilege-wrapper, package-management, network-transfer, and security-tool actions remain fresh-approval operations and cannot be persistently pre-authorized.
- Optional account-authorized provider profiles. Credentials are stored in the logged-in desktop's Linux Secret Service keyring. The native process ignores unmanaged provider-key environment variables; if a verified keyring backend is missing, it refuses plaintext fallback. Saving profile metadata makes no network call. Connection and tool-capability tests do, and may be billable.
- Local command history and private NOVA-created logs, CLI diagnostics, and a `.deb` package with a desktop entry and icon.

## Deliberately not included yet

There is no always-on background daemon, network service, native goal scheduler, voice/microphone, desktop automation, browser control, multi-user access, self-evolution workflow, or local-model download. Tasks run only while the desktop app is open. Closing the app stops active task/process work; durable checkpoints are preserved and in-flight tasks are marked resumable/cancelled as appropriate. Diagnostics make no provider requests.

## Install the Debian package

The package artifact in this workspace is:

`releases/nova-x-desktop_0.2.0_all.deb`

On a compatible Kali/Debian host, install with the normal package manager and its ordinary authentication prompt:

```bash
sudo apt install ./releases/nova-x-desktop_0.2.0_all.deb
```

The application itself must be launched as the logged-in desktop user, **not root**:

```bash
nova-x
```

It is also listed as **NOVA X** in the application menu. The package installs `/usr/bin/nova-x`, the desktop entry, icon, source modules, and Debian dependencies for Python, HTTPX, Pydantic, keyring, and PySide6/Qt. It does not install or start a service. If a distribution does not provide the listed split PySide6 packages, resolve dependencies from that distribution's trusted repositories or use the source/virtual-environment method below; do not install random wheels or run the application with elevated privileges.

Package metadata can be inspected without installing:

```bash
dpkg-deb --info releases/nova-x-desktop_0.2.0_all.deb
dpkg-deb --contents releases/nova-x-desktop_0.2.0_all.deb
```

## Build the `.deb` from source

From the repository root on Debian/Kali with `dpkg-deb` installed:

```bash
scripts/build_deb.sh
```

This creates `releases/nova-x-desktop_<version>_all.deb`. It copies only the NOVA Python package and packaging assets; it does not bundle credentials, local databases, test data, or workspace files. Re-run `dpkg-deb --info` and `dpkg-deb --contents` after rebuilding.

## Run from a Python virtual environment

Python 3.11 or newer is required by the native package metadata. Qt and Secret Service support are optional for the CLI but required for the native window/key storage.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[desktop]'
nova-x
```

For Kali, using distribution packages for PySide6 and Secret Service integration is generally preferable when available. Start the app from the same logged-in graphical session whose keyring should be used.

## CLI

```bash
nova-x --version
nova-x diagnostics
nova-x exec -- pwd
nova-x exec --cwd ~/NOVA-X-workspace -- ls
nova-x exec --shell -- "printf 'hello from a reviewed script\\n'"
```

`exec` takes structured argv by default. Commands outside the narrow trusted-prefix policy pause for an interactive one-time confirmation; a non-interactive CLI refuses to approve them. `--shell` is a separate user-authored Bash path that always asks first. `--privileged` uses `pkexec`/polkit only when installed and asks for NOVA confirmation plus normal system authentication. NOVA never collects a sudo password. Do not pipe credentials through command arguments.

## First-run setup

1. Launch `nova-x` as your ordinary desktop user.
2. Review **Workspace access**. The default workspace is `~/NOVA-X-workspace`; add other directories only if needed. The bounded file tools use the currently active workspace, while the command page can use any explicitly selected authorized root.
3. Check **Permissions**. Plan review starts enabled for new tasks. Only register narrow commands you trust for repeated routine execution; never trust a shell or a broad code/interpreter command.
4. In **Models & credentials**, select a provider, enter the exact model ID your account can use, and save the key to the keyring. The provider is not contacted until you explicitly test or submit a request. No live account access, subscription, pricing, or quota is assumed.
5. To enable agent tool calls for a model, request the bounded synthetic tool-call evaluation. It makes up to three provider requests and can incur charges; the synthetic function proposal is never executed. Tool routing stays disabled until the identity-matched test passes.
6. Use **Tasks & plans** for tool-mediated work. Review the proposed plan; review each non-routine command/operation separately. Check actual exit codes/output and verification status rather than trusting a model's claim.

## Files and credential protection

- App data: `$XDG_DATA_HOME/nova-x`, normally `~/.local/share/nova-x`.
- Default workspace: `~/NOVA-X-workspace`.
- SQLite database and NOVA-created command logs are restricted to the local account. Command history is capped; clearing it removes its corresponding NOVA log files but cannot undo command effects.
- Model credentials are not written to SQLite, source files, conversation history, command history, or child-process environments. Provider keys are read from Secret Service into the native process only while it runs. The app restores the original process environment on exit.
- Output redaction is best-effort, so avoid passing secrets as command arguments or asking a model to inspect private files. Agent workspace/process tools hard-block common credential paths. Manually approved local commands remain your responsibility and may display data on screen.
- Local SQLite history is not encrypted by NOVA; full-disk/account protection remains the operator's responsibility.

## Security model

- Commands execute using the logged-in user's operating-system privileges by default. NOVA never runs the whole app as root.
- A model response, webpage, repo, file, or tool result cannot authorize a command. Only the user can approve a pending operation through the app, CLI prompt, or system polkit agent.
- Structured process arguments prevent shell-string concatenation for model tool calls. The agent cannot invoke shells/interpreters or common file-reader/scanner programs through the process tool; destructive/system/security/network operations remain approval-gated.
- Persistent trusted prefixes are exact token prefixes, bound to selected workspace directories, and reviewed by the user. Sensitive operations remain gated even if a similar prefix was saved.
- Child processes use a restricted environment that omits provider secrets, receive no stdin, have bounded timeout/output, and are terminated as a process group on cancellation/emergency stop.
- A separate privilege request uses `pkexec` and the desktop polkit agent, if available. Approval in NOVA is not a substitute for system authentication. No fallback to sudo password storage or piping is implemented.

## Verification performed for this artifact

The latest `.deb` was built with `dpkg-deb --root-owner-group`; its metadata and contents were inspected, the extracted Python modules compiled, and the extracted package's CLI diagnostics and real `pwd` command passed in the development sandbox. A temporary offscreen Qt test using extracted Debian Qt packages created the native window and verified all eight pages. The automated process tests cover command policy, real execution, stdout/exit status, timeout/stop, redaction, keyring refusal, workspace secret exclusions, task-engine integration, and exact privileged approval previews.

The system environment is Debian 13 without an active graphical session, system-installed PySide6, desktop Secret Service, or polkit agent. The offscreen widget smoke test does **not** validate a real display/window manager, keyring unlock, polkit, package installation, or the target Kali host. Therefore **the `.deb` was not installed and has not been tested on the user's Kali machine**. Those checks remain to be done on the target machine; this package build is not a claim that it is already installed or validated there.
