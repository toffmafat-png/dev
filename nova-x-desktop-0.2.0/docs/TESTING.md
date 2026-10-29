# Testing and manual acceptance

## Automated suite

From the project root:

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
pytest -q
node --check static/app.js
python -m compileall -q nova tests app.py
```

Automated provider tests use deterministic fake providers/HTTP responses; they require no paid key and do not call external APIs. Coverage includes:

- safe arithmetic; traversal/symlink denial; overwrite approval and backup;
- task planning, tool use, result/evidence status, plan review/edit/approval, and controls;
- auth gate, missing credentials, conversation persistence, model-profile CRUD and key-field rejection;
- HTTPS/official host and environment-reference validation;
- OpenAI token parameter, native Anthropic/Gemini message/tool translation, catalog completeness;
- Fusion and Maximum call counts, request-budget degradation, configured-rate budget ceiling, and one-model fallback;
- versioned evaluation scoring and synthetic tool-call checks that do not execute a tool;
- autonomy A–D decisions, explicit-deny precedence, narrow workspace overwrite scopes, stale-approval rechecks, and Level A plan/tool approval flow;
- goal CRUD/provenance, disabled-goal suppression, atomic scheduled dispatch/daily cap/no catch-up burst, setup diagnostics, and the seven-case isolated policy benchmark (zero provider/external calls).

## Native desktop/CLI tests (no provider required)

Automated `tests/test_desktop.py` exercises the process runner on real installed commands in a disposable workspace, not on the user's Kali host. It checks structured-prefix policy, explicit approval, stdout/exit status, timeout/stop, output/history/log redaction, credential-path denial, fake Secret Service behavior/refusal, workspace secret exclusions, task-engine command integration, and exact privileged approval previews. No provider request or `pkexec` action is executed by these tests. `tests/test_desktop_ui.py` is skipped when PySide6 is absent; when Qt is available it creates the native window offscreen and checks all eight staged pages.

Package smoke checks:

```bash
scripts/build_deb.sh
dpkg-deb --info releases/nova-x-desktop_0.2.0_all.deb
dpkg-deb --contents releases/nova-x-desktop_0.2.0_all.deb
```

The extracted package's non-GUI CLI can be exercised with the source Python environment and core dependencies. This does not equal installation through apt. On the target Kali desktop, verify the following with an ordinary non-root user:

1. Install through the system package manager, launch from both the app menu and `nova-x`, and confirm a native Qt window (no browser/server) appears.
2. Confirm `$XDG_DATA_HOME/nova-x` and the default workspace are created with appropriate user-only permissions, and diagnostics identify the actual Qt/display/session state.
3. Confirm keyring status is truthful. Save a test key to Secret Service, close/reopen the app, verify only the configured state appears (never the value), remove it, and verify unlock/cancel behavior. If no Secret Service backend is available, confirm the app refuses to save it anywhere else.
4. Run `nova-x exec -- pwd`; run a non-preauthorized harmless command and decline, then approve it once in an interactive terminal. Confirm non-interactive CLI does not auto-approve.
5. In the command page, run a harmless approved command, inspect actual stdout/stderr/exit code and history, test timeout and emergency stop, and confirm child process termination. Test the shell mode only with an expendable `printf` script.
6. Add a disposable workspace, inspect how the active scope changes, verify `.env`/private key paths are excluded from agent file/process tools, and confirm manual local commands still require review where policy says so.
7. With no model profile, submit a chat/task and verify an honest configuration failure rather than a fabricated answer. Only then configure an account-authorized model and explicitly confirm any billable connection/tool tests.
8. Request one harmless `pwd` task after a model's synthetic tool-call validation succeeds; inspect exact approval/plan gates, real exit code/output, evidence state, pause/resume/cancel, and restart recovery.
9. Verify privileged actions require fresh NOVA approval and a system polkit prompt. If no graphical polkit agent exists, confirm the action fails safely; never enter/store a sudo password in NOVA.
10. Uninstall from a disposable test user only after exporting/retaining any desired data; verify uninstall does not silently delete user workspaces/database.

The system build environment has no active desktop session, installed Qt stack, Secret Service, or polkit agent. A temporary offscreen Qt smoke test using extracted Debian packages successfully created the window and all eight pages; this does not validate a visible window manager, package installation, keyring, polkit, or the target Kali host. The remaining interactive checks must be run on the target Kali installation.

## Manual local smoke test (no provider required)

1. Start with no `AI_MODEL`/API secret and open the UI. Confirm the provider profile is **missing credential/unavailable**, not reported connected or tested. Attempt chat and confirm it reports configuration failure rather than a pretend answer.
2. Open **Models & intelligence**. Inspect provider presets and mode limits. Confirm there is no browser API-key input; the credential field contains only an environment-variable name.
3. Try a non-HTTPS provider URL and an unrecognized credential variable. Confirm validation rejects it. Confirm custom host is rejected until both `NOVA_ALLOW_CUSTOM_PROVIDER_ENDPOINTS=true` and `NOVA_ACCESS_TOKEN` are set.
4. Create a disposable provider profile with a currently authorized model ID and an environment-variable name. Add the secret through your host environment/secret manager, restart if needed, refresh catalog, and test inference. The test sends one small billable request. Confirm configured/connected/available/tested states change accurately.
5. Run the three-request evaluation suite only if comfortable with potential charges. Its synthetic tool-call case runs even while `tools` is disabled; enable `tools` only after that case passes for this provider/model identity. Confirm result version, score, request count, token-usage completeness, and unknown/estimated cost.
6. With current rates configured, test a low fusion budget and confirm over-budget fusion is blocked before provider calls. With rates blank, confirm the UI says the USD ceiling cannot be enforced. Never interpret missing cost as free.
7. Send the same short prompt in Balanced, Frontier Fusion, and Maximum modes. Confirm actual model roles/calls, failure/fallback/degradation, comparison summaries, no-majority note, request totals, and cost uncertainty are visible. Fusion itself does not browse or fact-check sources.
8. Select a profile declared tool-capable; run “Calculate 18% of 2450.” Confirm a single tool-capable model turn, actual calculator output, and evidence review when budget remains. Fusion does not execute tools in parallel.
9. Try plan review/edit/approval, overwrite approval, pause/resume/cancel, and emergency stop. Confirm actions occur only after their existing approvals and task records report actual results.
10. Set `NOVA_ACCESS_TOKEN`, restart, and confirm APIs are blocked before login. Verify sign-in/out and session reset on restart.
11. Verify persisted model profiles, evaluations, feedback, conversations, tasks, and workspace files after restart only when durable storage is configured.
12. Test narrow/mobile layout and keyboard interactions; CSS syntax/device matrix has not been browser-automated here.
13. Open **Settings → Autonomy & permissions**. Confirm Level B is the default; set Level A and launch a disposable task. It should pause for plan review and then ask before every tool. Set a `deny` override and confirm no one-time approval bypasses it.
14. Create a workspace test file; under Level B, ask NOVA to replace it. Confirm the task waits for approval and creates a backup only after approval. Then configure a narrow path prefix, verify an in-scope overwrite backs up, and confirm a sibling prefix does not match.
15. Open **Goals & schedules**. Create a goal with scheduling disabled and confirm no task is automatically created. Use **Run now** and inspect goal provenance, task events, approvals, and evidence. Enable a schedule only when the bounded objective and cost exposure are understood; hosting sleep pauses it.
16. Run **Policy benchmark** and confirm seven deterministic cases pass, `provider_requests` and `external_requests` are zero, and the temporary workspace is reported. Open **Bootstrap checklist** and confirm it reports configuration status without secret values.

## Provider-live acceptance

A fake test or successful catalog read does not prove a paid inference works for the selected model/tools. Before relying on a workflow, use authorized credentials to test: one small inference; one declared tool-call schema; a NOVA calculator task; one harmless workspace write to a disposable path; a bounded timeout/error; provider token/billing usage; current terms/data-retention; quotas; and fallback behavior. Verify the provider invoice/console independently. xAI's first adapter currently uses the legacy Chat Completions path; do not assume newer Responses API features are present.

No live-provider, live-price, live-Tavily, public-Hugging-Face, or real Space persistence test was performed in this workspace.
