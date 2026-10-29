# Security and permissions

## Provider/API boundary

- **No browser key input:** model-profile create/update payloads accept only an environment-variable reference. API responses expose the reference name and whether it is present, never its value. Provider secrets are not stored in task/conversation history or logged by NOVA's adapter.
- **Provider-specific key references:** official profiles restrict references to known provider-specific variable names. This reduces the risk of sending unrelated server environment secrets as API credentials.
- **Host allowlist:** official profile types use the relevant official provider API host. Scheme is HTTPS only by default; URL credentials, query, fragment, redirects, and non-loopback HTTP are rejected. A custom compatible endpoint requires both `NOVA_ALLOW_CUSTOM_PROVIDER_ENDPOINTS=true` and configured `NOVA_ACCESS_TOKEN`. Enabling this explicitly trusts the custom host with the selected provider key and prompt data.
- **No subscription assumption:** consumer/web-chat subscription is not considered API credential, quota, or entitlement. A catalog entry or test result is scoped to that provider response/time and does not guarantee future account access.
- **Untrusted provider content:** model outputs and retrieved/file content are not authorization. They do not change tool permissions, approve actions, or change security controls. The fusion synthesizer is instructed not to trust analyst outputs as instructions/proof and not to use majority vote.
- **Bounded requests:** provider requests/minute, per-run requests, model concurrency, fallback count, output tokens, context characters, time, task concurrency/steps, retries, tool outputs, and file size are capped. Frontier/Maximum may still be billable; estimated-cost limits require all current participant rates.
- **Provider-specific capabilities:** only chat is enabled by default for managed profiles. Tool capability is explicit, and real tool routing is blocked until the synthetic tool-call evaluation passes for the current provider/model identity. Catalog listing of generation support is not treated as proof of tool-call support; evaluation sends a synthetic call request and never executes it.

## Existing tool controls

- **Web/backend tool scope:** workspace paths are relative to `NOVA_WORKSPACE_DIR`; absolute/drive paths, traversal, and symlink components are rejected; regular UTF-8 files and byte limits are enforced. The web API has no shell or deletion tool. The separate native app's local process boundary is described below.
- **Overwrite gate:** existing files pause in `waiting_approval`; the user's decision is stored server-side. Approved replacements back up the prior file before atomic replacement. Denial does not bypass the gate.
- **Validated tools:** each tool has schema validation, permission description, availability, and bounded output. Only available registered tools are sent to the model.
- **No server privilege escalation:** the web/backend does not provide remote shell, arbitrary code execution, remote desktop, system-level changes, mail/payment actions, or an unrestricted plugin runtime. The native desktop allows local commands only under its separate approval boundary and has no default privilege escalation.
- **Task audit:** states, tool names/outcomes, approvals, requests, token totals, and model traces are persisted. If there is no successful tool evidence, task verification is explicitly unverified.

## Native Linux desktop boundary

The native Qt application is a separate local process; it does not start the web server or listen on a TCP port. It runs as the logged-in user. The native process runner uses `asyncio.create_subprocess_exec` with structured arguments, sanitized child environment, closed stdin, bounded output/time, process-group cancellation, and a durable local result/exit status. Model-supplied shell command strings are rejected; agent-mediated shells, interpreters/build runners, direct file readers/scanners/mutators, Git commands, and command wrappers that could invoke them indirectly are disabled in this increment in favor of the bounded workspace tools. User-authored Bash in the desktop UI/CLI is a separate mode with fresh confirmation and is not exposed as a model tool.

The native command policy auto-allows only a narrow set of token-exact prefixes inside deliberately selected workspace roots. Other commands require one-time review of executable, arguments, and working directory. Destructive/admin, package, network-transfer, privilege-wrapper, and security-tool operations remain review-gated and cannot be added as persistent automatic prefixes. `system.run_privileged` is separate, requires NOVA approval plus normal `pkexec`/polkit authentication, and never collects a sudo password. Missing `pkexec` fails closed.

Native workspace file tools follow the currently active selected directory and reject common credential/private-key paths such as `.env`, `.ssh`, `.aws`, `.kube`, keyrings, private-key filenames, and credential directories. This is a defense-in-depth list, not a general-purpose data-classification engine. Command output redaction is best-effort; avoid passing secrets as arguments or exposing arbitrary private files to a model. Model-facing commands hard-block the detected sensitive paths/flags.

Provider keys in the native app are stored in the user's Linux Secret Service/keyring only. The app refuses plaintext keyring fallback and ignores unmanaged provider-key environment variables while active; keys are restored/cleaned up on exit and excluded from child process environments. Keyring unlock/prompt behavior depends on the user's desktop session. If Secret Service is unavailable, provider-key saving is disabled; there is no plaintext fallback.

SQLite, task/checkpoint data, conversation text, and command logs are local but are not encrypted by NOVA. The package creates a private app data directory and restrictive mode for its database/log files. Clearing command history removes NOVA-created logs indexed by that history; it does not undo commands or remove arbitrary files created by child processes. No background service runs when the app is closed.

## Autonomy policy and scheduled goals

- **Default Level B (Routine):** only tools marked routine may run automatically. Level A forces plan review and tool-action approvals. Levels C/D are selectable but keep the installed registry/permission ceiling; they do not grant email, deployment, payment, or security-policy access. The native desktop's process tool has additional command-specific gates independent of the global autonomy level.
- **Per-tool overrides:** `deny` blocks a tool and is rechecked when a pending action is approved; `approve` pauses; `allow` is accepted only for a routine-class tool. Unregistered/unclassified tools default to approval or denial at the registry boundary. Model output cannot modify the policy.
- **Workspace overwrite scopes:** grants are workspace-relative path prefixes, reject absolute/traversal paths, and do not bypass the file tool's path/symlink validation, race-safe writes, backup creation, output/file limits, or scoped root. Empty by default. A one-time user approval is bound to checkpointed tool arguments.
- **Configured goals only:** the scheduler dispatches only explicitly saved and enabled user goals. New goals are paused by default. Scheduled work uses Balanced mode, existing per-task request/time/tool caps, a daily dispatch cap, and the same autonomy policy. A schedule does not authorize a file overwrite or other gated operation.
- **Hosting reality:** schedule times/tasks are stored in SQLite, but the poller is in the web process; sleep/stop pauses it, missed windows are skipped without burst catch-up, and execution is not guaranteed. Use persistent storage and private/authenticated hosting. `NOVA_MAX_SCHEDULED_GOAL_RUNS_PER_DAY=0` disables dispatch. Provider/public-search usage may be billable; cost may be unknown.
- **Policy benchmark:** the local deterministic suite uses an isolated temporary workspace/database; it makes zero model/provider/external requests. It validates permission and schedule invariants, not model correctness or production uptime.

## Authentication and deployment checklist

1. Set a long random `NOVA_ACCESS_TOKEN` before public exposure. Hugging Face startup fails closed without it. Prefer private Space/access control and a trusted HTTPS ingress.
2. Store provider/Tavily credentials only in server environment/secret manager. Do not place keys in browser code, task prompts, logs, or commits.
3. Keep custom endpoints disabled unless required. If enabled, also require token authentication and use only a host you control/trust; it receives the selected credential and relevant prompts.
4. Review provider data retention/privacy terms: chat, task context, tool output, and fusion comparisons may be sent to each participating provider.
5. Keep task parallelism low on small hardware. Raise token/request/concurrency/budget caps only after testing costs and provider limits.
6. Protect the SQLite database and workspace volume; task checkpoints and evaluation records are local data. Back up before upgrades and test restores.
7. The limiter and session store are process-local; they are not a WAF, distributed quota, or multi-instance lock. Use a trusted edge limiter and shared secure session storage before horizontal scaling.
8. Review exported run/task information before sharing. The app does not automatically classify/redact arbitrary user content.

## Self-improvement/data policy

Evaluation runs and optional 1–5 feedback are stored locally for operator comparison. They do not train model weights or automatically change routing/security controls. There is no candidate-code execution or automatic production patch/apply system in this build. Code changes remain isolated operator development, regression testing, review, explicit deployment approval, and rollback through the deployment process. Future code-candidate workflows require an OS/container sandbox and approval design before activation.

## Remaining gaps

This is an early single-user foundation, not a security-certified product. It lacks multi-user authorization, SSO/OAuth, persistent/distributed sessions, distributed rate limits, encrypted-at-rest SQLite, full data-retention UI for all local records, external security review, OS-level candidate code isolation, and provider-live security tests. Public deployments should remain private/restricted until those controls and owner configuration are reviewed.

Access-token rotation requires restarting/reconfiguring the service, which invalidates in-memory sessions. Local HTTP is not permitted for external provider hosts. Reverse-proxy headers are not trusted for client identity; `X-Forwarded-Proto` is used only for Secure cookie handling as described in code.
