---
title: NOVA X
emoji: 🚀
colorFrom: cyan
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# NOVA X — multi-model orchestration foundation

NOVA X is a lightweight personal AI workspace with a responsive command center, a bounded task runner, a capability-aware provider registry, and a scoped tool system. It can route an authorized request to configured APIs, compare a small number of model outputs, report actual model calls and errors, and save measurable evaluation results. It reports generated text as a model response—not proof that an action or factual claim is true.

> **Current build: controlled orchestration foundation.** The original app features are retained. Provider APIs and available models still require the operator's own API credentials and account entitlements. No live provider credentials were confirmed in this development environment; real provider calls, pricing, quotas, and production availability are therefore **not live-verified**.

## What is implemented

- **Four selectable intelligence modes:** Fast, Balanced (default), Frontier Fusion, and Maximum Intelligence. Fast favors observed latency; Balanced uses one primary; Frontier Fusion runs independent analyses in parallel, requests a targeted disagreement review, then synthesizes; Maximum adds a critique and revision pass. Fusion never resolves disagreement by majority vote.
- **Manual and adaptive routing:** pick profiles in the dashboard or leave all unchecked for adaptive selection. Model IDs come from a fresh provider catalog; catalogs that return only identifiers require a successful inference test before the model becomes routable. NOVA does not route by hardcoded vendor model names.
- **Bounded fallback and parallelism:** at most three profiles per fusion by default; one alternate enabled/available profile can follow the primary on a single-model failure. Default/priority ordering chooses the alternate (there is no separate fallback toggle yet), while manual selection order is respected. Up to seven provider requests per intelligence operation, three concurrent provider calls, one task worker by default, capped output, request rate, context, timeout, bounded retries that honor provider `Retry-After` (or stop rather than retry early), and an estimated fusion budget. Actual requests and fallback failures are reported.
- **Provider registry:** OpenAI, OpenAI-compatible/custom, Anthropic, Gemini, xAI, DeepSeek, and Mistral profiles. OpenAI-compatible integrations use a standard Chat Completions adapter; Anthropic and Gemini use native request/response adapters. Current catalog results distinguish configured, connected, listed/available, inference-tested, disabled, and unavailable profiles.
- **Safe server-side credential references:** profiles contain an environment-variable name—not an API-key value. Keys are never requested in the browser, sent back by registry APIs, or stored in conversation/task history. A web-chat subscription does not imply API credentials or API quota.
- **Capability-aware tool routing:** tool turns use one selected model that is explicitly declared as tool-capable and has passed the synthetic tool-call evaluation for the current provider/model identity, with bounded fallback among eligible models. Fusion applies to tool-free analysis/synthesis; actual tool execution stays inside NOVA's backend registry, validation, scopes, and existing approval gates.
- **Usage transparency:** actual profile/model, role, calls, failures, latency, provider-reported tokens, configured-rate estimates, and fusion degradation are reported in chat and tasks. NOVA marks token usage incomplete when a provider omits usage; missing token data is never presented as a verified zero. Costs remain **unknown** unless the operator supplies current rates and the call returns usable token counts; estimates can differ from invoices and do not model every pricing modifier.
- **Evaluation baseline:** versioned `nova-eval-v1` runs three checks—exact instruction following, strict JSON, and a synthetic tool-call schema (the tool is never executed). A passed tool-call case is required before real tool routing is enabled for that provider/model identity. Results can be compared across profiles. Optional per-run 1–5 feedback is stored locally; it does not train model weights.
- **Central autonomy policy:** Levels A (Assisted), B (Routine, default), C (Advanced), and D (High); persistent per-tool allow/approve/deny rules; workspace-overwrite grants limited to relative path prefixes. Unknown/unclassified tools require approval; explicit deny wins; a pending approval is rechecked against current denies. Existing workspace replacements still make backups. C/D do not unlock unavailable features or high-impact permissions.
- **Configured-goal scheduler:** SQLite-backed user-defined goals with hourly/daily/weekly intervals, explicit enable/pause, manual run-now, task linkage, one scheduled run per goal per due window, no catch-up burst, and configurable daily cap. Scheduled tasks use Balanced mode and the same policy/approval gates. The lightweight scheduler runs only inside the web process.
- **Bootstrap checks and autonomy benchmark:** read-only setup diagnostics expose no secrets; a deterministic seven-case permission/scheduler benchmark runs in a temporary local workspace, makes zero provider/external requests, and does not test reasoning or live deployments.
- **Cognition layer (§70–§89, partial):** measurable reasoning mechanisms rather than fluent-sounding text. Claims carry provenance, and a statement with no evidence is demoted instead of being accepted as an observation. Stated confidence is scored against observed outcomes (ECE, Brier, overconfidence) and reports `insufficient_data` below ten samples rather than publishing a flattering number. A world model holds time-bounded observations, resolves predictions against reality, and flags whatever changed for re-inspection. Every plan gets a pre-flight review — capability gaps, derived acceptance criteria, cheapest sufficient verification, abandon conditions — and every finished run gets a post-hoc attribution to one of eight causes, from recorded evidence. Options are scored on cost, risk, reversibility and verifiability, with a bounded short-circuit when one cheap reversible option is already sufficient. Curiosity follows a cost-ordered ladder inside hard budget, authorization and privacy bounds. Learned procedures need three attempts and a 60% success ratio before they are `established` — a single success only ever creates a candidate — and can be transferred, corrected, superseded or removed with provenance. Agreement between models is never treated as evidence. All of it is offline, deterministic and verified by the `nova-gie-v1` suite (30 cases, held-out split, versioned baselines): `python -m nova.cognition`. **Not implemented:** skill acquisition, multimodal perception, scientific mode, creative/strategic reasoning, social modelling, and any self-improvement apply path. See [cognition status](docs/COGNITION.md).
- **Modular local platform stack (§90–§115):** event-driven intelligence bus (`nova/events.py`) with cycle/depth/dedupe/permission guards; permission-scoped plugin & extension SDK (`nova/plugins.py`, 4 reference extensions, sandboxed candidate staging); optional JSON-RPC 2.0 MCP client & unified integration gateway (`nova/mcp_client.py`); SQLite FTS5 + optional hybrid semantic knowledge search (`nova/knowledge.py`); compartmentalized context optimizer (`nova/context_manager.py`); multi-session terminal workspace with actor attribution, PTY and replay guard (`nova/terminal.py`); DAG workflow engine & checkpointed cross-application automation (`nova/workflows.py`); Linux namespace execution sandbox (`nova/sandbox.py`, fail-closed when unavailable); developer & streaming data workspaces (`nova/devtools.py`, `nova/data_workspace.py`); modular consent-gated visual & voice layers (`nova/modalities.py`); redacted OpenTelemetry-shaped observability (`nova/observability.py`); privacy inventory, health center, trusted backup/rollback update manager & offline coordinator (`nova/governance.py`, `nova/updates.py`); dual-core ~10 GB resource adaptation (`nova/resources.py`); capability discovery (`nova/capabilities.py`); and the 18-case §114 integration matrix (`tests/test_integration_matrix.py`). See [platform architecture](docs/PLATFORM_ARCHITECTURE.md), [extension SDK](docs/EXTENSION_SDK.md), and [release checklist](docs/RELEASE_CHECKLIST.md).
- **Existing working features:** plan → tool → outcome tasks; plan review/edit/approval; pause/resume/cancel/emergency stop; calculator; bounded workspace file tools; optional Tavily search; SQLite conversations/tasks/audit; optional single-user auth; Docker/Hugging Face Spaces configuration.

## Autonomy levels and configured goals

The default is **Level B · Routine autonomy**. In the web/backend task runner, registered routine tools (bounded arithmetic, scoped workspace operations, and configured public search) can run during an explicitly launched task. The native desktop additionally exposes a local process tool with a separate command policy: only a narrow exact-prefix set can run automatically inside a selected workspace; other commands pause for one-time user review, and high-impact/admin/network/security actions remain gated. Level A requires plan review and approval before tool actions. The database persists per-tool `allow`, `approve`, or `deny` rules; `allow` is rejected for unclassified tools, explicit `deny` wins, and approvals for pending actions are checked against current denies before execution. Existing-file replacement still waits for approval unless a deliberately configured workspace-relative prefix covers it; approved replacements retain a backup.

Levels C and D are selectable policy settings, not a claim of a full autonomous platform: they remain limited to installed/registered scopes. The native desktop's optional Bash input is only for a user-authored script and always requires fresh confirmation; model tool calls never use shell-string parsing. There is no production deployment, email/public-posting, payment, account-login, desktop automation, or self-modifying policy tool. Changing autonomy level never creates new capabilities or overrides backend path/validation checks.

Proactive execution is limited to **goals the user explicitly saves and enables** in **Goals & schedules**. New goals are paused by default. Scheduled runs create durable SQLite task records, use Balanced mode, and are subject to the per-task request/time/tool limits and the configured daily scheduled-run cap (default 5; set `NOVA_MAX_SCHEDULED_GOAL_RUNS_PER_DAY=0` to disable dispatch). The scheduler polls in-process; hosting sleep/restarts pause work, missed windows are skipped rather than replayed in a burst, and a missing model can cause a task to fail. Public research and provider calls may incur charges; configured caps are not a guarantee of zero or fully measured spend.

The **Run policy benchmark** button uses a temporary workspace to test the active permission design's invariant cases without changing the configured policy, workspace, or provider usage. It reports deterministic permission/scheduler regression checks only—not AI quality, factuality, provider access, or production uptime.

## Explicit limits and unimplemented work

- No credentials were used to live-test providers. A catalog check or inference test must be performed by the operator before relying on an account's access. Provider documentation searches are not a substitute for an authorized live call.
- xAI's first adapter uses its OpenAI-compatible Chat Completions surface, which xAI documentation labels as legacy/deprecated in favor of newer APIs. The newer Responses API migration is not implemented in this first adapter.
- Provider model catalogs do not always expose per-model tool-call support. NOVA does **not** infer `tools` capability from a model name; the operator must validate it with the small eval suite before enabling the capability.
- Pricing is not scraped or hardcoded. Operators should use the official pricing page, include the appropriate worst-case tier/rate, and refresh it themselves. Budget enforcement is estimate-based and is disabled when any participating profile has missing prices.
- The evaluation suite is a narrow deterministic format/capability check, not a truth, safety, reasoning, or benchmark guarantee. Cross-model consensus is not evidence. No web search or external evidence check is performed by chat fusion.
- No automatic model-weight learning, private-chat training, production code rewrite, or security-policy change occurs. An isolated candidate-code test/apply/review/rollback workbench is **not implemented**; code changes remain operator-reviewed deployments with existing tests and backups.
- The web/backend task runner does not expose shell or local operating-system execution. The separate native desktop includes structured local process execution plus an explicitly confirmed user-authored Bash route; model-provided shell strings are blocked. No repository-editing agent beyond scoped workspace file tools, browser automation, email/calendar/GitHub integration, desktop automation, voice, upload parsing, long-term personal memory, multi-user identity, durable external worker, or always-on native service is provided. The existing web configured-goal scheduler is lightweight and in-process; the native desktop does not run it.

See [platform architecture](docs/PLATFORM_ARCHITECTURE.md), [extension SDK](docs/EXTENSION_SDK.md), [release checklist](docs/RELEASE_CHECKLIST.md), [cognition status](docs/COGNITION.md), [feature status](docs/FEATURE_MATRIX.md), [security design](docs/SECURITY.md), [integration details](docs/INTEGRATIONS.md), [manual acceptance tests](docs/TESTING.md), and the [staged roadmap](docs/ROADMAP.md).

## Quick start

Requires Python 3.10+ (the Docker image uses Python 3.11). A dual-core / ~10 GB RAM machine is sufficient; no GPU or local model is required. Cloud inference is preferred for this low-resource configuration.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env       # Windows PowerShell: Copy-Item .env.example .env
# Edit .env on the server; set a current provider-visible model ID and secret.
uvicorn nova.main:app --host 0.0.0.0 --port 7860 --reload
```

Open `http://127.0.0.1:7860` locally. `AI_MODEL` and `AI_API_KEY` are blank in `.env.example` intentionally; no stale model identifier or free-tier access is assumed. Without configured model credentials, the health page, local tool registry, and profile configuration are available, while AI requests fail with a clear configuration response.

## Native Kali/Linux desktop application

The separate **native PySide6/Qt application** is the primary local desktop deliverable; it does not use a browser, Hugging Face Spaces, Gradio, or Streamlit as its UI. It provides local SQLite chat/tasks/history, plan and approval controls, a scoped structured command runner, workspace/permission settings, keyring-backed optional model profiles, diagnostics, CLI, desktop entry, and `.deb` packaging. It runs only while the user opens the app; no always-on service is installed. The complete source is available in the [source archive](releases/nova-x-desktop_0.2.0_source.zip); the build artifact and full safety/setup notes are in [docs/NATIVE_DESKTOP.md](docs/NATIVE_DESKTOP.md). The `.deb` was rebuilt and smoke-tested outside an installation; the Qt window builds offscreen, but no real desktop session, keyring unlock, polkit action, install, or target-Kali validation has been done here.

Build the Debian package from source with `scripts/build_deb.sh`; install it on a compatible Kali/Debian host with the normal package manager, then launch `nova-x` as the logged-in user. For a shell-free CLI check, run `nova-x diagnostics`; for a command, use `nova-x exec -- PROGRAM ARG...`. The CLI refuses unattended approval. Do not launch NOVA as root.

## Connect an authorized provider

1. Open **Models & intelligence** and select a provider preset. Add an account-visible model ID from that profile's refreshed catalog; current IDs are not bundled in code.
2. Put the provider secret in the server's environment/host secret manager under the displayed credential variable name. Restart NOVA if your host injects secrets only at startup. **Do not enter the secret in the browser.**
3. Run **Refresh catalog**, then **Test · may bill**. The test sends one small inference request and may incur provider charges. A model listed in a catalog may still be inaccessible to your account.
4. Enable the `tools` capability only after a provider tool-call test succeeds and the model supports the supplied schema. Chat availability alone does not establish tool capability.
5. Enter current input/output prices in USD per million tokens from the provider's official pricing page if you want estimates or fusion budget enforcement. Pricing varies by tier, cache, context length, tools, region, and provider changes; estimates omit some modifiers.

For the environment-based single default, configure `AI_BASE_URL`, `AI_MODEL`, and `AI_API_KEY` in `.env`. The default URL is OpenAI's official API, but the model ID must still be chosen from a current account-visible catalog. At official `api.openai.com`, NOVA uses `max_completion_tokens`; legacy compatible endpoints use `max_tokens` unless they are explicitly configured as OpenAI.

### Provider adapters and official references

| Provider/profile type | Adapter behavior | Official API / catalog / pricing references |
|---|---|---|
| OpenAI | Chat Completions, `max_completion_tokens`, `/models` | [Chat Completions](https://platform.openai.com/docs/api-reference/chat/completions), [model API](https://platform.openai.com/docs/api-reference/models), [pricing](https://platform.openai.com/docs/pricing/) |
| Anthropic | Native Messages API; tool schema translation; `/v1/models` | [Messages](https://docs.anthropic.com/en/api/messages), [models list](https://docs.anthropic.com/en/api/models-list), [pricing](https://platform.claude.com/docs/en/about-claude/pricing) |
| Google Gemini API | Native `generateContent`; paginated `/models` metadata; tool capability is not inferred | [generateContent](https://ai.google.dev/api/generate-content), [models list](https://ai.google.dev/api/models), [pricing](https://ai.google.dev/gemini-api/docs/pricing) |
| xAI | OpenAI-compatible Chat Completions adapter (legacy/deprecated surface in xAI docs) | [Chat Completions lifecycle note](https://docs.x.ai/developers/model-capabilities/legacy/chat-completions), [current model/pricing docs](https://docs.x.ai/developers/models.md) |
| DeepSeek | OpenAI-compatible Chat Completions and `/models` | [API docs](https://api-docs.deepseek.com/), [models & pricing](https://api-docs.deepseek.com/quick_start/pricing/) |
| Mistral | Chat Completions and `/models` | [API reference](https://docs.mistral.ai/api), [function calling](https://docs.mistral.ai/studio/conversations/function-calling), [pricing](https://docs.mistral.ai/inference/pricing) |
| OpenAI-compatible custom | Chat Completions and `/models`; custom host is opt-in and requires access-token auth | Custom host must be operator-authorized; only HTTPS is accepted except explicitly enabled loopback during local development. |

A custom service must implement the API shape/capabilities NOVA sends. For any provider, official documentation and an account-authenticated live test determine current support. This docs search was performed during implementation; models, APIs, access, terms, quotas, and prices can change after this build.

## Intelligence modes and limits

- **Fast:** one eligible model, sorted by observed latency and success data; fallback is bounded. Lowest cross-checking.
- **Balanced (default):** one primary model. If it fails, the first other enabled/available profile in the configured default/priority order may be used; manual selection order takes precedence.
- **Frontier Fusion:** normally three parallel independent analyses + one targeted conflict review + one synthesis (five calls). If fewer models, time, or request budget are available, NOVA reduces/degrades the mode and reports it.
- **Maximum Intelligence:** Frontier Fusion plus a separate critique and revision; up to seven calls with three eligible models. Each call is output-token-capped. Maximum does not mean universally more accurate.

`NOVA_MAX_FUSION_BUDGET_USD` is enforced only when every participating model has prices entered and the value is greater than zero; set it to `0` to disable the estimate ceiling. The preflight estimate uses the configured rates and bounded prompt/output sizes, but the actual provider invoice can differ. If rates are missing, the run can proceed only with request/time/token bounds and the UI says cost is unknown. Do not interpret an unknown estimate as free.

Task plans and evidence review inherit the chosen mode. Turns that call tools are routed to one tool-capable primary/fallback model; synthesis does not execute or approve tools. All tool outputs remain untrusted and all side effects remain behind the existing permission/approval boundary.

## Evaluation and improvement policy

The **Evaluation baseline** runs a small `nova-eval-v1` suite against one profile. Each check may cost an API request. Results record suite version, score, calls, tokens, and known price estimate so operators can compare providers/runs. Optional response ratings support later routing analysis; they are stored in SQLite and can be deleted with local data.

This is a measurable workflow-improvement foundation—not self-training. It never updates model weights or automatically trains on private chats. The server does not yet apply candidate code patches, run untrusted candidate code, or auto-promote production changes. Continue code changes through isolated development, regression tests, code review, explicit deployment approval, and operator rollback; future isolated experiment/apply workflows are tracked in the roadmap. Security controls and tool permissions are never changed by a model.

## Hugging Face Spaces deployment

1. Create a Docker Space and push this repository.
2. Set `NOVA_ACCESS_TOKEN` before startup; Hugging Face deployments fail closed when it is missing.
3. Add only required provider/Tavily secrets in Space secrets. The model profile stores a variable name, not the secret.
4. The app listens on `0.0.0.0:$PORT`, defaulting to port `7860`, and uses one task worker by default.
5. Enable persistent storage if SQLite history, profiles, evaluation results, feedback, and workspace files must survive rebuilds/restarts. Confirm the mounted directory is writable.

Free hosted compute may sleep, cold-start, throttle, or have ephemeral disk. A sleeping Space is not an always-on scheduler. There is no promise of unlimited free inference; verify provider pricing, quotas, model access, and hosting limits before relying on a workflow.

## Configuration reference

| Variable | Purpose | Default / note |
|---|---|---|
| `AI_BASE_URL` | Environment-based default endpoint | `https://api.openai.com/v1` |
| `AI_MODEL` | Environment-based default model identifier | **Blank**; choose current account-visible ID |
| `AI_API_KEY` | Environment-based default credential | Blank; server environment only |
| `AI_MODEL_CAPABILITIES` | Environment default capabilities | `chat`; add `tools` only after validating tool calls for the selected model |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `XAI_API_KEY`, `DEEPSEEK_API_KEY`, `MISTRAL_API_KEY` | Optional managed-profile secret variables | Blank unless configured on server |
| `NOVA_ACCESS_TOKEN` | Single-user access gate | Blank means open local mode; set before public exposure |
| `NOVA_ALLOW_CUSTOM_PROVIDER_ENDPOINTS` | Allow non-provider custom API hosts | `false`; requires `NOVA_ACCESS_TOKEN` as well |
| `NOVA_ALLOW_LOCAL_HTTP_PROVIDER` | Permit HTTP loopback endpoint | `false`; local development only |
| `NOVA_DEFAULT_INTELLIGENCE_MODE` | Default UI/task mode | `balanced` |
| `NOVA_AUTONOMY_LEVEL` | Initial global autonomy level (database policy can be changed in UI) | `routine` (A/B/C/D values are `assisted`/`routine`/`advanced`/`high`) |
| `NOVA_GOAL_SCHEDULER_ENABLED` | In-process scheduler master switch | `true`; only explicitly enabled user goals are eligible; host sleep still stops it |
| `NOVA_GOAL_SCHEDULER_POLL_SECONDS` | Scheduler polling interval | 30 seconds (clamped 10–300) |
| `NOVA_MAX_SCHEDULED_GOAL_RUNS_PER_DAY` | Cap on automatically scheduled goal tasks | 5 per UTC day; set `0` to disable scheduled dispatch |
| `NOVA_MAX_FUSION_MODELS` | Models per multi-model run | 3 (clamped 2–6) |
| `NOVA_MAX_INTELLIGENCE_REQUESTS` | Provider calls per chat orchestration | 7 (clamped 1–20) |
| `NOVA_MAX_MODEL_CONCURRENCY` | Concurrent provider calls | 3 (clamped 1–6) |
| `NOVA_MAX_MODEL_FALLBACKS` | Sequential fallback attempts after primary | 1 (clamped 0–3) |
| `NOVA_MAX_INTELLIGENCE_SECONDS` | Overall fusion/evaluation time | 180 seconds |
| `NOVA_MAX_FUSION_OUTPUT_TOKENS` | Max output tokens per model call | 1,200 (clamped 128–8,000) |
| `NOVA_MAX_FUSION_BUDGET_USD` | Configured-rate fusion estimate ceiling | $1.00; only enforced if all participant rates are entered; `0` disables the estimate ceiling |
| `NOVA_MAX_AI_REQUESTS_PER_MINUTE` | Process-wide AI request cap | 20/minute; in-memory, includes catalog/inference tests |
| `NOVA_MAX_AI_REQUESTS_PER_TASK` | Provider request budget per task | 12, including plan, agent, and verifier requests |
| `NOVA_MAX_TASK_STEPS` | Tool calls per task | 8 |
| `NOVA_MAX_TASK_SECONDS` | Runtime per task/resume window | 240 seconds |
| `NOVA_MAX_PARALLEL_TASKS` | Task concurrency | 1 in low-resource mode |
| `NOVA_MAX_CONTEXT_CHARS` | Approximate message-character cap | 100,000 |
| `NOVA_MAX_REQUEST_CHARS` | User prompt size | 12,000 |
| `NOVA_MAX_TOOL_OUTPUT_CHARS` | Tool result size | 12,000 |
| `NOVA_MAX_FILE_BYTES` | Text file read/write limit | 512 KiB |
| `NOVA_MAX_CHAT_HISTORY_MESSAGES` | Prior chat turns sent as provider context | 20 (clamped 1–200); the full transcript stays in SQLite |
| `NOVA_VERIFY_TASKS` | Evidence-review call when tool evidence exists | `true`; consumes provider budget |
| `TAVILY_API_KEY` | Optional public web-search integration | Blank/disabled |
| `NOVA_DATA_DIR`, `NOVA_WORKSPACE_DIR` | Local database/workspace roots | `./data`, `./workspace` |

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
ruff check .
node --check static/app.js
python -m compileall -q nova tests app.py
```

The same checks run in CI (`.github/workflows/ci.yml`) across Python 3.11–3.13, plus a job that installs the system graphics libraries so the native Qt window test actually executes instead of skipping, and a job that builds the `.deb` and asserts its control version matches `pyproject.toml`.

Automated tests use deterministic fake adapters/providers and do not call paid APIs. They exercise API/task flows, safe tools, provider normalization, catalog completeness, endpoint/secret-reference validation, request budgeting, fallback, fusion, maximum mode, price-ceiling behavior, evaluation scoring, and UI syntax. `tests/test_regressions.py` pins previously fixed defects: server-side session revocation on logout, a bounded/pruned session store, tolerant task serialization, startup-free app construction, clean storage-failure responses, import purity, and per-role fusion reporting. Native desktop tests additionally run real local commands in a temporary workspace, verify stdout/exit status/timeouts/cancellation, redaction, secret-path denial, fake Secret Service behavior, structured task-tool integration, and approval previews. They do **not** verify live account access, provider billing, service quotas, Qt interaction, polkit/keyring unlock, or deployment behavior on Kali.

`tests/test_desktop_ui.py` skips when PySide6 is absent **or** when it is installed but cannot load (for example a container missing `libGL`/`libEGL`); the skip is module-scoped so the rest of the suite still runs.

## Security, privacy, and data

- Use `NOVA_ACCESS_TOKEN`, HTTPS, private hosting/access controls, and a trusted ingress for public deployments. The process-local limiter is not a WAF/distributed quota.
- API keys are server-side environment values. Managed profiles can reference only provider-specific secret-variable names by default. They never accept a browser-supplied key.
- Official provider hosts are allowlisted by provider type. A custom compatible host requires `NOVA_ALLOW_CUSTOM_PROVIDER_ENDPOINTS=true` **and** `NOVA_ACCESS_TOKEN`; custom endpoints receive the configured credential, so only use endpoints under your authority. Requests do not follow redirects. HTTP is rejected except explicitly allowed loopback.
- Provider prompts include relevant user conversation/task context and tool outputs. Review each provider's data retention and privacy terms. SQLite stores conversation content, task checkpoints, model run metadata, model profiles, evaluation results, and optional ratings. No automatic training is enabled.
- Tools run server-side within the registered permission boundary. There is no shell/code runner, delete tool, arbitrary plugin execution, email/payment action, or operating-system control.
- Back up local data/workspace before upgrades. Treat database and workspace files as sensitive.

See [SECURITY.md](docs/SECURITY.md) and [INTEGRATIONS.md](docs/INTEGRATIONS.md).
