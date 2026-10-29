# Model providers and integrations

## Provider registry contract

The UI registry stores only provider type, endpoint, current model identifier, credential **environment-variable name**, declared capabilities, optional context/rate values, routing priority, enabled/default flags, and status/usage metrics. The browser never receives API-key values. Model names are not bundled as a provider registry; refresh the authorized provider catalog and/or run an inference check for the currently configured identifier.

Provider state deliberately separates:

- **Configured:** endpoint/model format is valid and the referenced server environment variable has a value.
- **Connected:** NOVA received a successful catalog or inference response.
- **Available:** a catalog explicitly reported chat-generation support for the matching ID, or an inference test proved it callable for the current profile identity, and the profile is enabled/configured. Identifier-only catalogs produce **Listed · test chat**, not routable availability, until a successful inference test.
- **Inference-tested:** the one-request `Test` succeeded. This is an actual provider inference call and may bill.
- **Listed · test chat / not listed / disabled / missing credential / invalid endpoint / catalog incomplete:** separate states; none imply usable access until the applicable availability condition is met.

A model appearing in a catalog is not proof of account entitlement, tool-call support, or stable availability. Validation is tied to the provider/endpoint/model/credential-reference/capability fingerprint; changing those identity settings invalidates old catalog/test state rather than reusing it for a different model. Provider errors update per-profile failure/latency metrics; NOVA reports which profiles were attempted and any capability degradation.

## Supported adapters

| Type | Request surface | Model catalog | Important limitations |
|---|---|---|---|
| OpenAI | Chat Completions, `max_completion_tokens` | `/models` | Account-visible IDs and model capabilities vary. |
| OpenAI-compatible | `/chat/completions`, `max_tokens` | `/models` when implemented | Use only compatible services. For `api.openai.com`, NOVA selects the OpenAI token parameter. Custom hosts are disabled unless explicitly enabled with access-token auth. |
| Anthropic | Native `/messages`; server translates tools/messages | `/models` (bounded first page, pagination completeness reported) | Not OpenAI Chat Completions. Model ID/tool availability remains account-specific. |
| Google Gemini API | Native `models/{id}:generateContent`; server translates tools/messages | `/models?pageSize=1000`, supported actions/context metadata | Catalog generation support does not imply function calling; `tools` remains operator-declared. |
| xAI | OpenAI-compatible Chat Completions | `/models` | The first adapter uses the legacy/deprecated Chat Completions surface, not the newer Responses API. Migrate before relying on newer Responses-only functionality. |
| DeepSeek | OpenAI-compatible Chat Completions | `/models` | Feature/tool support and model identifiers are provider-owned and change. |
| Mistral | Chat Completions | `/models` | Function calling is model-specific; verify against the provider guide and eval. |

The Mistral and DeepSeek adapters use the compatible Chat Completions surface; only Anthropic and Gemini have native adapters in this increment. A custom endpoint can be configured as an OpenAI-compatible profile only after the operator sets `NOVA_ALLOW_CUSTOM_PROVIDER_ENDPOINTS=true` and `NOVA_ACCESS_TOKEN`. Only HTTPS is allowed, redirects are disabled, and the credential environment variable is constrained to provider-appropriate names unless the authenticated custom endpoint opt-in is active. An operator who enables custom mode must trust that endpoint because NOVA will send that configured secret to it.

Local HTTP endpoints are rejected unless the operator explicitly sets `NOVA_ALLOW_LOCAL_HTTP_PROVIDER=true`; only loopback hosts are accepted. Do not enable this option on a public deployment.

## Credential setup

- `AI_API_KEY` is the compatibility credential used by the environment-based default, `AI_BASE_URL`, and `AI_MODEL`.
- Managed profiles store a variable name such as `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `XAI_API_KEY`, `DEEPSEEK_API_KEY`, `MISTRAL_API_KEY`, `OPENAI_API_KEY`, or `AI_API_KEY`. Store the corresponding **value** in `.env`/the hosting secret manager and restart if required.
- The API rejects unknown fields such as `api_key`; keys cannot be submitted through model-profile create/update requests.
- A subscription to a web chat product is not the same as an API key, billable API account, quota, or authorization to use a model. NOVA does not claim provider access until configured/tested.

### Official provider API/catalog references

- OpenAI: [Chat Completions](https://platform.openai.com/docs/api-reference/chat/completions), [models](https://platform.openai.com/docs/api-reference/models), [pricing](https://platform.openai.com/docs/pricing/).
- Anthropic: [Messages API](https://docs.anthropic.com/en/api/messages), [model list](https://docs.anthropic.com/en/api/models-list), [pricing](https://platform.claude.com/docs/en/about-claude/pricing).
- Google: [Gemini `generateContent`](https://ai.google.dev/api/generate-content), [paginated model list and metadata](https://ai.google.dev/api/models), [pricing](https://ai.google.dev/gemini-api/docs/pricing).
- xAI: [Chat Completions legacy notice](https://docs.x.ai/developers/model-capabilities/legacy/chat-completions), [models and pricing](https://docs.x.ai/developers/models.md). This first adapter intentionally discloses its legacy Chat API limitation.
- DeepSeek: [API docs](https://api-docs.deepseek.com/), [models and pricing](https://api-docs.deepseek.com/quick_start/pricing/), [tool calls](https://api-docs.deepseek.com/guides/tool_calls/).
- Mistral: [API reference](https://docs.mistral.ai/api), [function calling](https://docs.mistral.ai/studio/conversations/function-calling), [pricing](https://docs.mistral.ai/inference/pricing).

These documentation sources were searched during implementation (2026-10-29); they do not establish credentials, live account access, service quotas, prices for an individual account, or behavior at deployment time. Provider model IDs and pricing change. Use the current official catalog and pricing page on each use; NOVA does not scrape price tables or hardcode model-specific rates.

## Modes, selection, and bounded execution

- **Fast:** one eligible primary; prioritize observed latency, then success history/default/priority. One alternate may be attempted after failure if bounded budget remains.
- **Balanced:** one primary (default mode); at most one other enabled/available profile can be attempted after a primary failure. With adaptive routing, default/priority ordering chooses the alternate; with manual routing, selected order is respected. There is not yet a separate fallback-enable flag.
- **Frontier Fusion:** up to three parallel independent analyst calls, a separate targeted disagreement-review call, and one integrated synthesis. With three working profiles this is five provider calls. The conflict reviewer is instructed to identify claims/checks, not choose a winner by vote. It does not browse or verify sources.
- **Maximum Intelligence:** Frontier Fusion plus a separate critique and revision, at most seven provider calls with three eligible profiles.
- **Tool turns:** use one selected model with `tools` capability (bounded fallback); tool execution remains server-side in the existing permission system. A fusion mode is not falsely reported as parallel tool execution.

The orchestrator respects `NOVA_MAX_FUSION_MODELS`, `NOVA_MAX_INTELLIGENCE_REQUESTS`, remaining task request budget, `NOVA_MAX_MODEL_CONCURRENCY`, `NOVA_MAX_INTELLIGENCE_SECONDS`, output token cap, context limit, process-wide requests-per-minute, and the configured estimate ceiling. Task retries honor a parsed `Retry-After` delay only when it fits the bounded wait and remaining task time; if the requested delay is longer, NOVA fails rather than retrying early. When resources/candidates are insufficient, it degrades to a single model or reports failure rather than calling every provider.

## Pricing and cost estimates

The dashboard accepts operator-entered input/output USD per million tokens. No rate table is hardcoded or automatically refreshed. The fusion preflight ceiling is enforced only when each participant has both rates and `NOVA_MAX_FUSION_BUDGET_USD` is greater than zero. With complete rates and a zero budget value, the estimate is still reported but the ceiling is disabled; with missing rates, the cost estimate and ceiling cannot be enforced. Actual usage may differ because of cache hits, context-based tiers, reasoning/thinking tokens, tool charges, provider rounding, exchange rates, or pricing updates. When a provider omits token usage, NOVA flags token/cost reporting incomplete instead of calling it zero. Enter the **current conservative/highest applicable rate** for the expected workload and verify actual invoices/provider dashboards. Missing rates are not evidence of zero cost.

## Evaluation and feedback

The per-profile `nova-eval-v1` suite makes three bounded provider calls (the configured per-run request cap must allow all three):

1. Exact instruction-following marker.
2. Valid strict JSON with expected field types/values.
3. Request a synthetic `nova_eval_add` tool-call schema—even if `tools` is not yet enabled—and inspect the returned tool call. NOVA never executes the synthetic function. A passing case validates tool support for the current provider/model identity and is required before enabling real tool routing.

The suite records version, result per case, score, calls, token count, known rate estimate, and timestamp. It is useful for smoke/regression comparisons, not factuality/safety certification. User ratings are linked to local run metadata for later comparison; they neither train model weights nor automatically change default routing today.

No untrusted code is executed by the evaluation suite. Candidate code isolation, apply/review, high-impact code approval, and rollback are not implemented in this increment. Production code and permission policy are changed only by an operator through a reviewed deployment.

## Web research integration

`research.search_web` uses Tavily's public search API when `TAVILY_API_KEY` is configured. Without a key, the tool is marked unavailable and omitted from the model tool list. Retrieved pages/snippets are untrusted evidence. This is not browser automation, login, CAPTCHA/paywall bypass, or a guaranteed citation check. Live Tavily use was not tested.

## Existing tool registry

`ToolDefinition` in `nova/tools/registry.py` specifies name/purpose, JSON schema and validation, handler, permission description, availability, missing-configuration reason, and category. Only available registered tools are sent to a model. Add a new external action only with narrow scopes, tests for allow/deny/error, explicit approval for consequential side effects, idempotency/reconciliation where possible, and audit events. Do not load untrusted plugins directly.

No email, calendar, GitHub, cloud storage, messaging, finance, or local-computer integration is connected.
