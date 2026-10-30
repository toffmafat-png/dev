# DEV — Corrected Master Architecture (§1–§11)

## Locally Hosted Autonomous AI Platform Powered by Cloud Frontier Intelligence

DEV (NOVA X Desktop on Kali Linux) implements a strict hybrid architecture:

1. **§1 Local OS Hosting vs. Cloud Frontier Intelligence (`nova/hybrid_cloud/architecture.py`):**
   - **Locally Hosted on Kali Linux (15 components):** Native PySide6 desktop application, agent orchestration engine, task planner, persistent SQLite WAL memory & knowledge base, file management, local command execution, hardware/driver integration, application control, screen capture & authorized desktop automation, background task workers, system diagnostics, workflow engine, security/permission management, project development environment, and logs/history/checkpoints.
   - **Cloud Frontier APIs (8 components):** Frontier AI inference, complex reasoning, specialist model collaboration, coding intelligence, research/analysis, multimodal processing when configured, cloud model upgrades, and optional specialist inference.
   - **Non-Spaces Guarantee:** No Hugging Face Spaces deployment metadata or externally hosted primary web runtime; `app.py` and `Dockerfile` bind strictly to `127.0.0.1` loopback by default as a local companion service.

2. **§2 Unified Cloud Frontier AI Gateway (`nova/hybrid_cloud/gateway_and_fusion.py`, `nova/model_providers.py`):**
   - Supports OpenAI, Anthropic, Google Gemini, xAI Grok, DeepSeek, Mistral, OpenAI-compatible endpoints, Ollama, `llama.cpp`, and runtime-registered extensible providers (`dynamic_provider_specs`).
   - Distinguishes all **5 lifecycle states** (`configured`, `connected`, `available`, `tested`, `actually_used`) with zero hardcoded outdated vendor model IDs.
   - Supports parallel requests, streaming SSE responses (`stream_chat`), strict JSON schema validation (`structured_chat`), tool-call validation, latency/token/cost tracking, and privacy-gated fallback.

3. **§3 Frontier Model Fusion & 9 Specialist Roles (`SpecialistFusionCoordinator`):**
   - Modes: `fast`, `balanced`, `frontier_fusion`, and `maximum_intelligence`.
   - Dynamic specialist roles: `lead_reasoning`, `independent_analysis`, `coding`, `research`, `mathematics`, `critical_review`, `security_review`, `verification`, and `final_synthesis`.
   - Resolves disagreements via local calculation, documentation, and tool execution evidence—never via majority vote or draft concatenation.

4. **§4 & §5 Local Execution Separation & Cloud Privacy Gateway (`nova/hybrid_cloud/privacy_gateway.py`):**
   - 8-step Kali diagnostic/tool workflow keeping local execution strictly behind `AutonomyPolicy` and `UntrustedExternalInputValidator`.
   - Context minimization, credential/key/cookie/sudo/SSH-key redaction, per-provider policies, sensitive-file approval gates, `local_only` project mode, anti-payload-escalation fallback guard, and a secret-free `cloud_transmission_ledger`.

5. **§6, §7, §8, §9 & §10 Persistence, `llama.cpp` Fallback, Unified Execution & Security (`nova/hybrid_cloud/persistence_and_resources.py`):**
   - Durable `offline_cloud_queue` that keeps local work running while offline, never falsely marks cloud AI tasks complete, and resumes idempotently from checkpoints when connectivity returns.
   - Optional `llama.cpp` (`LlamaCppAdapter`) fallback restricted to compact quantized models that fit available host RAM, rejecting enormous (`>14B`) or unquantized (`FP16`/`FP32`) models automatically.
   - Single unified task engine (`competing_execution_engines == 0`), separated local host vs. cloud API resource intelligence across 8 routing signals, and hard blocks against cloud self-permission mutation, secret-store exfiltration, or root execution.

## Verification

```bash
python -m nova.hybrid_cloud.acceptance
pytest tests/test_corrected_master_architecture.py
```
