# NOVA X — Unified Universal AI Operating System (§1–§27)

NOVA X is a single, integrated, native Kali Linux desktop application (`PySide6` / Qt) optimized for dual-core CPU, ~10 GB RAM, and no dedicated GPU.

## 1. Unified 12-Module Architecture (§3)

Every capability operates inside **one** coherent architecture without duplicate subsystems:

| # | Subsystem | Implementation Module(s) |
|---|---|---|
| 1 | Native Desktop Control Center | `nova/desktop/app.py`, `nova/desktop/runtime.py`, `nova/desktop/cli.py` |
| 2 | Universal Request & Planning Core | `nova/cognition/` (`CognitionService`, §70–§89) + `nova/unified_os.py` |
| 3 | Multi-Model & Local AI Gateway | `nova/model_providers.py`, `nova/intelligence.py` (Cloud + optional loopback `ollama`) |
| 4 | Autonomous Task & Workflow Engine | `nova/engine.py`, `nova/workflows.py`, `nova/unified_os.py` (`BackgroundWorkerSupervisor`) |
| 5 | Unified Capability, Tool & Plugin Registry | `nova/capabilities.py`, `nova/tools/registry.py`, `nova/plugins.py`, `nova/mcp_client.py` |
| 6 | Linux System & Optional Desktop Control | `nova/desktop/commands.py`, `nova/terminal.py`, `nova/desktop_control.py` |
| 7 | Universal Creation & Quality Pipeline | `nova/creation/` (`UniversalCreationEngine`, 10 domains, §116–§148) |
| 8 | Shared Memory & Knowledge System | `nova/memory_hub.py` + `nova/knowledge.py` (SQLite + FTS5 + provenance/secret guard) |
| 9 | Multimodal Interaction Layer | `nova/modalities.py` (Push-to-talk voice, document/image/screenshot analysis) |
| 10 | Security, Policy & Permission Framework | `nova/autonomy.py`, `nova/desktop/policy.py`, `nova/desktop/secrets.py`, `nova/sandbox.py` |
| 11 | Observability, Event & Diagnostics | `nova/events.py`, `nova/observability.py`, `nova/governance.py`, `nova/resources.py` |
| 12 | Packaging, Update & Controlled Self-Improvement | `scripts/build_deb.sh`, `nova/updates.py`, `nova/self_improvement.py` |

## 2. API Fees, Software Licenses & Hardware Disclosures (§4, §18, §24)

- **Software License**: Open-source Python + PySide6 stack (`pyproject.toml`, `requirements.txt`).
- **Cloud API Fees**: Configuring OpenAI, Anthropic, Google Gemini, xAI, DeepSeek, Mistral, OpenAI-compatible endpoints, or Tavily web search incurs usage-based charges billed by the respective third-party provider. NOVA X tracks token/cost estimates and enforces `max_fusion_budget_usd`.
- **Optional Local AI (`ollama`)**: Free of cloud API fees (`http://127.0.0.1:11434/api/chat`), optional, and never loaded by default. On ~10 GB RAM with no dedicated GPU, quantized models <= 3B parameters (`q4_K_M`, <= 3.5 GB) are recommended; models >= 7B are flagged before execution.
- **Honest Capability Boundaries**: NOVA X never claims consciousness, infallibility, or unverified execution. Unavailable host binaries (`ffmpeg`, `blender`, `libreoffice`, `tesseract`, etc.) are dynamically reported as `unconfigured`/`missing` with concrete fallback paths.

## 3. Kali Linux Lifecycle: Install, Run, Upgrade, Rollback & Remove (§21)

### Option A — User-Level Virtualenv Install (Non-Root)
```bash
./scripts/install_user.sh
~/.local/bin/nova-x setup        # Verify environment & capabilities
~/.local/bin/nova-x              # Launch native Qt Control Center
~/.local/bin/nova-x worker --once # Optional single background tick
```
Optional background worker service (disabled by default):
```bash
systemctl --user enable --now nova-x-worker.service
```

### Option B — Debian Package (`.deb`) Install, Upgrade & Remove
```bash
./scripts/build_deb.sh
sudo apt install ./releases/nova-x-desktop_0.2.0_all.deb
```
- **Upgrade**: Build/download the newer `.deb` (verify SHA-256 via `UpdateManager` before applying) and run `sudo apt install ./nova-x-desktop_<version>_all.deb`. User SQLite data and workspaces under `~/.local/share/nova-x` remain intact.
- **Rollback**: Re-install the previous `.deb` (`sudo apt install --allow-downgrades ./nova-x-desktop_<prev>_all.deb`) or roll back staged self-improvement promotions via `ControlledImprovementEngine.rollback_promotion(experiment_id)`.
- **Clean Uninstall**:
  - User install: `./scripts/uninstall_user.sh` (preserves `~/.local/share/nova-x`; pass `--purge-data` to delete user data).
  - Debian package: `sudo apt remove nova-x-desktop` (preserves user home data).

## 4. Security & Troubleshooting (§19, §21)

- **Never Run as Root**: NOVA X operates under your normal user account. Administrative actions require explicit NOVA approval plus desktop Polkit (`pkexec`); plaintext `sudo` passwords are never stored.
- **Secret Storage**: Cloud API keys require a verified Linux Secret Service keyring (`gnome-keyring` / `kwallet`). Plaintext keyring fallbacks are refused.
- **Emergency Stop**: Click **Emergency stop** in the top bar of NOVA X at any time to cancel active tasks and terminate child processes.
- **Troubleshooting**: Run `nova-x diagnostics` or open the **Diagnostics** / **OS control center** pages to export a redacted diagnostic bundle.
