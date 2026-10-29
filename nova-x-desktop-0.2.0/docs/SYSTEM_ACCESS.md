# NOVA X — System Access, Hardware Intelligence & Continuous Autonomy (§149–§164)

This document describes NOVA X's legitimate Linux hardware inspection, driver intelligence, privilege separation, durable crash/power-off recovery, session-aware screen studio, system/network observability, persistent troubleshooting, and authorized remote OpenSSH/node administration.

## Architecture Overview (`nova/system_access/`)

All §149–§164 capabilities integrate directly into `PlatformService` (`platform.system_access`) and share NOVA X's single SQLite WAL database (`nova/db.py`), `ToolRegistry` (`nova/tools/system_access.py`), `AutonomyPolicy`, `Redactor`, and native 11-page PySide6 Control Center (`nova/desktop/app.py` -> **Hardware & servers**).

| Section | Module | Responsibility |
|---|---|---|
| §149–§151 | `nova/system_access/hardware.py` | `HardwareInventoryEngine` (19 Linux hardware/subsystem probes, searchable explorer classifying `active`, `detected`, `supported`, `error`, `restricted_access`, and `unexposed`), `DriverIntelligenceEngine` (evidence-based 12-step diagnostics, 5-layer taxonomy, post-repair verification), and `DeviceOperationsController` (dry-run preview + primary-interface and critical-storage safety gates). |
| §152 | `nova/system_access/privilege.py` & `helper_cli.py` | Split unprivileged Desktop/Runtime Client (`PrivilegedHelperClient`) + narrowly scoped `PrivilegedSystemHelper` (`nova-x-privileged-helper` / `packaging/polkit/org.novax.pkexec.helper.policy`). Strict allowlist, zero shell expansion, zero plaintext sudo storage, and model instructions alone never authorize admin operations. |
| §153, §154, §161–§163 | `nova/system_access/resilience.py` | `StartupRecoveryPolicyManager` (9 independent startup/recovery toggles with pre-enable account/purpose/permission disclosures, XDG autostart, `systemd --user` worker unit, Safe Recovery Mode, versioned config backup recovery, log rotation) and `DurableTaskJournal` (17-field WAL checkpoint + idempotency ledger inspecting actual disk/remote state before repeating interrupted steps). |
| §155 | `nova/system_access/recording.py` | `ScreenRecordingStudio`: X11 / Wayland Portal+PipeWire / headless session detection, explicit microphone opt-in consent, visible recording indicator (`recording_indicator.json`), segmented RIFF AVI media writing, lock/revocation/crash recovery without fabricating uncaptured frames, and post-recording analysis separating `direct_observations` from `ai_interpretations`. |
| §156, §158, §159 | `nova/system_access/observability_net.py` | `SystemNetworkMonitor` (14 low-overhead telemetry signals + alert rules), `PersistentTroubleshooter` (multi-source hypothesis pivoting + untrusted external prompt-injection stripping), and `InfrastructureKnowledgeEngine` (13 categories, TTL staleness tracking, raw secret rejection). |
| §157, §160 | `nova/system_access/remote.py` | `ServerRegistryAndAdmin` (standard OpenSSH `ssh`/`scp`/`ssh-keyscan` with `BatchMode=yes`, `StrictHostKeyChecking=yes`, pinned `known_hosts` fingerprint verification, unexpected host-key rejection, `ProtectedCredentialVault` `0600` isolation, high-impact approval gates, multi-server audits) and `MultiDeviceNodeCoordinator` + `LocalNodeAgent` (HMAC-SHA256 mutual auth + independent local node policy enforcement). |
| §164 | `nova/system_access/acceptance.py` | 20-check acceptance runner (`python -m nova.system_access.acceptance`), including live ephemeral non-root `/usr/sbin/sshd` verification for checks #11–#15. |

## Running the §164 Acceptance Suite

```bash
cd nova-x-desktop-0.2.0
python -m nova.system_access.acceptance
```
