"""DEV Personal-Use Security and Autonomy Policy Engine (Sections 1–7)."""
from __future__ import annotations

import hashlib
import os
import re
import shlex
import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nova.db import Database
from nova.observability import Redactor

# Section 1 & 7 Architectural Posture Constants
DEPLOYMENT_MODEL = "single_user_personal_kali_linux"
PUBLIC_MULTI_TENANT_SAAS = False
STRICT_OWASP_CHECKLIST_MANDATORY = False
ENTERPRISE_CERTIFICATION_REQUIRED = False
COMPLIANCE_THEATRE_ENABLED = False

# Section 3, 5 & 6 Core Invariants
MINIMAL_INTERVENTION_EQUALS_UNLIMITED_AUTHORIZATION = False
ARTIFICIALLY_LIMIT_SECURITY_KNOWLEDGE = False
LOCAL_STORAGE_BY_DEFAULT = True
EXPOSE_CREDENTIALS_TO_REMOTE_MODELS = False
EXPOSE_UNRESTRICTED_HOST_ACCESS_TO_REMOTE_MODELS = False

PERSONAL_14_COMPUTING_DOMAINS: tuple[str, ...] = (
    "terminal_and_command_execution",
    "installed_applications",
    "file_operations",
    "hardware_and_driver_discovery",
    "system_diagnostics",
    "software_installation",
    "development_tools",
    "background_services",
    "authorized_network_operations",
    "registered_remote_servers",
    "browser_automation",
    "screen_capture",
    "automation_and_scripting",
    "software_and_security_research",
)

AUTONOMOUS_11_INDEPENDENT_OPERATIONS: tuple[str, ...] = (
    "plan_tasks",
    "create_subtasks",
    "choose_suitable_tools",
    "research_technical_problems",
    "execute_permitted_operations",
    "recover_from_recoverable_failures",
    "create_custom_utilities",
    "install_approved_dependencies",
    "run_tests",
    "improve_its_software",
    "resume_interrupted_tasks",
)

MATERIAL_9_PROTECTED_RISKS: tuple[str, ...] = (
    "accidental_deletion_of_important_information",
    "credential_exposure",
    "malicious_downloads",
    "compromised_plugins",
    "dangerous_ai_generated_commands",
    "unauthorized_remote_access",
    "unintended_external_data_disclosure",
    "unrecoverable_system_modifications",
    "uncontrolled_resource_consumption",
)

CYBER_8_RESEARCH_CAPABILITIES: tuple[str, ...] = (
    "vulnerability_discovery",
    "defensive_testing",
    "controlled_exploitation_research",
    "reverse_engineering",
    "digital_forensics",
    "application_security_assessment",
    "security_tool_development",
    "remediation_verification",
)

DEFAULT_POWER_USER_PROGRAMS: tuple[str, ...] = (
    "pwd",
    "ls",
    "uname",
    "df",
    "free",
    "which",
    "file",
    "stat",
    "wc",
    "head",
    "tail",
    "cat",
    "grep",
    "rg",
    "fd",
    "fdfind",
    "find",
    "tree",
    "jq",
    "sha256sum",
    "git",
    "python",
    "python3",
    "pytest",
    "ruff",
    "node",
    "npm",
    "make",
    "cmake",
    "gcc",
    "g++",
    "cargo",
    "go",
    "objdump",
    "readelf",
    "strings",
)

# Catastrophic / unrecoverable patterns that remain blocked even under power-user grants (Section 4)
_CATASTROPHIC_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "root_or_home_recursive_wipe",
        re.compile(r"(?:^|\s)rm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+(?:/|/\*|~|\$HOME|\.\.)(?:\s|$)"),
    ),
    (
        "raw_disk_format_or_wipe",
        re.compile(r"\b(?:mkfs(?:\.[a-z0-9]+)?|wipefs|shred)\b|\bdd\b[^\n]*\bof=/dev/(?:sd|nvme|vd|hd|mmcblk|loop)"),
    ),
    (
        "unverified_remote_pipe_to_shell",
        re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b"),
    ),
    (
        "fork_bomb_or_world_writable_root",
        re.compile(r":\(\)\s*\{\s*:\|\:&\s*\};:|chmod\s+-R\s+0?777\s+/(?:\s|$)"),
    ),
    (
        "bootloader_or_partition_destruction",
        re.compile(r"\b(?:sfdisk|fdisk|parted)\s+/dev/|\bgrub-install\b"),
    ),
)

_CREDENTIAL_PATH_MARKERS: tuple[str, ...] = (
    "/.ssh/",
    ".ssh/id_",
    "/.gnupg/",
    "/.aws/credentials",
    "/.kube/config",
    "/.netrc",
    "/etc/shadow",
    "/etc/gshadow",
    "keyrings/",
)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


class FrameworkFlexibilityAndAntiTheatreGuard:
    """Sections 1 & 7: Treat security standards as engineering references, reject compliance theatre."""

    @staticmethod
    def evaluate_safeguard_proportionality(
        control_name: str,
        *,
        mitigates_material_risk: str = "",
        introduces_repeated_prompts: bool = False,
        multi_tenant_enterprise_only: bool = False,
        blocks_legitimate_local_capability: bool = False,
        heavy_dependency_without_measured_benefit: bool = False,
    ) -> dict[str, Any]:
        rejection_reasons: list[str] = []
        if multi_tenant_enterprise_only:
            rejection_reasons.append("targets_multi_tenant_saas_not_single_user_kali")
        if introduces_repeated_prompts:
            rejection_reasons.append("creates_repetitive_confirmation_friction_for_authorized_work")
        if blocks_legitimate_local_capability and not mitigates_material_risk:
            rejection_reasons.append("disables_useful_capability_without_concrete_local_risk")
        if heavy_dependency_without_measured_benefit:
            rejection_reasons.append("adds_heavy_dependency_without_demonstrated_benefit")

        has_material_benefit = mitigates_material_risk in MATERIAL_9_PROTECTED_RISKS
        adopt = has_material_benefit and not rejection_reasons
        return {
            "control_name": control_name,
            "deployment_model": DEPLOYMENT_MODEL,
            "strict_owasp_checklist_mandatory": STRICT_OWASP_CHECKLIST_MANDATORY,
            "enterprise_certification_required": ENTERPRISE_CERTIFICATION_REQUIRED,
            "compliance_theatre_enabled": COMPLIANCE_THEATRE_ENABLED,
            "adopt_control": adopt,
            "mitigates_material_risk": mitigates_material_risk if has_material_benefit else "",
            "rejection_reasons": rejection_reasons,
        }

    @classmethod
    def evaluate_framework_recommendation(
        cls,
        reference_id: str,
        description: str,
        *,
        mitigates_material_risk: str = "",
        enterprise_multi_tenant_only: bool = False,
        introduces_repeated_prompts: bool = False,
    ) -> dict[str, Any]:
        ev = cls.evaluate_safeguard_proportionality(
            reference_id,
            mitigates_material_risk=mitigates_material_risk,
            multi_tenant_enterprise_only=enterprise_multi_tenant_only,
            introduces_repeated_prompts=introduces_repeated_prompts,
        )
        return {
            "reference_id": reference_id,
            "description": description,
            "adopt": ev["adopt_control"],
            "mandatory_prerequisite": STRICT_OWASP_CHECKLIST_MANDATORY,
            "reason": ",".join(ev["rejection_reasons"]) or "proportionate_single_user_engineering_reference",
        }

    @staticmethod
    def audit_proposal(
        *,
        claims_unsafe_solely_for_missing_enterprise_control: bool = False,
        adds_local_single_user_auth_prompt: bool = False,
        repeats_approval_for_persistent_grant: bool = False,
        disables_useful_capability_without_concrete_reason: bool = False,
        prioritizes_docs_over_working_code: bool = False,
        adds_heavy_unjustified_dependency: bool = False,
    ) -> dict[str, Any]:
        violations: list[str] = []
        if claims_unsafe_solely_for_missing_enterprise_control:
            violations.append("claimed_unsafe_solely_for_missing_enterprise_control")
        if adds_local_single_user_auth_prompt:
            violations.append("unnecessary_local_single_user_authentication_layer")
        if repeats_approval_for_persistent_grant:
            violations.append("repeated_approval_dialog_for_persistent_grant")
        if disables_useful_capability_without_concrete_reason:
            violations.append("disabled_useful_capability_without_concrete_technical_reason")
        if prioritizes_docs_over_working_code:
            violations.append("prioritized_policy_docs_over_working_functionality")
        if adds_heavy_unjustified_dependency:
            violations.append("added_heavy_dependency_without_demonstrated_benefit")
        return {
            "passed": len(violations) == 0,
            "compliance_theatre_enabled": COMPLIANCE_THEATRE_ENABLED,
            "violations": violations,
        }


class RiskProportionateSafeguardEngine:
    """Section 4: Essential safeguards (backups, rollback, secret redaction, catastrophic command block) without enterprise bloat."""

    def __init__(self, *, db: Database, workspace_dir: Path, redactor: Redactor | None = None) -> None:
        self.db = db
        self.workspace_dir = Path(workspace_dir)
        self.redactor = redactor or Redactor()

    @property
    def backup_vault_dir(self) -> Path:
        d = self.workspace_dir / ".dev_safeguard_backups"
        d.mkdir(parents=True, exist_ok=True)
        return d

    @staticmethod
    def inspect_command_safety(command_or_argv: str | list[str]) -> dict[str, Any]:
        """Fast, risk-proportionate classifier catching catastrophic/credential-stealing commands while allowing normal CLI work."""
        if isinstance(command_or_argv, list):
            tokens = [str(x) for x in command_or_argv]
            joined = " ".join(tokens)
        else:
            joined = str(command_or_argv)
            try:
                tokens = shlex.split(joined)
            except ValueError:
                tokens = joined.split()

        violations: list[str] = []
        for code, pattern in _CATASTROPHIC_COMMAND_PATTERNS:
            if pattern.search(joined):
                violations.append(code)

        for tok in tokens:
            norm = tok.replace("\\", "/")
            low = norm.lower()
            if any(marker in low for marker in _CREDENTIAL_PATH_MARKERS) or low.endswith("/.env") or low == ".env":
                violations.append("credential_or_private_key_access")
                break

        first_prog = Path(tokens[0]).name.lower() if tokens else ""
        needs_linux_polkit = first_prog in {"sudo", "su", "doas", "pkexec"}

        return {
            "safe_for_personal_execution": len(violations) == 0 and not needs_linux_polkit,
            "blocked_catastrophic_or_credential": len(violations) > 0,
            "requires_linux_polkit": needs_linux_polkit,
            "violations": violations,
            "program": first_prog,
        }

    def guarded_file_operation(
        self,
        target_path: str | Path,
        *,
        operation: str,
        new_content: str | bytes | None = None,
    ) -> dict[str, Any]:
        """Section 4: Protects against accidental deletion or unrecoverable modification via automatic SHA-256 backup."""
        if operation not in {"overwrite", "delete"}:
            raise ValueError("operation must be 'overwrite' or 'delete'.")
        target = Path(target_path).expanduser().resolve()
        low = str(target).replace("\\", "/").lower()
        if any(m in low for m in ("/.ssh/", "/.gnupg/", "/etc/shadow", "/boot/grub")):
            return {
                "ok": False,
                "blocked": True,
                "reason": "protected_credential_or_boot_path",
            }

        backup_id = ""
        backup_file_str = ""
        orig_sha = ""
        if target.exists() and target.is_file():
            orig_bytes = target.read_bytes()
            orig_sha = hashlib.sha256(orig_bytes).hexdigest()
            backup_id = f"fbackup-{uuid.uuid4().hex[:10]}"
            bfile = self.backup_vault_dir / f"{backup_id}.bin"
            bmeta = self.backup_vault_dir / f"{backup_id}.meta.txt"
            bfile.write_bytes(orig_bytes)
            bmeta.write_text(f"{target}\n{orig_sha}\n{_iso()}\n", encoding="utf-8")
            backup_file_str = str(bfile)

        if operation == "delete":
            if target.exists():
                target.unlink()
            return {
                "ok": True,
                "operation": "delete",
                "target_path": str(target),
                "backup_id": backup_id,
                "backup_path": backup_file_str,
                "original_sha256": orig_sha,
            }

        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(new_content, bytes):
            target.write_bytes(new_content)
        else:
            target.write_text(str(new_content or ""), encoding="utf-8")
        return {
            "ok": True,
            "operation": "overwrite",
            "target_path": str(target),
            "backup_id": backup_id,
            "backup_path": backup_file_str,
            "original_sha256": orig_sha,
        }

    def restore_file_from_backup(self, backup_id: str) -> dict[str, Any]:
        safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "", backup_id)
        bfile = self.backup_vault_dir / f"{safe_id}.bin"
        bmeta = self.backup_vault_dir / f"{safe_id}.meta.txt"
        if not bfile.is_file() or not bmeta.is_file():
            raise FileNotFoundError(f"Safeguard backup '{backup_id}' not found.")
        lines = bmeta.read_text(encoding="utf-8").splitlines()
        orig_target = Path(lines[0])
        expected_sha = lines[1]
        data = bfile.read_bytes()
        actual_sha = hashlib.sha256(data).hexdigest()
        if actual_sha != expected_sha:
            raise ValueError("Backup integrity SHA-256 mismatch.")
        orig_target.parent.mkdir(parents=True, exist_ok=True)
        orig_target.write_bytes(data)
        return {
            "ok": True,
            "restored": True,
            "backup_id": safe_id,
            "restored_path": str(orig_target),
            "verified_sha256": actual_sha,
        }

    def rollback_file_operation(self, backup_id: str) -> dict[str, Any]:
        return self.restore_file_from_backup(backup_id)

    @staticmethod
    def verify_download_artifact(data_bytes: bytes, *, expected_sha256: str = "") -> dict[str, Any]:
        actual_sha = hashlib.sha256(data_bytes).hexdigest()
        is_executable = data_bytes.startswith(b"\x7fELF") or data_bytes.startswith(b"#!")
        sha_ok = (not expected_sha256) or (actual_sha.lower() == expected_sha256.strip().lower())
        verified = sha_ok and (bool(expected_sha256) or not is_executable)
        return {
            "verified": verified,
            "sha256": actual_sha,
            "is_executable_binary_or_script": is_executable,
            "reason": "verified" if verified else "checksum_mismatch_or_unverified_executable_download",
        }

    @staticmethod
    def verify_plugin_source(code_text: str, *, declared_permissions: list[str] | None = None) -> dict[str, Any]:
        perms = set(declared_permissions or [])
        findings: list[str] = []
        if re.search(r"\b(?:subprocess|os\.system|pty\.spawn)\b", code_text) and "process_execute" not in perms:
            findings.append("undeclared_subprocess_execution")
        if re.search(r"\b(?:urllib\.request|socket|httpx|requests)\b", code_text) and "network_outbound" not in perms:
            findings.append("undeclared_network_access")
        if any(m in code_text.lower() for m in (".ssh/id_", "/etc/shadow", ".gnupg")):
            findings.append("credential_harvesting_pattern")
        return {"safe": len(findings) == 0, "findings": findings}

    @staticmethod
    def validate_remote_bind_host(bind_host: str, *, user_authorized_lan: bool = False) -> dict[str, Any]:
        h = bind_host.strip().lower()
        loopback = h in {"127.0.0.1", "::1", "localhost"}
        allowed = loopback or bool(user_authorized_lan)
        return {
            "allowed": allowed,
            "bind_host": bind_host,
            "reason": "loopback_or_authorized" if allowed else "non_loopback_bind_requires_explicit_user_lan_authorization",
        }

    @staticmethod
    def check_resource_bounds(*, timeout_seconds: int = 120, memory_mb: int = 2048) -> dict[str, Any]:
        within = 1 <= int(timeout_seconds) <= 3600 and 32 <= int(memory_mb) <= 32768
        return {
            "within_bounds": within,
            "timeout_seconds": int(timeout_seconds),
            "memory_mb": int(memory_mb),
        }


class PersonalAutonomyAndCapabilityEngine:
    """Sections 2 & 3: Broad Kali Personal Computing + Persistent Permissions with Minimal Human Intervention."""

    def __init__(
        self,
        *,
        db: Database,
        workspace_dir: Path,
        safeguards: RiskProportionateSafeguardEngine,
        autonomy_policy: Any | None = None,
    ) -> None:
        self.db = db
        self.workspace_dir = Path(workspace_dir)
        self.safeguards = safeguards
        self.autonomy_policy = autonomy_policy

    def get_policy(self) -> dict[str, Any]:
        rec = self.db.get_personal_policy_config()
        defaults = {
            "deployment_model": DEPLOYMENT_MODEL,
            "public_multi_tenant_saas": PUBLIC_MULTI_TENANT_SAAS,
            "strict_owasp_checklist_mandatory": STRICT_OWASP_CHECKLIST_MANDATORY,
            "compliance_theatre_enabled": COMPLIANCE_THEATRE_ENABLED,
            "minimal_intervention_equals_unlimited_authorization": MINIMAL_INTERVENTION_EQUALS_UNLIMITED_AUTHORIZATION,
            "minimal_task_context_only": True,
            "auto_backup_before_file_modify": True,
            "log_external_transfers": True,
            "allow_persistent_cyber_lab_ops": True,
            "local_only_projects": [],
        }
        profile_mode = "balanced"
        if rec:
            profile_mode = rec["profile_mode"]
            defaults.update(rec["settings"])
        return {
            "profile_mode": profile_mode,
            "supported_computing_domains": list(PERSONAL_14_COMPUTING_DOMAINS),
            "independent_autonomous_operations": list(AUTONOMOUS_11_INDEPENDENT_OPERATIONS),
            "settings": defaults,
        }

    def update_policy(self, *, profile_mode: str | None = None, settings_updates: dict[str, Any] | None = None) -> dict[str, Any]:
        current = self.get_policy()
        mode = profile_mode or current["profile_mode"]
        valid_modes = {
            "balanced",
            "balanced_personal",
            "personal_power_user",
            "cyber_lab_research",
            "strict_review",
            "conservative",
        }
        if mode not in valid_modes:
            raise ValueError(f"profile_mode must be one of {sorted(valid_modes)}.")
        merged = dict(current["settings"])
        if settings_updates:
            merged.update(settings_updates)
        # Preserve architectural truth invariants
        merged["strict_owasp_checklist_mandatory"] = STRICT_OWASP_CHECKLIST_MANDATORY
        merged["compliance_theatre_enabled"] = COMPLIANCE_THEATRE_ENABLED
        merged["minimal_intervention_equals_unlimited_authorization"] = MINIMAL_INTERVENTION_EQUALS_UNLIMITED_AUTHORIZATION
        self.db.upsert_personal_policy_config(mode, merged)
        return self.get_policy()

    def configure_policy(self, *, profile_mode: str | None = None, settings_updates: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.update_policy(profile_mode=profile_mode, settings_updates=settings_updates)

    def revoke_persistent_permission(self, grant_id: str) -> bool:
        return self.db.revoke_personal_persistent_grant(grant_id)

    def capability_domains_status(self) -> dict[str, Any]:
        probe = self.discover_local_kali_capabilities()
        return {
            "domain_count": len(PERSONAL_14_COMPUTING_DOMAINS),
            "domains": [{"domain": d, "enabled": True} for d in PERSONAL_14_COMPUTING_DOMAINS],
            "host_probe": probe,
        }

    @staticmethod
    def autonomous_operations_manifest() -> dict[str, Any]:
        return {
            "independent_operations": list(AUTONOMOUS_11_INDEPENDENT_OPERATIONS),
            "minimal_intervention_equals_unlimited_authorization": MINIMAL_INTERVENTION_EQUALS_UNLIMITED_AUTHORIZATION,
        }

    def grant_persistent_permission(
        self,
        *,
        domain: str,
        scope_target: str,
        allowed_programs: list[str] | None = None,
        allowed_operations: list[str] | None = None,
        notes: str = "",
        grant_id: str = "",
    ) -> dict[str, Any]:
        """Section 3: Configure persistent permissions for trusted, recurring activities without repeated prompts."""
        if domain not in PERSONAL_14_COMPUTING_DOMAINS:
            raise ValueError(f"Unsupported personal computing domain '{domain}'. Valid: {', '.join(PERSONAL_14_COMPUTING_DOMAINS)}")
        raw_target = scope_target.strip()
        if not raw_target:
            raise ValueError("scope_target cannot be blank.")
        resolved_scope = "*" if raw_target == "*" else str(Path(raw_target).expanduser().resolve())
        progs = sorted({Path(p).name.lower() for p in (allowed_programs or []) if p.strip()})
        # Privilege wrappers remain governed by normal Linux polkit, never silent persistent bypass
        if any(p in {"sudo", "su", "doas", "pkexec"} for p in progs):
            raise ValueError("Administrative privilege wrappers use standard Linux polkit authentication and cannot be silently pre-granted.")
        ops = sorted({o.strip() for o in (allowed_operations or ["execute", "read", "write", "test"]) if o.strip()})
        saved = self.db.upsert_personal_persistent_grant(
            {
                "grant_id": grant_id or f"pgrant-{uuid.uuid4().hex[:10]}",
                "domain": domain,
                "scope_target": resolved_scope,
                "allowed_programs": progs,
                "allowed_operations": ops,
                "active": True,
                "notes": notes,
            }
        )
        # If this grant covers a workspace subdirectory for file_operations, sync into AutonomyPolicy overwrite scopes
        if domain == "file_operations" and resolved_scope != "*" and self.autonomy_policy is not None:
            try:
                ws_root = self.workspace_dir.resolve()
                rel = Path(resolved_scope).relative_to(ws_root).as_posix().strip("/")
                if rel and rel != ".":
                    cur = self.autonomy_policy.get()
                    prefixes = list(cur.get("authorized_overwrite_prefixes") or [])
                    if rel not in prefixes and len(prefixes) < 20:
                        self.autonomy_policy.update(cur["level"], cur["tool_overrides"], [*prefixes, rel])
            except ValueError:
                pass
        return saved

    def grant_power_user_workspace_preset(self, scope_dir: str | Path) -> dict[str, Any]:
        """One-call preset enabling frictionless dev, CLI, file, diagnostic & scripting access in an owned directory."""
        resolved = str(Path(scope_dir).expanduser().resolve())
        self.update_policy(profile_mode="personal_power_user")
        g_dev = self.grant_persistent_permission(
            domain="development_tools",
            scope_target=resolved,
            allowed_programs=list(DEFAULT_POWER_USER_PROGRAMS),
            allowed_operations=["execute", "test", "build", "lint", "inspect"],
            notes="Personal-use power preset for trusted Kali workspace",
            grant_id=f"preset-dev-{hashlib.sha256(resolved.encode()).hexdigest()[:8]}",
        )
        g_files = self.grant_persistent_permission(
            domain="file_operations",
            scope_target=resolved,
            allowed_programs=["cp", "mv", "mkdir", "touch", "tar", "gzip", "unzip"],
            allowed_operations=["read", "write", "overwrite_with_backup"],
            notes="Persistent file operations with automatic safeguard backups",
            grant_id=f"preset-files-{hashlib.sha256(resolved.encode()).hexdigest()[:8]}",
        )
        return {"profile_mode": "personal_power_user", "scope_target": resolved, "grants": [g_dev, g_files]}

    def check_persistent_command_grant(self, argv: list[str], cwd: str) -> dict[str, Any]:
        """Evaluates whether `argv` in `cwd` is pre-authorized by an active personal persistent grant."""
        grants = self.db.list_personal_persistent_grants(active_only=True)
        if not grants or not argv:
            return {"granted": False, "reason": "no_active_personal_grants"}

        safety = self.safeguards.inspect_command_safety(argv)
        if safety["blocked_catastrophic_or_credential"]:
            return {
                "granted": False,
                "blocked": True,
                "reason": f"blocked_by_risk_proportionate_safeguard:{','.join(safety['violations'])}",
            }
        if safety["requires_linux_polkit"]:
            return {
                "granted": False,
                "blocked": False,
                "reason": "requires_normal_linux_polkit_privilege",
            }

        try:
            resolved_cwd = Path(cwd).expanduser().resolve()
        except (OSError, RuntimeError):
            return {"granted": False, "reason": "invalid_cwd"}

        prog = Path(argv[0]).name.lower()
        # Prevent git remote push/force-reset surprises unless explicitly granted under 'git_remote'
        if prog == "git" and len(argv) > 1 and argv[1].lower() in {"push"}:
            has_remote_op = any(
                "git_push" in set(g["allowed_operations"])
                for g in grants
                if prog in set(g["allowed_programs"])
            )
            if not has_remote_op:
                return {"granted": False, "reason": "git_push_requires_explicit_operation_grant"}

        for g in grants:
            allowed_progs = set(g["allowed_programs"])
            if prog not in allowed_progs and "*" not in allowed_progs:
                continue
            starget = g["scope_target"]
            if starget == "*":
                return {"granted": True, "grant_id": g["grant_id"], "domain": g["domain"]}
            try:
                scope_path = Path(starget).resolve()
                if resolved_cwd == scope_path or scope_path in resolved_cwd.parents:
                    return {"granted": True, "grant_id": g["grant_id"], "domain": g["domain"]}
            except (OSError, RuntimeError):
                continue

        return {"granted": False, "reason": "command_or_scope_not_covered_by_grant"}

    def decide_autonomous_operation(
        self,
        operation: str,
        *,
        requires_linux_root: bool = False,
        involves_unapproved_financial_spend: bool = False,
        outside_configured_scope: bool = False,
    ) -> dict[str, Any]:
        """Section 3: Allow independent planning, tool selection, testing, utilities & recovery without nagging; gate real boundaries."""
        if involves_unapproved_financial_spend:
            return {
                "permitted_without_prompt": False,
                "action": "approval_required",
                "reason": "financial_commitment_requires_explicit_user_approval",
                "unlimited_authorization_assumed": MINIMAL_INTERVENTION_EQUALS_UNLIMITED_AUTHORIZATION,
            }
        if outside_configured_scope:
            return {
                "permitted_without_prompt": False,
                "action": "approval_required",
                "reason": "target_outside_configured_personal_scope",
                "unlimited_authorization_assumed": MINIMAL_INTERVENTION_EQUALS_UNLIMITED_AUTHORIZATION,
            }
        if requires_linux_root and (not hasattr(os, "geteuid") or os.geteuid() != 0):
            return {
                "permitted_without_prompt": False,
                "action": "linux_polkit_required",
                "reason": "genuinely_administrative_operation_uses_normal_linux_permission_system",
                "unlimited_authorization_assumed": MINIMAL_INTERVENTION_EQUALS_UNLIMITED_AUTHORIZATION,
            }
        if operation in AUTONOMOUS_11_INDEPENDENT_OPERATIONS:
            return {
                "permitted_without_prompt": True,
                "action": "allow",
                "operation": operation,
                "unlimited_authorization_assumed": MINIMAL_INTERVENTION_EQUALS_UNLIMITED_AUTHORIZATION,
            }
        return {
            "permitted_without_prompt": False,
            "action": "approval_required",
            "reason": f"unclassified_operation:{operation}",
            "unlimited_authorization_assumed": MINIMAL_INTERVENTION_EQUALS_UNLIMITED_AUTHORIZATION,
        }

    def discover_local_kali_capabilities(self) -> dict[str, Any]:
        """Section 2: Live probe of broad personal Kali computing utilities on this host."""
        probed = {prog: shutil.which(prog) for prog in DEFAULT_POWER_USER_PROGRAMS}
        available = {k: v for k, v in probed.items() if v is not None}
        return {
            "domains_supported": list(PERSONAL_14_COMPUTING_DOMAINS),
            "linux_user_euid": os.geteuid() if hasattr(os, "geteuid") else -1,
            "pkexec_installed": shutil.which("pkexec") is not None,
            "available_cli_and_dev_programs_count": len(available),
            "available_programs": available,
        }


class PersonalCyberResearchAuthorizer:
    """Section 5: Persistent authorization for owned/registered cybersecurity labs without artificial censorship."""

    def __init__(
        self,
        *,
        db: Database,
        autonomy_engine: PersonalAutonomyAndCapabilityEngine,
        cyber_division: Any | None = None,
    ) -> None:
        self.db = db
        self.autonomy_engine = autonomy_engine
        self.cyber_division = cyber_division

    def register_persistent_lab_environment(
        self,
        *,
        name: str,
        category: str = "development_environment",
        targets: list[str],
        notes: str = "Persistent personal cybersecurity lab authorization",
    ) -> dict[str, Any]:
        if not targets:
            raise ValueError("Provide at least one owned/authorized lab target or directory.")
        normalized_category = "development_environment" if category == "local_lab" else category
        scope_rec: dict[str, Any] = {}
        if self.cyber_division is not None:
            scope_rec = self.cyber_division.scope_registry.register_scope(
                name=name,
                category=normalized_category,
                targets=targets,
                authorization_evidence=f"Persistent personal-use lab policy: {notes}",
            )
        grants: list[dict[str, Any]] = []
        for t in targets:
            is_path = t.startswith("/") or t.startswith("./") or t.startswith("~") or Path(t).exists()
            scope_val = str(Path(t).expanduser().resolve()) if is_path and Path(t).expanduser().exists() else t
            gid = f"cyberlab-{hashlib.sha256(f'{name}:{scope_val}'.encode()).hexdigest()[:10]}"
            g = self.db.upsert_personal_persistent_grant(
                {
                    "grant_id": gid,
                    "domain": "software_and_security_research",
                    "scope_target": scope_val,
                    "allowed_programs": ["python3", "nmap", "objdump", "readelf", "strings", "sha256sum", "tcpdump"],
                    "allowed_operations": list(CYBER_8_RESEARCH_CAPABILITIES),
                    "active": True,
                    "notes": notes,
                }
            )
            grants.append(g)
        primary_grant = dict(grants[0], persistent=True) if grants else {"persistent": True}
        return {
            "lab_name": name,
            "persistent_authorization": True,
            "repeated_prompts_required": False,
            "artificially_limit_security_knowledge": ARTIFICIALLY_LIMIT_SECURITY_KNOWLEDGE,
            "enabled_research_capabilities": list(CYBER_8_RESEARCH_CAPABILITIES),
            "cyber_scope": scope_rec,
            "grant": primary_grant,
            "persistent_grants": grants,
        }

    def authorize_research_step(self, *, capability: str, target: str) -> dict[str, Any]:
        res = self.authorize_lab_research_step(target=target, capability=capability)
        return {
            **res,
            "requires_repeated_approval": bool(res.get("prompt_required", not res.get("authorized", False))),
        }

    def authorize_lab_research_step(self, *, target: str, capability: str) -> dict[str, Any]:
        if capability not in CYBER_8_RESEARCH_CAPABILITIES:
            raise ValueError(f"Unsupported cyber research capability '{capability}'.")
        grants = self.db.list_personal_persistent_grants(active_only=True, domain="software_and_security_research")
        resolved_candidate = str(Path(target).expanduser().resolve()) if Path(target).expanduser().exists() else target

        matched_grant = None
        for g in grants:
            st = g["scope_target"]
            if capability not in set(g["allowed_operations"]):
                continue
            if resolved_candidate == st or resolved_candidate.startswith(st.rstrip("/") + "/"):
                matched_grant = g
                break

        if matched_grant is None:
            return {
                "authorized": False,
                "prompt_required": True,
                "reason": "target_not_in_persistent_personal_lab_scope",
                "artificially_limit_security_knowledge": ARTIFICIALLY_LIMIT_SECURITY_KNOWLEDGE,
            }

        if self.cyber_division is not None:
            sc_auth = self.cyber_division.scope_registry.authorize_operation(target=resolved_candidate)
            if not sc_auth["authorized"]:
                return {
                    "authorized": False,
                    "prompt_required": True,
                    "reason": sc_auth.get("reason", "scope_check_failed"),
                }

        return {
            "authorized": True,
            "prompt_required": False,
            "grant_id": matched_grant["grant_id"],
            "capability": capability,
            "target": resolved_candidate,
            "artificially_limit_security_knowledge": ARTIFICIALLY_LIMIT_SECURITY_KNOWLEDGE,
        }


class LocalFirstPrivacyController:
    """Section 6: Local-by-default data, stripped credentials, minimal context & visible external transfers."""

    _INLINE_SECRET_RE = re.compile(
        r"(?im)(?:^\s*[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)\s*=\s*\S+.*$|"
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----)",
        re.DOTALL,
    )

    def __init__(
        self,
        *,
        db: Database,
        autonomy_engine: PersonalAutonomyAndCapabilityEngine,
        redactor: Redactor | None = None,
    ) -> None:
        self.db = db
        self.autonomy_engine = autonomy_engine
        self.redactor = redactor or Redactor()

    def set_project_local_only(self, project_id: str | Path, *, local_only: bool = True) -> dict[str, Any]:
        pid = str(Path(project_id).expanduser().resolve()) if isinstance(project_id, Path) or str(project_id).startswith("/") else str(project_id)
        pol = self.autonomy_engine.get_policy()
        cur = set(pol["settings"].get("local_only_projects") or [])
        if local_only:
            cur.add(pid)
        else:
            cur.discard(pid)
        updated = self.autonomy_engine.update_policy(settings_updates={"local_only_projects": sorted(cur)})
        return {"project_id": pid, "local_only": local_only, "local_only_projects": updated["settings"]["local_only_projects"]}

    def prepare_outbound_provider_context(
        self,
        *,
        provider: str,
        endpoint_host: str,
        purpose: str,
        context_text: str,
        project_path: str = "",
        included_files: list[str] | None = None,
        max_chars: int = 12_000,
    ) -> dict[str, Any]:
        proj = str(Path(project_path).expanduser().resolve()) if project_path and project_path.startswith("/") else project_path
        for fpath in included_files or []:
            low = str(fpath).replace("\\", "/").lower()
            if any(m in low for m in _CREDENTIAL_PATH_MARKERS) or "id_ed25519" in low or "id_rsa" in low or low.endswith(".env"):
                rec = self.db.record_personal_external_transfer(
                    {
                        "destination": f"{provider}:{endpoint_host}",
                        "purpose": purpose,
                        "project_id": proj,
                        "bytes_sent": 0,
                        "credentials_stripped": True,
                        "allowed": False,
                    }
                )
                return {
                    "allowed": False,
                    "reason": "private_credential_file_blocked",
                    "minimized_context": "",
                    "redacted_secrets_count": 0,
                    "expose_credentials_to_remote_models": EXPOSE_CREDENTIALS_TO_REMOTE_MODELS,
                    "expose_unrestricted_host_access_to_remote_models": EXPOSE_UNRESTRICTED_HOST_ACCESS_TO_REMOTE_MODELS,
                    "transfer_record": rec,
                }
        res = self.prepare_outbound_model_context(
            context_text,
            destination=f"{provider}:{endpoint_host}",
            purpose=purpose,
            project_id=proj,
            max_chars=max_chars,
        )
        redacted_count = 1 if res.get("sanitized_context", "") != context_text[: max(256, int(max_chars))] else 0
        return {
            **res,
            "minimized_context": res.get("sanitized_context", ""),
            "redacted_secrets_count": redacted_count,
            "expose_credentials_to_remote_models": EXPOSE_CREDENTIALS_TO_REMOTE_MODELS,
            "expose_unrestricted_host_access_to_remote_models": EXPOSE_UNRESTRICTED_HOST_ACCESS_TO_REMOTE_MODELS,
        }

    def prepare_outbound_model_context(
        self,
        raw_context: str,
        *,
        destination: str = "configured_frontier_ai_provider",
        purpose: str = "task_context",
        project_id: str = "",
        max_chars: int = 12_000,
    ) -> dict[str, Any]:
        """Section 6: Blocks local-only projects, strips credentials, minimizes context, and logs transfer visibility."""
        pol = self.autonomy_engine.get_policy()["settings"]
        local_only_set = set(pol.get("local_only_projects") or [])
        if project_id and project_id in local_only_set:
            rec = self.db.record_personal_external_transfer(
                {
                    "destination": destination,
                    "purpose": purpose,
                    "project_id": project_id,
                    "bytes_sent": 0,
                    "credentials_stripped": True,
                    "allowed": False,
                }
            )
            return {
                "allowed": False,
                "reason": f"project_configured_local_only:{project_id}",
                "sanitized_context": "",
                "transfer_record": rec,
            }

        cleaned = self._INLINE_SECRET_RE.sub("[CREDENTIAL_STRIPPED_LOCAL_PRIVACY]", raw_context)
        cleaned = self.redactor.scrub_text(cleaned)
        if pol.get("minimal_task_context_only", True):
            cleaned = cleaned[: max(256, int(max_chars))]

        encoded_len = len(cleaned.encode("utf-8"))
        rec = self.db.record_personal_external_transfer(
            {
                "destination": destination,
                "purpose": purpose,
                "project_id": project_id,
                "bytes_sent": encoded_len,
                "credentials_stripped": True,
                "allowed": True,
            }
        )
        return {
            "allowed": True,
            "local_storage_by_default": LOCAL_STORAGE_BY_DEFAULT,
            "expose_credentials_to_remote_models": EXPOSE_CREDENTIALS_TO_REMOTE_MODELS,
            "expose_unrestricted_host_access_to_remote_models": EXPOSE_UNRESTRICTED_HOST_ACCESS_TO_REMOTE_MODELS,
            "sanitized_context": cleaned,
            "bytes_prepared": encoded_len,
            "transfer_record": rec,
        }

    def inspect_external_transfers(self, *, limit: int = 100) -> dict[str, Any]:
        rows = self.db.list_personal_external_transfers(limit=limit)
        return {
            "local_storage_by_default": LOCAL_STORAGE_BY_DEFAULT,
            "transfer_count": len(rows),
            "blocked_count": sum(1 for r in rows if not r["allowed"]),
            "transfers": rows,
        }
