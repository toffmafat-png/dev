"""§152 Privilege and System-Access Architecture.

Splits execution cleanly into:
1. Unprivileged Desktop/Runtime Client (`PrivilegedHelperClient`) running under
   the logged-in account.
2. Narrowly Scoped Privileged System Helper (`PrivilegedSystemHelper`) exposing
   only a fixed allowlist of validated administrative operations mediated via
   Polkit (`pkexec`) and persistent operator-configured scoped rules.

Hard security invariants:
- `RUN_ENTIRE_APP_AS_ROOT = False`
- `PLAINTEXT_SUDO_PASSWORD_STORAGE = False`
- `MODEL_INSTRUCTION_SUFFICIENT_FOR_ADMIN = False`
- `EXPOSE_ADMIN_CREDENTIALS_TO_MODELS = False`
"""
from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from nova.db import Database
from nova.observability import Redactor

RUN_ENTIRE_APP_AS_ROOT = False
PLAINTEXT_SUDO_PASSWORD_STORAGE = False
MODEL_INSTRUCTION_SUFFICIENT_FOR_ADMIN = False
EXPOSE_ADMIN_CREDENTIALS_TO_MODELS = False

_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:@/-]{1,120}$")
_SAFE_IFACE_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_SAFE_MOD_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SAFE_PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]{1,80}$")


@dataclass(frozen=True)
class HelperOperationSpec:
    operation: str
    description: str
    min_privilege: str
    risk_level: str
    reversible: bool
    recovery_hint: str


DEFINED_HELPER_OPERATIONS: dict[str, HelperOperationSpec] = {
    "kernel.read_dmesg": HelperOperationSpec(
        operation="kernel.read_dmesg",
        description="Read kernel ring buffer diagnostics when kernel.dmesg_restrict=1.",
        min_privilege="cap_syslog / adm",
        risk_level="low",
        reversible=True,
        recovery_hint="Read-only diagnostic operation.",
    ),
    "driver.modprobe_load": HelperOperationSpec(
        operation="driver.modprobe_load",
        description="Load a validated Linux kernel module via modprobe.",
        min_privilege="cap_sys_module / polkit",
        risk_level="medium",
        reversible=True,
        recovery_hint="Unload module with `modprobe -r <module>` if device regresses.",
    ),
    "driver.modprobe_unload": HelperOperationSpec(
        operation="driver.modprobe_unload",
        description="Unload a non-critical Linux kernel module via modprobe -r.",
        min_privilege="cap_sys_module / polkit",
        risk_level="medium",
        reversible=True,
        recovery_hint="Reload module with `modprobe <module>`.",
    ),
    "package.apt_install_firmware": HelperOperationSpec(
        operation="package.apt_install_firmware",
        description="Install an approved Debian/Kali firmware or driver package.",
        min_privilege="root via polkit pkexec",
        risk_level="high",
        reversible=True,
        recovery_hint="Remove package via `apt-get remove <pkg>` and restore initramfs backup.",
    ),
    "service.systemctl_restart": HelperOperationSpec(
        operation="service.systemctl_restart",
        description="Restart a named system service unit.",
        min_privilege="polkit org.freedesktop.systemd1.manage-units",
        risk_level="medium",
        reversible=True,
        recovery_hint="Inspect `systemctl status <unit>` and revert unit override if needed.",
    ),
    "network.interface_toggle": HelperOperationSpec(
        operation="network.interface_toggle",
        description="Bring a non-primary network interface up or down via ip link.",
        min_privilege="cap_net_admin / polkit",
        risk_level="high",
        reversible=True,
        recovery_hint="Restore link state via `ip link set <iface> up`.",
    ),
}


class PrivilegedSystemHelper:
    """Narrowly scoped privileged operation validator, Polkit mediator, and auditor."""

    def __init__(self, *, db: Database, redactor: Redactor) -> None:
        self.db = db
        self.redactor = redactor

    def capabilities(self) -> dict[str, Any]:
        pkexec_path = shutil.which("pkexec") or ""
        return {
            "pkexec_available": bool(pkexec_path),
            "pkexec_path": pkexec_path,
            "running_as_root": bool(hasattr(os, "geteuid") and os.geteuid() == 0),
            "run_entire_app_as_root": RUN_ENTIRE_APP_AS_ROOT,
            "plaintext_sudo_password_storage": PLAINTEXT_SUDO_PASSWORD_STORAGE,
            "model_instruction_sufficient_for_admin": MODEL_INSTRUCTION_SUFFICIENT_FOR_ADMIN,
            "defined_operations": [
                {
                    "operation": spec.operation,
                    "description": spec.description,
                    "min_privilege": spec.min_privilege,
                    "risk_level": spec.risk_level,
                    "reversible": spec.reversible,
                    "recovery_hint": spec.recovery_hint,
                }
                for spec in DEFINED_HELPER_OPERATIONS.values()
            ],
        }

    def validate_request(self, operation: str, params: dict[str, Any]) -> tuple[bool, str, list[str], str]:
        """Validate operation name, target scope, and exact argv without shell expansion."""
        spec = DEFINED_HELPER_OPERATIONS.get(operation)
        if spec is None:
            return False, "", [], f"Operation '{operation}' is not in the privileged helper allowlist."

        if operation == "kernel.read_dmesg":
            dmesg_bin = shutil.which("dmesg") or "/usr/bin/dmesg"
            return True, "dmesg", [dmesg_bin, "--ctime", "--nopager"], ""

        if operation in {"driver.modprobe_load", "driver.modprobe_unload"}:
            mod = str(params.get("module") or "").strip()
            if not _SAFE_MOD_RE.match(mod) or ".." in mod:
                return False, mod, [], "Invalid kernel module identifier."
            modprobe_bin = shutil.which("modprobe") or "/usr/sbin/modprobe"
            argv = [modprobe_bin, mod] if operation == "driver.modprobe_load" else [modprobe_bin, "-r", mod]
            return True, mod, argv, ""

        if operation == "package.apt_install_firmware":
            pkg = str(params.get("package") or "").strip()
            if not _SAFE_PKG_RE.match(pkg):
                return False, pkg, [], "Invalid Debian/Kali package name."
            apt_bin = shutil.which("apt-get") or "/usr/bin/apt-get"
            return True, pkg, [apt_bin, "install", "-y", "--no-install-recommends", pkg], ""

        if operation == "service.systemctl_restart":
            unit = str(params.get("unit") or "").strip()
            if not _SAFE_TOKEN_RE.match(unit) or "/" in unit or not unit.endswith(".service"):
                return False, unit, [], "Service target must be a valid `<name>.service` unit."
            sys_bin = shutil.which("systemctl") or "/usr/bin/systemctl"
            return True, unit, [sys_bin, "restart", unit], ""

        if operation == "network.interface_toggle":
            iface = str(params.get("interface") or "").strip()
            state = str(params.get("state") or "").strip().lower()
            if not _SAFE_IFACE_RE.match(iface) or state not in {"up", "down"}:
                return False, iface, [], "Invalid network interface or target state (`up`/`down`)."
            ip_bin = shutil.which("ip") or "/usr/sbin/ip"
            return True, f"{iface}:{state}", [ip_bin, "link", "set", "dev", iface, state], ""

        return False, "", [], "Unhandled operation."

    def check_authorization(
        self,
        operation: str,
        target: str,
        *,
        requester: str,
        operator_approved: bool,
    ) -> dict[str, Any]:
        """Independently check authorization; AI model proposals alone are NEVER sufficient."""
        if operation not in DEFINED_HELPER_OPERATIONS:
            return {"authorized": False, "mechanism": "unknown_operation", "reason": "Undefined helper operation."}

        # Check persistent narrowly scoped operator policies first.
        policies = self.db.list_privileged_policies()
        matched_policy = None
        for pol in policies:
            if not pol.get("enabled"):
                continue
            if pol["operation"] == operation and fnmatch.fnmatch(target or "*", pol["scope_pattern"]):
                matched_policy = pol
                break

        if requester == "ai_model" and not operator_approved:
            if matched_policy and matched_policy.get("allow_without_prompt"):
                return {
                    "authorized": True,
                    "mechanism": "scoped_persistent_policy",
                    "policy_id": matched_policy["id"],
                    "reason": f"Matched trusted scoped policy '{matched_policy['scope_pattern']}'.",
                }
            return {
                "authorized": False,
                "mechanism": "model_proposal_rejected",
                "reason": "Model-originated instruction is insufficient for administrative execution without explicit operator approval or a narrow pre-authorized policy.",
            }

        if operator_approved:
            return {
                "authorized": True,
                "mechanism": "polkit_or_operator_approval",
                "policy_id": matched_policy["id"] if matched_policy else "",
                "reason": "Explicitly approved by operator; mediated via Polkit when elevation is required.",
            }

        if matched_policy and matched_policy.get("allow_without_prompt"):
            return {
                "authorized": True,
                "mechanism": "scoped_persistent_policy",
                "policy_id": matched_policy["id"],
                "reason": f"Matched trusted scoped policy '{matched_policy['scope_pattern']}'.",
            }

        return {
            "authorized": False,
            "mechanism": "approval_required",
            "reason": f"Administrative operation '{operation}' on '{target}' requires explicit operator approval and Polkit authentication.",
        }

    def execute_request(
        self,
        operation: str,
        params: dict[str, Any],
        *,
        requester: str = "user_ui",
        operator_approved: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        valid, target, argv, err = self.validate_request(operation, params)
        if not valid:
            audit = self.db.add_privileged_audit(
                {
                    "operation": operation,
                    "target": target,
                    "requester": requester,
                    "authorized": False,
                    "auth_mechanism": "validation_failed",
                    "dry_run": dry_run,
                    "status": "rejected_malformed",
                    "detail": err,
                }
            )
            return {"ok": False, "status": "rejected_malformed", "reason": err, "audit_id": audit["id"]}

        auth = self.check_authorization(operation, target, requester=requester, operator_approved=operator_approved)
        if not auth["authorized"]:
            audit = self.db.add_privileged_audit(
                {
                    "operation": operation,
                    "target": target,
                    "requester": requester,
                    "authorized": False,
                    "auth_mechanism": auth["mechanism"],
                    "dry_run": dry_run,
                    "status": "denied",
                    "detail": auth["reason"],
                }
            )
            return {
                "ok": False,
                "status": "approval_required" if auth["mechanism"] == "approval_required" else "denied",
                "reason": auth["reason"],
                "auth_mechanism": auth["mechanism"],
                "audit_id": audit["id"],
            }

        spec = DEFINED_HELPER_OPERATIONS[operation]
        pkexec = shutil.which("pkexec")
        planned_argv = ([pkexec, *argv] if pkexec and os.geteuid() != 0 else argv)

        if dry_run:
            audit = self.db.add_privileged_audit(
                {
                    "operation": operation,
                    "target": target,
                    "requester": requester,
                    "authorized": True,
                    "auth_mechanism": auth["mechanism"],
                    "dry_run": True,
                    "status": "dry_run_ok",
                    "detail": f"Preview argv: {' '.join(planned_argv)}",
                }
            )
            return {
                "ok": True,
                "status": "dry_run_ok",
                "dry_run": True,
                "planned_argv": planned_argv,
                "risk_level": spec.risk_level,
                "recovery_hint": spec.recovery_hint,
                "auth_mechanism": auth["mechanism"],
                "audit_id": audit["id"],
            }

        if os.geteuid() != 0 and not pkexec:
            detail = "Polkit `pkexec` is not installed in this environment; refusing to bypass Linux authentication or prompt for plaintext sudo passwords."
            audit = self.db.add_privileged_audit(
                {
                    "operation": operation,
                    "target": target,
                    "requester": requester,
                    "authorized": True,
                    "auth_mechanism": auth["mechanism"],
                    "dry_run": False,
                    "status": "polkit_unavailable",
                    "detail": detail,
                }
            )
            return {
                "ok": False,
                "status": "polkit_unavailable",
                "reason": detail,
                "planned_argv": argv,
                "audit_id": audit["id"],
            }

        try:
            proc = subprocess.run(
                planned_argv,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            msg = self.redactor.scrub_text(str(exc), max_chars=240)
            audit = self.db.add_privileged_audit(
                {
                    "operation": operation,
                    "target": target,
                    "requester": requester,
                    "authorized": True,
                    "auth_mechanism": auth["mechanism"],
                    "dry_run": False,
                    "status": "execution_error",
                    "detail": msg,
                }
            )
            return {"ok": False, "status": "execution_error", "reason": msg, "audit_id": audit["id"]}

        ok = proc.returncode == 0
        out_clean = self.redactor.scrub_text((proc.stdout or "").strip(), max_chars=2000)
        err_clean = self.redactor.scrub_text((proc.stderr or "").strip(), max_chars=600)
        audit = self.db.add_privileged_audit(
            {
                "operation": operation,
                "target": target,
                "requester": requester,
                "authorized": True,
                "auth_mechanism": auth["mechanism"],
                "dry_run": False,
                "status": "succeeded" if ok else "failed",
                "detail": (err_clean or out_clean or f"exit_code={proc.returncode}")[:300],
            }
        )
        return {
            "ok": ok,
            "status": "succeeded" if ok else "failed",
            "exit_code": proc.returncode,
            "stdout": out_clean,
            "stderr": err_clean,
            "audit_id": audit["id"],
        }


class PrivilegedHelperClient:
    """Desktop-side unprivileged client mediating requests to `PrivilegedSystemHelper`."""

    def __init__(self, helper: PrivilegedSystemHelper) -> None:
        self._helper = helper

    def status(self) -> dict[str, Any]:
        return {
            **self._helper.capabilities(),
            "policies": self._helper.db.list_privileged_policies(),
            "recent_audit": self._helper.db.list_privileged_audit(limit=25),
        }

    def configure_trusted_policy(
        self,
        operation: str,
        scope_pattern: str,
        *,
        allow_without_prompt: bool = True,
        enabled: bool = True,
        notes: str = "",
    ) -> dict[str, Any]:
        if operation not in DEFINED_HELPER_OPERATIONS:
            raise ValueError(f"Unknown helper operation '{operation}'.")
        if not scope_pattern.strip() or ".." in scope_pattern:
            raise ValueError("Invalid scope pattern.")
        return self._helper.db.upsert_privileged_policy(
            operation,
            scope_pattern.strip(),
            enabled=enabled,
            allow_without_prompt=allow_without_prompt,
            notes=notes,
        )

    def request(
        self,
        operation: str,
        params: dict[str, Any],
        *,
        requester: str = "user_ui",
        operator_approved: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        return self._helper.execute_request(
            operation,
            params,
            requester=requester,
            operator_approved=operator_approved,
            dry_run=dry_run,
        )
