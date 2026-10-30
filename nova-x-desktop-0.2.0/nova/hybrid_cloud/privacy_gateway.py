"""§4 Local Tool Execution Separation & §5 Local Data & Cloud Privacy Gateway."""
from __future__ import annotations

import json
import os
import platform as py_platform
import re
import urllib.parse
from pathlib import Path
from typing import Any

from nova.db import Database
from nova.hybrid_cloud.architecture import (
    FORBIDDEN_PRIVILEGE_ESCALATION_TOOLS,
    UntrustedExternalInputValidator,
)
from nova.observability import Redactor

_SENSITIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ssh_private_key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.MULTILINE,
        ),
    ),
    (
        "api_key",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9_\-]{16,}|sk-ant-[A-Za-z0-9_\-]{16,}|AIza[0-9A-Za-z_\-]{20,}|"
            r"xai-[A-Za-z0-9_\-]{16,}|ghp_[A-Za-z0-9]{20,}|tvly-[A-Za-z0-9_\-]{16,})\b"
        ),
    ),
    (
        "sudo_credential",
        re.compile(
            r"(?i)(?:\[sudo\]\s*password\s+for\s+\S+\s*:\s*\S+|echo\s+['\"]?([^'\"\s|]+)['\"]?\s*\|\s*sudo\s+-S|"
            r"sudo_password\s*[=:]\s*['\"]?\S+['\"]?)"
        ),
    ),
    (
        "password_assignment",
        re.compile(r"(?i)\b(?:password|passwd|passphrase|secret_key|access_token)\s*[=:]\s*['\"]?([^\s'\",;]{4,})['\"]?"),
    ),
    (
        "session_cookie",
        re.compile(
            r"(?i)(?:\b(?:Cookie|Set-Cookie)\s*:\s*[^\r\n]+|\b(?:nova_session|sessionid|connect\.sid|auth_session)\s*=\s*[A-Za-z0-9._\-]{8,})"
        ),
    ),
)

_FORBIDDEN_PRIVATE_FILE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:^|/)\.env(?:\..+)?$", re.IGNORECASE),
    re.compile(r"(?:^|/)\.ssh(?:/|$)", re.IGNORECASE),
    re.compile(r"(?:^|/)id_(?:rsa|ed25519|ecdsa|dsa)(?:\.pem)?$", re.IGNORECASE),
    re.compile(r"(?:^|/)\.gnupg(?:/|$)", re.IGNORECASE),
    re.compile(r"(?:^|/)etc/(?:shadow|gshadow|sudoers)(?:$|\.)", re.IGNORECASE),
    re.compile(r"(?:^|/)nova_vault(?:/|$)", re.IGNORECASE),
    re.compile(r"\.(?:pem|key|p12|pfx|kdbx)$", re.IGNORECASE),
)

_SENSITIVE_FILE_APPROVAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:^|/)(?:config|credentials|secrets|auth|tokens)\b", re.IGNORECASE),
    re.compile(r"\.(?:conf|ini|sqlite|sqlite3|db)$", re.IGNORECASE),
)


class CloudPrivacyGateway:
    """§5 Enforces context minimization, secret redaction, provider policies, local-only projects & audit ledger."""

    SILENT_LARGER_PAYLOAD_FALLBACK_ALLOWED = False

    def __init__(self, db: Database, redactor: Redactor | None = None):
        self.db = db
        self.redactor = redactor or Redactor()
        self._task_baseline_payload_chars: dict[str, int] = {}

    def get_effective_provider_policy(self, provider_type: str) -> dict[str, Any]:
        ptype = provider_type.strip().lower()
        stored = self.db.get_provider_privacy_policy(ptype)
        if stored is not None:
            return stored
        is_local = ptype in {"ollama", "llama_cpp"}
        return {
            "provider_type": ptype,
            "enabled": True,
            "max_payload_chars": 64000 if is_local else 24000,
            "allow_diagnostic_context": True,
            "allow_file_excerpts": True,
            "require_sensitive_transfer_approval": not is_local,
            "allowed_categories": ["prompt", "diagnostics", "workspace_excerpt"],
        }

    def set_provider_policy(self, policy: dict[str, Any]) -> dict[str, Any]:
        return self.db.upsert_provider_privacy_policy(policy)

    def set_project_local_only(
        self,
        project_key: str,
        *,
        project_path: str = "",
        local_only: bool = True,
        allow_quantized_local_fallback: bool = True,
        reason: str = "",
    ) -> dict[str, Any]:
        return self.db.upsert_local_only_project(
            {
                "project_key": project_key,
                "project_path": project_path or project_key,
                "local_only": local_only,
                "allow_quantized_local_fallback": allow_quantized_local_fallback,
                "reason": reason,
            }
        )

    def is_project_local_only(self, project_key: str = "", included_files: list[str] | None = None) -> dict[str, Any] | None:
        if project_key:
            rec = self.db.get_local_only_project(project_key)
            if rec and rec.get("local_only"):
                return rec
        files = included_files or []
        if files:
            for item in self.db.list_local_only_projects():
                if not item.get("local_only"):
                    continue
                ppath = str(item.get("project_path") or "").rstrip("/")
                if ppath and any(str(f).startswith(ppath) for f in files):
                    return item
        return None

    def redact_sensitive_text(self, text: str) -> tuple[str, list[str]]:
        if not text:
            return "", []
        detected: list[str] = []
        current = text
        for category, pattern in _SENSITIVE_PATTERNS:
            if pattern.search(current):
                detected.append(category)
                current = pattern.sub(f"[REDACTED:{category.upper()}]", current)
        scrubbed = str(self.redactor.scrub(current, max_chars=0))
        if scrubbed != current and "redactor_secret" not in detected:
            detected.append("redactor_secret")
        return scrubbed, detected

    def inspect_and_prepare_outbound(
        self,
        *,
        provider_type: str,
        model_id: str,
        base_url: str,
        messages: list[dict[str, Any]],
        task_id: str = "",
        project_key: str = "",
        included_files: list[str] | None = None,
        included_categories: list[str] | None = None,
        task_allowed_files: list[str] | None = None,
        sensitive_transfer_approved: bool = False,
        is_fallback: bool = False,
        local_task_failed: bool = False,
    ) -> dict[str, Any]:
        """Validate, minimize, redact, and log an outbound model request before any network transmission."""
        ptype = provider_type.strip().lower()
        is_local_runtime = ptype in {"ollama", "llama_cpp"}
        endpoint_host = (urllib.parse.urlsplit(base_url.strip()).hostname or "").lower()
        files = [str(f) for f in (included_files or []) if str(f).strip()]
        categories = list(dict.fromkeys([str(c) for c in (included_categories or ["prompt"]) if str(c).strip()]))
        policy = self.get_effective_provider_policy(ptype)

        # 1. Local-only project enforcement (§5)
        local_project = self.is_project_local_only(project_key, files)
        if local_project is not None and not is_local_runtime:
            return self._record_and_return(
                task_id=task_id,
                provider_type=ptype,
                model_id=model_id,
                endpoint_host=endpoint_host,
                decision="blocked",
                payload_chars=0,
                redacted_count=0,
                included_files=files,
                included_categories=categories,
                reason=f"project_local_only:{local_project['project_key']}",
                sanitized_messages=[],
            )

        # 2. Provider privacy policy enabled check (§5)
        if not policy.get("enabled", True):
            return self._record_and_return(
                task_id=task_id,
                provider_type=ptype,
                model_id=model_id,
                endpoint_host=endpoint_host,
                decision="blocked",
                payload_chars=0,
                redacted_count=0,
                included_files=files,
                included_categories=categories,
                reason="provider_disabled_by_privacy_policy",
                sanitized_messages=[],
            )

        # 3. Forbidden private credential files & unrelated files check (§5)
        for fpath in files:
            norm = fpath.replace("\\", "/")
            if any(pat.search(norm) for pat in _FORBIDDEN_PRIVATE_FILE_PATTERNS):
                return self._record_and_return(
                    task_id=task_id,
                    provider_type=ptype,
                    model_id=model_id,
                    endpoint_host=endpoint_host,
                    decision="blocked",
                    payload_chars=0,
                    redacted_count=0,
                    included_files=files,
                    included_categories=categories,
                    reason=f"forbidden_private_credential_file:{Path(norm).name}",
                    sanitized_messages=[],
                )
            if task_allowed_files is not None and fpath not in task_allowed_files:
                return self._record_and_return(
                    task_id=task_id,
                    provider_type=ptype,
                    model_id=model_id,
                    endpoint_host=endpoint_host,
                    decision="blocked",
                    payload_chars=0,
                    redacted_count=0,
                    included_files=files,
                    included_categories=categories,
                    reason=f"unrelated_file_excluded_by_task_scope:{Path(norm).name}",
                    sanitized_messages=[],
                )
            if (
                not is_local_runtime
                and policy.get("require_sensitive_transfer_approval", True)
                and not sensitive_transfer_approved
                and any(pat.search(norm) for pat in _SENSITIVE_FILE_APPROVAL_PATTERNS)
            ):
                return self._record_and_return(
                    task_id=task_id,
                    provider_type=ptype,
                    model_id=model_id,
                    endpoint_host=endpoint_host,
                    decision="approval_required",
                    payload_chars=0,
                    redacted_count=0,
                    included_files=files,
                    included_categories=categories,
                    reason=f"sensitive_file_transfer_requires_approval:{Path(norm).name}",
                    sanitized_messages=[],
                )

        # 4. Category policy check (§5)
        if not policy.get("allow_diagnostic_context", True) and "diagnostics" in categories and not is_local_runtime:
            return self._record_and_return(
                task_id=task_id,
                provider_type=ptype,
                model_id=model_id,
                endpoint_host=endpoint_host,
                decision="blocked",
                payload_chars=0,
                redacted_count=0,
                included_files=files,
                included_categories=categories,
                reason="diagnostic_context_disallowed_for_provider",
                sanitized_messages=[],
            )
        if not policy.get("allow_file_excerpts", True) and (files or "workspace_excerpt" in categories) and not is_local_runtime:
            return self._record_and_return(
                task_id=task_id,
                provider_type=ptype,
                model_id=model_id,
                endpoint_host=endpoint_host,
                decision="blocked",
                payload_chars=0,
                redacted_count=0,
                included_files=files,
                included_categories=categories,
                reason="file_excerpts_disallowed_for_provider",
                sanitized_messages=[],
            )

        # 5. Sensitive-data detection, credential redaction & context minimization (§5)
        max_chars = int(policy.get("max_payload_chars") or 24000)
        redacted_categories: list[str] = []
        sanitized_messages: list[dict[str, Any]] = []
        remaining_budget = max_chars
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            cleaned_msg = dict(msg)
            raw_content = cleaned_msg.get("content")
            if isinstance(raw_content, str):
                scrubbed_text, hits = self.redact_sensitive_text(raw_content)
                redacted_categories.extend(hits)
                if len(scrubbed_text) > remaining_budget:
                    scrubbed_text = scrubbed_text[: max(0, remaining_budget)]
                remaining_budget = max(0, remaining_budget - len(scrubbed_text))
                cleaned_msg["content"] = scrubbed_text
            sanitized_messages.append(cleaned_msg)

        payload_chars = sum(len(str(m.get("content") or "")) for m in sanitized_messages)

        # 6. Anti-payload-escalation fallback guard (§5: "A failed local task must never silently route
        #    a larger data payload to another cloud provider.")
        if (is_fallback or local_task_failed) and not is_local_runtime:
            if local_task_failed and task_id not in self._task_baseline_payload_chars:
                return self._record_and_return(
                    task_id=task_id,
                    provider_type=ptype,
                    model_id=model_id,
                    endpoint_host=endpoint_host,
                    decision="blocked",
                    payload_chars=payload_chars,
                    redacted_count=len(redacted_categories),
                    included_files=files,
                    included_categories=categories,
                    reason="failed_local_task_cannot_silently_escalate_to_cloud_provider",
                    sanitized_messages=[],
                )
            baseline = self._task_baseline_payload_chars.get(task_id)
            if baseline is not None and payload_chars > baseline:
                return self._record_and_return(
                    task_id=task_id,
                    provider_type=ptype,
                    model_id=model_id,
                    endpoint_host=endpoint_host,
                    decision="blocked",
                    payload_chars=payload_chars,
                    redacted_count=len(redacted_categories),
                    included_files=files,
                    included_categories=categories,
                    reason=f"larger_fallback_payload_blocked:{payload_chars}>{baseline}",
                    sanitized_messages=[],
                )
        elif task_id and task_id not in self._task_baseline_payload_chars:
            self._task_baseline_payload_chars[task_id] = payload_chars

        return self._record_and_return(
            task_id=task_id,
            provider_type=ptype,
            model_id=model_id,
            endpoint_host=endpoint_host,
            decision="permitted",
            payload_chars=payload_chars,
            redacted_count=len(redacted_categories),
            included_files=files,
            included_categories=categories,
            reason="context_minimized_and_redacted" if redacted_categories else "clean_minimized_context",
            sanitized_messages=sanitized_messages,
            redacted_categories=sorted(set(redacted_categories)),
        )

    def register_local_task_baseline(self, task_id: str, payload_chars: int = 0) -> None:
        """Record baseline outbound allowance (0 for strictly local tasks) to block silent cloud payload escalation."""
        if task_id:
            self._task_baseline_payload_chars[task_id] = max(0, int(payload_chars))

    def _record_and_return(
        self,
        *,
        task_id: str,
        provider_type: str,
        model_id: str,
        endpoint_host: str,
        decision: str,
        payload_chars: int,
        redacted_count: int,
        included_files: list[str],
        included_categories: list[str],
        reason: str,
        sanitized_messages: list[dict[str, Any]],
        redacted_categories: list[str] | None = None,
    ) -> dict[str, Any]:
        ledger_entry = self.db.record_cloud_transmission(
            {
                "task_id": task_id,
                "provider_type": provider_type,
                "model_id": model_id,
                "endpoint_host": endpoint_host,
                "decision": decision,
                "payload_chars": payload_chars,
                "redacted_items_count": redacted_count,
                "included_files": included_files,
                "included_categories": included_categories,
                "reason": reason,
            }
        )
        return {
            "permitted": decision == "permitted",
            "decision": decision,
            "reason": reason,
            "payload_chars": payload_chars,
            "redacted_items_count": redacted_count,
            "redacted_categories": redacted_categories or [],
            "included_files": included_files,
            "included_categories": included_categories,
            "sanitized_messages": sanitized_messages,
            "ledger_entry": ledger_entry,
        }


class KaliLocalCloudDiagnosticCoordinator:
    """§4 Strict separation between Cloud Frontier Reasoning and Local Kali Tool Execution."""

    WORKFLOW_STEPS: tuple[str, ...] = (
        "1_receive_objective",
        "2_collect_local_diagnostics",
        "3_privacy_gateway_filter",
        "4_cloud_model_proposes",
        "5_local_permission_validation",
        "6_local_authorized_execution",
        "7_return_sanitized_output",
        "8_local_outcome_verification",
    )

    def __init__(
        self,
        *,
        db: Database,
        privacy_gateway: CloudPrivacyGateway,
        tool_registry: Any,
        autonomy_policy: Any,
        validator: UntrustedExternalInputValidator | None = None,
    ):
        self.db = db
        self.privacy_gateway = privacy_gateway
        self.tool_registry = tool_registry
        self.autonomy_policy = autonomy_policy
        self.validator = validator or UntrustedExternalInputValidator()

    def collect_local_kali_diagnostics(self, workspace_dir: Path | None = None) -> dict[str, Any]:
        """Collect read-only local host evidence without invoking any cloud service."""
        uname = py_platform.uname()
        mem_available_mb = 0
        try:
            with open("/proc/meminfo", encoding="utf-8") as mf:
                for line in mf:
                    if line.startswith("MemAvailable:"):
                        mem_available_mb = int(line.split()[1]) // 1024
                        break
        except OSError:
            pass
        net_ifaces: list[str] = []
        net_root = Path("/sys/class/net")
        if net_root.is_dir():
            net_ifaces = sorted(p.name for p in net_root.iterdir() if not p.name.startswith("."))
        return {
            "system": uname.system,
            "release": uname.release,
            "machine": uname.machine,
            "mem_available_mb": mem_available_mb,
            "network_interfaces": net_ifaces[:16],
            "effective_uid": os.geteuid() if hasattr(os, "geteuid") else 1000,
            "workspace_exists": bool(workspace_dir and workspace_dir.exists()),
        }

    async def execute_separated_workflow(
        self,
        *,
        objective: str,
        cloud_proposer: Any,
        provider_type: str = "openai",
        model_id: str = "dynamic-frontier-model",
        base_url: str = "https://api.openai.com/v1",
        task_id: str = "",
        project_key: str = "",
        workspace_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Execute the 8-step §4 Kali diagnostic / tool workflow with strict cloud/local separation."""
        trace: list[dict[str, Any]] = [{"step": "1_receive_objective", "objective": objective[:400]}]
        diagnostics = self.collect_local_kali_diagnostics(workspace_dir)
        trace.append({"step": "2_collect_local_diagnostics", "local_evidence_keys": sorted(diagnostics.keys())})

        outbound_messages = [
            {
                "role": "system",
                "content": (
                    "You are a cloud frontier reasoning model assisting a locally hosted Kali Linux platform. "
                    "Propose structured tool calls only; local permission gates govern all execution."
                ),
            },
            {
                "role": "user",
                "content": f"Objective: {objective}\nLocal diagnostics: {json.dumps(diagnostics, sort_keys=True)}",
            },
        ]
        gate = self.privacy_gateway.inspect_and_prepare_outbound(
            provider_type=provider_type,
            model_id=model_id,
            base_url=base_url,
            messages=outbound_messages,
            task_id=task_id,
            project_key=project_key,
            included_categories=["prompt", "diagnostics"],
        )
        trace.append(
            {
                "step": "3_privacy_gateway_filter",
                "permitted": gate["permitted"],
                "decision": gate["decision"],
                "reason": gate["reason"],
                "payload_chars": gate["payload_chars"],
            }
        )
        if not gate["permitted"]:
            return {
                "ok": False,
                "status": gate["decision"],
                "reason": gate["reason"],
                "steps": trace,
                "cloud_direct_access": False,
            }

        raw_proposal = await cloud_proposer(gate["sanitized_messages"])
        raw_message = raw_proposal.get("message") if isinstance(raw_proposal, dict) else {}
        validated = self.validator.validate_model_message(raw_message if isinstance(raw_message, dict) else {})
        sanitized_msg = validated["sanitized_message"]
        proposed_calls = sanitized_msg.get("tool_calls") or []
        trace.append(
            {
                "step": "4_cloud_model_proposes",
                "proposed_tool_count": len(proposed_calls),
                "blocked_untrusted_calls": validated["blocked_tool_calls"],
            }
        )

        permission_decisions: list[dict[str, Any]] = []
        executed_results: list[dict[str, Any]] = []
        for call in proposed_calls:
            fn = call.get("function") or {}
            tool_name = str(fn.get("name") or "")
            args = json.loads(fn.get("arguments") or "{}")
            if tool_name in FORBIDDEN_PRIVILEGE_ESCALATION_TOOLS:
                permission_decisions.append({"tool": tool_name, "action": "deny", "rule": "security_boundary"})
                continue
            if self.tool_registry.get(tool_name) is None:
                permission_decisions.append({"tool": tool_name, "action": "deny", "rule": "unregistered_tool"})
                continue
            decision = self.autonomy_policy.decide(tool_name, args)
            permission_decisions.append({"tool": tool_name, **decision})
            if decision.get("action") == "allow":
                outcome = await self.tool_registry.execute(tool_name, args, approved=bool(decision.get("approved")))
                is_ok = outcome.status in {"success", "completed"}
                scrubbed_summary, _ = self.privacy_gateway.redact_sensitive_text(outcome.summary)
                executed_results.append(
                    {
                        "tool": tool_name,
                        "ok": is_ok,
                        "status": outcome.status,
                        "summary": scrubbed_summary,
                        "data": self.privacy_gateway.redactor.scrub(outcome.data, max_chars=0),
                    }
                )

        trace.append({"step": "5_local_permission_validation", "decisions": permission_decisions})
        trace.append({"step": "6_local_authorized_execution", "executed_count": len(executed_results)})
        trace.append(
            {
                "step": "7_return_sanitized_output",
                "outputs_scrubbed": True,
                "result_count": len(executed_results),
            }
        )

        all_succeeded = all(r["ok"] for r in executed_results) and len(validated["blocked_tool_calls"]) == 0
        verification = {
            "verified": all_succeeded,
            "executed_tools": [r["tool"] for r in executed_results],
            "blocked_privilege_attempts": len(validated["blocked_tool_calls"]),
            "pending_approvals": [d["tool"] for d in permission_decisions if d.get("action") == "approval_required"],
        }
        trace.append({"step": "8_local_outcome_verification", **verification})
        self.db.add_privileged_audit(
            {
                "operation": "hybrid.separated_execution",
                "target": task_id or provider_type,
                "requester": "kali_separator",
                "authorized": all_succeeded,
                "auth_mechanism": "autonomy_policy",
                "status": "completed" if all_succeeded else "gated_or_blocked",
                "detail": json.dumps(
                    {
                        "provider_type": provider_type,
                        "executed_tools": verification["executed_tools"],
                        "blocked_privilege_attempts": verification["blocked_privilege_attempts"],
                    }
                ),
            }
        )
        return {
            "ok": all_succeeded,
            "status": "completed" if all_succeeded else "gated_or_blocked",
            "cloud_direct_access": False,
            "diagnostics": diagnostics,
            "model_response": str(sanitized_msg.get("content") or ""),
            "permission_decisions": permission_decisions,
            "executed_results": executed_results,
            "verification": verification,
            "steps": trace,
        }
