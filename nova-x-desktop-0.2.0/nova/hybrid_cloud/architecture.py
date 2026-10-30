"""§1, §7, §10 & §11 Hybrid Local-Hosted + Cloud-Frontier Architecture Contract & Security Boundaries."""
from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from nova.model_providers import (
    MAX_AUTOMATIC_LOCAL_FALLBACK_PARAMS_B,
    PROVIDER_CATALOG,
    check_local_model_resource_fit,
)

LOCAL_HOSTED_COMPONENTS: tuple[str, ...] = (
    "native_desktop_application",
    "agent_orchestration_engine",
    "task_planner",
    "persistent_memory_and_knowledge_base",
    "file_management",
    "local_command_execution",
    "hardware_and_driver_integration",
    "application_control",
    "screen_capture_and_authorized_desktop_automation",
    "background_task_workers",
    "system_diagnostics",
    "workflow_engine",
    "security_and_permission_management",
    "project_development_environment",
    "logs_history_and_checkpoints",
)

CLOUD_INTELLIGENCE_COMPONENTS: tuple[str, ...] = (
    "frontier_ai_inference",
    "complex_reasoning",
    "specialist_model_collaboration",
    "coding_intelligence",
    "research_and_analysis",
    "multimodal_processing_when_configured",
    "cloud_model_upgrades",
    "optional_specialist_inference",
)

HYBRID_INVARIANTS: dict[str, bool] = {
    "local_hosts_complete_desktop_and_backend": True,
    "cloud_provides_frontier_intelligence_only": True,
    "cloud_hosts_application": False,
    "cloud_stores_task_database": False,
    "cloud_replaces_native_desktop": False,
    "huggingface_spaces_deployment": False,
    "externally_hosted_primary_web_runtime": False,
    "single_ai_provider_lock_in": False,
    "run_whole_application_as_root": False,
    "cloud_model_can_modify_permissions": False,
    "cloud_model_can_read_secret_stores": False,
    "cloud_model_can_disable_local_authorization": False,
    "auto_run_enormous_local_models": False,
    "silent_larger_payload_cloud_fallback": False,
    "false_cloud_completion_when_offline": False,
    "competing_execution_engines": False,
}

FORBIDDEN_PRIVILEGE_ESCALATION_TOOLS: frozenset[str] = frozenset(
    {
        "autonomy.modify_policy",
        "autonomy.disable",
        "permissions.grant_self",
        "permissions.override",
        "secrets.read_raw",
        "secrets.export_all",
        "vault.dump_secrets",
        "system.root_shell",
        "security.disable_authorization",
    }
)

_PRIVILEGE_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "self_permission_mutation",
        re.compile(
            r"\b(?:set\s+autonomy[_\s-]*level\s*=\s*['\"]?high|disable\s+local\s+authorization|"
            r"override\s+autonomy\s+policy|grant\s+unrestricted\s+privileges)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "secret_store_exfiltration",
        re.compile(
            r"\b(?:dump\s+org\.nova-x\.desktop|read\s+/etc/shadow|cat\s+~/.ssh/id_(?:rsa|ed25519)|"
            r"export\s+all\s+secret[_\s-]*keys)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "unrestricted_root_escalation",
        re.compile(
            r"\b(?:chmod\s+[+0-7]*s\s+/bin/(?:ba)?sh|NOPASSWD:\s*ALL|echo\s+\S+\s*\|\s*sudo\s+-S)\b",
            re.IGNORECASE,
        ),
    ),
)


class UntrustedExternalInputValidator:
    """§10 Treats all model responses, tool results, documents, webpages, and downloads as untrusted input."""

    MAX_CONTENT_CHARS = 120_000
    MAX_TOOL_CALLS_PER_TURN = 16

    def validate_model_message(self, message: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(message, dict):
            return {
                "valid": False,
                "blocked": True,
                "violations": ["non_dict_model_message"],
                "sanitized_message": {"role": "assistant", "content": ""},
            }
        violations: list[str] = []
        content = str(message.get("content") or "")
        if len(content) > self.MAX_CONTENT_CHARS:
            content = content[: self.MAX_CONTENT_CHARS]
            violations.append("oversized_model_content_trimmed")

        for label, pattern in _PRIVILEGE_INJECTION_PATTERNS:
            if pattern.search(content):
                violations.append(f"untrusted_content_flag:{label}")

        raw_calls = message.get("tool_calls")
        safe_calls: list[dict[str, Any]] = []
        blocked_calls: list[dict[str, Any]] = []
        if isinstance(raw_calls, list):
            for idx, call in enumerate(raw_calls[: self.MAX_TOOL_CALLS_PER_TURN]):
                if not isinstance(call, dict):
                    violations.append(f"malformed_tool_call_{idx}")
                    continue
                fn = call.get("function") if isinstance(call.get("function"), dict) else {}
                tool_name = str(fn.get("name") or "").strip()
                raw_args = fn.get("arguments", "{}")
                try:
                    parsed_args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except ValueError:
                    parsed_args = None
                if not isinstance(parsed_args, dict):
                    violations.append(f"invalid_tool_arguments_json:{tool_name or idx}")
                    blocked_calls.append({"tool": tool_name, "reason": "arguments_must_be_json_object"})
                    continue
                arg_blob = json.dumps(parsed_args, ensure_ascii=False)
                if tool_name in FORBIDDEN_PRIVILEGE_ESCALATION_TOOLS or tool_name.startswith(("secrets.", "permissions.self")):
                    violations.append(f"blocked_privilege_escalation_tool:{tool_name}")
                    blocked_calls.append({"tool": tool_name, "reason": "cloud_model_cannot_modify_permissions_or_read_secrets"})
                    continue
                injected_label = next(
                    (lbl for lbl, pat in _PRIVILEGE_INJECTION_PATTERNS if pat.search(arg_blob)),
                    None,
                )
                if injected_label is not None:
                    violations.append(f"blocked_tool_argument_escalation:{tool_name}:{injected_label}")
                    blocked_calls.append({"tool": tool_name, "reason": injected_label})
                    continue
                safe_calls.append(
                    {
                        "id": str(call.get("id") or f"call-{idx}"),
                        "type": "function",
                        "function": {
                            "name": tool_name,
                            "arguments": json.dumps(parsed_args, ensure_ascii=False),
                        },
                    }
                )
            if len(raw_calls) > self.MAX_TOOL_CALLS_PER_TURN:
                violations.append("excess_tool_calls_truncated")

        sanitized: dict[str, Any] = {"role": "assistant", "content": content.replace("\x00", "")}
        if safe_calls:
            sanitized["tool_calls"] = safe_calls
        return {
            "valid": len(blocked_calls) == 0,
            "blocked": len(blocked_calls) > 0,
            "violations": violations,
            "blocked_tool_calls": blocked_calls,
            "sanitized_message": sanitized,
        }

    def validate_external_artifact(self, content: str, *, source_kind: str = "webpage") -> dict[str, Any]:
        """Validate untrusted text from webpages, documents, tool outputs, or downloaded metadata."""
        cleaned = (content or "").replace("\x00", "")
        flags: list[str] = []
        if len(cleaned) > self.MAX_CONTENT_CHARS:
            cleaned = cleaned[: self.MAX_CONTENT_CHARS]
            flags.append("artifact_truncated")
        for label, pattern in _PRIVILEGE_INJECTION_PATTERNS:
            if pattern.search(cleaned):
                flags.append(label)
        if re.search(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions\b", cleaned):
            flags.append("prompt_injection_directive")
        return {
            "source_kind": source_kind,
            "trusted": False,
            "quarantine_recommended": any(
                f in {"self_permission_mutation", "secret_store_exfiltration", "unrestricted_root_escalation"}
                for f in flags
            ),
            "flags": flags,
            "sanitized_excerpt": cleaned,
        }


class LlamaCppFallbackAdvisor:
    """§7 Optional local model fallback via llama.cpp for compact quantized models within host RAM."""

    RECOMMENDED_COMPACT_MODELS: tuple[dict[str, Any], ...] = (
        {"model_id": "qwen2.5-coder-1.5b-instruct-q4_k_m.gguf", "params_b": 1.5, "quantization": "Q4_K_M", "min_ram_mb": 2048},
        {"model_id": "llama-3.2-3b-instruct-q4_k_m.gguf", "params_b": 3.0, "quantization": "Q4_K_M", "min_ram_mb": 3200},
        {"model_id": "qwen2.5-7b-instruct-q4_k_m.gguf", "params_b": 7.0, "quantization": "Q4_K_M", "min_ram_mb": 6400},
    )

    def inspect_runtime(self, available_ram_mb: int | None = None) -> dict[str, Any]:
        llama_server = shutil.which("llama-server")
        llama_cli = shutil.which("llama-cli")
        probe = check_local_model_resource_fit(
            "llama-3.2-3b-instruct-q4_k_m.gguf",
            available_ram_mb=available_ram_mb,
            require_compact_quantized=True,
        )
        ram_mb = int(probe["available_ram_mb"])
        eligible_recommendations = [
            item
            for item in self.RECOMMENDED_COMPACT_MODELS
            if check_local_model_resource_fit(
                item["model_id"],
                available_ram_mb=ram_mb,
                require_compact_quantized=True,
            )["fits_resource_budget"]
        ]
        return {
            "provider_type": "llama_cpp",
            "default_endpoint": PROVIDER_CATALOG["llama_cpp"]["default_base_url"],
            "llama_server_binary": llama_server or "",
            "llama_cli_binary": llama_cli or "",
            "binary_installed": bool(llama_server or llama_cli),
            "available_ram_mb": ram_mb,
            "max_automatic_params_b": MAX_AUTOMATIC_LOCAL_FALLBACK_PARAMS_B,
            "auto_run_enormous_models": False,
            "role": "optional_offline_basic_task_fallback_only",
            "recommended_compact_models": eligible_recommendations,
        }

    def evaluate_candidate(self, model_id: str, available_ram_mb: int | None = None) -> dict[str, Any]:
        return check_local_model_resource_fit(
            model_id,
            available_ram_mb=available_ram_mb,
            require_compact_quantized=True,
        )


def verify_hybrid_architecture_integrity(app_root: Path | None = None) -> dict[str, Any]:
    """§1, §10 & §11 Verify local-hosted vs cloud-frontier separation and non-root / non-Spaces invariants."""
    root = (app_root or Path(__file__).resolve().parents[2]).resolve()
    readme_path = root / "README.md"
    app_py_path = root / "app.py"
    dockerfile_path = root / "Dockerfile"

    readme_head = readme_path.read_text(encoding="utf-8")[:400] if readme_path.is_file() else ""
    has_hf_frontmatter = readme_head.lstrip().startswith("---") and "app_port: 7860" in readme_head

    app_py_text = app_py_path.read_text(encoding="utf-8") if app_py_path.is_file() else ""
    app_defaults_loopback = '"127.0.0.1"' in app_py_text and "0.0.0.0" not in app_py_text

    dockerfile_text = dockerfile_path.read_text(encoding="utf-8") if dockerfile_path.is_file() else ""
    dockerfile_non_root = "USER nova" in dockerfile_text and "127.0.0.1" in dockerfile_text

    euid = os.geteuid() if hasattr(os, "geteuid") else 1000
    running_as_root = euid == 0
    frontier_cloud_providers = sorted(
        k for k, v in PROVIDER_CATALOG.items() if not v.get("local_runtime")
    )
    local_fallback_providers = sorted(
        k for k, v in PROVIDER_CATALOG.items() if v.get("local_runtime")
    )

    return {
        "architecture": "locally_hosted_autonomous_os_powered_by_cloud_frontier_intelligence",
        "local_components": list(LOCAL_HOSTED_COMPONENTS),
        "cloud_components": list(CLOUD_INTELLIGENCE_COMPONENTS),
        "invariants": dict(HYBRID_INVARIANTS),
        "frontier_cloud_providers": frontier_cloud_providers,
        "local_fallback_providers": local_fallback_providers,
        "multi_provider_no_lock_in": len(frontier_cloud_providers) >= 6,
        "huggingface_spaces_frontmatter_removed": not has_hf_frontmatter,
        "companion_asgi_loopback_only_default": app_defaults_loopback,
        "container_non_root_and_loopback": dockerfile_non_root,
        "effective_uid": euid,
        "running_as_non_root_recommended": not running_as_root,
        "admin_boundary_policy": "linux_polkit_pkexec_and_scoped_helpers_never_run_app_as_root",
    }
