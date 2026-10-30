"""§185 Kali Community & Forum Intelligence and §197 Multi-Source Technical Research Verification."""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from nova.db import Database
from nova.kali_intel.system_model import KaliSystemKnowledgeModel
from nova.kali_intel.tool_and_doc_engine import AutomaticDocumentationEngine
from nova.observability import Redactor

KALI_PUBLIC_SOURCES: dict[str, str] = {
    "kali_forums": "https://forums.kali.org/",
    "kali_docs": "https://www.kali.org/docs/",
    "kali_tools": "https://www.kali.org/tools/",
    "kali_blog": "https://www.kali.org/blog/",
    "kali_gitlab": "https://gitlab.com/kalilinux/packages",
}

HAZARDOUS_FORUM_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("recursive_forced_delete", re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b|\brm\s+-[a-zA-Z]*f[a-zA-Z]*r\b")),
    ("raw_block_device_write", re.compile(r"\bdd\b[^\n]*\bof=/dev/")),
    ("pipe_network_script_to_shell", re.compile(r"\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(ba)?sh\b")),
    ("world_writable_permissions", re.compile(r"\bchmod\s+(-R\s+)?0?777\b")),
    ("overwrite_apt_sources", re.compile(r">\s*/etc/apt/sources\.list\b")),
    ("unauthenticated_apt_bypass", re.compile(r"--allow-unauthenticated|--allow-insecure-repositories")),
)

OUTDATED_KALI_ADVICE_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "deprecated_apt_key",
        re.compile(r"\bapt-key\s+add\b"),
        "Modern Kali Rolling uses signed-by keyrings in /etc/apt/keyrings or /usr/share/keyrings instead of deprecated `apt-key add`.",
    ),
    (
        "obsolete_kali_codename",
        re.compile(r"\b(kali-sana|kali-moto|backtrack)\b", re.IGNORECASE),
        "Legacy Kali release codename detected; current Kali uses `kali-rolling`.",
    ),
    (
        "externally_managed_system_pip",
        re.compile(r"\bsudo\s+pip3?\s+install\b|--break-system-packages"),
        "Modern Kali enforces PEP 668 externally-managed Python environments; use `pipx` or `python3 -m venv` instead of mutating system site-packages.",
    ),
)

_EXTRA_SENSITIVE_RE = re.compile(
    r"(?i)(\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|bearer)\s*[:=]\s*\S+|-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----)"
)


class KaliCommunityForumIntelligence:
    """§185 Safe read-only Kali community synthesis, command hazard audit, and redacted support drafting."""

    AUTO_EXECUTE_FORUM_COMMANDS = False
    AUTO_PUBLISH_ONLINE = False
    ALLOW_USER_IMPERSONATION = False

    def __init__(
        self,
        *,
        db: Database,
        system_model: KaliSystemKnowledgeModel,
        doc_engine: AutomaticDocumentationEngine,
        redactor: Redactor | None = None,
        public_fetcher: Callable[[str], dict[str, Any]] | None = None,
    ):
        self.db = db
        self.system_model = system_model
        self.doc_engine = doc_engine
        self.redactor = redactor or Redactor()
        self.public_fetcher = public_fetcher

    def inspect_forum_command_safety(self, command_text: str) -> dict[str, Any]:
        """§185 Never execute forum commands automatically without inspecting destructive effects & compatibility."""
        hazards = [label for label, pat in HAZARDOUS_FORUM_COMMAND_PATTERNS if pat.search(command_text or "")]
        stale_notes = [
            {"flag": label, "modern_guidance": guidance}
            for label, pat, guidance in OUTDATED_KALI_ADVICE_PATTERNS
            if pat.search(command_text or "")
        ]
        safe_for_manual_review = len(hazards) == 0 and len(stale_notes) == 0
        return {
            "command": command_text,
            "auto_execution_permitted": False,
            "safe_for_supervised_consideration": safe_for_manual_review,
            "destructive_or_unsafe_hazards": hazards,
            "outdated_kali_release_warnings": stale_notes,
            "verdict": (
                "blocked_hazardous_forum_command"
                if hazards
                else ("requires_modern_kali_adaptation" if stale_notes else "review_against_local_man_page_before_run")
            ),
        }

    def analyze_troubleshooting_discussions(
        self,
        error_or_symptom: str,
        *,
        candidate_posts: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """§185 Compare explanations, prefer maintainer/accepted answers, flag stale release advice & hazards."""
        env = self.system_model.get_or_refresh_model()["model"]
        posts = list(candidate_posts or self._default_curated_reference_posts(error_or_symptom))

        evaluated: list[dict[str, Any]] = []
        for idx, post in enumerate(posts, start=1):
            proposed_cmd = str(post.get("proposed_command") or "")
            cmd_audit = self.inspect_forum_command_safety(proposed_cmd) if proposed_cmd else {
                "destructive_or_unsafe_hazards": [],
                "outdated_kali_release_warnings": [],
                "safe_for_supervised_consideration": True,
            }
            is_maintainer = bool(post.get("is_maintainer") or post.get("source_tier", 5) <= 2)
            is_accepted = bool(post.get("accepted_solution"))
            score = (
                (40 if is_maintainer else 10)
                + (20 if is_accepted else 0)
                - (50 * len(cmd_audit["destructive_or_unsafe_hazards"]))
                - (20 * len(cmd_audit["outdated_kali_release_warnings"]))
            )
            evaluated.append(
                {
                    "rank_score": score,
                    "title": str(post.get("title") or f"Discussion #{idx}"),
                    "source": str(post.get("source") or KALI_PUBLIC_SOURCES["kali_forums"]),
                    "author_role": "maintainer" if is_maintainer else str(post.get("author_role") or "community_member"),
                    "accepted_solution": is_accepted,
                    "kali_release_mentioned": str(post.get("kali_release") or "unspecified"),
                    "missing_prerequisites": list(post.get("prerequisites") or []),
                    "explanation": str(post.get("explanation") or ""),
                    "proposed_command": proposed_cmd,
                    "command_safety_audit": cmd_audit,
                    "treated_as_authoritative": is_maintainer and int(post.get("source_tier", 5)) <= 2,
                }
            )

        evaluated.sort(key=lambda item: -item["rank_score"])
        recommended = next(
            (e for e in evaluated if not e["command_safety_audit"]["destructive_or_unsafe_hazards"]),
            None,
        )
        return {
            "symptom": error_or_symptom,
            "local_distro": env["distribution"]["pretty_name"],
            "local_kernel": env["kernel_and_architecture"]["release"],
            "community_posts_are_authoritative": False,
            "auto_executed_commands": 0,
            "evaluated_discussions": evaluated,
            "recommended_summary": (
                recommended["explanation"]
                if recommended
                else "All candidate forum snippets contained unsafe commands; consult official Kali docs (`kali.org/docs/`) and local `man` pages instead."
            ),
        }

    def prepare_redacted_support_draft(
        self,
        *,
        issue_title: str,
        observed_error: str,
        steps_reproduced: list[str],
        raw_log_excerpt: str = "",
    ) -> dict[str, Any]:
        """§185 Draft a clean support question & secret-scrubbed log report without publishing online."""
        env = self.system_model.get_or_refresh_model()["model"]
        scrubbed_err = _EXTRA_SENSITIVE_RE.sub("[REDACTED_SECRET]", str(self.redactor.scrub(observed_error, max_chars=0)))
        scrubbed_logs = _EXTRA_SENSITIVE_RE.sub("[REDACTED_SECRET]", str(self.redactor.scrub(raw_log_excerpt, max_chars=0)))

        markdown_draft = (
            f"### Summary\n{issue_title.strip()}\n\n"
            f"### Environment\n"
            f"- Distribution: {env['distribution']['pretty_name']}\n"
            f"- Kernel / Arch: {env['kernel_and_architecture']['release']} ({env['kernel_and_architecture']['architecture']})\n"
            f"- Session: {env['desktop_environment']['session_type']}\n\n"
            f"### Steps Taken\n"
            + "\n".join(f"{i}. {self.redactor.scrub_text(s)}" for i, s in enumerate(steps_reproduced, start=1))
            + f"\n\n### Observed Error (Redacted)\n```\n{scrubbed_err}\n```\n"
            + (f"\n### Diagnostic Log Excerpt (Redacted)\n```\n{scrubbed_logs}\n```\n" if scrubbed_logs else "")
        )
        return {
            "title": issue_title.strip(),
            "published_online": False,
            "requires_explicit_user_submission": True,
            "secrets_redacted": True,
            "target_forum_url": KALI_PUBLIC_SOURCES["kali_forums"],
            "support_post_markdown": markdown_draft,
            "redacted_log_report": scrubbed_logs,
        }

    @staticmethod
    def _default_curated_reference_posts(symptom: str) -> list[dict[str, Any]]:
        s = symptom.lower()
        if "pip" in s or "externally-managed" in s:
            return [
                {
                    "title": "Kali Docs: Installing Python Applications cleanly (PEP 668)",
                    "source": "https://www.kali.org/docs/general-use/python3-external-packages/",
                    "source_tier": 2,
                    "is_maintainer": True,
                    "accepted_solution": True,
                    "kali_release": "kali-rolling",
                    "prerequisites": ["python3-venv", "pipx"],
                    "explanation": "Use `python3 -m venv .venv` for project libraries or `pipx` for standalone Python CLI tools so APT-managed Python packages remain intact.",
                    "proposed_command": "python3 -m venv .venv",
                },
                {
                    "title": "Old forum workaround bypassing system package protection",
                    "source": "https://forums.kali.org/",
                    "source_tier": 5,
                    "is_maintainer": False,
                    "accepted_solution": False,
                    "kali_release": "2021.1",
                    "prerequisites": [],
                    "explanation": "Force system pip install globally as root.",
                    "proposed_command": "sudo pip3 install --break-system-packages requests",
                },
            ]
        return [
            {
                "title": "Kali Official Troubleshooting: Inspect package & service state non-destructively",
                "source": "https://www.kali.org/docs/troubleshooting/",
                "source_tier": 2,
                "is_maintainer": True,
                "accepted_solution": True,
                "kali_release": "kali-rolling",
                "prerequisites": ["dpkg", "apt"],
                "explanation": "Verify package integrity with `dpkg --audit` and check official Kali repositories before altering configuration files.",
                "proposed_command": "dpkg --audit",
            }
        ]


class TechnicalResearchVerifier:
    """§197 Multi-source technical research, citation tracking, and version/date conflict resolution."""

    SUPPORTED_SOURCE_CLASSES: tuple[str, ...] = (
        "kali_documentation",
        "kali_tool_pages",
        "local_man_pages",
        "upstream_project_documentation",
        "technical_standards_and_rfcs",
        "official_repositories",
        "issue_trackers",
        "community_forums",
        "academic_and_technical_resources",
        "user_local_notes",
    )

    def __init__(self, *, db: Database, doc_engine: AutomaticDocumentationEngine):
        self.db = db
        self.doc_engine = doc_engine

    def research_and_reconcile(
        self,
        topic: str,
        *,
        additional_claims: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """§197 Gather multi-tier evidence, detect conflicts, compare dates/versions, and cite exact sources."""
        local_docs = self.db.search_kali_knowledge_docs(query=topic, max_priority_tier=5, limit=20)
        if not local_docs and re.fullmatch(r"[A-Za-z0-9._+\-]+", topic.strip()):
            self.doc_engine.retrieve_prioritized_documentation(topic.strip())
            local_docs = self.db.search_kali_knowledge_docs(tool_or_topic=topic.strip(), max_priority_tier=5, limit=20)

        claims: list[dict[str, Any]] = []
        for doc in local_docs:
            claims.append(
                {
                    "source_ref": doc["source_ref"] or doc["doc_key"],
                    "title": doc["title"],
                    "priority_tier": int(doc["priority_tier"]),
                    "reliability": doc["reliability"],
                    "version_context": doc["version_context"],
                    "date": doc["updated_at"],
                    "statement": doc["content_excerpt"][:360],
                }
            )
        for extra in additional_claims or []:
            claims.append(
                {
                    "source_ref": str(extra.get("source_ref") or "external_claim"),
                    "title": str(extra.get("title") or "Additional source"),
                    "priority_tier": int(extra.get("priority_tier") or 5),
                    "reliability": str(extra.get("reliability") or "community_unverified"),
                    "version_context": str(extra.get("version_context") or "unspecified"),
                    "date": str(extra.get("date") or "unspecified"),
                    "statement": str(extra.get("statement") or ""),
                }
            )

        claims.sort(key=lambda c: (c["priority_tier"], str(c["date"])))
        official_claims = [c for c in claims if c["priority_tier"] <= 3]
        community_claims = [c for c in claims if c["priority_tier"] >= 5]

        conflicts: list[dict[str, Any]] = []
        for comm in community_claims:
            for off in official_claims:
                if comm["version_context"] != off["version_context"] or (
                    "deprecated" in off["statement"].lower()
                    or "apt-key" in comm["statement"].lower()
                    or "--break-system-packages" in comm["statement"].lower()
                ):
                    conflicts.append(
                        {
                            "preferred_source": off["source_ref"],
                            "preferred_tier": off["priority_tier"],
                            "preferred_version": off["version_context"],
                            "superseded_source": comm["source_ref"],
                            "superseded_tier": comm["priority_tier"],
                            "superseded_date": comm["date"],
                            "resolution": "Resolved in favor of higher-priority current official documentation and local installed version context.",
                        }
                    )
                    break

        citations = [
            {
                "id": idx,
                "title": c["title"],
                "source_ref": c["source_ref"],
                "priority_tier": c["priority_tier"],
                "reliability": c["reliability"],
                "version_context": c["version_context"],
            }
            for idx, c in enumerate(claims[:10], start=1)
        ]
        authoritative_winner = claims[0] if claims else None
        return {
            "topic": topic,
            "supported_source_classes": list(self.SUPPORTED_SOURCE_CLASSES),
            "conflicts_detected": len(conflicts),
            "conflict_resolutions": conflicts,
            "primary_verified_conclusion": authoritative_winner["statement"] if authoritative_winner else "",
            "citations": citations,
        }
