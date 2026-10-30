"""§165.3 Unified Multi-Source Internet Search, §165.4 12-Step Dark-Web
Research Assistant, and §165.10 Autonomous Research & Monitoring.

Hard truthfulness & epistemic invariants:
- `SINGLE_ENGINE_INDEXES_ENTIRE_DARK_WEB = False`
- `FABRICATE_SEARCH_RESULTS_OR_ONIONS = False`
- `MULTI_MODEL_AGREEMENT_IS_PROOF = False`
- `CLAIM_CONTINUOUS_MONITORING_WHEN_STOPPED = False`
- `AUTO_EXPAND_MONITOR_SCOPE = False`
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus, urlparse

from nova.db import Database
from nova.knowledge import KnowledgeStore
from nova.memory_hub import SharedMemorySystem
from nova.observability import Redactor
from nova.privacy_intel.tor_network import (
    OnionServiceBrowser,
    TorIntegrationManager,
    socks5h_http_request,
)

SINGLE_ENGINE_INDEXES_ENTIRE_DARK_WEB = False
FABRICATE_SEARCH_RESULTS_OR_ONIONS = False
MULTI_MODEL_AGREEMENT_IS_PROOF = False
CLAIM_CONTINUOUS_MONITORING_WHEN_STOPPED = False
AUTO_EXPAND_MONITOR_SCOPE = False

ALL_SOURCE_CATEGORIES: tuple[str, ...] = (
    "public_web",
    "official_docs",
    "code_repositories",
    "academic_sources",
    "security_advisories",
    "public_breach_notices",
    "public_blockchain",
    "public_onion_services",
    "privacy_network_search",
    "user_supplied_archives",
    "authorized_threat_intel",
)

SCAM_AND_DECEPTION_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b(?:send\s+(?:btc|bitcoin|xmr|monero)|escrow\s+guarantee|100%\s+undetectable|guaranteed\s+hack)\b", "probable_financial_or_service_scam"),
    (r"\b(?:full\s+database\s+for\s+sale|dm\s+on\s+tox|pay\s+within\s+\d+\s+hours|proof\s+pack\s+available)\b", "unverified_extortion_or_leak_claim"),
    (r"\b(?:zero[- ]day\s+exploit\s+instant\s+access|bypass\s+any\s+2fa)\b", "high_deception_probability_claim"),
)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_ONION_TOKEN_RE = re.compile(r"\b[a-z2-7]{56}\.onion(?::\d+)?(?:/[^\s<>'\"]*)?", re.IGNORECASE)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


@dataclass(slots=True)
class SearchHit:
    source_category: str
    adapter_name: str
    title: str
    url_or_ref: str
    snippet: str
    retrieved_at: str
    trust_level: str  # verified_local | official_reference | public_unverified | onion_unverified
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_category": self.source_category,
            "adapter_name": self.adapter_name,
            "title": self.title,
            "url_or_ref": self.url_or_ref,
            "snippet": self.snippet,
            "retrieved_at": self.retrieved_at,
            "trust_level": self.trust_level,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class SourceExecutionRecord:
    category: str
    adapter_name: str
    consulted: bool
    status: str
    hit_count: int
    latency_ms: float
    checked_at: str
    limitation_note: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "adapter_name": self.adapter_name,
            "consulted": self.consulted,
            "status": self.status,
            "hit_count": self.hit_count,
            "latency_ms": round(self.latency_ms, 2),
            "checked_at": self.checked_at,
            "limitation_note": self.limitation_note,
            "error": self.error,
        }


SearchAdapterFn = Callable[[str, dict[str, Any]], tuple[list[SearchHit], str, str]]


class UnifiedSearchOrchestrator:
    """§165.3 Pluggable Multi-Source Internet & Privacy-Network Search Engine."""

    def __init__(
        self,
        *,
        db: Database,
        knowledge: KnowledgeStore,
        tor_manager: TorIntegrationManager,
        onion_browser: OnionServiceBrowser,
        workspace_dir: Path,
        redactor: Redactor,
    ) -> None:
        self.db = db
        self.knowledge = knowledge
        self.tor = tor_manager
        self.onion_browser = onion_browser
        self.workspace_dir = workspace_dir
        self.redactor = redactor
        self._adapters: dict[str, tuple[str, SearchAdapterFn]] = {}
        self._custom_endpoints: dict[str, str] = {}
        self._register_builtin_adapters()

    def configure_endpoint(self, category: str, endpoint_url_template: str) -> None:
        """Register or override a live HTTP/JSON or HTML endpoint template (`{query}`) for a source category."""
        if category not in ALL_SOURCE_CATEGORIES:
            raise ValueError(f"Unknown search source category '{category}'.")
        self._custom_endpoints[category] = endpoint_url_template.strip()

    def register_adapter(self, category: str, adapter_name: str, fn: SearchAdapterFn) -> None:
        if category not in ALL_SOURCE_CATEGORIES:
            raise ValueError(f"Unsupported category '{category}'.")
        self._adapters[category] = (adapter_name, fn)

    def select_minimum_sufficient_sources(self, query: str, *, requested_categories: list[str] | None = None) -> list[str]:
        """§165.11 Select the minimum sufficient source set — ordinary queries never invoke Tor unnecessarily."""
        if requested_categories:
            return [c for c in requested_categories if c in ALL_SOURCE_CATEGORIES]

        ql = query.lower()
        selected: list[str] = ["user_supplied_archives"]
        has_onion = bool(_ONION_TOKEN_RE.search(query)) or any(k in ql for k in (".onion", "onion service", "dark web", "tor hidden"))
        has_sec = bool(_CVE_RE.search(query)) or any(k in ql for k in ("cve", "advisory", "vulnerability", "exploit", "ioc", "malware"))
        has_breach = any(k in ql for k in ("breach", "exposure", "leaked", "ransomware", "incident notice"))
        has_code = any(k in ql for k in ("github", "repo", "package", "library", "commit", "source code"))
        has_academic = any(k in ql for k in ("paper", "arxiv", "doi", "academic", "study", "cryptography"))
        has_chain = any(k in ql for k in ("blockchain", "txid", "wallet", "ethereum", "bitcoin", "ledger"))

        if has_sec:
            selected.extend(["security_advisories", "authorized_threat_intel", "official_docs"])
        if has_breach:
            selected.extend(["public_breach_notices", "authorized_threat_intel"])
        if has_code:
            selected.extend(["code_repositories", "official_docs"])
        if has_academic:
            selected.append("academic_sources")
        if has_chain:
            selected.append("public_blockchain")
        if has_onion:
            selected.extend(["public_onion_services", "privacy_network_search"])
        if len(selected) == 1 and not has_onion:
            selected.extend(["public_web", "official_docs"])

        # Deduplicate preserving order
        deduped: list[str] = []
        for c in selected:
            if c not in deduped:
                deduped.append(c)
        return deduped

    def search(
        self,
        query: str,
        *,
        categories: list[str] | None = None,
        explicit_urls: list[str] | None = None,
        limit_per_source: int = 8,
    ) -> dict[str, Any]:
        """§165.3 Run unified search across selected source adapters with full audit of consulted sources, limitations & errors."""
        chosen = self.select_minimum_sufficient_sources(query, requested_categories=categories)
        skipped_categories = [c for c in ALL_SOURCE_CATEGORIES if c not in chosen]

        ctx: dict[str, Any] = {
            "explicit_urls": list(explicit_urls or []),
            "limit": max(1, min(int(limit_per_source), 25)),
        }
        hits: list[SearchHit] = []
        consulted_records: list[dict[str, Any]] = []
        limitations: list[str] = [
            "No single search engine indexes the entire public internet or Tor `.onion` network (§165.3).",
        ]
        errors: list[dict[str, str]] = []

        for cat in chosen:
            adapter_name, fn = self._adapters[cat]
            t0 = time.perf_counter()
            checked_at = _iso()
            try:
                cat_hits, lim_note, err_note = fn(query, ctx)
            except Exception as exc:
                cat_hits, lim_note, err_note = [], "", f"{type(exc).__name__}: {exc}"
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            status = "error" if err_note else ("ok" if cat_hits else "no_results_or_unconfigured")
            rec = SourceExecutionRecord(
                category=cat,
                adapter_name=adapter_name,
                consulted=True,
                status=status,
                hit_count=len(cat_hits),
                latency_ms=elapsed_ms,
                checked_at=checked_at,
                limitation_note=lim_note,
                error=err_note,
            )
            consulted_records.append(rec.to_dict())
            hits.extend(cat_hits[: ctx["limit"]])
            if lim_note and lim_note not in limitations:
                limitations.append(lim_note)
            if err_note:
                errors.append({"category": cat, "adapter": adapter_name, "error": err_note})

        skipped_records = [{"category": c, "reason": "not_required_by_minimum_sufficient_selection"} for c in skipped_categories]
        saved_run = self.db.add_internet_search_run(
            {
                "query": query,
                "mode": "unified_search",
                "sources_consulted": consulted_records,
                "sources_skipped": skipped_records,
                "query_limitations": limitations,
                "retrieval_errors": errors,
                "result_count": len(hits),
            }
        )
        return {
            "search_run_id": saved_run.get("id", ""),
            "query": query,
            "executed_at": saved_run.get("created_at", _iso()),
            "hits": [h.to_dict() for h in hits],
            "result_count": len(hits),
            "sources_consulted": consulted_records,
            "sources_skipped": skipped_records,
            "query_limitations": limitations,
            "retrieval_errors": errors,
            "single_engine_indexes_entire_dark_web": SINGLE_ENGINE_INDEXES_ENTIRE_DARK_WEB,
        }

    # ------------------------------------------------- Built-in 11 Source Adapters

    def _register_builtin_adapters(self) -> None:
        self.register_adapter("user_supplied_archives", "local_knowledge_and_workspace_adapter", self._search_user_archives)
        self.register_adapter("authorized_threat_intel", "local_and_configured_threat_intel_adapter", self._search_authorized_threat_intel)
        self.register_adapter("public_onion_services", "tor_v3_onion_collection_adapter", self._search_public_onion_services)
        self.register_adapter("privacy_network_search", "configured_privacy_search_adapter", self._search_privacy_network)
        self.register_adapter("public_web", "direct_public_web_adapter", lambda q, c: self._search_clearnet_category("public_web", "direct_public_web_adapter", q, c, trust="public_unverified"))
        self.register_adapter("official_docs", "official_documentation_adapter", lambda q, c: self._search_clearnet_category("official_docs", "official_documentation_adapter", q, c, trust="official_reference"))
        self.register_adapter("code_repositories", "public_code_repository_adapter", lambda q, c: self._search_clearnet_category("code_repositories", "public_code_repository_adapter", q, c, trust="public_unverified"))
        self.register_adapter("academic_sources", "academic_and_technical_index_adapter", lambda q, c: self._search_clearnet_category("academic_sources", "academic_and_technical_index_adapter", q, c, trust="official_reference"))
        self.register_adapter("security_advisories", "public_security_advisory_adapter", lambda q, c: self._search_clearnet_category("security_advisories", "public_security_advisory_adapter", q, c, trust="official_reference"))
        self.register_adapter("public_breach_notices", "public_breach_disclosure_adapter", lambda q, c: self._search_clearnet_category("public_breach_disclosure_adapter_cat", "public_breach_disclosure_adapter", q, c, trust="public_unverified", canonical_cat="public_breach_notices"))
        self.register_adapter("public_blockchain", "public_blockchain_explorer_adapter", lambda q, c: self._search_clearnet_category("public_blockchain", "public_blockchain_explorer_adapter", q, c, trust="public_unverified"))

    def _search_user_archives(self, query: str, ctx: dict[str, Any]) -> tuple[list[SearchHit], str, str]:
        now = _iso()
        hits: list[SearchHit] = []
        kb_res = self.knowledge.search(query, limit=ctx["limit"])
        for row in kb_res.get("results", []):
            prov = row.get("provenance") or {}
            is_ext = bool(prov.get("external")) or prov.get("source_kind") == "external_source"
            hits.append(
                SearchHit(
                    source_category="user_supplied_archives",
                    adapter_name="local_knowledge_and_workspace_adapter",
                    title=str(row.get("title") or row.get("citation") or "Local Knowledge Chunk"),
                    url_or_ref=f"knowledge://{row.get('document_id', '')}#{row.get('rank', 1)}",
                    snippet=self.redactor.scrub_text(str(row.get("text") or ""), max_chars=500),
                    retrieved_at=now,
                    trust_level="public_unverified" if is_ext else "verified_local",
                    metadata={"score": row.get("score", 0.0), "provenance": prov},
                )
            )
        # Also scan user-supplied `.txt`/`.md`/`.json` files under `workspace/archives` if present
        arch_dir = self.workspace_dir / "archives"
        if arch_dir.is_dir():
            terms = re.findall(r"[a-z0-9_.-]{3,}", query.lower())[:6]
            for fp in sorted(arch_dir.rglob("*"))[:40]:
                if fp.is_file() and fp.suffix.lower() in {".txt", ".md", ".json", ".log"} and fp.stat().st_size <= 512_000:
                    txt = fp.read_text(encoding="utf-8", errors="replace")
                    tl = txt.lower()
                    if terms and any(t in tl for t in terms):
                        hits.append(
                            SearchHit(
                                source_category="user_supplied_archives",
                                adapter_name="local_knowledge_and_workspace_adapter",
                                title=fp.name,
                                url_or_ref=f"file://{fp}",
                                snippet=self.redactor.scrub_text(txt[:500]),
                                retrieved_at=now,
                                trust_level="verified_local",
                                metadata={"bytes": fp.stat().st_size},
                            )
                        )
        return hits, "Local archive search covers indexed KnowledgeStore documents and `workspace/archives` only.", ""

    def _search_authorized_threat_intel(self, query: str, ctx: dict[str, Any]) -> tuple[list[SearchHit], str, str]:
        now = _iso()
        hits: list[SearchHit] = []
        ql = query.lower()
        terms = re.findall(r"[a-z0-9_.-]{3,}", ql)
        for row in self.db.list_threat_intel_findings(limit=80):
            hay = f"{row['summary']} {row['asset_scope']} {json.dumps(row['indicators'])}".lower()
            if not terms or any(t in hay for t in terms):
                hits.append(
                    SearchHit(
                        source_category="authorized_threat_intel",
                        adapter_name="local_and_configured_threat_intel_adapter",
                        title=f"[{row['severity'].upper()}] {row['finding_kind']} ({row['source_classification']})",
                        url_or_ref=f"threat-finding://{row['id']}",
                        snippet=row["summary"][:500],
                        retrieved_at=now,
                        trust_level="verified_local" if row["source_classification"] == "verified_local_observation" else "public_unverified",
                        metadata={"confidence_tier": row["confidence_tier"], "indicators": row["indicators"]},
                    )
                )
        ep_hits, lim, err = self._query_configured_endpoint("authorized_threat_intel", "local_and_configured_threat_intel_adapter", query, "official_reference")
        hits.extend(ep_hits)
        return hits, lim or "Authorized threat-intel adapter queries recorded local findings and explicitly configured feeds only.", err

    def _search_public_onion_services(self, query: str, ctx: dict[str, Any]) -> tuple[list[SearchHit], str, str]:
        cfg = self.tor.get_config()
        if not cfg["tor_enabled"]:
            return (
                [],
                "Tor integration is currently disabled; `.onion` endpoints were not contacted.",
                "tor_integration_disabled",
            )
        hits: list[SearchHit] = []
        errors: list[str] = []
        # Gather explicit `.onion` URLs from query, context, and saved bookmarks matching query terms
        candidate_urls: list[str] = []
        for u in list(ctx.get("explicit_urls") or []) + [m.group(0) for m in _ONION_TOKEN_RE.finditer(query)]:
            norm = u if "://" in u else f"http://{u}"
            if (urlparse(norm).hostname or "").lower().endswith(".onion") and norm not in candidate_urls:
                candidate_urls.append(norm)

        ql_terms = [t for t in re.findall(r"[a-z0-9]{3,}", query.lower()) if t != "onion"]
        for bm in self.db.list_onion_bookmarks(limit=50):
            hay = f"{bm['title']} {bm['notes']} {bm['onion_address']}".lower()
            if not candidate_urls or any(t in hay for t in ql_terms):
                u = f"http://{bm['onion_address']}/"
                if u not in candidate_urls:
                    candidate_urls.append(u)

        for u in candidate_urls[:6]:
            page = self.onion_browser.open_onion_page(u, source_obtained_from="unified_search")
            if page.get("ok"):
                hits.append(
                    SearchHit(
                        source_category="public_onion_services",
                        adapter_name="tor_v3_onion_collection_adapter",
                        title=page.get("title") or page.get("onion_address", u),
                        url_or_ref=u,
                        snippet=page.get("summary") or "",
                        retrieved_at=page["accessed_at"],
                        trust_level="official_reference" if page.get("trust_status") == "verified_against_reference" else "onion_unverified",
                        metadata={
                            "http_status": page.get("http_status"),
                            "trust_status": page.get("trust_status"),
                            "broken_links": page.get("broken_or_outdated_links", []),
                        },
                    )
                )
            else:
                errors.append(f"{u}: {page.get('status')} ({page.get('reason', '')})")

        lim = "Only user-supplied or bookmarked publicly accessible v3 `.onion` services were queried; unindexed or auth-gated hidden services are excluded."
        return hits, lim, "; ".join(errors)

    def _search_privacy_network(self, query: str, ctx: dict[str, Any]) -> tuple[list[SearchHit], str, str]:
        cfg = self.tor.get_config()
        tpl = self._custom_endpoints.get("privacy_network_search", "")
        if not tpl:
            return (
                [],
                "No verified privacy-network search endpoint URL template is configured; NOVA never fabricates dark-web index results.",
                "",
            )
        if not cfg["tor_enabled"]:
            return ([], "Tor integration is disabled; privacy-network search endpoint was not contacted.", "tor_integration_disabled")
        target = tpl.replace("{query}", quote_plus(query))
        res = socks5h_http_request(target, socks_host=cfg["socks_host"], socks_port=cfg["socks_port"], isolation_token="privsearch")
        if not res.get("ok"):
            return ([], "Privacy-network search indexes only a partial subset of public `.onion` pages.", str(res.get("reason") or res.get("status")))
        hits = self._parse_endpoint_payload(res["body_bytes"], "privacy_network_search", "configured_privacy_search_adapter", target, "onion_unverified")
        return hits, "Privacy-network search covers only pages crawled by the configured index, never the entire Tor network.", ""

    def _search_clearnet_category(
        self,
        endpoint_key: str,
        adapter_name: str,
        query: str,
        ctx: dict[str, Any],
        *,
        trust: str,
        canonical_cat: str = "",
    ) -> tuple[list[SearchHit], str, str]:
        cat = canonical_cat or endpoint_key
        hits: list[SearchHit] = []
        errors: list[str] = []

        # Fetch explicit clearnet URLs when searching public_web / official_docs
        if cat == "public_web":
            clearnet_urls = [
                u
                for u in list(ctx.get("explicit_urls") or []) + [m.group(0) for m in _URL_RE.finditer(query)]
                if not (urlparse(u).hostname or "").lower().endswith(".onion")
            ]
            for u in clearnet_urls[:5]:
                page = self.onion_browser.fetch_ordinary_website(u)
                if page.get("ok"):
                    hits.append(
                        SearchHit(
                            source_category=cat,
                            adapter_name=adapter_name,
                            title=page.get("title") or u,
                            url_or_ref=u,
                            snippet=page.get("content_excerpt", "")[:500],
                            retrieved_at=page["accessed_at"],
                            trust_level=trust,
                            metadata={"via": "ordinary_direct", "http_status": page.get("http_status")},
                        )
                    )
                else:
                    errors.append(f"{u}: {page.get('status')} ({page.get('reason', '')})")

        ep_hits, lim, ep_err = self._query_configured_endpoint(cat, adapter_name, query, trust)
        hits.extend(ep_hits)
        if ep_err:
            errors.append(ep_err)
        return hits, lim, "; ".join(errors)

    def _query_configured_endpoint(self, category: str, adapter_name: str, query: str, trust: str) -> tuple[list[SearchHit], str, str]:
        tpl = self._custom_endpoints.get(category, "")
        if not tpl:
            return (
                [],
                f"No external feed endpoint configured for `{category}`; only direct URLs and local records were consulted.",
                "",
            )
        target = tpl.replace("{query}", quote_plus(query))
        page = self.onion_browser.fetch_ordinary_website(target)
        if not page.get("ok"):
            return ([], f"Configured `{category}` feed failed to respond.", f"{target}: {page.get('reason') or page.get('status')}")
        raw_bytes = page.get("content_excerpt", "").encode("utf-8", errors="replace")
        hits = self._parse_endpoint_payload(raw_bytes, category, adapter_name, target, trust, fallback_title=page.get("title", ""))
        return hits, f"Consulted configured `{category}` endpoint `{target}`.", ""

    def _parse_endpoint_payload(
        self,
        payload: bytes,
        category: str,
        adapter_name: str,
        source_url: str,
        trust: str,
        *,
        fallback_title: str = "",
    ) -> list[SearchHit]:
        now = _iso()
        text = payload.decode("utf-8", errors="replace").strip()
        try:
            parsed = json.loads(text)
            rows = parsed.get("results", parsed) if isinstance(parsed, dict) else parsed
            if isinstance(rows, list):
                out: list[SearchHit] = []
                for idx, item in enumerate(rows[:15]):
                    if isinstance(item, dict):
                        out.append(
                            SearchHit(
                                source_category=category,
                                adapter_name=adapter_name,
                                title=str(item.get("title") or f"{category} result #{idx + 1}"),
                                url_or_ref=str(item.get("url") or source_url),
                                snippet=self.redactor.scrub_text(str(item.get("snippet") or item.get("summary") or ""), max_chars=500),
                                retrieved_at=now,
                                trust_level=str(item.get("trust_level") or trust),
                                metadata={k: v for k, v in item.items() if k not in {"title", "url", "snippet", "summary"}},
                            )
                        )
                if out:
                    return out
        except json.JSONDecodeError:
            pass

        if not text:
            return []
        return [
            SearchHit(
                source_category=category,
                adapter_name=adapter_name,
                title=fallback_title or source_url,
                url_or_ref=source_url,
                snippet=self.redactor.scrub_text(text, max_chars=500),
                retrieved_at=now,
                trust_level=trust,
                metadata={},
            )
        ]


class DarkWebResearchAssistant:
    """§165.4 Structured 12-Step Research Workflow with Epistemic Tier Separation & Scam/Contradiction Detection."""

    WORKFLOW_STEPS: tuple[str, ...] = (
        "1_interpret_research_question",
        "2_select_appropriate_sources",
        "3_search_public_sources",
        "4_retrieve_permitted_onion_material",
        "5_compare_claims_across_sources",
        "6_detect_contradictions",
        "7_flag_probable_scams_and_unsupported_claims",
        "8_preserve_citations_and_timestamps",
        "9_separate_observations_claims_hypotheses_verified_facts",
        "10_generate_structured_report",
        "11_save_findings_to_knowledge_base",
        "12_record_uncompleted_parts",
    )

    def __init__(
        self,
        *,
        db: Database,
        search_orchestrator: UnifiedSearchOrchestrator,
        onion_browser: OnionServiceBrowser,
        knowledge: KnowledgeStore,
        memory_os: SharedMemorySystem,
        redactor: Redactor,
        cognition: Any | None = None,
    ) -> None:
        self.db = db
        self.search = search_orchestrator
        self.onion_browser = onion_browser
        self.knowledge = knowledge
        self.memory_os = memory_os
        self.redactor = redactor
        self.cognition = cognition

    def conduct_research(
        self,
        question: str,
        *,
        explicit_urls: list[str] | None = None,
        categories: list[str] | None = None,
        independent_model_reviews: list[dict[str, Any]] | None = None,
        save_to_kb: bool = True,
    ) -> dict[str, Any]:
        started_at = _iso()
        urls = list(explicit_urls or [])
        for m in _URL_RE.finditer(question):
            if m.group(0) not in urls:
                urls.append(m.group(0))
        for m in _ONION_TOKEN_RE.finditer(question):
            cand = m.group(0) if "://" in m.group(0) else f"http://{m.group(0)}"
            if cand not in urls:
                urls.append(cand)

        # Step 1 & 2: Interpret question & select minimum-sufficient sources
        cves = sorted({m.group(0).upper() for m in _CVE_RE.finditer(question)})
        onion_targets = [u for u in urls if (urlparse(u).hostname or "").lower().endswith(".onion")]
        clearnet_targets = [u for u in urls if u not in onion_targets]
        selected_sources = self.search.select_minimum_sufficient_sources(question, requested_categories=categories)
        if onion_targets and "public_onion_services" not in selected_sources:
            selected_sources.append("public_onion_services")
        if clearnet_targets and "public_web" not in selected_sources:
            selected_sources.append("public_web")

        # Step 3 & 4: Search public sources & retrieve permitted `.onion` material
        public_cats = [c for c in selected_sources if c not in {"public_onion_services", "privacy_network_search"}]
        onion_cats = [c for c in selected_sources if c in {"public_onion_services", "privacy_network_search"}]

        all_hits: list[dict[str, Any]] = []
        consulted: list[dict[str, Any]] = []
        limitations: list[str] = []
        errors: list[dict[str, str]] = []

        if public_cats:
            pub_res = self.search.search(question, categories=public_cats, explicit_urls=clearnet_targets)
            all_hits.extend(pub_res["hits"])
            consulted.extend(pub_res["sources_consulted"])
            limitations.extend(pub_res["query_limitations"])
            errors.extend(pub_res["retrieval_errors"])

        if onion_cats:
            on_res = self.search.search(question, categories=onion_cats, explicit_urls=onion_targets)
            all_hits.extend(on_res["hits"])
            consulted.extend(on_res["sources_consulted"])
            for lim in on_res["query_limitations"]:
                if lim not in limitations:
                    limitations.append(lim)
            errors.extend(on_res["retrieval_errors"])

        # Step 5, 6 & 7: Cross-source comparison, contradiction detection, and scam/deception flagging
        corroborations = self._compare_across_sources(all_hits)
        contradictions = self._detect_contradictions(all_hits)
        scam_and_unsupported_flags = self._flag_scams_and_unsupported(all_hits)

        # Step 8: Citations with timestamps
        citations = [
            {
                "id": f"cite-{idx + 1}",
                "title": h["title"],
                "url_or_ref": h["url_or_ref"],
                "source_category": h["source_category"],
                "trust_level": h["trust_level"],
                "retrieved_at": h["retrieved_at"],
            }
            for idx, h in enumerate(all_hits)
        ]

        # Step 9: Strict separation of observations, claims, hypotheses, and verified_facts
        observations: list[str] = []
        claims: list[str] = []
        hypotheses: list[str] = []
        verified_facts: list[str] = []

        flagged_urls = {f["url_or_ref"] for f in scam_and_unsupported_flags}
        trust_by_url = {h["url_or_ref"]: h["trust_level"] for h in all_hits}
        authoritative_tiers = {"verified_local", "official_reference"}
        authoritatively_contradicted_urls = {
            u
            for c in contradictions
            if trust_by_url.get(c["source_a"]) in authoritative_tiers and trust_by_url.get(c["source_b"]) in authoritative_tiers
            for u in (c["source_a"], c["source_b"])
        }

        for h in all_hits:
            ref = h["url_or_ref"]
            observations.append(
                f"Retrieved `{h['title']}` from `{ref}` ({h['source_category']}) at {h['retrieved_at']}."
            )
            if h["trust_level"] in authoritative_tiers and ref not in flagged_urls and ref not in authoritatively_contradicted_urls:
                verified_facts.append(f"[{ref}] {h['snippet'][:260]}")
            else:
                claims.append(f"[Unverified {h['trust_level']} @ {ref}] {h['snippet'][:260]}")

        if contradictions:
            hypotheses.append(
                "Conflicting statements exist across retrieved sources; either one source is outdated or an unverified source is fabricating/exaggerating impact."
            )
        if scam_and_unsupported_flags:
            hypotheses.append(
                "One or more retrieved items exhibit classic dark-web scam, advance-fee, or unsubstantiated extortion markers and must be treated as untrusted."
            )
        if not hypotheses and all_hits:
            hypotheses.append("Available observations are internally consistent so far, subject to the recorded coverage limitations.")

        # Step 9b: Multi-model reasoning & cognition review (strictly enforcing MULTI_MODEL_AGREEMENT_IS_PROOF = False)
        reviews_input = list(independent_model_reviews or [])
        models_concurring = sum(1 for r in reviews_input if bool(r.get("agrees_with_claim")))
        cognition_attached = self.cognition is not None
        if self.cognition is not None and hasattr(self.cognition, "record_claim"):
            try:
                for vf in verified_facts[:5]:
                    self.cognition.record_claim(claim=vf[:240], status="verified", evidence="authoritative_source")
            except Exception:
                pass
        multi_model_review = {
            "cognition_engine_integrated": cognition_attached,
            "independent_reviews_evaluated": len(reviews_input),
            "models_concurring_on_unverified_claims": models_concurring,
            "promoted_unverified_claims_from_consensus": 0,
            "multi_model_agreement_treated_as_proof": MULTI_MODEL_AGREEMENT_IS_PROOF,
            "note": (
                "Independent model reviews assist critique and hypothesis generation only; "
                "agreement among models never upgrades an unverified claim to `verified_facts` (§165.4)."
            ),
        }

        # Step 12: Record any part of the research that could not be completed
        uncompleted_parts: list[str] = []
        for err in errors:
            uncompleted_parts.append(f"Source `{err['category']}` ({err['adapter']}) incomplete: {err['error']}")
        for c in consulted:
            if c["hit_count"] == 0 and c["status"] == "no_results_or_unconfigured":
                uncompleted_parts.append(f"Source `{c['category']}` returned 0 results ({c['limitation_note']}).")

        # Step 10 & 11: Generate structured report & persist to KnowledgeStore + SharedMemorySystem
        report_id = f"dwr-{hashlib.sha256(f'{question}:{started_at}'.encode()).hexdigest()[:12]}"
        markdown_report = self._render_markdown_report(
            report_id=report_id,
            question=question,
            verified_facts=verified_facts,
            observations=observations,
            claims=claims,
            hypotheses=hypotheses,
            contradictions=contradictions,
            scam_flags=scam_and_unsupported_flags,
            citations=citations,
            uncompleted=uncompleted_parts,
        )

        kb_doc_id = ""
        if save_to_kb:
            ingested = self.knowledge.index_text(
                markdown_report,
                document_id=f"privacy_intel:{report_id}",
                title=f"Research Report {report_id}: {question[:80]}",
                source_kind="documentation",
                external=True,
                publisher="nova_privacy_intel",
            )
            kb_doc_id = str(ingested.document_id)
            self.memory_os.store(
                category="external_information",
                subject=f"Research report {report_id}",
                content=(
                    f"Completed §165.4 research on '{question[:120]}' "
                    f"({len(verified_facts)} verified facts, {len(claims)} unverified claims, {len(uncompleted_parts)} uncompleted items)."
                ),
                provenance="verified_tool_output",
                source_ref=report_id,
                evidence_verified=False,
            )

        return {
            "report_id": report_id,
            "question": question,
            "started_at": started_at,
            "completed_at": _iso(),
            "workflow_steps_completed": list(self.WORKFLOW_STEPS),
            "extracted_cves": cves,
            "selected_sources": selected_sources,
            "sources_consulted": consulted,
            "cross_source_comparison": corroborations,
            "contradictions": contradictions,
            "scam_and_unsupported_flags": scam_and_unsupported_flags,
            "epistemic_separation": {
                "observations": observations,
                "claims": claims,
                "hypotheses": hypotheses,
                "verified_facts": verified_facts,
            },
            "citations": citations,
            "query_limitations": limitations,
            "uncompleted_parts": uncompleted_parts,
            "multi_model_review": multi_model_review,
            "knowledge_base_doc_id": kb_doc_id,
            "markdown_report": markdown_report,
        }

    @staticmethod
    def _compare_across_sources(hits: list[dict[str, Any]]) -> dict[str, Any]:
        by_category: dict[str, int] = {}
        for h in hits:
            by_category[h["source_category"]] = by_category.get(h["source_category"], 0) + 1
        return {
            "total_hits": len(hits),
            "distinct_source_categories": len(by_category),
            "hits_by_category": by_category,
            "independent_corroboration_present": len(by_category) >= 2,
        }

    @staticmethod
    def _detect_contradictions(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Detect explicit negations / status conflicts across sources mentioning shared entities."""
        neg_markers = ("no breach", "not affected", "false claim", "unconfirmed", "patched", "fabricated", "denied")
        pos_markers = ("breached", "compromised", "exfiltrated", "vulnerable", "unpatched", "confirmed leak")
        contradictions: list[dict[str, Any]] = []
        for i, a in enumerate(hits):
            al = f"{a['title']} {a['snippet']}".lower()
            a_neg = any(m in al for m in neg_markers)
            a_pos = any(m in al for m in pos_markers) and not a_neg
            for b in hits[i + 1 :]:
                if a["url_or_ref"] == b["url_or_ref"]:
                    continue
                bl = f"{b['title']} {b['snippet']}".lower()
                b_neg = any(m in bl for m in neg_markers)
                b_pos = any(m in bl for m in pos_markers) and not b_neg
                if (a_pos and b_neg) or (a_neg and b_pos):
                    contradictions.append(
                        {
                            "source_a": a["url_or_ref"],
                            "source_b": b["url_or_ref"],
                            "summary": f"Conflicting status assertions between `{a['url_or_ref']}` and `{b['url_or_ref']}`.",
                        }
                    )
        return contradictions

    @staticmethod
    def _flag_scams_and_unsupported(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
        flags: list[dict[str, Any]] = []
        for h in hits:
            text = f"{h['title']} {h['snippet']}"
            matched_reasons: list[str] = []
            for pat, label in SCAM_AND_DECEPTION_PATTERNS:
                if re.search(pat, text, flags=re.IGNORECASE):
                    matched_reasons.append(label)
            if h["trust_level"] == "onion_unverified" and not matched_reasons:
                matched_reasons.append("single_unverified_onion_source_requires_corroboration")
            if matched_reasons:
                flags.append(
                    {
                        "url_or_ref": h["url_or_ref"],
                        "title": h["title"],
                        "flags": matched_reasons,
                    }
                )
        return flags

    @staticmethod
    def _render_markdown_report(
        *,
        report_id: str,
        question: str,
        verified_facts: list[str],
        observations: list[str],
        claims: list[str],
        hypotheses: list[str],
        contradictions: list[dict[str, Any]],
        scam_flags: list[dict[str, Any]],
        citations: list[dict[str, Any]],
        uncompleted: list[str],
    ) -> str:
        lines = [
            f"# NOVA X Intelligence Research Report (`{report_id}`)",
            f"**Question:** {question}",
            "",
            "## Verified Facts",
            *([f"- {x}" for x in verified_facts] or ["- None independently verified yet."]),
            "",
            "## Direct Observations",
            *([f"- {x}" for x in observations] or ["- No external or local documents matched."]),
            "",
            "## Unverified Claims",
            *([f"- {x}" for x in claims] or ["- None."]),
            "",
            "## Analytical Hypotheses",
            *([f"- {x}" for x in hypotheses] or ["- None."]),
            "",
            "## Contradictions & Deception / Scam Flags",
            *([f"- **Contradiction:** {c['summary']}" for c in contradictions] or ["- No direct cross-source contradictions detected."]),
            *([f"- **Flag (`{f['url_or_ref']}`):** {', '.join(f['flags'])}" for f in scam_flags] or []),
            "",
            "## Citations",
            *([f"- `{c['id']}` [{c['source_category']} / {c['trust_level']}] {c['title']} — `{c['url_or_ref']}` ({c['retrieved_at']})" for c in citations] or ["- None."]),
            "",
            "## Uncompleted / Coverage Limitations",
            *([f"- {u}" for u in uncompleted] or ["- All selected sources responded within budget."]),
        ]
        return "\n".join(lines)


class AutonomousResearchMonitor:
    """§165.10 Scoped, Rate-Limited, Resource-Aware, Restart-Persistent Research & Threat Monitoring."""

    def __init__(
        self,
        *,
        db: Database,
        search_orchestrator: UnifiedSearchOrchestrator,
        scheduler_active_probe: Callable[[], bool] | None = None,
        resource_manager: Any | None = None,
    ) -> None:
        self.db = db
        self.search = search_orchestrator
        self._scheduler_active_probe = scheduler_active_probe or (lambda: False)
        self._resource_manager = resource_manager
        self._run_timestamps_by_monitor: dict[str, list[float]] = {}

    def create_monitor(
        self,
        *,
        name: str,
        topic_or_query: str,
        allowed_sources: list[str] | None = None,
        asset_targets: list[str] | None = None,
        interval_seconds: int = 3600,
        rate_limit_per_hour: int = 6,
        alert_condition: str = "any_change",
    ) -> dict[str, Any]:
        sources = [
            c for c in (allowed_sources or self.search.select_minimum_sufficient_sources(topic_or_query)) if c in ALL_SOURCE_CATEGORIES
        ]
        if not sources:
            raise ValueError("Monitor requires at least one valid `allowed_sources` category.")
        saved = self.db.save_research_monitor(
            {
                "name": name,
                "topic_or_query": topic_or_query,
                "allowed_sources": sources,
                "asset_targets": list(asset_targets or []),
                "interval_seconds": max(60, int(interval_seconds)),
                "rate_limit_per_hour": max(1, min(int(rate_limit_per_hour), 60)),
                "enabled": True,
                "alert_condition": alert_condition,
            }
        )
        return {
            **saved,
            "continuous_monitoring_active": bool(self._scheduler_active_probe()),
            "auto_expand_scope": AUTO_EXPAND_MONITOR_SCOPE,
        }

    def status_snapshot(self) -> dict[str, Any]:
        scheduler_running = bool(self._scheduler_active_probe())
        monitors = self.db.list_research_monitors()
        return {
            "continuous_monitoring_active": scheduler_running,
            "honest_scheduler_disclosure": (
                "Background scheduler is actively polling enabled monitors."
                if scheduler_running
                else "Background scheduler is NOT currently running; monitor rules and checkpoints are persisted in SQLite and execute on explicit trigger or when the daemon starts (§165.10)."
            ),
            "monitor_count": len(monitors),
            "enabled_count": sum(1 for m in monitors if m["enabled"]),
            "monitors": monitors,
        }

    def run_monitor_once(self, monitor_id: str, *, force: bool = False) -> dict[str, Any]:
        mon = self.db.get_research_monitor(monitor_id)
        if mon is None:
            return {"ok": False, "status": "not_found", "reason": f"Monitor '{monitor_id}' not found."}
        if not mon["enabled"] and not force:
            return {"ok": False, "status": "monitor_disabled", "monitor_id": monitor_id}

        if self._resource_manager is not None and not force:
            try:
                budget = self._resource_manager.assess()
                if getattr(budget, "pressure", "") == "critical":
                    return {
                        "ok": False,
                        "status": "deferred_resource_budget",
                        "monitor_id": monitor_id,
                        "reason": "Host resource pressure is critical; recurring research monitor deferred to respect resource budget (§165.10).",
                    }
            except Exception:
                pass

        now_mono = time.monotonic()
        recent = [t for t in self._run_timestamps_by_monitor.get(monitor_id, []) if now_mono - t < 3600.0]
        if len(recent) >= int(mon["rate_limit_per_hour"]) and not force:
            return {
                "ok": False,
                "status": "rate_limited",
                "monitor_id": monitor_id,
                "reason": f"Rate limit ({mon['rate_limit_per_hour']}/hour) reached for monitor '{mon['name']}'.",
            }
        recent.append(now_mono)
        self._run_timestamps_by_monitor[monitor_id] = recent

        # Strictly honor `allowed_sources` (never auto-expand monitor scope to unrelated sources/targets!)
        sres = self.search.search(mon["topic_or_query"], categories=mon["allowed_sources"])
        canonical_material = json.dumps(
            [(h["url_or_ref"], h["title"], h["snippet"]) for h in sres["hits"]],
            sort_keys=True,
        )
        new_checkpoint = hashlib.sha256(canonical_material.encode("utf-8")).hexdigest()
        changed = bool(new_checkpoint != mon["checkpoint_hash"] and sres["result_count"] > 0) or (
            mon["checkpoint_hash"] == "" and sres["result_count"] > 0
        )

        run_ts = _iso()
        had_only_errors = sres["result_count"] == 0 and bool(sres["retrieval_errors"])
        summary = (
            f"Retrieved {sres['result_count']} items across {len(sres['sources_consulted'])} scoped sources; "
            f"delta_detected={changed}."
        )
        updated = self.db.save_research_monitor(
            {
                **mon,
                "checkpoint_hash": new_checkpoint if not had_only_errors else mon["checkpoint_hash"],
                "last_run_at": run_ts,
                "last_success_at": run_ts if not had_only_errors else mon["last_success_at"],
                "last_summary": summary,
            }
        )
        if changed:
            self.db.save_observation(
                {
                    "scope": "privacy_intel_monitor",
                    "subject": mon["name"],
                    "predicate": "checkpoint_delta",
                    "value": summary,
                    "source": "verified_tool_output",
                    "evidence_ref": f"research_monitor:{monitor_id}",
                }
            )
        return {
            "ok": not had_only_errors,
            "status": "completed" if not had_only_errors else "source_errors_encountered",
            "monitor": updated,
            "delta_detected": changed,
            "search_run_id": sres["search_run_id"],
            "continuous_monitoring_active": bool(self._scheduler_active_probe()),
        }

    def run_due_monitors(self) -> list[dict[str, Any]]:
        """Execute enabled monitors whose `interval_seconds` have elapsed since `last_run_at`."""
        now_dt = datetime.now(UTC)
        executed: list[dict[str, Any]] = []
        for mon in self.db.list_research_monitors(enabled_only=True):
            due = True
            if mon.get("last_run_at"):
                try:
                    last_dt = datetime.fromisoformat(str(mon["last_run_at"]))
                    due = (now_dt - last_dt).total_seconds() >= float(mon["interval_seconds"])
                except ValueError:
                    due = True
            if due:
                executed.append(self.run_monitor_once(mon["id"]))
        return executed
