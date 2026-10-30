"""§165.11 & §165.12 Unified ToolRegistry Definitions for Privacy Network, Tor,
Legitimate `.onion` Research, Multi-Source OSINT Search, Defensive Threat
Intelligence, Quarantined File Analysis, Optional Onion Hosting & Monitors.

Every §165 capability passes through NOVA X's central `ToolRegistry` and
`AutonomyPolicy` — no model can bypass policy via an alternate connector.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from nova.privacy_intel.service import PrivacyIntelligenceService
from nova.tools.registry import ToolDefinition, ToolOutcome


class EmptyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PrivacyNetworkConfigInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tor_enabled: bool | None = None
    socks_host: str | None = Field(default=None, max_length=255)
    socks_port: int | None = Field(default=None, ge=1, le=65535)
    onion_hosting_enabled: bool | None = None
    component_routing: dict[str, str] | None = None


class OnionOpenInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=8, max_length=1000)
    source_obtained_from: str = Field(default="tool_call", max_length=200)


class OnionVerifyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidate_onion: str = Field(min_length=8, max_length=500)
    documented_official_onion: str = Field(min_length=8, max_length=500)
    reference_source: str = Field(default="", max_length=500)


class AdvancedSearchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=1000)
    categories: list[str] | None = None
    explicit_urls: list[str] | None = None


class DarkWebResearchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=3, max_length=1000)
    explicit_urls: list[str] | None = None
    categories: list[str] | None = None
    save_to_kb: bool = True


class ThreatAnalyzeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(default="External Advisory", max_length=240)
    advisory_text: str = Field(default="", max_length=20_000)
    source_url: str = Field(default="external://advisory", max_length=500)
    is_official_vendor_or_cert: bool = False
    severity: str = Field(default="medium", max_length=24)
    log_text: str = Field(default="", max_length=50_000)
    log_source_label: str = Field(default="supplied_log", max_length=200)
    watch_indicators: list[str] | None = None


class QuarantineDownloadInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=8, max_length=1000)
    max_bytes: int | None = Field(default=None, ge=1024, le=52_428_800)
    extract_archive_isolated: bool = False


class OnionHostingPlanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service_name: str = Field(min_length=2, max_length=48)
    local_bind_host: str = Field(default="127.0.0.1", max_length=64)
    local_bind_port: int = Field(ge=1, le=65535)
    virtual_port: int = Field(default=80, ge=1, le=65535)


class ResearchMonitorInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=200)
    topic_or_query: str = Field(min_length=2, max_length=1000)
    allowed_sources: list[str] | None = None
    asset_targets: list[str] | None = None
    interval_seconds: int = Field(default=3600, ge=60, le=604_800)
    rate_limit_per_hour: int = Field(default=6, ge=1, le=60)


def build_privacy_intel_tools(service_provider: Callable[[], PrivacyIntelligenceService]) -> list[ToolDefinition]:
    """Build `ToolDefinition` instances registered into NOVA X's central `ToolRegistry`."""

    async def _tor_status(_args: BaseModel, _approved: bool) -> ToolOutcome:
        svc = service_provider()
        det = await asyncio.to_thread(svc.tor.detect_installation_and_status)
        dash = await asyncio.to_thread(svc.tor.privacy_dashboard)
        return ToolOutcome(status="success", summary=det["status_indicator"], data={"tor": det, "dashboard": dash})

    async def _configure_network(args: BaseModel, approved: bool) -> ToolOutcome:
        p = PrivacyNetworkConfigInput.model_validate(args.model_dump())
        updates = {k: v for k, v in p.model_dump().items() if v is not None}
        if not approved:
            return ToolOutcome(
                status="approval_required",
                summary="Updating Tor / privacy-network routing configuration requires operator approval.",
                approval_payload={"updates": updates},
            )
        updated = await asyncio.to_thread(service_provider().tor.update_config, updates)
        return ToolOutcome(status="success", summary=f"Updated privacy network config (tor_enabled={updated['tor_enabled']}).", data=updated)

    async def _onion_open(args: BaseModel, approved: bool) -> ToolOutcome:
        p = OnionOpenInput.model_validate(args.model_dump())
        svc = service_provider()
        guard = svc.check_ethics(p.url)
        if not guard["allowed"]:
            return ToolOutcome(status="error", summary=guard["reason"], data=guard)
        if not approved:
            return ToolOutcome(
                status="approval_required",
                summary=f"Opening v3 `.onion` service `{p.url}` over Tor SOCKS5h requires operator approval.",
                approval_payload={"url": p.url},
            )
        res = await asyncio.to_thread(svc.onion_browser.open_onion_page, p.url, source_obtained_from=p.source_obtained_from)
        return ToolOutcome(
            status="success" if res.get("ok") else "error",
            summary=f"Onion status={res.get('status')} ({res.get('title') or res.get('reason', '')})",
            data=res,
        )

    async def _onion_verify(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = OnionVerifyInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().onion_browser.verify_against_official_reference,
            p.candidate_onion,
            p.documented_official_onion,
            reference_source=p.reference_source,
        )
        return ToolOutcome(status="success", summary=f"Onion reference match={res['matched']} ({res['trust_status']}).", data=res)

    async def _advanced_search(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = AdvancedSearchInput.model_validate(args.model_dump())
        svc = service_provider()
        guard = svc.check_ethics(p.query)
        if not guard["allowed"]:
            return ToolOutcome(status="error", summary=guard["reason"], data=guard)
        res = await asyncio.to_thread(
            svc.search.search,
            p.query,
            categories=p.categories,
            explicit_urls=p.explicit_urls,
        )
        return ToolOutcome(
            status="success",
            summary=f"Consulted {len(res['sources_consulted'])} source(s); {res['result_count']} hit(s).",
            data=res,
        )

    async def _dark_web_research(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = DarkWebResearchInput.model_validate(args.model_dump())
        svc = service_provider()
        guard = svc.check_ethics(p.question)
        if not guard["allowed"]:
            return ToolOutcome(status="error", summary=guard["reason"], data=guard)
        res = await asyncio.to_thread(
            svc.research_assistant.conduct_research,
            p.question,
            explicit_urls=p.explicit_urls,
            categories=p.categories,
            save_to_kb=p.save_to_kb,
        )
        ep = res["epistemic_separation"]
        return ToolOutcome(
            status="success",
            summary=(
                f"Research {res['report_id']}: {len(ep['verified_facts'])} verified fact(s), "
                f"{len(ep['claims'])} unverified claim(s), {len(res['scam_and_unsupported_flags'])} scam/risk flag(s)."
            ),
            data=res,
        )

    async def _threat_analyze(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = ThreatAnalyzeInput.model_validate(args.model_dump())
        svc = service_provider()
        if p.log_text.strip():
            res = await asyncio.to_thread(
                svc.threat_intel.analyze_supplied_logs,
                p.log_text,
                log_source_label=p.log_source_label,
                watch_indicators=p.watch_indicators,
            )
            return ToolOutcome(status="success", summary=res["finding"]["summary"], data=res)
        res = await asyncio.to_thread(
            svc.threat_intel.ingest_external_advisory,
            title=p.title,
            advisory_text=p.advisory_text,
            source_url=p.source_url,
            is_official_vendor_or_cert=p.is_official_vendor_or_cert,
            severity=p.severity,
        )
        if not res.get("ok"):
            return ToolOutcome(status="error", summary=str(res.get("reason") or "Blocked"), data=res)
        return ToolOutcome(status="success", summary=res["finding"]["summary"], data=res)

    async def _quarantine_dl(args: BaseModel, approved: bool) -> ToolOutcome:
        p = QuarantineDownloadInput.model_validate(args.model_dump())
        if not approved:
            return ToolOutcome(
                status="approval_required",
                summary=f"Downloading untrusted artifact `{p.url}` into 0700 quarantine requires operator approval.",
                approval_payload={"url": p.url, "auto_execute": False},
            )
        res = await asyncio.to_thread(
            service_provider().downloads.download_and_quarantine_url,
            p.url,
            max_bytes=p.max_bytes,
            extract_archive_isolated=p.extract_archive_isolated,
        )
        return ToolOutcome(
            status="success" if res.get("ok") else "error",
            summary=f"Quarantine status={res.get('status')} (auto_executed=False).",
            data=res,
        )

    async def _onion_hosting_plan(args: BaseModel, approved: bool) -> ToolOutcome:
        p = OnionHostingPlanInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().onion_hosting.prepare_onion_service_plan,
            service_name=p.service_name,
            local_bind_host=p.local_bind_host,
            local_bind_port=p.local_bind_port,
            virtual_port=p.virtual_port,
            operator_approved=approved,
        )
        if res.get("status") == "approval_required":
            return ToolOutcome(
                status="approval_required",
                summary=res["reason"],
                approval_payload=p.model_dump(),
            )
        return ToolOutcome(
            status="success" if res.get("ok") else "error",
            summary=f"Onion hosting plan status={res.get('status')}.",
            data=res,
        )

    async def _monitor_create(args: BaseModel, approved: bool) -> ToolOutcome:
        p = ResearchMonitorInput.model_validate(args.model_dump())
        if not approved:
            return ToolOutcome(
                status="approval_required",
                summary=f"Creating recurring research monitor `{p.name}` requires operator approval.",
                approval_payload=p.model_dump(),
            )
        res = await asyncio.to_thread(
            service_provider().monitors.create_monitor,
            name=p.name,
            topic_or_query=p.topic_or_query,
            allowed_sources=p.allowed_sources,
            asset_targets=p.asset_targets,
            interval_seconds=p.interval_seconds,
            rate_limit_per_hour=p.rate_limit_per_hour,
        )
        return ToolOutcome(status="success", summary=f"Created monitor `{res['name']}` ({res['id']}).", data=res)

    return [
        ToolDefinition(
            name="tor_status_and_dashboard",
            description="Inspect Kali Linux Tor & Tor Browser installation, service state, SOCKS5h reachability, and the 6-component Privacy Network Dashboard (§165.1, §165.8).",
            parameters=EmptyInput.model_json_schema(),
            input_model=EmptyInput,
            handler=_tor_status,
            permission="read_only",
            category="privacy_intel",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="privacy_network_configure",
            description="Enable/disable Tor integration, update SOCKS5h host/port, or configure per-component network routing (§165.1, §165.8).",
            parameters=PrivacyNetworkConfigInput.model_json_schema(),
            input_model=PrivacyNetworkConfigInput,
            handler=_configure_network,
            permission="network_config_write",
            category="privacy_intel",
            autonomy_class="approval_required",
        ),
        ToolDefinition(
            name="onion_open_page",
            description="Open a user-supplied publicly accessible v3 `.onion` URL over isolated Tor SOCKS5h (`ATYP=0x03`), recording timestamps & trust status (§165.2).",
            parameters=OnionOpenInput.model_json_schema(),
            input_model=OnionOpenInput,
            handler=_onion_open,
            permission="tor_onion_read",
            category="privacy_intel",
            autonomy_class="approval_required",
        ),
        ToolDefinition(
            name="onion_verify_reference",
            description="Verify a v3 `.onion` address against an independently documented official onion address (§165.2).",
            parameters=OnionVerifyInput.model_json_schema(),
            input_model=OnionVerifyInput,
            handler=_onion_verify,
            permission="read_only",
            category="privacy_intel",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="advanced_internet_search",
            description="Run §165.3 multi-source OSINT search with minimum-sufficient source selection, recording consulted sources, limitations & errors.",
            parameters=AdvancedSearchInput.model_json_schema(),
            input_model=AdvancedSearchInput,
            handler=_advanced_search,
            permission="network_research",
            category="privacy_intel",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="dark_web_research_report",
            description="Execute the §165.4 12-step research workflow separating observations, claims, hypotheses & verified facts, flagging scams/contradictions, and saving to KnowledgeStore.",
            parameters=DarkWebResearchInput.model_json_schema(),
            input_model=DarkWebResearchInput,
            handler=_dark_web_research,
            permission="network_research",
            category="privacy_intel",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="threat_intel_analyze",
            description="Ingest defensive security advisories or analyze supplied host logs, strictly separating external reports from verified local observations (§165.5).",
            parameters=ThreatAnalyzeInput.model_json_schema(),
            input_model=ThreatAnalyzeInput,
            handler=_threat_analyze,
            permission="defensive_analysis",
            category="privacy_intel",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="quarantine_download_and_analyze",
            description="Download an untrusted artifact into `0700` quarantine (`0400` non-exec), compute SHA-256/512, detect magic MIME, inspect archives safely, and run static analysis without executing (§165.7).",
            parameters=QuarantineDownloadInput.model_json_schema(),
            input_model=QuarantineDownloadInput,
            handler=_quarantine_dl,
            permission="quarantine_write",
            category="privacy_intel",
            autonomy_class="approval_required",
        ),
        ToolDefinition(
            name="onion_hosting_prepare_plan",
            description="Prepare an optional hardened v3 HiddenService deployment plan (disabled by default; blocks NOVA admin API/SSH; isolates keys in 0600 vault; §165.9).",
            parameters=OnionHostingPlanInput.model_json_schema(),
            input_model=OnionHostingPlanInput,
            handler=_onion_hosting_plan,
            permission="service_plan_write",
            category="privacy_intel",
            autonomy_class="approval_required",
        ),
        ToolDefinition(
            name="research_monitor_create",
            description="Create a scoped, rate-limited, restart-persistent recurring research or threat advisory monitor (§165.10).",
            parameters=ResearchMonitorInput.model_json_schema(),
            input_model=ResearchMonitorInput,
            handler=_monitor_create,
            permission="monitor_write",
            category="privacy_intel",
            autonomy_class="approval_required",
        ),
    ]
