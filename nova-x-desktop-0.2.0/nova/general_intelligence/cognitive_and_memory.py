"""§236 Unified Cognitive Architecture, §237 Multi-Layer Memory, §238 Dynamic World Model, and §256 Information Provenance."""
from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from nova.db import Database
from nova.knowledge import KnowledgeStore
from nova.observability import Redactor

DISCONNECTED_AGENT_REALITIES = False
SILENT_DESTRUCTIVE_MEMORY_OVERWRITE = False

COGNITIVE_11_SUBSYSTEMS: tuple[str, ...] = (
    "perception_system",
    "working_memory",
    "episodic_memory",
    "semantic_memory",
    "procedural_memory",
    "reasoning_engine",
    "planning_engine",
    "action_engine",
    "metacognitive_engine",
    "learning_engine",
    "executive_coordinator",
)

SUPPORTED_PERCEPT_MODALITIES: tuple[str, ...] = (
    "text",
    "voice",
    "document",
    "screenshot",
    "image",
    "video",
    "application_state",
    "system_information",
)

MEMORY_11_LAYERS: tuple[str, ...] = (
    "immediate_working_memory",
    "conversation_memory",
    "episodic_memory",
    "semantic_memory",
    "procedural_memory",
    "project_memory",
    "technical_knowledge",
    "personal_preference_memory",
    "environmental_memory",
    "experimental_memory",
    "long_term_goal_memory",
)

CLAIM_8_ORIGINS: tuple[str, ...] = (
    "direct_user_statement",
    "official_documentation",
    "external_publication",
    "tool_observation",
    "measurement",
    "experimental_result",
    "model_generated_hypothesis",
    "inferred_conclusion",
)

EMPIRICAL_VERIFIED_ORIGINS: frozenset[str] = frozenset(
    {"tool_observation", "measurement", "experimental_result"}
)

WORLD_15_DOMAINS: tuple[str, ...] = (
    "computer_hardware",
    "operating_systems",
    "applications",
    "drivers",
    "files",
    "processes",
    "services",
    "networks",
    "servers",
    "databases",
    "software_projects",
    "ai_providers",
    "user_defined_goals",
    "external_information_sources",
    "connected_tools",
)

WORLD_RELATIONSHIP_TYPES: tuple[str, ...] = (
    "depends_on_package",
    "depends_on_config_file",
    "depends_on_interface",
    "depends_on_route",
    "depends_on_driver",
    "depends_on_permission",
    "depends_on_runtime",
    "depends_on_task",
    "connects_to",
    "monitors",
)

_SECRET_GUARD_RE = re.compile(
    r"(?i)(\b(?:password|passwd|api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*\S+)"
)
_UNSUPPORTED_GENERALIZATION_RE = re.compile(
    r"(?i)\b(always\s+guaranteed|never\s+fails\s+under\s+any\s+condition|100%\s+bug[-\s]?free|universally\s+true\s+everywhere)\b"
)


def _iso(dt: datetime | None = None) -> str:
    return (dt or datetime.now(UTC)).isoformat(timespec="microseconds")


def _parse_iso(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


def _fingerprint(subject: str, content: str) -> str:
    norm = re.sub(r"\s+", " ", f"{subject.strip().lower()}::{content.strip().lower()}")
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:32]


class MultiLayerMemoryAndProvenanceEngine:
    """§237 Multi-Layer Memory Architecture & §256 Knowledge Quality / Information Provenance."""

    def __init__(
        self,
        *,
        db: Database,
        knowledge: KnowledgeStore | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        self.db = db
        self.knowledge = knowledge
        self.redactor = redactor or Redactor()

    def record_memory(
        self,
        *,
        layer: str,
        subject: str,
        content: str,
        attribute_key: str = "",
        claim_origin: str = "direct_user_statement",
        independently_tested: bool = False,
        source_ref: str = "",
        related_concepts: list[str] | None = None,
        relevant_projects: list[str] | None = None,
        ttl_hours: float | None = None,
        confidence_score: float | None = None,
    ) -> dict[str, Any]:
        if layer not in MEMORY_11_LAYERS:
            raise ValueError(f"Unsupported memory layer '{layer}'. Valid: {', '.join(MEMORY_11_LAYERS)}")
        if claim_origin not in CLAIM_8_ORIGINS:
            raise ValueError(f"Unsupported claim origin '{claim_origin}'. Valid: {', '.join(CLAIM_8_ORIGINS)}")
        if _SECRET_GUARD_RE.search(subject) or _SECRET_GUARD_RE.search(content):
            raise ValueError("Refusing to store plaintext credentials or private tokens in cognitive memory.")

        clean_subj = self.redactor.scrub_text(subject.strip())
        clean_content = self.redactor.scrub_text(content.strip())
        fp = _fingerprint(clean_subj, clean_content)

        # Deduplication check: if exact subject+content already active in this layer, refresh verification metadata.
        existing_same = [
            m
            for m in self.db.list_gi_memories(layer=layer, subject=clean_subj, limit=50)
            if m["fingerprint"] == fp and not m["superseded_by"]
        ]
        now = _iso()
        is_emp_verified = bool(independently_tested and claim_origin in EMPIRICAL_VERIFIED_ORIGINS)
        verification_mode = "independently_verified" if is_emp_verified else (
            "hypothesis_unverified" if claim_origin in {"model_generated_hypothesis", "inferred_conclusion"} else "source_reported"
        )
        evidence_status = (
            "Verified"
            if is_emp_verified
            else "Strongly supported"
            if (claim_origin in {"official_documentation", "external_publication"} and bool(source_ref.strip()))
            else "Probable"
            if claim_origin == "direct_user_statement"
            else "Untested"
        )
        base_conf = (
            0.95
            if is_emp_verified
            else 0.80
            if evidence_status == "Strongly supported"
            else 0.65
            if evidence_status == "Probable"
            else 0.35
        )
        if confidence_score is not None:
            base_conf = max(0.05, min(float(confidence_score), 0.99 if is_emp_verified else 0.85))

        quality_flags = self.inspect_claim_quality(
            content=clean_content,
            claim_origin=claim_origin,
            source_ref=source_ref,
            independently_tested=is_emp_verified,
        )
        if quality_flags["weak_evidence"] or quality_flags["unsupported_generalization"]:
            base_conf = min(base_conf, 0.40)
            if evidence_status not in {"Untested", "Uncertain"}:
                evidence_status = "Uncertain"

        exp_at = _iso(datetime.now(UTC) + timedelta(hours=float(ttl_hours))) if ttl_hours is not None else ""

        if existing_same:
            target = existing_same[0]
            merged_concepts = sorted(set(target["related_concepts"]) | set(related_concepts or []))
            merged_projects = sorted(set(target["relevant_projects"]) | set(relevant_projects or []))
            saved = self.db.save_gi_memory(
                {
                    **target,
                    "verification_mode": verification_mode if is_emp_verified else target["verification_mode"],
                    "evidence_status": evidence_status if is_emp_verified else target["evidence_status"],
                    "confidence_score": max(float(target["confidence_score"]), base_conf),
                    "related_concepts": merged_concepts,
                    "relevant_projects": merged_projects,
                    "last_verified_at": now if is_emp_verified else target["last_verified_at"],
                    "review_or_expiration_at": exp_at or target["review_or_expiration_at"],
                }
            )
            return {
                "stored": True,
                "deduplicated": True,
                "entry": saved,
                "quality_inspection": quality_flags,
                "contradictions": self.detect_contradictions(subject=clean_subj),
            }

        saved = self.db.save_gi_memory(
            {
                "layer": layer,
                "subject": clean_subj,
                "attribute_key": attribute_key.strip(),
                "content": clean_content,
                "fingerprint": fp,
                "claim_origin": claim_origin,
                "verification_mode": verification_mode,
                "evidence_status": evidence_status,
                "confidence_score": round(base_conf, 4),
                "source_ref": self.redactor.scrub_text(source_ref.strip()),
                "related_concepts": sorted({c.strip() for c in (related_concepts or []) if c.strip()}),
                "relevant_projects": sorted({p.strip() for p in (relevant_projects or []) if p.strip()}),
                "review_or_expiration_at": exp_at,
                "correction_history": [],
                "created_at": now,
                "last_verified_at": now if is_emp_verified else "",
            }
        )
        if self.knowledge is not None:
            self.knowledge.index_text(
                f"{clean_subj} {attribute_key}\n{clean_content}",
                document_id=f"gimem:{saved['id']}",
                title=f"[{layer}] {clean_subj}",
                source_kind="tool_result" if is_emp_verified else "documentation",
                project=(relevant_projects or [""])[0],
                external=claim_origin in {"external_publication", "official_documentation"},
                publisher=claim_origin,
            )
        contradictions = self.detect_contradictions(subject=clean_subj)
        return {
            "stored": True,
            "deduplicated": False,
            "entry": saved,
            "quality_inspection": quality_flags,
            "contradictions": contradictions,
        }

    @staticmethod
    def inspect_claim_quality(
        *,
        content: str,
        claim_origin: str,
        source_ref: str,
        independently_tested: bool,
    ) -> dict[str, Any]:
        missing_citation = claim_origin in {"official_documentation", "external_publication"} and not bool(source_ref.strip())
        unsupported_gen = bool(_UNSUPPORTED_GENERALIZATION_RE.search(content)) and not independently_tested
        weak_evidence = (
            claim_origin in {"model_generated_hypothesis", "inferred_conclusion"}
            and not independently_tested
        ) or missing_citation
        return {
            "missing_citation": missing_citation,
            "unsupported_generalization": unsupported_gen,
            "weak_evidence": weak_evidence,
            "source_vs_verified_distinction": "independently_verified" if independently_tested else "source_or_hypothesis",
        }

    def detect_contradictions(self, *, subject: str = "") -> list[dict[str, Any]]:
        """§237 & §256 Detect contradictory claims across active memories."""
        records = [
            m
            for m in self.db.list_gi_memories(subject=subject, limit=400)
            if not m["superseded_by"] and not m["forgotten"]
        ]
        by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for rec in records:
            key = (rec["subject"].strip().lower(), (rec["attribute_key"] or "general").strip().lower())
            by_key.setdefault(key, []).append(rec)

        contradictions: list[dict[str, Any]] = []
        for (subj, attr), group in by_key.items():
            if len(group) < 2:
                continue
            distinct_contents = {g["fingerprint"]: g for g in group}
            if len(distinct_contents) < 2:
                continue
            items = list(distinct_contents.values())
            # Flag contradiction when attribute_key is explicitly shared or negation polarity conflicts
            has_explicit_attr = attr != "general"
            neg_conflict = any(
                bool(re.search(r"\b(not|disabled|false|offline|failed|absent)\b", a["content"], re.I))
                != bool(re.search(r"\b(not|disabled|false|offline|failed|absent)\b", b["content"], re.I))
                for i, a in enumerate(items)
                for b in items[i + 1 :]
            )
            num_vals = {
                m.group(0)
                for it in items
                for m in re.finditer(r"\b\d+(?:\.\d+)?\b", it["content"])
            }
            if has_explicit_attr or neg_conflict or len(num_vals) >= 2:
                contradictions.append(
                    {
                        "subject": subj,
                        "attribute_key": attr,
                        "conflicting_memory_ids": [it["id"] for it in items],
                        "claims": [
                            {
                                "id": it["id"],
                                "content": it["content"],
                                "claim_origin": it["claim_origin"],
                                "verification_mode": it["verification_mode"],
                                "evidence_status": it["evidence_status"],
                                "source_ref": it["source_ref"],
                            }
                            for it in items
                        ],
                    }
                )
        return contradictions

    def update_memory_preserving_history(
        self,
        memory_id: str,
        *,
        new_content: str,
        claim_origin: str = "measurement",
        independently_tested: bool = True,
        source_ref: str = "",
        reason: str = "empirical_reverification",
    ) -> dict[str, Any]:
        """§237 Allow knowledge to be updated without silently destroying historically important information."""
        old = self.db.get_gi_memory(memory_id)
        if old is None:
            raise KeyError(f"Memory '{memory_id}' not found.")
        history = list(old["correction_history"])
        history.append(
            {
                "archived_at": _iso(),
                "previous_content": old["content"],
                "previous_claim_origin": old["claim_origin"],
                "previous_verification_mode": old["verification_mode"],
                "previous_evidence_status": old["evidence_status"],
                "previous_source_ref": old["source_ref"],
                "reason": reason,
            }
        )
        clean_new = self.redactor.scrub_text(new_content.strip())
        is_verified = bool(independently_tested and claim_origin in EMPIRICAL_VERIFIED_ORIGINS)
        updated = self.db.save_gi_memory(
            {
                **old,
                "content": clean_new,
                "fingerprint": _fingerprint(old["subject"], clean_new),
                "claim_origin": claim_origin,
                "verification_mode": "independently_verified" if is_verified else "source_reported",
                "evidence_status": "Verified" if is_verified else "Probable",
                "confidence_score": 0.96 if is_verified else 0.70,
                "source_ref": source_ref or old["source_ref"],
                "correction_history": history,
                "last_verified_at": _iso() if is_verified else old["last_verified_at"],
            }
        )
        # Mark conflicting unverified siblings on same subject+attribute_key as superseded while keeping them inspectable
        if old["attribute_key"]:
            siblings = self.db.list_gi_memories(subject=old["subject"], limit=100)
            for sib in siblings:
                if (
                    sib["id"] != updated["id"]
                    and sib["attribute_key"] == old["attribute_key"]
                    and sib["verification_mode"] != "independently_verified"
                    and not sib["superseded_by"]
                ):
                    sib_hist = list(sib["correction_history"])
                    sib_hist.append({"superseded_at": _iso(), "superseded_by": updated["id"], "reason": reason})
                    self.db.save_gi_memory({**sib, "superseded_by": updated["id"], "correction_history": sib_hist})
        return updated

    def detect_outdated_memories(self, *, reference_time: datetime | None = None) -> list[dict[str, Any]]:
        ref = reference_time or datetime.now(UTC)
        outdated: list[dict[str, Any]] = []
        for m in self.db.list_gi_memories(limit=500):
            if m["superseded_by"]:
                outdated.append({"id": m["id"], "subject": m["subject"], "reason": f"superseded_by:{m['superseded_by']}"})
                continue
            exp = _parse_iso(m["review_or_expiration_at"])
            if exp is not None and exp <= ref:
                outdated.append({"id": m["id"], "subject": m["subject"], "reason": "review_or_expiration_elapsed"})
        return outdated

    def consolidate_temporary_memories(self, *, min_confidence: float = 0.60) -> dict[str, Any]:
        """§237 Consolidate salient temporary experiences into durable long-term memory layers."""
        temp_layers = ("immediate_working_memory", "conversation_memory", "experimental_memory")
        promoted: list[dict[str, Any]] = []
        for layer in temp_layers:
            for item in self.db.list_gi_memories(layer=layer, limit=150):
                if float(item["confidence_score"]) < min_confidence or item["superseded_by"]:
                    continue
                target_layer = (
                    "procedural_memory"
                    if "procedure" in item["subject"].lower() or "workflow" in item["content"].lower()
                    else "technical_knowledge"
                    if item["verification_mode"] == "independently_verified"
                    else "semantic_memory"
                )
                res = self.record_memory(
                    layer=target_layer,
                    subject=item["subject"],
                    attribute_key=item["attribute_key"],
                    content=item["content"],
                    claim_origin=item["claim_origin"],
                    independently_tested=(item["verification_mode"] == "independently_verified"),
                    source_ref=item["source_ref"] or f"consolidated_from:{item['id']}",
                    related_concepts=item["related_concepts"],
                    relevant_projects=item["relevant_projects"],
                    confidence_score=float(item["confidence_score"]),
                )
                promoted.append({"from_id": item["id"], "to_id": res["entry"]["id"], "target_layer": target_layer})
        return {"consolidated_count": len(promoted), "promoted": promoted}

    def run_controlled_forgetting(self, *, reference_time: datetime | None = None) -> dict[str, Any]:
        """§237 Controlled forgetting of expired low-confidence transient memories; never deletes verified history."""
        ref = reference_time or datetime.now(UTC)
        forgotten_ids: list[str] = []
        protected_ids: list[str] = []
        for m in self.db.list_gi_memories(limit=500):
            exp = _parse_iso(m["review_or_expiration_at"])
            if exp is None or exp > ref:
                continue
            if m["verification_mode"] == "independently_verified" or m["layer"] in {
                "procedural_memory",
                "long_term_goal_memory",
                "personal_preference_memory",
            }:
                protected_ids.append(m["id"])
                continue
            if float(m["confidence_score"]) < 0.75:
                hist = list(m["correction_history"])
                hist.append({"forgotten_at": _iso(ref), "reason": "controlled_expiration_low_salience"})
                self.db.save_gi_memory({**m, "forgotten": True, "correction_history": hist})
                forgotten_ids.append(m["id"])
        return {"forgotten_count": len(forgotten_ids), "forgotten_ids": forgotten_ids, "protected_count": len(protected_ids)}

    def search_memories(self, query: str, *, layer: str = "", project: str = "", limit: int = 20) -> dict[str, Any]:
        tokens = list(re.findall(r"[a-z0-9_\-]{2,}", query.lower()))
        candidates = self.db.list_gi_memories(layer=layer, limit=400)
        scored: list[tuple[float, dict[str, Any]]] = []
        for m in candidates:
            if m["superseded_by"]:
                continue
            if project and project not in m["relevant_projects"]:
                continue
            hay = " ".join(
                [m["subject"], m["attribute_key"], m["content"], " ".join(m["related_concepts"])]
            ).lower()
            hits = sum(1 for t in tokens if t in hay) if tokens else 1
            if hits == 0:
                continue
            ver_bonus = 0.35 if m["verification_mode"] == "independently_verified" else 0.0
            score = hits + float(m["confidence_score"]) + ver_bonus
            scored.append((score, m))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        results = [item for _, item in scored[: max(1, min(int(limit), 100))]]
        related_graph_concepts = sorted({c for item in results for c in item["related_concepts"]})
        return {
            "query": query,
            "count": len(results),
            "results": results,
            "related_graph_concepts": related_graph_concepts,
        }


class DynamicEnvironmentWorldModel:
    """§238 Continuously updateable World Model across 15 domains with Observation vs Prediction separation."""

    def __init__(self, *, db: Database, workspace_dir: Path) -> None:
        self.db = db
        self.workspace_dir = workspace_dir

    def register_entity(
        self,
        *,
        entity_id: str,
        domain: str,
        name: str,
        attributes: dict[str, Any] | None = None,
        epistemic_kind: str = "observation",
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        if domain not in WORLD_15_DOMAINS:
            raise ValueError(f"Unsupported world domain '{domain}'. Valid: {', '.join(WORLD_15_DOMAINS)}")
        if epistemic_kind not in {"observation", "prediction"}:
            raise ValueError("epistemic_kind must be 'observation' or 'prediction'.")
        existing = [r for r in self.db.list_gi_world_records(record_type="entity", limit=500) if r["id"] == entity_id]
        prev_state = existing[0]["state"] if existing else {}
        transitions = list(prev_state.get("transitions") or [])
        new_attrs = dict(attributes or {})
        if prev_state.get("attributes") and prev_state.get("attributes") != new_attrs:
            transitions.append(
                {
                    "at": _iso(),
                    "from_status": prev_state["attributes"].get("status", "unknown"),
                    "to_status": new_attrs.get("status", "unknown"),
                }
            )
            transitions = transitions[-10:]
        return self.db.upsert_gi_world_record(
            {
                "id": entity_id,
                "record_type": "entity",
                "domain": domain,
                "name": name,
                "epistemic_kind": epistemic_kind,
                "ttl_seconds": int(ttl_seconds),
                "observed_at": _iso(),
                "state": {"attributes": new_attrs, "transitions": transitions},
            }
        )

    def register_dependency(
        self,
        *,
        source_entity_id: str,
        relation: str,
        target_entity_id: str,
        criticality: str = "required",
    ) -> dict[str, Any]:
        edge_id = f"edge:{source_entity_id}->{relation}->{target_entity_id}"
        return self.db.upsert_gi_world_record(
            {
                "id": edge_id,
                "record_type": "edge",
                "domain": "connected_tools",
                "name": relation,
                "epistemic_kind": "observation",
                "ttl_seconds": 3600,
                "observed_at": _iso(),
                "state": {
                    "source": source_entity_id,
                    "relation": relation,
                    "target": target_entity_id,
                    "criticality": criticality,
                },
            }
        )

    def predict_action_side_effects(
        self,
        target_entity_id: str,
        proposed_action: str,
    ) -> dict[str, Any]:
        """§238 Predict downstream side effects and transitive dependencies BEFORE taking action."""
        edges = self.db.list_gi_world_records(record_type="edge", limit=1000)
        entities = {e["id"]: e for e in self.db.list_gi_world_records(record_type="entity", limit=1000)}

        # Reverse adjacency: if target_entity_id changes/stops, who depends on it?
        rev_adj: dict[str, list[dict[str, Any]]] = {}
        fwd_adj: dict[str, list[dict[str, Any]]] = {}
        for edge in edges:
            st = edge["state"]
            rev_adj.setdefault(st["target"], []).append(st)
            fwd_adj.setdefault(st["source"], []).append(st)

        impacted: list[dict[str, Any]] = []
        visited: set[str] = {target_entity_id}
        queue: list[tuple[str, int, str]] = [(target_entity_id, 0, "direct_target")]
        while queue:
            curr, depth, via = queue.pop(0)
            for dep_edge in rev_adj.get(curr, []):
                dependent_id = dep_edge["source"]
                if dependent_id in visited:
                    continue
                visited.add(dependent_id)
                ent = entities.get(dependent_id, {"domain": "unknown", "name": dependent_id})
                impacted.append(
                    {
                        "entity_id": dependent_id,
                        "name": ent.get("name", dependent_id),
                        "domain": ent.get("domain", "unknown"),
                        "dependency_relation": dep_edge["relation"],
                        "criticality": dep_edge.get("criticality", "required"),
                        "hop_distance": depth + 1,
                        "via": via,
                    }
                )
                queue.append((dependent_id, depth + 1, dep_edge["relation"]))

        prerequisites = [
            {
                "prerequisite_id": d["target"],
                "relation": d["relation"],
                "criticality": d.get("criticality", "required"),
            }
            for d in fwd_adj.get(target_entity_id, [])
        ]

        destructive = any(w in proposed_action.lower() for w in ("remove", "delete", "stop", "disable", "overwrite", "down"))
        risk_level = (
            "high"
            if (destructive and any(i["criticality"] == "required" for i in impacted))
            else "medium"
            if impacted
            else "low"
        )
        prediction_rec = self.db.upsert_gi_world_record(
            {
                "id": f"pred:{target_entity_id}:{hashlib.sha256(proposed_action.encode()).hexdigest()[:8]}",
                "record_type": "prediction",
                "domain": entities.get(target_entity_id, {}).get("domain", "applications"),
                "name": f"Predicted impact of '{proposed_action}' on {target_entity_id}",
                "epistemic_kind": "prediction",
                "ttl_seconds": 120,
                "observed_at": _iso(),
                "state": {
                    "target_entity_id": target_entity_id,
                    "proposed_action": proposed_action,
                    "impacted_dependents": impacted,
                    "direct_prerequisites": prerequisites,
                    "risk_level": risk_level,
                },
            }
        )
        return {
            "epistemic_kind": "prediction",
            "is_confirmed_observation": False,
            "target_entity_id": target_entity_id,
            "proposed_action": proposed_action,
            "risk_level": risk_level,
            "impacted_dependents": impacted,
            "direct_prerequisites": prerequisites,
            "prediction_record_id": prediction_rec["id"],
        }

    def refresh_host_observations(self, *, tool_names: list[str] | None = None) -> dict[str, Any]:
        """§238 Continuously refresh real host hardware, OS, filesystem, and tool observations."""
        disk = shutil.disk_usage(self.workspace_dir if self.workspace_dir.exists() else "/")
        now_dt = datetime.now(UTC)
        self.register_entity(
            entity_id="hw:local_host",
            domain="computer_hardware",
            name=platform.machine() or "x86_64",
            attributes={
                "cpu_count": os.cpu_count() or 1,
                "disk_free_gb": round(disk.free / (1024**3), 2),
                "status": "online",
            },
            epistemic_kind="observation",
            ttl_seconds=120,
        )
        self.register_entity(
            entity_id="os:local_kernel",
            domain="operating_systems",
            name=f"{platform.system()} {platform.release()}",
            attributes={"system": platform.system(), "release": platform.release(), "python": platform.python_version(), "status": "running"},
            epistemic_kind="observation",
            ttl_seconds=600,
        )
        self.register_entity(
            entity_id="proj:nova_workspace",
            domain="software_projects",
            name=self.workspace_dir.name,
            attributes={"path": str(self.workspace_dir), "exists": self.workspace_dir.exists(), "status": "ready"},
            epistemic_kind="observation",
            ttl_seconds=180,
        )
        if tool_names:
            self.register_entity(
                entity_id="tools:active_registry",
                domain="connected_tools",
                name="DEV Registered Toolset",
                attributes={"tool_count": len(tool_names), "sample": sorted(tool_names)[:15], "status": "ready"},
                epistemic_kind="observation",
                ttl_seconds=180,
            )

        stale_ids: list[str] = []
        observations = [
            r for r in self.db.list_gi_world_records(record_type="entity", limit=500) if r["epistemic_kind"] == "observation"
        ]
        for obs in observations:
            obs_dt = _parse_iso(obs["observed_at"])
            if obs_dt and (now_dt - obs_dt).total_seconds() > int(obs["ttl_seconds"]):
                stale_ids.append(obs["id"])
        return {
            "observed_entity_count": len(observations),
            "stale_entity_ids": stale_ids,
            "refreshed_at": _iso(now_dt),
        }


class UnifiedCognitiveArchitecture:
    """§236 Coordinates all 11 cognitive subsystems over one versioned SharedCognitiveContext."""

    def __init__(
        self,
        *,
        db: Database,
        memory_engine: MultiLayerMemoryAndProvenanceEngine,
        world_model: DynamicEnvironmentWorldModel,
    ) -> None:
        self.db = db
        self.memory_engine = memory_engine
        self.world_model = world_model

    def perceive_inputs(self, inputs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Perception System: normalizes text, voice, docs, screenshots, images, video, app states, and system info."""
        percepts: list[dict[str, Any]] = []
        for idx, item in enumerate(inputs):
            modality = str(item.get("modality") or "text").strip().lower()
            if modality not in SUPPORTED_PERCEPT_MODALITIES:
                modality = "text"
            payload = str(item.get("content") or item.get("summary") or "")
            source = str(item.get("source") or f"input_{idx}")
            percepts.append(
                {
                    "percept_id": f"p-{idx}-{hashlib.sha256(f'{modality}:{source}:{payload[:120]}'.encode()).hexdigest()[:8]}",
                    "modality": modality,
                    "source": source,
                    "summary": payload[:400],
                    "byte_or_char_len": len(payload),
                    "observed_at": _iso(),
                }
            )
        return percepts

    def run_coordinated_cycle(
        self,
        *,
        context_id: str = "default",
        objective: str,
        inputs: list[dict[str, Any]] | None = None,
        proposed_steps: list[str] | None = None,
        executed_actions: list[dict[str, Any]] | None = None,
        verified_outcome: bool = False,
    ) -> dict[str, Any]:
        """Executes a full coordinated cycle across all 11 cognitive subsystems with a single versioned state."""
        percepts = self.perceive_inputs(inputs or [{"modality": "text", "content": objective, "source": "user_prompt"}])

        # Working Memory update
        wm_res = self.memory_engine.record_memory(
            layer="immediate_working_memory",
            subject=f"context:{context_id}:active_objective",
            content=objective,
            claim_origin="direct_user_statement",
            ttl_hours=12.0,
        )

        # Semantic & Procedural retrieval
        sem_hits = self.memory_engine.search_memories(objective, layer="semantic_memory", limit=5)
        proc_hits = self.memory_engine.search_memories(objective, layer="procedural_memory", limit=5)
        ep_hits = self.memory_engine.search_memories(objective, layer="episodic_memory", limit=5)

        # World Model snapshot
        world_snap = self.world_model.refresh_host_observations()

        # Reasoning & Planning synthesis
        steps = list(proposed_steps or [
            "Inspect perceptual inputs and world-model dependencies",
            "Retrieve applicable validated procedures and semantic facts",
            "Execute bounded authorized actions and collect empirical evidence",
            "Verify outcome against objective criteria and consolidate lessons",
        ])
        actions = list(executed_actions or [])

        # Metacognitive check
        metacog = {
            "objective_understood": bool(objective.strip()),
            "world_stale_count": len(world_snap["stale_entity_ids"]),
            "empirical_actions_recorded": len(actions),
            "epistemic_label": "Verified" if (verified_outcome and len(actions) > 0) else ("Probable" if sem_hits["count"] > 0 else "Untested"),
            "needs_additional_verification": not (verified_outcome and len(actions) > 0),
        }

        # Episodic & Learning updates when actions occurred
        learned_entry_id = ""
        if actions:
            ep = self.memory_engine.record_memory(
                layer="episodic_memory",
                subject=f"episode:{context_id}:{objective[:60]}",
                content=f"Objective '{objective}' executed {len(actions)} action(s); verified={verified_outcome}.",
                claim_origin="tool_observation" if verified_outcome else "inferred_conclusion",
                independently_tested=verified_outcome,
                source_ref=f"context:{context_id}",
            )
            learned_entry_id = ep["entry"]["id"]

        subsystem_states = {
            "perception_system": {"percept_count": len(percepts), "modalities": sorted({p["modality"] for p in percepts}), "percepts": percepts},
            "working_memory": {"memory_id": wm_res["entry"]["id"], "active_objective": objective},
            "episodic_memory": {"recalled_count": ep_hits["count"], "recorded_episode_id": learned_entry_id},
            "semantic_memory": {"recalled_count": sem_hits["count"], "concepts": sem_hits["related_graph_concepts"]},
            "procedural_memory": {"recalled_count": proc_hits["count"]},
            "reasoning_engine": {
                "active_hypothesis": f"Objective '{objective[:80]}' solvable via {len(steps)}-step plan",
                "uncertainty_present": metacog["needs_additional_verification"],
            },
            "planning_engine": {"step_count": len(steps), "steps": steps},
            "action_engine": {"executed_count": len(actions), "actions": actions},
            "metacognitive_engine": metacog,
            "learning_engine": {"learned_episode_id": learned_entry_id, "consolidated": bool(verified_outcome and actions)},
            "executive_coordinator": {
                "coordinated_subsystems": list(COGNITIVE_11_SUBSYSTEMS),
                "consistent_shared_state": True,
                "disconnected_agent_realities": DISCONNECTED_AGENT_REALITIES,
            },
        }
        saved_ctx = self.db.upsert_gi_cognitive_context(
            {
                "context_id": context_id,
                "active_objective": objective,
                "subsystem_states": subsystem_states,
            }
        )
        return {
            "context_id": saved_ctx["context_id"],
            "state_version": saved_ctx["state_version"],
            "active_objective": saved_ctx["active_objective"],
            "subsystems_active": list(COGNITIVE_11_SUBSYSTEMS),
            "subsystem_states": saved_ctx["subsystem_states"],
            "updated_at": saved_ctx["updated_at"],
        }
