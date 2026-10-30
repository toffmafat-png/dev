"""§239 Causal Reasoning & Hypothesis Engine, §240 Metacognition & Calibration, §241 Autonomous Objectives, §242 Strategic Planning."""
from __future__ import annotations

import hashlib
import subprocess
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nova.db import Database
from nova.general_intelligence.cognitive_and_memory import (
    DynamicEnvironmentWorldModel,
    MultiLayerMemoryAndProvenanceEngine,
)

UNTESTED_EXPLANATION_TREATED_AS_CONFIRMED = False
MODEL_CONSENSUS_SUBSTITUTES_FOR_VERIFICATION = False
ALLOW_UNBOUNDED_TASK_GENERATION = False

EPISTEMIC_6_LEVELS: tuple[str, ...] = (
    "Verified",
    "Strongly supported",
    "Probable",
    "Uncertain",
    "Untested",
    "Unknown",
)

METACOG_8_CHECKS: tuple[str, ...] = (
    "understands_objective",
    "information_is_current",
    "assumptions_justified",
    "tools_suitable",
    "actions_reversible",
    "sufficient_evidence",
    "answer_verifiable",
    "independent_model_review_needed",
)

AUTONOMOUS_8_OPPORTUNITY_KINDS: tuple[str, ...] = (
    "project_missing_automated_tests",
    "outdated_dependency",
    "recurring_diagnostic_problem",
    "workflow_tool_improvement",
    "incomplete_objective",
    "system_configuration_maintenance",
    "repeated_user_activity_automation",
    "missing_dev_capability",
)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


class ScientificCausalReasoningEngine:
    """§239 12-Step Scientific Problem-Solving, Causal, Counterfactual & Sensitivity Engine."""

    def __init__(
        self,
        *,
        db: Database,
        memory_engine: MultiLayerMemoryAndProvenanceEngine,
        world_model: DynamicEnvironmentWorldModel,
        workspace_dir: Path,
    ) -> None:
        self.db = db
        self.memory_engine = memory_engine
        self.world_model = world_model
        self.workspace_dir = workspace_dir

    def run_12_step_investigation(
        self,
        *,
        observed_problem: str,
        initial_observations: list[str],
        candidate_hypotheses: list[dict[str, Any]],
        experiment_runner: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        remediation_runner: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        resolution_verifier: Callable[[], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Executes the full 12-step scientific investigation loop (§239)."""
        if len(candidate_hypotheses) < 2:
            raise ValueError("Scientific causal reasoning requires at least 2 competing explanations (§239).")

        steps_log: list[dict[str, Any]] = []
        # Step 1: Identify observed problem
        steps_log.append({"step": 1, "name": "identify_observed_problem", "problem": observed_problem, "observations": initial_observations})

        # Step 2 & 3: Develop several explanations & map supporting observations
        normalized_hyps: list[dict[str, Any]] = []
        for idx, h in enumerate(candidate_hypotheses):
            hid = str(h.get("id") or f"H{idx + 1}")
            normalized_hyps.append(
                {
                    "id": hid,
                    "explanation": str(h["explanation"]),
                    "supporting_observations": list(h.get("supporting_observations") or []),
                    "missing_information": list(h.get("missing_information") or ["empirical_probe_output"]),
                    "discriminating_test": str(h.get("discriminating_test") or f"probe_{hid}"),
                    "expected_outcome": str(h.get("expected_outcome") or "match"),
                    "proposed_remediation": h.get("proposed_remediation") or {},
                    "probe_command": h.get("probe_command"),
                    "confirmed_cause": False,  # Never confirmed before experiment!
                }
            )
        steps_log.append({"step": 2, "name": "develop_competing_explanations", "hypothesis_count": len(normalized_hyps)})
        steps_log.append(
            {
                "step": 3,
                "name": "identify_supporting_observations",
                "mapping": {h["id"]: h["supporting_observations"] for h in normalized_hyps},
            }
        )

        # Step 4: Determine missing information
        missing_info = sorted({m for h in normalized_hyps for m in h["missing_information"]})
        steps_log.append({"step": 4, "name": "determine_missing_information", "missing": missing_info})

        # Step 5 & 6: Design discriminating tests & predict expected outcomes
        steps_log.append(
            {
                "step": 5,
                "name": "design_discriminating_tests",
                "tests": [{h["id"]: h["discriminating_test"]} for h in normalized_hyps],
            }
        )
        steps_log.append(
            {
                "step": 6,
                "name": "predict_expected_outcomes",
                "predictions": {h["id"]: h["expected_outcome"] for h in normalized_hyps},
            }
        )

        # If no experiment runner and no probe commands, never treat any hypothesis as confirmed!
        has_any_experiment = experiment_runner is not None or any(h.get("probe_command") for h in normalized_hyps)
        if not has_any_experiment:
            return {
                "problem": observed_problem,
                "confirmed_cause": None,
                "epistemic_status": "Untested",
                "untested_treated_as_confirmed": UNTESTED_EXPLANATION_TREATED_AS_CONFIRMED,
                "hypotheses": normalized_hyps,
                "steps": steps_log,
                "problem_resolved": False,
            }

        # Step 7 & 8: Execute permitted experiments & compare actual results vs predictions
        experiment_results: dict[str, dict[str, Any]] = {}
        surviving: list[dict[str, Any]] = []
        eliminated: list[dict[str, Any]] = []
        for h in normalized_hyps:
            if experiment_runner is not None:
                actual = experiment_runner(h)
            elif h.get("probe_command"):
                proc = subprocess.run(
                    list(h["probe_command"]),
                    cwd=str(self.workspace_dir),
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                out = ((proc.stdout or "") + (proc.stderr or "")).strip()
                actual = {
                    "observed_outcome": out[:400],
                    "exit_code": proc.returncode,
                    "matches_prediction": h["expected_outcome"].lower() in out.lower(),
                }
            else:
                actual = {"observed_outcome": "not_executed", "matches_prediction": False}

            experiment_results[h["id"]] = actual
            if bool(actual.get("matches_prediction")):
                h["confirmed_cause"] = True
                surviving.append(h)
            else:
                eliminated.append(h)

        steps_log.append({"step": 7, "name": "execute_permitted_experiments", "executed_count": len(experiment_results)})
        steps_log.append(
            {
                "step": 8,
                "name": "compare_actual_vs_predicted",
                "comparisons": {
                    hid: {"predicted": next(x["expected_outcome"] for x in normalized_hyps if x["id"] == hid), "actual": res}
                    for hid, res in experiment_results.items()
                },
            }
        )

        # Step 9: Eliminate unsupported hypotheses
        steps_log.append(
            {
                "step": 9,
                "name": "eliminate_unsupported_hypotheses",
                "eliminated_ids": [e["id"] for e in eliminated],
                "surviving_ids": [s["id"] for s in surviving],
            }
        )

        selected_cause = surviving[0] if len(surviving) == 1 else (surviving[0] if surviving else None)

        # Step 10: Update understanding in Memory & World Model
        mem_id = ""
        if selected_cause is not None:
            rec = self.memory_engine.record_memory(
                layer="technical_knowledge",
                subject=f"causal_diagnosis:{observed_problem[:80]}",
                content=f"Root cause verified experimentally: {selected_cause['explanation']}",
                claim_origin="experimental_result",
                independently_tested=True,
                source_ref=f"hypothesis:{selected_cause['id']}",
            )
            mem_id = rec["entry"]["id"]
        steps_log.append({"step": 10, "name": "update_understanding", "memory_id": mem_id})

        # Step 11: Select suitable solution (and apply if remediation_runner provided)
        selected_solution = selected_cause["proposed_remediation"] if selected_cause else {"action": "collect_more_observations"}
        remediation_result: dict[str, Any] = {}
        if selected_cause is not None and remediation_runner is not None:
            remediation_result = remediation_runner(selected_cause)
        steps_log.append({"step": 11, "name": "select_suitable_solution", "solution": selected_solution, "remediation_result": remediation_result})

        # Step 12: Verify whether the original problem was resolved
        resolution_check = resolution_verifier() if (selected_cause is not None and resolution_verifier is not None) else {"resolved": False}
        problem_resolved = bool(resolution_check.get("resolved"))
        steps_log.append({"step": 12, "name": "verify_original_problem_resolved", "verification": resolution_check})

        return {
            "problem": observed_problem,
            "confirmed_cause": selected_cause["explanation"] if selected_cause else None,
            "confirmed_hypothesis_id": selected_cause["id"] if selected_cause else None,
            "eliminated_hypothesis_ids": [e["id"] for e in eliminated],
            "epistemic_status": "Verified" if selected_cause else "Uncertain",
            "untested_treated_as_confirmed": UNTESTED_EXPLANATION_TREATED_AS_CONFIRMED,
            "selected_solution": selected_solution,
            "problem_resolved": problem_resolved,
            "steps": steps_log,
        }

    @staticmethod
    def run_sensitivity_analysis(
        model_fn: Callable[[dict[str, float]], float],
        baseline_params: dict[str, float],
        *,
        perturbation_pct: float = 0.10,
    ) -> dict[str, Any]:
        """§239 Counterfactual & sensitivity analysis across numerical parameters."""
        base_out = float(model_fn(dict(baseline_params)))
        sensitivities: list[dict[str, Any]] = []
        for key, val in baseline_params.items():
            delta = (abs(val) * perturbation_pct) if val != 0 else perturbation_pct
            up_params = {**baseline_params, key: val + delta}
            down_params = {**baseline_params, key: val - delta}
            up_out = float(model_fn(up_params))
            down_out = float(model_fn(down_params))
            slope = (up_out - down_out) / (2.0 * delta)
            elasticity = (slope * val / base_out) if base_out != 0 else slope
            sensitivities.append(
                {
                    "parameter": key,
                    "baseline_value": val,
                    "output_at_minus_delta": round(down_out, 6),
                    "output_at_plus_delta": round(up_out, 6),
                    "local_derivative": round(slope, 6),
                    "elasticity": round(abs(elasticity), 6),
                }
            )
        sensitivities.sort(key=lambda item: item["elasticity"], reverse=True)
        return {
            "baseline_output": round(base_out, 6),
            "dominant_driver": sensitivities[0]["parameter"] if sensitivities else "",
            "sensitivities": sensitivities,
        }

    @staticmethod
    def evaluate_counterfactual(
        causal_fn: Callable[[dict[str, Any]], Any],
        factual_inputs: dict[str, Any],
        counterfactual_interventions: dict[str, Any],
    ) -> dict[str, Any]:
        factual_outcome = causal_fn(dict(factual_inputs))
        cf_inputs = {**factual_inputs, **counterfactual_interventions}
        cf_outcome = causal_fn(cf_inputs)
        return {
            "factual_inputs": factual_inputs,
            "factual_outcome": factual_outcome,
            "interventions": counterfactual_interventions,
            "counterfactual_outcome": cf_outcome,
            "outcome_changed": factual_outcome != cf_outcome,
        }


class MetacognitiveCalibrationEngine:
    """§240 Metacognition, 8-Factor Preflight & Empirical Task-Type Calibration."""

    def __init__(self, *, db: Database) -> None:
        self.db = db

    def record_task_outcome(
        self,
        *,
        task_domain: str,
        predicted_probability: float,
        actual_succeeded: bool,
    ) -> dict[str, Any]:
        key = f"metacog_domain:{task_domain.strip().lower()}"
        rec = self.db.get_gi_governance_record(key)
        payload = dict(rec["payload"]) if rec else {"runs": 0, "successes": 0, "brier_sum": 0.0}
        p = max(0.0, min(1.0, float(predicted_probability)))
        y = 1.0 if actual_succeeded else 0.0
        payload["runs"] = int(payload["runs"]) + 1
        payload["successes"] = int(payload["successes"]) + (1 if actual_succeeded else 0)
        payload["brier_sum"] = float(payload["brier_sum"]) + ((p - y) ** 2)
        payload["empirical_accuracy"] = round(payload["successes"] / payload["runs"], 4)
        payload["mean_brier_error"] = round(payload["brier_sum"] / payload["runs"], 4)
        self.db.upsert_gi_governance_record(key, "metacognitive_calibration", payload)
        return {"task_domain": task_domain, **payload}

    def get_domain_calibration(self, task_domain: str) -> dict[str, Any]:
        rec = self.db.get_gi_governance_record(f"metacog_domain:{task_domain.strip().lower()}")
        if not rec:
            return {"task_domain": task_domain, "runs": 0, "empirical_accuracy": None, "mean_brier_error": None}
        return {"task_domain": task_domain, **rec["payload"]}

    def evaluate_decision_reliability(
        self,
        *,
        objective: str,
        task_domain: str = "general",
        information_is_current: bool = True,
        assumptions_justified: bool = True,
        tools_suitable: bool = True,
        actions_reversible: bool = True,
        evidence_items: list[str] | None = None,
        answer_verifiable: bool = True,
        independent_verification_passed: bool = False,
        agreeing_models_count: int = 1,
        high_stakes: bool = False,
    ) -> dict[str, Any]:
        """§240 Evaluates all 8 pre-decision criteria and calibrates epistemic status without letting model consensus fake verification."""
        ev_count = len(evidence_items or [])
        checks = {
            "understands_objective": len(objective.strip()) >= 5,
            "information_is_current": bool(information_is_current),
            "assumptions_justified": bool(assumptions_justified),
            "tools_suitable": bool(tools_suitable),
            "actions_reversible": bool(actions_reversible),
            "sufficient_evidence": ev_count >= 1,
            "answer_verifiable": bool(answer_verifiable),
            "independent_model_review_needed": bool(high_stakes or not actions_reversible or not independent_verification_passed),
        }
        hist = self.get_domain_calibration(task_domain)
        emp_acc = hist["empirical_accuracy"]

        # §240 Hard invariant: several agreeing AI models NEVER substitute for independent verification!
        if not checks["understands_objective"]:
            level = "Unknown"
            calibrated_conf = 0.10
        elif independent_verification_passed and checks["sufficient_evidence"] and checks["information_is_current"]:
            level = "Verified"
            calibrated_conf = 0.95 if emp_acc is None else round(0.5 * 0.95 + 0.5 * max(0.75, float(emp_acc)), 4)
        elif ev_count >= 2 and checks["information_is_current"] and checks["assumptions_justified"]:
            level = "Strongly supported"
            calibrated_conf = 0.80
        elif ev_count >= 1 and checks["assumptions_justified"]:
            # Even if 5 AI models agree, without independent verification we cap at Probable!
            level = "Probable"
            calibrated_conf = 0.65
        elif ev_count == 0 and agreeing_models_count >= 1:
            level = "Untested"
            calibrated_conf = 0.30
        else:
            level = "Uncertain"
            calibrated_conf = 0.40

        if emp_acc is not None and hist["runs"] >= 3 and level != "Verified":
            calibrated_conf = round(0.6 * calibrated_conf + 0.4 * float(emp_acc), 4)

        return {
            "epistemic_status": level,
            "calibrated_confidence": calibrated_conf,
            "checks": checks,
            "historical_domain_calibration": hist,
            "agreeing_models_count": int(agreeing_models_count),
            "independent_verification_passed": bool(independent_verification_passed),
            "model_consensus_substituted_for_verification": MODEL_CONSENSUS_SUBSTITUTES_FOR_VERIFICATION,
            "proceed_recommended": level in {"Verified", "Strongly supported"} or (level == "Probable" and actions_reversible),
        }


class AutonomousObjectiveGenerator:
    """§241 Policy-bounded Autonomous Objective Generation with anti-runaway guards."""

    MAX_ACTIVE_AUTONOMOUS_OBJECTIVES = 8

    def __init__(self, *, db: Database) -> None:
        self.db = db

    def scan_and_propose_objectives(
        self,
        *,
        authorized_policy_ref: str = "maintenance_policy:default",
        project_dirs: list[str | Path] | None = None,
        diagnostic_history: list[dict[str, Any]] | None = None,
        missing_capabilities: list[str] | None = None,
        repeated_activities: list[str] | None = None,
        parent_generation_depth: int = 0,
    ) -> dict[str, Any]:
        # Prevent recursive / infinite self-spawning task loops (§241)
        if parent_generation_depth >= 1:
            return {
                "created": [],
                "skipped_reason": "recursive_autonomous_spawning_blocked",
                "allow_unbounded_task_generation": ALLOW_UNBOUNDED_TASK_GENERATION,
            }
        if not authorized_policy_ref.strip():
            raise ValueError("Autonomous objectives require an explicit authorized user goal or maintenance policy reference (§241).")

        existing = self.db.list_gi_goals_and_roadmaps(goal_kind="autonomous_objective", limit=200)
        active = [g for g in existing if g["status"] in {"proposed", "scheduled", "in_progress"}]
        existing_sigs = {g["spec"].get("signature", "") for g in existing}

        candidates: list[dict[str, Any]] = []
        for raw_dir in project_dirs or []:
            pdir = Path(raw_dir)
            if not pdir.is_dir():
                continue
            py_files = list(pdir.glob("*.py")) + list(pdir.glob("src/**/*.py"))
            test_files = list(pdir.glob("test_*.py")) + list(pdir.glob("tests/**/test_*.py"))
            if py_files and not test_files:
                candidates.append(
                    {
                        "opportunity_kind": "project_missing_automated_tests",
                        "title": f"Add automated pytest coverage for project '{pdir.name}'",
                        "justification": f"Detected {len(py_files)} Python module(s) in '{pdir.name}' with 0 automated test files.",
                        "expected_benefits": "Catch regressions automatically before deployment.",
                        "priority": 75,
                        "success_criteria": ["pytest suite exists and exits with code 0"],
                    }
                )

        if diagnostic_history:
            counts: dict[str, int] = {}
            for d in diagnostic_history:
                sig = str(d.get("failure_code") or d.get("error") or "").strip()
                if sig:
                    counts[sig] = counts.get(sig, 0) + 1
            for sig, cnt in counts.items():
                if cnt >= 2:
                    candidates.append(
                        {
                            "opportunity_kind": "recurring_diagnostic_problem",
                            "title": f"Resolve recurring diagnostic fault '{sig[:60]}'",
                            "justification": f"Diagnostic issue '{sig[:60]}' recurred {cnt} times.",
                            "expected_benefits": "Eliminate repeated operational failures.",
                            "priority": 85,
                            "success_criteria": ["Root cause verified experimentally", "Zero recurrence in post-fix check"],
                        }
                    )

        for cap in missing_capabilities or []:
            candidates.append(
                {
                    "opportunity_kind": "missing_dev_capability",
                    "title": f"Evaluate and integrate missing capability '{cap}'",
                    "justification": f"Authorized task workflow referenced unavailable capability '{cap}'.",
                    "expected_benefits": f"Enable native execution for '{cap}' requests.",
                    "priority": 70,
                    "success_criteria": [f"Capability '{cap}' verified in isolated sandbox and registered"],
                }
            )

        for act in repeated_activities or []:
            candidates.append(
                {
                    "opportunity_kind": "repeated_user_activity_automation",
                    "title": f"Create reusable workflow automation for '{act[:60]}'",
                    "justification": f"Repeated manual sequence '{act[:60]}' observed.",
                    "expected_benefits": "Save operator time with deterministic one-step execution.",
                    "priority": 60,
                    "success_criteria": ["Validated workflow registered and passes dry-run check"],
                }
            )

        created: list[dict[str, Any]] = []
        for cand in candidates:
            if len(active) + len(created) >= self.MAX_ACTIVE_AUTONOMOUS_OBJECTIVES:
                break
            sig = hashlib.sha256(f"{cand['opportunity_kind']}::{cand['title'].lower()}".encode()).hexdigest()[:16]
            if sig in existing_sigs:
                continue
            existing_sigs.add(sig)
            spec = {
                "signature": sig,
                "opportunity_kind": cand["opportunity_kind"],
                "justification": cand["justification"],
                "authorized_goal_or_policy_ref": authorized_policy_ref,
                "expected_benefits": cand["expected_benefits"],
                "required_resources": {"cpu_cores": 1, "max_memory_mb": 512, "network_required": False},
                "priority": cand["priority"],
                "execution_limits": {"max_duration_seconds": 300, "max_tool_calls": 10, "generation_depth": 1},
                "success_criteria": cand["success_criteria"],
                "completion_conditions": ["All success_criteria empirically verified or explicitly dismissed by operator"],
            }
            saved = self.db.upsert_gi_goal_or_roadmap(
                {
                    "id": f"autoobj-{sig[:10]}",
                    "goal_kind": "autonomous_objective",
                    "title": cand["title"],
                    "status": "proposed",
                    "priority": cand["priority"],
                    "authorized_policy_ref": authorized_policy_ref,
                    "spec": spec,
                }
            )
            created.append(saved)

        return {
            "created_count": len(created),
            "created": created,
            "active_cap": self.MAX_ACTIVE_AUTONOMOUS_OBJECTIVES,
            "allow_unbounded_task_generation": ALLOW_UNBOUNDED_TASK_GENERATION,
        }


class LongTermStrategicPlanner:
    """§242 Multi-Day/Week/Month Hierarchical Strategic Roadmaps, Replanning & Interruption Recovery."""

    def __init__(self, *, db: Database) -> None:
        self.db = db

    def create_roadmap(
        self,
        *,
        title: str,
        horizon_days: int,
        user_constraints: list[str],
        milestones: list[dict[str, Any]],
        priority: int = 80,
    ) -> dict[str, Any]:
        rid = f"roadmap-{uuid.uuid4().hex[:10]}"
        norm_milestones: list[dict[str, Any]] = []
        for idx, m in enumerate(milestones):
            mid = str(m.get("id") or f"M{idx + 1}")
            norm_milestones.append(
                {
                    "id": mid,
                    "title": str(m["title"]),
                    "depends_on": list(m.get("depends_on") or []),
                    "deadline_day": int(m.get("deadline_day") or min(horizon_days, (idx + 1) * 7)),
                    "required_resources": dict(m.get("required_resources") or {"worker": "local"}),
                    "fallback_strategy": str(m.get("fallback_strategy") or "switch_to_local_offline_adapter"),
                    "status": "pending",
                    "active_strategy": "primary",
                    "blocker": "",
                }
            )
        risks = [
            {
                "milestone_id": m["id"],
                "risk": "dependency_chain_delay" if len(m["depends_on"]) >= 2 else "integration_or_resource_contention",
                "mitigation": m["fallback_strategy"],
            }
            for m in norm_milestones
        ]
        spec = {
            "horizon_days": int(horizon_days),
            "user_constraints": list(user_constraints),
            "milestones": norm_milestones,
            "risk_assessment": risks,
            "replan_count": 0,
            "impossible_or_outdated": False,
            "impossible_reason": "",
        }
        return self.db.upsert_gi_goal_or_roadmap(
            {
                "id": rid,
                "goal_kind": "strategic_roadmap",
                "title": title,
                "status": "active",
                "priority": int(priority),
                "authorized_policy_ref": "user_defined_strategic_goal",
                "spec": spec,
                "checkpoints": [{"at": _iso(), "event": "roadmap_created", "completed_milestones": []}],
            }
        )

    def advance_or_replan_milestone(
        self,
        roadmap_id: str,
        *,
        milestone_id: str,
        outcome: str,
        blocker_detail: str = "",
        objective_became_impossible_reason: str = "",
    ) -> dict[str, Any]:
        """§242 Checkpoints milestone progress, triggers fallback replanning on failure, or flags impossible objectives."""
        roadmap = self.db.get_gi_goal_or_roadmap(roadmap_id)
        if roadmap is None:
            raise KeyError(f"Roadmap '{roadmap_id}' not found.")
        spec = dict(roadmap["spec"])
        checkpoints = list(roadmap["checkpoints"])

        if objective_became_impossible_reason:
            spec["impossible_or_outdated"] = True
            spec["impossible_reason"] = objective_became_impossible_reason
            checkpoints.append({"at": _iso(), "event": "objective_marked_impossible_or_outdated", "reason": objective_became_impossible_reason})
            return self.db.upsert_gi_goal_or_roadmap(
                {**roadmap, "status": "halted_impossible_or_outdated", "spec": spec, "checkpoints": checkpoints}
            )

        completed_ids = {m["id"] for m in spec["milestones"] if m["status"] == "completed"}
        for m in spec["milestones"]:
            if m["id"] != milestone_id:
                continue
            unmet = [d for d in m["depends_on"] if d not in completed_ids]
            if unmet and outcome == "completed":
                raise ValueError(f"Cannot complete milestone '{milestone_id}' before dependencies: {unmet}")
            if outcome == "completed":
                m["status"] = "completed"
                m["blocker"] = ""
            elif outcome == "failed_primary":
                # Replan onto alternative execution strategy while preserving user constraints!
                m["active_strategy"] = f"fallback:{m['fallback_strategy']}"
                m["status"] = "replanned_ready"
                m["blocker"] = blocker_detail
                spec["replan_count"] = int(spec.get("replan_count") or 0) + 1
            elif outcome == "blocked":
                m["status"] = "blocked"
                m["blocker"] = blocker_detail

        all_done = all(m["status"] == "completed" for m in spec["milestones"])
        new_status = "completed" if all_done else "active"
        checkpoints.append(
            {
                "at": _iso(),
                "event": f"milestone_{milestone_id}_{outcome}",
                "completed_milestones": [m["id"] for m in spec["milestones"] if m["status"] == "completed"],
                "replan_count": spec["replan_count"],
            }
        )
        return self.db.upsert_gi_goal_or_roadmap(
            {**roadmap, "status": new_status, "spec": spec, "checkpoints": checkpoints}
        )

    def generate_progress_report(self, roadmap_id: str) -> dict[str, Any]:
        roadmap = self.db.get_gi_goal_or_roadmap(roadmap_id)
        if roadmap is None:
            raise KeyError(f"Roadmap '{roadmap_id}' not found.")
        spec = roadmap["spec"]
        ms = spec["milestones"]
        done = [m["id"] for m in ms if m["status"] == "completed"]
        blockers = [{"milestone_id": m["id"], "blocker": m["blocker"], "strategy": m["active_strategy"]} for m in ms if m["blocker"]]
        ready_next = [
            m["id"]
            for m in ms
            if m["status"] in {"pending", "replanned_ready"} and all(d in done for d in m["depends_on"])
        ]
        return {
            "roadmap_id": roadmap["id"],
            "title": roadmap["title"],
            "status": roadmap["status"],
            "progress_pct": round(100.0 * len(done) / max(1, len(ms)), 1),
            "completed_milestones": done,
            "ready_next_milestones": ready_next,
            "active_blockers": blockers,
            "replan_count": spec["replan_count"],
            "preserved_user_constraints": spec["user_constraints"],
            "checkpoint_count": len(roadmap["checkpoints"]),
            "impossible_or_outdated": spec["impossible_or_outdated"],
            "impossible_reason": spec["impossible_reason"],
        }
