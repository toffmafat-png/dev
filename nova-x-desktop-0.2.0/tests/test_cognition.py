"""Tests for the cognition layer (nova.cognition) and its engine integration.

These tests are the reason the cognition modules are written to be offline and
deterministic: every mechanism below is asserted on its observable behaviour,
with no provider calls and no network. The engine test at the end runs a real
task through ``TaskEngine`` with a fake provider and asserts that the reasoning
mechanisms actually fired and were persisted - a library that is never called
would pass every other test in this file.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from nova.cognition import (
    MIN_ATTEMPTS_TO_ESTABLISH,
    MIN_CALIBRATION_SAMPLES,
    AgentOutput,
    CalibrationLedger,
    CuriosityBudget,
    KnowledgeGap,
    Observation,
    Option,
    ProcedureLibrary,
    WorldModel,
    classify_claim,
    derive_roles,
    evaluate_options,
    post_hoc,
    preflight,
    reconcile,
    resolve_gap,
    transfer_check,
    within_scope,
)
from nova.cognition.evaluation import SUITE_VERSION, EvalContext, run_suite
from nova.cognition.service import CognitionService, _signature, environment_markers
from nova.db import Database
from nova.engine import TaskEngine, _cognition_context
from tests.conftest import FakeProvider, msg

# --------------------------------------------------------------- epistemic


def test_unsupported_observation_is_demoted_not_accepted():
    claim = classify_claim("The database has 42 rows.", kind="observation", provenance="model_generated", confidence=0.9)
    assert claim.kind == "inference"
    assert not claim.is_actionable_evidence

    grounded = classify_claim(
        "The database has 42 rows.", kind="observation", provenance="tool_result", evidence_refs=("tool:7",)
    )
    assert grounded.kind == "observation"
    assert grounded.is_actionable_evidence
    assert grounded.confidence == 0.0


def test_observation_without_evidence_refs_is_demoted_even_with_good_provenance():
    claim = classify_claim("Disk usage is 91%.", kind="observation", provenance="tool_result")
    assert claim.kind != "observation"


def test_calibration_detects_systematic_overconfidence():
    ledger = CalibrationLedger()
    for _ in range(12):
        ledger.add(0.95, False, statement="the deploy will succeed", domain="tasks")
    report = ledger.report()
    assert report.status == "poorly_calibrated"
    assert report.samples == 12
    assert float(report.overconfidence) > 0.5
    assert float(report.expected_calibration_error) > 0.15


def test_calibration_refuses_to_score_too_few_samples():
    ledger = CalibrationLedger()
    for _ in range(3):
        ledger.add(0.9, True)
    report = ledger.report()
    assert report.status == "insufficient_data"
    assert report.expected_calibration_error is None
    assert MIN_CALIBRATION_SAMPLES == 10


def test_well_calibrated_history_is_recognised():
    ledger = CalibrationLedger()
    for index in range(20):
        ledger.add(0.7, index % 10 < 7, domain="tasks")
    report = ledger.report()
    assert report.status == "well_calibrated"
    assert abs(float(report.overconfidence)) <= 0.15


# ------------------------------------------------------------- world model


def test_stale_observations_are_reported_not_silently_reused():
    long_ago = (datetime.now(UTC) - timedelta(seconds=3600)).isoformat(timespec="microseconds")
    fresh = Observation(subject="svc:api", predicate="service.state", value="up", source="tool_result")
    old = Observation(subject="svc:api", predicate="service.state", value="up", source="tool_result", observed_at=long_ago)
    permanent = Observation(subject="cmd:1", predicate="command.exit_code", value="0", source="tool_result", observed_at=long_ago)

    assert not fresh.is_stale()
    assert old.is_stale()
    assert old.ttl() == 30
    # A completed run's exit code is a historical fact and never goes stale.
    assert not permanent.is_stale()
    assert permanent.ttl() is None


def test_contradicted_prediction_marks_subject_for_reinspection():
    model = WorldModel()
    model.observe("db:users", "row_count", "42", "tool_result", evidence_ref="tool:1")
    prediction = model.predict("INSERT rows", {"db:users.row_count": "42"})
    model.observe("db:users", "row_count", "57", "tool_result", evidence_ref="tool:2")

    resolved = model.resolve_prediction(prediction.id, {"db:users.row_count": "57"})
    assert resolved.resolved
    assert resolved.agreement == 0.0
    assert len(resolved.contradicted) == 1
    assert resolved.contradicted[0]["reason"] == "mismatch"
    assert "db:users" in model.requires_reinspection()
    assert model.prediction_accuracy()["mean_agreement"] == 0.0

    model.clear_reinspection("db:users")
    assert model.requires_reinspection() == []


def test_confirmed_prediction_does_not_demand_reinspection():
    model = WorldModel()
    prediction = model.predict("restart", {"svc:api.service.state": "up"})
    resolved = model.resolve_prediction(prediction.id, {"svc:api.service.state": "up"})
    assert resolved.agreement == 1.0
    assert model.requires_reinspection() == []
    assert model.prediction_accuracy()["fully_confirmed"] == 1


def test_unfounded_inferred_relation_is_marked_unfounded():
    model = WorldModel()
    relation = model.relate("svc:api", "depends_on", "db:primary", inferred=True, evidence_refs=())
    assert relation.inferred
    assert "(unfounded)" in relation.predicate

    grounded = model.relate("svc:api", "depends_on", "db:primary", inferred=True, evidence_refs=("tool:3",))
    assert "(unfounded)" not in grounded.predicate


def test_hypothesis_needs_repeated_confirmation_and_any_refutation_wins():
    model = WorldModel()
    hypothesis = model.hypothesize("port mismatch", "500 responses", evidence_refs=("tool:1",))
    assert hypothesis.status == "untested"
    for _ in range(2):
        hypothesis = model.record_hypothesis_outcome(hypothesis.id, confirmed=True, evidence_ref="tool:2")
    assert hypothesis.status != "supported"
    hypothesis = model.record_hypothesis_outcome(hypothesis.id, confirmed=True, evidence_ref="tool:3")
    assert hypothesis.status == "supported"

    refuted = model.record_hypothesis_outcome(hypothesis.id, confirmed=False, evidence_ref="tool:4")
    assert refuted.status == "refuted"


def test_observation_store_is_bounded():
    from nova.cognition.world_model import MIN_MAX_OBSERVATIONS

    # A tiny bound is floored so the model cannot be shrunk into uselessness.
    floored = WorldModel(max_observations=1)
    assert floored.max_observations == MIN_MAX_OBSERVATIONS

    bound = MIN_MAX_OBSERVATIONS
    model = WorldModel(max_observations=bound)
    for index in range(bound * 3):
        model.observe(f"subject:{index}", "value", str(index), "tool_result")
    assert len(model.subjects()) == bound
    assert model.stats().observations == bound
    # Eviction keeps the newest entries, not an arbitrary subset.
    assert "subject:0" not in model.subjects()
    assert f"subject:{bound * 3 - 1}" in model.subjects()


# ---------------------------------------------------------- meta-reasoning


def test_preflight_blocks_on_a_capability_nova_does_not_have():
    review = preflight(
        "Reboot the server and email the report to the customer.",
        ["Reboot the production server", "Send the report by email"],
        available_tools={"workspace.read_file"},
    )
    assert review.proceed == "blocked"
    assert len(review.blocking_capability_gaps) >= 2
    assert any("outbound communication" in gap for gap in review.blocking_capability_gaps)
    assert any("system power or service control" in gap for gap in review.blocking_capability_gaps)
    assert any("substitute" in item for item in review.abandon_conditions)


def test_policy_gated_capability_is_flagged_without_blocking():
    review = preflight(
        "Remove the stale build artifacts.",
        ["Delete the build directory"],
        available_tools={"process.execute"},
    )
    assert review.proceed != "blocked"
    assert any("destructive file or data removal" in gap for gap in review.capability_gaps)
    assert review.blocking_capability_gaps == []


def test_preflight_derives_checkable_criteria_or_flags_the_objective_unverifiable():
    concrete = preflight("Fix the failing login test and verify it passes.", ["Run pytest"], available_tools={"process.execute"})
    assert len(concrete.acceptance_criteria) >= 2
    assert not any("checkable success criterion" in item for item in concrete.missing_evidence)

    vague = preflight("do the thing", [], available_tools=set())
    assert any("checkable success criterion" in item for item in vague.missing_evidence)
    assert vague.proceed == "gather_information_first"


def test_preflight_picks_the_cheapest_sufficient_verification():
    with_tests = preflight("Fix the login bug and run the test suite.", ["Run pytest"], available_tools={"process.execute"})
    assert "test" in with_tests.cheapest_verification.lower()

    # With no tool registered nothing can be observed, and the review must say
    # so rather than presenting a second model opinion as verification.
    no_tools = preflight("Explain the retry policy.", ["Describe it"], available_tools=set())
    assert "no observational verification is available" in no_tools.cheapest_verification.lower()
    assert "not independent evidence" in no_tools.cheapest_verification.lower()

    # And when even a model review is off the table, the result is unverified.
    nothing = preflight("Explain it.", ["Describe it"], available_tools=set(), supports_verification_call=False)
    assert "unverified" in nothing.cheapest_verification.lower()


def test_preflight_confidence_rises_with_observations():
    grounded = preflight("Point the client at the port.", ["Update config"], available_tools={"workspace.write_file"}, known_facts=["svc listens on 9090"])
    ungrounded = preflight("Point the client at the port.", ["Update config"], available_tools={"workspace.write_file"}, known_facts=[])
    assert ungrounded.confidence < grounded.confidence
    assert 0.05 <= ungrounded.confidence <= 0.9


def test_post_hoc_attributes_each_cause_from_recorded_evidence():
    review = preflight("List files.", ["List them"], available_tools={"process.execute"})

    denied = post_hoc(task_id="t", state="failed", review=review, tool_outcomes=[{"status": "denied", "summary": "blocked by policy"}])
    assert denied.cause == "unavailable_tool"
    assert denied.actual_outcome is False

    errored = post_hoc(task_id="t", state="failed", review=review, tool_outcomes=[{"status": "error", "summary": "exit 1"}])
    assert errored.cause == "execution_error"

    cancelled = post_hoc(task_id="t", state="cancelled", review=review)
    assert cancelled.cause == "cancelled"
    assert "cancelled" in cancelled.lesson.lower()

    exhausted = post_hoc(task_id="t", state="running", review=review, provider_requests=99, budget_exhausted=True)
    assert exhausted.cause == "budget_exhausted"

    contradicted = post_hoc(task_id="t", state="failed", review=review, contradictions=2)
    assert contradicted.cause == "incorrect_information"

    ignored = post_hoc(task_id="t", state="failed", review=review)
    assert ignored.cause == "poor_planning"


def test_post_hoc_success_requires_criteria_to_be_met():
    review = preflight("Fix the bug and verify it.", ["Patch", "Run tests"], available_tools={"process.execute"})
    total = len(review.acceptance_criteria)
    met = post_hoc(task_id="t", state="completed", review=review, tool_outcomes=[{"status": "ok"}], criteria_met=total)
    assert met.cause == "success"
    assert met.actual_outcome is True
    assert met.confidence_error == round(review.confidence - 1.0, 4)

    partial = post_hoc(task_id="t", state="completed", review=review, tool_outcomes=[{"status": "ok"}], criteria_met=0)
    assert partial.cause == "bad_success_criterion"
    assert partial.actual_outcome is False


def test_a_single_post_hoc_lesson_is_only_tentative():
    review = preflight("Do the work.", ["Work"], available_tools={"process.execute"})
    result = post_hoc(task_id="t", state="completed", review=review, criteria_met=len(review.acceptance_criteria))
    assert result.lesson_status == "tentative"


# ---------------------------------------------------------------- planning


def _options() -> list[Option]:
    return [
        Option(id="read-config", description="Read the config file", estimated_tool_calls=1, estimated_provider_requests=1, estimated_minutes=1.0, risk=0.02),
        Option(id="rewrite", description="Rewrite and redeploy the service", estimated_tool_calls=9, estimated_provider_requests=20, estimated_minutes=90.0, risk=0.8, reversible=False),
        Option(id="email-vendor", description="Email the vendor", estimated_minutes=1440.0, requires_missing_capability=True, missing_capability="outbound communication"),
    ]


def test_one_clearly_sufficient_option_short_circuits_the_comparison():
    decision = evaluate_options("Find out why the port is wrong.", _options(), max_tool_calls=8, max_provider_requests=12, max_minutes=30.0)
    assert decision.short_circuited is True
    assert decision.chosen_option_id == "read-config"
    assert len(decision.alternatives_rejected) == 2


def test_predicted_outcome_is_labelled_as_a_prediction_until_recorded():
    decision = evaluate_options("Why did the job fail?", [Option(id="a", description="Inspect the log", estimated_minutes=2.0, risk=0.05)])
    assert decision.actual_outcome is None
    assert decision.predicted_outcome.startswith("Predicted (not yet executed)")

    decision.record_actual("The job failed: the credential expired.", matched=False)
    assert decision.actual_outcome is not None
    assert decision.prediction_matched is False
    assert decision.prediction_accuracy == 0.0


def test_unauthorized_and_over_budget_options_can_never_be_chosen():
    options = [
        Option(id="deploy", description="Deploy to production", risk=0.3, reversible=False, authorization_required=True),
        Option(id="scan-everything", description="Analyse every file", estimated_tool_calls=40, estimated_provider_requests=60, estimated_minutes=200.0),
    ]
    decision = evaluate_options("Ship the fix now.", options, max_tool_calls=8, max_provider_requests=12, max_minutes=30.0)
    assert decision.chosen_option_id is None
    assert len(decision.alternatives_rejected) == 2
    assert "authorization" in decision.decision_rationale.lower()
    assert "workaround" in decision.decision_rationale.lower()


def test_explicit_authorization_does_not_leak_to_other_options():
    options = [
        Option(id="deploy", description="Deploy to production", risk=0.3, reversible=False, authorization_required=True),
        Option(id="rollback", description="Roll back the deploy", risk=0.4, reversible=False, authorization_required=True),
    ]
    decision = evaluate_options("Ship it.", options, authorization_granted={"deploy"})
    assert decision.chosen_option_id == "deploy"
    assert decision.authorization_needed is True
    assert "cannot extend" in decision.authorization_note
    assert any("rollback" in item for item in decision.alternatives_rejected)


def test_risk_tolerance_changes_the_choice_without_changing_the_rules():
    risky = [
        Option(id="safe", description="Read the log", estimated_minutes=5.0, risk=0.05),
        Option(id="fast", description="Force-restart in place", estimated_minutes=1.0, risk=0.55, reversible=False),
    ]
    cautious = evaluate_options("Restore service.", risky, risk_tolerance="cautious", max_minutes=30.0)
    aggressive = evaluate_options("Restore service.", risky, risk_tolerance="aggressive", max_minutes=30.0)
    assert cautious.chosen_option_id == "safe"
    assert aggressive.chosen_option_id == "safe"
    safe_cautious = next(item for item in cautious.evaluations if item.option.id == "safe")
    fast_cautious = next(item for item in cautious.evaluations if item.option.id == "fast")
    fast_aggressive = next(item for item in aggressive.evaluations if item.option.id == "fast")
    assert fast_cautious.risk_penalty > fast_aggressive.risk_penalty
    assert safe_cautious.score > fast_cautious.score


def test_option_validation_rejects_nonsense():
    with pytest.raises(ValueError):
        Option(id="", description="x")
    with pytest.raises(ValueError):
        Option(id="a", description="")
    with pytest.raises(ValueError):
        Option(id="a", description="x", risk=1.5)
    with pytest.raises(ValueError):
        Option(id="a", description="x", estimated_tool_calls=-1)


# --------------------------------------------------------------- curiosity


def test_curiosity_refuses_paths_outside_authorized_roots(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    allowed, _ = within_scope(str(root / "src"), (str(root),))
    denied, reason = within_scope(str(tmp_path / ".ssh" / "id_rsa"), (str(root),))
    escaped, _ = within_scope(str(root / ".." / ".." / "etc" / "passwd"), (str(root),))
    assert allowed
    assert not denied
    assert "outside every authorized root" in reason
    assert not escaped
    assert not within_scope("anything", ())[0]


def test_curiosity_ladder_skips_privacy_sensitive_local_exploration(tmp_path):
    root = str(tmp_path)
    gap = KnowledgeGap(id="g1", question="Where are the credentials?", candidate_paths=(str(tmp_path / ".ssh"),), privacy_sensitive=True)
    plan = resolve_gap(gap, budget=CuriosityBudget(authorized_roots=(root,)), available_tools=set())
    assert any("privacy-sensitive" in step.skip_reason for step in plan.skipped_steps)
    assert all(step.step != "read_local_documentation" for step in plan.steps)


def test_curiosity_escalates_to_the_user_when_the_budget_is_gone(tmp_path):
    gap = KnowledgeGap(id="g2", question="What does the vendor return for 429?")
    plan = resolve_gap(
        gap,
        budget=CuriosityBudget(max_steps_per_gap=2, max_provider_requests=1, authorized_roots=(str(tmp_path),)),
        available_tools=set(),
        provider_requests_used=1,
    )
    assert plan.total_provider_requests <= 1
    assert len(plan.steps) <= 2
    assert plan.terminal == "ask_user"
    assert any("budget" in step.skip_reason.lower() for step in plan.skipped_steps)


def test_curiosity_uses_the_cheapest_rung_first(tmp_path):
    gap = KnowledgeGap(id="g3", question="What is the retry limit?")
    plan = resolve_gap(
        gap,
        # Two rungs: recall and local documentation. Both are free, so a plan
        # that stays inside them costs no provider requests at all.
        budget=CuriosityBudget(max_steps_per_gap=2, authorized_roots=(str(tmp_path),)),
        available_tools={"workspace.search_files", "research.search_web", "process.execute", "workspace.write_file"},
        memory_hits=2,
    )
    assert [step.step for step in plan.steps] == ["recall_from_memory", "read_local_documentation"]
    assert plan.total_provider_requests == 0
    assert plan.steps[0].provider_requests == 0

    # Widening the budget reaches the paid rungs, and the cost stays bounded.
    wider = resolve_gap(
        gap,
        budget=CuriosityBudget(max_steps_per_gap=4, max_provider_requests=2, authorized_roots=(str(tmp_path),)),
        available_tools={"workspace.search_files", "research.search_web", "process.execute", "workspace.write_file"},
        memory_hits=2,
    )
    assert wider.steps[2].step == "external_search"
    assert wider.total_provider_requests <= 2


def test_exploration_log_audits_what_curiosity_cost(tmp_path):
    from nova.cognition import ExplorationLog

    log = ExplorationLog()
    gap = KnowledgeGap(id="g4", question="Something unknown")
    log.record(resolve_gap(gap, budget=CuriosityBudget(authorized_roots=(str(tmp_path),)), available_tools=set()))
    assert log.gaps_planned == 1
    assert log.refused_out_of_scope == 0
    payload = log.to_dict()
    assert payload["gaps_planned"] == 1
    assert len(payload["entries"]) == 1


def test_curiosity_budget_rejects_nonsense():
    with pytest.raises(ValueError):
        CuriosityBudget(max_steps_per_gap=0)
    with pytest.raises(ValueError):
        CuriosityBudget(experiment_timeout_seconds=0)


# -------------------------------------------------------------- procedures


def test_one_success_creates_a_candidate_never_an_established_procedure():
    library = ProcedureLibrary()
    procedure = library.add(procedure_id="p1", name="Diagnose a wrong port", domain="ops", summary="s", steps=["a"], provenance="tool_result")
    library.record_outcome("p1", success=True, evidence_ref="tool:1")
    assert procedure.status == "candidate"
    assert procedure.attempts == 1
    assert procedure.reliability_known is False
    assert procedure.reliability == 0.0
    assert MIN_ATTEMPTS_TO_ESTABLISH == 3


def test_reliability_thresholds_promote_and_demote():
    library = ProcedureLibrary()
    library.add(procedure_id="good", name="g", domain="d", summary="s", steps=["a"])
    library.add(procedure_id="bad", name="b", domain="d", summary="s", steps=["a"])
    for index in range(3):
        library.record_outcome("good", success=True, evidence_ref=f"t:{index}")
        library.record_outcome("bad", success=False, evidence_ref=f"t:{index}")
    assert library.get("good").status == "established"
    assert library.get("bad").status == "deprecated"
    assert "success ratio" in library.get("bad").correction_reason


def test_an_established_procedure_that_degrades_is_demoted():
    library = ProcedureLibrary()
    library.add(procedure_id="p", name="p", domain="d", summary="s", steps=["a"])
    for _ in range(3):
        library.record_outcome("p", success=True)
    assert library.get("p").status == "established"
    for _ in range(6):
        library.record_outcome("p", success=False)
    assert library.get("p").status == "deprecated"
    assert "degraded" in library.get("p").correction_reason


def test_pruning_forgets_unreliable_candidates_but_keeps_what_works():
    library = ProcedureLibrary()
    library.add(procedure_id="est", name="e", domain="d", summary="s", steps=["a"])
    for index in range(4):
        library.record_outcome("est", success=index < 3)
    library.add(procedure_id="junk", name="j", domain="d", summary="s", steps=["a"])
    for _ in range(4):
        library.record_outcome("junk", success=False)

    assert library.prune_unreliable() == ["junk"]
    assert library.get("est").status == "established"
    assert library.get("junk") is None


def test_wrong_knowledge_can_be_corrected_superseded_and_removed_with_provenance():
    library = ProcedureLibrary()
    library.add(procedure_id="old", name="Old way", domain="d", summary="s", steps=["a"])
    library.add(procedure_id="new", name="New way", domain="d", summary="s", steps=["b"], supersedes="old")
    assert library.get("old").status == "superseded"
    assert library.get("old").superseded_by == "new"

    assert library.correct("old", reason="Upstream API changed.", provenance="external_source", replacement_id="new")
    assert library.get("old").provenance == "external_source"

    with pytest.raises(ValueError):
        library.correct("old", reason="x", provenance="not-a-provenance")

    assert library.remove("old", reason="superseded")
    assert library.get("old") is None
    assert [item["event"] for item in library.history()].count("removed") == 1
    assert not library.remove("old")


def test_procedure_state_survives_export_and_import():
    library = ProcedureLibrary()
    library.add(procedure_id="p", name="n", domain="d", summary="s", steps=["a", "b"], environment={"os": "linux"}, provenance="tool_result")
    for index in range(3):
        library.record_outcome("p", success=True, evidence_ref=f"t:{index}")
    payload = library.export_state()

    restored = ProcedureLibrary()
    assert restored.import_state(payload) == 1
    procedure = restored.get("p")
    assert procedure.status == "established"
    assert procedure.attempts == 3
    assert procedure.environment == {"os": "linux"}
    assert procedure.steps == ["a", "b"]


def test_import_rejects_unknown_provenance_and_status_rather_than_trusting_them():
    restored = ProcedureLibrary()
    restored.import_state({"procedures": [{"id": "p", "provenance": "made_up", "status": "also_made_up"}]})
    procedure = restored.get("p")
    assert procedure.provenance == "model_generated"
    assert procedure.status == "candidate"


def test_transfer_check_compares_only_what_can_be_compared():
    library = ProcedureLibrary()
    procedure = library.add(
        procedure_id="p",
        name="Restart a systemd unit",
        domain="system_diagnosis",
        summary="s",
        steps=["restart", "check socket"],
        preconditions=["unit exists"],
        environment={"os": "linux", "init": "systemd", "runtime": "python3.11"},
        tools_required=["process.execute"],
        provenance="tool_result",
    )
    same = transfer_check(procedure, target_environment={"os": "linux", "init": "systemd", "runtime": "python3.11"}, available_tools={"process.execute"})
    changed = transfer_check(procedure, target_domain="container_ops", target_environment={"os": "linux", "init": "none", "runtime": "python3.13"}, available_tools={"process.execute"})
    no_tool = transfer_check(procedure, target_environment={"os": "linux", "init": "systemd", "runtime": "python3.11"}, available_tools={"workspace.read_file"})

    assert same.verdict == "compatible"
    assert changed.verdict == "partially_compatible"
    assert changed.confidence < same.confidence
    assert any("init" in item for item in changed.required_adaptations)
    assert no_tool.tool_gaps == ["process.execute"]
    assert "Do not fake their output" in " ".join(no_tool.required_adaptations)
    assert any("reliability is unknown" in item for item in same.reverify)


def test_transfer_check_reports_unknown_when_nothing_is_comparable():
    library = ProcedureLibrary()
    procedure = library.add(procedure_id="p", name="n", domain="d", summary="s", steps=["a"])
    verdict = transfer_check(procedure)
    assert verdict.verdict == "unknown"
    assert verdict.confidence == 0.0
    assert "cannot be assessed" in verdict.notes


def test_retrieval_prefers_demonstrated_reliability_over_vocabulary():
    library = ProcedureLibrary()
    library.add(procedure_id="untried", name="Fix the failing login test", domain="software", summary="Fix the failing login test", steps=["fix", "login", "test"], provenance="model_generated")
    library.add(procedure_id="proven", name="Repair a failing login test", domain="software", summary="Reproduce the failing login test then repair it", steps=["reproduce", "repair", "login", "test"], provenance="tool_result")
    for index in range(4):
        library.record_outcome("proven", success=True, evidence_ref=f"t:{index}")

    hits = library.retrieve("fix the failing login test", domain="software", limit=3)
    assert hits[0].procedure.id == "proven"
    assert hits[0].score > hits[1].score


def test_retrieval_penalises_procedures_whose_tools_are_missing():
    library = ProcedureLibrary()
    library.add(procedure_id="needs-tool", name="Run the deploy pipeline", domain="ops", summary="Run the deploy pipeline", steps=["run"], tools_required=["process.execute"])
    hits = library.retrieve("run the deploy pipeline", available_tools={"workspace.read_file"})
    assert hits
    assert "missing tool(s)" in hits[0].reason


def test_retrieval_hides_deprecated_knowledge_by_default():
    library = ProcedureLibrary()
    library.add(procedure_id="p", name="Old approach to the login problem", domain="d", summary="login problem", steps=["a"])
    library.correct("p", reason="wrong", provenance="user")
    assert library.retrieve("login problem") == []
    assert [hit.procedure.id for hit in library.retrieve("login problem", include_deprecated=True)] == ["p"]


# ----------------------------------------------------------- orchestration


def test_unanimous_models_without_evidence_are_an_unverified_consensus():
    outputs = [
        AgentOutput(role="independent_analysis", model_id=f"m{index}", status="ok", statements=["The retry limit is 3 and the queue is empty."], provenance="model_generated")
        for index in range(3)
    ]
    result = reconcile(outputs)
    assert result.succeeded == 3
    assert result.consensus_status == "unverified_consensus"
    assert result.sufficiency == "insufficient"
    assert result.confidence <= 0.35
    assert any("not proof" in warning for warning in result.warnings)


def test_one_independent_observation_upgrades_the_consensus():
    outputs = [
        AgentOutput(role="independent_analysis", model_id="m1", status="ok", statements=["The retry limit is 3 and the queue is empty."], provenance="model_generated"),
        AgentOutput(role="tool_verification", model_id="m2", status="ok", statements=["The retry limit is 3 and the queue is empty."], evidence_refs=["tool:42"], provenance="tool_result"),
    ]
    result = reconcile(outputs)
    assert result.consensus_status == "confirmed"
    assert result.sufficiency == "sufficient"
    assert result.confidence > 0.5


def test_numeric_and_polarity_contradictions_are_detected():
    numeric = reconcile([
        AgentOutput(role="a", model_id="m1", status="ok", statements=["The worker retry limit is 3 in the deployed config."]),
        AgentOutput(role="b", model_id="m2", status="ok", statements=["The worker retry limit is 10 in the deployed config."]),
    ])
    assert numeric.consensus_status == "contested"
    assert numeric.contradictions[0].kind == "numeric"

    polarity = reconcile([
        AgentOutput(role="a", model_id="m1", status="ok", statements=["The cache is enabled for this route."]),
        AgentOutput(role="b", model_id="m2", status="ok", statements=["The cache is not enabled for this route."]),
    ])
    assert polarity.contradictions[0].kind == "polarity"
    assert "Settle the contradiction with an observation" in polarity.next_action


def test_unrelated_statements_are_not_reported_as_contradictions():
    result = reconcile([
        AgentOutput(role="a", model_id="m1", status="ok", statements=["The cache TTL is 300 seconds."]),
        AgentOutput(role="b", model_id="m2", status="ok", statements=["The deploy pipeline runs nightly."]),
    ])
    assert result.contradictions == []


def test_failed_participants_are_reported_not_silently_dropped():
    result = reconcile([
        AgentOutput(role="independent_analysis", model_id="m1", status="ok", statements=["The cache TTL is 300 seconds."], evidence_refs=["tool:1"], provenance="tool_result"),
        AgentOutput(role="independent_analysis", model_id="m2", status="failed", statements=[], error="rate limited"),
        AgentOutput(role="synthesis", model_id="m3", status="failed", statements=[], error="context overflow"),
    ])
    assert result.succeeded == 1
    assert result.failed_roles == ["independent_analysis", "synthesis"]
    assert any("produced nothing usable" in item for item in result.missing_evidence)
    # Evidence exists but only one analysis survived, so it cannot be 'confirmed'.
    assert result.consensus_status == "unverified_consensus"


def test_no_participants_is_a_failure_not_a_conclusion():
    result = reconcile([AgentOutput(role="a", model_id="m1", status="failed", statements=[], error="down")])
    assert result.consensus_status == "failed"
    assert result.confidence == 0.0
    assert result.consensus_provenance == "model_generated"


def test_roles_are_derived_from_the_objective_not_a_fixed_cast():
    diagnostic = derive_roles(
        "Diagnose why the API returns 500 and verify the fix with the test suite.",
        plan_steps=["Read the error log", "Run pytest to confirm"],
        available_tools={"process.execute", "workspace.read_file"},
        acceptance_criteria=["The 500 no longer reproduces.", "The suite passes."],
    )
    diagnostic_roles = {role.role for role in diagnostic.roles}
    assert "tool_verification" in diagnostic_roles
    assert "clarification" not in diagnostic_roles
    assert diagnostic.unassignable == []
    assert all(role.output_contract for role in diagnostic.roles)

    ambiguous = derive_roles("make it better", available_tools=set(), acceptance_criteria=[])
    ambiguous_roles = {role.role for role in ambiguous.roles}
    assert "tool_verification" not in ambiguous_roles
    assert "clarification" in ambiguous_roles


def test_a_subtask_that_cannot_be_verified_is_routed_to_clarification():
    plan = derive_roles("Confirm the service is healthy.", plan_steps=["Run the health check"], available_tools=set())
    assert len(plan.unassignable) == 1
    assert plan.subtasks[0].assigned_role == "clarification"
    assert "unverified claim" in plan.subtasks[0].blocking_reason


def test_role_identifiers_match_the_ones_the_orchestrator_already_emits():
    plan = derive_roles(
        "Compare the two retry strategies and pick one.",
        plan_steps=["Compare options", "Run the benchmark test"],
        available_tools={"process.execute"},
        provider_requests_remaining=12,
    )
    known = {"independent_analysis", "conflict_review", "synthesis", "targeted_critique", "revision"}
    assert {role.provider_role for role in plan.roles} <= known


def test_a_contested_objective_gets_an_extra_independent_pass():
    plain = derive_roles("Report the disk usage.", plan_steps=["Run df"])
    contested = derive_roles("Compare the options and decide which is best.", plan_steps=["Compare the options"])
    plain_passes = sum(1 for role in plain.roles if role.role == "independent_analysis")
    assert "because the objective itself poses a choice" in contested.rationale
    assert plain_passes == 1


def test_a_tiny_budget_reduces_coordination_instead_of_overspending():
    plan = derive_roles("Diagnose and verify the fix.", plan_steps=["Read log", "Run test"], available_tools={"process.execute"}, provider_requests_remaining=3)
    assert plan.provider_requests_estimate <= 3
    assert "provider request(s) remain" in plan.rationale


# --------------------------------------------------------- service + db


@pytest.fixture
def service(tmp_path):
    db = Database(tmp_path / "nova.sqlite3")
    db.initialize()
    return CognitionService(db=db, scope="test", workspace_root=str(tmp_path)), db


def test_service_persists_observations_and_resolves_predictions(service):
    cognition, db = service
    prediction_id = cognition.predict_tool_call("task-1", "process.execute", arguments={"command": "df"})
    assert prediction_id
    recorded = cognition.observe_tool_result(
        "task-1", "process.execute", {"status": "ok", "summary": "exit 0", "data": {"exit_code": 0}}, prediction_id=prediction_id
    )
    assert recorded["observations"] >= 2
    assert recorded["resolved"]["agreement"] == 1.0

    rows = db.list_observations("test")
    assert {row["predicate"] for row in rows} >= {"outcome", "status", "last_summary"}
    assert all(row["stale"] is False for row in rows)
    # The normalized class drives reasoning; the raw status is preserved too.
    by_predicate = {row["predicate"]: row["value"] for row in rows}
    assert by_predicate["outcome"] == "succeeded"
    assert by_predicate["status"] == "ok"
    assert db.list_predictions("test", resolved=True)


def test_a_failed_tool_call_becomes_a_contradiction_and_flags_reinspection(service):
    cognition, _db = service
    prediction_id = cognition.predict_tool_call("task-2", "process.execute")
    recorded = cognition.observe_tool_result("task-2", "process.execute", {"status": "error", "summary": "exit 1"}, prediction_id=prediction_id)
    assert recorded["resolved"]["agreement"] == 0.0
    assert recorded["resolved"]["contradicted"] == 1
    assert "tool:process.execute" in recorded["reinspection"]


def test_service_hydrates_persisted_state_after_a_restart(tmp_path):
    path = tmp_path / "nova.sqlite3"
    original = Database(path)
    original.initialize()
    first = CognitionService(db=original, scope="s", workspace_root=str(tmp_path))
    first.observe_tool_result("task-1", "workspace.read_file", {"status": "ok", "summary": "read 12 bytes"})
    first.procedures.add(procedure_id="p1", name="n", domain="d", summary="s", steps=["a"], provenance="tool_result")
    for index in range(3):
        first.procedures.record_outcome("p1", success=True, evidence_ref=f"t:{index}")
    first.db.upsert_procedure(first.procedures.get("p1").to_dict())
    first.record_calibration(0.8, True, statement="s", domain="task", task_id="task-1")

    reopened = Database(path)
    reopened.initialize()
    second = CognitionService(db=reopened, scope="s", workspace_root=str(tmp_path))
    counts = second.hydration_counts
    assert counts["observations"] >= 1
    assert counts["procedures"] == 1
    assert counts["calibration"] == 1
    # Hydration is idempotent: a second call must not double-count anything.
    assert second.hydrate() == {"observations": 0, "predictions": 0, "procedures": 0, "calibration": 0}
    assert second.procedures.get("p1").attempts == 3
    assert second.procedures.get("p1").status == "established"
    assert second.world_model.value_of("tool:workspace.read_file", "outcome") == "succeeded"
    assert second.world_model.value_of("tool:workspace.read_file", "status") == "ok"


def test_learning_reinforces_a_matching_procedure_instead_of_duplicating_it(service):
    cognition, db = service
    objective = "Fix the failing login test in the auth module"
    first = cognition.learn_from_task(
        task_id="t1", objective=objective, state="completed", plan={"steps": ["reproduce", "patch", "re-run"]},
        tool_outcomes=[{"tool": "process.execute", "status": "ok"}], verification="passed",
    )
    assert first["action"] == "created"
    assert first["status"] == "candidate"

    second = cognition.learn_from_task(
        task_id="t2", objective=objective, state="completed", plan={"steps": ["reproduce", "patch", "re-run"]},
        tool_outcomes=[{"tool": "process.execute", "status": "ok"}], verification="passed",
    )
    assert second["action"] == "reinforced"
    assert second["procedure_id"] == first["procedure_id"]
    assert second["attempts"] == 2
    assert len(cognition.procedures) == 1
    assert len(db.list_procedures()) == 1


def test_learning_never_establishes_a_procedure_from_one_run(service):
    cognition, _db = service
    info = cognition.learn_from_task(
        task_id="t1", objective="Migrate the database schema", state="completed", plan={"steps": ["dump", "migrate"]},
        tool_outcomes=[{"tool": "process.execute", "status": "ok"}], verification="passed",
    )
    assert info["status"] == "candidate"
    assert info["attempts"] == 1


def test_learning_records_failures_as_failures(service):
    cognition, _db = service
    info = cognition.learn_from_task(
        task_id="t1", objective="Rebuild the docker image", state="failed", plan={"steps": ["build"]},
        tool_outcomes=[{"tool": "process.execute", "status": "error"}], verification="failed",
    )
    assert info["attempts"] == 1
    assert info["status"] == "candidate"
    assert "failed attempt" in info["note"]


def test_learning_skips_runs_with_nothing_to_learn_from(service):
    cognition, _db = service
    info = cognition.learn_from_task(task_id="t1", objective="", state="completed", plan={"steps": []}, tool_outcomes=[])
    assert info["action"] == "skipped"


def test_finalize_records_calibration_only_when_a_prediction_exists(service):
    cognition, db = service
    cognition.review_plan("task-1", "Fix the failing login test and verify it.", {"steps": ["patch", "run pytest"]})
    result = cognition.finalize("task-1", "completed", objective="Fix the failing login test and verify it.", checkpoint={"tool_results": [{"tool": "process.execute", "status": "ok"}]}, verification="passed")
    assert result["calibration"]["recorded"] is True
    assert result["posthoc"]["cause"] in {"success", "bad_success_criterion"}
    assert db.list_calibration_records()

    no_prediction = cognition.finalize("task-9", "completed", objective="Something else entirely", checkpoint={})
    assert no_prediction["calibration"]["recorded"] is False
    assert "No pre-flight prediction" in no_prediction["calibration"]["reason"]


def test_finalize_survives_a_database_that_raises(tmp_path):
    class BrokenDatabase(Database):
        def save_review(self, *args, **kwargs):
            raise RuntimeError("disk full")

        def save_observation(self, *args, **kwargs):
            raise RuntimeError("disk full")

    broken = BrokenDatabase(tmp_path / "broken.sqlite3")
    broken.initialize()
    cognition = CognitionService(db=broken, scope="s", workspace_root=str(tmp_path))
    cognition.observe_tool_result("t", "process.execute", {"status": "ok", "summary": "fine"})
    result = cognition.finalize("t", "completed", objective="Do something", checkpoint={"tool_results": [{"status": "ok"}]})
    assert cognition.errors > 0
    assert cognition.snapshot()["degraded"] is True
    assert "disk full" in cognition.last_error
    assert result["posthoc"] is not None


def test_preflight_review_is_persisted_and_rehydrated(service):
    cognition, db = service
    payload = cognition.review_plan("task-1", "Reboot the server and email the customer.", {"steps": ["Reboot the server", "Send email"]})
    assert payload["proceed"] == "blocked"
    assert db.get_reviews("task-1", "preflight")

    from nova.cognition.service import _rehydrate_preflight

    review = _rehydrate_preflight(payload)
    assert review is not None
    assert review.proceed == "blocked"
    assert review.blocking_capability_gaps == payload["blocking_capability_gaps"]


def test_decisions_are_persisted_and_resolved_separately_from_forecasts(service):
    cognition, db = service
    payload = cognition.decide(
        "Find the wrong port.",
        [{"id": "read-config", "description": "Read the config", "estimated_minutes": 1.0, "risk": 0.02}],
        task_id="task-1",
    )
    assert payload["id"]
    assert len(db.list_decisions(unresolved_only=True)) == 1
    assert cognition.resolve_decision(payload["id"], "The port was wrong in the config.")
    stored = db.list_decisions()[0]
    assert stored["actual_outcome"] == "The port was wrong in the config."
    assert stored["prediction_matched"] is True
    assert stored["resolved_at"]


def test_resolve_decision_treats_an_error_outcome_as_a_missed_prediction(service):
    cognition, db = service
    payload = cognition.decide("Deploy.", [{"id": "a", "description": "Deploy now", "risk": 0.1}], task_id="t")
    cognition.resolve_decision(payload["id"], "The deploy failed with a timeout.")
    assert db.list_decisions()[0]["prediction_matched"] is False


def test_knowledge_gaps_are_resolved_within_the_authorized_workspace(service, tmp_path):
    cognition, _db = service
    plan = cognition.resolve_knowledge_gap(
        "What is in the config?", candidate_paths=(str(tmp_path / "config.yaml"), "/etc/shadow")
    )
    assert plan["refused_paths"] == ["/etc/shadow"]
    assert cognition.exploration.gaps_planned == 1


def test_signature_is_stable_for_the_same_objective_and_differs_across_objectives():
    assert _signature("Fix the login bug") == _signature("fix the LOGIN bug")
    assert _signature("Fix the login bug") != _signature("Migrate the database")


def test_environment_markers_are_measured_not_assumed():
    markers = environment_markers("/tmp/x")
    assert markers["os"]
    assert markers["python"]
    assert markers["workspace"] == "/tmp/x"


def test_beliefs_summarise_the_world_model(service):
    cognition, _db = service
    cognition.observe_tool_result("t", "process.execute", {"status": "ok", "summary": "exit 0"})
    beliefs = cognition.beliefs()
    assert beliefs["summary"]["total"] >= 1
    assert beliefs["snapshot"]["observations"]


def test_cognition_context_renders_only_what_was_actually_derived():
    assert _cognition_context({}) == ""
    assert _cognition_context({"cognition": {}}) == ""
    context = _cognition_context({
        "cognition": {
            "preflight": {
                "acceptance_criteria": ["A test passes."],
                "blocking_capability_gaps": ["outbound communication"],
                "cheapest_verification": "Run the tests.",
            },
            "requires_reinspection": ["tool:process.execute"],
        }
    })
    assert "A test passes." in context
    assert "outbound communication" in context
    assert "re-check them" in context


# -------------------------------------------------- engine integration


@pytest.mark.asyncio
async def test_a_real_task_run_drives_the_whole_cognition_loop(environment):
    settings, db, registry, workspace = environment
    provider = FakeProvider([
        msg('{"summary":"Calculate the requested percentage.","steps":["Compute 18 percent of 2450","Report the result"]}'),
        msg(None, [{
            "id": "call-1", "type": "function",
            "function": {"name": "math.calculate", "arguments": json.dumps({"expression": "2450 * 0.18"})},
        }]),
        msg("18% of 2,450 is 441. The calculator tool returned 441.0."),
        msg('{"status":"verified","note":"The arithmetic tool produced 441.0, supporting the requested calculation."}'),
    ])
    task_id = db.create_task("Calculate 18% of 2450 and verify the result", review_plan=False)
    engine = TaskEngine(db, provider, registry, settings)
    await engine.run_task(task_id)

    task = db.get_task(task_id)
    assert task["state"] == "completed"

    # The plan was assessed before execution, and the assessment is on the record.
    preflight_reviews = db.get_reviews(task_id, "preflight")
    assert len(preflight_reviews) == 1
    assert preflight_reviews[0]["payload"]["acceptance_criteria"]
    assert task["checkpoint"]["cognition"]["preflight"]["proceed"] in {"proceed", "gather_information_first", "blocked"}

    # The tool call was predicted, executed, observed and the prediction resolved.
    cognition_state = task["checkpoint"]["cognition"]
    assert cognition_state["predictions"] == 1
    assert cognition_state["observations"] >= 2
    assert "pending_prediction" not in cognition_state
    assert cognition_state.get("contradictions", 0) == 0
    resolved = db.list_predictions(engine.cognition.scope, resolved=True)
    assert resolved and resolved[0]["agreement"] == 1.0
    assert engine.cognition.world_model.requires_reinspection() == []

    # The real result became a world-model observation, in both the normalized
    # outcome class and the tool's own raw status vocabulary.
    observations = db.list_observations(engine.cognition.scope)
    observed = {(row["subject"], row["predicate"]): row["value"] for row in observations}
    assert observed[("tool:math.calculate", "outcome")] == "succeeded"
    assert observed[("tool:math.calculate", "status")] == "success"

    # Post-hoc attribution and calibration were recorded for the finished run.
    posthoc_reviews = db.get_reviews(task_id, "posthoc")
    assert len(posthoc_reviews) == 1
    assert posthoc_reviews[0]["payload"]["cause"] in {"success", "bad_success_criterion"}
    assert db.list_calibration_records()

    # And the run became a candidate procedure - not an established one.
    procedures = db.list_procedures()
    assert len(procedures) == 1
    assert procedures[0]["status"] == "candidate"
    assert procedures[0]["attempts"] == 1
    assert task_id in procedures[0]["source_task_ids"]

    kinds = [event["kind"] for event in db.get_task_events(task_id)]
    assert kinds.count("cognition") >= 2


@pytest.mark.asyncio
async def test_the_assessment_reaches_the_executing_model(environment):
    settings, db, registry, _workspace = environment
    provider = FakeProvider([
        msg('{"summary":"Reboot and notify.","steps":["Reboot the production server","Email the customer the report"]}'),
        msg("I cannot reboot the server or send email; neither capability is installed."),
        msg('{"status":"insufficient","note":"No tool result supports either step."}'),
    ])
    task_id = db.create_task("Reboot the server and email the report to the customer.", review_plan=False)
    engine = TaskEngine(db, provider, registry, settings)
    await engine.run_task(task_id)

    # The blocking gaps were reported to the user through the task timeline.
    events = [event for event in db.get_task_events(task_id) if event["kind"] == "cognition"]
    assert events
    assert any("blocked" in str(event["message"]) for event in events)

    # And they were placed in front of the model that executes the plan.
    execution_prompt = json.dumps(provider.calls[1][0])
    assert "Capability gaps" in execution_prompt
    assert "outbound communication" in execution_prompt
    assert "Acceptance criteria" in execution_prompt


@pytest.mark.asyncio
async def test_a_denied_tool_call_is_attributed_to_availability_not_the_plan(environment):
    settings, db, registry, workspace = environment
    db.update_autonomy_policy("routine", {"workspace.write_file": "deny"}, [])
    provider = FakeProvider([
        msg('{"summary":"Write the report.","steps":["Save report.txt"]}'),
        msg(None, [{
            "id": "call-1", "type": "function",
            "function": {"name": "workspace.write_file", "arguments": json.dumps({"path": "report.txt", "content": "x"})},
        }]),
        msg("The write was blocked by policy."),
        msg('{"status":"unverified","note":"No tool result supports the outcome."}'),
    ])
    task_id = db.create_task("Write the report to report.txt", review_plan=False)
    engine = TaskEngine(db, provider, registry, settings)
    await engine.run_task(task_id)

    reviews = db.get_reviews(task_id, "posthoc")
    assert reviews, "a finished run must always get a post-hoc review"
    payload = reviews[-1]["payload"]
    assert payload["cause"] == "unavailable_tool"
    assert payload["actual_outcome"] is False
    assert "blocked by policy" in payload["explanation"].lower() or "denied" in payload["explanation"].lower()
    assert not (workspace / "report.txt").exists()

    events = [event for event in db.get_task_events(task_id) if event["kind"] == "cognition"]
    assert any("unavailable_tool" in str(event["payload"]) for event in events)


@pytest.mark.asyncio
async def test_an_unfinished_task_gets_no_post_hoc_attribution(environment):
    settings, db, registry, workspace = environment
    existing = workspace / "brief.txt"
    existing.write_text("old content", encoding="utf-8")
    provider = FakeProvider([
        msg('{"summary":"Update the brief.","steps":["Write the new content"]}'),
        msg(None, [{
            "id": "call-write", "type": "function",
            "function": {"name": "workspace.write_file", "arguments": json.dumps({"path": "brief.txt", "content": "new content"})},
        }]),
    ])
    task_id = db.create_task("Update brief.txt with new content", review_plan=False)
    engine = TaskEngine(db, provider, registry, settings)
    await engine.run_task(task_id)

    task = db.get_task(task_id)
    assert task["state"] == "waiting_approval"
    # The plan was assessed, but nothing is concluded about an unfinished run.
    assert db.get_reviews(task_id, "preflight")
    assert db.get_reviews(task_id, "posthoc") == []
    assert db.list_procedures() == []
    # The pending write never happened while the task waits on the user.
    assert existing.read_text(encoding="utf-8") == "old content"


@pytest.mark.asyncio
async def test_a_cognition_failure_cannot_break_task_execution(environment, monkeypatch):
    settings, db, registry, _workspace = environment

    class ExplodingCognition(CognitionService):
        def review_plan(self, *args, **kwargs):
            raise RuntimeError("cognition is broken")

        def observe_tool_result(self, *args, **kwargs):
            raise RuntimeError("cognition is broken")

        def finalize(self, *args, **kwargs):
            raise RuntimeError("cognition is broken")

        def predict_tool_call(self, *args, **kwargs):
            raise RuntimeError("cognition is broken")

    provider = FakeProvider([
        msg('{"summary":"Calculate.","steps":["Compute 18 percent of 2450"]}'),
        msg(None, [{"id": "c1", "type": "function", "function": {"name": "math.calculate", "arguments": json.dumps({"expression": "2450 * 0.18"})}}]),
        msg("The result is 441."),
        msg('{"status":"verified","note":"The calculator returned 441.0."}'),
    ])
    task_id = db.create_task("Calculate 18% of 2450", review_plan=False)
    engine = TaskEngine(db, provider, registry, settings, cognition=ExplodingCognition(db=db, workspace_root=str(settings.workspace_dir)))
    await engine.run_task(task_id)

    task = db.get_task(task_id)
    assert task["state"] == "completed"
    assert "441" in task["result"]
    assert task["verification"] == "verified"


# --------------------------------------------------------------- evaluation


def test_the_gie_suite_passes_with_a_real_database(tmp_path):
    db = Database(tmp_path / "eval.sqlite3")
    db.initialize()
    report = run_suite(EvalContext(workspace_root=str(tmp_path), db=db, authorized_roots=(str(tmp_path),)))
    failed = [(item.case.id, item.detail) for item in report.results if item.status != "passed"]
    assert not failed, f"failing cases: {failed}"
    assert report.suite_version == SUITE_VERSION
    assert report.totals["total"] == 27
    assert report.pass_rate == 1.0
    assert report.held_out_pass_rate is None


def test_held_out_cases_are_excluded_by_default_and_reported_separately(tmp_path):
    default = run_suite(EvalContext(workspace_root=str(tmp_path)))
    assert all(not item.case.held_out for item in default.results)
    assert default.held_out_pass_rate is None

    full = run_suite(EvalContext(workspace_root=str(tmp_path)), include_held_out=True)
    assert len(full.results) == len(default.results) + 3
    assert full.held_out_pass_rate == 1.0
    assert any("held-out" in item for item in full.claim_limitations)


def test_a_baseline_with_no_case_rows_is_not_treated_as_comparable(tmp_path):
    report = run_suite(EvalContext(workspace_root=str(tmp_path)), baseline={"suite_version": SUITE_VERSION, "cases": {}})
    assert report.comparable_to_baseline is False
    assert any("stored no per-case results" in item for item in report.claim_limitations)


def test_a_version_mismatched_baseline_is_not_compared(tmp_path):
    report = run_suite(EvalContext(workspace_root=str(tmp_path)), baseline={"suite_version": "nova-gie-v0", "cases": {"x": {"status": "passed"}}})
    assert report.comparable_to_baseline is False
    assert any("nova-gie-v0" in item for item in report.claim_limitations)


def test_regressions_are_detected_against_a_real_baseline(tmp_path):
    db = Database(tmp_path / "eval.sqlite3")
    db.initialize()
    baseline_report = run_suite(EvalContext(workspace_root=str(tmp_path), db=db))
    baseline = {
        "suite_version": baseline_report.suite_version,
        "cases": {item.case.id: {"status": item.status} for item in baseline_report.results},
    }
    # Simulate a regression: a case that passed in the baseline now fails.
    baseline["cases"]["staleness_is_detected"]["status"] = "passed"
    report = run_suite(EvalContext(workspace_root=str(tmp_path), db=db), baseline=baseline, case_ids=["staleness_is_detected"])
    assert report.comparable_to_baseline is True
    assert report.regressions == []

    baseline["cases"]["staleness_is_detected"]["status"] = "failed"
    improved = run_suite(EvalContext(workspace_root=str(tmp_path), db=db), baseline=baseline, case_ids=["staleness_is_detected"])
    assert improved.improvements == ["staleness_is_detected"]


def test_the_suite_never_claims_general_intelligence(tmp_path):
    report = run_suite(EvalContext(workspace_root=str(tmp_path)))
    joined = " ".join(report.claim_limitations).lower()
    assert "not a measure of general intelligence" in joined
    assert "agi" in joined or "human-level" in joined
    assert "held-out" in joined or "deterministic" in joined


def test_a_case_that_raises_is_reported_as_a_failure_not_hidden(tmp_path):
    from nova.cognition import evaluation as ev

    original = list(ev._CASES)
    try:
        def boom(_ctx):
            raise RuntimeError("deliberate")

        ev._CASES.append(ev.EvalCase(id="deliberate_crash", capability="problem_solving", title="crashes", held_out=False, run=boom))
        report = run_suite(EvalContext(workspace_root=str(tmp_path)), case_ids=["deliberate_crash"])
        assert report.results[0].status == "failed"
        assert "deliberate_crash" in report.summary or report.totals["failed"] == 1
        assert "RuntimeError" in report.results[0].detail
    finally:
        ev._CASES[:] = original


def test_a_skipped_case_is_reported_as_skipped_with_its_reason(tmp_path):
    report = run_suite(EvalContext(workspace_root=str(tmp_path)), case_ids=["plan_persists_across_restart"])
    assert report.results[0].status == "skipped"
    assert "database" in report.results[0].detail.lower()
    assert report.totals["skipped"] == 1
    assert any("skipped" in item for item in report.claim_limitations)
    # A skipped case is not scored as a pass.
    assert report.pass_rate == 0.0


def test_the_suite_runs_without_any_provider_calls(tmp_path, monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("the evaluation suite must not call a provider")

    monkeypatch.setattr("nova.provider.OpenAICompatibleProvider.chat", explode, raising=False)
    db = Database(tmp_path / "eval.sqlite3")
    db.initialize()
    report = run_suite(EvalContext(workspace_root=str(tmp_path), db=db, authorized_roots=(str(tmp_path),)), include_held_out=True)
    assert report.totals["failed"] == 0
    assert report.totals["skipped"] == 0
    assert report.totals["passed"] == 30


def test_service_runs_the_suite_and_persists_a_reusable_baseline(tmp_path):
    db = Database(tmp_path / "eval.sqlite3")
    db.initialize()
    cognition = CognitionService(db=db, scope="test", workspace_root=str(tmp_path))
    payload = cognition.run_evaluation(commit="abc1234")
    assert payload["run_id"]
    assert payload["pass_rate"] == 1.0

    baseline = db.get_latest_intelligence_baseline(SUITE_VERSION)
    assert baseline["commit"] == "abc1234"
    assert len(baseline["cases"]) == 27

    second = cognition.run_evaluation()
    assert second["comparable_to_baseline"] is True
    assert second["regressions"] == []

    # A held-out run is stored, but is never selected as a baseline.
    held_out = cognition.run_evaluation(include_held_out=True)
    assert held_out["totals"]["total"] == 30
    runs = db.list_intelligence_eval_runs(SUITE_VERSION)
    assert len(runs) == 3
    assert sum(1 for run in runs if run["include_held_out"]) == 1
    assert db.get_latest_intelligence_baseline(SUITE_VERSION)["include_held_out"] is False


def test_suite_manifest_describes_every_case(tmp_path):
    from nova.cognition.evaluation import suite_manifest

    manifest = suite_manifest()
    assert manifest["suite_version"] == SUITE_VERSION
    assert manifest["case_count"] == 30
    assert manifest["held_out_count"] == 3
    executed = {item.case.id for item in run_suite(EvalContext(workspace_root=str(tmp_path)), include_held_out=True).results}
    assert {item["id"] for item in manifest["cases"]} == executed
    assert all(item["label"].startswith("§") for item in manifest["capabilities"])
    assert {item["id"] for item in manifest["capabilities"] if item["cases"]} <= {item["capability"] for item in manifest["cases"]}
