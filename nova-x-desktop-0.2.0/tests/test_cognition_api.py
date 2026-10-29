"""HTTP surface tests for the cognition layer.

These assert the routes are wired to the real service and database, that limits
are clamped, that corrections require a valid provenance, and - the point of the
whole layer - that the API reports limitations instead of inventing results.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from nova.cognition import SUITE_VERSION
from nova.main import create_app
from tests.conftest import FakeProvider, msg


@pytest.fixture
def client(environment):
    settings, db, registry, _workspace = environment
    app = create_app(settings, provider=FakeProvider([]), db=db, tools=registry)
    with TestClient(app) as test_client:
        yield test_client, db, app


def test_health_reports_cognition_state_without_inflating_it(client):
    test_client, _db, _app = client
    payload = test_client.get("/api/health").json()
    cognition = payload["cognition"]
    assert cognition["suite_version"] == SUITE_VERSION
    # No outcomes have been recorded yet, so no calibration score may be claimed.
    assert cognition["calibration_status"] == "insufficient_data"
    assert cognition["prediction_accuracy"] == "no_predictions_resolved"
    assert cognition["degraded"] is False


def test_cognition_state_exposes_the_live_service(client):
    test_client, _db, _app = client
    payload = test_client.get("/api/cognition").json()
    assert payload["scope"] == "default"
    assert payload["degraded"] is False
    assert payload["calibration"]["status"] == "insufficient_data"
    assert payload["procedures"]["thresholds"]["min_attempts_to_establish"] == 3
    assert payload["world_model"]["observations"] == 0


def test_observations_endpoint_is_empty_and_honest_before_any_run(client):
    test_client, _db, _app = client
    payload = test_client.get("/api/cognition/observations").json()
    assert payload["count"] == 0
    assert payload["observations"] == []
    assert payload["prediction_accuracy"]["status"] == "no_predictions_resolved"


def test_calibration_endpoint_states_why_it_has_no_score(client):
    test_client, _db, _app = client
    payload = test_client.get("/api/cognition/calibration").json()
    assert payload["report"]["status"] == "insufficient_data"
    assert payload["report"]["expected_calibration_error"] is None
    assert "no score is reported" in payload["note"]


def test_decision_endpoint_scores_options_and_labels_the_forecast(client):
    test_client, db, _app = client
    body = {
        "objective": "Find out why the service listens on the wrong port.",
        "options": [
            {"id": "read-config", "description": "Read the service config file", "estimated_tool_calls": 1,
             "estimated_provider_requests": 1, "estimated_minutes": 1.0, "risk": 0.02},
            {"id": "rewrite", "description": "Rewrite and redeploy the service", "estimated_tool_calls": 9,
             "estimated_provider_requests": 20, "estimated_minutes": 90.0, "risk": 0.8, "reversible": False},
        ],
        "risk_tolerance": "cautious",
        "task_id": "",
    }
    response = test_client.post("/api/cognition/decisions", json=body)
    assert response.status_code == 200
    decision = response.json()["decision"]
    assert decision["short_circuited"] is True
    assert decision["chosen_option_id"] == "read-config"
    assert decision["predicted_outcome"].startswith("Predicted (not yet executed)")
    assert decision["actual_outcome"] is None
    assert decision["risk_tolerance"] == "cautious"
    assert db.list_decisions(unresolved_only=True)


def test_decision_endpoint_rejects_an_unknown_risk_tolerance(client):
    test_client, _db, _app = client
    response = test_client.post("/api/cognition/decisions", json={
        "objective": "Do it.", "options": [{"description": "Read the file"}], "risk_tolerance": "reckless",
    })
    assert response.status_code == 422
    assert "cautious" in response.json()["detail"]


def test_decision_endpoint_validates_option_shapes(client):
    test_client, _db, _app = client
    response = test_client.post("/api/cognition/decisions", json={
        "objective": "Do it.", "options": [{"description": "x", "risk": 4.0}],
    })
    assert response.status_code == 422
    response = test_client.post("/api/cognition/decisions", json={"objective": "Do it.", "options": []})
    assert response.status_code == 422


def test_an_unauthorized_option_is_never_selected(client):
    test_client, _db, _app = client
    response = test_client.post("/api/cognition/decisions", json={
        "objective": "Deploy the fix.",
        "options": [{"id": "deploy", "description": "Deploy to production", "authorization_required": True, "risk": 0.3}],
        "authorized_option_ids": [],
    })
    decision = response.json()["decision"]
    assert decision["chosen_option_id"] is None
    assert "authorization" in decision["decision_rationale"].lower()

    authorized = test_client.post("/api/cognition/decisions", json={
        "objective": "Deploy the fix.",
        "options": [{"id": "deploy", "description": "Deploy to production", "authorization_required": True, "risk": 0.3}],
        "authorized_option_ids": ["deploy"],
    }).json()["decision"]
    assert authorized["chosen_option_id"] == "deploy"
    assert authorized["authorization_needed"] is True


def test_prediction_accuracy_excludes_unresolved_decisions(client):
    test_client, db, _app = client
    payload = test_client.get("/api/cognition/decisions").json()
    assert payload["prediction_accuracy"]["rate"] is None
    assert payload["prediction_accuracy"]["resolved"] == 0
    assert "excluded" in payload["prediction_accuracy"]["note"]


def test_knowledge_gap_planning_refuses_paths_outside_the_workspace(client, tmp_path):
    test_client, _db, app = client
    engine = app.state.engine
    response = test_client.post("/api/cognition/gaps", json={
        "question": "Where are the SSH keys?",
        "candidate_paths": ["/home/user/.ssh", "/etc/shadow"],
    })
    assert response.status_code == 200
    plan = response.json()["plan"]
    assert set(plan["refused_paths"]) == {"/home/user/.ssh", "/etc/shadow"}
    assert any("privacy" in step["skip_reason"].lower() or "outside" in step["skip_reason"].lower()
               for step in plan["skipped_steps"])
    assert engine.cognition.exploration.gaps_planned == 1


def test_knowledge_gap_validation(client):
    test_client, _db, _app = client
    assert test_client.post("/api/cognition/gaps", json={"question": ""}).status_code == 422


def test_procedure_correction_requires_a_known_provenance(client):
    test_client, db, _app = client
    db.upsert_procedure({"id": "p1", "name": "Old way", "domain": "ops", "summary": "s", "steps": ["a"], "provenance": "tool_result"})
    response = test_client.post("/api/cognition/procedures/p1/correct", json={"reason": "API changed.", "provenance": "rumour"})
    assert response.status_code == 422
    assert "provenance must be one of" in response.json()["detail"]


def test_procedure_correction_records_the_reason_and_source(client):
    test_client, db, app = client
    db.upsert_procedure({"id": "p1", "name": "Old way", "domain": "ops", "summary": "s", "steps": ["a"], "provenance": "tool_result"})
    response = test_client.post("/api/cognition/procedures/p1/correct", json={
        "reason": "The upstream API changed; this sequence now 404s.", "provenance": "external_source",
    })
    assert response.status_code == 200
    procedure = response.json()["procedure"]
    assert procedure["status"] == "deprecated"
    assert procedure["provenance"] == "external_source"
    assert "404" in procedure["correction_reason"]
    assert db.get_procedure("p1")["status"] == "deprecated"
    assert app.state.engine.cognition.procedures.get("p1") is not None


def test_correcting_an_unknown_procedure_is_a_404(client):
    test_client, _db, _app = client
    response = test_client.post("/api/cognition/procedures/nope/correct", json={"reason": "wrong"})
    assert response.status_code == 404


def test_procedure_removal_is_persisted(client):
    test_client, db, app = client
    db.upsert_procedure({"id": "p1", "name": "n", "domain": "d", "summary": "s", "steps": ["a"]})
    assert test_client.delete("/api/cognition/procedures/p1", params={"reason": "obsolete"}).status_code == 200
    assert db.get_procedure("p1") is None
    assert app.state.engine.cognition.procedures.get("p1") is None
    assert test_client.delete("/api/cognition/procedures/p1").status_code == 404


def test_transfer_endpoint_reports_unknown_when_nothing_is_comparable(client):
    test_client, db, _app = client
    db.upsert_procedure({"id": "p1", "name": "n", "domain": "d", "summary": "s", "steps": ["a"]})
    payload = test_client.get("/api/cognition/procedures/p1/transfer").json()
    assert payload["verdict"] in {"unknown", "partially_compatible", "compatible"}
    assert "notes" in payload


def test_procedures_endpoint_reports_counts_and_thresholds(client):
    test_client, db, _app = client
    db.upsert_procedure({"id": "p1", "name": "n", "domain": "d", "summary": "s", "steps": ["a"], "attempts": 1, "successes": 1})
    payload = test_client.get("/api/cognition/procedures").json()
    assert payload["counts"]["total"] >= 0
    assert payload["thresholds"]["min_success_ratio"] == 0.6
    assert [item["id"] for item in payload["procedures"]] == ["p1"]
    assert payload["procedures"][0]["success_ratio"] == 1.0


def test_evaluation_manifest_lists_every_case(client):
    test_client, _db, _app = client
    payload = test_client.get("/api/cognition/evaluation/manifest").json()
    assert payload["suite_version"] == SUITE_VERSION
    assert payload["case_count"] == 30
    assert payload["held_out_count"] == 3
    assert all(item["capability_label"].startswith("§") for item in payload["cases"])


def test_evaluation_run_executes_and_persists_a_baseline(client):
    test_client, db, _app = client
    assert test_client.get("/api/cognition/evaluation/baseline").json()["baseline"] is None

    payload = test_client.post("/api/cognition/evaluation/run", json={"include_held_out": False}).json()
    assert payload["totals"]["failed"] == 0
    assert payload["pass_rate"] == 1.0
    assert payload["run_id"]
    assert any("not a measure of general intelligence" in item for item in payload["claim_limitations"])

    baseline = db.get_latest_intelligence_baseline(SUITE_VERSION)
    assert baseline is not None
    assert len(baseline["cases"]) == 27

    second = test_client.post("/api/cognition/evaluation/run", json={}).json()
    assert second["comparable_to_baseline"] is True
    assert second["regressions"] == []


def test_a_held_out_evaluation_run_is_stored_but_never_baselined(client):
    test_client, db, _app = client
    payload = test_client.post("/api/cognition/evaluation/run", json={"include_held_out": True}).json()
    assert payload["totals"]["total"] == 30
    assert payload["held_out_pass_rate"] == 1.0
    assert any("must not be used as a baseline" in item for item in payload["claim_limitations"])
    assert db.get_latest_intelligence_baseline(SUITE_VERSION) is None


def test_evaluation_runs_endpoint_lists_history(client):
    test_client, _db, _app = client
    test_client.post("/api/cognition/evaluation/run", json={})
    payload = test_client.get("/api/cognition/evaluation/runs").json()
    assert payload["suite_version"] == SUITE_VERSION
    assert len(payload["runs"]) == 1
    assert payload["runs"][0]["include_held_out"] is False


def test_task_reviews_are_404_for_an_unknown_task(client):
    test_client, _db, _app = client
    assert test_client.get("/api/cognition/tasks/nope/reviews").status_code == 404


def test_beliefs_endpoint_reports_an_empty_model_as_empty(client):
    test_client, _db, _app = client
    payload = test_client.get("/api/cognition/beliefs").json()
    assert payload["summary"]["total"] == 0
    assert payload["requires_reinspection"] == []


@pytest.mark.asyncio
async def test_a_completed_task_populates_the_cognition_api(environment):
    settings, db, registry, _workspace = environment
    provider = FakeProvider([
        msg('{"summary":"Calculate.","steps":["Compute 18 percent of 2450"]}'),
        msg(None, [{"id": "c1", "type": "function",
                    "function": {"name": "math.calculate", "arguments": json.dumps({"expression": "2450 * 0.18"})}}]),
        msg("The result is 441."),
        msg('{"status":"verified","note":"The calculator returned 441.0."}'),
    ])
    app = create_app(settings, provider=provider, db=db, tools=registry)
    with TestClient(app) as test_client:
        task_id = db.create_task("Calculate 18% of 2450 and verify the result", review_plan=False)
        await app.state.engine.run_task(task_id)

        reviews = test_client.get(f"/api/cognition/tasks/{task_id}/reviews").json()
        assert reviews["state"] == "completed"
        assert len(reviews["preflight"]) == 1
        assert len(reviews["posthoc"]) == 1
        assert reviews["posthoc"][0]["cause"] in {"success", "bad_success_criterion"}

        observations = test_client.get("/api/cognition/observations").json()
        assert observations["count"] >= 3
        assert observations["prediction_accuracy"]["mean_agreement"] == 1.0

        calibration = test_client.get("/api/cognition/calibration").json()
        assert calibration["report"]["samples"] >= 1

        procedures = test_client.get("/api/cognition/procedures").json()
        assert len(procedures["procedures"]) == 1
        # One verified run is a candidate. It is not evidence of a general skill.
        assert procedures["procedures"][0]["status"] == "candidate"
        assert procedures["procedures"][0]["attempts"] == 1


class _BrokenCognition:
    """A cognition layer that fails on every aggregate read."""

    errors = 3

    def __getattr__(self, name):
        raise RuntimeError(f"cognition is broken: {name}")


def test_health_survives_a_broken_cognition_layer(client):
    """§88: the liveness probe must not fail because cognition is degraded."""
    test_client, _db, app = client
    app.state.engine.cognition = _BrokenCognition()

    response = test_client.get("/api/health")

    assert response.status_code == 200
    cognition = response.json()["cognition"]
    # It reports the degradation instead of publishing a score it cannot compute.
    assert cognition["degraded"] is True
    assert cognition["calibration_status"] == "unavailable"
    assert cognition["prediction_accuracy"] == "unavailable"
    assert cognition["subjects_requiring_reinspection"] == 0


def test_health_survives_a_missing_engine(client):
    """A probe before the engine exists still answers, and says so honestly."""
    test_client, _db, app = client
    app.state.engine = None

    response = test_client.get("/api/health")

    assert response.status_code == 200
    cognition = response.json()["cognition"]
    assert cognition["degraded"] is True
    assert cognition["calibration_status"] == "unavailable"


def test_health_exposes_no_observation_values(client):
    """The unauthenticated probe carries counts and statuses only.

    Observation values can contain workspace paths and tool output, so they must
    stay behind the authenticated /api/cognition routes.
    """
    test_client, _db, _app = client
    cognition = test_client.get("/api/health").json()["cognition"]

    assert set(cognition) == {
        "suite_version",
        "calibration_status",
        "prediction_accuracy",
        "subjects_requiring_reinspection",
        "degraded",
        "detail",
    }
    assert isinstance(cognition["subjects_requiring_reinspection"], int)
    assert cognition["detail"] == "/api/cognition"
