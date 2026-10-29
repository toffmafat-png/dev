from __future__ import annotations

import pytest
from pydantic import BaseModel

from nova.autonomy import AutonomyPolicy
from nova.tools.registry import ToolDefinition, ToolOutcome


class _ActionInput(BaseModel):
    value: str = ""


async def _action_handler(_args: BaseModel, _approved: bool) -> ToolOutcome:
    return ToolOutcome("success", "done")


def test_default_routine_policy_allows_only_registered_routine_tools(environment):
    settings, db, registry, _workspace = environment
    policy = AutonomyPolicy(settings, db, registry)

    assert policy.get()["level"] == "routine"
    assert policy.decide("math.calculate", {"expression": "1 + 1"})["action"] == "allow"
    assert policy.decide("unknown.tool", {})["action"] == "deny"


def test_assisted_level_requires_plan_and_each_tool_action_unless_narrowly_overridden(environment):
    settings, db, registry, _workspace = environment
    policy = AutonomyPolicy(settings, db, registry)
    policy.update("assisted", {}, [])

    decision = policy.decide("math.calculate", {"expression": "2 + 2"})
    assert decision["action"] == "approval_required"
    assert decision["rule"] == "assisted_level"

    policy.update("assisted", {"math.calculate": "allow"}, [])
    assert policy.decide("math.calculate", {"expression": "2 + 2"})["action"] == "allow"
    policy.update("assisted", {"math.calculate": "deny"}, [])
    assert policy.decide("math.calculate", {"expression": "2 + 2"})["action"] == "deny"


def test_workspace_overwrite_authorization_is_exactly_path_scoped(environment):
    settings, db, registry, _workspace = environment
    policy = AutonomyPolicy(settings, db, registry)
    policy.update("routine", {}, ["drafts", "notes/working"])

    inside = policy.decide("workspace.write_file", {"path": "drafts/project.txt", "content": "new"})
    assert inside["action"] == "allow"
    assert inside["approved"] is True
    assert inside["rule"] == "authorized_workspace_overwrite_scope"

    sibling = policy.decide("workspace.write_file", {"path": "drafts-archive/project.txt", "content": "new"})
    assert sibling["action"] == "allow"
    assert sibling["approved"] is False

    traversal = policy.decide("workspace.write_file", {"path": "drafts/../important.txt", "content": "new"})
    assert traversal["approved"] is False


def test_assisted_mode_does_not_bypass_approval_via_overwrite_scope(environment):
    settings, db, registry, _workspace = environment
    policy = AutonomyPolicy(settings, db, registry)
    policy.update("assisted", {}, ["drafts"])

    decision = policy.decide("workspace.write_file", {"path": "drafts/notes.txt", "content": "new"})
    assert decision["action"] == "approval_required"
    assert decision["approved"] is False


def test_policy_update_rejects_broad_or_unsafe_overwrite_scopes(environment):
    settings, db, registry, _workspace = environment
    policy = AutonomyPolicy(settings, db, registry)

    with pytest.raises(ValueError, match="traversal"):
        policy.update("routine", {}, ["drafts/../outside"])
    with pytest.raises(ValueError, match="entire workspace"):
        policy.update("routine", {}, ["."])
    with pytest.raises(ValueError, match="Unknown tool"):
        policy.update("routine", {"arbitrary.tool": "allow"}, [])
    registry.register(ToolDefinition(
        name="system.control",
        description="test-only unclassified action",
        parameters={"type": "object", "properties": {}, "additionalProperties": False},
        input_model=_ActionInput,
        handler=_action_handler,
        permission="test-only system control",
    ))
    with pytest.raises(ValueError, match="not classified as routine"):
        policy.update("routine", {"system.control": "allow"}, [])


def test_policy_persists_across_service_instances(environment):
    settings, db, registry, _workspace = environment
    first = AutonomyPolicy(settings, db, registry)
    first.update("advanced", {"math.calculate": "approve"}, ["scratch"])

    second = AutonomyPolicy(settings, db, registry)
    restored = second.get()
    assert restored["level"] == "advanced"
    assert restored["tool_overrides"] == {"math.calculate": "approve"}
    assert restored["authorized_overwrite_prefixes"] == ["scratch"]
