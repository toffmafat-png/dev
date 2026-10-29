from __future__ import annotations

import pytest

from nova.tools.calculator import calculate


@pytest.mark.parametrize(("expression", "expected"), [
    ("(12 + 3) * 4", 60),
    ("18%", None),
    ("2 ** 8", 256),
    ("-7 // 2", -4),
])
def test_calculator(expression, expected):
    if expected is None:
        with pytest.raises((ValueError, SyntaxError)):
            calculate(expression)
    else:
        assert calculate(expression) == expected


@pytest.mark.parametrize("expression", [
    "__import__('os').system('echo unsafe')",
    "open('/etc/passwd').read()",
    "2 ** 100",
    "1 / 0",
    "x + 1",
])
def test_calculator_rejects_code_and_unsafe_ranges(expression):
    with pytest.raises((ValueError, SyntaxError, TypeError)):
        calculate(expression)


@pytest.mark.asyncio
async def test_workspace_scope_and_overwrite_approval(environment):
    settings, _db, registry, workspace = environment
    outside = workspace.parent / "outside.txt"
    outside.write_text("keep", encoding="utf-8")

    blocked = await registry.execute("workspace.read_file", {"path": "../outside.txt"})
    assert blocked.status == "denied"
    assert outside.read_text(encoding="utf-8") == "keep"

    original = workspace / "existing.txt"
    original.write_text("original", encoding="utf-8")
    ask = await registry.execute("workspace.write_file", {"path": "existing.txt", "content": "changed"})
    assert ask.status == "approval_required"
    assert original.read_text(encoding="utf-8") == "original"

    approved = await registry.execute("workspace.write_file", {"path": "existing.txt", "content": "changed"}, approved=True)
    assert approved.status == "success"
    assert original.read_text(encoding="utf-8") == "changed"
    backup = workspace / approved.data["backup"]
    assert backup.read_text(encoding="utf-8") == "original"


@pytest.mark.asyncio
async def test_workspace_rejects_symlink(environment):
    _settings, _db, registry, workspace = environment
    outside = workspace.parent / "private.txt"
    outside.write_text("secret", encoding="utf-8")
    link = workspace / "link.txt"
    link.symlink_to(outside)
    result = await registry.execute("workspace.read_file", {"path": "link.txt"})
    assert result.status == "denied"
