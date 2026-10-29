"""A tiny arithmetic evaluator; deliberately avoids eval/exec."""
from __future__ import annotations

import ast
import math
import operator

from pydantic import BaseModel, ConfigDict, Field

from nova.tools.registry import ToolDefinition, ToolOutcome


class CalculatorInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expression: str = Field(min_length=1, max_length=240, description="Arithmetic expression, for example (12 + 3) * 4")


_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def calculate(expression: str) -> int | float:
    if len(expression) > 240:
        raise ValueError("Expression is too long")
    tree = ast.parse(expression, mode="eval")
    nodes = list(ast.walk(tree))
    if len(nodes) > 64:
        raise ValueError("Expression is too complex")

    def visit(node: ast.AST) -> int | float:
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            if abs(node.value) > 1_000_000_000:
                raise ValueError("Number literal is outside the supported range")
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
            left = visit(node.left)
            right = visit(node.right)
            if isinstance(node.op, ast.Pow) and abs(right) > 12:
                raise ValueError("Exponent is outside the supported range")
            result = _BINOPS[type(node.op)](left, right)
            if isinstance(result, complex) or not math.isfinite(float(result)) or abs(result) > 1e100:
                raise ValueError("Result is outside the supported range")
            return result
        if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY:
            return _UNARY[type(node.op)](visit(node.operand))
        raise ValueError("Only basic arithmetic operators and numeric literals are allowed")

    try:
        return visit(tree)
    except ZeroDivisionError as exc:
        raise ValueError("Division by zero") from exc
    except OverflowError as exc:
        raise ValueError("Result is outside the supported range") from exc


async def _run(args: BaseModel, _approved: bool) -> ToolOutcome:
    expression = args.expression  # type: ignore[attr-defined]
    try:
        value = calculate(expression)
    except (ValueError, SyntaxError, TypeError) as exc:
        return ToolOutcome("error", str(exc))
    return ToolOutcome("success", f"Calculated {expression}.", {"expression": expression, "value": value})


def build_calculator_tool() -> ToolDefinition:
    return ToolDefinition(
        name="math.calculate",
        description="Evaluate a basic arithmetic expression using a safe, bounded calculator. No variables, functions, or code execution.",
        parameters={
            "type": "object",
            "properties": {"expression": {"type": "string", "minLength": 1, "maxLength": 240}},
            "required": ["expression"],
            "additionalProperties": False,
        },
        input_model=CalculatorInput,
        handler=_run,
        permission="local computation; no external side effects",
        category="utility",
        autonomy_class="routine",
    )
