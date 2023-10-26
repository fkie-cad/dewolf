import pytest
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.collapse_constants import CollapseConstants
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.collapse_nested_constants import CollapseNestedConstants
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.simplify_trivial_arithmetic import SimplifyTrivialArithmetic
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.sub_to_add import SubToAdd
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.term_order import TermOrder
from decompiler.pipeline.controlflowanalysis.expression_simplification.stages import _ExpressionSimplificationBase
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Constant,
    Expression,
    Instruction,
    Integer,
    Operation,
    OperationType,
    Variable,
)


class _RedundantChanges(SimplificationRule):
    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        return [(operation, operation)]


class _NoChanges(SimplificationRule):
    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        return []


def _add(left: Expression, right: Expression) -> BinaryOperation:
    return BinaryOperation(OperationType.plus, [left, right])


def _sub(left: Expression, right: Expression) -> BinaryOperation:
    return BinaryOperation(OperationType.minus, [left, right])


def _c_i32(value: int) -> Constant:
    return Constant(value, Integer.int32_t())


def _v_i32(name: str) -> Variable:
    return Variable(name, Integer.int32_t())


@pytest.mark.parametrize(
    ["rule_set", "instruction", "expected_result"],
    [
        ([TermOrder()], Assignment(_v_i32("a"), _add(_c_i32(1), _v_i32("b"))), Assignment(_v_i32("a"), _add(_v_i32("b"), _c_i32(1)))),
        ([CollapseConstants()], Assignment(_v_i32("a"), _sub(_c_i32(10), _add(_c_i32(3), _c_i32(2)))), Assignment(_v_i32("a"), _c_i32(5))),
        (
            [SubToAdd(), SimplifyTrivialArithmetic(), CollapseConstants(), CollapseNestedConstants()],
            Assignment(_v_i32("a"), _sub(_add(_v_i32("a"), _c_i32(5)), _c_i32(5))),
            Assignment(_v_i32("a"), _v_i32("a")),
        ),
    ],
)
def test_simplify_instructions_with_rule_set(rule_set: list[SimplificationRule], instruction: Instruction, expected_result: Instruction):
    _ExpressionSimplificationBase._simplify_instructions_with_rule_set([instruction], rule_set, 100, True)
    assert instruction == expected_result


@pytest.mark.parametrize(
    ["rule_set", "instruction", "max_iterations", "expect_exceed_max_iterations"],
    [
        ([_RedundantChanges()], Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Constant(1), Variable("b")])), 10, True),
        ([_NoChanges()], Assignment(_v_i32("a"), _v_i32("b")), 0, False),
    ],
)
def test_simplify_instructions_with_rule_set_max_iterations(
    rule_set: list[SimplificationRule], instruction: Instruction, max_iterations: int, expect_exceed_max_iterations: bool
):
    iterations = _ExpressionSimplificationBase._simplify_instructions_with_rule_set([instruction], rule_set, max_iterations, True)
    assert (iterations > max_iterations) == expect_exceed_max_iterations
