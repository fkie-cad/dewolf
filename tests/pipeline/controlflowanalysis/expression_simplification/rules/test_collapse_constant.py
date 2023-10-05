import pytest
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.collapse_constants import CollapseConstants
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Float, Integer, Operation, OperationType, Variable


def _c_i32(value: int) -> Constant:
    return Constant(value, Integer.int32_t())


def _c_float(value: float) -> Constant:
    return Constant(value, Float.float())


@pytest.mark.parametrize(
    ["operation", "result"],
    [
        (BinaryOperation(OperationType.plus, [_c_i32(3), _c_i32(4)]), [_c_i32(7)]),
        (BinaryOperation(OperationType.plus, [_c_i32(3), Variable("x")]), []),
        (BinaryOperation(OperationType.plus_float, [_c_float(3.0), _c_float(4.0)]), []),
    ],
)
def test_collapse_constant(operation: Operation, result: list[Expression]):
    assert CollapseConstants().apply(operation) == [(operation, e) for e in result]
