import pytest
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.collapse_add_neg import CollapseAddNeg
from decompiler.structures.pseudo import BinaryOperation, Expression, Operation, OperationType, UnaryOperation, Variable

var_x = Variable("x")
var_y = Variable("y")


@pytest.mark.parametrize(
    ["operation", "result"],
    [
        (
            BinaryOperation(OperationType.plus, [var_x, UnaryOperation(OperationType.negate, [var_y])]),
            [BinaryOperation(OperationType.minus, [var_x, var_y])],
        ),
        (
            BinaryOperation(OperationType.minus, [var_x, UnaryOperation(OperationType.negate, [var_y])]),
            [BinaryOperation(OperationType.plus, [var_x, var_y])],
        ),
    ],
)
def test_collapse_add_neg(operation: Operation, result: list[Expression]):
    assert CollapseAddNeg().apply(operation) == [(operation, e) for e in result]
