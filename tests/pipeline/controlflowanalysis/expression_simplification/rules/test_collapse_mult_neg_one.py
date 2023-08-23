import pytest
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.collapse_mult_neg_one import CollapseMultNegOne
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Operation, OperationType, UnaryOperation, Variable


@pytest.mark.parametrize(
    ["operation", "result"],
    [
        (
            BinaryOperation(OperationType.multiply, [var := Variable("x"), Constant(-1)]),
            [UnaryOperation(OperationType.negate, [var])],
        )
    ],
)
def test_mult_neg_one(operation: Operation, result: list[Expression]):
    assert CollapseMultNegOne().apply(operation) == [(operation, e) for e in result]
