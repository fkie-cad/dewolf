import pytest
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.simplify_redundant_reference import SimplifyRedundantReference
from decompiler.structures.pseudo import Expression, Operation, OperationType, UnaryOperation, Variable


@pytest.mark.parametrize(
    ["operation", "result"],
    [
        (UnaryOperation(OperationType.dereference, [UnaryOperation(OperationType.address, [var := Variable("x")])]), [var]),
        (UnaryOperation(OperationType.address, [Variable("x")]), []),
        (UnaryOperation(OperationType.dereference, [Variable("x")]), []),
    ],
)
def test_simplify_redundant_reference(operation: Operation, result: list[Expression]):
    assert SimplifyRedundantReference().apply(operation) == [(operation, e) for e in result]
