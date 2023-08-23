import pytest
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.simplify_trivial_shift import SimplifyTrivialShift
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Integer, Operation, OperationType, Variable

var = Variable("x")
con_0 = Constant(0, Integer.int32_t())


@pytest.mark.parametrize(
    ["operation", "result"],
    [
        (BinaryOperation(OperationType.left_shift, [var, con_0]), [var]),
        (BinaryOperation(OperationType.right_shift, [var, con_0]), [var]),
        (BinaryOperation(OperationType.right_shift_us, [var, con_0]), [var]),
        (BinaryOperation(OperationType.left_rotate, [var, con_0]), [var]),
        (BinaryOperation(OperationType.right_rotate, [var, con_0]), [var]),
    ],
)
def test_simplify_trivial_shift(operation: Operation, result: list[Expression]):
    assert SimplifyTrivialShift().apply(operation) == [(operation, e) for e in result]
