import pytest
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.simplify_trivial_arithmetic import SimplifyTrivialArithmetic
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Integer, Operation, OperationType, UnaryOperation, Variable

var = Variable("x")
con_0 = Constant(0, Integer.int32_t())
con_1 = Constant(1, Integer.int32_t())
con_neg1 = Constant(-1, Integer.int32_t())


@pytest.mark.parametrize(
    ["operation", "result"],
    [
        (BinaryOperation(OperationType.plus, [var, con_0]), [var]),
        (BinaryOperation(OperationType.minus, [var, con_0]), [var]),
        (BinaryOperation(OperationType.multiply, [var, con_1]), [var]),
        (BinaryOperation(OperationType.multiply_us, [var, con_1]), [var]),
        (BinaryOperation(OperationType.multiply, [var, con_neg1]), [UnaryOperation(OperationType.negate, [var])]),
        (BinaryOperation(OperationType.multiply_us, [var, con_neg1]), [UnaryOperation(OperationType.negate, [var])]),
        (BinaryOperation(OperationType.divide, [var, con_1]), [var]),
        (BinaryOperation(OperationType.divide_us, [var, con_1]), [var]),
        (BinaryOperation(OperationType.divide, [var, con_neg1]), [UnaryOperation(OperationType.negate, [var])]),
        (BinaryOperation(OperationType.divide_us, [var, con_neg1]), []),
    ],
)
def test_simplify_trivial_arithmetic(operation: Operation, result: list[Expression]):
    assert SimplifyTrivialArithmetic().apply(operation) == [(operation, e) for e in result]
