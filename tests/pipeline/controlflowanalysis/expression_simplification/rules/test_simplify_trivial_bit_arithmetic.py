import pytest
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.simplify_trivial_bit_arithmetic import (
    SimplifyTrivialBitArithmetic,
)
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Integer, Operation, OperationType, Variable

var = Variable("x", Integer.int32_t())
con_0 = Constant(0, Integer.int32_t())


@pytest.mark.parametrize(
    ["operation", "result"],
    [
        (BinaryOperation(OperationType.bitwise_or, [var, con_0]), [var]),
        (BinaryOperation(OperationType.bitwise_or, [var, var]), [var]),
        (BinaryOperation(OperationType.bitwise_and, [var, con_0]), [con_0]),
        (BinaryOperation(OperationType.bitwise_and, [var, var]), [var]),
        (BinaryOperation(OperationType.bitwise_xor, [var, con_0]), [var]),
        (BinaryOperation(OperationType.bitwise_xor, [var, var]), [con_0]),
    ],
)
def test_simplify_trivial_bit_arithmetic(operation: Operation, result: list[Expression]):
    assert SimplifyTrivialBitArithmetic().apply(operation) == [(operation, e) for e in result]
