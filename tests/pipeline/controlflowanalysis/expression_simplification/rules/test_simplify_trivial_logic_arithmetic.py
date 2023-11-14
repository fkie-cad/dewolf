import pytest
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.simplify_trivial_logic_arithmetic import (
    SimplifyTrivialLogicArithmetic,
)
from decompiler.structures.pseudo import BinaryOperation, Constant, CustomType, Expression, Operation, OperationType, Variable

var = Variable("x", CustomType.bool())
con_false = Constant(0, CustomType.bool())
con_true = Constant(1, CustomType.bool())


@pytest.mark.parametrize(
    ["operation", "result"],
    [
        (BinaryOperation(OperationType.logical_or, [var, con_false]), [var]),
        (BinaryOperation(OperationType.logical_or, [var, con_true]), [con_true]),
        (BinaryOperation(OperationType.logical_and, [var, con_false]), [con_false]),
        (BinaryOperation(OperationType.logical_and, [var, con_true]), [var]),
    ],
)
def test_simplify_trivial_logic_arithmetic(operation: Operation, result: list[Expression]):
    assert SimplifyTrivialLogicArithmetic().apply(operation) == [(operation, e) for e in result]
