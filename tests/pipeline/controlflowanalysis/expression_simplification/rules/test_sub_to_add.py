import pytest
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.sub_to_add import SubToAdd
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Integer, Operation, OperationType, UnaryOperation, Variable

var_x = Variable("x", Integer.int32_t())
var_y = Variable("y", Integer.int32_t())
con_neg1 = Constant(-1, Integer.int32_t())


@pytest.mark.parametrize(
    ["operation", "result"],
    [
        (
            BinaryOperation(OperationType.minus, [var_x, var_y]),
            [BinaryOperation(OperationType.plus, [var_x, UnaryOperation(OperationType.negate, [var_y])])],
        ),
    ],
)
def test_sub_to_add(operation: Operation, result: list[Expression]):
    assert SubToAdd().apply(operation) == [(operation, e) for e in result]
