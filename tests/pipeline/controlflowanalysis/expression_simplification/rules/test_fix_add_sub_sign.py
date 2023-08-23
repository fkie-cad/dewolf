import pytest
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.fix_add_sub_sign import FixAddSubSign
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Integer, Operation, OperationType, Variable

var_x_i = Variable("x", Integer.int32_t())
var_x_u = Variable("x", Integer.uint32_t())


@pytest.mark.parametrize(
    ["operation", "result"],
    [
        (
            BinaryOperation(OperationType.minus, [var_x_i, (Constant(-3, Integer.int32_t()))]),
            [BinaryOperation(OperationType.plus, [var_x_i, Constant(3, Integer.int32_t())])],
        ),
        (
            BinaryOperation(OperationType.plus, [var_x_i, (Constant(-3, Integer.int32_t()))]),
            [BinaryOperation(OperationType.minus, [var_x_i, Constant(3, Integer.int32_t())])],
        ),
        (BinaryOperation(OperationType.plus, [var_x_i, (Constant(3, Integer.int32_t()))]), []),
        (BinaryOperation(OperationType.minus, [var_x_i, (Constant(3, Integer.int32_t()))]), []),

        (
            BinaryOperation(OperationType.minus, [var_x_u, (Constant(4294967293, Integer.uint32_t()))]),
            [BinaryOperation(OperationType.plus, [var_x_u, Constant(3, Integer.uint32_t())])],
        ),
        (
            BinaryOperation(OperationType.plus, [var_x_u, (Constant(4294967293, Integer.uint32_t()))]),
            [BinaryOperation(OperationType.minus, [var_x_u, Constant(3, Integer.uint32_t())])],
        ),
        (BinaryOperation(OperationType.plus, [var_x_u, (Constant(3, Integer.uint32_t()))]), []),
        (BinaryOperation(OperationType.minus, [var_x_u, (Constant(3, Integer.uint32_t()))]), []),
    ],
)
def test_fix_add_sub_sign(operation: Operation, result: list[Expression]):
    assert FixAddSubSign().apply(operation) == [(operation, e) for e in result]
