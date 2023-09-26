import pytest
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.term_order import TermOrder
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Integer, Operation, Variable
from decompiler.structures.pseudo.operations import COMMUTATIVE_OPERATIONS

var = Variable("x")
con = Constant(42, Integer.int32_t())


@pytest.mark.parametrize(
    ["operation", "result"],
    [(BinaryOperation(operation, [con, var]), [BinaryOperation(operation, [var, con])]) for operation in COMMUTATIVE_OPERATIONS],
)
def test_term_order(operation: Operation, result: list[Expression]):
    assert TermOrder().apply(operation) == [(operation, e) for e in result]
