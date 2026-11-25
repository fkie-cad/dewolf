"""Pytest for the Boissinot et al. 2008 Out of SSA."""

from decompiler.pipeline.ssa.outofssatranslation import OutOfSsaTranslation
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo import Assignment, BinaryOperation, Branch, Condition, Constant, Integer, OperationType, Phi, Return, Variable

from tests.pipeline.SSA.utils_out_of_ssa_tests import decompiler_task


def test_parameter_class_keeps_parameter_name():
    """The variable class containing a function parameter must be renamed to the parameter name.
    Each class was returned once per member, so it was renamed several times and ended up as a__4 instead of a.
    +------------------+     +------------------+
    |        0.        |     |        0.        |
    +------------------+     +------------------+
      |                        |
      v                        v
    +------------------+     +------------------+
    |        1.        |     |        1.        |
    | a#1 = ϕ(a#0,a#2) |     | a = a + 1        |
    | a#2 = a#1 + 1    |     | if(a < 10)       |
    | if(a#2 < 10)     |     +------------------+
    +------------------+       |
      |                        v
      v                      +------------------+
    +------------------+     |        2.        |
    |        2.        |     | return a         |
    | return a#2       |     +------------------+
    +------------------+
    """

    def var(label=None):
        return Variable("a", Integer.int32_t(), ssa_label=label)

    cfg = ControlFlowGraph()
    n0 = BasicBlock(0, [])
    n1 = BasicBlock(
        1,
        [
            Phi(var(1), [var(0), var(2)]),
            Assignment(var(2), BinaryOperation(OperationType.plus, [var(1), Constant(1)])),
            Branch(Condition(OperationType.less, [var(2), Constant(10)])),
        ],
    )
    n2 = BasicBlock(2, [Return([var(2)])])
    n1.instructions[0]._origin_block = {n0: var(0), n1: var(2)}
    cfg.add_nodes_from([n0, n1, n2])
    cfg.add_edges_from([UnconditionalEdge(n0, n1), TrueCase(n1, n1), FalseCase(n1, n2)])

    OutOfSsaTranslation().run(decompiler_task(cfg, "boissinot2008", [var(0)]))

    assert n0.instructions == []
    assert n1.instructions == [
        Assignment(var(), BinaryOperation(OperationType.plus, [var(), Constant(1)])),
        Branch(Condition(OperationType.less, [var(), Constant(10)])),
    ]
    assert n2.instructions == [Return([var()])]
