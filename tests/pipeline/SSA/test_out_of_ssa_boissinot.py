"""Pytest for the Boissinot et al. 2008 Out of SSA."""

from collections import defaultdict

import pytest

from decompiler.pipeline.ssa.boissinot_2008 import Boissinot2008
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


def test_parameter_class_name_not_taken_by_other_class():
    """The class containing a parameter must get the parameter name even if another class with the same variable name comes first.
    Names were handed out first-come, so the loop class took a and the parameter class became a__0, which is never defined.
    +------------------+     +------------------+
    |        0.        |     |        0.        |
    | a#1 = 5          |     | a__0 = 5         |
    +------------------+     +------------------+
      |                        |
      v                        v
    +------------------+     +------------------+
    |        1.        |     |        1.        |
    | a#2 = ϕ(a#1,a#3) |     | a__0 = a__0 + a  |
    | a#3 = a#2 + a#0  |     | if(a__0 < 10)    |
    | if(a#3 < 10)     |     +------------------+
    +------------------+       |
      |                        v
      v                      +------------------+
    +------------------+     |        2.        |
    |        2.        |     | return a__0 + a  |
    | return a#3 + a#0 |     +------------------+
    +------------------+
    """

    def var(label=None, name="a"):
        return Variable(name, Integer.int32_t(), ssa_label=label)

    cfg = ControlFlowGraph()
    n0 = BasicBlock(0, [Assignment(var(1), Constant(5))])
    n1 = BasicBlock(
        1,
        [
            Phi(var(2), [var(1), var(3)]),
            Assignment(var(3), BinaryOperation(OperationType.plus, [var(2), var(0)])),
            Branch(Condition(OperationType.less, [var(3), Constant(10)])),
        ],
    )
    n2 = BasicBlock(2, [Return([BinaryOperation(OperationType.plus, [var(3), var(0)])])])
    n1.instructions[0]._origin_block = {n0: var(1), n1: var(3)}
    cfg.add_nodes_from([n0, n1, n2])
    cfg.add_edges_from([UnconditionalEdge(n0, n1), TrueCase(n1, n1), FalseCase(n1, n2)])

    OutOfSsaTranslation().run(decompiler_task(cfg, "boissinot2008", [var(0)]))

    loop = var(name="a__0")
    assert n0.instructions == [Assignment(loop, Constant(5))]
    assert n1.instructions == [
        Assignment(loop, BinaryOperation(OperationType.plus, [loop, var()])),
        Branch(Condition(OperationType.less, [loop, Constant(10)])),
    ]
    assert n2.instructions == [Return([BinaryOperation(OperationType.plus, [loop, var()])])]


def test_errors_are_not_swallowed(monkeypatch):
    """Errors in a translation step must propagate, perform() used to print them and leave the CFG half translated."""

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

    def fail(self):
        raise RuntimeError("step failed")

    monkeypatch.setattr(Boissinot2008, "step3", fail)

    with pytest.raises(RuntimeError, match="step failed"):
        OutOfSsaTranslation().run(decompiler_task(cfg, "boissinot2008", [var(0)]))


def test_parallel_copy_destinations_interfere():
    """The phi arguments are live-out of their predecessor as in the paper, so the copies of one parallel copy interfere.
    +------------------+
    |        0.        |
    | x#0 = 0x1        |
    | y#0 = 0x2        |
    +------------------+
      |
      v
    +------------------+  true
    |        1.        | -----+
    | x#1 = ϕ(x#0,y#1) |      |
    | y#1 = ϕ(y#0,x#1) |      |
    | if(x#1 < 0xa)    | <----+
    +------------------+
      | false
      v
    +------------------+
    |        2.        |
    | return x#1 - y#1 |
    +------------------+
    """

    def var(name, label=None):
        return Variable(name, Integer.int32_t(), ssa_label=label)

    cfg = ControlFlowGraph()
    n0 = BasicBlock(0, [Assignment(var("x", 0), Constant(1)), Assignment(var("y", 0), Constant(2))])
    n1 = BasicBlock(
        1,
        [
            Phi(var("x", 1), [var("x", 0), var("y", 1)]),
            Phi(var("y", 1), [var("y", 0), var("x", 1)]),
            Branch(Condition(OperationType.less, [var("x", 1), Constant(10)])),
        ],
    )
    n2 = BasicBlock(2, [Return([BinaryOperation(OperationType.minus, [var("x", 1), var("y", 1)])])])
    n1.instructions[0]._origin_block = {n0: var("x", 0), n1: var("y", 1)}
    n1.instructions[1]._origin_block = {n0: var("y", 0), n1: var("x", 1)}
    cfg.add_nodes_from([n0, n1, n2])
    cfg.add_edges_from([UnconditionalEdge(n0, n1), TrueCase(n1, n1), FalseCase(n1, n2)])

    task = decompiler_task(cfg, "boissinot2008", [])
    boissinot = Boissinot2008(task, defaultdict(list, {n1: n1.instructions[:2]}))
    boissinot._to_cssa()
    boissinot._build_interference_graph()

    spaces = boissinot._parallel_spaces._parallel_spaces_map
    latch_address = next(address for address in spaces if address not in (0, 1, 2))
    graph = boissinot._interference_graph
    for address in (0, latch_address):
        destinations = [assignment.destination for assignment in spaces[address].end_of_block_assigns]
        assert len(destinations) == 2 and graph.are_interfering(*destinations)
    latch_destinations = [assignment.destination for assignment in spaces[latch_address].end_of_block_assigns]
    assert not graph.are_interfering(latch_destinations[0], var("x", 0))
    assert not graph.are_interfering(latch_destinations[1], var("y", 0))
