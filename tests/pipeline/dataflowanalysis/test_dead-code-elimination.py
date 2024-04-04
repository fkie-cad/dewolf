""" Tests for the DeadCodeElimination pipeline stage"""

from abc import ABC, abstractmethod

import pytest
from decompiler.pipeline.dataflowanalysis.deadcodeelimination import DeadCodeElimination
from decompiler.pipeline.expressions import DeadComponentPruner
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, FunctionSymbol, ImportedFunctionSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Phi, Relation, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import CustomType, Integer, Pointer


class MockDecompilerTask:
    """Mock class for decompilerTasks only containing a cfg."""

    def __init__(self, cfg):
        self.graph = cfg


"""Fixtures and helper functions."""


@pytest.fixture
def task() -> MockDecompilerTask:
    """A mock task with an empty cfg."""
    return MockDecompilerTask(ControlFlowGraph())


def variable(name="a", version=0) -> Variable:
    """A test variable as an unsigned 32bit integer."""
    return Variable(name, ssa_label=version, vartype=Integer.int32_t())


class BaseDceTests(ABC):
    @abstractmethod
    def run_dce(self, task: MockDecompilerTask):
        """Run an implementation of dead code elimination."""

    def test_empty(self, task: MockDecompilerTask):
        """DCE should not crash facing an empty cfg."""
        DeadCodeElimination().run(task)

    def test_assignment_unnessecary(self, task: MockDecompilerTask):
        """A cfg with a single Assignment should always be returned empty.
        +-------------+
        | a#0 = 1     |
        +-------------+
        """
        task.graph.add_node(BasicBlock(0, instructions=[Assignment(variable(), Constant(1))]))
        DeadCodeElimination().run(task)
        assert len(list(task.graph.instructions)) == 0

    def test_assignment_nessecary_for_call(self, task: MockDecompilerTask):
        """An instruction utilized in a call shall never be removed. Also tests Assignment.
        +-----------------+
        | a#0 = 1         |
        | a#1 = func(a#0) |
        +-----------------+
        """
        instructions = [
            Assignment(variable(), Constant(1)),
            Assignment(variable(version=1), Call(FunctionSymbol("func", 0x42), [variable()])),
        ]
        task.graph.add_node(node := BasicBlock(0, instructions=[instr.copy() for instr in instructions]))
        DeadCodeElimination().run(task)
        assert node.instructions[0] == instructions[0] and node.instructions[1] == Assignment(
            ListOperation([]), Call(FunctionSymbol("func", 0x42), [variable()])
        )

    def test_assignment_nessecary_for_branch(self, task: MockDecompilerTask):
        """A variable utilized in a branch should remain in any case.
        +-------------+
        | a#0 = 1     |
        | if a#0 == 1 |
        +-------------+
        """
        instructions = [Assignment(variable(), Constant(1)), Branch(Condition(OperationType.equal, [variable(), Constant(1)]))]
        task.graph.add_node(node := BasicBlock(0, instructions=[instr.copy() for instr in instructions]))
        DeadCodeElimination().run(task)
        assert node.instructions[0] == instructions[0] and node.instructions[1] == instructions[1]

    def test_assignment_nessecary_for_return(self, task: MockDecompilerTask):
        """A variable utilized in a Return statement should not be removed.
        +--------------+
        | a#0 = 1      |
        | return a#0   |
        +--------------+
        """
        instructions = [Assignment(variable(), Constant(1)), Return([variable()])]
        task.graph.add_node(node := BasicBlock(0, [instr.copy() for instr in instructions]))
        DeadCodeElimination().run(task)
        assert node.instructions[0] == instructions[0] and node.instructions[1] == instructions[1]

    def test_phi_unnessecary(self, task: MockDecompilerTask):
        """Unnessecary phi function should be removed when its value is dead.
               +-----------+
               | if 1 == 2 |
               +-----+-----+
                     |
             --------+--------
             |               |
        +----+----+     +----+----+
        | a#0 = 1 |     | a#1 = 2 |
        +----+----+     +----+----+
             |               |
             +-------+-------+
                     |
           +---------+---------+
           | a#3 = φ(a#0, a#1) |
           +-------------------+
        """
        instructions = [
            Branch(Condition(OperationType.equal, [Constant(1), Constant(2)])),
            Assignment(variable(version=0), Constant(1)),
            Assignment(variable(version=1), Constant(2)),
            Phi(variable(version=3), [variable(version=0), variable(version=1)]),
        ]
        vertices = [
            node_0 := BasicBlock(0, instructions=[instructions[0].copy()]),
            node_1 := BasicBlock(1, instructions=[instructions[1].copy()]),
            node_2 := BasicBlock(2, instructions=[instructions[2].copy()]),
            node_3 := BasicBlock(3, instructions=[instructions[3].copy()]),
        ]
        edges = [
            UnconditionalEdge(vertices[0], vertices[1]),
            UnconditionalEdge(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[3]),
        ]
        task.graph.add_nodes_from(vertices)
        task.graph.add_edges_from(edges)
        DeadCodeElimination().run(task)
        assert (
            node_0.instructions[0] == instructions[0]
            and len(node_1.instructions) == 0
            and len(node_2.instructions) == 0
            and len(node_3.instructions) == 0
        )

    def test_phi_nessecary(self, task: MockDecompilerTask):
        """Unnessecary phi function which is relevant should not be removed
               +-----------+
               | if 1 == 2 |
               +-----+-----+
                     |
             --------+--------
             |               |
        +----+----+     +----+----+
        | a#0 = 1 |     | a#1 = 2 |
        +----+----+     +----+----+
             |               |
             +-------+-------+
                     |
           +---------+---------+
           | a#3 = φ(a#0, a#1) |
           | return a#3        |
           +-------------------+
        """
        instructions = [
            Branch(Condition(OperationType.equal, [Constant(1), Constant(2)])),
            Assignment(variable(version=0), Constant(1)),
            Assignment(variable(version=1), Constant(2)),
            Phi(variable(version=3), [variable(version=0), variable(version=1)]),
            Return([variable(version=3)]),
        ]
        vertices = [
            node_0 := BasicBlock(0, instructions=[instructions[0].copy()]),
            node_1 := BasicBlock(1, instructions=[instructions[1].copy()]),
            node_2 := BasicBlock(2, instructions=[instructions[2].copy()]),
            node_3 := BasicBlock(3, instructions=[instr.copy() for instr in instructions[3:]]),
        ]
        edges = [
            UnconditionalEdge(vertices[0], vertices[1]),
            UnconditionalEdge(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[3]),
        ]
        task.graph.add_nodes_from(vertices)
        task.graph.add_edges_from(edges)
        DeadCodeElimination().run(task)
        assert (
            node_0.instructions == [instructions[0]]
            and node_1.instructions == [instructions[1]]
            and node_2.instructions == [instructions[2]]
            and node_3.instructions == instructions[3:]
        )

    def test_loop(self, task: MockDecompilerTask):
        """A more complex test scenario with a loop and a phi function.
            +-----------+
            | a#0 = 1   |
            | b#2 = 2   |
            +-----+-----+
                  |
        +---------+---------+
        | a#1 = φ(a#0, a#2) |
        | b#3 = φ(b#2, b#4) |<-+
        | a#2 = a#1 + 1     |  |
        | b#4 = b#3 + 3     |  |
        +---------+---------+  |
                  |            |
          +-------+-------+    |
          |  if a#2 == 5  |----+
          +-------+-------+
                  |
           +------+------+
           | return a#2  |
           +-------------+
        """
        instructions = [
            Assignment(variable(), Constant(1)),
            Assignment(variable(name="b", version=2), Constant(2)),
            Phi(variable(version=1), [variable(), variable(version=2)]),
            Phi(variable(name="b", version=3), [variable(name="b", version=2), variable(name="b", version=4)]),
            Assignment(variable(version=2), BinaryOperation(OperationType.plus, [variable(version=1), Constant(1)])),
            Assignment(variable(name="b", version=4), BinaryOperation(OperationType.plus, [variable(name="b", version=3), Constant(3)])),
            Branch(Condition(OperationType.equal, [variable(version=2), Constant(5)])),
            Return([variable(version=2)]),
        ]
        vertices = [
            node_0 := BasicBlock(0, instructions=[instr.copy() for instr in instructions[:2]]),
            node_1 := BasicBlock(1, instructions=[instr.copy() for instr in instructions[2:6]]),
            node_2 := BasicBlock(2, instructions=[instructions[6].copy()]),
            node_3 := BasicBlock(3, instructions=[instructions[7].copy()]),
        ]
        edges = [
            UnconditionalEdge(vertices[0], vertices[1]),
            UnconditionalEdge(vertices[1], vertices[2]),
            UnconditionalEdge(vertices[2], vertices[1]),
            UnconditionalEdge(vertices[2], vertices[3]),
        ]
        task.graph.add_nodes_from(vertices)
        task.graph.add_edges_from(edges)
        DeadCodeElimination().run(task)
        assert (
            node_0.instructions == [instructions[0]]
            and node_1.instructions == [instructions[2], instructions[4]]
            and node_2.instructions == [instructions[6]]
            and node_3.instructions == [instructions[7]]
        )

    def test_circular_dependency(self, task: MockDecompilerTask):
        """Test phi functions in a circular dependency.
                 +-----------+
                 | a#0 = 1   |
                 +-----+-----+
                       |
             +---------+---------+
        +--->| a#1 = φ(a#0, a#2) |-----------+
        |    +---------+---------+           |
        |              |                     |
        |    +---------+---------+   +-------+-------+
        +----| a#2 = φ(a#1, a#3) |<--| a#3 = a#1 + 1 |
             +---------+---------+   +---------------+
        """
        instructions = [
            Assignment(variable(), Constant(1)),
            Phi(variable(version=1), [variable(), variable(version=2)]),
            Assignment(variable(version=3), BinaryOperation(OperationType.plus, [variable(version=1), Constant(1)])),
            Phi(variable(version=2), [variable(version=1), variable(version=3)]),
        ]
        vertices = [
            node_0 := BasicBlock(0, instructions=[instructions[0].copy()]),
            node_1 := BasicBlock(1, instructions=[instructions[1].copy()]),
            node_2 := BasicBlock(2, instructions=[instructions[2].copy()]),
            node_3 := BasicBlock(3, instructions=[instructions[3].copy()]),
        ]
        edges = [
            UnconditionalEdge(vertices[0], vertices[1]),
            UnconditionalEdge(vertices[1], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[3]),
        ]
        task.graph.add_nodes_from(vertices)
        task.graph.add_edges_from(edges)
        DeadCodeElimination().run(task)
        assert all(
            [len(node_0.instructions) == 0, len(node_1.instructions) == 0, len(node_2.instructions) == 0, len(node_3.instructions) == 0]
        )

    def test_dereference_used(self, task: MockDecompilerTask):
        """
        +----------------------------+
        |        *(a#0) = b#1        |
        |      a#1 = a#0 + 0x2       |
        |        a#2 = *(a#1)        |
        | b#2 = func(a#2 + 0x4, b#1) |
        +----------------------------+
        """
        instructions = [
            Assignment(UnaryOperation(OperationType.dereference, [variable("a", 0)]), variable("b", 1)),
            Assignment(variable("a", 1), BinaryOperation(OperationType.plus, [variable("a", 0), Constant(0x2)])),
            Assignment(variable("a", 2), UnaryOperation(OperationType.dereference, [variable("a", 1)])),
            Assignment(
                variable("b", 2),
                Call(
                    FunctionSymbol("func", 0x42), [BinaryOperation(OperationType.plus, [variable("a", 2), Constant(0x4)]), variable("b", 1)]
                ),
            ),
        ]
        task.graph.add_node(node_0 := BasicBlock(0, [instr.copy() for instr in instructions]))
        DeadCodeElimination().run(task)
        assert node_0.instructions == [
            instructions[0],
            instructions[1],
            instructions[2],
            Assignment(
                ListOperation([]),
                Call(
                    FunctionSymbol("func", 0x42), [BinaryOperation(OperationType.plus, [variable("a", 2), Constant(0x4)]), variable("b", 1)]
                ),
            ),
        ]

    def test_dead_variables_in_return_values(self):
        """x = foo() will become [] = foo()"""
        x, y, a = (lambda x, name=name: Variable(name, Integer.int32_t(), ssa_label=x) for name in ["x", "y", "a"])
        foo = lambda: Call(FunctionSymbol("foo", 0x42), [])
        cfg = ControlFlowGraph()
        cfg.add_nodes_from([node := BasicBlock(0, instructions=[Assignment(x(0), foo())])])
        DeadCodeElimination().run(MockDecompilerTask(cfg))
        assert node.instructions == [Assignment(ListOperation([]), foo())]
        # [x] = foo() will become [] = foo()
        cfg = ControlFlowGraph()
        cfg.add_nodes_from([node := BasicBlock(0, instructions=[Assignment(ListOperation([x(0)]), foo())])])
        DeadCodeElimination().run(MockDecompilerTask(cfg))
        assert node.instructions == [Assignment(ListOperation([]), foo())]
        # [x, a] = foo() will result in [x, a] = foo()
        cfg = ControlFlowGraph()
        cfg.add_nodes_from([node := BasicBlock(0, instructions=[Assignment(ListOperation([x(0), a(0)]), foo()), Return([a(0)])])])
        DeadCodeElimination().run(MockDecompilerTask(cfg))
        assert node.instructions == [Assignment(ListOperation([x(0), a(0)]), foo()), Return([a(0)])]

    def test_dead_variables_with_ambiguous_type(self):
        """Check that ambigious variable types don't lead to mistaskenly removed variables."""
        cfg = ControlFlowGraph()
        cfg.add_node(
            node := BasicBlock(
                0,
                instructions=[
                    Assignment(Variable("b", Integer.int32_t()), Constant(0)),
                    Assignment(Variable("a", Integer.int32_t()), Variable("b", Integer.int32_t())),
                    Return([Variable("a", Integer.char())]),
                ],
            )
        )
        DeadCodeElimination().run(MockDecompilerTask(cfg))
        assert len(node.instructions) == 3

    def test_pointers_trivial(self):
        """
        Check whether aliased variables are correctly considered sinks.

        +--------------+
        |      0.      |
        |  ptr = &x#0  |
        |  x#1 = 0xa   |
        |  return ptr  |
        +--------------+
        """
        cfg = ControlFlowGraph()
        cfg.add_node(
            node := BasicBlock(
                0,
                instructions=[
                    Assignment(
                        Variable("ptr", Pointer(Integer.int32_t())),
                        UnaryOperation(OperationType.address, [Variable("x", ssa_label=0, is_aliased=True)]),
                    ),
                    Assignment(Variable("x", ssa_label=1, is_aliased=True), Constant(10)),
                    Return([Variable("ptr", Pointer(Integer.int32_t()))]),
                ],
            )
        )
        DeadCodeElimination().run(MockDecompilerTask(cfg))
        assert len(node.instructions) == 3

    def test_pointers_extended(self):
        """
        Check whether DCE handled pointers correctly in a more sophisticated scenario.
        (Based on test10 in test_memory)

        +--------------+     +------------------+
        |              |     |        0.        |
        |      2.      |     |    a#1 = 0x1     |
        | p#1 = &(b#7) |     |    b#7 = 0x2     |
        |              | <-- |   if(x == 0x0)   |
        +--------------+     +------------------+
          |                    |
          |                    |
          |                    v
          |                  +------------------+
          |                  |        1.        |
          |                  |   p#0 = &(a#1)   |
          |                  +------------------+
          |                    |
          |                    |
          |                    v
          |                  +------------------+
          |                  |        3.        |
          |                  | p#2 = ϕ(p#0,p#1) |
          |                  |   *(p#2) = 0x3   |
          |                  |     foo(a#1)     |
          |                  |     foo(b#7)     |
          |                  |    a#3 = 0x4     |
          |                  |    b#9 = 0x5     |
          |                  |    a#4 = 0x4     |
          +----------------> |    return p#2    |
                             +------------------+
        """
        cfg = ControlFlowGraph()
        cfg.add_nodes_from(
            [
                start := BasicBlock(
                    0,
                    instructions=[
                        Assignment(Variable("a", ssa_label=1), Constant(1)),
                        Assignment(Variable("b", ssa_label=7), Constant(2)),
                        Branch(Condition(OperationType.equal, [Variable("x"), Constant(0)])),
                    ],
                ),
                branch_true := BasicBlock(
                    1,
                    instructions=[
                        Assignment(Variable("p", ssa_label=0), UnaryOperation(OperationType.address, [Variable("a", ssa_label=1)]))
                    ],
                ),
                branch_false := BasicBlock(
                    2,
                    instructions=[
                        Assignment(Variable("p", ssa_label=1), UnaryOperation(OperationType.address, [Variable("b", ssa_label=7)]))
                    ],
                ),
                end := BasicBlock(
                    3,
                    instructions=[
                        Phi(Variable("p", ssa_label=2), [Variable("p", ssa_label=0), Variable("p", ssa_label=1)]),
                        Assignment(UnaryOperation(OperationType.dereference, [Variable("p", ssa_label=2)]), Constant(3)),
                        Assignment(ListOperation([]), Call(FunctionSymbol("foo", 0x42), [Variable("a", ssa_label=1)])),
                        Assignment(ListOperation([]), Call(FunctionSymbol("foo", 0x42), [Variable("b", ssa_label=7)])),
                        Assignment(Variable("a", ssa_label=3), Constant(4)),
                        Assignment(Variable("b", ssa_label=9), Constant(5)),
                        Assignment(Variable("a", ssa_label=4), Constant(4)),
                        Return([Variable("p", ssa_label=2)]),
                    ],
                ),
            ]
        )
        cfg.add_edges_from(
            [
                TrueCase(start, branch_true),
                FalseCase(start, branch_false),
                UnconditionalEdge(branch_true, end),
                UnconditionalEdge(branch_false, end),
            ]
        )
        DeadCodeElimination().run(MockDecompilerTask(cfg))
        assert end.instructions == [
            Phi(Variable("p", ssa_label=2), [Variable("p", ssa_label=0), Variable("p", ssa_label=1)]),
            Assignment(UnaryOperation(OperationType.dereference, [Variable("p", ssa_label=2)]), Constant(3)),
            Assignment(ListOperation([]), Call(FunctionSymbol("foo", 0x42), [Variable("a", ssa_label=1)])),
            Assignment(ListOperation([]), Call(FunctionSymbol("foo", 0x42), [Variable("b", ssa_label=7)])),
            Assignment(Variable("b", ssa_label=9), Constant(5)),
            Assignment(Variable("a", ssa_label=4), Constant(4)),
            Return([Variable("p", ssa_label=2)]),
        ]

    def test_never_remove_relations_basic(self):
        """
        Basic test that we never remove relations
        +----------------------------+  +----------------------------+
        |             0.             |  |             0.             |
        |   var_10#1 = &(var_18#2)   |  |   var_10#1 = &(var_18#2)   |
        |     *(var_10#1) = 0xa      |  |     *(var_10#1) = 0xa      |
        |   var_18#3 -> var_18#2     |  |    var_18#3 -> var_18#2    |
        |         return 0x0         |  |         return 0x0         |
        +----------------------------+  +----------------------------+

        """
        var_18 = [Variable("var_18", Integer(32, True), i, True, None) for i in range(5)]
        var_10_1 = Variable("var_10", Pointer(Integer(32, True), 32), 1, False, None)
        cfg = ControlFlowGraph()
        cfg.add_node(
            vertex := BasicBlock(
                0,
                [
                    Assignment(var_10_1, UnaryOperation(OperationType.address, [var_18[2]], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(
                        UnaryOperation(OperationType.dereference, [var_10_1], Pointer(Integer(32, True), 32), 3, False),
                        Constant(10, Pointer(Integer(32, True), 32)),
                    ),
                    Relation(var_18[3], var_18[2]),
                    Return(ListOperation([Constant(0, Integer(32, True))])),
                ],
            )
        )
        DeadCodeElimination().run(MockDecompilerTask(cfg))
        assert vertex.instructions == [
            Assignment(var_10_1, UnaryOperation(OperationType.address, [var_18[2]], Pointer(Integer(32, True), 32), None, False)),
            Assignment(
                UnaryOperation(OperationType.dereference, [var_10_1], Pointer(Integer(32, True), 32), 3, False),
                Constant(10, Pointer(Integer(32, True), 32)),
            ),
            Relation(var_18[3], var_18[2]),
            Return(ListOperation([Constant(0, Integer(32, True))])),
        ]

    def test_never_remove_relations(self):
        """
        test_memory test14
        +----------------------------+  +----------------------------+
        |             0.             |  |             0.             |
        |       eax#1 = rand()       |  |       eax#1 = rand()       |
        |    var_18#1 = var_18#0     |  |   var_18#2 = eax#1 + 0x1   |
        |   eax_1#2 = eax#1 + 0x1    |  |   var_10#1 = &(var_18#2)   |
        |   var_18#2 = eax#1 + 0x1   |  |     eax_2#3 = var_18#2     |
        |   var_10#1 = &(var_18#2)   |  |     *(var_10#1) = 0xa      |
        |     eax_2#3 = var_18#2     |  |    var_18#3 -> var_18#2    |
        |     var_14#1 = eax_2#3     |  | printf(0x804a018, eax_2#3) |
        |     eax_3#4 = var_10#1     |  |         return 0x0         |
        |     *(var_10#1) = 0xa      |  +----------------------------+
        |    var_18#3 -> var_18#2    |
        |     var_28#1 = eax_2#3     |
        | printf(0x804a018, eax_2#3) |
        |    var_18#4 = var_18#3     |
        |       eax_4#5 = 0x0        |
        |         return 0x0         |
        +----------------------------+
        """
        cfg = ControlFlowGraph()
        eax_1 = Variable("eax", Integer(32, True), 1, False, None)
        eax_1_2 = Variable("eax_1", Integer(32, True), 2, False, None)
        eax_2_3 = Variable("eax_2", Integer(32, True), 3, False, None)
        eax_3_4 = Variable("eax_3", Pointer(Integer(32, True), 32), 4, False, None)
        eax_4_5 = Variable("eax_4", Integer(32, True), 5, False, None)
        var_18 = [Variable("var_18", Integer(32, True), i, True, None) for i in range(5)]
        var_10_1 = Variable("var_10", Pointer(Integer(32, True), 32), 1, False, None)
        var_14_1 = Variable("var_14", Integer(32, True), 1, False, None)
        var_28_1 = Variable("var_28", Integer(32, True), 1, False, None)
        cfg.add_node(
            vertex := BasicBlock(
                0,
                [
                    Assignment(ListOperation([eax_1]), Call(FunctionSymbol("rand", 0), [], Pointer(CustomType("void", 0), 32), 1)),
                    Assignment(var_18[1], var_18[0]),
                    Assignment(eax_1_2, BinaryOperation(OperationType.plus, [eax_1, Constant(1, Integer(32, True))], Integer(32, True))),
                    Assignment(var_18[2], BinaryOperation(OperationType.plus, [eax_1, Constant(1, Integer(32, True))], Integer(32, True))),
                    Assignment(var_10_1, UnaryOperation(OperationType.address, [var_18[2]], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(eax_2_3, var_18[2]),
                    Assignment(var_14_1, eax_2_3),
                    Assignment(eax_3_4, var_10_1),
                    Assignment(
                        UnaryOperation(OperationType.dereference, [var_10_1], Pointer(Integer(32, True), 32), 3, False),
                        Constant(10, Pointer(Integer(32, True), 32)),
                    ),
                    Relation(var_18[3], var_18[2]),
                    Assignment(var_28_1, eax_2_3),
                    Assignment(
                        ListOperation([]),
                        Call(
                            ImportedFunctionSymbol("printf", 0),
                            [Constant(134520856, Integer(32, True)), eax_2_3],
                            Pointer(CustomType("void", 0), 32),
                            4,
                        ),
                    ),
                    Assignment(var_18[4], var_18[3]),
                    Assignment(eax_4_5, Constant(0, Integer(32, True))),
                    Return(ListOperation([Constant(0, Integer(32, True))])),
                ],
            )
        )
        DeadCodeElimination().run(MockDecompilerTask(cfg))
        assert vertex.instructions == [
            Assignment(ListOperation([eax_1]), Call(FunctionSymbol("rand", 0), [], Pointer(CustomType("void", 0), 32), 1)),
            Assignment(var_18[2], BinaryOperation(OperationType.plus, [eax_1, Constant(1, Integer(32, True))], Integer(32, True))),
            Assignment(var_10_1, UnaryOperation(OperationType.address, [var_18[2]], Pointer(Integer(32, True), 32), None, False)),
            Assignment(eax_2_3, var_18[2]),
            Assignment(
                UnaryOperation(OperationType.dereference, [var_10_1], Pointer(Integer(32, True), 32), 3, False),
                Constant(10, Pointer(Integer(32, True), 32)),
            ),
            Relation(var_18[3], var_18[2]),
            Assignment(
                ListOperation([]),
                Call(
                    ImportedFunctionSymbol("printf", 0),
                    [Constant(134520856, Integer(32, True)), eax_2_3],
                    Pointer(CustomType("void", 0), 32),
                    4,
                ),
            ),
            Return(ListOperation([Constant(0, Integer(32, True))])),
        ]


@pytest.mark.usefixtures("task")
class TestClassicDce(BaseDceTests):
    def run_dce(self, task: MockDecompilerTask):
        DeadCodeElimination().run(task)


@pytest.mark.usefixtures("task")
class TestExpressionDce(BaseDceTests):
    def run_dce(self, task: MockDecompilerTask):
        DeadComponentPruner().run(task)
