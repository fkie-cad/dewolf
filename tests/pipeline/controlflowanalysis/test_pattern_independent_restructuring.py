""" Tests for the PatternIndependentRestructuring pipeline stage"""

import pytest
from decompiler.pipeline.controlflowanalysis.restructuring import PatternIndependentRestructuring
from decompiler.structures.ast.ast_comparator import ASTComparator
from decompiler.structures.ast.ast_nodes import (
    CaseNode,
    CodeNode,
    ConditionNode,
    DoWhileLoopNode,
    LoopNode,
    SeqNode,
    SwitchNode,
    WhileLoopNode,
)
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, SwitchCase, TrueCase, UnconditionalEdge
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo.expressions import Constant, FunctionSymbol, ImportedFunctionSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Break, Continue, IndirectBranch, Phi, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import CustomType, Integer, Pointer
from decompiler.task import DecompilerTask

# class MockDecompilerTask(DecompilerTask):
#     """Mock class for decompilerTasks only containing a cfg."""
#
#     # class MockFunction:
#     #     class FunctionType:
#     #         def __init__(self):
#     #             self.return_value = "void"
#     #             self.parameters = []
#     #
#     #     def __init__(self):
#     #         self.name = "test"
#     #         self.function_type = self.FunctionType()
#
#     def __init__(self, cfg: ControlFlowGraph):
#         super().__init__("test", None)
#         self._cfg = cfg
#
#     # def reset(self):
#     #     pass


@pytest.fixture
def task() -> DecompilerTask:
    """A mock task with an empty cfg."""
    return DecompilerTask("test", ControlFlowGraph())


def variable(name="a", version=0, ssa_name=None) -> Variable:
    """A test variable as an unsigned 32bit integer."""
    return Variable(name, ssa_label=version, vartype=Integer.int32_t(), ssa_name=ssa_name)


def imp_function_symbol(name: str, value: int = 0x42) -> ImportedFunctionSymbol:
    return ImportedFunctionSymbol(name, value)


def test_empty_graph_one_basic_block(task):
    """
    +----+
    | 0. |
    +----+
    """
    task.graph.add_node(BasicBlock(0, instructions=[]))
    PatternIndependentRestructuring().run(task)

    assert isinstance(task._ast.root, CodeNode) and task._ast.root.instructions == []


def test_empty_graph_two_basic_blocks(task):
    """
    +----+
    | 0. |
    +----+
      |
      |
      v
    +----+
    | 1. |
    +----+
    """
    task.graph.add_nodes_from(vertices := [BasicBlock(0, instructions=[]), BasicBlock(1, instructions=[])])
    task.graph.add_edge(UnconditionalEdge(vertices[0], vertices[1]))
    PatternIndependentRestructuring().run(task)

    assert isinstance(task._ast.root, CodeNode) and task._ast.root.instructions == []


def test_empty_graph_with_conditions_1(task):
    """
    +----+     +---------------+
    | 1. |     |      0.       |
    |    | <-- | if(a#0 < 0x2) |
    +----+     +---------------+
      |          |
      |          |
      |          v
      |        +---------------+
      |        |      2.       |
      |        | if(b#0 < 0x2) | -+
      |        +---------------+  |
      |          |                |
      |          |                |
      |          v                |
      |        +---------------+  |
      |        |      3.       |  |
      |        +---------------+  |
      |          |                |
      |          |                |
      |          v                |
      |        +---------------+  |
      +------> |      4.       | <+
               +---------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Branch(Condition(OperationType.less, [variable("a"), Constant(2)]))]),
            BasicBlock(1, instructions=[]),
            BasicBlock(2, instructions=[Branch(Condition(OperationType.less, [variable("b"), Constant(2)]))]),
            BasicBlock(3, instructions=[]),
            BasicBlock(4, instructions=[]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[4]),
            TrueCase(vertices[2], vertices[3]),
            FalseCase(vertices[2], vertices[4]),
            UnconditionalEdge(vertices[3], vertices[4]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    assert isinstance(task._ast.root, CodeNode) and task._ast.root.instructions == []


def test_empty_graph_with_conditions_2(task):
    """
    +----+     +---------------+     +---------------+
    | 7. |     |      5.       |     |      0.       |
    |    | <-- | if(b#0 < 0xa) | <-- | if(a#0 < 0x2) |
    +----+     +---------------+     +---------------+
      |          |                     |
      |          |                     |
      |          v                     v
      |        +---------------+     +---------------+     +----+
      |        |      6.       |     |      1.       |     | 3. |
      |        |               |     | if(b#0 < 0x2) | --> |    |
      |        +---------------+     +---------------+     +----+
      |          |                     |                     |
      |          |                     |                     |
      |          v                     v                     |
      |        +---------------+     +---------------+       |
      +------> |      8.       |     |      2.       |       |
               +---------------+     +---------------+       |
                                       |                     |
                                       |                     |
                                       v                     |
                                     +---------------+       |
                                     |      4.       | <-----+
                                     +---------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Branch(Condition(OperationType.less, [variable("a"), Constant(2)]))]),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.less, [variable("b"), Constant(2)]))]),
            BasicBlock(2, instructions=[]),
            BasicBlock(3, instructions=[]),
            BasicBlock(4, instructions=[]),
            BasicBlock(5, instructions=[Branch(Condition(OperationType.less, [variable("b"), Constant(10)]))]),
            BasicBlock(6, instructions=[]),
            BasicBlock(7, instructions=[]),
            BasicBlock(8, instructions=[]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[5]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[4]),
            UnconditionalEdge(vertices[3], vertices[4]),
            TrueCase(vertices[5], vertices[6]),
            FalseCase(vertices[5], vertices[7]),
            UnconditionalEdge(vertices[6], vertices[8]),
            UnconditionalEdge(vertices[7], vertices[8]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    assert isinstance(task._ast.root, CodeNode) and task._ast.root.instructions == []


def test_empty_graph_with_switch(task):
    """
               +---------+
               |   4.    | ------------+
               +---------+             |
                 ^                     |
                 |                     |
                 |                     |
    +----+     +---------+     +----+  |
    | 2. |     |   0.    |     | 3. |  |
    |    | <-- | jmp a#0 | --> |    |  |
    +----+     +---------+     +----+  |
      |          |               |     |
      |          |               |     |
      |          v               |     |
      |        +---------+       |     |
      |        |   1.    |       |     |
      |        +---------+       |     |
      |          |               |     |
      |          |               |     |
      |          v               v     |
      |        +--------------------+  |
      +------> |         5.         | <+
               +--------------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[IndirectBranch(variable("a"))]),
            BasicBlock(1, instructions=[]),
            BasicBlock(2, instructions=[]),
            BasicBlock(3, instructions=[]),
            BasicBlock(4, instructions=[]),
            BasicBlock(5, instructions=[]),
        ]
    )
    task.graph.add_edges_from(
        [
            SwitchCase(vertices[0], vertices[1], [Constant(1)]),
            SwitchCase(vertices[0], vertices[2], [Constant(2)]),
            SwitchCase(vertices[0], vertices[3], [Constant(3)]),
            SwitchCase(vertices[0], vertices[4], [Constant(4)]),
            UnconditionalEdge(vertices[1], vertices[5]),
            UnconditionalEdge(vertices[2], vertices[5]),
            UnconditionalEdge(vertices[3], vertices[5]),
            UnconditionalEdge(vertices[4], vertices[5]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    assert isinstance(task._ast.root, CodeNode) and task._ast.root.instructions == []


def test_graph_with_switch_empty_nodes1(task):
    """
                      +-----------+                +-----------+     +--------------+     +-----------+
                      |    4.     | ------------+  |     3     |     |      0       |     |     4     |
                      +-----------+             |  | case 0x3: | <-- | switch (a#0) | --> | case 0x4: |
                        ^                       |  +-----------+     +--------------+     +-----------+
                        |                       |                      |                    |
                        |                       |                      |                    |
    +-----------+     +-----------+     +----+  |                      v                    v
    |    1.     |     |    0.     |     | 2. |  |                    +--------------+     +-----------+
    | a#0 = 0x2 | <-- |  jmp a#0  | --> |    |  |                    |      1       |     |     5     |
    +-----------+     +-----------+     +----+  |                    |  case 0x1:   |     | a#0 = 0x3 |
      |                 |                 |     |                    +--------------+     +-----------+
      |                 |                 |     |                      |
      |                 v                 |     |                      |
      |               +-----------+       |     |                      v
      |               |    3.     |       |     |                    +--------------+
      |               +-----------+       |     |                    |      2       |
      |                 |                 |     |                    |  a#0 = 0x2   |
      |                 |                 |     |                    +--------------+
      |                 v                 |     |
      |               +-----------+       |     |
      |               |    5.     |       |     |
      |               | a#0 = 0x3 | <-----+-----+
      |               +-----------+       |
      |                 |                 |
      |                 |                 |
      |                 v                 |
      |               +-----------+       |
      +-------------> |    6.     | <-----+
                      +-----------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[IndirectBranch(variable("a"))]),
            BasicBlock(1, instructions=[Assignment(variable("a"), Constant(2, Integer.int32_t()))]),
            BasicBlock(2, instructions=[]),
            BasicBlock(3, instructions=[]),
            BasicBlock(4, instructions=[]),
            BasicBlock(5, instructions=[Assignment(variable("a"), Constant(3, Integer.int32_t()))]),
            BasicBlock(6, instructions=[]),
        ]
    )
    task.graph.add_edges_from(
        [
            SwitchCase(vertices[0], vertices[1], [Constant(1, Integer.int32_t())]),
            SwitchCase(vertices[0], vertices[2], [Constant(2, Integer.int32_t())]),
            SwitchCase(vertices[0], vertices[3], [Constant(3, Integer.int32_t())]),
            SwitchCase(vertices[0], vertices[4], [Constant(4, Integer.int32_t())]),
            UnconditionalEdge(vertices[3], vertices[5]),
            UnconditionalEdge(vertices[4], vertices[5]),
            UnconditionalEdge(vertices[1], vertices[6]),
            UnconditionalEdge(vertices[2], vertices[6]),
            UnconditionalEdge(vertices[5], vertices[6]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    assert (
        isinstance(switch_node := task._ast.root, SwitchNode) and len(switch_node.children) == 3 and switch_node.expression == variable("a")
    )
    assert (
        isinstance(case1 := switch_node.children[0], CaseNode)
        and case1.expression == variable("a")
        and case1.constant == Constant(1, Integer.int32_t())
    )
    assert (
        isinstance(case2 := switch_node.children[1], CaseNode)
        and case1.expression == variable("a")
        and case2.constant == Constant(3, Integer.int32_t())
    )
    assert (
        isinstance(case3 := switch_node.children[2], CaseNode)
        and case1.expression == variable("a")
        and case3.constant == Constant(4, Integer.int32_t())
    )
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[1].instructions
    assert case2.child.is_empty_code_node
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[5].instructions


def test_graph_with_switch_empty_nodes2(task):
    """
               +-----------+                                  +-----------+     +--------------+
               |    6.     |                                  |   7True   |     |    6True     |
               | a#0 = 0xa | ------------------------------+  | a#0 = 0xa | <-- |  case 0x5:   |
               +-----------+                               |  +-----------+     +--------------+
                 ^                                         |                      ^
                 |                                         |                      |
                 |                                         |                      |
    +----+     +-----------------------------+     +----+  |  +-----------+     +--------------+     +-----------+
    | 2. |     |             0.              |     | 4. |  |  |   3True   |     |    0True     |     |   4True   |
    |    | <-- |           jmp a#0           | --> |    |  |  | case 0x3: | <-- | switch (a#0) | --> | case 0x4: |
    +----+     +-----------------------------+     +----+  |  +-----------+     +--------------+     +-----------+
      |          |                 |                 |     |                      |                    |
      |          |                 |                 |     |                      |                    |
      |          v                 v                 |     |                      v                    v
      |        +-----------+     +-----------+       |     |                    +--------------+     +-----------+
      |        |    3.     |     |    1.     |       |     |                    |    1True     |     |   5True   |
      |        |           |     | a#0 = 0x2 |       |     |                    |  case 0x1:   |     | a#0 = 0x3 |
      |        +-----------+     +-----------+       |     |                    +--------------+     +-----------+
      |          |                 |                 |     |                      |
      |          |                 |                 |     |                      |
      |          v                 |                 |     |                      v
      |        +-----------+       |                 |     |                    +--------------+
      |        |    5.     |       |                 |     |                    |    2True     |
      |        | a#0 = 0x3 | <-----+-----------------+     |                    |  a#0 = 0x2   |
      |        +-----------+       |                       |                    +--------------+
      |          |                 |                       |
      |          |                 |                       |
      |          v                 v                       |
      |        +-----------------------------+             |
      +------> |             7.              | <-----------+
               +-----------------------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[IndirectBranch(variable("a"))]),
            BasicBlock(1, instructions=[Assignment(variable("a"), Constant(2))]),
            BasicBlock(2, instructions=[]),
            BasicBlock(3, instructions=[]),
            BasicBlock(4, instructions=[]),
            BasicBlock(5, instructions=[Assignment(variable("a"), Constant(3))]),
            BasicBlock(6, instructions=[Assignment(variable("a"), Constant(10))]),
            BasicBlock(7, instructions=[]),
        ]
    )
    task.graph.add_edges_from(
        [
            SwitchCase(vertices[0], vertices[1], cases=[Constant(1)]),
            SwitchCase(vertices[0], vertices[2], cases=[Constant(2)]),
            SwitchCase(vertices[0], vertices[3], cases=[Constant(3)]),
            SwitchCase(vertices[0], vertices[4], cases=[Constant(4)]),
            SwitchCase(vertices[0], vertices[6], cases=[Constant(5)]),
            UnconditionalEdge(vertices[3], vertices[5]),
            UnconditionalEdge(vertices[4], vertices[5]),
            UnconditionalEdge(vertices[1], vertices[7]),
            UnconditionalEdge(vertices[2], vertices[7]),
            UnconditionalEdge(vertices[5], vertices[7]),
            UnconditionalEdge(vertices[6], vertices[7]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    assert isinstance(switch_node := task._ast.root, SwitchNode) and len(switch_node.children) == 4
    assert switch_node.expression == variable("a")

    assert isinstance(case1 := switch_node.children[0], CaseNode) and case1.constant == Constant(1) and case1.break_case is True
    assert isinstance(case2 := switch_node.children[1], CaseNode) and case2.constant == Constant(3) and case2.break_case is False
    assert isinstance(case3 := switch_node.children[2], CaseNode) and case3.constant == Constant(4) and case3.break_case is True
    assert isinstance(case4 := switch_node.children[3], CaseNode) and case4.constant == Constant(5) and case4.break_case is True

    assert isinstance(code_node_1 := case1.child, CodeNode) and code_node_1.instructions == vertices[1].instructions
    assert case2.child.is_empty_code_node
    assert isinstance(code_node_3 := case3.child, CodeNode) and code_node_3.instructions == vertices[5].instructions
    assert isinstance(code_node_4 := case4.child, CodeNode) and code_node_4.instructions == vertices[6].instructions


def test_empty_basic_block_after_removing(task):
    """
    +-----------+     +---------------+
    |    1.     |     |      0.       |
    | a#0 = 0x2 | <-- | if(a#0 < 0x2) |
    +-----------+     +---------------+
      |                 |
      |                 |
      |                 v
      |               +---------------+     +-----------+
      |               |      2.       |     |     1     |
      |               | if(b#0 < 0x2) | -+  |  if (x1)  |
      |               +---------------+  |  +-----------+
      |                 |                |    |
      |                 |                |    | T
      |                 v                |    v
      |               +---------------+  |  +-----------+
      |               |      3.       |  |  |     2     |
      |               +---------------+  |  | a#0 = 0x2 |
      |                 |                |  +-----------+
      |                 |                |
      |                 v                |
      |               +---------------+  |
      +-------------> |      4.       | <+
                      +---------------+

    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Branch(Condition(OperationType.less, [variable("a"), Constant(2)]))]),
            BasicBlock(1, instructions=[Assignment(variable("a"), Constant(2))]),
            BasicBlock(2, instructions=[Branch(Condition(OperationType.less, [variable("b"), Constant(2)]))]),
            BasicBlock(3, instructions=[]),
            BasicBlock(4, instructions=[]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[4]),
            TrueCase(vertices[2], vertices[3]),
            FalseCase(vertices[2], vertices[4]),
            UnconditionalEdge(vertices[3], vertices[4]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    context = LogicCondition.generate_new_context()
    resulting_ast = AbstractSyntaxTree(
        SeqNode(LogicCondition.initialize_true(context)),
        {LogicCondition.initialize_symbol("x1", context): Condition(OperationType.less, [variable("a"), Constant(2)])},
    )
    true_branch = resulting_ast._add_code_node([Assignment(variable("a"), Constant(2))])
    condition_node = resulting_ast._add_condition_node_with(LogicCondition.initialize_symbol("x1", context), true_branch)
    resulting_ast._add_edge(resulting_ast.root, condition_node)
    resulting_ast.flatten_sequence_node(resulting_ast.root)

    assert ASTComparator.compare(task._ast, resulting_ast) and task._ast.condition_map == resulting_ast.condition_map


def test_empty_graph_with_loop(task):
    """
    +----+     +---------------+
    | 1. |     |      0.       |
    |    | <-- | if(a#0 < 0x2) |
    +----+     +---------------+
      |          |
      |          |
      |          v
      |        +---------------+     +-----------+
      |        |      2.       | <+  |     1     |
      |        +---------------+  |  |  if (!x1) |
      |          |                |  +-----------+
      |          |                |    |
      |          v                |    | T
      |        +---------------+  |    v
      |        |      3.       |  |  +-------------+
      |        | if(b#0 < 0x2) | -+  |     2       |
      |        +---------------+     | while (!x2) |
      |          |                   +-------------+
      |          |                     |
      |          v                     |
      |        +---------------+       v
      +------> |      4.       |     +-----------+
               +---------------+     |     3     |
                                     +-----------+

    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Branch(Condition(OperationType.less, [variable("a"), Constant(2)]))]),
            BasicBlock(1, instructions=[]),
            BasicBlock(2, instructions=[]),
            BasicBlock(3, instructions=[Branch(Condition(OperationType.less, [variable("b"), Constant(2)]))]),
            BasicBlock(4, instructions=[]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[4]),
            UnconditionalEdge(vertices[2], vertices[3]),
            FalseCase(vertices[3], vertices[2]),
            TrueCase(vertices[3], vertices[4]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make sure condition restructured correctly.
    context = LogicCondition.generate_new_context()
    resulting_ast = AbstractSyntaxTree(
        SeqNode(LogicCondition.initialize_true(context)),
        {
            LogicCondition.initialize_symbol("x1", context): Condition(OperationType.less, [variable("a"), Constant(2)]),
            LogicCondition.initialize_symbol("x2", context): Condition(OperationType.less, [variable("b"), Constant(2)]),
        },
    )
    loop_body = resulting_ast._add_code_node([])
    while_loop = resulting_ast.factory.create_while_loop_node(~LogicCondition.initialize_symbol("x2", context))
    resulting_ast._add_node(while_loop)
    condition_node = resulting_ast._add_condition_node_with(~LogicCondition.initialize_symbol("x1", context), while_loop)
    resulting_ast._add_edge(while_loop, loop_body)
    resulting_ast._add_edge(resulting_ast.root, condition_node)
    resulting_ast.flatten_sequence_node(resulting_ast.root)

    assert ASTComparator.compare(task.syntax_tree, resulting_ast) and task.syntax_tree.condition_map == resulting_ast.condition_map


def test_restructure_cfg_sequence(task):
    """
    In this simple example, nothing in the cfg should be restructured to loops, conditions and switches
    +-----------------+
    |       0.        |
    |    i#0 = 0x0    |
    |   x#0 = 0x2a    |
    +-----------------+
      |
      |
      v
    +-----------------+
    |       1.        |
    | i#1 = i#0 + 0x1 |
    | x#1 = x#0 - i#1 |
    +-----------------+
      |
      |
      v
    +-----------------+
    |       2.        |
    | x#2 = x#1 - i#1 |
    +-----------------+
      |
      |
      v
    +-----------------+
    |       3.        |
    |   return x#2    |
    +-----------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                instructions=[
                    Assignment(variable(name="i", version=0), Constant(0)),
                    Assignment(variable(name="x", version=0), Constant(42)),
                ],
            ),
            BasicBlock(
                1,
                instructions=[
                    Assignment(
                        variable(name="i", version=1), BinaryOperation(OperationType.plus, [variable(name="i", version=0), Constant(1)])
                    ),
                    Assignment(
                        variable(name="x", version=1),
                        BinaryOperation(OperationType.minus, [variable(name="x", version=0), variable(name="i", version=1)]),
                    ),
                ],
            ),
            BasicBlock(
                2,
                instructions=[
                    Assignment(
                        variable(name="x", version=2),
                        BinaryOperation(OperationType.minus, [variable(name="x", version=1), variable(name="i", version=1)]),
                    ),
                ],
            ),
            BasicBlock(3, instructions=[Return([variable(name="x", version=2)])]),
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            UnconditionalEdge(vertices[1], vertices[2]),
            UnconditionalEdge(vertices[2], vertices[3]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make sure that only SeqNodes or CodeNodes have been created during Restructuring
    assert isinstance(code_node := task._ast.root, CodeNode)
    assert code_node.instructions == [
        Assignment(variable(name="i", version=0), Constant(0)),
        Assignment(variable(name="x", version=0), Constant(42)),
        Assignment(variable(name="i", version=1), BinaryOperation(OperationType.plus, [variable(name="i", version=0), Constant(1)])),
        Assignment(
            variable(name="x", version=1),
            BinaryOperation(OperationType.minus, [variable(name="x", version=0), variable(name="i", version=1)]),
        ),
        Assignment(
            variable(name="x", version=2),
            BinaryOperation(OperationType.minus, [variable(name="x", version=1), variable(name="i", version=1)]),
        ),
        Return([variable(name="x", version=2)]),
    ]


def test_one_node(task):
    """An graph with one node.
    +------------+
    |     0.     |
    | print("a") |
    +------------+
    """
    task.graph.add_node(
        block := BasicBlock(0, instructions=[Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("a")]))])
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(code_node := task._ast.root, CodeNode)
    assert code_node.instructions == [Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("a")]))]


def test_while_loop_one_node(task):
    """An endless while loop consisting of one cycle.
    +------------+
    |     0.     | ---+
    | print("a") |    |
    |            | <--+
    +------------+
    """
    task.graph.add_node(
        block := BasicBlock(0, instructions=[Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("a")]))])
    )
    task.graph.add_edge(UnconditionalEdge(block, block))

    PatternIndependentRestructuring().run(task)

    context = LogicCondition.generate_new_context()
    while_loop = WhileLoopNode(LogicCondition.initialize_true(context), reaching_condition=LogicCondition.initialize_true(context))
    resulting_ast = AbstractSyntaxTree(while_loop, {})
    loop_body = resulting_ast._add_code_node([Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("a")]))])
    resulting_ast._add_edge(while_loop, loop_body)

    assert ASTComparator.compare(task.syntax_tree, resulting_ast) and task.syntax_tree.condition_map == resulting_ast.condition_map


def test_empty_endless_loop(task):
    """An empty endless while loop consisting of one cycle.
    +------------+
    |     0.     | ---+
    |            |    |
    |            | <--+
    +------------+
    """
    task.graph.add_node(block := BasicBlock(0, instructions=[]))
    task.graph.add_edge(UnconditionalEdge(block, block))

    PatternIndependentRestructuring().run(task)

    context = LogicCondition.generate_new_context()
    while_loop = WhileLoopNode(LogicCondition.initialize_true(context), reaching_condition=LogicCondition.initialize_true(context))
    resulting_ast = AbstractSyntaxTree(while_loop, {})
    loop_body = resulting_ast._add_code_node([])
    resulting_ast._add_edge(while_loop, loop_body)

    assert ASTComparator.compare(task.syntax_tree, resulting_ast) and task.syntax_tree.condition_map == resulting_ast.condition_map


def test_empty_endless_loop_instructions_before(task):
    """An empty endless while loop consisting of one cycle.
    +------------+
    |     0.     |
    | print("a") |
    +------------+
        |
        v
    +------------+
    |     1.     | ---+
    |            |    |
    |            | <--+
    +------------+
    """
    task.graph.add_nodes_from(
        [
            BasicBlock0 := BasicBlock(
                0, instructions=[Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("a")]))]
            ),
            BasicBlock1 := BasicBlock(1, instructions=[]),
        ]
    )
    task.graph.add_edges_from([UnconditionalEdge(BasicBlock0, BasicBlock1), UnconditionalEdge(BasicBlock1, BasicBlock1)])

    PatternIndependentRestructuring().run(task)

    context = LogicCondition.generate_new_context()
    resulting_ast = AbstractSyntaxTree(seq_node := SeqNode(LogicCondition.initialize_true(context)), {})
    code_node = resulting_ast._add_code_node([Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("a")]))])
    resulting_ast._add_node(while_loop := resulting_ast.factory.create_endless_loop_node())
    loop_body = resulting_ast._add_code_node([])
    resulting_ast._add_edges_from(((seq_node, code_node), (seq_node, while_loop), (while_loop, loop_body)))
    resulting_ast._code_node_reachability_graph.add_reachability(code_node, loop_body)
    seq_node.sort_children()

    assert ASTComparator.compare(task.syntax_tree, resulting_ast) and task.syntax_tree.condition_map == resulting_ast.condition_map


def test_while_loop_with_empty_body(task):
    """
        Test the restructuring of a while loop
                       +-----------------+
                       |       0.        |
                       |    i#0 = 0x0    |
                       |   x#0 = 0x2a    |
                       +-----------------+
                         |
                         |
                         v
    +------------+     +-----------------+
    |     3.     |     |       1.        |
    | return x#0 | <-- | if(i#0 != 0x3)  | <+
    +------------+     +-----------------+  |
                         |                  |
                         |                  |
                         v                  |
                       +-----------------+  |
                       |       2.        | -+
                       +-----------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Assignment(variable(name="i"), Constant(0)), Assignment(variable(name="x"), Constant(42))]),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.not_equal, [variable(name="i"), Constant(3)]))]),
            BasicBlock(2, instructions=[]),
            BasicBlock(3, instructions=[Return([variable(name="x")])]),
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[1]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make sure that a LoopNode has been created during Restructuring
    context = LogicCondition.generate_new_context()
    resulting_ast = AbstractSyntaxTree(
        seq_node := SeqNode(LogicCondition.initialize_true(context)),
        {LogicCondition.initialize_symbol("x1", context): Condition(OperationType.not_equal, [variable("i"), Constant(3)])},
    )
    code_node = resulting_ast._add_code_node([Assignment(variable("i"), Constant(0)), Assignment(variable("x"), Constant(42))])
    resulting_ast._add_node(while_loop := resulting_ast.factory.create_while_loop_node(LogicCondition.initialize_symbol("x1", context)))
    loop_body = resulting_ast._add_code_node([])
    return_node = resulting_ast._add_code_node([Return([variable("x")])])
    resulting_ast._add_edges_from(((seq_node, code_node), (seq_node, while_loop), (while_loop, loop_body), (seq_node, return_node)))
    resulting_ast._code_node_reachability_graph.add_reachability_from(
        ((code_node, loop_body), (code_node, return_node), (loop_body, return_node))
    )
    seq_node.sort_children()

    assert ASTComparator.compare(task.syntax_tree, resulting_ast) and task.syntax_tree.condition_map == resulting_ast.condition_map


def test_restructure_cfg_dowhile(task):
    """
    Test the restructuring of a do while loop
    +------------------+
    |        0.        |
    |    i#0 = 0x0     |
    |    x#0 = 0x2a    |
    +------------------+
      |
      |
      v
    +------------------+
    |        1.        |
    | i#1 = ϕ(i#0,i#2) |
    | x#1 = ϕ(x#0,x#2) |
    | i#2 = i#1 + 0x1  |
    | x#2 = x#1 - i#2  | <+
    +------------------+  |
      |                   |
      |                   |
      v                   |
    +------------------+  |
    |        2.        |  |
    |  if(i#2 == 0x3)  | -+
    +------------------+
      |
      |
      v
    +------------------+
    |        3.        |
    |    return x#2    |
    +------------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                instructions=[
                    Assignment(variable(name="i", version=0), Constant(0)),
                    Assignment(variable(name="x", version=0), Constant(42)),
                ],
            ),
            BasicBlock(
                1,
                instructions=[
                    Phi(variable(name="i", version=1), [variable(name="i", version=0), variable(name="i", version=2)]),
                    Phi(variable(name="x", version=1), [variable(name="x", version=0), variable(name="x", version=2)]),
                    Assignment(
                        variable(name="i", version=2), BinaryOperation(OperationType.plus, [variable(name="i", version=1), Constant(1)])
                    ),
                    Assignment(
                        variable(name="x", version=2),
                        BinaryOperation(OperationType.minus, [variable(name="x", version=1), variable(name="i", version=2)]),
                    ),
                ],
            ),
            BasicBlock(2, instructions=[Branch(Condition(OperationType.equal, [variable(name="i", version=2), Constant(3)]))]),
            BasicBlock(3, instructions=[Return([variable(name="x", version=2)])]),
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            UnconditionalEdge(vertices[1], vertices[2]),
            TrueCase(vertices[2], vertices[1]),
            FalseCase(vertices[2], vertices[3]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make sure that a LoopNode has been created during Restructuring
    context = LogicCondition.generate_new_context()
    resulting_ast = AbstractSyntaxTree(
        seq_node := SeqNode(LogicCondition.initialize_true(context)),
        {LogicCondition.initialize_symbol("x1", context): Condition(OperationType.equal, [variable(name="i", version=2), Constant(3)])},
    )
    code_node = resulting_ast._add_code_node([Assignment(variable("i", 0), Constant(0)), Assignment(variable("x", 0), Constant(42))])
    resulting_ast._add_node(while_loop := resulting_ast.factory.create_do_while_loop_node(LogicCondition.initialize_symbol("x1", context)))
    loop_body = resulting_ast._add_code_node(
        [
            Phi(variable("i", 1), [variable("i", 0), variable("i", 2)]),
            Phi(variable("x", 1), [variable("x", 0), variable("x", 2)]),
            Assignment(variable("i", 2), BinaryOperation(OperationType.plus, [variable("i", 1), Constant(1)])),
            Assignment(variable("x", 2), BinaryOperation(OperationType.minus, [variable("x", 1), variable("i", 2)])),
        ]
    )
    return_node = resulting_ast._add_code_node([Return([variable("x", 2)])])
    resulting_ast._add_edges_from(((seq_node, code_node), (seq_node, while_loop), (while_loop, loop_body), (seq_node, return_node)))
    resulting_ast._code_node_reachability_graph.add_reachability_from(
        ((code_node, loop_body), (code_node, return_node), (loop_body, return_node))
    )
    seq_node.sort_children()

    assert ASTComparator.compare(task.syntax_tree, resulting_ast) and task.syntax_tree.condition_map == resulting_ast.condition_map


def test_restructure_cfg_endless(task):
    """
    Test the restructuring of an endless loop
    +------------------+
    |        0.        |
    |    i#0 = 0x0     |
    |    x#0 = 0x2a    |
    +------------------+
      |
      |
      v
    +------------------+
    |        1.        |
    | i#1 = ϕ(i#0,i#2) |
    | x#1 = ϕ(x#0,x#2) | ---+
    | i#2 = i#1 + 0x1  |    |
    | x#2 = x#1 - i#2  | <--+
    +------------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                instructions=[
                    Assignment(variable(name="i", version=0), Constant(0)),
                    Assignment(variable(name="x", version=0), Constant(42)),
                ],
            ),
            BasicBlock(
                1,
                instructions=[
                    Phi(variable(name="i", version=1), [variable(name="i", version=0), variable(name="i", version=2)]),
                    Phi(variable(name="x", version=1), [variable(name="x", version=0), variable(name="x", version=2)]),
                    Assignment(
                        variable(name="i", version=2), BinaryOperation(OperationType.plus, [variable(name="i", version=1), Constant(1)])
                    ),
                    Assignment(
                        variable(name="x", version=2),
                        BinaryOperation(OperationType.minus, [variable(name="x", version=1), variable(name="i", version=2)]),
                    ),
                ],
            ),
        ]
    )
    task.graph.add_edges_from([UnconditionalEdge(vertices[0], vertices[1]), UnconditionalEdge(vertices[1], vertices[1])])
    PatternIndependentRestructuring().run(task)

    # make sure that a LoopNode has been created during Restructuring
    context = LogicCondition.generate_new_context()
    resulting_ast = AbstractSyntaxTree(seq_node := SeqNode(LogicCondition.initialize_true(context)), {})
    code_node = resulting_ast._add_code_node([Assignment(variable("i", 0), Constant(0)), Assignment(variable("x", 0), Constant(42))])
    resulting_ast._add_node(while_loop := resulting_ast.factory.create_endless_loop_node())
    loop_body = resulting_ast._add_code_node(
        [
            Phi(variable("i", 1), [variable("i", 0), variable("i", 2)]),
            Phi(variable("x", 1), [variable("x", 0), variable("x", 2)]),
            Assignment(variable("i", 2), BinaryOperation(OperationType.plus, [variable("i", 1), Constant(1)])),
            Assignment(variable("x", 2), BinaryOperation(OperationType.minus, [variable("x", 1), variable("i", 2)])),
        ]
    )
    resulting_ast._add_edges_from(((seq_node, code_node), (seq_node, while_loop), (while_loop, loop_body)))
    resulting_ast._code_node_reachability_graph.add_reachability(code_node, loop_body)
    seq_node.sort_children()

    assert ASTComparator.compare(task.syntax_tree, resulting_ast) and task.syntax_tree.condition_map == resulting_ast.condition_map

    assert isinstance(seq_node := task._ast.root, SeqNode)
    assert all(not isinstance(n, ConditionNode) for n in seq_node.children)
    assert all(not isinstance(n, SwitchNode) for n in seq_node.children)
    assert any(isinstance(loop_node := n, WhileLoopNode) for n in seq_node.children)
    assert loop_node.is_endless_loop


def test_restructure_cfg_while(task):
    """
        Test the restructuring of a while loop
                       +-----------------+
                       |       0.        |
                       |    i#0 = 0x0    |
                       |   x#0 = 0x2a    |
                       +-----------------+
                         |
                         |
                         v
    +------------+     +-----------------+
    |     3.     |     |       1.        |
    | return x#0 | <-- | if(i#0 != 0x3)  | <+
    +------------+     +-----------------+  |
                         |                  |
                         |                  |
                         v                  |
                       +-----------------+  |
                       |       2.        |  |
                       | i#0 = i#0 + 0x1 |  |
                       | x#0 = x#0 - i#0 | -+
                       +-----------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Assignment(variable(name="i"), Constant(0)), Assignment(variable(name="x"), Constant(42))]),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.not_equal, [variable(name="i"), Constant(3)]))]),
            BasicBlock(
                2,
                instructions=[
                    Assignment(variable(name="i"), BinaryOperation(OperationType.plus, [variable(name="i"), Constant(1)])),
                    Assignment(variable(name="x"), BinaryOperation(OperationType.minus, [variable(name="x"), variable(name="i")])),
                ],
            ),
            BasicBlock(3, instructions=[Return([variable(name="x")])]),
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[1]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make sure that a LoopNode has been created during Restructuring
    context = LogicCondition.generate_new_context()
    resulting_ast = AbstractSyntaxTree(
        seq_node := SeqNode(LogicCondition.initialize_true(context)),
        {LogicCondition.initialize_symbol("x1", context): Condition(OperationType.not_equal, [variable(name="i", version=0), Constant(3)])},
    )
    code_node = resulting_ast._add_code_node([Assignment(variable("i", 0), Constant(0)), Assignment(variable("x", 0), Constant(42))])
    resulting_ast._add_node(while_loop := resulting_ast.factory.create_while_loop_node(LogicCondition.initialize_symbol("x1", context)))
    loop_body = resulting_ast._add_code_node(
        [
            Assignment(variable("i"), BinaryOperation(OperationType.plus, [variable("i"), Constant(1)])),
            Assignment(variable("x"), BinaryOperation(OperationType.minus, [variable("x"), variable("i")])),
        ]
    )
    return_node = resulting_ast._add_code_node([Return([variable("x", 0)])])
    resulting_ast._add_edges_from(((seq_node, code_node), (seq_node, while_loop), (while_loop, loop_body), (seq_node, return_node)))
    resulting_ast._code_node_reachability_graph.add_reachability_from(
        ((code_node, loop_body), (code_node, return_node), (loop_body, return_node))
    )
    seq_node.sort_children()

    assert ASTComparator.compare(task.syntax_tree, resulting_ast) and task.syntax_tree.condition_map == resulting_ast.condition_map


def test_restructure_cfg_if(task):
    """
    Test the restructuring of an if-clause
    +----------------+
    |       0.       |
    |   i#0 = 0x0    |
    +----------------+
      |
      |
      v
    +----------------+
    |       1.       |
    | if(i#0 == 0x0) | -+
    +----------------+  |
      |                 |
      |                 |
      v                 |
    +----------------+  |
    |       2.       |  |
    |   i#0 = 0x5    |  |
    +----------------+  |
      |                 |
      |                 |
      v                 |
    +----------------+  |
    |       3.       |  |
    |   return i#0   | <+
    +----------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Assignment(variable(name="i"), Constant(0))]),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.equal, [variable(name="i"), Constant(0)]))]),
            BasicBlock(2, instructions=[Assignment(variable(name="i"), Constant(5))]),
            BasicBlock(3, instructions=[Return([variable(name="i")])]),
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[3]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make sure that a ConditionNode has been created during Restructuring
    context = LogicCondition.generate_new_context()
    resulting_ast = AbstractSyntaxTree(
        seq_node := SeqNode(LogicCondition.initialize_true(context)),
        {LogicCondition.initialize_symbol("x1", context): Condition(OperationType.equal, [variable("i"), Constant(0)])},
    )
    code_node_0 = resulting_ast._add_code_node([Assignment(variable("i"), Constant(0))])
    code_node_2 = resulting_ast._add_code_node([Assignment(variable("i"), Constant(5))])
    code_node_3 = resulting_ast._add_code_node([Return([variable("i")])])
    condition_node = resulting_ast._add_condition_node_with(LogicCondition.initialize_symbol("x1", context), code_node_2)
    resulting_ast._add_edges_from(((seq_node, code_node_0), (seq_node, condition_node), (seq_node, code_node_3)))
    resulting_ast._code_node_reachability_graph.add_reachability_from(
        ((code_node_0, code_node_2), (code_node_0, code_node_3), (code_node_2, code_node_3))
    )
    seq_node.sort_children()

    assert ASTComparator.compare(task.syntax_tree, resulting_ast) and task.syntax_tree.condition_map == resulting_ast.condition_map


def test_restructure_cfg_ifelse(task):
    """
    Test the restructuring of an if-else-clause
                        +----------------+
                        |       0.       |
                        |   i#0 = 0x0    |
                        |   x#0 = 0x2a   |
                        +----------------+
                          |
                          |
                          v
     +------------+     +----------------+
     |     3.     |     |       1.       |
     | return i#0 | <-- | if(i#0 == 0x0) |
     +------------+     +----------------+
                          |
                          |
                          v
                        +----------------+
                        |       2.       |
                        |   return x#0   |
                        +----------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Assignment(variable(name="i"), Constant(0)), Assignment(variable(name="x"), Constant(42))]),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.equal, [variable(name="i"), Constant(0)]))]),
            BasicBlock(2, instructions=[Return([variable(name="x")])]),
            BasicBlock(3, instructions=[Return([variable(name="i")])]),
        ]
    )
    task.graph.add_edges_from(
        [UnconditionalEdge(vertices[0], vertices[1]), TrueCase(vertices[1], vertices[2]), FalseCase(vertices[1], vertices[3])]
    )
    PatternIndependentRestructuring().run(task)

    # make sure that a ConditionNode has been created during Restructuring
    context = LogicCondition.generate_new_context()
    resulting_ast = AbstractSyntaxTree(
        seq_node := SeqNode(LogicCondition.initialize_true(context)),
        {LogicCondition.initialize_symbol("x1", context): Condition(OperationType.equal, [variable("i"), Constant(0)])},
    )
    code_node_0 = resulting_ast._add_code_node([Assignment(variable("i"), Constant(0)), Assignment(variable("x"), Constant(42))])
    code_node_2 = resulting_ast._add_code_node([Return([variable("x")])])
    code_node_3 = resulting_ast._add_code_node([Return([variable("i")])])
    condition_node = resulting_ast._add_condition_node_with(LogicCondition.initialize_symbol("x1", context), code_node_2)
    resulting_ast._add_edges_from(((seq_node, code_node_0), (seq_node, condition_node), (seq_node, code_node_3)))
    resulting_ast._code_node_reachability_graph.add_reachability_from(
        ((code_node_0, code_node_2), (code_node_0, code_node_3), (code_node_2, code_node_3))
    )
    seq_node.sort_children()

    assert ASTComparator.compare(task.syntax_tree, resulting_ast) and task.syntax_tree.condition_map == resulting_ast.condition_map


def test_restructure_cfg_nested_loop(task):
    """
       Test the restructuring of a nested loop
                       +-----------------+
                       |       0.        |
                       |    i#0 = 0x0    |
                       |   x#0 = 0x2a    |
                       +-----------------+
                         |
                         |
                         v
    +------------+     +-----------------+
    |     3.     |     |       1.        |
    | return x#0 | <-- | if(i#0 != 0x3)  | <+
    +------------+     +-----------------+  |
                         |                  |
                         |                  |
                         v                  |
                       +-----------------+  |
                       |       2.        |  |
                       | i#0 = i#0 + 0x1 |  |
                       | x#0 = x#0 - i#0 |  |
                       +-----------------+  |
                         |                  |
                         |                  |
                         v                  |
                       +-----------------+  |
                       |       4.        |  |
                       |    j#0 = 0x0    |  |
                       +-----------------+  |
                         |                  |
                         |                  |
                         v                  |
                       +-----------------+  |
                       |       5.        |  |
                    +> | if(j#0 != 0x3)  | -+
                    |  +-----------------+
                    |    |
                    |    |
                    |    v
                    |  +-----------------+
                    |  |       6.        |
                    +- | j#0 = j#0 + 0x1 |
                       +-----------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Assignment(variable(name="i"), Constant(0)), Assignment(variable(name="x"), Constant(42))]),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.not_equal, [variable(name="i"), Constant(3)]))]),
            BasicBlock(
                2,
                instructions=[
                    Assignment(variable(name="i"), BinaryOperation(OperationType.plus, [variable(name="i"), Constant(1)])),
                    Assignment(variable(name="x"), BinaryOperation(OperationType.minus, [variable(name="x"), variable(name="i")])),
                ],
            ),
            BasicBlock(3, instructions=[Return([variable(name="x")])]),
            BasicBlock(4, instructions=[Assignment(variable(name="j"), Constant(0))]),
            BasicBlock(5, instructions=[Branch(Condition(OperationType.not_equal, [variable(name="j"), Constant(3)]))]),
            BasicBlock(
                6, instructions=[Assignment(variable(name="j"), BinaryOperation(OperationType.plus, [variable(name="j"), Constant(1)]))]
            ),
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[4]),
            UnconditionalEdge(vertices[4], vertices[5]),
            TrueCase(vertices[5], vertices[6]),
            FalseCase(vertices[5], vertices[1]),
            UnconditionalEdge(vertices[6], vertices[5]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make sure that a LoopNode has been created during Restructuring
    context = LogicCondition.generate_new_context()
    resulting_ast = AbstractSyntaxTree(
        seq_node := SeqNode(LogicCondition.initialize_true(context)),
        {
            LogicCondition.initialize_symbol("x1", context): Condition(OperationType.not_equal, [variable("i"), Constant(3)]),
            LogicCondition.initialize_symbol("x2", context): Condition(OperationType.not_equal, [variable("j"), Constant(3)]),
        },
    )
    code_node_0 = resulting_ast._add_code_node([Assignment(variable("i"), Constant(0)), Assignment(variable("x"), Constant(42))])
    resulting_ast._add_node(while_loop := resulting_ast.factory.create_while_loop_node(LogicCondition.initialize_symbol("x1", context)))
    resulting_ast._add_node(loop_body := resulting_ast.factory.create_seq_node())
    code_node_2_4 = resulting_ast._add_code_node(
        [
            Assignment(variable("i"), BinaryOperation(OperationType.plus, [variable("i"), Constant(1)])),
            Assignment(variable("x"), BinaryOperation(OperationType.minus, [variable("x"), variable("i")])),
            Assignment(variable("j"), Constant(0)),
        ]
    )
    resulting_ast._add_node(
        nested_while_loop := resulting_ast.factory.create_while_loop_node(LogicCondition.initialize_symbol("x2", context))
    )
    nested_loop_body = resulting_ast._add_code_node(
        [Assignment(variable("j"), BinaryOperation(OperationType.plus, [variable("j"), Constant(1)]))]
    )
    code_node_3 = resulting_ast._add_code_node([Return([variable("x")])])
    resulting_ast._add_edges_from(
        (
            (seq_node, code_node_0),
            (seq_node, while_loop),
            (while_loop, loop_body),
            (loop_body, code_node_2_4),
            (loop_body, nested_while_loop),
            (nested_while_loop, nested_loop_body),
            (seq_node, code_node_3),
        )
    )
    resulting_ast._code_node_reachability_graph.add_reachability_from(
        (
            (code_node_0, code_node_3),
            (code_node_0, code_node_2_4),
            (code_node_0, nested_loop_body),
            (code_node_2_4, nested_loop_body),
            (code_node_2_4, code_node_3),
            (nested_loop_body, code_node_3),
        )
    )
    seq_node.sort_children()
    loop_body.sort_children()

    assert ASTComparator.compare(task.syntax_tree, resulting_ast) and task.syntax_tree.condition_map == resulting_ast.condition_map


def test_restructure_cfg_loop_two_back_edges(task):
    """
    Test loop with two back-edges to the same head
    This is an example why we do not want an exit node that has one successor.
    After inserting break and continue nodes, the node 5 dominates itself, the node 6 and the two new continue nodes.
    Now, the node 6 would be an exit node, but we do not want so restructure the single successor, which is a continue node, separately.
                       +-----------------+
                       |       0.        |
                       |    i#0 = 0x0    |
                       |   x#0 = 0x2a    |
                       +-----------------+
                         |
                         |
                         v
    +------------+     +---------------------------+
    |     3.     |     |            1.             |
    | return x#0 | <-- |      if(i#0 != 0x3)       |
    +------------+     +---------------------------+
                         |                  ^    ^
                         |                  |    |
                         v                  |    |
                       +-----------------+  |    |
                       |       2.        |  |    |
                       | i#0 = i#0 + 0x1 |  |    |
                       | x#0 = x#0 - i#0 |  |    |
                       +-----------------+  |    |
                         |                  |    |
                         |                  |    |
                         v                  |    |
                       +-----------------+  |    |
                       |       4.        |  |    |
                       |    j#0 = 0x0    |  |    |
                       +-----------------+  |    |
                         |                  |    |
                         |                  |    |
                         v                  |    |
                       +-----------------+  |    |
                       |       5.        |  |    |
                       | if(j#0 != 0x3)  | -+    |
                       +-----------------+       |
                         |                       |
                         |                       |
                         v                       |
                       +-----------------+       |
                       |       6.        |       |
                       | j#0 = j#0 + 0x1 | ------+
                       +-----------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Assignment(variable(name="i"), Constant(0)), Assignment(variable(name="x"), Constant(42))]),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.not_equal, [variable(name="i"), Constant(3)]))]),
            BasicBlock(
                2,
                instructions=[
                    Assignment(variable(name="i"), BinaryOperation(OperationType.plus, [variable(name="i"), Constant(1)])),
                    Assignment(variable(name="x"), BinaryOperation(OperationType.minus, [variable(name="x"), variable(name="i")])),
                ],
            ),
            BasicBlock(3, instructions=[Return([variable(name="x")])]),
            BasicBlock(4, instructions=[Assignment(variable(name="j"), Constant(0))]),
            BasicBlock(5, instructions=[Branch(Condition(OperationType.not_equal, [variable(name="j"), Constant(3)]))]),
            BasicBlock(
                6, instructions=[Assignment(variable(name="j"), BinaryOperation(OperationType.plus, [variable(name="j"), Constant(1)]))]
            ),
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[4]),
            UnconditionalEdge(vertices[4], vertices[5]),
            TrueCase(vertices[5], vertices[6]),
            FalseCase(vertices[5], vertices[1]),
            UnconditionalEdge(vertices[6], vertices[1]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make sure that a LoopNode has been created during Restructuring
    context = LogicCondition.generate_new_context()
    resulting_ast = AbstractSyntaxTree(
        seq_node := SeqNode(LogicCondition.initialize_true(context)),
        {
            LogicCondition.initialize_symbol("x1", context): Condition(OperationType.not_equal, [variable("i"), Constant(3)]),
            LogicCondition.initialize_symbol("x2", context): Condition(OperationType.not_equal, [variable("j"), Constant(3)]),
        },
    )
    code_node_0 = resulting_ast._add_code_node([Assignment(variable("i"), Constant(0)), Assignment(variable("x"), Constant(42))])
    resulting_ast._add_node(while_loop := resulting_ast.factory.create_while_loop_node(LogicCondition.initialize_symbol("x1", context)))
    resulting_ast._add_node(loop_body := resulting_ast.factory.create_seq_node())
    code_node_2_4 = resulting_ast._add_code_node(
        [
            Assignment(variable("i"), BinaryOperation(OperationType.plus, [variable("i"), Constant(1)])),
            Assignment(variable("x"), BinaryOperation(OperationType.minus, [variable("x"), variable("i")])),
            Assignment(variable("j"), Constant(0)),
        ]
    )
    code_node_6 = resulting_ast._add_code_node(
        [Assignment(variable("j"), BinaryOperation(OperationType.plus, [variable("j"), Constant(1)]))]
    )
    true_branch = resulting_ast._add_code_node([Continue()])
    nested_condition = resulting_ast._add_condition_node_with(~LogicCondition.initialize_symbol("x2", context), true_branch)
    code_node_3 = resulting_ast._add_code_node([Return([variable("x")])])
    resulting_ast._add_edges_from(
        (
            (seq_node, code_node_0),
            (seq_node, while_loop),
            (while_loop, loop_body),
            (loop_body, code_node_2_4),
            (loop_body, nested_condition),
            (loop_body, code_node_6),
            (seq_node, code_node_3),
        )
    )
    resulting_ast._code_node_reachability_graph.add_reachability_from(
        (
            (code_node_0, code_node_3),
            (code_node_0, code_node_2_4),
            (code_node_0, code_node_6),
            (true_branch, code_node_6),
            (code_node_2_4, code_node_6),
            (code_node_2_4, code_node_3),
            (code_node_2_4, true_branch),
            (code_node_6, code_node_3),
        )
    )
    seq_node.sort_children()
    loop_body.sort_children()

    assert ASTComparator.compare(task.syntax_tree, resulting_ast) and task.syntax_tree.condition_map == resulting_ast.condition_map


def test_restructure_cfg_loop_two_back_edges_condition_1(task):
    """
    Test loop with two back-edges to the same head and if-else condition
          +-----------------+
          |       0.        |
          |    i#0 = 0x0    |
          |   x#0 = 0x2a    |
          +-----------------+
            |
            |
            v
          +---------------------------+     +------------+
          |            1.             |     |     3.     |
       +> |      if(i#0 != 0x3)       | --> | return x#0 |
       |  +---------------------------+     +------------+
       |    |                       ^
       |    |                       |
       |    v                       |
       |  +-----------------+       |
       |  |       2.        |       |
       |  | i#0 = i#0 + 0x1 |       |
       |  | x#0 = x#0 - i#0 |       |
       |  +-----------------+       |
       |    |                       |
       |    |                       |
       |    v                       |
       |  +-----------------+       |
       |  |       4.        |       |
       |  |    j#0 = 0x0    |       |
       |  | if(x#0 != 0x3)  | -+    |
       |  +-----------------+  |    |
       |    |                  |    |
       |    |                  |    |
       |    v                  |    |
       |  +-----------------+  |    |
       |  |       5.        |  |    |
       +- | if(j#0 != 0x3)  |  |    |
          +-----------------+  |    |
            |                  |    |
            |                  |    |
            v                  |    |
          +-----------------+  |    |
          |       6.        |  |    |
          | j#0 = j#0 + 0x1 | <+    |
          +-----------------+       |
            |                       |
            +-----------------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Assignment(variable(name="i"), Constant(0)), Assignment(variable(name="x"), Constant(42))]),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.not_equal, [variable(name="i"), Constant(3)]))]),
            BasicBlock(
                2,
                instructions=[
                    Assignment(variable(name="i"), BinaryOperation(OperationType.plus, [variable(name="i"), Constant(1)])),
                    Assignment(variable(name="x"), BinaryOperation(OperationType.minus, [variable(name="x"), variable(name="i")])),
                ],
            ),
            BasicBlock(3, instructions=[Return([variable(name="x")])]),
            BasicBlock(
                4,
                instructions=[
                    Assignment(variable(name="j"), Constant(0)),
                    Branch(Condition(OperationType.not_equal, [variable(name="x"), Constant(3)])),
                ],
            ),
            BasicBlock(5, instructions=[Branch(Condition(OperationType.not_equal, [variable(name="j"), Constant(3)]))]),
            BasicBlock(
                6, instructions=[Assignment(variable(name="j"), BinaryOperation(OperationType.plus, [variable(name="j"), Constant(1)]))]
            ),
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[4]),
            FalseCase(vertices[4], vertices[5]),
            TrueCase(vertices[4], vertices[6]),
            TrueCase(vertices[5], vertices[6]),
            FalseCase(vertices[5], vertices[1]),
            UnconditionalEdge(vertices[6], vertices[1]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make sure that a LoopNode has been created during Restructuring
    assert isinstance(seq_node := task.syntax_tree.root, SeqNode)

    assert len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[3].instructions
    assert isinstance(loop_node := seq_node.children[1], WhileLoopNode)

    # make sure that the loop has the correct type and condition
    assert isinstance(cond := task._ast.condition_map[loop_node.condition], Condition) and str(cond) == "i#0 != 0x3"

    assert isinstance(loop_body := loop_node.body, SeqNode)
    assert len(loop_body.children) == 3
    assert (
        isinstance(loop_body.children[0], CodeNode)
        and loop_body.children[0].instructions == vertices[2].instructions + vertices[4].instructions[:-1]
    )
    assert isinstance(loop_body.children[2], CodeNode) and loop_body.children[2].instructions == vertices[6].instructions
    assert isinstance(condition_node := loop_body.children[1], ConditionNode)

    # make sure condition node is restructured correctly
    assert condition_node.condition.is_conjunction and len(operands := condition_node.condition.operands) == 2
    assert all(op.is_negation for op in operands) and {str(task._ast.condition_map[~op]) for op in operands} == {"x#0 != 0x3", "j#0 != 0x3"}
    assert isinstance(continue_node := condition_node.true_branch_child, CodeNode) and condition_node.false_branch is None
    assert continue_node.instructions == [Continue()]

    tmp_context = LogicCondition.generate_new_context()
    assert task.syntax_tree.condition_map == {
        LogicCondition.initialize_symbol("x1", tmp_context): Condition(OperationType.not_equal, [variable("i"), Constant(3)]),
        LogicCondition.initialize_symbol("x2", tmp_context): Condition(OperationType.not_equal, [variable("x"), Constant(3)]),
        LogicCondition.initialize_symbol("x3", tmp_context): Condition(OperationType.not_equal, [variable("j"), Constant(3)]),
    }


def test_restructure_cfg_loop_two_back_edges_condition_2(task):
    """
    Test loop with two back-edges to the same head and if-else condition, the sources of the back-edges are not restructured in same region
          +-----------------+
          |       0.        |
          |    i#0 = 0x0    |
          |   x#0 = 0x2a    |
          +-----------------+
            |
            |
            v
          +----------------------+     +------------+
          |          1.          |     |     3.     |
       +> |    if(i#0 != 0x3)    | --> | return x#0 |
       |  +----------------------+     +------------+
       |    |                  ^
       |    |                  |
       |    v                  |
       |  +-----------------+  |
       |  |       2.        |  |
       |  | i#0 = i#0 + 0x1 |  |
       |  | x#0 = x#0 - i#0 |  |
       |  | if(x#0 != 0x3)  | -+
       |  +-----------------+
       |    |
       |    |
       |    v
       |  +-----------------+
       |  |       4.        |
       |  | if(j#0 != 0x3)  | -+
       |  +-----------------+  |
       |    |                  |
       |    |                  |
       |    v                  |
       |  +-----------------+  |
       |  |       5.        |  |
       |  |    j#0 = 0x0    |  |
       |  +-----------------+  |
       |    |                  |
       |    |                  |
       |    v                  |
       |  +-----------------+  |
       |  |       6.        |  |
       +- | j#0 = j#0 + 0x1 | <+
          +-----------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Assignment(variable(name="i"), Constant(0)), Assignment(variable(name="x"), Constant(42))]),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.not_equal, [variable(name="i"), Constant(3)]))]),
            BasicBlock(
                2,
                instructions=[
                    Assignment(variable(name="i"), BinaryOperation(OperationType.plus, [variable(name="i"), Constant(1)])),
                    Assignment(variable(name="x"), BinaryOperation(OperationType.minus, [variable(name="x"), variable(name="i")])),
                    Branch(Condition(OperationType.not_equal, [variable(name="x"), Constant(3)])),
                ],
            ),
            BasicBlock(3, instructions=[Return([variable(name="x")])]),
            BasicBlock(4, instructions=[Branch(Condition(OperationType.not_equal, [variable(name="j"), Constant(3)]))]),
            BasicBlock(5, instructions=[Assignment(variable(name="j"), Constant(0))]),
            BasicBlock(
                6, instructions=[Assignment(variable(name="j"), BinaryOperation(OperationType.plus, [variable(name="j"), Constant(1)]))]
            ),
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            TrueCase(vertices[2], vertices[4]),
            FalseCase(vertices[2], vertices[1]),
            TrueCase(vertices[4], vertices[5]),
            FalseCase(vertices[4], vertices[6]),
            UnconditionalEdge(vertices[5], vertices[6]),
            UnconditionalEdge(vertices[6], vertices[1]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make sure that a LoopNode has been created during Restructuring
    context = LogicCondition.generate_new_context()
    resulting_ast = AbstractSyntaxTree(
        seq_node := SeqNode(LogicCondition.initialize_true(context)),
        {
            LogicCondition.initialize_symbol("x1", context): Condition(OperationType.not_equal, [variable("i"), Constant(3)]),
            LogicCondition.initialize_symbol("x2", context): Condition(OperationType.not_equal, [variable("x"), Constant(3)]),
            LogicCondition.initialize_symbol("x3", context): Condition(OperationType.not_equal, [variable("j"), Constant(3)]),
        },
    )
    code_node_0 = resulting_ast._add_code_node([Assignment(variable("i"), Constant(0)), Assignment(variable("x"), Constant(42))])
    resulting_ast._add_node(while_loop := resulting_ast.factory.create_while_loop_node(LogicCondition.initialize_symbol("x1", context)))
    resulting_ast._add_node(loop_body := resulting_ast.factory.create_seq_node())
    code_node_2 = resulting_ast._add_code_node(
        [
            Assignment(variable("i"), BinaryOperation(OperationType.plus, [variable("i"), Constant(1)])),
            Assignment(variable("x"), BinaryOperation(OperationType.minus, [variable("x"), variable("i")])),
        ]
    )
    continue_branch = resulting_ast._add_code_node([Continue()])
    continue_condition = resulting_ast._add_condition_node_with(~LogicCondition.initialize_symbol("x2", context), continue_branch)
    code_node_5 = resulting_ast._add_code_node([Assignment(variable(name="j"), Constant(0))])
    node_5_condition = resulting_ast._add_condition_node_with(LogicCondition.initialize_symbol("x3", context), code_node_5)
    code_node_6 = resulting_ast._add_code_node(
        [Assignment(variable("j"), BinaryOperation(OperationType.plus, [variable("j"), Constant(1)]))]
    )
    code_node_3 = resulting_ast._add_code_node([Return([variable("x")])])
    resulting_ast._add_edges_from(
        (
            (seq_node, code_node_0),
            (seq_node, while_loop),
            (while_loop, loop_body),
            (loop_body, code_node_2),
            (loop_body, continue_condition),
            (loop_body, node_5_condition),
            (loop_body, code_node_6),
            (seq_node, code_node_3),
        )
    )
    resulting_ast._code_node_reachability_graph.add_reachability_from(
        (
            (code_node_0, code_node_3),
            (code_node_0, code_node_2),
            (code_node_0, code_node_6),
            (code_node_2, code_node_6),
            (code_node_2, code_node_5),
            (code_node_2, code_node_3),
            (code_node_2, continue_branch),
            (continue_branch, code_node_5),
            (continue_branch, code_node_6),
            (code_node_5, code_node_3),
            (code_node_5, code_node_6),
            (code_node_6, code_node_3),
        )
    )
    seq_node.sort_children()
    loop_body.sort_children()

    assert ASTComparator.compare(task.syntax_tree, resulting_ast) and task.syntax_tree.condition_map == resulting_ast.condition_map


def test_restructure_cfg_loop_two_back_edges_condition_3(task):
    """
    Test loop with two back-edges to the same head and if-else condition, the sources of the back-edges are not restructured in same region
                        +-----------------------+
                        |                       |
                        |  +-----------------+  |
                        |  |       0.        |  |
                        |  |    i#0 = 0x0    |  |
      +-----------------+  |   x#0 = 0x2a    |  |
      |                    +-----------------+  |
      |                      |                  |
      |                      |                  |
      |                      v                  v
      |                    +---------------------------+
      |                    |            1.             |
      |                    |      i#0 = i#0 + 0x1      |
      |                 +> |      if(i#0 != 0x3)       |
      |                 |  +---------------------------+
      |                 |    |                  |
      |                 |    |                  |
      |                 |    v                  |
    +-----------+       |  +-----------------+  |
    |    3.     |       |  |       2.        |  |
    | j#0 = 0x0 |       |  | x#0 = x#0 - i#0 |  |
    |           | <-----+- | if(x#0 != 0x3)  |  |
    +-----------+       |  +-----------------+  |
                        |    |                  |
                        |    |                  |
                        |    v                  |
                        |  +-----------------+  |
                        |  |       4.        |  |
                        |  |   printf(x#0)   |  |
                        |  | if(j#0 != 0x3)  | -+----+
                        |  +-----------------+  |    |
                        |    |                  |    |
                        |    |                  |    |
                        |    v                  |    |
                        |  +-----------------+  |    |
                        |  |       5.        |  |    |
                        +- | j#0 = j#0 + 0x1 | <+    |
                           +-----------------+       |
                           +-----------------+       |
                           |       6.        |       |
                           |   return x#0    | <-----+
                           +-----------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                instructions=[
                    Assignment(variable(name="i"), Constant(0)),
                    Assignment(variable(name="x"), Constant(42)),
                ],
            ),
            BasicBlock(
                1,
                instructions=[
                    Assignment(variable(name="i"), BinaryOperation(OperationType.plus, [variable(name="i"), Constant(1)])),
                    Branch(Condition(OperationType.not_equal, [variable(name="i"), Constant(3)])),
                ],
            ),
            BasicBlock(
                2,
                instructions=[
                    Assignment(variable(name="x"), BinaryOperation(OperationType.minus, [variable(name="x"), variable(name="i")])),
                    Branch(Condition(OperationType.not_equal, [variable(name="x"), Constant(3)])),
                ],
            ),
            BasicBlock(3, instructions=[Assignment(variable(name="j"), Constant(0))]),
            BasicBlock(
                4,
                instructions=[
                    Call(imp_function_symbol("printf"), [variable("x")]),
                    Branch(Condition(OperationType.not_equal, [variable(name="j"), Constant(3)])),
                ],
            ),
            BasicBlock(
                5, instructions=[Assignment(variable(name="j"), BinaryOperation(OperationType.plus, [variable(name="j"), Constant(1)]))]
            ),
            BasicBlock(6, instructions=[Return([variable(name="x")])]),
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[5]),
            TrueCase(vertices[2], vertices[4]),
            FalseCase(vertices[2], vertices[3]),
            UnconditionalEdge(vertices[3], vertices[1]),
            TrueCase(vertices[4], vertices[5]),
            FalseCase(vertices[4], vertices[6]),
            UnconditionalEdge(vertices[5], vertices[1]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make sure that a LoopNode has been created during Restructuring
    assert isinstance(seq_node := task.syntax_tree.root, SeqNode)
    assert len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[6].instructions
    assert isinstance(loop_node := seq_node.children[1], WhileLoopNode)

    # make sure that the loop has the correct type and condition
    assert loop_node.is_endless_loop

    # TODO update after fixing this Problem -> after extracting break, we could do a different if-else
    # # make sure that the two back-edges been restructured to a ConditionNode
    # assert isinstance(loop_node.body, SeqNode) and len(loop_node.body.children) == 3
    # assert isinstance(loop_node.body.children[0], CodeNode) and loop_node.body.children[0].stmts == vertices[1].instructions[:-1]
    # assert isinstance(loop_middle := loop_node.body.children[1], ConditionNode)
    # assert isinstance(loop_node.body.children[2], CodeNode) and loop_node.body.children[2].stmts == vertices[5].instructions
    #
    # # Continue case restructured correctly
    # if loop_middle.condition.is_symbol:
    #     assert isinstance(loop_middle_seq := loop_middle.true_branch, SeqNode)
    #     assert loop_middle.false_branch is None
    #     assert isinstance(cond := task._ast.condition_map[loop_middle.condition], Condition) and str(cond) == "i#0 != 0x3"
    # else:
    #     assert (loop_middle.condition).is_negation
    #     assert isinstance(loop_middle_seq := loop_middle.false_branch, SeqNode)
    #     assert loop_middle.true_branch is None
    #     assert isinstance(cond := task._ast.condition_map[loop_middle.condition.operands[0]], Condition) and str(cond) == "i#0 != 0x3"
    #
    # # loop_middle_seq is restructured correctly:
    # assert len(loop_middle_seq.children) == 4
    # assert isinstance(loop_middle_seq.children[0], CodeNode) and loop_middle_seq.children[0].stmts == vertices[2].instructions[:-1]
    #
    # assert isinstance(continue_branch := loop_middle_seq.children[1], ConditionNode)
    # if continue_branch.condition.is_symbol:
    #     assert isinstance(cond_node := continue_branch.false_branch, CodeNode)
    #     assert continue_branch.true_branch is None
    #     assert isinstance(cond := task._ast.condition_map[continue_branch.condition], Condition) and str(cond) == "x#0 != 0x3"
    # else:
    #     assert (continue_branch.condition).is_negation
    #     assert isinstance(cond_node := continue_branch.true_branch, CodeNode)
    #     assert continue_branch.false_branch is None
    #     assert isinstance(cond := task._ast.condition_map[continue_branch.condition.operands[0]], Condition) and str(cond) == "x#0 != 0x3"
    # assert cond_node.stmts == vertices[3].instructions + ["continue"]
    #
    # assert isinstance(loop_middle_seq.children[2], CodeNode) and loop_middle_seq.children[2].stmts == vertices[4].instructions[:-1]
    #
    # assert isinstance(break_branch := loop_middle_seq.children[3], ConditionNode)
    # if is_and(break_branch.condition):
    #     assert isinstance(break_branch.true_branch, CodeNode) and break_branch.true_branch.stmts == ["break"]
    #     assert break_branch.false_branch is None
    #     assert isinstance(cond := task._ast.condition_map[break_branch.condition.operands[0]], Condition) and str(cond) == "x#0 != 0x3"
    #     assert isinstance(cond := task._ast.condition_map[break_branch.condition.operands[1].operands[0]], Condition) and str(cond) == "j#0 != 0x3"
    # else:
    #     assert is_or(break_branch.condition)
    #     assert isinstance(break_branch.false_branch, CodeNode) and break_branch.false_branch.stmts == ["break"]
    #     assert break_branch.true_branch is None
    #     assert isinstance(cond := task._ast.condition_map[break_branch.condition.operands[0].operands[0]], Condition) and str(cond) == "x#0 != 0x3"
    #     assert isinstance(cond := task._ast.condition_map[break_branch.condition.operands[1]], Condition) and str(cond) == "j#0 != 0x3"


def test_restructure_cfg_loop_two_back_edges_condition_4(task):
    """
    Test loop with two back-edges to the same head and if-else condition, the sources of the back-edges are not restructured in same region
    Here, we find a smaller region when searching for earlier exit nodes.
    Consider the loop region with head 1, consisting of the nodes 1, 2, 3, 4, 5 and two added continue nodes and one added break node.
    The regions dominated by 4 and 5 are too small. When restructuring region 3, the node 4 is an exit node, i.e. we split the break node
    from the region.
                        +-----------------+
                        |       0.        |
                        |    i#0 = 0x0    |
                        |   x#0 = 0x2a    |
                        +-----------------+
                          |
                          |
                          v
                        +---------------------------+
                        |            1.             |
                        |      i#0 = i#0 + 0x1      |
                     +> |      if(i#0 != 0x3)       |
                     |  +---------------------------+
                     |    |                  |    ^
                     |    |                  |    |
                     |    v                  |    |
                     |  +-----------------+  |    |
                     |  |       2.        |  |    |
                     |  | x#0 = x#0 - i#0 |  |    |
                     |  +-----------------+  |    |
                     |    |                  |    |
                     |    |                  |    |
                     |    v                  |    |
                     |  +-----------------+  |    |
                     |  |       3.        |  |    |
                     |  |    j#0 = 0x0    |  |    |
                     +- | if(x#0 != 0x3)  |  |    |
                        +-----------------+  |    |
                          |                  |    |
                          |                  |    |
                          v                  |    |
     +------------+     +-----------------+  |    |
     |     6.     |     |       4.        |  |    |
     | return x#0 |     |   printf(x#0)   |  |    |
     |            | <-- | if(j#0 != 0x3)  |  |    |
     +------------+     +-----------------+  |    |
                          |                  |    |
                          |                  |    |
                          v                  |    |
                        +-----------------+  |    |
                        |       5.        |  |    |
                        | j#0 = j#0 + 0x1 | <+    |
                        +-----------------+       |
                          |                       |
                          +-----------------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Assignment(variable(name="i"), Constant(0)), Assignment(variable(name="x"), Constant(42))]),
            BasicBlock(
                1,
                instructions=[
                    Assignment(variable(name="i"), BinaryOperation(OperationType.plus, [variable(name="i"), Constant(1)])),
                    Branch(Condition(OperationType.not_equal, [variable(name="i"), Constant(3)])),
                ],
            ),
            BasicBlock(
                2,
                instructions=[
                    Assignment(variable(name="x"), BinaryOperation(OperationType.minus, [variable(name="x"), variable(name="i")]))
                ],
            ),
            BasicBlock(
                3,
                instructions=[
                    Assignment(variable(name="j"), Constant(0)),
                    Branch(Condition(OperationType.not_equal, [variable(name="x"), Constant(3)])),
                ],
            ),
            BasicBlock(
                4,
                instructions=[
                    Call(imp_function_symbol("printf"), [variable("x")]),
                    Branch(Condition(OperationType.not_equal, [variable(name="j"), Constant(3)])),
                ],
            ),
            BasicBlock(
                5, instructions=[Assignment(variable(name="j"), BinaryOperation(OperationType.plus, [variable(name="j"), Constant(1)]))]
            ),
            BasicBlock(6, instructions=[Return([variable(name="x")])]),
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[5]),
            UnconditionalEdge(vertices[2], vertices[3]),
            FalseCase(vertices[3], vertices[1]),
            TrueCase(vertices[3], vertices[4]),
            TrueCase(vertices[4], vertices[5]),
            FalseCase(vertices[4], vertices[6]),
            UnconditionalEdge(vertices[5], vertices[1]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make sure that a LoopNode has been created during Restructuring
    assert isinstance(seq_node := task._ast.root, SeqNode)
    assert len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[6].instructions
    assert isinstance(loop_node := seq_node.children[1], WhileLoopNode)

    # make sure that the loop has the correct type and condition
    assert loop_node.is_endless_loop

    # make sure that the two back-edges been restructured to a ConditionNode
    assert isinstance(loop_node.body, SeqNode) and len(loop_node.body.children) == 3
    assert isinstance(loop_node.body.children[0], CodeNode) and loop_node.body.children[0].instructions == vertices[1].instructions[:-1]
    assert isinstance(loop_middle := loop_node.body.children[1], ConditionNode)
    assert isinstance(loop_node.body.children[2], CodeNode) and loop_node.body.children[2].instructions == vertices[5].instructions

    # Continue case restructured correctly
    assert loop_middle.condition.is_symbol
    assert isinstance(loop_middle_seq := loop_middle.true_branch_child, SeqNode)
    assert loop_middle.false_branch is None
    assert isinstance(cond := task._ast.condition_map[loop_middle.condition], Condition) and str(cond) == "i#0 != 0x3"

    # loop_middle_seq is restructured correctly:
    assert len(loop_middle_seq.children) == 4
    assert (
        isinstance(loop_middle_seq.children[0], CodeNode)
        and loop_middle_seq.children[0].instructions == vertices[2].instructions + vertices[3].instructions[:-1]
    )

    assert isinstance(continue_branch := loop_middle_seq.children[1], ConditionNode)
    assert continue_branch.condition.is_negation
    assert isinstance(continue_branch.true_branch_child, CodeNode) and continue_branch.true_branch_child.instructions == [Continue()]
    assert continue_branch.false_branch is None
    assert isinstance(cond := task._ast.condition_map[~continue_branch.condition], Condition) and str(cond) == "x#0 != 0x3"

    assert isinstance(loop_middle_seq.children[2], CodeNode) and loop_middle_seq.children[2].instructions == vertices[4].instructions[:-1]
    #
    assert isinstance(break_branch := loop_middle_seq.children[3], ConditionNode)
    assert break_branch.condition.is_negation
    assert isinstance(break_branch.true_branch_child, CodeNode) and break_branch.true_branch_child.instructions == [Break()]
    assert break_branch.false_branch is None
    assert isinstance(cond := task._ast.condition_map[~break_branch.condition], Condition) and str(cond) == "j#0 != 0x3"


def test_restructure_cfg_loop_two_back_edges_condition_5(task):
    """
    Test loop with two back-edges to the same head and if-else condition, the sources of the back-edges are not restructured in same region
                        +-----------------+
                        |       0.        |
                        |    i#0 = 0x0    |
                        |   x#0 = 0x2a    |
                        +-----------------+
                          |
                          |
                          v
                        +---------------------------+
                        |            1.             |
                        |      i#0 = i#0 + 0x1      |
                     +> |      if(i#0 != 0x3)       |
                     |  +---------------------------+
                     |    |                  |    ^
                     |    |                  |    |
                     |    v                  |    |
                     |  +-----------------+  |    |
                     |  |       2.        |  |    |
                     |  | x#0 = x#0 - i#0 |  |    |
                     |  +-----------------+  |    |
                     |    |                  |    |
                     |    |                  |    |
                     |    v                  |    |
                     |  +-----------------+  |    |
                     |  |       3.        |  |    |
                     |  |    j#0 = 0x0    |  |    |
                     +- | if(x#0 != 0x3)  |  |    |
                        +-----------------+  |    |
                          |                  |    |
                          |                  |    |
                          v                  |    |
                        +-----------------+  |    |
                        |       4.        |  |    |
                        |   printf(x#0)   |  |    |
                        +-----------------+  |    |
                          |                  |    |
                          |                  |    |
                          v                  |    |
     +------------+     +-----------------+  |    |
     |     7.     |     |       5.        |  |    |
     | return x#0 |     | j#0 = j#0 + 0x1 |  |    |
     |            | <-- | if(j#0 != 0x3)  | <+    |
     +------------+     +-----------------+       |
                          |                       |
                          |                       |
                          v                       |
                        +-----------------+       |
                        |       6.        |       |
                        |   printf(j#0)   | ------+
                        +-----------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Assignment(variable(name="i"), Constant(0)), Assignment(variable(name="x"), Constant(42))]),
            BasicBlock(
                1,
                instructions=[
                    Assignment(variable(name="i"), BinaryOperation(OperationType.plus, [variable(name="i"), Constant(1)])),
                    Branch(Condition(OperationType.not_equal, [variable(name="i"), Constant(3)])),
                ],
            ),
            BasicBlock(
                2,
                instructions=[
                    Assignment(variable(name="x"), BinaryOperation(OperationType.minus, [variable(name="x"), variable(name="i")])),
                ],
            ),
            BasicBlock(
                3,
                instructions=[
                    Assignment(variable(name="j"), Constant(0)),
                    Branch(Condition(OperationType.not_equal, [variable(name="x"), Constant(3)])),
                ],
            ),
            BasicBlock(4, instructions=[Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [variable("x")]))]),
            BasicBlock(
                5,
                instructions=[
                    Assignment(variable(name="j"), BinaryOperation(OperationType.plus, [variable(name="j"), Constant(1)])),
                    Branch(Condition(OperationType.not_equal, [variable(name="j"), Constant(3)])),
                ],
            ),
            BasicBlock(6, instructions=[Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [variable("j")]))]),
            BasicBlock(7, instructions=[Return([variable(name="x")])]),
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[5]),
            UnconditionalEdge(vertices[2], vertices[3]),
            FalseCase(vertices[3], vertices[1]),
            TrueCase(vertices[3], vertices[4]),
            UnconditionalEdge(vertices[4], vertices[5]),
            TrueCase(vertices[5], vertices[6]),
            FalseCase(vertices[5], vertices[7]),
            UnconditionalEdge(vertices[6], vertices[1]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make sure that a LoopNode has been created during Restructuring
    assert isinstance(seq_node := task._ast.root, SeqNode)
    assert len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[7].instructions
    assert isinstance(loop_node := seq_node.children[1], WhileLoopNode)

    # make sure that the loop has the correct type and condition
    assert loop_node.is_endless_loop

    # make sure that the two back-edges been restructured to a ConditionNode
    assert isinstance(loop_node.body, SeqNode) and len(loop_node.body.children) == 5
    assert isinstance(loop_node.body.children[0], CodeNode) and loop_node.body.children[0].instructions == vertices[1].instructions[:-1]
    assert isinstance(loop_middle := loop_node.body.children[1], ConditionNode)
    assert isinstance(loop_node.body.children[2], CodeNode) and loop_node.body.children[2].instructions == vertices[5].instructions[:-1]
    assert isinstance(break_condition := loop_node.body.children[3], ConditionNode)
    assert isinstance(loop_node.body.children[4], CodeNode) and loop_node.body.children[4].instructions == vertices[6].instructions

    # Continue case restructured correctly
    assert loop_middle.condition.is_symbol
    assert isinstance(loop_middle_seq := loop_middle.true_branch_child, SeqNode)
    assert loop_middle.false_branch is None
    assert isinstance(cond := task._ast.condition_map[loop_middle.condition], Condition) and str(cond) == "i#0 != 0x3"

    # loop_middle_seq is restructured correctly:
    assert len(loop_middle_seq.children) == 3
    assert (
        isinstance(loop_middle_seq.children[0], CodeNode)
        and loop_middle_seq.children[0].instructions == vertices[2].instructions + vertices[3].instructions[:-1]
    )

    assert isinstance(continue_branch := loop_middle_seq.children[1], ConditionNode)
    assert continue_branch.condition.is_negation
    assert isinstance(continue_branch.true_branch_child, CodeNode) and continue_branch.true_branch_child.instructions == [Continue()]
    assert continue_branch.false_branch is None
    assert isinstance(cond := task._ast.condition_map[~continue_branch.condition], Condition) and str(cond) == "x#0 != 0x3"

    assert isinstance(loop_middle_seq.children[2], CodeNode) and loop_middle_seq.children[2].instructions == vertices[4].instructions

    # break_condition is restructured correctly
    assert break_condition.condition.is_negation
    assert isinstance(break_condition.true_branch_child, CodeNode) and break_condition.true_branch_child.instructions == [Break()]
    assert break_condition.false_branch is None
    assert isinstance(cond := task._ast.condition_map[~break_condition.condition], Condition) and str(cond) == "j#0 != 0x3"


def test_restructure_cfg_nested_loop_not_head(task):
    """
        A nested loop where the head of the inner loop is not the source of the back-edge.
                       +-----------------+
                       |       0.        |
                       |    i#0 = 0x0    |
                       |   x#0 = 0x2a    |
                       +-----------------+
                         |
                         |
                         v
    +------------+     +-----------------+
    |     3.     |     |       1.        |
    | return x#0 | <-- | if(i#0 != 0x3)  | <+
    +------------+     +-----------------+  |
                         |                  |
                         |                  |
                         v                  |
                       +-----------------+  |
                       |       2.        |  |
                       | i#0 = i#0 + 0x1 |  |
                       | x#0 = x#0 - i#0 |  |
                       +-----------------+  |
                         |                  |
                         |                  |
                         v                  |
                       +-----------------+  |
                       |       4.        |  |
                    +> |    j#0 = 0x0    |  |
                    |  +-----------------+  |
                    |    |                  |
                    |    |                  |
                    |    v                  |
                    |  +-----------------+  |
                    |  |       5.        |  |
                    |  | if(j#0 != 0x3)  | -+
                    |  +-----------------+
                    |    |
                    |    |
                    |    v
                    |  +-----------------+
                    |  |       6.        |
                    +- | j#0 = j#0 + 0x1 |
                       +-----------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                instructions=[
                    Assignment(variable(name="i"), Constant(0)),
                    Assignment(variable(name="x"), Constant(42)),
                ],
            ),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.not_equal, [variable(name="i"), Constant(3)]))]),
            BasicBlock(
                2,
                instructions=[
                    Assignment(variable(name="i"), BinaryOperation(OperationType.plus, [variable(name="i"), Constant(1)])),
                    Assignment(variable(name="x"), BinaryOperation(OperationType.minus, [variable(name="x"), variable(name="i")])),
                ],
            ),
            BasicBlock(3, instructions=[Return([variable(name="x")])]),
            BasicBlock(4, instructions=[Assignment(variable(name="j"), Constant(0))]),
            BasicBlock(
                5,
                instructions=[
                    Branch(Condition(OperationType.not_equal, [variable(name="j"), Constant(3)])),
                ],
            ),
            BasicBlock(
                6,
                instructions=[
                    Assignment(variable(name="j"), BinaryOperation(OperationType.plus, [variable(name="j"), Constant(1)])),
                ],
            ),
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[4]),
            UnconditionalEdge(vertices[4], vertices[5]),
            TrueCase(vertices[5], vertices[6]),
            FalseCase(vertices[5], vertices[1]),
            UnconditionalEdge(vertices[6], vertices[4]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make sure that a LoopNode has been created during Restructuring
    assert isinstance(seq_node := task._ast.root, SeqNode)
    assert len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode)
    assert isinstance(loop_node := seq_node.children[1], WhileLoopNode)
    assert isinstance(seq_node.children[2], CodeNode)

    # make sure that the loop has the correct type and condition
    assert isinstance(cond := task._ast.condition_map[loop_node.condition], Condition) and str(cond) == "i#0 != 0x3"

    assert isinstance(loop_body := loop_node.body, SeqNode)
    assert len(loop_body.children) == 2
    assert isinstance(loop_body.children[0], CodeNode)
    assert isinstance(nested_loop := loop_body.children[1], LoopNode)

    # nested loop
    assert nested_loop.is_endless_loop

    assert isinstance(nested_loop_body := nested_loop.body, SeqNode)
    assert len(nested_loop_body.children) == 3
    assert isinstance(cn1 := nested_loop.body.children[0], CodeNode) and cn1.instructions == vertices[4].instructions
    assert isinstance(cond_node := nested_loop.body.children[1], ConditionNode)
    assert isinstance(cn2 := nested_loop.body.children[2], CodeNode) and cn2.instructions == vertices[6].instructions

    # Check condition node break
    assert cond_node.condition.is_negation
    assert isinstance(cond := task._ast.condition_map[~cond_node.condition], Condition)
    assert isinstance(code_node := cond_node.true_branch_child, CodeNode)
    assert cond_node.false_branch is None
    assert str(cond) == "j#0 != 0x3"
    assert code_node.instructions == [Break()]


def test_dream_paper_fig3(task):
    """
      This test implements the example from the first dream paper (https://www.ndss-symposium.org/wp-content/uploads/2017/09/11_4_2.pdf)
      on site 4, see figure 3 for the control flow graph and figure 5 for the expected decompiled code.
                                                   +------------------------------------+
                                                   |                                    |
                                                   |                +----------------+  |  +--------------------------+     +------------+
                                                   |                |       0.       |  |  |            7.            |     |     8.     |
                            +----------------------+-------------+  | if(a#0 == 0x0) | -+> |      if(d#0 == 0x0)      | --> | n#0 = 0x2a |
                            |                      |             |  +----------------+  |  +--------------------------+     +------------+
                            |                      |             |    |                 |    |                 ^    ^         |
                            |                      |             |    |                 |    |                 |    +---------+
                            v                      v             |    v                 |    v                 |
       +------------+     +----------------+     +------------+  |  +----------------+  |  +----------------+  |
       |     4.     |     |       3.       |     |    10.     |  |  |       1.       |  |  |       9.       |  |
       | k#0 = 0x2a | <-- | if(c#0 == 0x0) |     | o#0 = 0x2a |  +- | if(b#0 == 0x0) |  +- | if(e#0 == 0x0) |  |
       +------------+     +----------------+     +------------+     +----------------+     +----------------+  |
         |                  |                      |                  |                      |                 |
         |                  |                      |                  |                      |                 |
         |                  |                      |                  v                      v                 |
         |                  |                      |                +----------------+     +----------------+  |
         |                  |                      |                |       2.       |     |      11.       |  |
         |                  |                      |                |   j#0 = 0x2a   |     |   p#0 = 0x2a   |  |
         |                  |                      |                +----------------+     +----------------+  |
         |                  |                      |                  |                      |                 |
         |                  |                      |                  |                      |                 |
         |                  |                      |                  v                      v                 |
         |                  |                      |                +----------------+     +----------------+  |
         |                  |                      |                |       5.       |     |      12.       |  |
         |                  +----------------------+--------------> |   l#0 = 0x2a   |     | if(f#0 == 0x0) | -+
         |                                         |                +----------------+     +----------------+
         |                                         |                  |                      |
         |                                         |                  |                      |
         |                                         |                  v                      |
         |                                         |                +----------------+       |
         |                                         |                |       6.       |       |
         +-----------------------------------------+--------------> |   m#0 = 0x2a   |       |
                                                   |                +----------------+       |
                                                   |                  |                      |
                                                   |                  |                      |
                                                   |                  v                      |
       +------------+     +----------------+       |                +----------------+       |
       |    17.     |     |      16.       |       |                |      14.       |       |
    +> | r#0 = 0x2a | <-- | if(i#0 == 0x0) | <-----+--------------- | if(g#0 == 0x0) | <-----+-----------------+
    |  +------------+     +----------------+       |                +----------------+       |                 |
    |    |                  |                      |                  |                      |                 |
    |    |                  |                      |                  |                      |                 |
    |    |                  |                      |                  v                      |                 |
    |    |                  |                      |                +----------------+       |                 |
    |    |                  |                      |                |      15.       |       |                 |
    +----+------------------+----------------------+--------------- | if(h#0 == 0x0) |       |                 |
         |                  |                      |                +----------------+       |                 |
         |                  |                      |                  |                      |                 |
         |                  |                      |                  |                      |                 |
         |                  |                      |                  v                      v                 |
         |                  |                      |                +---------------------------------------+  |
         |                  |                      |                |                  13.                  |  |
         |                  |                      +--------------> |              q#0 = 0x2a               |  |
         |                  |                                       +---------------------------------------+  |
         |                  |                                         ^                                        |
         |                  +-----------------------------------------+                                        |
         |                                                                                                     |
         |                                                                                                     |
         +-----------------------------------------------------------------------------------------------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Branch(Condition(OperationType.equal, [variable(name="a"), Constant(0)]))]),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.equal, [variable(name="b"), Constant(0)]))]),
            BasicBlock(2, instructions=[Assignment(variable(name="j"), Constant(42))]),
            BasicBlock(3, instructions=[Branch(Condition(OperationType.equal, [variable(name="c"), Constant(0)]))]),
            BasicBlock(4, instructions=[Assignment(variable(name="k"), Constant(42))]),
            BasicBlock(5, instructions=[Assignment(variable(name="l"), Constant(42))]),
            BasicBlock(6, instructions=[Assignment(variable(name="m"), Constant(42))]),
            BasicBlock(7, instructions=[Branch(Condition(OperationType.equal, [variable(name="d"), Constant(0)]))]),
            BasicBlock(8, instructions=[Assignment(variable(name="n"), Constant(42))]),
            BasicBlock(9, instructions=[Branch(Condition(OperationType.equal, [variable(name="e"), Constant(0)]))]),
            BasicBlock(10, instructions=[Assignment(variable(name="o"), Constant(42))]),
            BasicBlock(11, instructions=[Assignment(variable(name="p"), Constant(42))]),
            BasicBlock(12, instructions=[Branch(Condition(OperationType.equal, [variable(name="f"), Constant(0)]))]),
            BasicBlock(13, instructions=[Assignment(variable(name="q"), Constant(42))]),
            BasicBlock(14, instructions=[Branch(Condition(OperationType.equal, [variable(name="g"), Constant(0)]))]),
            BasicBlock(15, instructions=[Branch(Condition(OperationType.equal, [variable(name="h"), Constant(0)]))]),
            BasicBlock(16, instructions=[Branch(Condition(OperationType.equal, [variable(name="i"), Constant(0)]))]),
            BasicBlock(17, instructions=[Assignment(variable(name="r"), Constant(42))]),
        ]
    )
    task.graph.add_edges_from(
        [
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[0], vertices[7]),
            FalseCase(vertices[1], vertices[2]),
            TrueCase(vertices[1], vertices[3]),
            FalseCase(vertices[7], vertices[9]),
            TrueCase(vertices[7], vertices[8]),
            FalseCase(vertices[9], vertices[11]),
            TrueCase(vertices[9], vertices[10]),
            FalseCase(vertices[3], vertices[5]),
            TrueCase(vertices[3], vertices[4]),
            FalseCase(vertices[12], vertices[13]),
            TrueCase(vertices[12], vertices[7]),
            FalseCase(vertices[14], vertices[16]),
            TrueCase(vertices[14], vertices[15]),
            FalseCase(vertices[15], vertices[13]),
            TrueCase(vertices[15], vertices[17]),
            FalseCase(vertices[16], vertices[13]),
            TrueCase(vertices[16], vertices[17]),
            UnconditionalEdge(vertices[2], vertices[5]),
            UnconditionalEdge(vertices[4], vertices[6]),
            UnconditionalEdge(vertices[5], vertices[6]),
            UnconditionalEdge(vertices[6], vertices[14]),
            UnconditionalEdge(vertices[8], vertices[7]),
            UnconditionalEdge(vertices[10], vertices[13]),
            UnconditionalEdge(vertices[11], vertices[12]),
            UnconditionalEdge(vertices[17], vertices[14]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode)
    assert len(seq_node.children) == 2
    assert isinstance(seq_node.children[1], CodeNode)
    assert isinstance(cond_node := seq_node.children[0], ConditionNode)
    if cond_node.condition.is_negation:
        assert isinstance(region_one := cond_node.false_branch_child, DoWhileLoopNode)
        assert isinstance(region_two := cond_node.true_branch_child, SeqNode)
    else:
        assert isinstance(region_one := cond_node.true_branch_child, DoWhileLoopNode)
        assert isinstance(region_two := cond_node.false_branch_child, SeqNode)

    # Region 1
    assert isinstance(region_one.body, SeqNode)
    assert len(region_one.body.children) == 3
    assert isinstance(region_one_nested_loop := region_one.body.children[0], WhileLoopNode)
    assert isinstance(region_one_cond := region_one.body.children[1], ConditionNode)
    assert isinstance(region_one_cond.true_branch_child, CodeNode) and region_one_cond.false_branch is None
    assert isinstance(region_one.body.children[2], CodeNode)

    # Region 2
    assert len(region_two.children) == 4
    assert isinstance(region_two.children[0], ConditionNode)
    assert isinstance(region_two.children[0].true_branch_child, CodeNode) and region_two.children[0].false_branch is None
    assert isinstance(region_two.children[1], ConditionNode)
    assert isinstance(region_two.children[1].true_branch_child, CodeNode) and isinstance(
        region_two.children[1].false_branch_child, CodeNode
    )
    assert isinstance(region_two.children[2], CodeNode)
    assert isinstance(region_three := region_two.children[3], WhileLoopNode)

    # Region 3
    assert isinstance(region_three.body, CodeNode)


def test_condition_based_corner_case_complementary_condition_yes(task):
    """
      Nodes 3 & 4 can be restructured with complementary condition
       +-----------------+     +-----------------+
       |       4.        |     |       1.        |
    +> | b#0 = b#0 - a#0 | <-- |  if(a#0 < 0xa)  | <+
    |  +-----------------+     +-----------------+  |
    |    |                       |                  |
    |    |                       |                  |
    |    |                       v                  |
    |    |                     +-----------------+  |
    |    |                     |       2.        |  |
    +----+-------------------- |  if(b#0 < 0xa)  |  |
         |                     +-----------------+  |
         |                       |                  |
         |                       |                  |
         |                       v                  |
         |                     +-----------------+  |
         |                     |       3.        |  |
         |                     | b#0 = a#0 + b#0 |  |
         |                     +-----------------+  |
         |                       |                  |
         |                       |                  |
         |                       v                  |
         |                     +-----------------+  |
         |                     |       5.        |  |
         |                     | c#0 = a#0 + b#0 |  |
         +-------------------> | if(c#0 < 0x14)  | -+
                               +-----------------+
                                 |
                                 |
                                 v
                               +-----------------+
                               |       6.        |
                               |     return      |
                               +-----------------+
    """
    vertices = [
        BasicBlock(0),
        BasicBlock(1, instructions=[Branch(Condition(OperationType.less, [variable(name="a"), Constant(10)]))]),
        BasicBlock(2, instructions=[Branch(Condition(OperationType.less, [variable(name="b"), Constant(10)]))]),
        BasicBlock(
            3,
            instructions=[Assignment(variable(name="b"), BinaryOperation(OperationType.plus, [variable(name="a"), variable(name="b")]))],
        ),
        BasicBlock(
            4,
            instructions=[Assignment(variable(name="b"), BinaryOperation(OperationType.minus, [variable(name="b"), variable(name="a")]))],
        ),
        BasicBlock(
            5,
            instructions=[
                Assignment(variable(name="c"), BinaryOperation(OperationType.plus, [variable(name="a"), variable(name="b")])),
                Branch(Condition(OperationType.less, [variable(name="c"), Constant(20)])),
            ],
        ),
        BasicBlock(6, instructions=[Return([variable(name="c")])]),
    ]

    task.graph.add_nodes_from(vertices[1:])
    task.graph.add_edges_from(
        [
            FalseCase(vertices[1], vertices[4]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[2], vertices[4]),
            TrueCase(vertices[2], vertices[3]),
            UnconditionalEdge(vertices[3], vertices[5]),
            UnconditionalEdge(vertices[4], vertices[5]),
            TrueCase(vertices[5], vertices[1]),
            FalseCase(vertices[5], vertices[6]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make sure that a LoopNode has been created during Restructuring
    context = LogicCondition.generate_new_context()
    resulting_ast = AbstractSyntaxTree(
        seq_node := SeqNode(LogicCondition.initialize_true(context)),
        {
            LogicCondition.initialize_symbol("x1", context): Condition(OperationType.less, [variable(name="a"), Constant(10)]),
            LogicCondition.initialize_symbol("x2", context): Condition(OperationType.less, [variable(name="b"), Constant(10)]),
            LogicCondition.initialize_symbol("x3", context): Condition(OperationType.less, [variable(name="c"), Constant(20)]),
        },
    )
    resulting_ast._add_node(
        dowhile_loop := resulting_ast.factory.create_do_while_loop_node(LogicCondition.initialize_symbol("x3", context))
    )
    code_node_6 = resulting_ast._add_code_node([Return([variable(name="c")])])
    resulting_ast._add_node(loop_body := resulting_ast.factory.create_seq_node())
    true_branch = resulting_ast._add_code_node(
        [Assignment(variable("b"), BinaryOperation(OperationType.plus, [variable("a"), variable("b")]))]
    )
    false_branch = resulting_ast._add_code_node(
        [Assignment(variable("b"), BinaryOperation(OperationType.minus, [variable("b"), variable("a")]))]
    )
    condition_node = resulting_ast._add_condition_node_with(
        LogicCondition.initialize_symbol("x1", context) & LogicCondition.initialize_symbol("x2", context), true_branch, false_branch
    )
    code_node_5 = resulting_ast._add_code_node(
        [Assignment(variable("c"), BinaryOperation(OperationType.plus, [variable("a"), variable("b")]))]
    )

    resulting_ast._add_edges_from(
        (
            (seq_node, dowhile_loop),
            (seq_node, code_node_6),
            (dowhile_loop, loop_body),
            (loop_body, condition_node),
            (loop_body, code_node_5),
        )
    )
    resulting_ast._code_node_reachability_graph.add_reachability_from(
        (
            (true_branch, code_node_5),
            (true_branch, code_node_6),
            (false_branch, code_node_5),
            (false_branch, code_node_6),
            (code_node_5, code_node_6),
        )
    )
    seq_node.sort_children()
    loop_body.sort_children()

    assert ASTComparator.compare(task.syntax_tree, resulting_ast) and task.syntax_tree.condition_map == resulting_ast.condition_map


# TODO not possible until dealing with side effects of reaching conditions
# def test_condition_based_corner_case_complementary_condition_no(task):
#     """Nodes 4 can not be restructured with complementary condition"""
#     vertices = [
#         BasicBlock(0, instructions=[Assignment(variable(name="a"), BinaryOperation(OperationType.minus, [variable(name="a"), Constant(2)]))]),
#         BasicBlock(1, instructions=[Branch(Condition(OperationType.less, [variable(name="a"), Constant(10)]))]),
#         BasicBlock(2, instructions=[Branch(Condition(OperationType.less, [variable(name="b"), Constant(10)])),],),
#         BasicBlock(
#             3, instructions=[Assignment(variable(name="b"), BinaryOperation(OperationType.plus, [variable(name="a"), variable(name="b")]))],
#         ),
#         BasicBlock(
#             4,
#             instructions=[Assignment(variable(name="b"), BinaryOperation(OperationType.minus, [variable(name="b"), variable(name="a")]))],
#         ),
#         BasicBlock(
#             5,
#             instructions=[
#                 Assignment(variable(name="c"), BinaryOperation(OperationType.plus, [variable(name="a"), variable(name="b")])),
#                 Branch(Condition(OperationType.less, [variable(name="c"), Constant(20)])),
#             ],
#         ),
#         BasicBlock(6, instructions=[Return(variable(name="c"))]),
#     ]
#
#     task.graph.add_nodes_from(vertices[1:])
#     task.graph.add_edges_from(
#         [
#             FalseCase(vertices[1], vertices[0]),
#             UnconditionalEdge(vertices[0], vertices[4]),
#             TrueCase(vertices[1], vertices[2]),
#             FalseCase(vertices[2], vertices[4]),
#             TrueCase(vertices[2], vertices[3]),
#             UnconditionalEdge(vertices[3], vertices[5]),
#             UnconditionalEdge(vertices[4], vertices[5]),
#             TrueCase(vertices[5], vertices[1]),
#             FalseCase(vertices[5], vertices[6]),
#         ]
#     )
#     logging.info(DecoratedCFG.from_cfg(task.graph).export_ascii())
#     PatternIndependentRestructuring().run(task)

# make sure that a LoopNode has been created during Restructuring
# assert isinstance(seq_node := task._ast.root, SeqNode)
# assert len(seq_node.children) == 2
# assert isinstance(loop_node := seq_node.children[0], LoopNode)
# assert isinstance(seq_node.children[1], CodeNode) and seq_node.children[1].stmts == vertices[6].instructions

# make sure that the loop has the correct type and condition
# assert loop_node.type == "do_while"
# assert isinstance(cond := task._ast.condition_map[loop_node.condition], Condition) and cond == vertices[5].instructions[-1].condition
# assert isinstance(loop_body := loop_node.body, SeqNode)
# assert len(loop_body.children) == 2
# assert isinstance(complementary_cond := loop_body.children[0], ConditionNode)
# assert isinstance(loop_body.children[1], CodeNode) and loop_body.children[1].stmts == [vertices[5].instructions[0]]
#
# # complementary condition
# assert isinstance(complementary_cond.true_branch, CodeNode) and isinstance(complementary_cond.false_branch, CodeNode)
# assert len(complementary_cond.condition.operands) == 2
# assert is_or(complementary_cond.condition) or is_and(complementary_cond.condition)
# arg_1, arg_2 = complementary_cond.condition.operands
# if is_or(complementary_cond.condition):
#     assert isinstance(cond_1 := task._ast.condition_map[arg_1.operands[0]], Condition)
#     assert isinstance(cond_2 := task._ast.condition_map[arg_2.operands[0]], Condition)
#     assert complementary_cond.true_branch.stmts == vertices[4].instructions
#     assert complementary_cond.false_branch.stmts == vertices[3].instructions
# else:
#     assert isinstance(cond_1 := task._ast.condition_map[arg_1], Condition)
#     assert isinstance(cond_2 := task._ast.condition_map[arg_2], Condition)
#     assert complementary_cond.false_branch.stmts == vertices[4].instructions
#     assert complementary_cond.true_branch.stmts == vertices[3].instructions
# assert {cond_1, cond_2} == {vertices[1].instructions[0].condition, vertices[2].instructions[0].condition}

# logging.info(f"Abstract syntax tree of this region:")
# for node in task._ast.topological_order():
#     logging.info(f"Node {node}")
#     if isinstance(node, CodeNode):
#         logging.info(f"statements: {[str(inst) for inst in node.stmts]}")
#     elif isinstance(node, ConditionNode):
#         logging.info(f"condition {node.condition} and true {node.true_branch}, false {node.false_branch}")
#     elif isinstance(node, LoopNode):
#         logging.info(f"condition: {node.condition}, type: {node.type} and body {node.body}")
#     else:
#         logging.info(f"children {node.children}")
#
# print(CodeGenerator().from_task(task))


# TODO not possible until dealing with side effects of reaching conditions
# def test_condition_based_corner_case_complementary_condition_no(task):
#     """Node 5 can /cannot not be restructured with complementary condition"""
#     vertices = [
#         BasicBlock(0),
#         BasicBlock(1, instructions=[Branch(Condition(OperationType.less, [variable(name="a"), Constant(10)]))]),
#         BasicBlock(2, instructions=[Assignment(variable(name="a"), BinaryOperation(OperationType.minus, [variable(name="a"), Constant(2)]))]),
#         BasicBlock(
#             3,
#             instructions=[
#                 Assignment(variable(name="a"), BinaryOperation(OperationType.multiply, [Constant(2), variable(name="a")])),
#                 Branch(Condition(OperationType.less, [variable(name="b"), Constant(10)])),
#             ],
#         ),
#         BasicBlock(
#             4,
#             instructions=[
#                 Assignment(variable(name="b"), BinaryOperation(OperationType.plus, [variable(name="a"), variable(name="b")])),
#                 Branch(Condition(OperationType.less, [variable(name="c"), Constant(10)])),
#             ],
#         ),
#         BasicBlock(
#             5,
#             instructions=[
#                 Assignment(variable(name="b"), BinaryOperation(OperationType.minus, [variable(name="b"), variable(name="a")])),
#                 Branch(Condition(OperationType.less, [variable(name="d"), Constant(10)])),
#             ],
#         ),
#         BasicBlock(
#             6,
#             instructions=[
#                 Assignment(
#                     variable(name="d"),
#                     BinaryOperation(
#                         OperationType.plus,
#                         [
#                             BinaryOperation(OperationType.plus, [variable(name="a"), variable(name="b")]),
#                             BinaryOperation(OperationType.plus, [variable(name="c"), variable(name="d")]),
#                         ],
#                     ),
#                 )
#             ],
#         ),
#         BasicBlock(
#             7,
#             instructions=[
#                 Assignment(
#                     variable(name="d"),
#                     BinaryOperation(
#                         OperationType.minus,
#                         [variable(name="c"), BinaryOperation(OperationType.multiply, [Constant(2), variable(name="b")])],
#                     ),
#                 )
#             ],
#         ),
#         BasicBlock(
#             8, instructions=[Assignment(variable(name="d"), BinaryOperation(OperationType.minus, [variable(name="d"), variable(name="b")]))]
#         ),
#         BasicBlock(9, instructions=[Branch(Condition(OperationType.less, [variable(name="d"), Constant(5)]))]),
#         BasicBlock(10, instructions=[Return(variable(name="d"))]),
#     ]
#
#     task.graph.add_nodes_from(vertices[1:])
#     task.graph.add_edges_from(
#         [
#             FalseCase(vertices[1], vertices[2]),
#             TrueCase(vertices[1], vertices[3]),
#             UnconditionalEdge(vertices[2], vertices[5]),
#             FalseCase(vertices[3], vertices[5]),
#             TrueCase(vertices[3], vertices[4]),
#             TrueCase(vertices[4], vertices[6]),
#             FalseCase(vertices[4], vertices[7]),
#             TrueCase(vertices[5], vertices[6]),
#             FalseCase(vertices[5], vertices[8]),
#             UnconditionalEdge(vertices[6], vertices[9]),
#             UnconditionalEdge(vertices[7], vertices[9]),
#             UnconditionalEdge(vertices[8], vertices[9]),
#             TrueCase(vertices[9], vertices[1]),
#             FalseCase(vertices[9], vertices[10]),
#         ]
#     )
#     PatternIndependentRestructuring().run(task)
#
#     # logging.info(f"Abstract syntax tree of this region:")
#     # for node in task._ast.topological_order():
#     #     logging.info(f"Node {node}")
#     #     if isinstance(node, CodeNode):
#     #         logging.info(f"statements: {[str(inst) for inst in node.stmts]}")
#     #     elif isinstance(node, ConditionNode):
#     #         logging.info(f"condition {node.condition} and true {node.true_branch}, false {node.false_branch}")
#     #     elif isinstance(node, LoopNode):
#     #         logging.info(f"condition: {node.condition}, type: {node.type} and body {node.body}")
#     #     else:
#     #         logging.info(f"children {node.children}")
#     #
#     # print(CodeGenerator().from_task(task))
#

# TODO done after dealing with side effects, problem is the `is_conditional`
# def test_nested_conditions(task):
#     vertices = [
#         BasicBlock(0, [Assignment(variable("a"), Constant(2)), Branch(Condition(OperationType.equal, [variable("b"), Constant(0)])),]),
#         BasicBlock(1, [Assignment(variable("c"), Constant(2))]),
#         BasicBlock(2, [Assignment(variable("c"), Constant(5)), Branch(Condition(OperationType.equal, [variable("d"), Constant(0)])),]),
#         BasicBlock(3, [Assignment(variable("d"), Constant(10)), Branch(Condition(OperationType.equal, [variable("e"), Constant(0)])),]),
#         BasicBlock(4, [Assignment(variable("f"), Constant(-2))]),
#         BasicBlock(5, [Assignment(variable("f"), Constant(2))]),
#         BasicBlock(6, [Assignment(variable("g"), variable("f"))]),
#         BasicBlock(7, [Assignment(variable("f"), Constant(10))]),
#         BasicBlock(8, [Assignment(variable("e"), Constant(10))]),
#     ]
#
#     edges = [
#         TrueCase(vertices[0], vertices[1]),
#         FalseCase(vertices[0], vertices[2]),
#         UnconditionalEdge(vertices[1], vertices[3]),
#         TrueCase(vertices[2], vertices[3]),
#         FalseCase(vertices[2], vertices[7]),
#         TrueCase(vertices[3], vertices[4]),
#         FalseCase(vertices[3], vertices[5]),
#         UnconditionalEdge(vertices[4], vertices[6]),
#         UnconditionalEdge(vertices[5], vertices[6]),
#         UnconditionalEdge(vertices[6], vertices[8]),
#         UnconditionalEdge(vertices[7], vertices[8]),
#     ]
#     task.graph.add_nodes_from(vertices)
#     task.graph.add_edges_from(edges)
#     logging.info(DecoratedCFG.from_cfg(task.graph).export_ascii())
#
# PatternIndependentRestructuring().run(task)
#
# # root node
# assert isinstance(seq_node := task._ast.root, SeqNode)
# assert len(seq_node.children) == 4
# assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].stmts == [vertices[0].instructions[0]]
# assert isinstance(condition_root := seq_node.children[1], ConditionNode)
# assert isinstance(complementary_cond := seq_node.children[2], ConditionNode)
# assert isinstance(seq_node.children[3], CodeNode) and seq_node.children[3].stmts == vertices[8].instructions
#
# # make sure that the root note condition is restructured correctly
# if condition_root.condition.is_negation:
#     assert task._ast.condition_map[condition_root.condition.operands[0]] == vertices[0].instructions[-1].condition
#     assert isinstance(condition_root.true_branch, CodeNode) and condition_root.true_branch.stmts == [vertices[2].instructions[0]]
#     assert isinstance(condition_root.false_branch, CodeNode) and condition_root.false_branch.stmts == vertices[1].instructions
# else:
#     assert task._ast.condition_map[condition_root.condition] == vertices[0].instructions[-1].condition
#     assert isinstance(condition_root.false_branch, CodeNode) and condition_root.false_branch.stmts == [vertices[2].instructions[0]]
#     assert isinstance(condition_root.true_branch, CodeNode) and condition_root.true_branch.stmts == vertices[1].instructions
#
# # make sure the complementary condition branch is set correctly
# cond = complementary_cond.condition
# assert len(cond.operands) == 2 and (is_and(cond) or is_or(cond))
# if is_and(cond):
#     assert {task._ast.condition_map[cond.arg.operands[0](0)], task._ast.condition_map[cond.arg.operands[0](1)]} == {
#         vertices[0].instructions[-1].condition,
#         vertices[2].instructions[-1].condition,
#     }
#     assert isinstance(complementary_cond.true_branch, CodeNode) and complementary_cond.true_branch.stmts == vertices[7].instructions
#     assert isinstance(ifelse_node_3 := complementary_cond.false_branch, SeqNode)
# else:
#     assert {task._ast.condition_map[cond.operands[0]], task._ast.condition_map[cond.operands[1]]} == {
#         vertices[0].instructions[-1].condition,
#         vertices[2].instructions[-1].condition,
#     }
#     assert isinstance(complementary_cond.false_branch, CodeNode) and complementary_cond.false_branch.stmts == vertices[7].instructions
#     assert isinstance(ifelse_node_3 := complementary_cond.true_branch, SeqNode)
#
# # check if-else region with head 3:
# assert len(ifelse_node_3.children) == 3
# assert isinstance(ifelse_node_3.children[0], CodeNode) and ifelse_node_3.children[0].stmts == [vertices[3].instructions[0]]
# assert isinstance(ifelse_node_3_cond := ifelse_node_3.children[1], ConditionNode)
# assert isinstance(ifelse_node_3.children[2], CodeNode) and ifelse_node_3.children[2].stmts == vertices[6].instructions
#
# if ifelse_node_3_cond.condition.is_negation:
#     assert task._ast.condition_map[ifelse_node_3_cond.condition.operands[0]] == vertices[3].instructions[-1].condition
#     assert isinstance(ifelse_node_3_cond.true_branch, CodeNode) and ifelse_node_3_cond.true_branch.stmts == vertices[5].instructions
#     assert isinstance(ifelse_node_3_cond.false_branch, CodeNode) and ifelse_node_3_cond.false_branch.stmts == vertices[4].instructions
# else:
#     assert task._ast.condition_map[ifelse_node_3_cond.condition] == vertices[3].instructions[-1].condition
#     assert isinstance(ifelse_node_3_cond.false_branch, CodeNode) and ifelse_node_3_cond.false_branch.stmts == vertices[5].instructions
#     assert isinstance(ifelse_node_3_cond.true_branch, CodeNode) and ifelse_node_3_cond.true_branch.stmts == vertices[4].instructions


def test_easy_multiple_entry_loop(task):
    """
      Multiple Entry loop.
       +-----------------------+
       |          1.           |
       | scanf(0x804b01f, a#0) |
       |     if(a#0 < 0xa)     | -+
       +-----------------------+  |
         |                        |
         |                        |
         v                        |
       +-----------------------+  |
       |          2.           |  |
    +> |    a#0 = 0x2 * a#0    |  |
    |  +-----------------------+  |
    |    |                        |
    |    |                        |
    |    v                        |
    |  +-----------------------+  |
    |  |          3.           |  |
    |  |    b#0 = a#0 + b#0    |  |
    |  +-----------------------+  |
    |    |                        |
    |    |                        |
    |    v                        |
    |  +-----------------------+  |
    |  |          4.           |  |
    |  |    c#0 = a#0 + b#0    |  |
    +- |    if(c#0 < 0x14)     | <+
       +-----------------------+
         |
         |
         v
       +-----------------------+
       |          5.           |
       |        return         |
       +-----------------------+
    """
    vertices = [
        BasicBlock(0),
        BasicBlock(
            1,
            [
                Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804B01F), variable("a")])),
                Branch(Condition(OperationType.less, [variable("a"), Constant(10)])),
            ],
        ),
        BasicBlock(2, [Assignment(variable("a"), BinaryOperation(OperationType.multiply, [Constant(2), variable("a")]))]),
        BasicBlock(3, [Assignment(variable("b"), BinaryOperation(OperationType.plus, [variable("a"), variable("b")]))]),
        BasicBlock(
            4,
            [
                Assignment(variable("c"), BinaryOperation(OperationType.plus, [variable("a"), variable("b")])),
                Branch(Condition(OperationType.less, [variable("c"), Constant(20)])),
            ],
        ),
        BasicBlock(5, [Return([variable("c")])]),
    ]
    task.graph.add_nodes_from(vertices[1:])
    task.graph.add_edges_from(
        [
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[4]),
            UnconditionalEdge(vertices[2], vertices[3]),
            UnconditionalEdge(vertices[3], vertices[4]),
            TrueCase(vertices[4], vertices[2]),
            FalseCase(vertices[4], vertices[5]),
        ]
    )
    task.graph.root = vertices[1]
    PatternIndependentRestructuring().run(task)

    # make sure that a LoopNode has been created during Restructuring
    assert isinstance(seq_node := task._ast.root, SeqNode)
    assert len(seq_node.children) == 4
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[1].instructions[:-1]
    assert isinstance(cond_node := seq_node.children[1], ConditionNode)
    assert isinstance(loop := seq_node.children[2], DoWhileLoopNode)
    assert isinstance(seq_node.children[3], CodeNode) and seq_node.children[3].instructions == vertices[5].instructions

    # make sure that the condition is correct
    assert isinstance(cond_node.true_branch_child, CodeNode) and isinstance(cond_node.false_branch_child, CodeNode)
    new_variable = cond_node.true_branch_child.instructions[0].definitions[0]
    if cond_node.condition.is_negation:
        assert (
            isinstance(cond := task._ast.condition_map[~cond_node.condition], Condition) and cond == vertices[1].instructions[-1].condition
        )
        assert cond_node.true_branch_child.instructions == [Assignment(new_variable, Constant(1, Integer.int32_t()))]
        assert cond_node.false_branch_child.instructions == [Assignment(new_variable, Constant(0, Integer.int32_t()))]
    else:
        assert (
            isinstance(cond := task._ast.condition_map[cond_node.condition], Condition) and cond == vertices[1].instructions[-1].condition
        )
        assert cond_node.true_branch_child.instructions == [Assignment(new_variable, Constant(0, Integer.int32_t()))]
        assert cond_node.false_branch_child.instructions == [Assignment(new_variable, Constant(1, Integer.int32_t()))]

    # make sure that the loop is correct
    assert isinstance(loop_body := loop.body, SeqNode)
    assert isinstance(cond := task._ast.condition_map[loop.condition], Condition) and cond == vertices[4].instructions[-1].condition
    assert len(loop_body.children) == 2
    assert isinstance(multiple_entry_condition := loop_body.children[0], ConditionNode)
    assert isinstance(cond := task._ast.condition_map[multiple_entry_condition.condition], Condition)
    assert cond == Condition(OperationType.equal, [new_variable, Constant(0, Integer.int32_t())])
    assert isinstance(multiple_entry_condition.true_branch_child, CodeNode) and multiple_entry_condition.false_branch is None
    assert multiple_entry_condition.true_branch_child.instructions == vertices[2].instructions + vertices[3].instructions
    assert isinstance(loop_body.children[1], CodeNode)
    assert loop_body.children[1].instructions == [vertices[4].instructions[0], Assignment(new_variable, Constant(0, Integer.int32_t()))]


# TODO not possible until dealing with side effects of reaching conditions
# def test_multiple_entry_loop(task):
#     """Multiple Entry loop, 4 entries""
#     vertices = [
#         BasicBlock(
#             0,
#             [
#                 Assignment(ListOperation([]), Call("scanf", [Constant(0x804B01F), variable("a")])),
#                 Branch(Condition(OperationType.less, [variable("a"), Constant(10)])),
#             ],
#         ),
#         BasicBlock(
#             1,
#             [
#                 Assignment(variable("a"), BinaryOperation(OperationType.plus, [variable("a"), Constant(2)])),
#                 Branch(Condition(OperationType.less, [variable("a"), Constant(10)])),
#             ],
#         ),
#         BasicBlock(2, [Assignment(variable("b"), BinaryOperation(OperationType.multiply, [Constant(2), variable("a")]))],),
#         BasicBlock(3, [Assignment(variable("b"), BinaryOperation(OperationType.plus, [variable("a"), Constant(2)]))],),
#         BasicBlock(
#             4,
#             [
#                 Assignment(variable("b"), BinaryOperation(OperationType.plus, [variable("a"), Constant(1)])),
#                 Branch(Condition(OperationType.less, [variable("b"), Constant(10)])),
#             ],
#         ),
#         BasicBlock(
#             5,
#             [
#                 Assignment(variable("c"), BinaryOperation(OperationType.plus, [variable("a"), variable("b")])),
#                 Branch(Condition(OperationType.less, [variable("c"), Constant(10)])),
#             ],
#         ),
#         BasicBlock(
#             6,
#             [
#                 Assignment(variable("c"), BinaryOperation(OperationType.minus, [variable("b"), Constant(1)])),
#                 Branch(Condition(OperationType.less, [variable("c"), Constant(15)])),
#             ],
#         ),
#         BasicBlock(7, [Assignment(variable("c"), BinaryOperation(OperationType.multiply, [variable("a"), variable("c")]))],),
#         BasicBlock(8, [Assignment(variable("a"), BinaryOperation(OperationType.minus, [variable("c"), variable("a")]))],),
#         BasicBlock(9, [Assignment(variable("b"), BinaryOperation(OperationType.plus, [variable("b"), Constant(2)]))],),
#         BasicBlock(
#             10,
#             [
#                 Assignment(variable("c"), BinaryOperation(OperationType.plus, [variable("a"), variable("b")])),
#                 Branch(Condition(OperationType.less, [variable("c"), Constant(30)])),
#             ],
#         ),
#         BasicBlock(11, [Return(variable("c"))]),
#     ]
#     task.graph.add_nodes_from(vertices)
#     task.graph.add_edges_from(
#         [
#             TrueCase(vertices[0], vertices[1]),
#             FalseCase(vertices[0], vertices[4]),
#             TrueCase(vertices[1], vertices[3]),
#             FalseCase(vertices[1], vertices[2]),
#             UnconditionalEdge(vertices[2], vertices[7]),
#             UnconditionalEdge(vertices[3], vertices[7]),
#             TrueCase(vertices[4], vertices[5]),
#             FalseCase(vertices[4], vertices[6]),
#             TrueCase(vertices[5], vertices[7]),
#             FalseCase(vertices[5], vertices[8]),
#             TrueCase(vertices[6], vertices[9]),
#             FalseCase(vertices[6], vertices[10]),
#             UnconditionalEdge(vertices[7], vertices[8]),
#             UnconditionalEdge(vertices[8], vertices[9]),
#             UnconditionalEdge(vertices[9], vertices[10]),
#             TrueCase(vertices[10], vertices[7]),
#             FalseCase(vertices[10], vertices[11]),
#         ]
#     )
#
#     PatternIndependentRestructuring().run(task)
#
#     for node in task._ast.topological_order():
#         logging.info(f"Node {node}")
#         if isinstance(node, CodeNode):
#             logging.info(f"statements: {[str(inst) for inst in node.stmts]}")
#         elif isinstance(node, ConditionNode):
#             logging.info(f"condition {node.condition} and true {node.true_branch}, false {node.false_branch}")
#         elif isinstance(node, LoopNode):
#             logging.info(f"condition: {node.condition} and body {node.body}")
#         else:
#             logging.info(f"children {node.children}")
#
#     # Check sequence node children
#     assert isinstance(seq_node := task._ast.root, SeqNode)
#     assert len(seq_node.children) == 6
#     assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].stmts == [vertices[0].instructions[0]]
#     assert isinstance(cond_zero_node := seq_node.children[1], ConditionNode)
#     # assert isinstance(seq_node.children[2], )
#     # assert isinstance(seq_node.children[3], )
#     # assert isinstance(seq_node.children[4], )
#     assert isinstance(seq_node.children[5], CodeNode) and seq_node.children[5].stmts == vertices[11].instructions
#
#     # branches of cond_zero_node
#     if cond_zero_node.condition.is_negation:
#         assert task._ast.condition_map[cond_zero_node.condition.operands[0]] == vertices[0].instructions[-1].condition
#         assert isinstance(cond_zero_node.true_branch, CodeNode) and cond_zero_node.true_branch.stmts == [vertices[4].instructions[0]]
#         assert isinstance(ifelse_region := cond_zero_node.false_branch, SeqNode)
#     else:
#         assert task._ast.condition_map[cond_zero_node.condition] == vertices[0].instructions[-1].condition
#         assert isinstance(cond_zero_node.false_branch, CodeNode) and cond_zero_node.false_branch.stmts == [vertices[4].instructions[0]]
#         assert isinstance(ifelse_region := cond_zero_node.true_branch, SeqNode)
#     assert len(ifelse_region.children) == 2
#     assert isinstance(ifelse_region.children[0], CodeNode) and ifelse_region.children[0].stmts == [vertices[1].instructions[0]]
#     assert isinstance(cond_node_1 := ifelse_region.children[1], ConditionNode)
#
#     if cond_node_1.condition.is_negation:
#         assert task._ast.condition_map[cond_node_1.condition.operands[0]] == vertices[1].instructions[-1].condition
#         assert isinstance(cond_node_1.true_branch, CodeNode) and cond_node_1.true_branch.stmts == [vertices[2].instructions[0]]
#         assert isinstance(cond_node_1.false_branch, CodeNode) and cond_node_1.false_branch.stmts == [vertices[3].instructions[0]]
#     else:
#         assert task._ast.condition_map[cond_node_1.condition] == vertices[1].instructions[-1].condition
#         assert isinstance(cond_node_1.false_branch, CodeNode) and cond_node_1.false_branch.stmts == [vertices[2].instructions[0]]
#         assert isinstance(cond_node_1.true_branch, CodeNode) and cond_node_1.true_branch.stmts == [vertices[3].instructions[0]]
#
#     print(CodeGenerator().from_task(task))


# TODO not possible until dealing with side effects of reaching conditions
# def test_nested_loops_with_retreating(task):
#     """ Nested loop with retreating edge and back edge."""
#     vertices = [
#         BasicBlock(0, [Assignment(ListOperation([]), Call("scanf", [Constant(0x804B01F), variable("a")]))]),
#         BasicBlock(1, [Branch(Condition(OperationType.less, [variable("a"), Constant(10)]))],),
#         BasicBlock(
#             2,
#             [
#                 Assignment(variable("a"), BinaryOperation(OperationType.multiply, [Constant(2), variable("a")])),
#                 Branch(Condition(OperationType.less, [variable("b"), Constant(10)])),
#             ],
#         ),
#         BasicBlock(3, [Assignment(variable("b"), BinaryOperation(OperationType.plus, [variable("a"), Constant(2)]))]),
#         BasicBlock(
#             4,
#             [
#                 Assignment(variable("b"), BinaryOperation(OperationType.plus, [variable("a"), variable("b")])),
#                 Branch(Condition(OperationType.less, [variable("c"), Constant(10)])),
#             ],
#         ),
#         BasicBlock(
#             5,
#             [
#                 Assignment(variable("c"), BinaryOperation(OperationType.plus, [variable("a"), variable("b")])),
#                 Branch(Condition(OperationType.less, [variable("c"), Constant(20)])),
#             ],
#         ),
#         BasicBlock(6, [Return(variable("c"))]),
#     ]
#     task.graph.add_nodes_from(vertices[1:])
#     task.graph.add_edges_from(
#         [
#             UnconditionalEdge(vertices[0], vertices[1]),
#             TrueCase(vertices[1], vertices[2]),
#             FalseCase(vertices[1], vertices[5]),
#             TrueCase(vertices[2], vertices[3]),
#             FalseCase(vertices[2], vertices[4]),
#             UnconditionalEdge(vertices[3], vertices[2]),
#             FalseCase(vertices[4], vertices[1]),
#             TrueCase(vertices[4], vertices[5]),
#             TrueCase(vertices[5], vertices[2]),
#             FalseCase(vertices[5], vertices[6]),
#         ]
#     )
#
#     PatternIndependentRestructuring().run(task)
#
#     # make sure that a LoopNode has been created during Restructuring
#     assert isinstance(seq_node := task._ast.root, SeqNode)
#     assert len(seq_node.children) == 2
#     assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].stmts == vertices[0].instructions
#     assert isinstance(outer_loop := seq_node.children[1], LoopNode)
#
#     # make sure that outer loop, back edge (4,1), is correct
#     assert outer_loop.type == "endless"
#     assert isinstance(outer_loop_body := outer_loop.body, SeqNode)
#     assert len(outer_loop_body.children) == 2
#     assert isinstance(multiple_entry_cond := outer_loop_body.children[0], ConditionNode)
#     assert isinstance(multiple_entry_loop := outer_loop_body.children[1], LoopNode)
#
#     # make sure that multiple entry loop condition is correct
#     assert isinstance(multiple_entry_cond.true_branch, CodeNode) and isinstance(multiple_entry_cond.false_branch, CodeNode)
#     new_variable = multiple_entry_cond.true_branch.stmts[0].definitions[0]
#     if multiple_entry_cond.condition.is_negation:
#         assert isinstance(cond := task._ast.condition_map[multiple_entry_cond.condition.operands[0]], Condition)
#         assert cond == vertices[1].instructions[0].condition
#         assert multiple_entry_cond.true_branch.stmts == [Assignment(new_variable, Constant(1))]
#         assert multiple_entry_cond.false_branch.stmts == [Assignment(new_variable, Constant(0))]
#     else:
#         assert isinstance(cond := task._ast.condition_map[multiple_entry_cond.condition], Condition)
#         assert cond == vertices[1].instructions[0].condition
#         assert multiple_entry_cond.true_branch.stmts == [Assignment(new_variable, Constant(0))]
#         assert multiple_entry_cond.false_branch.stmts == [Assignment(new_variable, Constant(1))]
#
#     # make sure that the multiple_loop is correct
#     assert multiple_entry_loop.type == "endless" and isinstance(multiple_entry_loop_body := multiple_entry_loop.body, SeqNode)
#     assert len(multiple_entry_loop_body.children) == 3
#     assert isinstance(multiple_entry_condition := multiple_entry_loop_body.children[0], ConditionNode)
#     # assert isinstance(cond := task._ast.condition_map[multiple_entry_condition.condition], Condition)
#     # assert cond == Condition(OperationType.equal, [new_variable, Constant(0)])
#     # assert isinstance(multiple_entry_condition.true_branch, CodeNode) and multiple_entry_condition.false_branch is None
#     # assert multiple_entry_condition.true_branch.stmts == vertices[2].instructions + vertices[3].instructions
#     # assert isinstance(loop_body.children[1], CodeNode)
#     # assert loop_body.children[1].stmts == [vertices[4].instructions[0], Assignment(new_variable, Constant(0))]


# TODO is Done after handeling side effects.
# def test_multiple_entry_with_back_edge_from_back_edge_source(task):
#     """ Multiple entry loop and back edge, that starts at retreating edge source."""
#     vertices = [
#         BasicBlock(0, [Assignment(ListOperation([]), Call("scanf", [Constant(0x804B01F), variable("a")]))]),
#         BasicBlock(1, [Branch(Condition(OperationType.less, [variable("a"), Constant(10)]))],),
#         BasicBlock(
#             2,
#             [
#                 Assignment(variable("b"), BinaryOperation(OperationType.multiply, [Constant(2), variable("a")])),
#                 Branch(Condition(OperationType.less, [variable("b"), Constant(10)])),
#             ],
#         ),
#         BasicBlock(3, [Assignment(variable("a"), BinaryOperation(OperationType.plus, [variable("a"), variable("b")])),],),
#         BasicBlock(
#             4,
#             [
#                 Assignment(variable("c"), BinaryOperation(OperationType.plus, [variable("a"), variable("b")])),
#                 Branch(Condition(OperationType.less, [variable("c"), Constant(10)])),
#             ],
#         ),
#         BasicBlock(5, [Return(variable("b"))]),
#     ]
#     task.graph.add_nodes_from(vertices)
#     task.graph.add_edges_from(
#         [
#             UnconditionalEdge(vertices[0], vertices[1]),
#             TrueCase(vertices[1], vertices[2]),
#             FalseCase(vertices[1], vertices[4]),
#             FalseCase(vertices[2], vertices[5]),
#             TrueCase(vertices[2], vertices[3]),
#             UnconditionalEdge(vertices[3], vertices[4]),
#             FalseCase(vertices[4], vertices[1]),
#             TrueCase(vertices[4], vertices[2]),
#         ]
#     )
#
#     PatternIndependentRestructuring().run(task)

#     # make outer LoopNode created during Restructuring
#     assert isinstance(seq_node := task._ast.root, SeqNode)
#     assert len(seq_node.children) == 2
#     assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].stmts == vertices[0].instructions
#     assert isinstance(outer_loop := seq_node.children[1], LoopNode)
# #
#     # make sure that outer loop, back edge (4,1), is correct
#     assert outer_loop.type == "endless"
#     assert isinstance(outer_loop_body := outer_loop.body, SeqNode)
#     assert len(outer_loop_body.children) == 2
#     assert isinstance(multiple_entry_cond := outer_loop_body.children[0], ConditionNode)
#     assert isinstance(multiple_entry_loop := outer_loop_body.children[1], LoopNode)
#
#     # make sure that multiple entry loop condition is correct
#     assert isinstance(multiple_entry_cond.true_branch, CodeNode) and isinstance(multiple_entry_cond.false_branch, CodeNode)
#     new_variable = multiple_entry_cond.true_branch.stmts[0].definitions[0]
#     if multiple_entry_cond.condition.is_negation:
#         assert isinstance(cond := task._ast.condition_map[multiple_entry_cond.condition.operands[0]], Condition)
#         assert cond == vertices[1].instructions[0].condition
#         assert multiple_entry_cond.true_branch.stmts == [Assignment(new_variable, Constant(1))]
#         assert multiple_entry_cond.false_branch.stmts == [Assignment(new_variable, Constant(0))]
#     else:
#         assert isinstance(cond := task._ast.condition_map[multiple_entry_cond.condition], Condition)
#         assert cond == vertices[1].instructions[0].condition
#         assert multiple_entry_cond.true_branch.stmts == [Assignment(new_variable, Constant(0))]
#         assert multiple_entry_cond.false_branch.stmts == [Assignment(new_variable, Constant(1))]

#     # make sure that the multiple_loop is correct
#     assert multiple_entry_loop.type == "do_while" and isinstance(multiple_entry_loop_body := multiple_entry_loop.body, SeqNode)
#     assert is_or(cond := z3_to_dnf(multiple_entry_loop.condition))
#     assert (arg_1 := cond.operands[0]).is_symbol and is_and(arg_2 := cond.operands[1]) and len(arg_2.operands) == 2
#     assert task._ast.condition_map[arg_1] == vertices[4].instructions[-1].condition
#     assert {task._ast.condition_map[arg_2.operands[0]], task._ast.condition_map[arg_2.arg.operands[0](1)]} == {
#         Condition(OperationType.equal, [new_variable, Constant(0)]),
#         vertices[2].instructions[-1].condition,
#     }
#     assert len(multiple_entry_loop_body.children) == 2
#     assert isinstance(multiple_entry_condition := multiple_entry_loop_body.children[0], ConditionNode)
#     assert isinstance(cond := task._ast.condition_map[multiple_entry_condition.condition], Condition)
#     assert cond == Condition(OperationType.equal, [new_variable, Constant(0)])
#     assert isinstance(return_cond := multiple_entry_loop_body.children[1], ConditionNode)
#     assert len(return_cond.condition.operands) == 2
#     if is_or(return_cond.condition):
#         assert return_cond.true_branch.stmts == [vertices[4].instructions[0], Assignment(new_variable, Constant(0))]
#         assert return_cond.false_branch.stmts == vertices[5].instructions
#     else:
#         assert return_cond.false_branch.stmts == [vertices[4].instructions[0], Assignment(new_variable, Constant(0))]
#         assert return_cond.true_branch.stmts == vertices[5].instructions
#
#     # multiple_entry_condition
#     assert isinstance(multiple_entry_condition.true_branch, SeqNode) and multiple_entry_condition.false_branch is None
#     assert len(multiple_entry_condition.true_branch.children) == 2
#     assert multiple_entry_condition.true_branch.children[0].stmts == [vertices[2].instructions[0]]
#     assert isinstance(multiple_entry_condition.true_branch.children[1], ConditionNode)
#     assert task._ast.condition_map[multiple_entry_condition.true_branch.children[-1].condition] == vertices[2].instructions[-1].condition
#     assert multiple_entry_condition.true_branch.children[1].true_branch.stmts == vertices[3].instructions
#     assert multiple_entry_condition.true_branch.children[1].false_branch is None


def test_multiple_entry_with_outgoing_back_edge(task):
    """
        Multiple entry loop and back edge, that starts at retreating edge sink.
                        +-----------------------+
                        |          0.           |
                        | scanf(0x804b01f, a#0) |
                        +-----------------------+
                          |
                          |
                          v
                        +-----------------------+
                        |          1.           |
                     +> |     if(a#0 < 0xa)     | -+
                     |  +-----------------------+  |
                     |    |                        |
                     |    |                        |
                     |    v                        |
    +--------+       |  +-----------------------+  |
    |   5.   |       |  |          2.           |  |
    | return |       |  |    b#0 = 0x2 * a#0    |  |
    |        |  +----+> |     if(b#0 < 0xa)     | -+----+
    +--------+  |    |  +-----------------------+  |    |
      ^         |    |    |                        |    |
      |         |    |    |                        |    |
      |         |    |    v                        |    |
      |         |    |  +-----------------------+  |    |
      |         |    |  |          3.           |  |    |
      |         |    |  |    a#0 = a#0 + b#0    |  |    |
      |         |    +- |     if(c#0 < 0xa)     |  |    |
      |         |       +-----------------------+  |    |
      |         |         |                        |    |
      |         |         |                        |    |
      |         |         v                        |    |
      |         |       +-----------------------+  |    |
      |         |       |          4.           |  |    |
      |         +------ |    c#0 = a#0 + b#0    | <+    |
      |                 +-----------------------+       |
      |                                                 |
      +-------------------------------------------------+



    """
    vertices = [
        BasicBlock(0, [Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804B01F), variable("a")]))]),
        BasicBlock(1, [Branch(Condition(OperationType.less, [variable("a"), Constant(10)]))]),
        BasicBlock(
            2,
            [
                Assignment(variable("b"), BinaryOperation(OperationType.multiply, [Constant(2), variable("a")])),
                Branch(Condition(OperationType.less, [variable("b"), Constant(10)])),
            ],
        ),
        BasicBlock(
            3,
            [
                Assignment(variable("a"), BinaryOperation(OperationType.plus, [variable("a"), variable("b")])),
                Branch(Condition(OperationType.less, [variable("c"), Constant(10)])),
            ],
        ),
        BasicBlock(4, [Assignment(variable("c"), BinaryOperation(OperationType.plus, [variable("a"), variable("b")]))]),
        BasicBlock(5, [Return([variable("b")])]),
    ]
    task.graph.add_nodes_from(vertices)
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[4]),
            FalseCase(vertices[2], vertices[5]),
            TrueCase(vertices[2], vertices[3]),
            FalseCase(vertices[3], vertices[1]),
            TrueCase(vertices[3], vertices[4]),
            UnconditionalEdge(vertices[4], vertices[2]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # make outer LoopNode created during Restructuring
    assert isinstance(seq_node := task._ast.root, SeqNode)
    assert len(seq_node.children) == 2
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions
    assert isinstance(outer_loop := seq_node.children[1], WhileLoopNode)

    # make sure that outer loop, back edge (4,1), is correct
    assert outer_loop.is_endless_loop
    assert isinstance(outer_loop_body := outer_loop.body, SeqNode)
    assert len(outer_loop_body.children) == 2
    assert isinstance(multiple_entry_cond := outer_loop_body.children[0], ConditionNode)
    assert isinstance(multiple_entry_loop := outer_loop_body.children[1], LoopNode)

    # TODO update after fixing this Problem -> after extracting break, we could do a different if-else
    # # make sure that multiple entry loop condition is correct
    # assert isinstance(multiple_entry_cond.true_branch, CodeNode) and isinstance(multiple_entry_cond.false_branch, CodeNode)
    # new_variable = multiple_entry_cond.true_branch.stmts[0].definitions[0]
    # if multiple_entry_cond.condition.is_negation:
    #     assert isinstance(cond := task._ast.condition_map[multiple_entry_cond.condition.operands[0]], Condition)
    #     assert cond == vertices[1].instructions[0].condition
    #     assert multiple_entry_cond.true_branch.stmts == [Assignment(new_variable, Constant(1))]
    #     assert multiple_entry_cond.false_branch.stmts == [Assignment(new_variable, Constant(0))]
    # else:
    #     assert isinstance(cond := task._ast.condition_map[multiple_entry_cond.condition], Condition)
    #     assert cond == vertices[1].instructions[0].condition
    #     assert multiple_entry_cond.true_branch.stmts == [Assignment(new_variable, Constant(0))]
    #     assert multiple_entry_cond.false_branch.stmts == [Assignment(new_variable, Constant(1))]
    #
    # # make sure that the multiple_loop is correct
    # assert multiple_entry_loop.type == "endless" and isinstance(multiple_entry_loop_body := multiple_entry_loop.body, SeqNode)
    # assert len(multiple_entry_loop_body.children) == 2
    #
    # assert isinstance(multiple_entry_condition := multiple_entry_loop_body.children[0], ConditionNode)
    # assert isinstance(cond := task._ast.condition_map[multiple_entry_condition.condition], Condition)
    # assert cond == Condition(OperationType.equal, [new_variable, Constant(0)])
    # assert isinstance(multiple_entry_loop_body.children[1], CodeNode) and multiple_entry_loop_body.children[1].stmts == [
    #     vertices[4].instructions[0],
    #     Assignment(new_variable, Constant(0)),
    # ]
    #
    # # multiple_entry_condition
    # assert isinstance(multiple_entry_condition.true_branch, SeqNode) and multiple_entry_condition.false_branch is None
    # assert len(multiple_entry_condition.true_branch.children) == 4
    #
    # assert multiple_entry_condition.true_branch.children[0].stmts == [vertices[2].instructions[0]]
    #
    # assert isinstance(return_condition := multiple_entry_condition.true_branch.children[1], ConditionNode)
    # if (cond := return_condition.condition).is_symbol:
    #     assert task._ast.condition_map[cond] == vertices[2].instructions[-1].condition
    #     assert isinstance(return_condition.false_branch, CodeNode)
    #     assert return_condition.false_branch.stmts == vertices[5].instructions
    # else:
    #     assert task._ast.condition_map[cond.operands[0]] == vertices[2].instructions[-1].condition
    #     assert isinstance(return_condition.true_branch, CodeNode)
    #     assert return_condition.true_branch.stmts == vertices[5].instructions
    #
    # assert multiple_entry_condition.true_branch.children[2].stmts == [vertices[3].instructions[0]]
    #
    # assert isinstance(break_condition := multiple_entry_condition.true_branch.children[3], ConditionNode)
    # if is_and(cond := break_condition.condition):
    #     assert (
    #         isinstance(cond := task._ast.condition_map[break_condition.condition.operands[0]], Condition)
    #         and vertices[2].instructions[-1].condition
    #     )
    #     assert (
    #         isinstance(cond := task._ast.condition_map[break_condition.condition.operands[1].operands[0]], Condition)
    #         and vertices[3].instructions[-1].condition
    #     )
    #     assert isinstance(break_condition.true_branch, CodeNode)
    #     assert break_condition.true_branch.stmts == ["break"]
    # else:
    #     is_or(cond := break_condition.condition)
    #     assert (
    #         isinstance(cond := task._ast.condition_map[break_condition.condition.operands[0].operands[0]], Condition)
    #         and vertices[2].instructions[-1].condition
    #     )
    #     assert (
    #         isinstance(cond := task._ast.condition_map[break_condition.condition.operands[1]], Condition)
    #         and vertices[3].instructions[-1].condition
    #     )
    #     assert isinstance(break_condition.false_branch, CodeNode)
    #     assert break_condition.false_branch.stmts == ["break"]


def test_multiple_exit_1(task):
    """
      loop nodes: 0,1,2,3,4, and exits 9, 10, 11
                                      +----------------------------+
                                      |                            |
       +-----------------+            |  +-----------------+     +------------------+
       |       3.        |            |  |       2.        |     |        1.        |
       | x#0 = x#0 - i#0 |            |  | i#0 = i#0 + 0x1 |     |  if(i#0 != 0x3)  |
    +- | if(j#0 != 0x3)  | <----------+- | if(x#0 != 0x3)  | <-- |                  |
    |  +-----------------+            |  +-----------------+     +------------------+
    |    |                            |    |                       ^
    |    |                       +----+----+                       |
    |    |                       |    |                            |
    |    |                       |    |  +-----------------+     +------------------+     +------------------+
    |    |                       |    |  |       4.        |     |        0.        |     |        8.        |
    |    |                       |    |  |    j#0 = 0x0    |     |    i#0 = 0x0     |     |    x#0 = 0x2a    |
    +----+-----------------------+----+> |                 | --> |                  | <-- |  if(x#0 != 0x3)  |
         |                       |    |  +-----------------+     +------------------+     +------------------+
         |                       |    |                                                     |
         |                       |    |                                                     |
         |                       |    |                                                     v
         |                       |    |                          +------------------+     +------------------+
         |                       |    |                          |        9.        |     |        5.        |
         |                       |    +------------------------> | printf("exit 1") | --> | j#0 = j#0 - 0x1  |
         |                       |                               +------------------+     +------------------+
         |                       |                                                          |
         |                       |                                                          |
         |                       |                                                          v
         |                       |                               +------------------+     +------------------+
         |                       |                               |       10.        |     |        6.        |
         |                       +-----------------------------> | printf("exit 2") | --> | j#0 = j#0 + 0x1  |
         |                                                       +------------------+     +------------------+
         |                                                                                  |
         |                                                                                  |
         |                                                                                  v
         |                                                                                +------------------+
         |                                                                                |        7.        |
         |                                                                                |    return x#0    |
         |                                                                                +------------------+
         |                                                                                  ^
         |                                                                                  |
         |                                                                                  |
         |                                                                                +------------------+
         |                                                                                |       11.        |
         +------------------------------------------------------------------------------> | printf("exit 3") |
                                                                                          +------------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Assignment(variable(name="i"), Constant(0, Integer.int32_t()))]),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.not_equal, [variable(name="i"), Constant(3, Integer.int32_t())]))]),
            BasicBlock(
                2,
                instructions=[
                    Assignment(
                        variable(name="i"), BinaryOperation(OperationType.plus, [variable(name="i"), Constant(1, Integer.int32_t())])
                    ),
                    Branch(Condition(OperationType.not_equal, [variable(name="x"), Constant(3, Integer.int32_t())])),
                ],
            ),
            BasicBlock(
                3,
                instructions=[
                    Assignment(variable(name="x"), BinaryOperation(OperationType.minus, [variable(name="x"), variable(name="i")])),
                    Branch(Condition(OperationType.not_equal, [variable(name="j"), Constant(3, Integer.int32_t())])),
                ],
            ),
            BasicBlock(4, instructions=[Assignment(variable(name="j"), Constant(0, Integer.int32_t()))]),
            BasicBlock(
                5,
                instructions=[
                    Assignment(
                        variable(name="j"), BinaryOperation(OperationType.minus, [variable(name="j"), Constant(1, Integer.int32_t())])
                    )
                ],
            ),
            BasicBlock(
                6,
                instructions=[
                    Assignment(
                        variable(name="j"), BinaryOperation(OperationType.plus, [variable(name="j"), Constant(1, Integer.int32_t())])
                    ),
                ],
            ),
            BasicBlock(7, instructions=[Return([variable(name="x")])]),
            BasicBlock(
                8,
                instructions=[
                    Assignment(variable(name="x"), Constant(42)),
                    Branch(Condition(OperationType.not_equal, [variable(name="x"), Constant(3, Integer.int32_t())])),
                ],
            ),
            BasicBlock(9, instructions=[Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("exit 1")]))]),
            BasicBlock(10, instructions=[Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("exit 2")]))]),
            BasicBlock(11, instructions=[Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("exit 3")]))]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[8], vertices[0]),
            FalseCase(vertices[8], vertices[5]),
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[9]),
            UnconditionalEdge(vertices[9], vertices[5]),
            TrueCase(vertices[2], vertices[3]),
            FalseCase(vertices[2], vertices[10]),
            UnconditionalEdge(vertices[10], vertices[6]),
            TrueCase(vertices[3], vertices[4]),
            FalseCase(vertices[3], vertices[11]),
            UnconditionalEdge(vertices[11], vertices[7]),
            UnconditionalEdge(vertices[5], vertices[6]),
            UnconditionalEdge(vertices[6], vertices[7]),
            UnconditionalEdge(vertices[4], vertices[0]),
        ]
    )
    task.graph.root = vertices[8]

    PatternIndependentRestructuring().run(task)

    # outer branch is restructured correctly:
    assert isinstance(seq_node := task._ast.root, SeqNode)
    assert len(seq_node.children) == 5
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[8].instructions[:-1]
    assert isinstance(enter_loop := seq_node.children[1], ConditionNode)
    assert isinstance(succ_1 := seq_node.children[2], ConditionNode)
    assert isinstance(succ_2 := seq_node.children[3], ConditionNode)
    assert isinstance(seq_node.children[4], CodeNode) and seq_node.children[4].instructions == vertices[7].instructions

    # make sure that loop entered correctly:
    assert (cond := enter_loop.condition).is_symbol
    assert task._ast.condition_map[cond] == vertices[8].instructions[-1].condition
    assert isinstance(loop := enter_loop.true_branch_child, WhileLoopNode) and enter_loop.false_branch is None

    # make sure that loop is correct
    assert loop.is_endless_loop
    assert isinstance(loop_body := loop.body, SeqNode)

    # make sure that multiple exit loop is correct
    assert len(loop_body.children) == 7
    assert isinstance(loop_body.children[0], CodeNode) and loop_body.children[0].instructions == vertices[0].instructions
    assert isinstance(exit_1 := loop_body.children[1], ConditionNode)
    assert isinstance(loop_body.children[2], CodeNode) and loop_body.children[2].instructions == vertices[2].instructions[:-1]
    assert isinstance(exit_2 := loop_body.children[3], ConditionNode)
    assert isinstance(loop_body.children[4], CodeNode) and loop_body.children[4].instructions == vertices[3].instructions[:-1]
    assert isinstance(exit_3 := loop_body.children[5], ConditionNode)
    assert isinstance(loop_body.children[6], CodeNode) and loop_body.children[6].instructions == vertices[4].instructions

    # exit 1
    assert (cond := exit_1.condition).is_negation
    assert task._ast.condition_map[~cond] == vertices[1].instructions[-1].condition
    assert isinstance(branch := exit_1.true_branch_child, CodeNode) and exit_1.false_branch is None
    new_variable = branch.instructions[-2].definitions[0]
    assert branch.instructions == [vertices[9].instructions[0], Assignment(new_variable, Constant(0, Integer.int32_t())), Break()]

    # exit 2
    assert (cond := exit_2.condition).is_negation
    assert task._ast.condition_map[~cond] == vertices[2].instructions[-1].condition
    assert isinstance(branch := exit_2.true_branch_child, CodeNode) and exit_2.false_branch is None
    assert branch.instructions == [vertices[10].instructions[0], Assignment(new_variable, Constant(1, Integer.int32_t())), Break()]

    # exit 3
    assert (cond := exit_3.condition).is_negation
    assert task._ast.condition_map[~cond] == vertices[3].instructions[-1].condition
    assert isinstance(branch := exit_3.true_branch_child, CodeNode) and exit_3.false_branch is None
    assert branch.instructions == [vertices[11].instructions[0], Assignment(new_variable, Constant(2, Integer.int32_t())), Break()]

    # successor 1:
    assert (cond := succ_1.condition).is_disjunction
    assert len(arguments := cond.operands) == 2
    assert any((arg := argument).is_symbol for argument in arguments) and any((neg_arg := argument).is_negation for argument in arguments)
    assert task._ast.condition_map[arg] == Condition(OperationType.equal, [new_variable, Constant(0, Integer.int32_t())])
    assert task._ast.condition_map[~neg_arg] == vertices[8].instructions[-1].condition
    assert isinstance(branch := succ_1.true_branch_child, CodeNode) and succ_1.false_branch is None
    assert branch.instructions == vertices[5].instructions

    # successor 2:
    assert (cond := succ_2.condition).is_disjunction
    assert len(arguments := cond.operands) == 3
    assert any((neg_arg := argument).is_negation for argument in arguments)
    assert task._ast.condition_map[~neg_arg] == vertices[8].instructions[-1].condition
    assert {task._ast.condition_map[arg] for arg in arguments if arg.is_symbol} == {
        Condition(OperationType.equal, [new_variable, Constant(0, Integer.int32_t())]),
        Condition(OperationType.equal, [new_variable, Constant(1, Integer.int32_t())]),
    }
    assert isinstance(branch := succ_2.true_branch_child, CodeNode) and succ_2.false_branch is None
    assert branch.instructions == vertices[6].instructions


def test_multiple_exit_2(task):
    """
      loop nodes: 0,1,2,3,4, and exits 5,6,7, order of loop nodes same as order of exit nodes.
         +-------------------------------------------------------------+
         |                                                             |
       +-----------------+     +-----------+     +------------------+  |
       |       1.        |     |    0.     |     |        8.        |  |
       | if(i#0 != 0x3)  |     | i#0 = 0x0 |     |    x#0 = 0x2a    |  |
       |                 | <-- |           | <-- |  if(x#0 != 0x3)  |  |
       +-----------------+     +-----------+     +------------------+  |
         |                       ^                 |                   |
         |                       |                 |                   |
         v                       |                 v                   |
       +-----------------+     +-----------+     +------------------+  |
       |       2.        |     |    4.     |     |        5.        |  |
       | i#0 = i#0 + 0x1 |     | j#0 = 0x0 |     | j#0 = j#0 - 0x1  |  |
       | if(x#0 != 0x3)  | -+  |           |     | printf("exit 1") | <+
       +-----------------+  |  +-----------+     +------------------+
         |                  |    ^                 |
         |                  |    |                 |
         v                  |    |                 v
       +-----------------+  |    |               +------------------+
       |       3.        |  |    |               |        6.        |
       | x#0 = x#0 - i#0 |  |    |               | j#0 = j#0 + 0x1  |
    +- | if(j#0 != 0x3)  |  +----+-------------> | printf("exit 2") |
    |  +-----------------+       |               +------------------+
    |    |                       |                 |
    |    +-----------------------+                 |
    |                                              v
    |                                            +------------------+
    |                                            |        7.        |
    |                                            | printf("exit 3") |
    +------------------------------------------> |    return x#0    |
                                                 +------------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Assignment(variable(name="i"), Constant(0))]),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.not_equal, [variable(name="i"), Constant(3)]))]),
            BasicBlock(
                2,
                instructions=[
                    Assignment(variable(name="i"), BinaryOperation(OperationType.plus, [variable(name="i"), Constant(1)])),
                    Branch(Condition(OperationType.not_equal, [variable(name="x"), Constant(3)])),
                ],
            ),
            BasicBlock(
                3,
                instructions=[
                    Assignment(variable(name="x"), BinaryOperation(OperationType.minus, [variable(name="x"), variable(name="i")])),
                    Branch(Condition(OperationType.not_equal, [variable(name="j"), Constant(3)])),
                ],
            ),
            BasicBlock(4, instructions=[Assignment(variable(name="j"), Constant(0))]),
            BasicBlock(
                5,
                instructions=[
                    Assignment(variable(name="j"), BinaryOperation(OperationType.minus, [variable(name="j"), Constant(1)])),
                    Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("exit 1")])),
                ],
            ),
            BasicBlock(
                6,
                instructions=[
                    Assignment(variable(name="j"), BinaryOperation(OperationType.plus, [variable(name="j"), Constant(1)])),
                    Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("exit 2")])),
                ],
            ),
            BasicBlock(
                7,
                instructions=[
                    Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("exit 3")])),
                    Return([variable(name="x")]),
                ],
            ),
            BasicBlock(
                8,
                instructions=[
                    Assignment(variable(name="x"), Constant(42)),
                    Branch(Condition(OperationType.not_equal, [variable(name="x"), Constant(3)])),
                ],
            ),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[8], vertices[0]),
            FalseCase(vertices[8], vertices[5]),
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[5]),
            TrueCase(vertices[2], vertices[3]),
            FalseCase(vertices[2], vertices[6]),
            TrueCase(vertices[3], vertices[4]),
            FalseCase(vertices[3], vertices[7]),
            UnconditionalEdge(vertices[5], vertices[6]),
            UnconditionalEdge(vertices[6], vertices[7]),
            UnconditionalEdge(vertices[4], vertices[0]),
        ]
    )
    task.graph.root = vertices[8]
    PatternIndependentRestructuring().run(task)

    # outer branch is restructured correctly:
    assert isinstance(seq_node := task._ast.root, SeqNode)
    assert len(seq_node.children) == 5
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[8].instructions[:-1]
    assert isinstance(enter_loop := seq_node.children[1], ConditionNode)
    assert isinstance(succ_1 := seq_node.children[2], ConditionNode)
    assert isinstance(succ_2 := seq_node.children[3], ConditionNode)
    assert isinstance(seq_node.children[4], CodeNode) and seq_node.children[4].instructions == vertices[7].instructions

    # make sure that loop entered correctly:
    assert (cond := enter_loop.condition).is_symbol
    assert task._ast.condition_map[cond] == vertices[8].instructions[-1].condition
    assert isinstance(loop := enter_loop.true_branch_child, WhileLoopNode) and enter_loop.false_branch is None

    # make sure that loop is correct
    assert loop.is_endless_loop
    assert isinstance(loop_body := loop.body, SeqNode)

    # make sure that multiple exit loop is correct
    assert len(loop_body.children) == 7
    assert isinstance(loop_body.children[0], CodeNode) and loop_body.children[0].instructions == vertices[0].instructions
    assert isinstance(exit_1 := loop_body.children[1], ConditionNode)
    assert isinstance(loop_body.children[2], CodeNode) and loop_body.children[2].instructions == [vertices[2].instructions[0]]
    assert isinstance(exit_2 := loop_body.children[3], ConditionNode)
    assert isinstance(loop_body.children[4], CodeNode) and loop_body.children[4].instructions == [vertices[3].instructions[0]]
    assert isinstance(exit_3 := loop_body.children[5], ConditionNode)
    assert isinstance(loop_body.children[6], CodeNode) and loop_body.children[6].instructions == vertices[4].instructions

    # exit 1
    assert (cond := exit_1.condition).is_negation
    assert task._ast.condition_map[~cond] == vertices[1].instructions[-1].condition
    assert isinstance(branch := exit_1.true_branch_child, CodeNode) and exit_1.false_branch is None
    new_variable = branch.instructions[0].definitions[0]
    assert branch.instructions == [Assignment(new_variable, Constant(0, Integer.int32_t())), Break()]

    # exit 2
    assert (cond := exit_2.condition).is_negation
    assert task._ast.condition_map[~cond] == vertices[2].instructions[-1].condition
    assert isinstance(branch := exit_2.true_branch_child, CodeNode) and exit_2.false_branch is None
    assert branch.instructions == [Assignment(new_variable, Constant(1, Integer.int32_t())), Break()]

    # exit 3
    assert (cond := exit_3.condition).is_negation
    assert task._ast.condition_map[~cond] == vertices[3].instructions[-1].condition
    assert isinstance(branch := exit_3.true_branch_child, CodeNode) and exit_3.false_branch is None
    assert branch.instructions == [Assignment(new_variable, Constant(2, Integer.int32_t())), Break()]

    # successor 1:
    assert (cond := succ_1.condition).is_disjunction
    assert len(arguments := cond.operands) == 2
    assert any((arg := argument).is_symbol for argument in arguments) and any((neg_arg := argument).is_negation for argument in arguments)
    assert task._ast.condition_map[arg] == Condition(OperationType.equal, [new_variable, Constant(0, Integer.int32_t())])
    assert task._ast.condition_map[~neg_arg] == vertices[8].instructions[-1].condition
    assert isinstance(branch := succ_1.true_branch_child, CodeNode) and succ_1.false_branch is None
    assert branch.instructions == vertices[5].instructions

    # successor 2:
    assert (cond := succ_2.condition).is_disjunction
    assert len(arguments := cond.operands) == 3
    assert any((neg_arg := argument).is_negation for argument in arguments)
    assert task._ast.condition_map[~neg_arg] == vertices[8].instructions[-1].condition
    assert {task._ast.condition_map[arg] for arg in arguments if arg.is_symbol} == {
        Condition(OperationType.equal, [new_variable, Constant(0, Integer.int32_t())]),
        Condition(OperationType.equal, [new_variable, Constant(1, Integer.int32_t())]),
    }
    assert isinstance(branch := succ_2.true_branch_child, CodeNode) and succ_2.false_branch is None
    assert branch.instructions == vertices[6].instructions


def test_multiple_exit_3(task):
    """
      loop nodes: 0,1,2,3,4, and exits 5,6,7, order of loop nodes different as order of exit nodes.
                                 +-----------------------------------------------------------------------+
                                 |                                                                       |
                                 |       +-----------------+     +-----------+     +------------------+  |
                                 |       |       1.        |     |    0.     |     |        8.        |  |
                                 |       | if(i#0 != 0x3)  |     | i#0 = 0x0 |     |    x#0 = 0x2a    |  |
                                 |    +- |                 | <-- |           | <-- |  if(x#0 != 0x3)  |  |
                                 |    |  +-----------------+     +-----------+     +------------------+  |
                                 |    |    |                       ^                 |                   |
                                 |    |    |                       |                 |                   |
                                 |    |    v                       |                 v                   |
       +-----------------+       |    |  +-----------------+     +-----------+     +------------------+  |
       |       3.        |       |    |  |       2.        |     |    4.     |     |        5.        |  |
       | x#0 = x#0 - i#0 |       |    |  | i#0 = i#0 + 0x1 |     | j#0 = 0x0 |     | j#0 = j#0 - 0x1  |  |
    +- | if(j#0 != 0x3)  | ------+    |  | if(x#0 != 0x3)  | -+  |           |     | printf("exit 1") | <+
    |  +-----------------+            |  +-----------------+  |  +-----------+     +------------------+
    |    ^                            |    |                  |    ^                 |
    |    +----------------------------+----+                  |    |                 |
    |                                 |                       |    |                 v
    |                                 |                       |    |               +------------------+
    |                                 |                       |    |               |        6.        |
    |                                 |                       |    |               | j#0 = j#0 + 0x1  |
    |                                 |                       +----+-------------> | printf("exit 2") |
    |                                 |                            |               +------------------+
    |                                 |                            |                 |
    |                                 |                            |                 |
    |                                 |                            |                 v
    |                                 |                            |               +------------------+
    |                                 |                            |               |        7.        |
    |                                 |                            |               | printf("exit 3") |
    |                                 +----------------------------+-------------> |    return x#0    |
    |                                                              |               +------------------+
    |                                                              |
    +--------------------------------------------------------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Assignment(variable(name="i"), Constant(0, Integer.int32_t()))]),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.not_equal, [variable(name="i"), Constant(3, Integer.int32_t())]))]),
            BasicBlock(
                2,
                instructions=[
                    Assignment(
                        variable(name="i"), BinaryOperation(OperationType.plus, [variable(name="i"), Constant(1, Integer.int32_t())])
                    ),
                    Branch(Condition(OperationType.not_equal, [variable(name="x"), Constant(3, Integer.int32_t())])),
                ],
            ),
            BasicBlock(
                3,
                instructions=[
                    Assignment(variable(name="x"), BinaryOperation(OperationType.minus, [variable(name="x"), variable(name="i")])),
                    Branch(Condition(OperationType.not_equal, [variable(name="j"), Constant(3, Integer.int32_t())])),
                ],
            ),
            BasicBlock(4, instructions=[Assignment(variable(name="j"), Constant(0, Integer.int32_t()))]),
            BasicBlock(
                5,
                instructions=[
                    Assignment(
                        variable(name="j"), BinaryOperation(OperationType.minus, [variable(name="j"), Constant(1, Integer.int32_t())])
                    ),
                    Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("exit 1")])),
                ],
            ),
            BasicBlock(
                6,
                instructions=[
                    Assignment(
                        variable(name="j"), BinaryOperation(OperationType.plus, [variable(name="j"), Constant(1, Integer.int32_t())])
                    ),
                    Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("exit 2")])),
                ],
            ),
            BasicBlock(
                7,
                instructions=[
                    Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("exit 3")])),
                    Return([variable(name="x")]),
                ],
            ),
            BasicBlock(
                8,
                instructions=[
                    Assignment(variable(name="x"), Constant(42)),
                    Branch(Condition(OperationType.not_equal, [variable(name="x"), Constant(3, Integer.int32_t())])),
                ],
            ),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[8], vertices[0]),
            FalseCase(vertices[8], vertices[5]),
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[7]),
            TrueCase(vertices[2], vertices[3]),
            FalseCase(vertices[2], vertices[6]),
            TrueCase(vertices[3], vertices[4]),
            FalseCase(vertices[3], vertices[5]),
            UnconditionalEdge(vertices[5], vertices[6]),
            UnconditionalEdge(vertices[6], vertices[7]),
            UnconditionalEdge(vertices[4], vertices[0]),
        ]
    )
    task.graph.root = vertices[8]
    PatternIndependentRestructuring().run(task)

    # outer branch is restructured correctly:
    assert isinstance(seq_node := task._ast.root, SeqNode)
    assert len(seq_node.children) == 4
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[8].instructions[:-1]
    assert isinstance(enter_loop := seq_node.children[1], ConditionNode)
    assert isinstance(succ := seq_node.children[2], ConditionNode)
    assert isinstance(seq_node.children[3], CodeNode) and seq_node.children[3].instructions == vertices[7].instructions

    # make sure that loop entered correctly:
    assert (cond := enter_loop.condition).is_symbol
    assert task._ast.condition_map[cond] == vertices[8].instructions[-1].condition
    assert isinstance(loop := enter_loop.true_branch_child, WhileLoopNode) and enter_loop.false_branch is None

    # make sure that loop is correct
    assert loop.is_endless_loop
    assert isinstance(loop_body := loop.body, SeqNode)

    # make sure that multiple exit loop is correct
    assert len(loop_body.children) == 7
    assert isinstance(loop_body.children[0], CodeNode) and loop_body.children[0].instructions == vertices[0].instructions
    assert isinstance(exit_1 := loop_body.children[1], ConditionNode)
    assert isinstance(loop_body.children[2], CodeNode) and loop_body.children[2].instructions == [vertices[2].instructions[0]]
    assert isinstance(exit_2 := loop_body.children[3], ConditionNode)
    assert isinstance(loop_body.children[4], CodeNode) and loop_body.children[4].instructions == [vertices[3].instructions[0]]
    assert isinstance(exit_3 := loop_body.children[5], ConditionNode)
    assert isinstance(loop_body.children[6], CodeNode) and loop_body.children[6].instructions == vertices[4].instructions

    # exit 1
    assert (cond := exit_1.condition).is_negation
    assert task._ast.condition_map[~cond] == vertices[1].instructions[-1].condition
    assert isinstance(branch := exit_1.true_branch_child, CodeNode) and exit_1.false_branch is None
    new_variable = branch.instructions[0].definitions[0]
    assert branch.instructions == [Assignment(new_variable, Constant(0, Integer.int32_t())), Break()]

    # exit 2
    assert (cond := exit_2.condition).is_negation
    assert task._ast.condition_map[~cond] == vertices[2].instructions[-1].condition
    assert isinstance(branch := exit_2.true_branch_child, CodeNode) and exit_2.false_branch is None
    assert branch.instructions == [Assignment(new_variable, Constant(1, Integer.int32_t())), Break()]

    # exit 3
    assert (cond := exit_3.condition).is_negation
    assert task._ast.condition_map[~cond] == vertices[3].instructions[-1].condition
    assert isinstance(branch := exit_3.true_branch_child, CodeNode) and exit_3.false_branch is None
    assert branch.instructions == [Assignment(new_variable, Constant(2, Integer.int32_t())), Break()]

    # successor:
    assert succ.false_branch is None
    branch = succ.true_branch_child
    succ_cond = succ.condition
    assert succ_cond.is_disjunction and len(arguments := succ_cond.operands) == 2
    assert (
        arguments[0].is_negation
        and arguments[1].is_negation
        and len(arg_0 := arguments[0].operands) == 1
        and len(arg_1 := arguments[1].operands) == 1
    )
    assert (cond1 := arg_0[0]).is_symbol and (cond2 := arg_1[0]).is_symbol
    assert {task._ast.condition_map[cond1], task._ast.condition_map[cond2]} == {
        Condition(OperationType.equal, [new_variable, Constant(0, Integer.int32_t())]),
        vertices[8].instructions[-1].condition,
    }
    assert isinstance(branch, SeqNode) and len(branch.children) == 2
    assert isinstance(succ_1 := branch.children[0], ConditionNode) and isinstance(succ_2 := branch.children[1], CodeNode)

    # successor for exit 1:
    assert succ_1.false_branch is None
    branch_exit_1 = succ_1.true_branch_child
    succ_cond = succ_1.condition
    assert succ_cond.is_disjunction and len(arguments := succ_cond.operands) == 2
    assert (
        arguments[0].is_negation
        and arguments[1].is_negation
        and len(arg_0 := arguments[0].operands) == 1
        and len(arg_1 := arguments[1].operands) == 1
    )
    assert (cond1 := arg_0[0]).is_symbol and (cond2 := arg_1[0]).is_symbol
    assert {task._ast.condition_map[cond1], task._ast.condition_map[cond2]} == {
        Condition(OperationType.equal, [new_variable, Constant(1, Integer.int32_t())]),
        vertices[8].instructions[-1].condition,
    }
    assert branch_exit_1.instructions == vertices[5].instructions

    # successor for exit 2:
    assert succ_2.instructions == vertices[6].instructions


def test_multiple_exit_4(task):
    """
      loop nodes: 1,2,3,4,5 + 6 after refinement and exits 7,8,9, node 6 has two successors.
                                           +------------------------------------------------------------------------------+
                                           |                                                                              |
                                           |                                                                              |
    +---------+                       +----+-----------------------+                                                      |
    |         |                       |    |                       |                                                      |
    |       +-----------------+       |  +-----------------+     +-----------------+                                      |
    |       |       4.        |       |  |       3.        |     |       2.        |                                      |
    |       | c#0 = 0x5 * b#0 |       |  | c#0 = a#0 + b#0 |     | b#0 = a#0 + 0x5 |                                      |
    |    +- | if(c#0 < 0x14)  |       |  | if(c#0 < 0x14)  | <-- | if(b#0 < 0x14)  |                                      |
    |    |  +-----------------+       |  +-----------------+     +-----------------+                                      |
    |    |    ^                       |    |                       ^                                                      |
    |    |    +-----------------------+----+                       |                                                      |
    |    |                            |                            |                                                      |
    |    |                            |  +-----------------+     +-----------------+     +-----------------------------+  |
    |    |                            |  |                 |     |                 |     |             0.              |  |
    |    |                            |  |       5.        |     |       1.        |     |    scanf(0x804b01f, a#0)    |  |
    |    |                            |  |    a#0 = c#0    |     | a#0 = a#0 * 0x2 |     |          c#0 = 0x0          |  |
    |    |                            |  |                 | --> |                 | <-- |        if(a#0 < 0xa)        |  |
    |    |                            |  +-----------------+     +-----------------+     +-----------------------------+  |
    |    |                            |    ^                                               |                              |
    |    |                            |    |                                               |                              |
    |    |                            |    |                                               v                              |
    |    |                            |    |                     +-----------------+     +-----------------------------+  |
    |    |                            |    |                     |       6.        |     |             7.              |  |
    |    |                            |    |                     |    c#0 = b#0    |     | c#0 = 2_times_max(a#0, c#0) |  |
    |    |                            +----+-------------------> | if(c#0 < 0x19)  | --> |                             |  |
    |    |                                 |                     +-----------------+     +-----------------------------+  |
    |    |                                 |                       |                       |                              |
    |    +---------------------------------+                       |                       |                              |
    |                                                              |                       v                              |
    |                                                              |                     +-----------------------------+  |
    |                                                              |                     |             8.              |  |
    +--------------------------------------------------------------+-------------------> |       c#0 = c#0 - 0xa       | <+----+
                                                                   |                     +-----------------------------+  |    |
                                                                   |                       |                              |    |
                                                                   |                       |                              |    |
                                                                   |                       v                              |    |
                                                                   |                     +-----------------------------+  |    |
                                                                   |                     |             9.              |  |    |
                                                                   |                     |           return            | <+    |
                                                                   |                     +-----------------------------+       |
                                                                   |                                                           |
                                                                   +-----------------------------------------------------------+
    """
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                instructions=[
                    Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804B01F), variable("a")])),
                    Assignment(variable("c"), Constant(0)),
                    Branch(Condition(OperationType.less, [variable("a"), Constant(10, Integer.int32_t())])),
                ],
            ),
            BasicBlock(
                1,
                instructions=[
                    Assignment(variable("a"), BinaryOperation(OperationType.multiply, [variable("a"), Constant(2, Integer.int32_t())]))
                ],
            ),
            BasicBlock(
                2,
                instructions=[
                    Assignment(variable("b"), BinaryOperation(OperationType.plus, [variable("a"), Constant(5, Integer.int32_t())])),
                    Branch(Condition(OperationType.less, [variable("b"), Constant(20, Integer.int32_t())])),
                ],
            ),
            BasicBlock(
                3,
                instructions=[
                    Assignment(variable("c"), BinaryOperation(OperationType.plus, [variable("a"), variable("b")])),
                    Branch(
                        Condition(OperationType.less, [variable(name="c", ssa_name=variable("eax", 0)), Constant(20, Integer.int32_t())])
                    ),
                ],
            ),
            BasicBlock(
                4,
                instructions=[
                    Assignment(variable("c"), BinaryOperation(OperationType.multiply, [Constant(5, Integer.int32_t()), variable("b")])),
                    Branch(
                        Condition(OperationType.less, [variable(name="c", ssa_name=variable("eax", 1)), Constant(20, Integer.int32_t())])
                    ),
                ],
            ),
            BasicBlock(5, instructions=[Assignment(variable("a"), variable("c"))]),
            BasicBlock(
                6,
                instructions=[
                    Assignment(variable("c"), variable("b")),
                    Branch(
                        Condition(OperationType.less, [variable(name="c", ssa_name=variable("eax", 2)), Constant(25, Integer.int32_t())])
                    ),
                ],
            ),
            BasicBlock(
                7, instructions=[Assignment(variable("c"), Call(imp_function_symbol("2_times_max"), [variable("a"), variable("c")]))]
            ),
            BasicBlock(
                8,
                instructions=[
                    Assignment(variable(name="c"), BinaryOperation(OperationType.minus, [variable("c"), Constant(10, Integer.int32_t())]))
                ],
            ),
            BasicBlock(9, instructions=[Return([variable("d")])]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[7]),
            UnconditionalEdge(vertices[1], vertices[2]),
            TrueCase(vertices[2], vertices[3]),
            FalseCase(vertices[2], vertices[6]),
            TrueCase(vertices[3], vertices[4]),
            FalseCase(vertices[3], vertices[9]),
            TrueCase(vertices[4], vertices[5]),
            FalseCase(vertices[4], vertices[8]),
            UnconditionalEdge(vertices[5], vertices[1]),
            TrueCase(vertices[6], vertices[7]),
            FalseCase(vertices[6], vertices[8]),
            UnconditionalEdge(vertices[7], vertices[8]),
            UnconditionalEdge(vertices[8], vertices[9]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # outer branch is restructured correctly:
    assert isinstance(seq_node := task._ast.root, SeqNode)
    assert len(seq_node.children) == 5
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(enter_loop := seq_node.children[1], ConditionNode)
    assert isinstance(succ_node_7 := seq_node.children[2], ConditionNode)
    assert isinstance(succ_node_8 := seq_node.children[3], ConditionNode)
    assert isinstance(seq_node.children[4], CodeNode) and seq_node.children[4].instructions == vertices[9].instructions

    # make sure that loop entered correctly:
    assert (cond := enter_loop.condition).is_symbol
    assert task._ast.condition_map[cond] == vertices[0].instructions[-1].condition
    assert isinstance(loop := enter_loop.true_branch_child, WhileLoopNode) and enter_loop.false_branch is None

    # make sure that loop is correct
    assert loop.is_endless_loop
    assert isinstance(loop_body := loop.body, SeqNode)

    # make sure that multiple exit loop is correct
    assert len(loop_body.children) == 3
    assert (
        isinstance(loop_body.children[0], CodeNode)
        and loop_body.children[0].instructions == vertices[1].instructions + vertices[2].instructions[:-1]
    )
    assert isinstance(condition_2 := loop_body.children[1], ConditionNode)
    new_variable = Variable("exit_1", vartype=Integer.int32_t())
    assert isinstance(loop_body.children[2], CodeNode) and loop_body.children[2].instructions == [
        Assignment(new_variable, Constant(2, Integer.int32_t())),
        Break(),
    ]

    # make sure condition 2 is restructured correctly
    if (condition_2.condition).is_negation:
        condition_2.switch_branches()
    assert (cond := condition_2.condition).is_symbol
    assert task._ast.condition_map[cond] == vertices[2].instructions[-1].condition
    assert isinstance(true_branch := condition_2.true_branch_child, SeqNode)
    assert isinstance(false_branch := condition_2.false_branch_child, SeqNode)

    # true_branch
    assert len(true_branch.children) == 4
    assert isinstance(true_branch.children[0], CodeNode) and true_branch.children[0].instructions == vertices[3].instructions[:-1]
    assert isinstance(exit_over_3 := true_branch.children[1], ConditionNode)
    assert (cond := exit_over_3.condition).is_negation
    assert task._ast.condition_map[~cond] == vertices[3].instructions[-1].condition
    assert isinstance(branch := exit_over_3.true_branch_child, CodeNode) and exit_over_3.false_branch is None
    assert branch.instructions == [Assignment(new_variable, Constant(0, Integer.int32_t())), Break()]
    assert isinstance(true_branch.children[2], CodeNode) and true_branch.children[2].instructions == vertices[4].instructions[:-1]
    assert isinstance(loop_continue := true_branch.children[3], ConditionNode)
    assert (cond := loop_continue.condition).is_symbol
    assert task._ast.condition_map[cond] == vertices[4].instructions[-1].condition
    assert isinstance(branch := loop_continue.true_branch_child, CodeNode) and loop_continue.false_branch is None
    assert branch.instructions == vertices[5].instructions + [Continue()]

    # false_branch
    assert len(false_branch.children) == 2
    assert isinstance(false_branch.children[0], CodeNode) and false_branch.children[0].instructions == vertices[6].instructions[:-1]
    assert isinstance(exit_over_6 := false_branch.children[1], ConditionNode)
    assert (cond := exit_over_6.condition).is_symbol
    assert task._ast.condition_map[cond] == vertices[6].instructions[-1].condition
    assert isinstance(branch := exit_over_6.true_branch_child, CodeNode) and branch.instructions == [
        Assignment(new_variable, Constant(1, Integer.int32_t())),
        Break(),
    ]

    # successor node 7:
    assert succ_node_7.false_branch is None
    assert isinstance(succ_node_7.true_branch_child, CodeNode) and succ_node_7.true_branch_child.instructions == vertices[7].instructions
    assert succ_node_7.condition.is_disjunction and len(arguments := succ_node_7.condition.operands) == 2
    assert any((arg_1 := arg).is_negation for arg in arguments) and any((arg_2 := arg).is_symbol for arg in arguments)
    # check conditions:
    assert {task._ast.condition_map[~arg_1], task._ast.condition_map[arg_2]} == {
        vertices[0].instructions[-1].condition,
        Condition(OperationType.equal, [new_variable, Constant(1, Integer.int32_t())]),
    }

    # successor node 8:
    assert succ_node_8.false_branch is None
    assert isinstance(succ_node_8.true_branch_child, CodeNode) and succ_node_8.true_branch_child.instructions == vertices[8].instructions
    assert succ_node_8.condition.is_disjunction and len(arguments := succ_node_8.condition.operands) == 2
    assert all(arg.is_negation for arg in arguments)
    # check conditions:
    assert {task._ast.condition_map[~arg] for arg in arguments} == {
        vertices[0].instructions[-1].condition,
        Condition(OperationType.equal, [new_variable, Constant(0, Integer.int32_t())]),
    }


def test_same_reaching_condition_but_not_groupable(task):
    """
    The first region we can restructure is the region 3, 4, 5, 6.
    In this region, the nodes 2 and 6 have all the same region conditions, but we can can not group them,
    because node 2 reaches the nodes 4 and 5 that are not reachable from node 6.
    We structure smaller regions when considering possible exit-nodes in the region.
    Instead of considering the region 3, 4, 5, 6, 7, 8, we consider the smaller region 3,4,5,6 because 6 is an exit node
         +-----------------+     +-----------------+
         |       1.        |     |       0.        |
      +- |  if(b#0 < d#0)  | <-- |  if(a#0 < 0xa)  |
      |  +-----------------+     +-----------------+
      |    |                       |
      |    |                       |
      |    v                       v
      |  +-----------------+     +-----------------+
      |  |       10.       |     |       2.        |
      |  |   return b#0    |     | b#0 = a#0 + b#0 |
      |  +-----------------+     +-----------------+
      |    ^                       |
      |    |                       |
      |    |                       v
      |    |                     +-----------------+     +-----------------+
      |    |                     |       3.        |     |       5.        |
      |    |                     | c#0 = a#0 + b#0 |     | b#0 = c#0 - 0x5 |
      |    |                     | if(c#0 < 0x14)  | --> |                 |
      |    |                     +-----------------+     +-----------------+
      |    |                       |                       |
      |    |                       |                       |
      |    |                       v                       |
      |    |                     +-----------------+       |
      |    |                     |       4.        |       |
      |    |                     | c#0 = 0x2 * c#0 |       |
      |    |                     +-----------------+       |
      |    |                       |                       |
      |    |                       |                       |
      |    |                       v                       |
      |  +-----------------+     +-----------------+       |
      |  |       8.        |     |       6.        |       |
      |  | b#0 = d#0 - b#0 |     | d#0 = c#0 + b#0 |       |
      |  | if(b#0 < 0x14)  | <-- | if(d#0 < 0x14)  | <-----+
      |  +-----------------+     +-----------------+
      |    |                       |
      |    |                       |
      |    |                       v
      |    |                     +-----------------+
      |    |                     |       7.        |
      |    |                     | d#0 = c#0 + d#0 |
      |    |                     +-----------------+
      |    |                       |
      |    |                       |
      |    |                       v
      |    |                     +-----------------+
      |    |                     |       9.        |
      +----+-------------------> |   return d#0    |
           |                     +-----------------+
           |                       ^
           +-----------------------+
    """
    vertices = [
        BasicBlock(0, instructions=[Branch(Condition(OperationType.less, [variable(name="a"), Constant(10)]))]),
        BasicBlock(
            1,
            instructions=[
                # TODO this example later Assignment(variable(name="d"), variable(name="a")),
                Branch(Condition(OperationType.less, [variable(name="b"), variable(name="d")])),
            ],
        ),
        BasicBlock(
            2,
            instructions=[Assignment(variable(name="b"), BinaryOperation(OperationType.plus, [variable(name="a"), variable(name="b")]))],
        ),
        BasicBlock(
            3,
            instructions=[
                Assignment(variable(name="c"), BinaryOperation(OperationType.plus, [variable(name="a"), variable(name="b")])),
                Branch(Condition(OperationType.less, [variable(name="c"), Constant(20)])),
            ],
        ),
        BasicBlock(
            4,
            instructions=[Assignment(variable(name="c"), BinaryOperation(OperationType.multiply, [Constant(2), variable(name="c")]))],
        ),
        BasicBlock(
            5,
            instructions=[Assignment(variable(name="b"), BinaryOperation(OperationType.minus, [variable(name="c"), Constant(5)]))],
        ),
        BasicBlock(
            6,
            instructions=[
                Assignment(variable(name="d"), BinaryOperation(OperationType.plus, [variable(name="c"), variable(name="b")])),
                Branch(Condition(OperationType.less, [variable(name="d"), Constant(20)])),
            ],
        ),
        BasicBlock(
            7,
            instructions=[Assignment(variable(name="d"), BinaryOperation(OperationType.plus, [variable(name="c"), variable(name="d")]))],
        ),
        BasicBlock(
            8,
            instructions=[
                Assignment(variable(name="b"), BinaryOperation(OperationType.minus, [variable(name="d"), variable(name="b")])),
                Branch(Condition(OperationType.less, [variable(name="b"), Constant(20)])),
            ],
        ),
        BasicBlock(9, instructions=[Return([variable(name="d")])]),
        BasicBlock(10, instructions=[Return([variable(name="b")])]),
    ]

    task.graph.add_nodes_from(vertices)
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            FalseCase(vertices[1], vertices[9]),
            TrueCase(vertices[1], vertices[10]),
            UnconditionalEdge(vertices[2], vertices[3]),
            TrueCase(vertices[3], vertices[4]),
            FalseCase(vertices[3], vertices[5]),
            UnconditionalEdge(vertices[4], vertices[6]),
            UnconditionalEdge(vertices[5], vertices[6]),
            TrueCase(vertices[6], vertices[7]),
            FalseCase(vertices[6], vertices[8]),
            UnconditionalEdge(vertices[7], vertices[9]),
            TrueCase(vertices[8], vertices[9]),
            FalseCase(vertices[8], vertices[10]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # first if-else
    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(code_part := seq_node.children[0], ConditionNode)
    assert isinstance(return_part := seq_node.children[1], ConditionNode)
    assert isinstance(second_return := seq_node.children[2], CodeNode) and second_return.instructions == vertices[10].instructions

    # code_part restructured correctly:
    assert code_part.condition.is_negation and (cond := ~code_part.condition).is_symbol
    assert isinstance(code_seq := code_part.true_branch_child, SeqNode) and code_part.false_branch is None
    assert task._ast.condition_map[cond] == vertices[0].instructions[-1].condition
    assert len(code_seq.children) == 4
    assert (
        isinstance(code_seq.children[0], CodeNode)
        and code_seq.children[0].instructions == vertices[2].instructions + vertices[3].instructions[:-1]
    )
    assert isinstance(first_if_else := code_seq.children[1], ConditionNode)
    assert isinstance(code_seq.children[2], CodeNode) and code_seq.children[2].instructions == vertices[6].instructions[:-1]
    assert isinstance(second_if_else := code_seq.children[3], ConditionNode)

    # first if-else correct
    if (cond := first_if_else.condition).is_symbol:
        assert isinstance(node_4 := first_if_else.true_branch_child, CodeNode) and isinstance(
            node_5 := first_if_else.false_branch_child, CodeNode
        )
    else:
        assert first_if_else.condition.is_negation and (cond := ~first_if_else.condition).is_symbol
        assert isinstance(node_5 := first_if_else.true_branch_child, CodeNode) and isinstance(
            node_4 := first_if_else.false_branch_child, CodeNode
        )
    assert task._ast.condition_map[cond] == vertices[3].instructions[-1].condition
    assert node_4.instructions == vertices[4].instructions and node_5.instructions == vertices[5].instructions

    # second if-else correct
    if (cond := second_if_else.condition).is_symbol:
        assert isinstance(node_7 := second_if_else.true_branch_child, CodeNode) and isinstance(
            node_8 := second_if_else.false_branch_child, CodeNode
        )
    else:
        assert second_if_else.condition.is_negation and (cond := ~second_if_else.condition).is_symbol
        assert isinstance(node_8 := second_if_else.true_branch_child, CodeNode) and isinstance(
            node_7 := second_if_else.false_branch_child, CodeNode
        )
    assert task._ast.condition_map[cond] == vertices[6].instructions[-1].condition
    assert node_7.instructions == vertices[7].instructions and node_8.instructions == vertices[8].instructions[:-1]

    # return part
    assert isinstance(branch_1 := return_part.true_branch_child, CodeNode) and return_part.false_branch is None
    assert len(return_part.condition.operands) == 2
    assert branch_1.instructions == vertices[9].instructions


def test_head_is_no_loop_predecessor(task):
    """
    The initial loop region 4, 8, 10, 12 can not be extended by node 1, the head.
                                                   +---------------------------------------+
                                                   |                  1.                   |
                                                   |    var_2 = *(&(interrupt_signal))     |
      +------------------------------------------> |           if(var_2 != 0x0)            | -+
      |                                            +---------------------------------------+  |
      |                                              |                                        |
      |                                              |                                        |
      |                                              v                                        |
      |                                            +---------------------------------------+  |
      |                                            |                  3.                   |  |
      |                                            |    var_5 = *(&(info_signal_count))    |  |
      |                                         +- |   if(((unsigned int) var_5) == 0x0)   |  |
      |                                         |  +---------------------------------------+  |
      |                                         |    |                                        |
      |                                         |    |                                        |
      |                                         |    v                                        v
      |                                         |  +-------------------------------------------------+
      |                                         |  |                       4.                        |
      |                                         |  |                var_7 = &(var_6)                 |
      |                                         |  |   sigprocmask(0x0, &(caught_signals), var_7)    |
      |                                         |  |         var_3 = *(&(interrupt_signal))          |
      |                                         |  |         var_2 = *(&(info_signal_count))         |
      |                                         |  |                if(var_2 == 0x0)                 | <+
      |                                         |  +-------------------------------------------------+  |
      |                                         |    |                                        |    ^    |
      |                                         |    |                                        |    |    |
      |                                         |    v                                        |    |    |
      |                                         |  +---------------------------------------+  |    |    |
      |                                         |  |                  8.                   |  |    |    |
      |                                         |  | *(&(info_signal_count)) = var_2 - 0x1 |  |    |    |
      |                                         |  +---------------------------------------+  |    |    |
      |                                         |    |                                        |    |    |
      |                                         |    |                                        |    |    |
      |                                         |    v                                        |    |    |
    +-----------------------------------+       |  +---------------------------------------+  |    |    |
    |                11.                |       |  |                  10.                  |  |    |    |
    | arg1 = print_stats(cleanup(arg1)) |       |  |           var_7 = &(var_6)            |  |    |    |
    |           raise(var_3)            |       |  |     sigprocmask(0x2, var_7, 0x0)      |  |    |    |
    |                                   | <-----+- |           if(var_3 != 0x0)            | <+    |    |
    +-----------------------------------+       |  +---------------------------------------+       |    |
                                                |    |                                             |    |
                                                |    |                                             |    |
                                                |    v                                             |    |
                                                |  +---------------------------------------+       |    |
                                                |  |                  12.                  |       |    |
                                                |  |       arg1 = print_stats(arg1)        |       |    |
                                                |  |    var_2 = *(&(interrupt_signal))     |       |    |
                                                |  |           if(var_2 != 0x0)            | ------+    |
                                                |  +---------------------------------------+            |
                                                |    |                                                  |
                                                |    |                                                  |
                                                |    v                                                  |
                                                |  +---------------------------------------+            |
                                                |  |                  14.                  |            |
                                                |  |    var_5 = *(&(info_signal_count))    |            |
                                                |  |   if(((unsigned int) var_5) != 0x0)   | -----------+
                                                |  +---------------------------------------+
                                                |    |
                                                |    |
                                                |    v
                                                |  +---------------------------------------+
                                                |  |                  9.                   |
                                                +> |             return var_5              |
                                                   +---------------------------------------+
    """
    task._cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                1,
                [
                    Assignment(
                        Variable("var_2", Integer(32, False), ssa_name=Variable("rax_1", Integer(32, False), 2)),
                        UnaryOperation(
                            OperationType.dereference,
                            [
                                UnaryOperation(
                                    OperationType.address,
                                    [
                                        Variable(
                                            "interrupt_signal",
                                            Integer(32, False),
                                            ssa_name=Variable("interrupt_signal", Integer(32, False), 0),
                                        )
                                    ],
                                    Pointer(Integer(32, False), 32),
                                )
                            ],
                            Integer(32, False),
                        ),
                    ),
                    Branch(
                        Condition(
                            OperationType.not_equal,
                            [
                                Variable("var_2", Integer(32, False), ssa_name=Variable("rax_1", Integer(32, False), 2)),
                                Constant(0, Integer(32, True)),
                            ],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                3,
                [
                    Assignment(
                        Variable("var_5", Integer(64, False), ssa_name=Variable("rax_2", Integer(64, False), 3)),
                        UnaryOperation(
                            OperationType.dereference,
                            [
                                UnaryOperation(
                                    OperationType.address,
                                    [
                                        Variable(
                                            "info_signal_count",
                                            Integer(32, False),
                                            ssa_name=Variable("info_signal_count", Integer(32, False), 0),
                                        )
                                    ],
                                    Pointer(Integer(32, False), 32),
                                )
                            ],
                            Integer(32, False),
                        ),
                    ),
                    Branch(
                        Condition(
                            OperationType.equal,
                            [
                                UnaryOperation(
                                    OperationType.cast,
                                    [Variable("var_5", Integer(64, False), ssa_name=Variable("rax_2", Integer(64, False), 3))],
                                    Integer(32, False),
                                ),
                                Constant(0, Integer(32, True)),
                            ],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                4,
                [
                    Assignment(
                        Variable(
                            "var_7", Pointer(CustomType("void", 0), 64), ssa_name=Variable("rdx_1", Pointer(CustomType("void", 0), 64), 3)
                        ),
                        UnaryOperation(
                            OperationType.address,
                            [
                                Variable(
                                    "var_6", CustomType("void", 0), None, True, Variable("var_98", CustomType("void", 0), 6, True, None)
                                )
                            ],
                            Pointer(CustomType("void", 0), 64),
                        ),
                    ),
                    Assignment(
                        ListOperation([]),
                        Call(
                            FunctionSymbol("sigprocmask", 9456, Pointer(Integer(8, True), 32)),
                            [
                                Constant(0, Integer(32, True)),
                                UnaryOperation(
                                    OperationType.address,
                                    [
                                        Variable(
                                            "caught_signals",
                                            Integer(128, True),
                                            ssa_name=Variable("caught_signals", Integer(128, True), 0),
                                        )
                                    ],
                                    Pointer(Integer(128, True), 32),
                                ),
                                Variable(
                                    "var_7",
                                    Pointer(CustomType("void", 0), 64),
                                    ssa_name=Variable("rdx_1", Pointer(CustomType("void", 0), 64), 3),
                                ),
                            ],
                            Pointer(CustomType("void", 0), 64),
                            3,
                        ),
                    ),
                    Assignment(
                        Variable("var_3", Integer(32, False), ssa_name=Variable("rbp_1", Integer(32, False), 3)),
                        UnaryOperation(
                            OperationType.dereference,
                            [
                                UnaryOperation(
                                    OperationType.address,
                                    [
                                        Variable(
                                            "interrupt_signal",
                                            Integer(32, False),
                                            ssa_name=Variable("interrupt_signal", Integer(32, False), 0),
                                        )
                                    ],
                                    Pointer(Integer(32, False), 32),
                                )
                            ],
                            Integer(32, False),
                        ),
                    ),
                    Assignment(
                        Variable("var_2", Integer(32, False), ssa_name=Variable("rax_3", Integer(32, False), 5)),
                        UnaryOperation(
                            OperationType.dereference,
                            [
                                UnaryOperation(
                                    OperationType.address,
                                    [
                                        Variable(
                                            "info_signal_count",
                                            Integer(32, False),
                                            ssa_name=Variable("info_signal_count", Integer(32, False), 0),
                                        )
                                    ],
                                    Pointer(Integer(32, False), 32),
                                )
                            ],
                            Integer(32, False),
                        ),
                    ),
                    Branch(
                        Condition(
                            OperationType.equal,
                            [
                                Variable("var_2", Integer(32, False), ssa_name=Variable("rax_3", Integer(32, False), 5)),
                                Constant(0, Integer(32, True)),
                            ],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                8,
                [
                    Assignment(
                        UnaryOperation(
                            OperationType.dereference,
                            [
                                UnaryOperation(
                                    OperationType.address,
                                    [
                                        Variable(
                                            "info_signal_count",
                                            Integer(32, False),
                                            ssa_name=Variable("info_signal_count", Integer(32, False), 0),
                                        )
                                    ],
                                    Pointer(Integer(32, False), 32),
                                )
                            ],
                            Pointer(Integer(32, False), 32),
                            4,
                        ),
                        BinaryOperation(
                            OperationType.minus,
                            [
                                Variable("var_2", Integer(32, False), ssa_name=Variable("rax_3", Integer(32, False), 5)),
                                Constant(1, Integer(32, True)),
                            ],
                            Pointer(Integer(32, False), 32),
                        ),
                    )
                ],
            ),
            BasicBlock(
                9,
                [Return(ListOperation([Variable("var_5", Integer(64, False), ssa_name=Variable("rax_2", Integer(64, False), 10))]))],
            ),
            BasicBlock(
                10,
                [
                    Assignment(
                        Variable(
                            "var_7",
                            Pointer(CustomType("void", 0), 64),
                            ssa_name=Variable("rsi_1", Pointer(CustomType("void", 0), 64), 3),
                        ),
                        UnaryOperation(
                            OperationType.address,
                            [
                                Variable(
                                    "var_6", CustomType("void", 0), None, True, Variable("var_98", CustomType("void", 0), 3, True, None)
                                )
                            ],
                            Pointer(CustomType("void", 0), 64),
                        ),
                    ),
                    Assignment(
                        ListOperation([]),
                        Call(
                            FunctionSymbol("sigprocmask", 9456, Pointer(Integer(8, True), 32)),
                            [
                                Constant(2, Integer(32, True)),
                                Variable(
                                    "var_7",
                                    Pointer(CustomType("void", 0), 64),
                                    ssa_name=Variable("rsi_1", Pointer(CustomType("void", 0), 64), 3),
                                ),
                                Constant(0, Integer(64, False)),
                            ],
                            Pointer(CustomType("void", 0), 64),
                            6,
                        ),
                    ),
                    Branch(
                        Condition(
                            OperationType.not_equal,
                            [
                                Variable("var_3", Integer(32, False), ssa_name=Variable("rbp_1", Integer(32, False), 3)),
                                Constant(0, Integer(32, True)),
                            ],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                11,
                [
                    Assignment(
                        ListOperation([Variable("arg1", Integer(16, True), ssa_name=Variable("arg1", Integer(16, True), 4))]),
                        Call(
                            FunctionSymbol("print_stats", 19360, Pointer(Integer(8, True), 32)),
                            [
                                Call(
                                    FunctionSymbol("cleanup", 23120, Pointer(Integer(8, True), 32)),
                                    [Variable("arg1", Integer(16, True), ssa_name=Variable("arg1", Integer(16, True), 2))],
                                    Pointer(CustomType("void", 0), 64),
                                    7,
                                )
                            ],
                            Pointer(CustomType("void", 0), 64),
                            8,
                        ),
                    ),
                    Assignment(
                        ListOperation([]),
                        Call(
                            FunctionSymbol("raise", 9488, Pointer(Integer(8, True), 32)),
                            [Variable("var_3", Integer(32, False), ssa_name=Variable("rbp_1", Integer(32, False), 3))],
                            Pointer(CustomType("void", 0), 64),
                            9,
                        ),
                    ),
                ],
            ),
            BasicBlock(
                12,
                [
                    Assignment(
                        ListOperation([Variable("arg1", Integer(16, True), ssa_name=Variable("arg1", Integer(16, True), 5))]),
                        Call(
                            FunctionSymbol("print_stats", 19360, Pointer(Integer(8, True), 32)),
                            [Variable("arg1", Integer(16, True), ssa_name=Variable("arg1", Integer(16, True), 2))],
                            Pointer(CustomType("void", 0), 64),
                            10,
                        ),
                    ),
                    Assignment(
                        Variable("var_2", Integer(32, False), ssa_name=Variable("rax_5", Integer(32, False), 8)),
                        UnaryOperation(
                            OperationType.dereference,
                            [
                                UnaryOperation(
                                    OperationType.address,
                                    [
                                        Variable(
                                            "interrupt_signal",
                                            Integer(32, False),
                                            ssa_name=Variable("interrupt_signal", Integer(32, False), 0),
                                        )
                                    ],
                                    Pointer(Integer(32, False), 32),
                                )
                            ],
                            Integer(32, False),
                        ),
                    ),
                    Branch(
                        Condition(
                            OperationType.not_equal,
                            [
                                Variable("var_2", Integer(32, False), ssa_name=Variable("rax_5", Integer(32, False), 8)),
                                Constant(0, Integer(32, True)),
                            ],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                14,
                [
                    Assignment(
                        Variable("var_5", Integer(64, False), ssa_name=Variable("rax_2", Integer(64, False), 9)),
                        UnaryOperation(
                            OperationType.dereference,
                            [
                                UnaryOperation(
                                    OperationType.address,
                                    [
                                        Variable(
                                            "info_signal_count",
                                            Integer(32, False),
                                            ssa_name=Variable("info_signal_count", Integer(32, False), 0),
                                        )
                                    ],
                                    Pointer(Integer(32, False), 32),
                                )
                            ],
                            Integer(32, False),
                        ),
                    ),
                    Branch(
                        Condition(
                            OperationType.not_equal,
                            [
                                UnaryOperation(
                                    OperationType.cast,
                                    [Variable("var_5", Integer(64, False), ssa_name=Variable("rax_2", Integer(64, False), 9))],
                                    Integer(32, False),
                                ),
                                Constant(0, Integer(32, True)),
                            ],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
        ]
    )
    task._cfg.add_edges_from(
        [
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[0], vertices[2]),
            TrueCase(vertices[1], vertices[4]),
            FalseCase(vertices[1], vertices[2]),
            FalseCase(vertices[2], vertices[3]),
            TrueCase(vertices[2], vertices[5]),
            UnconditionalEdge(vertices[3], vertices[5]),
            TrueCase(vertices[5], vertices[6]),
            FalseCase(vertices[5], vertices[7]),
            UnconditionalEdge(vertices[6], vertices[0]),
            FalseCase(vertices[7], vertices[8]),
            TrueCase(vertices[7], vertices[2]),
            TrueCase(vertices[8], vertices[2]),
            FalseCase(vertices[8], vertices[4]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    # outer-loop
    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 2
    assert isinstance(do_while := seq_node.children[0], DoWhileLoopNode)
    assert isinstance(return_part := seq_node.children[1], CodeNode) and return_part.instructions == vertices[4].instructions

    # do-while loop:
    assert str(task._ast.condition_map[do_while.condition]) == "exit_4 == 0x0"
    assert isinstance(do_while_body := do_while.body, SeqNode) and len(do_while_body.children) == 4
    assert isinstance(do_while_body.children[0], CodeNode) and do_while_body.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(block_3_cond := do_while_body.children[1], ConditionNode)
    assert isinstance(break_cond := do_while_body.children[2], ConditionNode)
    assert isinstance(inner_loop := do_while_body.children[3], WhileLoopNode) and inner_loop.is_endless

    # block 3 cond:
    assert block_3_cond.condition.is_negation and str(task._ast.condition_map[~block_3_cond.condition]) == "var_2 != 0x0"
    assert isinstance(block_3_cond.true_branch_child, CodeNode) and block_3_cond.false_branch is None
    assert block_3_cond.true_branch_child.instructions == vertices[1].instructions[:-1]

    # break condition:
    assert (
        break_cond.condition.is_conjunction
        and len(arguments := break_cond.condition.operands) == 2
        and any((RC3 := arg).is_negation for arg in arguments)
        and any((RC1 := arg).is_symbol for arg in arguments)
    )
    assert str(task._ast.condition_map[~RC3]) == "var_2 != 0x0"
    assert str(task._ast.condition_map[RC1]) == "((unsigned int) var_5) == 0x0"
    assert isinstance(break_cond.true_branch_child, CodeNode) and break_cond.false_branch is None
    assert break_cond.true_branch_child.instructions == [Break()]

    # endldess loop:
    assert (inner_body := inner_loop.body, SeqNode) and len(inner_body.children) == 8
    assert isinstance(inner_body.children[0], CodeNode) and inner_body.children[0].instructions == vertices[2].instructions[:-1]
    assert isinstance(block_8_cond := inner_body.children[1], ConditionNode)
    assert isinstance(inner_body.children[2], CodeNode) and inner_body.children[2].instructions == vertices[5].instructions[:-1]
    assert isinstance(block_11_cond := inner_body.children[3], ConditionNode)
    assert isinstance(inner_body.children[4], CodeNode) and inner_body.children[4].instructions == vertices[7].instructions[:-1]
    assert isinstance(continue_cond := inner_body.children[5], ConditionNode)
    assert isinstance(inner_body.children[6], CodeNode) and inner_body.children[6].instructions == vertices[8].instructions[:-1]
    assert isinstance(inner_break_cond := inner_body.children[7], ConditionNode)

    # block 8 cond:
    assert block_8_cond.condition and str(task._ast.condition_map[~block_8_cond.condition]) == "var_2 == 0x0"
    assert isinstance(block_8_cond.true_branch_child, CodeNode) and block_8_cond.false_branch is None
    assert block_8_cond.true_branch_child.instructions == vertices[3].instructions

    # block 11 cond:
    assert block_11_cond.condition.is_symbol and str(task._ast.condition_map[block_11_cond.condition]) == "var_3 != 0x0"
    assert isinstance(block_11_cond.true_branch_child, CodeNode) and block_11_cond.false_branch is None
    assert block_11_cond.true_branch_child.instructions == vertices[6].instructions + [
        Assignment(Variable("exit_4", Integer.int32_t()), Constant(0, Integer.int32_t())),
        Break(),
    ]

    # continue cond:
    assert continue_cond.condition.is_symbol and str(task._ast.condition_map[continue_cond.condition]) == "var_2 != 0x0"
    assert isinstance(continue_cond.true_branch_child, CodeNode) and continue_cond.false_branch is None
    assert continue_cond.true_branch_child.instructions == [Continue()]

    # inner break cond:
    assert inner_break_cond.condition and str(task._ast.condition_map[~inner_break_cond.condition]) == "((unsigned int) var_5) != 0x0"
    assert isinstance(inner_break_cond.true_branch_child, CodeNode) and inner_break_cond.false_branch is None
    assert inner_break_cond.true_branch_child.instructions == [
        Assignment(Variable("exit_4", Integer.int32_t()), Constant(1, Integer.int32_t())),
        Break(),
    ]


def test_extract_return(task):
    """Extract return statement, even if both branches end with return. Choose the one with less complexity!"""
    var_i0 = Variable("var_i", Integer(32, False), ssa_name=Variable("rax_1", Integer(32, False), 0))
    var_i1 = Variable("var_i", Integer(32, False), ssa_name=Variable("rax_1", Integer(32, False), 1))
    var_x0 = Variable("var_x", Integer(32, False), ssa_name=Variable("var_c", Integer(32, False), 0))
    var_x1 = Variable("var_x", Integer(32, False), ssa_name=Variable("var_c", Integer(32, False), 1))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                instructions=[
                    Assignment(var_i0, Constant(0)),
                    Assignment(var_x0, Constant(42)),
                    Branch(Condition(OperationType.equal, [var_i0, Constant(0)])),
                ],
            ),
            BasicBlock(
                1,
                instructions=[
                    Assignment(var_x1, Constant(5)),
                    Branch(Condition(OperationType.equal, [var_x1, Constant(0)])),
                ],
            ),
            BasicBlock(2, instructions=[Return([var_x0])]),
            BasicBlock(3, instructions=[Return([var_i0])]),
            BasicBlock(4, instructions=[Assignment(var_i1, Constant(2)), Return([var_i1])]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            TrueCase(vertices[1], vertices[3]),
            FalseCase(vertices[1], vertices[4]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # outer-loop
    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 5
    assert isinstance(node_0 := seq_node.children[0], CodeNode) and node_0.instructions == vertices[0].instructions[:-1]
    assert isinstance(cond_1 := seq_node.children[1], ConditionNode) and cond_1.false_branch is None
    assert isinstance(node_1 := seq_node.children[2], CodeNode) and node_1.instructions == vertices[1].instructions[:-1]
    assert isinstance(cond_2 := seq_node.children[3], ConditionNode) and cond_2.false_branch is None
    assert isinstance(node_4 := seq_node.children[4], CodeNode) and node_4.instructions == vertices[4].instructions

    # cond 1:
    assert (cond := cond_1.condition).is_negation and task._ast.condition_map[~cond] == vertices[0].instructions[-1].condition
    assert isinstance(branch := cond_1.true_branch_child, CodeNode)
    assert branch.instructions == vertices[2].instructions

    # cond 2:
    assert (cond := cond_2.condition).is_symbol and task._ast.condition_map[cond] == vertices[1].instructions[-1].condition
    assert isinstance(branch := cond_2.true_branch_child, CodeNode)
    assert branch.instructions == vertices[3].instructions


def test_hash_eq_problem(task):
    """
    Hash and eq are not the same, therefore we have to be careful which one we want:

    - eq: Same condition node in sense of same condition
    - hash: same node in the graph
    """
    arg1 = Variable("arg1", Integer.int32_t(), ssa_name=Variable("arg1", Integer.int32_t(), 0))
    arg2 = Variable("arg2", Integer.int32_t(), ssa_name=Variable("arg2", Integer.int32_t(), 0))
    var_2 = Variable("var_2", Integer.int32_t(), None, True, Variable("rax_1", Integer.int32_t(), 1, True, None))
    var_5 = Variable("var_5", Integer.int32_t(), None, True, Variable("rax_2", Integer.int32_t(), 2, True, None))
    var_6 = Variable("var_6", Integer.int32_t(), None, True, Variable("rax_5", Integer.int32_t(), 30, True, None))
    var_7 = Variable("var_7", Integer.int32_t(), None, True, Variable("rax_3", Integer.int32_t(), 3, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Branch(Condition(OperationType.equal, [arg1, Constant(1, Integer.int32_t())]))]),
            BasicBlock(
                1,
                instructions=[
                    Assignment(var_2, BinaryOperation(OperationType.plus, [var_2, Constant(1, Integer.int32_t())])),
                    Branch(Condition(OperationType.not_equal, [var_2, Constant(0, Integer.int32_t())])),
                ],
            ),
            BasicBlock(
                2,
                instructions=[
                    Assignment(ListOperation([]), Call(imp_function_symbol("sub_140019288"), [arg2])),
                    Branch(Condition(OperationType.equal, [arg1, Constant(0, Integer.int32_t())])),
                ],
            ),
            BasicBlock(
                3,
                instructions=[
                    Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804B01F), var_5])),
                    Branch(Condition(OperationType.not_equal, [var_5, Constant(0, Integer.int32_t())])),
                ],
            ),
            BasicBlock(
                4, instructions=[Assignment(var_5, Constant(0, Integer.int32_t())), Assignment(var_7, Constant(-1, Integer.int32_t()))]
            ),
            BasicBlock(
                5,
                instructions=[
                    Assignment(var_5, Constant(0, Integer.int32_t())),
                    Assignment(var_7, Constant(-1, Integer.int32_t())),
                    Assignment(arg1, Constant(0, Integer.int32_t())),
                    Assignment(var_2, Constant(0, Integer.int32_t())),
                ],
            ),
            BasicBlock(
                6,
                instructions=[
                    Assignment(var_5, Constant(0, Integer.int32_t())),
                    Assignment(var_7, Constant(-1, Integer.int32_t())),
                    Assignment(var_2, Constant(0, Integer.int32_t())),
                ],
            ),
            BasicBlock(7, instructions=[Assignment(ListOperation([]), Call(imp_function_symbol("sub_1400193a8"), []))]),
            BasicBlock(
                8,
                instructions=[
                    Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804B01F), var_6])),
                    Branch(Condition(OperationType.greater_us, [var_6, Constant(0, Integer.int32_t())])),
                ],
            ),
            BasicBlock(9, instructions=[Assignment(arg1, Constant(1, Integer.int32_t()))]),
            BasicBlock(10, instructions=[Return([arg1])]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            TrueCase(vertices[1], vertices[3]),
            FalseCase(vertices[1], vertices[4]),
            TrueCase(vertices[2], vertices[5]),
            FalseCase(vertices[2], vertices[6]),
            TrueCase(vertices[3], vertices[7]),
            FalseCase(vertices[3], vertices[8]),
            UnconditionalEdge(vertices[4], vertices[7]),
            UnconditionalEdge(vertices[5], vertices[10]),
            UnconditionalEdge(vertices[6], vertices[9]),
            UnconditionalEdge(vertices[7], vertices[9]),
            TrueCase(vertices[8], vertices[9]),
            FalseCase(vertices[8], vertices[10]),
            UnconditionalEdge(vertices[9], vertices[10]),
        ]
    )
    PatternIndependentRestructuring().run(task)
    assert any(isinstance(node, SwitchNode) for node in task.syntax_tree)
    var_2_conditions = []
    for node in task.syntax_tree.get_condition_nodes_post_order():
        if (
            not node.condition.is_symbol
            and node.condition.is_literal
            and str(task.syntax_tree.condition_map[~node.condition]) in {"var_2 != 0x0"}
        ):
            node.switch_branches()
        if node.condition.is_symbol and str(task.syntax_tree.condition_map[node.condition]) in {"var_2 != 0x0"}:
            var_2_conditions.append(node)
    assert len(var_2_conditions) == 2
    assert var_2_conditions[0] == var_2_conditions[1]
    assert hash(var_2_conditions[0]) != hash(var_2_conditions[1])
