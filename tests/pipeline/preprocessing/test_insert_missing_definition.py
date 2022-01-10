"""Pytest for InsertingMissingDefinitions."""
from typing import List

import pytest
from decompiler.pipeline.preprocessing import InsertMissingDefinitions
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, FunctionSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Instruction, Phi, Relation, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import Integer
from decompiler.task import DecompilerTask


def function_symbol(name: str, value: int = 0x42) -> FunctionSymbol:
    return FunctionSymbol(name, value)


def construct_graph_non_aliased(number: int) -> (List[Instruction], DecompilerTask):
    """
    Construct graphs to check for all undefined non-aliased variables whether their definition is inserted at the correct place

    :param number: Number of the graph we want to check.
    :return: A tuple, where the first entry is a list of instructions and the second entry is a control flow graph.
    """

    list_instructions = [
        # Node 0
        Assignment(Variable("v", Integer.int32_t(), 0), Constant(5)),
        Assignment(
            Variable("x", Integer.int32_t(), 1), BinaryOperation(OperationType.plus, [Variable("v", Integer.int32_t(), 0), Constant(2)])
        ),
        # Node 1
        Assignment(
            Variable("w", Integer.int32_t(), 1), BinaryOperation(OperationType.multiply, [Variable("v", Integer.int32_t(), 0), Constant(4)])
        ),
        Assignment(
            ListOperation([Variable("v", Integer.int32_t(), 2)]),
            Call(function_symbol("binomial"), [Variable("x", Integer.int32_t(), 1), Constant(10)]),
        ),
        Branch(Condition(OperationType.greater, [Variable("w", Integer.int32_t(), 1), Variable("v", Integer.int32_t(), 2)], Integer(1))),
        # Node 2
        Assignment(
            Variable("x", Integer.int32_t(), 2),
            BinaryOperation(OperationType.multiply, [Variable("w", Integer.int32_t(), 1), Variable("v", Integer.int32_t(), 2)]),
        ),
        # Node 3
        Assignment(
            Variable("x", Integer.int32_t(), 3),
            BinaryOperation(OperationType.multiply, [Variable("v", Integer.int32_t(), 2), Variable("v", Integer.int32_t(), 2)]),
        ),
        # Node 4
        Phi(Variable("x", Integer.int32_t(), 4), [Variable("x", Integer.int32_t(), 2), Variable("x", Integer.int32_t(), 3)]),
        Assignment(
            Variable("w", Integer.int32_t(), 2),
            BinaryOperation(OperationType.plus, [Variable("w", Integer.int32_t(), 1), Variable("v", Integer.int32_t(), 2)]),
        ),
        Assignment(
            Variable("w", Integer.int32_t(), 2),
            BinaryOperation(OperationType.plus, [Variable("w", Integer.int32_t(), 1), Variable("x", Integer.int32_t(), 4)]),
        ),
        Branch(Condition(OperationType.greater, [Variable("v", Integer.int32_t(), 3), Variable("w", Integer.int32_t(), 2)], Integer(1))),
        Branch(Condition(OperationType.greater, [Variable("x", Integer.int32_t(), 4), Variable("w", Integer.int32_t(), 2)], Integer(1))),
        # Node 5
        Assignment(
            Variable("w", Integer.int32_t(), 3),
            BinaryOperation(OperationType.plus, [Variable("x", Integer.int32_t(), 4), Variable("x", Integer.int32_t(), 4)]),
        ),
        # Node 6
        Assignment(
            ListOperation([]),
            Call(
                function_symbol("simplify"),
                [Variable("v", Integer.int32_t(), 3), Variable("w", Integer.int32_t(), 3), Constant(2), Constant(4)],
            ),
        ),
        Assignment(
            Variable("v", Integer.int32_t(), 4),
            BinaryOperation(OperationType.plus, [Variable("v", Integer.int32_t(), 3), Variable("w", Integer.int32_t(), 3)]),
        ),
        # Node 7
        Assignment(ListOperation([]), Call(function_symbol("binomial"), [Variable("x", Integer.int32_t(), 4), Constant(4)])),
        # Node 8
        Assignment(
            Variable("v", Integer.int32_t(), 5), BinaryOperation(OperationType.plus, [Variable("v", Integer.int32_t(), 3), Constant(2)])
        ),
        Assignment(
            ListOperation([]), Call(function_symbol("binomial"), [Variable("v", Integer.int32_t(), 5), Variable("x", Integer.int32_t(), 4)])
        ),
        # Node 9
        Phi(Variable("v", Integer.int32_t(), 7), [Variable("v", Integer.int32_t(), 4), Variable("v", Integer.int32_t(), 5)]),
        Phi(Variable("v", Integer.int32_t(), 7), [Variable("v", Integer.int32_t(), 4), Variable("v", Integer.int32_t(), 6)]),
        Assignment(
            Variable("w", Integer.int32_t(), 4), BinaryOperation(OperationType.plus, [Variable("v", Integer.int32_t(), 7), Constant(2)])
        ),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(10)]
    # Add instructions:
    nodes[0].instructions = [i.copy() for i in list_instructions[0:2]]
    nodes[1].instructions = [i.copy() for i in list_instructions[2:5]]
    nodes[2].instructions = [list_instructions[5].copy()]
    nodes[3].instructions = [list_instructions[6].copy()]
    nodes[4].instructions = [i.copy() for i in list_instructions[7:9]]
    nodes[5].instructions = [list_instructions[12].copy()]
    nodes[6].instructions = [i.copy() for i in list_instructions[13:15]]
    nodes[7].instructions = [list_instructions[15].copy()]
    nodes[8].instructions = [i.copy() for i in list_instructions[16:18]]
    nodes[9].instructions = [list_instructions[18].copy(), list_instructions[20].copy()]

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            UnconditionalEdge(nodes[0], nodes[1]),
            UnconditionalEdge(nodes[1], nodes[2]),
            UnconditionalEdge(nodes[1], nodes[3]),
            UnconditionalEdge(nodes[2], nodes[4]),
            UnconditionalEdge(nodes[3], nodes[4]),
        ]
    )
    task = DecompilerTask("test", cfg)

    # First Graph - everything defined
    if number == 1:
        return list_instructions, task

    # Second Graph - only undefined variables where we do not insert a definition
    if number == 2:
        cfg.root = nodes[1]
        cfg.remove_node(nodes[0])
        return list_instructions, task

    # Third Graph - non-aliased variable not defined and not first.
    if number == 3:
        nodes[0].instructions.append(list_instructions[2].copy())
        nodes[1].instructions = [
            Branch(Condition(OperationType.greater, [Variable("w", Integer.int32_t(), 1), Variable("x", Integer.int32_t(), 1)], Integer(1)))
        ]
        return list_instructions, task

    # Fourth Graph - non-aliased variable not defined and not first and first is not defined, but this is okay.
    if number == 4:
        nodes[0].instructions = [list_instructions[2].copy()]
        nodes[1].instructions = [list_instructions[4].copy()]
        return list_instructions, task


def test_everything_defined():
    """Everything is defined.
                              +----------------------------+
                              |         v#0 = 0x5          |
                              |     x#1 = (v#0 + 0x2)      |
                              +----------------------------+
                                |
                                |
                                v
    +-------------------+     +----------------------------+
    |                   |     |     w#1 = (v#0 * 0x4)      |
    | x#3 = (v#2 * v#2) |     |  v#2 = binomial(x#1, 0xa)  |
    |                   | <-- | if w#1 > v#2 then 2 else 3 |
    +-------------------+     +----------------------------+
      |                         |
      |                         |
      |                         v
      |                       +----------------------------+
      |                       |     x#2 = (w#1 * v#2)      |
      |                       +----------------------------+
      |                         |
      |                         |
      |                         v
      |                       +----------------------------+
      |                       |      x#4 = ϕ(x#2,x#3)      |
      +---------------------> |     w#2 = (w#1 + v#2)      |
                              +----------------------------+
    """
    list_instructions, task = construct_graph_non_aliased(1)
    InsertMissingDefinitions().run(task)

    assert [node.instructions for node in task.graph.nodes] == [
        list_instructions[0:2],
        list_instructions[2:5],
        [list_instructions[5]],
        [list_instructions[6]],
        list_instructions[7:9],
    ]


def test_undefined_non_aliased_variables_first():
    """We have only undefined variables, namely v#0, X#1, where we do not insert a definition.
    +-------------------+     +----------------------------+
    |                   |     |     w#1 = (v#0 * 0x4)      |
    | x#3 = (v#2 * v#2) |     |  v#2 = binomial(x#1, 0xa)  |
    |                   | <-- | if w#1 > v#2 then 2 else 3 |
    +-------------------+     +----------------------------+
      |                         |
      |                         |
      |                         v
      |                       +----------------------------+
      |                       |     x#2 = (w#1 * v#2)      |
      |                       +----------------------------+
      |                         |
      |                         |
      |                         v
      |                       +----------------------------+
      |                       |      x#4 = ϕ(x#2,x#3)      |
      +---------------------> |     w#2 = (w#1 + v#2)      |
                              +----------------------------+
    """
    list_instructions, task = construct_graph_non_aliased(2)
    InsertMissingDefinitions().run(task)

    assert [node.instructions for node in task.graph.nodes] == [
        list_instructions[2:5],
        [list_instructions[5]],
        [list_instructions[6]],
        list_instructions[7:9],
    ]


def test_non_aliased_variable_not_defined():
    """ "Non-aliased variable v#2 is not defined. This should not happen. So we raise an Error.

                              +----------------------------+
                              |         v#0 = 0x5          |
                              |     x#1 = (v#0 + 0x2)      |
                              |     w#1 = (v#0 * 0x4)      |
                              +----------------------------+
                                |
                                |
                                v
    +-------------------+     +----------------------------+
    | x#3 = (v#2 * v#2) | <-- | if w#1 > x#1 then 2 else 3 |
    +-------------------+     +----------------------------+
      |                         |
      |                         |
      |                         v
      |                       +----------------------------+
      |                       |     x#2 = (w#1 * v#2)      |
      |                       +----------------------------+
      |                         |
      |                         |
      |                         v
      |                       +----------------------------+
      |                       |      x#4 = ϕ(x#2,x#3)      |
      +---------------------> |     w#2 = (w#1 + v#2)      |
                              +----------------------------+
    """
    list_instructions, task = construct_graph_non_aliased(3)

    with pytest.raises(ValueError):
        InsertMissingDefinitions().run(task)


def test_non_aliased_variable_and_first_not_defined():
    """Non-aliased variable v#2 is not defined as well as v#0. Not defining v#0 is okay, but not v#2. So we raise an Error.
                              +----------------------------+
                              |     w#1 = (v#0 * 0x4)      |
                              +----------------------------+
                                |
                                |
                                v
    +-------------------+     +----------------------------+
    | x#3 = (v#2 * v#2) | <-- | if w#1 > v#2 then 2 else 3 |
    +-------------------+     +----------------------------+
      |                         |
      |                         |
      |                         v
      |                       +----------------------------+
      |                       |     x#2 = (w#1 * v#2)      |
      |                       +----------------------------+
      |                         |
      |                         |
      |                         v
      |                       +----------------------------+
      |                       |      x#4 = ϕ(x#2,x#3)      |
      +---------------------> |     w#2 = (w#1 + v#2)      |
                              +----------------------------+
    """
    list_instructions, task = construct_graph_non_aliased(4)

    with pytest.raises(ValueError):
        InsertMissingDefinitions().run(task)


def construct_graph_aliased(number: int) -> (List[Instruction], List[Variable], ControlFlowGraph):
    """
    Construct graphs to check for all undefined aliased variables whether their definition is inserted at the correct place

    :param number: Number of the graph we want to check.
    :return: A tuple, where the first entry is a list of instructions and the second entry is a control flow graph.
    """

    aliased_variables = [Variable("x", Integer.int32_t(), index, True) for index in [1, 2, 3, 4, 5, 6, 7, 8]]
    aliased_variables_y = [Variable("y", Integer.int32_t(), index, True) for index in [1, 2, 3, 4, 5, 6, 7, 8]]

    list_instructions = [
        # Node 0: 0 - 4
        Assignment(ListOperation([]), Call(function_symbol("printf"), [Constant(0x804A00C)], writes_memory=1)),
        Assignment(Variable("v", Integer.int32_t(), 1), UnaryOperation(OperationType.address, [aliased_variables[0]], Integer.int32_t())),
        Assignment(
            ListOperation([]), Call(function_symbol("scanf"), [Constant(0x804A01F), Variable("v", Integer.int32_t(), 1)], writes_memory=2)
        ),
        Assignment(Variable("u", Integer.int32_t(), 1), aliased_variables[1]),
        Branch(Condition(OperationType.greater_or_equal, [Variable("u", Integer.int32_t(), 1), Constant(0xC)], Integer(1))),
        # Node 1: 5 - 14
        Assignment(Variable("w", Integer.int32_t(), 2), aliased_variables[1]),
        Assignment(Variable("z", Integer.int32_t(), 2), Variable("w", Integer.int32_t(), 2)),
        Assignment(
            ListOperation([]), Call(function_symbol("printf"), [Constant(0x804A03C), Variable("z", Integer.int32_t(), 2)], writes_memory=3)
        ),
        Assignment(Variable("z", Integer.int32_t(), 3), UnaryOperation(OperationType.address, [aliased_variables[2]], Integer.int32_t())),
        Assignment(
            ListOperation([]), Call(function_symbol("scanf"), [Constant(0x804A01F), Variable("z", Integer.int32_t(), 3)], writes_memory=4)
        ),
        Assignment(Variable("w", Integer.int32_t(), 3), aliased_variables[3]),
        Assignment(Variable("z", Integer.int32_t(), 4), Variable("w", Integer.int32_t(), 3)),
        Assignment(
            ListOperation([]), Call(function_symbol("printf"), [Constant(0x804A0C8), Variable("z", Integer.int32_t(), 4)], writes_memory=5)
        ),
        Assignment(Variable("z", Integer.int32_t(), 5), UnaryOperation(OperationType.address, [aliased_variables[4]], Integer.int32_t())),
        Assignment(
            ListOperation([]), Call(function_symbol("scanf"), [Constant(0x804A01F), Variable("z", Integer.int32_t(), 5)], writes_memory=6)
        ),
        # Node 2: 15 - 25
        Phi(Variable("z", Integer.int32_t(), 6), [Variable("v", Integer.int32_t(), 1), Variable("z", Integer.int32_t(), 5)]),
        Phi(Variable("w", Integer.int32_t(), 4), [Variable("u", Integer.int32_t(), 1), Variable("w", Integer.int32_t(), 3)]),
        Phi(aliased_variables[6], [aliased_variables[1], aliased_variables[5]]),
        Assignment(Variable("w", Integer.int32_t(), 5), aliased_variables[6]),
        Assignment(
            Variable("w", Integer.int32_t(), 6),
            BinaryOperation(OperationType.multiply, [Variable("w", Integer.int32_t(), 5), Constant(0xC)]),
        ),
        Assignment(aliased_variables[7], Variable("w", Integer.int32_t(), 6)),
        Assignment(Variable("w", Integer.int32_t(), 7), aliased_variables[7]),
        Assignment(Variable("z", Integer.int32_t(), 7), Variable("w", Integer.int32_t(), 7)),
        Assignment(
            ListOperation([]), Call(function_symbol("printf"), [Constant(0x804A05D), Variable("z", Integer.int32_t(), 7)], writes_memory=9)
        ),
        Assignment(Variable("w", Integer.int32_t(), 8), Constant(0x0)),
        Return([Constant(0x0)]),
        # Node 3: 26 - 34
        Assignment(ListOperation([]), Call(function_symbol("printf"), [Constant(0x804A00C)], writes_memory=1)),
        Assignment(Variable("w", Integer.int32_t(), 1), UnaryOperation(OperationType.address, [aliased_variables[0]])),
        Assignment(
            ListOperation([]), Call(function_symbol("scanf"), [Constant(0x804A01F), Variable("w", Integer.int32_t(), 1)], writes_memory=2)
        ),
        Assignment(ListOperation([]), Call(function_symbol("printf"), [Constant(0x804A022)], writes_memory=3)),
        Assignment(Variable("w", Integer.int32_t(), 2), UnaryOperation(OperationType.address, [aliased_variables_y[2]])),
        Assignment(
            ListOperation([]), Call(function_symbol("scanf"), [Constant(0x804A01F), Variable("w", Integer.int32_t(), 2)], writes_memory=4)
        ),
        Assignment(Variable("u", Integer.int32_t(), 1), aliased_variables[3]),
        Assignment(Variable("v", Integer.int32_t(), 1), aliased_variables_y[3]),
        Branch(
            Condition(
                OperationType.greater_or_equal, [Variable("u", Integer.int32_t(), 1), Variable("v", Integer.int32_t(), 1)], Integer(1)
            )
        ),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(10)]
    # Add instructions:
    nodes[0].instructions = [i.copy() for i in list_instructions[0:4]]
    nodes[1].instructions = [i.copy() for i in list_instructions[5:15]]
    nodes[2].instructions = [i.copy() for i in list_instructions[15:26]]
    nodes[3].instructions = [i.copy() for i in list_instructions[26:34]]

    cfg = ControlFlowGraph()
    task = DecompilerTask("test", cfg)
    cfg.add_node(nodes[0])
    if number == 1:
        return list_instructions, aliased_variables, task

    cfg.add_edge(UnconditionalEdge(nodes[0], nodes[1]))
    nodes[0].instructions = [i.copy() for i in list_instructions[0:5]]
    if number == 2:
        return list_instructions, aliased_variables, task

    cfg.add_edges_from([UnconditionalEdge(nodes[0], nodes[2]), UnconditionalEdge(nodes[1], nodes[2])])
    if number == 3:
        return list_instructions, aliased_variables, task

    if number == 4:
        new_instruction = Assignment(
            ListOperation([]), Call(function_symbol("printf"), [Constant(0x804A08D), Variable("w", Integer.int32_t(), 6)], writes_memory=8)
        )
        nodes[2].replace_instruction(list_instructions[20], [new_instruction.copy()])
        return list_instructions + [new_instruction], aliased_variables, task

    if number == 5:
        cfg = ControlFlowGraph()
        task = DecompilerTask("test", cfg)
        cfg.add_node(nodes[3])
        return list_instructions, aliased_variables + aliased_variables_y, task

    if number == 6:
        new_instruction_1 = Assignment(
            Variable("v", Integer.int32_t(), "2"), UnaryOperation(OperationType.address, [aliased_variables_y[0]], Integer.int32_t())
        )
        new_instruction_2 = Assignment(Variable("u", Integer.int32_t(), 2), aliased_variables_y[7])
        new_instruction_3 = Phi(aliased_variables_y[6], [aliased_variables_y[1], aliased_variables_y[5]])
        nodes[0].instructions.insert(2, new_instruction_1.copy())
        nodes[2].instructions.insert(7, new_instruction_2.copy())
        nodes[2].instructions.insert(3, new_instruction_3.copy())
        return list_instructions + [new_instruction_1, new_instruction_2, new_instruction_3], aliased_variables + aliased_variables_y, task

    if number == 7:
        new_instruction_1 = Assignment(Variable("v", Integer.int32_t(), 2), aliased_variables_y[0])
        new_instruction_2 = Assignment(Variable("u", Integer.int32_t(), 2), aliased_variables_y[6])
        nodes[0].instructions.insert(2, new_instruction_1.copy())
        nodes[2].instructions.insert(4, new_instruction_2.copy())
        return list_instructions, aliased_variables, task

    if number == 8:

        list_instructions[23].value._writes_memory = 7
        nodes[2].instructions = [i.copy() for i in list_instructions[15:17]] + [
            list_instructions[23].copy(),
            Phi(aliased_variables[7], [aliased_variables[1], aliased_variables[5]]),
            Assignment(Variable("w", Integer.int32_t(), 7), aliased_variables[6]),
        ]
        return list_instructions, aliased_variables, task

    if number == 9:
        cfg = ControlFlowGraph()
        nodes[0].instructions = [
            Assignment(
                Variable("u", Integer.int32_t(), 0),
                UnaryOperation(OperationType.address, [Variable("x", Integer.int32_t(), 0, is_aliased=True)]),
            ),
            Branch(Condition(OperationType.greater_or_equal, [Variable("u", Integer.int32_t(), 0), Constant(0xC)], Integer(1))),
        ]
        nodes[1].instructions = [i.copy() for i in list_instructions[0:4]]
        nodes[2].instructions = [i.copy() for i in list_instructions[7:11]]

        cfg.add_edges_from([UnconditionalEdge(nodes[0], nodes[1]), UnconditionalEdge(nodes[0], nodes[2])])

        return list_instructions, aliased_variables, task


def test_insert_aliased_variable_one_dominator_same_block():
    """
    Inserts a definition for an undefined aliased variable, where the memory version is set in the same basic block with only one dominator.
    -> After print an assignment and after scanf a relation.
    +-----------------------+
    |   printf(0x804a00c)   |
    |     v#1 = &(x#1)      |
    | scanf(0x804a01f, v#1) |
    |       u#1 = x#2       |
    +-----------------------+
    """
    list_instructions, aliased_variables, task = construct_graph_aliased(1)

    InsertMissingDefinitions().run(task)

    assert [node.instructions for node in task.graph.nodes] == [
        [list_instructions[0], Assignment(aliased_variables[0], Variable("x", Integer.int32_t(), 0, is_aliased=True))]
        + list_instructions[1:3]
        + [Relation(aliased_variables[1], aliased_variables[0])]
        + list_instructions[3:4]
    ]


def test_insert_aliased_variable_more_dominators_same_block():
    """
    Inserts a definition for an undefined aliased variable, where the memory_version is set in the same basic block
    and we have more than one dominator.
    +-----------------------------+
    |      printf(0x804a00c)      |
    |        v#1 = &(x#1)         |
    |    scanf(0x804a01f, v#1)    |
    |          u#1 = x#2          |
    | if u#1 >= 0xc then 1 else 2 |
    +-----------------------------+
      |
      |
      v
    +-----------------------------+
    |          w#2 = x#2          |
    |          z#2 = w#2          |
    |   printf(0x804a03c, z#2)    |
    |        z#3 = &(x#3)         |
    |    scanf(0x804a01f, z#3)    |
    |          w#3 = x#4          |
    |          z#4 = w#3          |
    |   printf(0x804a0c8, z#4)    |
    |        z#5 = &(x#5)         |
    |    scanf(0x804a01f, z#5)    |
    |        x#6 = x#5
    +-----------------------------+
    """
    list_instructions, aliased_variables, task = construct_graph_aliased(2)

    InsertMissingDefinitions().run(task)

    assert [node.instructions for node in task.graph.nodes] == [
        [list_instructions[0], Assignment(aliased_variables[0], Variable("x", Integer.int32_t(), 0, is_aliased=True))]
        + list_instructions[1:3]
        + [Relation(aliased_variables[1], aliased_variables[0])]
        + list_instructions[3:5],
        list_instructions[5:8]
        + [Assignment(aliased_variables[2], aliased_variables[1])]
        + list_instructions[8:10]
        + [Relation(aliased_variables[3], aliased_variables[2])]
        + list_instructions[10:13]
        + [Assignment(aliased_variables[4], aliased_variables[3])]
        + list_instructions[13:15]
        + [Relation(aliased_variables[5], aliased_variables[4])],
    ]


def test_insert_aliased_variable_dominator_prev_block():
    """
    Inserts a definition for an undefined aliased variable, where the memory_version is set in a previous basic block.
    +-----------------------------+
    |      printf(0x804a00c)      |
    |        v#1 = &(x#1)         |
    |    scanf(0x804a01f, v#1)    |
    |          u#1 = x#2          |
    | if u#1 >= 0xc then 1 else 2 | -+
    +-----------------------------+  |
      |                              |
      |                              |
      v                              |
    +-----------------------------+  |
    |          w#2 = x#2          |  |
    |          z#2 = w#2          |  |
    |   printf(0x804a03c, z#2)    |  |
    |        z#3 = &(x#3)         |  |
    |    scanf(0x804a01f, z#3)    |  |
    |          w#3 = x#4          |  |
    |          z#4 = w#3          |  |
    |   printf(0x804a0c8, z#4)    |  |
    |        z#5 = &(x#5)         |  |
    |    scanf(0x804a01f, z#5)    |  |
    +-----------------------------+  |
      |                              |
      |                              |
      v                              |
    +-----------------------------+  |
    |      z#6 = ϕ(v#1,z#5)       |  |
    |      w#4 = ϕ(u#1,w#3)       |  |
    |      x#7 = ϕ(x#2,x#6)       |  |
    |          w#5 = x#7          |  |
    |      w#6 = (w#5 * 0xc)      |  |
    |          x#8 = w#6          |  |
    |          w#7 = x#8          |  |
    |          z#7 = w#7          |  |
    |   printf(0x804a05d, z#7)    |  |
    |         x#9 = x#8           |  |
    |          w#8 = 0x0          |  |
    |         return 0x0          | <+
    +-----------------------------+
    """
    list_instructions, aliased_variables, task = construct_graph_aliased(3)

    InsertMissingDefinitions().run(task)

    assert [node.instructions for node in task.graph.nodes] == [
        [list_instructions[0], Assignment(aliased_variables[0], Variable("x", Integer.int32_t(), 0, is_aliased=True))]
        + list_instructions[1:3]
        + [Relation(aliased_variables[1], aliased_variables[0])]
        + list_instructions[3:5],
        list_instructions[5:8]
        + [Assignment(aliased_variables[2], aliased_variables[1])]
        + list_instructions[8:10]
        + [Relation(aliased_variables[3], aliased_variables[2])]
        + list_instructions[10:13]
        + [Assignment(aliased_variables[4], aliased_variables[3])]
        + list_instructions[13:15]
        + [Relation(aliased_variables[5], aliased_variables[4])],
        list_instructions[15:24]
        + [Assignment(Variable("x", Integer.int32_t(), 9, is_aliased=True), Variable("x", Integer.int32_t(), 8, is_aliased=True))]
        + list_instructions[24:26],
    ]


def test_insert_aliased_variable_dominator_phi_target():
    """
    Inserts a definition for an undefined aliased variable, where the dominator is a target of a phi-function.
    +-----------------------------+
    |      printf(0x804a00c)      |
    |        v#1 = &(x#1)         |
    |    scanf(0x804a01f, v#1)    |
    |          u#1 = x#2          |
    | if u#1 >= 0xc then 1 else 2 | -+
    +-----------------------------+  |
      |                              |
      |                              |
      v                              |
    +-----------------------------+  |
    |          w#2 = x#2          |  |
    |          z#2 = w#2          |  |
    |   printf(0x804a03c, z#2)    |  |
    |        z#3 = &(x#3)         |  |
    |    scanf(0x804a01f, z#3)    |  |
    |          w#3 = x#4          |  |
    |          z#4 = w#3          |  |
    |   printf(0x804a0c8, z#4)    |  |
    |        z#5 = &(x#5)         |  |
    |    scanf(0x804a01f, z#5)    |  |
    +-----------------------------+  |
      |                              |
      |                              |
      v                              |
    +-----------------------------+  |
    |      z#6 = ϕ(v#1,z#5)       |  |
    |      w#4 = ϕ(u#1,w#3)       |  |
    |      x#7 = ϕ(x#2,x#6)       |  |
    |          w#5 = x#7          |  |
    |      w#6 = (w#5 * 0xc)      |  |
    |   printf(0x804a08d, w#6)    |  |
    |          w#7 = x#8          |  |
    |          z#7 = w#7          |  |
    |   printf(0x804a05d, z#7)    |  |
    |          w#8 = 0x0          |  |
    |         return 0x0          | <+
    +-----------------------------+
    """
    list_instructions, aliased_variables, task = construct_graph_aliased(4)

    InsertMissingDefinitions().run(task)

    assert [node.instructions for node in task.graph.nodes] == [
        [list_instructions[0], Assignment(aliased_variables[0], Variable("x", Integer.int32_t(), 0, is_aliased=True))]
        + list_instructions[1:3]
        + [Relation(aliased_variables[1], aliased_variables[0])]
        + list_instructions[3:5],
        list_instructions[5:8]
        + [Assignment(aliased_variables[2], aliased_variables[1])]
        + list_instructions[8:10]
        + [Relation(aliased_variables[3], aliased_variables[2])]
        + list_instructions[10:13]
        + [Assignment(aliased_variables[4], aliased_variables[3])]
        + list_instructions[13:15]
        + [Relation(aliased_variables[5], aliased_variables[4])],
        list_instructions[15:20]
        + [list_instructions[-1]]
        + [Assignment(aliased_variables[7], aliased_variables[6])]
        + list_instructions[21:24]
        + [Assignment(Variable("x", Integer.int32_t(), 9, is_aliased=True), Variable("x", Integer.int32_t(), 8, is_aliased=True))]
        + list_instructions[24:26],
    ]


def test_insert_two_aliased_variables_same_memory_version():
    """
    Inserts a definition for two undefined aliased variable,with the same memory version.
    +-----------------------+
    |   printf(0x804a00c)   |
    |     w#1 = &(x#1)      |
    | scanf(0x804a01f, w#1) |
    |   printf(0x804a022)   |
    |     w#2 = &(y#3)      |
    | scanf(0x804a01f, w#2) |
    |       u#1 = x#4       |
    |       v#1 = y#4       |
    +-----------------------+
    """
    list_instructions, aliased_variables, task = construct_graph_aliased(5)

    InsertMissingDefinitions().run(task)

    x0, x1, x2, x3, x4 = (Variable("x", Integer.int32_t(), i, is_aliased=True) for i in range(5))
    y0, y1, y2, y3, y4 = (Variable("y", Integer.int32_t(), i, is_aliased=True) for i in range(5))
    result_with_x_first = [
        [list_instructions[26], Assignment(x1, x0), Assignment(y1, y0)]
        + list_instructions[27:29]
        + [Relation(x2, x1), Assignment(y2, y1), list_instructions[29]]
        + [Assignment(x3, x2), Assignment(y3, y2)]
        + list_instructions[30:32]
        + [Assignment(x4, x3), Relation(y4, y3)]
        + list_instructions[32:34]
    ]

    result_with_y_first = [
        [list_instructions[26], Assignment(y1, y0), Assignment(aliased_variables[0], Variable("x", Integer.int32_t(), 0, is_aliased=True))]
        + list_instructions[27:29]
        + [Assignment(y2, y1), Relation(x2, x1), list_instructions[29]]
        + [Assignment(y3, y2), Assignment(x3, x2)]
        + list_instructions[30:32]
        + [Relation(y4, y3), Assignment(x4, x3)]
        + list_instructions[32:34]
    ]

    assert [node.instructions for node in task.graph.nodes] == result_with_x_first or result_with_y_first


def test_insert_aliased_variable_dominator_assignment():
    """
    Inserts a definition for an undefined aliased variable, where the dominator is target of an assignment.
    +-----------------------------+
    |      printf(0x804a00c)      |
    |        v#1 = &(x#1)         |
    |        v#2 = &(y#1)         |
    |    scanf(0x804a01f, v#1)    |
    |          u#1 = x#2          |
    | if u#1 >= 0xc then 1 else 2 | -+
    +-----------------------------+  |
      |                              |
      |                              |
      v                              |
    +-----------------------------+  |
    |          w#2 = x#2          |  |
    |          z#2 = w#2          |  |
    |   printf(0x804a03c, z#2)    |  |
    |        z#3 = &(x#3)         |  |
    |    scanf(0x804a01f, z#3)    |  |
    |          w#3 = x#4          |  |
    |          z#4 = w#3          |  |
    |   printf(0x804a0c8, z#4)    |  |
    |        z#5 = &(x#5)         |  |
    |    scanf(0x804a01f, z#5)    |  |
    +-----------------------------+  |
      |                              |
      |                              |
      v                              |
    +-----------------------------+  |
    |      z#6 = ϕ(v#1,z#5)       |  |
    |      w#4 = ϕ(u#1,w#3)       |  |
    |      x#7 = ϕ(x#2,x#6)       |  |
    |          w#5 = x#7          |  |
    |      w#6 = (w#5 * 0xc)      |  |
    |          x#8 = w#6          |  |
    |          w#7 = x#8          |  |
    |          u#2 = y#8          |  |
    |          z#7 = w#7          |  |
    |   printf(0x804a05d, z#7)    |  |
    |          w#8 = 0x0          |  |
    |         return 0x0          | <+
    +-----------------------------+
    """
    list_instructions, aliased_variables, task = construct_graph_aliased(6)

    InsertMissingDefinitions().run(task)

    assert [node.instructions for node in task.graph.nodes] == [
        [
            list_instructions[0],
            Assignment(aliased_variables[0], Variable("x", Integer.int32_t(), 0, is_aliased=True)),
            Assignment(aliased_variables[8], Variable("y", Integer.int32_t(), 0, is_aliased=True)),
            list_instructions[1],
            list_instructions[-3],
            list_instructions[2],
            Relation(aliased_variables[1], aliased_variables[0]),
            Assignment(aliased_variables[9], aliased_variables[8]),
        ]
        + list_instructions[3:5],
        list_instructions[5:8]
        + [Assignment(aliased_variables[2], aliased_variables[1]), Assignment(aliased_variables[10], aliased_variables[9])]
        + list_instructions[8:10]
        + [Relation(aliased_variables[3], aliased_variables[2]), Assignment(aliased_variables[11], aliased_variables[10])]
        + list_instructions[10:13]
        + [Assignment(aliased_variables[4], aliased_variables[3]), Assignment(aliased_variables[12], aliased_variables[11])]
        + list_instructions[13:15]
        + [Relation(aliased_variables[5], aliased_variables[4]), Assignment(aliased_variables[13], aliased_variables[12])],
        list_instructions[15:18]
        + [list_instructions[-1]]
        + list_instructions[18:21]
        + [Assignment(aliased_variables[15], aliased_variables[14]), list_instructions[21], list_instructions[-2]]
        + list_instructions[22:24]
        + [
            Assignment(Variable("x", Integer.int32_t(), 9, is_aliased=True), aliased_variables[7]),
            Assignment(Variable("y", Integer.int32_t(), 9, is_aliased=True), aliased_variables[15]),
        ]
        + list_instructions[24:26],
    ] or [node.instructions for node in task.graph.nodes] == [
        [
            list_instructions[0],
            Assignment(aliased_variables[8], Variable("y", Integer.int32_t(), 0, is_aliased=True)),
            Assignment(aliased_variables[0], Variable("x", Integer.int32_t(), 0, is_aliased=True)),
            list_instructions[1],
            list_instructions[-3],
            list_instructions[2],
            Assignment(aliased_variables[9], aliased_variables[8]),
            Relation(aliased_variables[1], aliased_variables[0]),
        ]
        + list_instructions[3:5],
        list_instructions[5:8]
        + [Assignment(aliased_variables[10], aliased_variables[9]), Assignment(aliased_variables[2], aliased_variables[1])]
        + list_instructions[8:10]
        + [Assignment(aliased_variables[11], aliased_variables[10]), Relation(aliased_variables[3], aliased_variables[2])]
        + list_instructions[10:13]
        + [Assignment(aliased_variables[12], aliased_variables[11]), Assignment(aliased_variables[4], aliased_variables[3])]
        + list_instructions[13:15]
        + [Assignment(aliased_variables[13], aliased_variables[12]), Relation(aliased_variables[5], aliased_variables[4])],
        list_instructions[15:18]
        + [list_instructions[-1]]
        + list_instructions[18:21]
        + [Assignment(aliased_variables[15], aliased_variables[14]), list_instructions[21], list_instructions[-2]]
        + list_instructions[22:24]
        + [
            Assignment(Variable("y", Integer.int32_t(), 9, is_aliased=True), aliased_variables[15]),
            Assignment(Variable("x", Integer.int32_t(), 9, is_aliased=True), aliased_variables[7]),
        ]
        + list_instructions[24:26],
    ]


def test_undefined_aliased_variable_target_mem_phi():
    """
    Fails, because the undefined aliased variable should be target of a Phi-function
    +-----------------------------+
    |      printf(0x804a00c)      |
    |        v#1 = &(x#1)         |
    |          v#2 = y#1          |
    |    scanf(0x804a01f, v#1)    |
    |          u#1 = x#2          |
    | if u#1 >= 0xc then 1 else 2 | -+
    +-----------------------------+  |
      |                              |
      |                              |
      v                              |
    +-----------------------------+  |
    |          w#2 = x#2          |  |
    |          z#2 = w#2          |  |
    |   printf(0x804a03c, z#2)    |  |
    |        z#3 = &(x#3)         |  |
    |    scanf(0x804a01f, z#3)    |  |
    |          w#3 = x#4          |  |
    |          z#4 = w#3          |  |
    |   printf(0x804a0c8, z#4)    |  |
    |        z#5 = &(x#5)         |  |
    |    scanf(0x804a01f, z#5)    |  |
    +-----------------------------+  |
      |                              |
      |                              |
      v                              |
    +-----------------------------+  |
    |      z#6 = ϕ(v#1,z#5)       |  |
    |      w#4 = ϕ(u#1,w#3)       |  |
    |      x#7 = ϕ(x#2,x#6)       |  |
    |          w#5 = x#7          |  |
    |          u#2 = y#7          |  |
    |      w#6 = (w#5 * 0xc)      |  |
    |          x#8 = w#6          |  |
    |          w#7 = x#8          |  |
    |          z#7 = w#7          |  |
    |   printf(0x804a05d, z#7)    |  |
    |          w#8 = 0x0          |  |
    |         return 0x0          | <+
    +-----------------------------+
    """
    _, _, task = construct_graph_aliased(7)

    with pytest.raises(ValueError):
        InsertMissingDefinitions().run(task)


def test_memory_instruction_before_phi_instruction():
    """
    Fails, because there is an instruction before a phi-instruction in a basic block
    +-----------------------------+
    |      printf(0x804a00c)      |
    |        v#1 = &(x#1)         |
    |    scanf(0x804a01f, v#1)    |
    |          u#1 = x#2          |
    | if u#1 >= 0xc then 1 else 2 | -+
    +-----------------------------+  |
      |                              |
      |                              |
      v                              |
    +-----------------------------+  |
    |          w#2 = x#2          |  |
    |          z#2 = w#2          |  |
    |   printf(0x804a03c, z#2)    |  |
    |        z#3 = &(x#3)         |  |
    |    scanf(0x804a01f, z#3)    |  |
    |          w#3 = x#4          |  |
    |          z#4 = w#3          |  |
    |   printf(0x804a0c8, z#4)    |  |
    |        z#5 = &(x#5)         |  |
    |    scanf(0x804a01f, z#5)    |  |
    +-----------------------------+  |
      |                              |
      |                              |
      v                              |
    +-----------------------------+  |
    |      z#6 = ϕ(v#1,z#5)       |  |
    |      w#4 = ϕ(u#1,w#3)       |  |
    |   printf(0x804a05d, z#7)    |  |
    |      x#8 = ϕ(x#2,x#6)       |  |
    |          w#7 = x#7          | <+
    +-----------------------------+
    """
    _, _, task = construct_graph_aliased(8)

    with pytest.raises(ValueError):
        InsertMissingDefinitions().run(task)


def test_undefined_aliased_variable_aliased_zero_used():
    """
    aliased variable with label zero is used.
    +------------------------+     +-----------------------------+
    | printf(0x804a03c, z#2) |     |                             |
    |      z#3 = &(x#3)      |     |         u#0 = &x#0          |
    | scanf(0x804a01f, z#3)  |     | if u#0 >= 0xc then 1 else 2 |
    |       w#3 = x#4        | <-- |                             |
    +------------------------+     +-----------------------------+
                                     |
                                     |
                                     v
                                   +-----------------------------+
                                   |      printf(0x804a00c)      |
                                   |        v#1 = &(x#1)         |
                                   |    scanf(0x804a01f, v#1)    |
                                   |          u#1 = x#2          |
                                   +-----------------------------+
    """
    list_instructions, aliased_variables, task = construct_graph_aliased(9)

    InsertMissingDefinitions().run(task)

    assert [node.instructions for node in task.graph.nodes] == [
        [
            Assignment(
                Variable("u", Integer.int32_t(), 0),
                UnaryOperation(OperationType.address, [Variable("x", Integer.int32_t(), 0, is_aliased=True)]),
            ),
            Branch(Condition(OperationType.greater_or_equal, [Variable("u", Integer.int32_t(), 0), Constant(0xC)], Integer(1))),
        ],
        [list_instructions[0], Assignment(aliased_variables[0], Variable("x", Integer.int32_t(), 0, is_aliased=True))]
        + list_instructions[1:3]
        + [Relation(aliased_variables[1], aliased_variables[0]), list_instructions[3]],
        [list_instructions[7], Assignment(aliased_variables[2], Variable("x", Integer.int32_t(), 0, is_aliased=True))]
        + list_instructions[8:10]
        + [Relation(aliased_variables[3], aliased_variables[2]), list_instructions[10]],
    ]


def test_memory_version_does_not_exist():
    """The aliased variable v_4 is not defined but no assignment writes the memory version 4."""

    aliased_x = [Variable("x", Integer.int32_t(), i, is_aliased=True) for i in range(5)]
    var_v = [Variable("v", Integer.int32_t(), i) for i in range(5)]
    instructions = [
        Assignment(var_v[1], UnaryOperation(OperationType.address, [aliased_x[0]])),
        Assignment(ListOperation([]), Call(function_symbol("scanf"), [Constant(0x804A01F), var_v[1]], writes_memory=1)),
        Assignment(var_v[2], BinaryOperation(OperationType.plus, [aliased_x[1], Constant(5)])),
        Assignment(aliased_x[2], BinaryOperation(OperationType.multiply, [aliased_x[1], Constant(3)])),
        Assignment(ListOperation([]), Call(function_symbol("printf"), [Constant(0x804A00C), aliased_x[2]], writes_memory=3)),
        Assignment(var_v[4], aliased_x[4]),
    ]

    cfg = ControlFlowGraph()
    task = DecompilerTask("test", cfg)
    cfg.add_node(BasicBlock(1, instructions))

    with pytest.raises(ValueError):
        InsertMissingDefinitions().run(task)


def test_same_instruction_with_different_memory_version():
    """We have two times the same instruction with different memory versions and have to add the instructions at the correct position."""
    aliased_x = [Variable("x", Integer.int32_t(), i, is_aliased=True) for i in range(5)]
    aliased_y = [Variable("y", Integer.int32_t(), i, is_aliased=True) for i in range(5)]
    esi = Variable("esi", Integer.int32_t(), 3)
    var_v = [Variable("v", Integer.int32_t(), i) for i in range(5)]
    instructions = [
        Assignment(UnaryOperation(OperationType.dereference, [esi], writes_memory=1), Constant(3)),
        Assignment(var_v[1], aliased_x[1]),
        Assignment(ListOperation([]), Call(function_symbol("printf"), [Constant(0x804A00C), var_v[1]], writes_memory=2)),
        Assignment(var_v[2], aliased_y[2]),
        Assignment(ListOperation([]), Call(function_symbol("printf"), [Constant(0x804A00C), var_v[2]], writes_memory=3)),
        Assignment(UnaryOperation(OperationType.dereference, [esi], writes_memory=4), Constant(3)),
        Assignment(var_v[3], Constant(3)),
        Return([Constant(3)]),
    ]

    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(1, instructions))
    task = DecompilerTask("test", cfg)

    InsertMissingDefinitions().run(task)

    assert list(task.graph.instructions) == [
        Assignment(UnaryOperation(OperationType.dereference, [esi], writes_memory=1), Constant(3)),
        Assignment(aliased_x[1], aliased_x[0]),
        Assignment(aliased_y[1], aliased_y[0]),
        Assignment(var_v[1], aliased_x[1]),
        Assignment(ListOperation([]), Call(function_symbol("printf"), [Constant(0x804A00C), var_v[1]], writes_memory=2)),
        Assignment(aliased_x[2], aliased_x[1]),
        Assignment(aliased_y[2], aliased_y[1]),
        Assignment(var_v[2], aliased_y[2]),
        Assignment(ListOperation([]), Call(function_symbol("printf"), [Constant(0x804A00C), var_v[2]], writes_memory=3)),
        Assignment(aliased_x[3], aliased_x[2]),
        Assignment(aliased_y[3], aliased_y[2]),
        Assignment(UnaryOperation(OperationType.dereference, [esi], writes_memory=4), Constant(3)),
        Assignment(aliased_x[4], aliased_x[3]),
        Assignment(aliased_y[4], aliased_y[3]),
        Assignment(var_v[3], Constant(3)),
        Return([Constant(3)]),
    ] or list(task.graph.instructions) == [
        Assignment(UnaryOperation(OperationType.dereference, [esi], writes_memory=1), Constant(3)),
        Assignment(aliased_y[1], aliased_y[0]),
        Assignment(aliased_x[1], aliased_x[0]),
        Assignment(var_v[1], aliased_x[1]),
        Assignment(ListOperation([]), Call(function_symbol("printf"), [Constant(0x804A00C), var_v[1]], writes_memory=2)),
        Assignment(aliased_y[2], aliased_y[1]),
        Assignment(aliased_x[2], aliased_x[1]),
        Assignment(var_v[2], aliased_y[2]),
        Assignment(ListOperation([]), Call(function_symbol("printf"), [Constant(0x804A00C), var_v[2]], writes_memory=3)),
        Assignment(aliased_y[3], aliased_y[2]),
        Assignment(aliased_x[3], aliased_x[2]),
        Assignment(UnaryOperation(OperationType.dereference, [esi], writes_memory=4), Constant(3)),
        Assignment(aliased_y[4], aliased_y[3]),
        Assignment(aliased_x[4], aliased_x[3]),
        Assignment(var_v[3], Constant(3)),
        Return([Constant(3)]),
    ]
