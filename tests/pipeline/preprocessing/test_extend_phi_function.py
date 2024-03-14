from typing import List

import decompiler.structures.pseudo.expressions as expressions
import decompiler.structures.pseudo.instructions as instructions
import pytest
from decompiler.pipeline.preprocessing import PhiFunctionFixer
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, UnconditionalEdge
from decompiler.structures.pseudo.typing import Integer
from decompiler.task import DecompilerTask


def construct_graph(number: int) -> (List[BasicBlock], ControlFlowGraph):
    defined_instructions = [
        instructions.Phi(
            expressions.Variable("v", Integer.int32_t(), 0),
            [expressions.Variable("v", Integer.int32_t(), 1), expressions.Variable("v", Integer.int32_t(), 2)],
        ),
        instructions.Assignment(expressions.Variable("v", Integer.int32_t(), 1), expressions.Variable("u", Integer.int32_t())),
        instructions.Assignment(expressions.Variable("v", Integer.int32_t(), 2), expressions.Constant(5)),
        instructions.Assignment(expressions.Variable("u", Integer.int32_t()), expressions.Constant(3)),
    ]
    node = []
    for index, instruction in enumerate(defined_instructions):
        node.append(BasicBlock(index, instructions=[instruction]))
    cfg = ControlFlowGraph()
    task = DecompilerTask(name="test", function_identifier="", cfg=cfg)
    cfg.add_edges_from(
        [
            UnconditionalEdge(node[3], node[2]),
            UnconditionalEdge(node[3], node[1]),
            UnconditionalEdge(node[2], node[0]),
            UnconditionalEdge(node[1], node[0]),
        ]
    )
    # First Graph
    if number == 1:
        return node, task

    # Second and Third Graph
    if number == 2:
        node[1].replace_instruction(defined_instructions[1], [defined_instructions[3]])
        node[3].replace_instruction(
            defined_instructions[3],
            [instructions.Assignment(expressions.Variable("v", Integer.int32_t(), 1), expressions.Variable("w", Integer.int32_t(), 0))],
        )
        return node, task
    if number == 3:
        node[1].replace_instruction(
            defined_instructions[1], [instructions.Assignment(expressions.Variable("w", Integer.int32_t(), 1), expressions.Constant(3))]
        )
        return node, task
    # Fourth Graph:
    elif number == 4:
        node += [
            BasicBlock(4, instructions=[instructions.Assignment(expressions.Variable("u", Integer.int32_t(), 1), expressions.Constant(7))]),
            BasicBlock(5, instructions=[instructions.Assignment(expressions.Variable("u", Integer.int32_t(), 2), expressions.Constant(6))]),
        ]
        cfg.remove_edge(cfg.get_edge(node[1], node[0]))
        cfg.add_edges_from(
            [
                UnconditionalEdge(node[1], node[4]),
                UnconditionalEdge(node[4], node[0]),
                UnconditionalEdge(node[1], node[5]),
                UnconditionalEdge(node[5], node[0]),
            ]
        )
        return node, task
    # Fifth Graph:
    if number == 5:
        node += [
            BasicBlock(4, instructions=[instructions.Assignment(expressions.Variable("u", Integer.int32_t(), 1), expressions.Constant(7))])
        ]
        node[1].replace_instruction(
            defined_instructions[1], [instructions.Assignment(expressions.Variable("w", Integer.int32_t(), 1), expressions.Constant(3))]
        )
        cfg.add_edges_from([UnconditionalEdge(node[3], node[4]), UnconditionalEdge(node[4], node[0])])
        return node, task
    # Sixth Graph:
    if number == 6:
        node[1].replace_instruction(defined_instructions[1], [defined_instructions[3]])
        node[3].replace_instruction(
            defined_instructions[3],
            [
                instructions.Assignment(expressions.Variable("v", Integer.int32_t(), 1), expressions.Variable("v", Integer.int32_t(), 0)),
                instructions.Assignment(expressions.Variable("v", Integer.int32_t(), 2), expressions.Variable("v", Integer.int32_t(), 1)),
            ],
        )
        node[2].replace_instruction(
            defined_instructions[2], [instructions.Assignment(expressions.Variable("u", Integer.int32_t()), expressions.Constant(4))]
        )
        return node, task

    if number <= 8:
        node[1].replace_instruction(defined_instructions[1], [defined_instructions[3]])
        node[3].replace_instruction(
            defined_instructions[3], [instructions.Assignment(expressions.Variable("x", Integer.int32_t()), expressions.Constant(2))]
        )
        node.append(BasicBlock(4, instructions=[defined_instructions[1]]))
        node.append(BasicBlock(4, instructions=[defined_instructions[1]]))
        cfg.remove_edge(cfg.get_edge(node[3], node[1]))
        cfg.add_edges_from([UnconditionalEdge(node[3], node[4]), UnconditionalEdge(node[2], node[1])])

        if number == 7:
            cfg.add_edge(UnconditionalEdge(node[4], node[1]))
        return node, task


def test_basic1_extend_phi_functions():
    node, task = construct_graph(1)
    PhiFunctionFixer().run(task)

    assert node[0].instructions[0].origin_block == {
        node[1]: expressions.Variable("v", Integer.int32_t(), 1),
        node[2]: expressions.Variable("v", Integer.int32_t(), 2),
    }


def test_basic2_extend_phi_functions():
    node, task = construct_graph(2)
    PhiFunctionFixer().run(task)

    assert node[0].instructions[0].origin_block == {
        node[1]: expressions.Variable("v", Integer.int32_t(), 1),
        node[2]: expressions.Variable("v", Integer.int32_t(), 2),
    }


def test_basic3_extend_phi_functions():
    node, task = construct_graph(3)
    PhiFunctionFixer().run(task)

    assert node[0].instructions[0].origin_block == {
        node[1]: expressions.Variable("v", Integer.int32_t(), 1),
        node[2]: expressions.Variable("v", Integer.int32_t(), 2),
    }


def test_more_entries1_extend_phi_functions():
    node, task = construct_graph(4)
    PhiFunctionFixer().run(task)

    assert node[0].instructions[0].origin_block == {
        node[4]: expressions.Variable("v", Integer.int32_t(), 1),
        node[5]: expressions.Variable("v", Integer.int32_t(), 1),
        node[2]: expressions.Variable("v", Integer.int32_t(), 2),
    }


def test_more_entries2_extend_phi_function():
    node, task = construct_graph(5)
    PhiFunctionFixer().run(task)

    assert node[0].instructions[0].origin_block == {
        node[1]: expressions.Variable("v", Integer.int32_t(), 1),
        node[4]: expressions.Variable("v", Integer.int32_t(), 1),
        node[2]: expressions.Variable("v", Integer.int32_t(), 2),
    }


def test_variables_interfere_extend_phi_functions():
    _, task = construct_graph(6)

    try:
        with pytest.raises(ValueError):
            PhiFunctionFixer().run(task)
    except ValueError:
        with pytest.raises(ValueError):
            PhiFunctionFixer().run(task)


def test_not_dominated_extend_phi_functions():
    _, task = construct_graph(7)

    with pytest.raises(ValueError):
        PhiFunctionFixer().run(task)


def test_one_variable_not_used_extend_phi_functions():
    _, task = construct_graph(8)

    with pytest.raises(ValueError):
        PhiFunctionFixer().run(task)


def test_phi_function_in_head():
    """
    +--------------------+
    |        0.          | ---+
    | u#1 = ϕ(v#0, u#2)  |    |
    | u#2 = 10           | <--+
    +--------------------+
    """
    u1 = expressions.Variable("u", Integer.int32_t(), 1)
    u2 = expressions.Variable("u", Integer.int32_t(), 2)
    v0 = expressions.Variable("v", Integer.int32_t(), 0)
    node = BasicBlock(0, [instructions.Phi(u1, [v0, u2]), instructions.Assignment(u2, expressions.Constant(10))])
    cfg = ControlFlowGraph()
    cfg.add_node(node)
    cfg.add_edge(UnconditionalEdge(node, node))
    task = DecompilerTask(name="test", function_identifier="", cfg=cfg)
    PhiFunctionFixer().run(task)

    assert node.instructions[0].origin_block == {None: v0, node: u2}
