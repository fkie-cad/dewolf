from typing import List, Tuple

import pytest
from decompiler.pipeline.controlflowanalysis.restructuring_commons.graphslice import GraphSlice
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock, TransitionCFG
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch
from decompiler.structures.pseudo.operations import Condition, OperationType
from decompiler.structures.pseudo.typing import Integer


def variable(name: str) -> Variable:
    """A test variable as an unsigned 32bit integer."""
    return Variable(name, vartype=Integer.int32_t())


@pytest.fixture()
def graph_dream_paper() -> Tuple[TransitionCFG, List[TransitionBlock]]:
    graph = ControlFlowGraph()
    vertices = [
        # A
        BasicBlock(0, instructions=[Branch(Condition(OperationType.equal, [variable(name="a"), Constant(0)]))]),
        # b1
        BasicBlock(1, instructions=[Branch(Condition(OperationType.equal, [variable(name="b"), Constant(0)]))]),
        # n4
        BasicBlock(2, instructions=[Assignment(variable(name="j"), Constant(42))]),
        # b2
        BasicBlock(3, instructions=[Branch(Condition(OperationType.equal, [variable(name="c"), Constant(0)]))]),
        # n6
        BasicBlock(4, instructions=[Assignment(variable(name="k"), Constant(42))]),
        # n5
        BasicBlock(5, instructions=[Assignment(variable(name="l"), Constant(42))]),
        # n7
        BasicBlock(6, instructions=[Assignment(variable(name="m"), Constant(42))]),
        # c1
        BasicBlock(7, instructions=[Branch(Condition(OperationType.equal, [variable(name="d"), Constant(0)]))]),
        # n1
        BasicBlock(8, instructions=[Assignment(variable(name="n"), Constant(42))]),
        # c2
        BasicBlock(9, instructions=[Branch(Condition(OperationType.equal, [variable(name="e"), Constant(0)]))]),
        # n2
        BasicBlock(10, instructions=[Assignment(variable(name="o"), Constant(42))]),
        # n3
        BasicBlock(11, instructions=[Assignment(variable(name="p"), Constant(42))]),
        # c3
        BasicBlock(12, instructions=[Branch(Condition(OperationType.equal, [variable(name="f"), Constant(0)]))]),
        # n9
        BasicBlock(13, instructions=[Assignment(variable(name="q"), Constant(42))]),
        # d1
        BasicBlock(14, instructions=[Branch(Condition(OperationType.equal, [variable(name="g"), Constant(0)]))]),
        # d3
        BasicBlock(15, instructions=[Branch(Condition(OperationType.equal, [variable(name="h"), Constant(0)]))]),
        # d2
        BasicBlock(16, instructions=[Branch(Condition(OperationType.equal, [variable(name="i"), Constant(0)]))]),
        # n8
        BasicBlock(17, instructions=[Assignment(variable(name="r"), Constant(42))]),
    ]
    graph.add_nodes_from(vertices)
    edges = [
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
    graph.add_edges_from(edges)
    t_cfg: TransitionCFG = TransitionCFG.generate(graph)
    t_cfg_nodes: List[TransitionBlock] = sorted(t_cfg, key=lambda node: node.address)

    return t_cfg, t_cfg_nodes


def test_graph_slice_one_sink_1(graph_dream_paper):
    """
    Compute graph slice with source BasicBlock 7 (c1) and sink BasicBlock 12 (c3)
    """
    t_cfg, vertices = graph_dream_paper
    region = GraphSlice.compute_graph_slice_for_sink_nodes(t_cfg, vertices[7], [vertices[12]], back_edges=False)
    assert (
        len(region) == 4
        and len(region.edges) == 3
        and {(edge.source, edge.sink) for edge in region.edges}
        == {(vertices[7], vertices[9]), (vertices[9], vertices[11]), (vertices[11], vertices[12])}
    )


def test_graph_slice_one_sink_2(graph_dream_paper):
    """
    Compute graph slice with source BasicBlock 1 (b1) and sink BasicBlock 6 (n7)
    """
    t_cfg, vertices = graph_dream_paper
    region = GraphSlice.compute_graph_slice_for_sink_nodes(t_cfg, vertices[1], [vertices[6]], back_edges=False)
    assert (
        len(region) == 6
        and len(region.edges) == 7
        and {(edge.source, edge.sink) for edge in region.edges}
        == {
            (vertices[1], vertices[2]),
            (vertices[1], vertices[3]),
            (vertices[2], vertices[5]),
            (vertices[3], vertices[4]),
            (vertices[3], vertices[5]),
            (vertices[4], vertices[6]),
            (vertices[5], vertices[6]),
        }
    )


def test_graph_slice_for_sink_nodes_1(graph_dream_paper):
    """
    Compute graph slice with source BasicBlock 7 (c1) and sink vertices 8 and 12 (n1, c3)
    """
    t_cfg, vertices = graph_dream_paper
    region = GraphSlice.compute_graph_slice_for_sink_nodes(t_cfg, vertices[7], [vertices[8], vertices[12]], back_edges=False)
    assert (
        len(region) == 5
        and len(region.edges) == 4
        and {(edge.source, edge.sink) for edge in region.edges}
        == {(vertices[7], vertices[9]), (vertices[9], vertices[11]), (vertices[11], vertices[12]), (vertices[7], vertices[8])}
    )


def test_graph_slice_for_sink_nodes_2(graph_dream_paper):
    """
    Compute graph slice with source BasicBlock 14 (d1) and sink vertices 16 and 17 (d2, n8)
    """
    graph, vertices = graph_dream_paper
    region = GraphSlice.compute_graph_slice_for_sink_nodes(graph, vertices[14], [vertices[16], vertices[17]], back_edges=False)
    assert (
        len(region) == 4
        and len(region.edges) == 4
        and {(edge.source, edge.sink) for edge in region.edges}
        == {(vertices[14], vertices[15]), (vertices[15], vertices[17]), (vertices[14], vertices[16]), (vertices[16], vertices[17])}
    )


def test_graph_slice_one_region_1(graph_dream_paper):
    """
    Compute graph slice with source BasicBlock 1 (c1) for region R2.
    """
    graph, vertices = graph_dream_paper
    sub_region = set(vertices[1:7])
    region = GraphSlice.compute_graph_slice_for_region(graph, vertices[1], sub_region, back_edges=False)
    assert (
        len(region) == 6
        and len(region.edges) == 7
        and {(edge.source, edge.sink) for edge in region.edges}
        == {
            (vertices[1], vertices[2]),
            (vertices[1], vertices[3]),
            (vertices[2], vertices[5]),
            (vertices[3], vertices[4]),
            (vertices[3], vertices[5]),
            (vertices[4], vertices[6]),
            (vertices[5], vertices[6]),
        }
    )


def test_graph_slice_one_region_2(graph_dream_paper):
    """
    Compute graph slice with source BasicBlock 14 (d1) for region R3 cup {13 (n9)}.
    """
    graph, vertices = graph_dream_paper
    sub_region = set(vertices[13:])
    region = GraphSlice.compute_graph_slice_for_region(graph, vertices[14], sub_region, back_edges=False)
    assert (
        len(region) == 4
        and len(region.edges) == 4
        and {(edge.source, edge.sink) for edge in region.edges}
        == {
            (vertices[14], vertices[15]),
            (vertices[14], vertices[16]),
            (vertices[15], vertices[13]),
            (vertices[16], vertices[13]),
        }
    )
