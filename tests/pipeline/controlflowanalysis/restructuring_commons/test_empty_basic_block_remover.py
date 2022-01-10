import pytest
from decompiler.pipeline.controlflowanalysis.restructuring_commons.empty_basic_block_remover import EmptyBasicBlockRemover
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import FalseCase, SwitchCase, TrueCase, UnconditionalEdge
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, IndirectBranch
from decompiler.structures.pseudo.operations import Condition, OperationType
from decompiler.structures.pseudo.typing import Integer


def variable(name="a", version=0, ssa_name=None) -> Variable:
    """A test variable as an unsigned 32bit integer."""
    return Variable(name, ssa_label=version, vartype=Integer.int32_t(), ssa_name=ssa_name)


def test_empty_graph_one_basic_block():
    """
    +----+
    | 0. |
    +----+
    """
    graph = ControlFlowGraph()
    graph.add_node(
        BasicBlock(
            0,
            instructions=[],
        )
    )
    EmptyBasicBlockRemover(graph).remove()

    assert graph.nodes == tuple()


def test_empty_graph_two_basic_blocks():
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
    graph = ControlFlowGraph()
    graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                instructions=[],
            ),
            BasicBlock(
                1,
                instructions=[],
            ),
        ]
    )
    graph.add_edge(UnconditionalEdge(vertices[0], vertices[1]))
    EmptyBasicBlockRemover(graph).remove()

    assert graph.nodes == tuple()


def test_empty_graph_with_conditions_1():
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
    graph = ControlFlowGraph()
    graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Branch(Condition(OperationType.less, [variable("a"), Constant(2)]))]),
            BasicBlock(1, instructions=[]),
            BasicBlock(2, instructions=[Branch(Condition(OperationType.less, [variable("b"), Constant(2)]))]),
            BasicBlock(3, instructions=[]),
            BasicBlock(4, instructions=[]),
        ]
    )
    graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[4]),
            TrueCase(vertices[2], vertices[3]),
            FalseCase(vertices[2], vertices[4]),
            UnconditionalEdge(vertices[3], vertices[4]),
        ]
    )
    EmptyBasicBlockRemover(graph).remove()

    assert graph.nodes == tuple()


def test_empty_graph_with_conditions_2():
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
    graph = ControlFlowGraph()
    graph.add_nodes_from(
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
    graph.add_edges_from(
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
    EmptyBasicBlockRemover(graph).remove()

    assert graph.nodes == tuple()


def test_empty_graph_with_switch():
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
    graph = ControlFlowGraph()
    graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[IndirectBranch(variable("a"))]),
            BasicBlock(1, instructions=[]),
            BasicBlock(2, instructions=[]),
            BasicBlock(3, instructions=[]),
            BasicBlock(4, instructions=[]),
            BasicBlock(5, instructions=[]),
        ]
    )
    graph.add_edges_from(
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
    EmptyBasicBlockRemover(graph).remove()

    assert graph.nodes == tuple()


def test_empty_graph_with_loop():
    """
    +----+     +---------------+
    | 1. |     |      0.       |
    |    | <-- | if(a#0 < 0x2) |
    +----+     +---------------+
      |          |
      |          |
      |          v
      |        +---------------+
      |        |      2.       | <+
      |        +---------------+  |
      |          |                |
      |          |                |
      |          v                |
      |        +---------------+  |
      |        |      3.       |  |
      |        | if(b#0 < 0x2) | -+
      |        +---------------+
      |          |
      |          |
      |          v
      |        +---------------+
      +------> |      4.       |
               +---------------+
    """
    graph = ControlFlowGraph()
    graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Branch(Condition(OperationType.less, [variable("a"), Constant(2)]))]),
            BasicBlock(1, instructions=[]),
            BasicBlock(2, instructions=[]),
            BasicBlock(3, instructions=[Branch(Condition(OperationType.less, [variable("b"), Constant(2)]))]),
            BasicBlock(4, instructions=[]),
        ]
    )
    graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[4]),
            UnconditionalEdge(vertices[2], vertices[3]),
            FalseCase(vertices[3], vertices[2]),
            TrueCase(vertices[3], vertices[4]),
        ]
    )
    EmptyBasicBlockRemover(graph).remove()

    assert (
        set(graph.nodes) == {vertices[0], vertices[3], vertices[4]}
        and set(graph.edges)
        == {
            TrueCase(vertices[0], vertices[4]),
            FalseCase(vertices[0], vertices[3]),
            FalseCase(vertices[3], vertices[3]),
            TrueCase(vertices[3], vertices[4]),
        }
        and not vertices[0].is_empty()
        and not vertices[3].is_empty()
    )


def test_graph_with_switch_empty_nodes1():
    """
                      +-----------+
                      |    4.     | ------------+
                      +-----------+             |
                        ^                       |
                        |                       |
                        |                       |
    +-----------+     +-----------+     +----+  |
    |    1.     |     |    0.     |     | 2. |  |
    | a#0 = 0x2 | <-- |  jmp a#0  | --> |    |  |
    +-----------+     +-----------+     +----+  |
      |                 |                 |     |
      |                 |                 |     |
      |                 v                 |     |
      |               +-----------+       |     |
      |               |    3.     |       |     |
      |               +-----------+       |     |
      |                 |                 |     |
      |                 |                 |     |
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
    graph = ControlFlowGraph()
    graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[IndirectBranch(variable("a"))]),
            BasicBlock(1, instructions=[Assignment(variable("a"), Constant(2))]),
            BasicBlock(2, instructions=[]),
            BasicBlock(3, instructions=[]),
            BasicBlock(4, instructions=[]),
            BasicBlock(5, instructions=[Assignment(variable("a"), Constant(3))]),
            BasicBlock(6, instructions=[]),
        ]
    )
    graph.add_edges_from(
        [
            SwitchCase(vertices[0], vertices[1], [Constant(1)]),
            SwitchCase(vertices[0], vertices[2], [Constant(2)]),
            SwitchCase(vertices[0], vertices[3], [Constant(3)]),
            SwitchCase(vertices[0], vertices[4], [Constant(4)]),
            UnconditionalEdge(vertices[3], vertices[5]),
            UnconditionalEdge(vertices[4], vertices[5]),
            UnconditionalEdge(vertices[1], vertices[6]),
            UnconditionalEdge(vertices[2], vertices[6]),
            UnconditionalEdge(vertices[5], vertices[6]),
        ]
    )
    EmptyBasicBlockRemover(graph).remove()

    assert set(graph.nodes) == {vertices[0], vertices[1], vertices[2], vertices[5]} and set(graph.edges) == {
        SwitchCase(vertices[0], vertices[1], [Constant(1)]),
        SwitchCase(vertices[0], vertices[2], [Constant(2)]),
        SwitchCase(vertices[0], vertices[5], [Constant(3), Constant(4)]),
    }


def test_graph_with_switch_empty_nodes2():
    """
               +-----------+
               |    6.     |
               | a#0 = 0xa | ------------------------------+
               +-----------+                               |
                 ^                                         |
                 |                                         |
                 |                                         |
    +----+     +-----------------------------+     +----+  |
    | 2. |     |             0.              |     | 4. |  |
    |    | <-- |           jmp a#0           | --> |    |  |
    +----+     +-----------------------------+     +----+  |
      |          |                 |                 |     |
      |          |                 |                 |     |
      |          v                 v                 |     |
      |        +-----------+     +-----------+       |     |
      |        |    3.     |     |    1.     |       |     |
      |        |           |     | a#0 = 0x2 |       |     |
      |        +-----------+     +-----------+       |     |
      |          |                 |                 |     |
      |          |                 |                 |     |
      |          v                 |                 |     |
      |        +-----------+       |                 |     |
      |        |    5.     |       |                 |     |
      |        | a#0 = 0x3 | <-----+-----------------+     |
      |        +-----------+       |                       |
      |          |                 |                       |
      |          |                 |                       |
      |          v                 v                       |
      |        +-----------------------------+             |
      +------> |             7.              | <-----------+
               +-----------------------------+
    """
    graph = ControlFlowGraph()
    graph.add_nodes_from(
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
    graph.add_edges_from(
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
    EmptyBasicBlockRemover(graph).remove()

    assert set(graph.nodes) == {vertices[0], vertices[1], vertices[2], vertices[5], vertices[6]} and set(graph.edges) == {
        SwitchCase(vertices[0], vertices[1], cases=[Constant(1)]),
        SwitchCase(vertices[0], vertices[2], cases=[Constant(2)]),
        SwitchCase(vertices[0], vertices[5], cases=[Constant(3), Constant(4)]),
        SwitchCase(vertices[0], vertices[6], cases=[Constant(5)]),
    }


def test_empty_basic_block_after_removing():
    """
    +-----------+     +---------------+
    |    1.     |     |      0.       |
    | a#0 = 0x2 | <-- | if(a#0 < 0x2) |
    +-----------+     +---------------+
      |                 |
      |                 |
      |                 v
      |               +---------------+
      |               |      2.       |
      |               | if(b#0 < 0x2) | -+
      |               +---------------+  |
      |                 |                |
      |                 |                |
      |                 v                |
      |               +---------------+  |
      |               |      3.       |  |
      |               +---------------+  |
      |                 |                |
      |                 |                |
      |                 v                |
      |               +---------------+  |
      +-------------> |      4.       | <+
                      +---------------+

    """
    graph = ControlFlowGraph()
    graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Branch(Condition(OperationType.less, [variable("a"), Constant(2)]))]),
            BasicBlock(1, instructions=[Assignment(variable("a"), Constant(2))]),
            BasicBlock(2, instructions=[Branch(Condition(OperationType.less, [variable("b"), Constant(2)]))]),
            BasicBlock(3, instructions=[]),
            BasicBlock(4, instructions=[]),
        ]
    )
    graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[4]),
            TrueCase(vertices[2], vertices[3]),
            FalseCase(vertices[2], vertices[4]),
            UnconditionalEdge(vertices[3], vertices[4]),
        ]
    )
    EmptyBasicBlockRemover(graph).remove()

    assert set(graph.nodes) == {vertices[0], vertices[1], vertices[4]} and set(graph.edges) == {
        TrueCase(vertices[0], vertices[1]),
        FalseCase(vertices[0], vertices[4]),
    }


def test_do_not_remove_branch_edges():
    """
    +-----------+     +---------------+
    |    1.     |     |      0.       |
    | a#0 = 0x2 | <-- | if(a#0 < 0x2) |
    +-----------+     +---------------+
                         |
                         |
                         v
                       +---------------+
                       |      2.       |
                       +---------------+
    """
    graph = ControlFlowGraph()
    graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Branch(Condition(OperationType.less, [variable("a"), Constant(2)]))]),
            BasicBlock(1, instructions=[Assignment(variable("a"), Constant(2))]),
            BasicBlock(2, instructions=[]),
        ]
    )
    graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
        ]
    )
    EmptyBasicBlockRemover(graph).remove()

    assert set(graph.nodes) == {vertices[0], vertices[1], vertices[2]} and set(graph.edges) == {
        TrueCase(vertices[0], vertices[1]),
        FalseCase(vertices[0], vertices[2]),
    }


def test_do_not_remove_switch_edge():
    """
                      +-----------+
                      |    2.     |
                      +-----------+
                        ^
                        |
                        |
    +-----------+     +-----------+
    |    1.     |     |    0.     |
    | a#0 = 0x2 | <-- |  jmp a#0  |
    +-----------+     +-----------+
                        |
                        |
                        v
                      +-----------+
                      |    3.     |
                      | a#0 = 0x3 |
                      +-----------+
    """
    graph = ControlFlowGraph()
    graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[IndirectBranch(variable("a"))]),
            BasicBlock(1, instructions=[Assignment(variable("a"), Constant(2))]),
            BasicBlock(2, instructions=[]),
            BasicBlock(3, instructions=[Assignment(variable("a"), Constant(3))]),
        ]
    )
    graph.add_edges_from(
        [
            SwitchCase(vertices[0], vertices[1], [Constant(1)]),
            SwitchCase(vertices[0], vertices[2], [Constant(2)]),
            SwitchCase(vertices[0], vertices[3], [Constant(3)]),
        ]
    )
    EmptyBasicBlockRemover(graph).remove()

    assert set(graph.nodes) == {vertices[0], vertices[1], vertices[2], vertices[3]} and set(graph.edges) == {
        SwitchCase(vertices[0], vertices[1], [Constant(1)]),
        SwitchCase(vertices[0], vertices[2], [Constant(2)]),
        SwitchCase(vertices[0], vertices[3], [Constant(3)]),
    }


def test_all_predecessors_direct():
    graph = ControlFlowGraph()
    graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Branch(Condition(OperationType.less, [variable("a"), Constant(2)]))]),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.less, [variable("b"), Constant(2)]))]),
            BasicBlock(2, instructions=[Branch(Condition(OperationType.less, [variable("b"), Constant(5)]))]),
            BasicBlock(3, instructions=[Assignment(variable("b"), Constant(5))]),
            BasicBlock(4, instructions=[]),
            BasicBlock(5, instructions=[]),
        ]
    )
    graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            TrueCase(vertices[1], vertices[3]),
            FalseCase(vertices[1], vertices[4]),
            TrueCase(vertices[2], vertices[4]),
            FalseCase(vertices[2], vertices[5]),
        ]
    )
    EmptyBasicBlockRemover(graph).remove()

    assert (
        set(graph.nodes) == {vertices[0], vertices[1], vertices[2], vertices[3], vertices[4]}
        and set(graph.edges)
        == {
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            TrueCase(vertices[1], vertices[3]),
            FalseCase(vertices[1], vertices[4]),
        }
        and vertices[2].is_empty()
    )


def test_remove_switch1():
    graph = ControlFlowGraph()
    graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[IndirectBranch(variable("a"))]),
            BasicBlock(1, instructions=[]),
            BasicBlock(2, instructions=[]),
            BasicBlock(3, instructions=[]),
            BasicBlock(4, instructions=[Assignment(variable("a"), Constant(3))]),
        ]
    )
    graph.add_edges_from(
        [
            SwitchCase(vertices[0], vertices[1], [Constant(1)]),
            SwitchCase(vertices[0], vertices[2], [Constant(2)]),
            SwitchCase(vertices[0], vertices[3], [Constant(3)]),
            UnconditionalEdge(vertices[1], vertices[4]),
            UnconditionalEdge(vertices[2], vertices[4]),
            UnconditionalEdge(vertices[3], vertices[4]),
        ]
    )
    EmptyBasicBlockRemover(graph).remove()

    assert set(graph.nodes) == {vertices[4]}


def test_remove_switch2():
    graph = ControlFlowGraph()
    graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Assignment(variable("b"), Constant(2)), IndirectBranch(variable("a"))]),
            BasicBlock(1, instructions=[]),
            BasicBlock(2, instructions=[]),
            BasicBlock(3, instructions=[]),
            BasicBlock(4, instructions=[Assignment(variable("a"), Constant(3))]),
        ]
    )
    graph.add_edges_from(
        [
            SwitchCase(vertices[0], vertices[1], [Constant(1)]),
            SwitchCase(vertices[0], vertices[2], [Constant(2)]),
            SwitchCase(vertices[0], vertices[3], [Constant(3)]),
            UnconditionalEdge(vertices[1], vertices[4]),
            UnconditionalEdge(vertices[2], vertices[4]),
            UnconditionalEdge(vertices[3], vertices[4]),
        ]
    )
    EmptyBasicBlockRemover(graph).remove()

    assert (
        set(graph.nodes) == {vertices[0], vertices[4]}
        and set(graph.edges) == {UnconditionalEdge(vertices[0], vertices[4])}
        and vertices[0].instructions == [Assignment(variable("b"), Constant(2))]
    )


def test_empty_block_with_two_predecessors():
    graph = ControlFlowGraph()
    graph.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[]),
            BasicBlock(1, instructions=[Assignment(variable("a"), Constant(2))]),
            BasicBlock(2, instructions=[Assignment(variable("a"), Constant(3))]),
        ]
    )
    graph.add_edges_from([TrueCase(vertices[0], vertices[1]), FalseCase(vertices[0], vertices[2])])
    with pytest.raises(AssertionError):
        EmptyBasicBlockRemover(graph).remove()
