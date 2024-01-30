"""Module implementing tests for the RootedGraph implementation."""

from typing import Tuple

from decompiler.structures.graphs.basic import BasicEdge, BasicNode
from decompiler.structures.graphs.rootedgraph import RootedGraph
from pytest import raises


class TestRootedGraph:
    """Test the dominator functionality of the graph interface."""

    @staticmethod
    def get_graph() -> Tuple[RootedGraph, Tuple[BasicNode, ...], Tuple[BasicEdge, ...]]:
        """
        Return a graph for dominator-tests.

                  +---+
                  | 0 |
                  +---+
                    |
                    |
                    v
        +---+     +--------+     +---+
        | 3 | <-- |   1    | --> | 5 |
        +---+     +--------+     +---+
          |         |    ^
          |         |    |
          |         v    |
          |       +---+  |
          |       | 2 |  |
          |       +---+  |
          |         |    |
          |         |    |
          |         v    |
          |       +---+  |
          +-----> | 4 | -+
                  +---+
        """
        graph = RootedGraph()
        nodes = tuple(BasicNode(i) for i in range(6))
        edges = (
            BasicEdge(nodes[0], nodes[1]),
            BasicEdge(nodes[1], nodes[2]),
            BasicEdge(nodes[2], nodes[4]),
            BasicEdge(nodes[1], nodes[3]),
            BasicEdge(nodes[3], nodes[4]),
            BasicEdge(nodes[4], nodes[1]),
            BasicEdge(nodes[1], nodes[5]),
        )
        graph.add_nodes_from(nodes)
        graph.add_edges_from(edges)
        return graph, nodes, edges

    def test_dominator_tree(self):
        """Test the buffered dominator tree."""
        assert len(RootedGraph().dominator_tree) == 0
        graph, nodes, edges = self.get_graph()
        tree = graph.dominator_tree
        assert len(tree.edges) == 5
        assert (
            tree.get_edge(nodes[0], nodes[1])
            and tree.get_edge(nodes[1], nodes[2])
            and tree.get_edge(nodes[1], nodes[3])
            and tree.get_edge(nodes[1], nodes[4])
            and tree.get_edge(nodes[1], nodes[5])
        )
        graph.remove_node(nodes[2])
        assert tree != graph.dominator_tree
        tree = graph.dominator_tree
        assert len(tree.edges) == 4
        assert (
            tree.get_edge(nodes[0], nodes[1])
            and tree.get_edge(nodes[1], nodes[3])
            and tree.get_edge(nodes[3], nodes[4])
            and tree.get_edge(nodes[1], nodes[5])
        )

    def test_is_dominating(self):
        """Test the is_dominating function of buffered graphs."""
        graph, nodes, edges = self.get_graph()
        assert all((graph.is_dominating(nodes[0], other) for other in nodes[1:]))
        assert all((graph.is_dominating(nodes[1], other) for other in nodes[2:]))
        graph.add_edge(BasicEdge(nodes[0], nodes[4]))
        assert not graph.is_dominating(nodes[1], nodes[4])

    def test_find_common_dominator(self):
        """Test the find_common_dominator function of buffered graphs."""
        graph, nodes, edges = self.get_graph()
        assert graph.find_common_dominator(nodes[0], nodes[1]) == nodes[0]
        assert graph.find_common_dominator(nodes[2], nodes[3], nodes[4]) == nodes[1]

    def test_remove_head(self):
        """Test that an error is raised thwn an attempt to remove the head from the graph occures."""
        graph, nodes, edges = self.get_graph()
        with raises(Exception):
            graph.remove_node(nodes[0])

    def test_set_root(self):
        """Test that the root node is set correctly."""
        graph, nodes, edges = self.get_graph()
        assert graph.root == nodes[0]
        graph.root = nodes[1]
        assert graph.root == nodes[1]
