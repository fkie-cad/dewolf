"""Implementing tests for the GraphInterface."""
from typing import List, Tuple

import pytest
from decompiler.structures.graphs.basic import BasicEdge, BasicNode
from decompiler.structures.graphs.nxgraph import NetworkXGraph as Graph


class TestGraphInterface:
    """Test the three ordered iterator functions in the graph interface."""

    @pytest.fixture
    def nodes(self) -> List[BasicNode]:
        return [BasicNode(i) for i in range(10)]

    def test_equals(self, nodes):
        edges = [
            BasicEdge(nodes[0], nodes[1]),
            BasicEdge(nodes[1], nodes[2]),
            BasicEdge(nodes[2], nodes[3]),
            BasicEdge(nodes[2], nodes[1]),
            BasicEdge(nodes[1], nodes[4]),
            BasicEdge(nodes[1], nodes[5]),
            BasicEdge(nodes[4], nodes[5]),
            BasicEdge(nodes[4], nodes[6]),
        ]
        graph1 = Graph()
        graph1.add_nodes_from(nodes)
        graph1.add_edges_from(edges)
        graph2 = Graph()
        graph2.add_nodes_from(nodes)
        graph2.add_edges_from(edges[1:])
        assert graph1 != graph2
        assert graph2 == graph2.copy()
        graph2.add_edge(edges[0])
        assert graph1 == graph2
        graph3 = graph1.copy()
        assert graph1 == graph2 == graph3
        graph3.remove_node(nodes[0])
        assert graph3 != graph1

    def test_dfs(self, nodes):
        """
        Test the depth-first-search iteration.
        """
        graph = Graph()
        graph.add_nodes_from(nodes)
        graph.add_edges_from(
            [
                BasicEdge(nodes[0], nodes[1]),
                BasicEdge(nodes[1], nodes[3]),
                BasicEdge(nodes[1], nodes[4]),
                BasicEdge(nodes[0], nodes[2]),
                BasicEdge(nodes[2], nodes[5]),
                BasicEdge(nodes[5], nodes[2]),
            ]
        )
        assert tuple(graph.iter_depth_first(nodes[0])) == (
            nodes[0],
            nodes[1],
            nodes[3],
            nodes[4],
            nodes[2],
            nodes[5],
        )
        assert tuple(graph.iter_depth_first(nodes[2])) == (nodes[2], nodes[5])

    def test_bfs(self, nodes):
        """
        Test the breadth-first-search iteration.
        """
        graph = Graph()
        graph.add_nodes_from(nodes)
        graph.add_edges_from(
            [
                BasicEdge(nodes[0], nodes[1]),
                BasicEdge(nodes[1], nodes[3]),
                BasicEdge(nodes[1], nodes[4]),
                BasicEdge(nodes[0], nodes[2]),
                BasicEdge(nodes[2], nodes[5]),
                BasicEdge(nodes[5], nodes[2]),
            ]
        )
        assert tuple(graph.iter_breadth_first(nodes[0])) == (
            nodes[0],
            nodes[1],
            nodes[2],
            nodes[3],
            nodes[4],
            nodes[5],
        )

    def test_postorder(self, nodes):
        """
        Test whether post order iteration works correctly.

             +---+
             | 0 | -+
             +---+  |
               |    |
               |    |
               v    |
             +---+  |
             | 1 |  |
             +---+  |
               |    |
               |    |
               v    |
             +---+  |
          +- | 2 | <+
          |  +---+
          |    |
          |    |
          |    v
          |  +---+
          |  | 3 |
          |  +---+
          |    |
          |    |
          |    v
          |  +---+
          +> | 4 |
             +---+
               |
               |
               v
             +---+
             | 5 |
             +---+
        """
        graph = Graph()
        graph.add_edges_from(
            [
                BasicEdge(nodes[4], nodes[5]),
                BasicEdge(nodes[1], nodes[2]),
                BasicEdge(nodes[0], nodes[2]),
                BasicEdge(nodes[2], nodes[3]),
                BasicEdge(nodes[0], nodes[1]),
                BasicEdge(nodes[2], nodes[4]),
                BasicEdge(nodes[3], nodes[4]),
            ]
        )
        assert list(graph.iter_postorder()) == [nodes[5], nodes[4], nodes[3], nodes[2], nodes[1], nodes[0]]
        assert list(graph.iter_postorder(nodes[2])) == [nodes[5], nodes[4], nodes[3], nodes[2]]

        graph.add_edge(BasicEdge(nodes[2], nodes[0]))
        assert list(graph.iter_postorder(nodes[1])) == [nodes[5], nodes[4], nodes[3], nodes[0], nodes[2], nodes[1]] or list(
            graph.iter_postorder(nodes[1])
        ) == [
            nodes[0],
            nodes[5],
            nodes[4],
            nodes[3],
            nodes[2],
            nodes[1],
        ]
        assert (
            list(graph.iter_postorder()) == list(graph.iter_postorder(nodes[0]))
            or list(graph.iter_postorder()) == list(graph.iter_postorder(nodes[1]))
            or list(graph.iter_postorder()) == list(graph.iter_postorder(nodes[2]))
        )

        graph.add_edge(BasicEdge(nodes[6], nodes[4]))
        assert list(graph.iter_postorder(nodes[6])) == [nodes[5], nodes[4], nodes[6]]
        assert list(graph.iter_postorder(nodes[3])) == [nodes[5], nodes[4], nodes[3]]

    def test_topologicalorder_cylic(self, nodes):
        """
        Test that an error is raised if we try to invoke topological ordering on a cyclic graph.

             +---+
             | 0 | <+
             +---+  |
               |    |
               |    |
               v    |
             +---+  |
             | 2 | -+
             +---+
               |
               |
               v
             +---+
             | 3 | <+
             +---+  |
             +---+  |
          +> | 5 |  |
          |  +---+  |
          |    |    |
          |    |    |
          |    v    |
          |  +---+  |
          +- | 4 | -+
             +---+
        """
        graph = Graph()
        graph.add_edges_from(
            [
                BasicEdge(nodes[0], nodes[2]),
                BasicEdge(nodes[2], nodes[0]),
                BasicEdge(nodes[2], nodes[3]),
                BasicEdge(nodes[5], nodes[4]),
                BasicEdge(nodes[4], nodes[5]),
                BasicEdge(nodes[4], nodes[3]),
            ]
        )
        with pytest.raises(Exception):
            list(graph.iter_topological())

    def test_topologicalorder_acylic(self, nodes):
        """
        Test the topological order on acyclic graphs.

        """
        graph = Graph()
        graph.add_edges_from(
            [
                BasicEdge(nodes[4], nodes[5]),
                BasicEdge(nodes[1], nodes[2]),
                BasicEdge(nodes[0], nodes[2]),
                BasicEdge(nodes[2], nodes[3]),
                BasicEdge(nodes[0], nodes[1]),
                BasicEdge(nodes[2], nodes[4]),
                BasicEdge(nodes[3], nodes[4]),
            ]
        )
        assert list(graph.iter_topological()) == nodes[:6]

    def test_preorder(self, nodes):
        """
        Test preorder based on the wikipedia example.
        """
        graph = Graph()
        graph.add_edges_from(
            [
                BasicEdge(nodes[5], nodes[1]),
                BasicEdge(nodes[1], nodes[0]),
                BasicEdge(nodes[1], nodes[3]),
                BasicEdge(nodes[3], nodes[2]),
                BasicEdge(nodes[3], nodes[4]),
                BasicEdge(nodes[5], nodes[6]),
                BasicEdge(nodes[6], nodes[8]),
                BasicEdge(nodes[8], nodes[7]),
            ]
        )
        assert list(graph.iter_preorder()) == [nodes[5], nodes[1], nodes[0], nodes[3], nodes[2], nodes[4], nodes[6], nodes[8], nodes[7]]

    def test_node_management(self):
        """Test node adding, removing listing and iteration."""
        graph = Graph()
        n1 = BasicNode(1)
        assert n1 not in graph
        graph.add_node(n1)
        graph.add_node(n2 := BasicNode(2))
        assert graph.nodes == (n1, n2) == tuple(graph)
        assert n1 in graph
        graph.remove_node(n1)
        assert graph.nodes == (n2,) == tuple(graph)
        assert n1 not in graph and n2 in graph
        graph.remove_nodes_from([n2])
        assert graph.nodes == tuple() == tuple(graph)

    def test_edge_management(self):
        """Test edge adding, removing, getting and iteration."""
        graph = Graph()
        graph.add_edge(e1 := BasicEdge(n1 := BasicNode(1), n2 := BasicNode(2)))
        graph.add_edge(e2 := BasicEdge(n3 := BasicNode(3), n6 := BasicNode(6)))
        assert graph.edges == (e1, e2)
        assert graph.get_edge(n1, n2) == e1
        assert graph.get_edge(n1, n3) is None
        assert graph.get_in_edges(n6) == (e2,)
        assert graph.get_out_edges(n1) == (e1,)
        assert graph.get_incident_edges(n1) == (e1,)
        graph.remove_edge(e2)
        assert graph.edges == (e1,)

    def test_get_roots(self):
        """Test the function returning the nodes with in-degree zero."""
        graph = Graph()
        graph.add_nodes_from([n1 := BasicNode(1), n2 := BasicNode(2), n3 := BasicNode(3)])
        graph.add_edges_from([BasicEdge(n1, n2)])
        assert graph.get_roots() == (n1, n3)

    def test_get_leaves(self):
        """Test the get_leaves function of the graph."""
        graph = Graph()
        graph.add_nodes_from([n1 := BasicNode(1), n2 := BasicNode(2), n3 := BasicNode(3)])
        graph.add_edges_from([edge := BasicEdge(n1, n2), BasicEdge(n2, n3), BasicEdge(n3, n1)])
        assert graph.get_leaves() == tuple()
        graph.remove_edge(edge)
        assert graph.get_leaves() == (n1,)

    def test_order(self):
        """Tests whether __len__ returns the amount of nodes in the graph."""
        graph = Graph()
        graph.add_nodes_from([n1 := BasicNode(1), BasicNode(2), BasicNode(3)])
        assert len(graph) == 3
        graph.remove_node(n1)
        assert len(graph) == 2

    @staticmethod
    def get_easy_graph() -> Tuple[Graph, Tuple[BasicNode, ...], Tuple[BasicEdge, ...]]:
        graph = Graph()
        nodes = (
            n0 := BasicNode(0),
            n1 := BasicNode(1),
            n2 := BasicNode(2),
            BasicNode(3),
        )
        edges = (
            BasicEdge(n0, n1),
            BasicEdge(n1, n0),
            BasicEdge(n0, n2),
        )
        graph.add_nodes_from(nodes)
        graph.add_edges_from(edges)
        return graph, nodes, edges

    def test_degree(self):
        """Test the in_degree and out_degree functions."""
        graph, nodes, edges = self.get_easy_graph()
        assert graph.in_degree(nodes[3]) == 0 and graph.in_degree(nodes[0]) == 1 and graph.in_degree(nodes[2]) == 1
        assert graph.out_degree(nodes[3]) == 0 and graph.out_degree(nodes[1]) == 1 and graph.out_degree(nodes[0]) == 2
        graph.remove_edges_from([edges[0], edges[1]])
        assert graph.in_degree(nodes[0]) == 0 and graph.out_degree(nodes[0]) == 1

    def test_relations(self):
        """Test the get_adjacent_nodes, get_successors and get_predecessors functions"""
        graph, nodes, edges = self.get_easy_graph()
        assert (
            graph.get_successors(nodes[0])
            == (
                nodes[1],
                nodes[2],
            )
            and graph.get_predecessors(nodes[0]) == (nodes[1],)
            and graph.get_adjacent_nodes(nodes[0])
            == (
                nodes[1],
                nodes[2],
            )
        )
        assert (
            graph.get_successors(nodes[1]) == (nodes[0],)
            and graph.get_predecessors(nodes[1]) == (nodes[0],)
            and graph.get_adjacent_nodes(nodes[1]) == (nodes[0],)
        )
        assert (
            graph.get_successors(nodes[2]) == tuple()
            and graph.get_predecessors(nodes[2]) == (nodes[0],)
            and graph.get_adjacent_nodes(nodes[2]) == (nodes[0],)
        )
        assert (
            graph.get_successors(nodes[3]) == tuple()
            and graph.get_predecessors(nodes[3]) == tuple()
            and graph.get_adjacent_nodes(nodes[3]) == tuple()
        )
        n4 = BasicNode(4)
        assert graph.get_successors(n4) == tuple() and graph.get_predecessors(n4) == tuple() and graph.get_adjacent_nodes(n4) == tuple()

    def test_has_path(self):
        """Test the hash_path function, checking if there is a path between the two given nodes."""
        graph, nodes, edges = self.get_easy_graph()
        assert graph.has_path(nodes[0], nodes[1]) and graph.has_path(nodes[1], nodes[0])
        assert not graph.has_path(nodes[0], nodes[3]) and not graph.has_path(nodes[3], nodes[0])

    def test_subgraph(self):
        """Test subgraph creation."""
        graph, nodes, edges = self.get_easy_graph()
        subgraph = graph.subgraph(nodes[:2])
        assert isinstance(subgraph, Graph)
        assert subgraph.nodes == nodes[:2]
        assert subgraph.edges == edges[:2]

    def test_is_acyclic(self):
        graph, nodes, edges = self.get_easy_graph()
        assert not graph.is_acyclic()
        graph.remove_edge(edges[1])
        assert graph.is_acyclic()

    def test_get_paths(self, nodes):
        """Test the get_paths function iterating all simple paths between a given source and sink."""
        graph = Graph()
        graph.add_edges_from(
            [
                BasicEdge(nodes[0], nodes[1]),
                BasicEdge(nodes[0], nodes[2]),
                BasicEdge(nodes[0], nodes[3]),
                BasicEdge(nodes[1], nodes[4]),
                BasicEdge(nodes[2], nodes[0]),
                BasicEdge(nodes[2], nodes[4]),
            ]
        )
        assert list(graph.get_paths(nodes[0], nodes[4])) == [
            (
                nodes[0],
                nodes[1],
                nodes[4],
            ),
            (
                nodes[0],
                nodes[2],
                nodes[4],
            ),
        ]

    def test_get_shortest_path(self, nodes):
        """
        Test the Graph.get_shortest_path method.

             +---+
             | 0 | -+
             +---+  |
               |    |
               |    |
               v    |
             +---+  |
          +- | 1 |  |
          |  +---+  |
          |    |    |
          |    |    |
          |    v    |
          |  +---+  |
          |  | 2 | <+
          |  +---+
          |    |
          |    |
          |    v
          |  +---+
          |  | 4 |
          |  +---+
          |    |
          |    |
          |    v
          |  +---+
          |  | 5 | -+
          |  +---+  |
          |    |    |
          |    |    |
          |    v    |
          |  +---+  |
          +> | 3 |  |
             +---+  |
               |    |
               |    |
               v    |
             +---+  |
             | 6 | <+
             +---+
        """
        graph = Graph()
        graph.add_edges_from(
            [
                BasicEdge(nodes[0], nodes[1]),
                BasicEdge(nodes[1], nodes[3]),
                BasicEdge(nodes[3], nodes[6]),
                BasicEdge(nodes[0], nodes[2]),
                BasicEdge(nodes[1], nodes[2]),
                BasicEdge(nodes[2], nodes[4]),
                BasicEdge(nodes[4], nodes[5]),
                BasicEdge(nodes[5], nodes[3]),
                BasicEdge(nodes[5], nodes[6]),
            ]
        )

        assert graph.get_shortest_path(nodes[0], nodes[6]) == (nodes[0], nodes[1], nodes[3], nodes[6])
        graph.add_edge(BasicEdge(nodes[0], nodes[6]))
        assert graph.get_shortest_path(nodes[0], nodes[6]) == (nodes[0], nodes[6])
