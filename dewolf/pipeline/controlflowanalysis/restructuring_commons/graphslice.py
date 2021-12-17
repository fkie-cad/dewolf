"""Module to compute graph slices."""
from __future__ import annotations

from typing import Iterator, List, Set

from dewolf.structures.graphs.classifiedgraph import EdgeProperty
from dewolf.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock, TransitionCFG, TransitionEdge


class GraphSlice:
    def __init__(self, t_cfg: TransitionCFG, source: TransitionBlock, sink: TransitionBlock):
        """
        :param t_cfg: The transition control flow graph of which we want to compute a graph slice.
        :param source: The source of the graph slice.
        """
        assert t_cfg.is_acyclic(), "The given transition cfg is not a directed acyclic graph, therefore we can not compute the graph slice!"
        self._t_cfg: TransitionCFG = t_cfg
        self._source: TransitionBlock = source
        self._sink: TransitionBlock = sink
        self._graph_slice = TransitionCFG()

    @classmethod
    def compute_graph_slice_for_region(
        cls, t_cfg: TransitionCFG, source: TransitionBlock, region: Set[TransitionBlock], back_edges: bool = True
    ) -> TransitionCFG:
        """
        Return the graph slice of the transition cfg from source to a set of 'sink' nodes of the region.

        :param t_cfg: The original transition control flow graph of which we want to compute a graph slice.
        :param source: The source of the graph slice.
        :param region: The region of sinks.
        :param back_edges: Tells us whether we consider back edges in the graph slice computation.
        :return: The graph slice of the input transition cfg with source src and sinks from the region.
        """
        sink_nodes = GraphSlice._sink_nodes(t_cfg, region)
        return GraphSlice.compute_graph_slice_for_sink_nodes(t_cfg, source, sink_nodes, back_edges)

    @classmethod
    def compute_graph_slice_for_sink_nodes(
        cls, t_cfg: TransitionCFG, source: TransitionBlock, sink_nodes: List[TransitionBlock], back_edges: bool = True
    ) -> TransitionCFG:
        """
        Return the graph slice of the transition cfg from the source to a set of sink nodes sink_nodes.

        The slice is a directed acyclic graph (V,E), where
            - N is the set of all vertices on simple paths from source to a TransitionBlock in sink_node in the transition cfg.
            - E is the set of edges on simple paths from source to a TransitionBlock in sink_node in the transition cfg.

        :param t_cfg: The original transition control flow graph of which we want to compute a graph slice.
        :param source: The source of the graph slice.
        :param sink_nodes: The set of sinks of the graph slice.
        :param back_edges: Tells us whether we consider back-edges.
        :return: The graph slice of the input transition cfg with source source and sinks sink_nodes.
        """
        graph = TransitionCFG()
        graph.add_edges_from([edge for edge in t_cfg.edges if (back_edges or edge.property == EdgeProperty.non_loop)])
        graph.root = source
        virtual_node = graph.create_ast_block()
        instance = cls(graph, source, virtual_node)
        instance._add_virtual_sink_node(virtual_node, sink_nodes)
        instance._compute_graph_slice_for_single_sink_node()
        instance._graph_slice.remove_node(virtual_node)

        instance._graph_slice.condition_handler = t_cfg.condition_handler
        return instance._graph_slice

    @staticmethod
    def _sink_nodes(t_cfg, region: Set[TransitionBlock]) -> List[TransitionBlock]:
        """
        Return a list of all vertices in the given region that have no successor in the transition cfg or where at least one successor is not
        in the region.

        :param t_cfg: The transition control flow graph we consider.
        :param region: The region whose 'sinks' we want to compute
        :return: A list of 'sink' vertices of the region.
        """
        sink_nodes = []
        for node in region:
            successors = t_cfg.get_successors(node)
            if len(successors) == 0:
                sink_nodes.append(node)
            for succ in successors:
                if succ not in region:
                    sink_nodes.append(node)
                    break
        return sink_nodes

    def _compute_graph_slice_for_single_sink_node(self) -> None:
        """
        Compute the graph slice of the transition cfg from a source to a sink node.

        The input graph is (must be) a directed acyclic graph.
            - Since the graph is acyclic, every vertex that is reachable from the source and reaches the sink is part of the graph slice
            - Now, the graph slice is the subgraph consisting of all vertices that are reachable from source and reach sink.

        :return: The graph slice of the input transition cfg with the given source and sink.
        """
        if self._source == self._sink:
            self._graph_slice.add_node(self._source)
            return

        graph_slice_nodes = self._get_graph_slice_nodes()
        self._construct_graph_slice_with_nodes(graph_slice_nodes)
        self._graph_slice.root = self._source

    def _get_graph_slice_nodes(self) -> Iterator[TransitionBlock]:
        """
        Compute the set of nodes of the graph slice.

        This are all nodes that are reachable from the source and that reach the sink node.
        """
        reachable_from_source: Iterator[TransitionBlock] = self._t_cfg.iter_postorder(self._source)
        reverse_graph = self._construct_reverse_graph_for(reachable_from_source)
        return reverse_graph.iter_postorder(self._sink)

    def _construct_graph_slice_with_nodes(self, graph_slice_nodes: Iterator[TransitionBlock]) -> None:
        """Construct the graph slice from the given graph with the given set of vertices."""
        self._graph_slice.add_nodes_from(graph_slice_nodes)
        for node in self._graph_slice:
            for predecessor in self._t_cfg.get_predecessors(node):
                if predecessor in self._graph_slice:
                    self._graph_slice.add_edge(self._t_cfg.get_edge(predecessor, node).copy())

    def _construct_reverse_graph_for(self, subgraph_nodes: Iterator[TransitionBlock]) -> TransitionCFG:
        """Construct the reverse graph of the transition cfg containing only subgraph_nodes vertices."""
        reverse_graph = TransitionCFG()
        reverse_graph.add_nodes_from([node for node in subgraph_nodes])
        for node in reverse_graph:
            for successor in self._t_cfg.get_successors(node):
                if successor in reverse_graph:
                    reverse_graph.add_edge(TransitionEdge(successor, node, self._t_cfg.condition_handler.get_true_value()))
        return reverse_graph

    def _add_virtual_sink_node(self, virtual_node: TransitionBlock, sink_nodes: List[TransitionBlock]) -> None:
        """
        Add a the given virtual node as virtual sink node, by adding an edge between each sink node and the virtual node.

        :param virtual_node: The new virtual sink node of the region.
        :param sink_nodes: The list of sink nodes of the graph/region.
        """
        for sink in sink_nodes:
            self._t_cfg.add_edge(TransitionEdge(sink, virtual_node, self._t_cfg.condition_handler.get_true_value()))
