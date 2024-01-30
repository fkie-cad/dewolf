"""Module implementing networkx as a graph backend."""

from __future__ import annotations

from typing import Dict, Iterator, Optional, Tuple, TypeVar

from networkx import bfs_edges  # type: ignore
from networkx import (
    DiGraph,
    all_simple_paths,
    dfs_edges,
    dfs_postorder_nodes,
    dfs_preorder_nodes,
    has_path,
    immediate_dominators,
    is_directed_acyclic_graph,
    shortest_path,
    topological_sort,
)

from .interface import EDGE, NODE, GraphInterface

T = TypeVar("T", bound=GraphInterface)


class NetworkXGraph(GraphInterface[NODE, EDGE]):
    """A networkx implementation of the GraphInterface."""

    def __init__(self, graph: Optional[DiGraph] = None):
        """Init a new empty instance."""
        self._graph = DiGraph() if not graph else graph

    # Interface implementation

    def add_node(self, node: NODE):
        """Add the given node to the graph."""
        self._graph.add_node(node)

    def add_edge(self, edge: EDGE):
        """Add the given edge to the graph."""
        self._graph.add_edge(edge.source, edge.sink, data=edge)

    def remove_node(self, node: NODE):
        """Remove the node edge from the graph."""
        self._graph.remove_node(node)

    def remove_edge(self, edge: EDGE):
        """Remove the given edge from the graph."""
        self._graph.remove_edge(edge.source, edge.sink)

    def get_roots(self) -> Tuple[NODE, ...]:
        """Return all nodes with in degree 0."""
        return tuple(node for node, d in self._graph.in_degree() if not d)

    def get_leaves(self) -> Tuple[NODE, ...]:
        """Return all nodes with out degree 0."""
        return tuple(node for node, d in self._graph.out_degree() if not d)

    def __len__(self) -> int:
        """Return the amount of nodes in the graph."""
        return len(self._graph.nodes)

    def __eq__(self, other: object) -> bool:
        """Check if the given graph is equal to another instance."""
        return isinstance(other, GraphInterface) and set(self.nodes) == set(other.nodes) and set(self.edges) == set(other.edges)

    def __iter__(self) -> Iterator[NODE]:
        """Iterate all nodes in the graph."""
        yield from self._graph.nodes

    def iter_depth_first(self, source: NODE) -> Iterator[NODE]:
        """Iterate all nodes in dfs fashion."""
        edges = dfs_edges(self._graph, source=source)
        yield source
        yield from (edge[1] for edge in edges)

    def iter_breadth_first(self, source: NODE) -> Iterator[NODE]:
        """Iterate all nodes in dfs fashion."""
        edges = bfs_edges(self._graph, source=source)
        yield source
        yield from (edge[1] for edge in edges)

    def iter_postorder(self, source: NODE = None) -> Iterator[NODE]:
        """Iterate all nodes in post order starting at the given source."""
        yield from dfs_postorder_nodes(self._graph, source)

    def iter_preorder(self, source: NODE = None) -> Iterator[NODE]:
        """Iterate all nodes in pre order."""
        yield from dfs_preorder_nodes(self._graph, source)

    def iter_topological(self) -> Iterator[NODE]:
        """Iterate all nodes in topological order, if the graph is acyclic."""
        try:
            yield from topological_sort(self._graph)
        except Exception as _:
            raise ValueError("A cyclic graph can not be sorted in topological order.")

    @property
    def edges(self) -> Tuple[EDGE, ...]:
        """Return a tuple containing all edges in the graph."""
        return tuple(data["data"] for _, _, data in self._graph.edges(data=True))

    @property
    def nodes(self) -> Tuple[NODE, ...]:
        """Return a tuple of all nodes contained in the graph."""
        return tuple(self._graph.nodes)

    def copy(self) -> NetworkXGraph[NODE, EDGE]:
        """Return a deep copy of the graph."""
        graph, _ = self._full_copy()
        return graph

    def get_predecessors(self, node: NODE) -> Tuple[NODE, ...]:
        """Return the parent nodes of the given node."""
        if self._graph.has_node(node):
            return tuple(dict.fromkeys(self._graph.predecessors(node)))
        return tuple()

    def get_successors(self, node: NODE) -> Tuple[NODE, ...]:
        """Return the child nodes of the given node."""
        if self._graph.has_node(node):
            return tuple(dict.fromkeys(self._graph.successors(node)))
        return tuple()

    def get_adjacent_nodes(self, node: NODE) -> Tuple[NODE, ...]:
        """Get all nodes directly connected to the given node."""
        return tuple(dict.fromkeys(self.get_predecessors(node) + self.get_successors(node)))

    def get_in_edges(self, node: NODE) -> Tuple[EDGE, ...]:
        """Get all edges targeting the given node."""
        return tuple(data["data"] for source, sink, data in self._graph.in_edges((node,), data=True))

    def get_out_edges(self, node: NODE) -> Tuple[EDGE, ...]:
        """Get all edges starting at the given node."""
        return tuple(data["data"] for source, sink, data in self._graph.out_edges((node,), data=True))

    def get_incident_edges(self, node: NODE) -> Tuple[EDGE, ...]:
        """Get all edges either starting or ending at the given node."""
        incident_edges: Tuple[EDGE, ...] = self.get_in_edges(node) + self.get_out_edges(node)
        return incident_edges

    def get_edge(self, source: NODE, sink: NODE) -> Optional[EDGE]:  # type: ignore
        """Return any edge between source and sink if it exists."""
        edge = self._graph.get_edge_data(source, sink)
        return edge["data"] if edge else None

    def has_path(self, source: NODE, sink: NODE) -> bool:
        """Check if there is a valid path connecting the given nodes."""
        return source in self.nodes and sink in self.nodes and has_path(self._graph, source, sink)

    def get_paths(self, source: NODE, sink: NODE) -> Iterator[Tuple[NODE, ...]]:
        """Iterate all paths between the given nodes."""
        yield from (tuple(path) for path in all_simple_paths(self._graph, source, sink))

    def get_shortest_path(self, source: NODE, sink: NODE) -> Tuple[NODE, ...]:
        """Return one of the shortest paths between source and sink."""
        return tuple(shortest_path(self._graph, source, sink))

    def subgraph(self, nodes: Tuple[NODE, ...], copy: bool = False) -> GraphInterface:
        """Return a shallow copy of the graph containing the given nodes."""
        graph = self if not copy else self.copy()
        return self.__class__(graph._graph.subgraph(nodes))

    def is_acyclic(self):
        """Check whether the graph does not contain any cycles."""
        return is_directed_acyclic_graph(self._graph)

    def _full_copy(self: T) -> Tuple[T, Dict[NODE, NODE]]:
        """Generate a full copy of the graph and return the directory mapping the node ids to the copied objects."""
        graph = self.__class__()
        nodes = {node: node.copy() for node in self}
        graph.add_nodes_from(nodes.values())
        graph.add_edges_from((edge.copy(source=nodes[edge.source], sink=nodes[edge.sink]) for edge in self.edges))
        return graph, nodes
