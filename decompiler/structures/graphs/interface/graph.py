"""Defines a generic graph interface suitable for multiple graph backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, Iterable, Iterator, Optional, Tuple, TypeVar, Union

from .edge import GraphEdgeInterface
from .node import GraphNodeInterface

NODE = TypeVar("NODE", bound=GraphNodeInterface)
EDGE = TypeVar("EDGE", bound=GraphEdgeInterface)


class GraphInterface(ABC, Generic[NODE, EDGE]):
    """Basic interface for all graph backends."""

    # Graph properties
    @abstractmethod
    def get_roots(self) -> Tuple[NODE, ...]:
        """Return all root nodes of the graph."""

    @abstractmethod
    def get_leaves(self) -> Tuple[NODE, ...]:
        """Return all leaf nodes of the graph."""

    @abstractmethod
    def __len__(self) -> int:
        """Return the overall amount of nodes."""

    @abstractmethod
    def __eq__(self, other: object) -> bool:
        """Check whether the two uniquely labeled graphs are equal."""

    @abstractmethod
    def __iter__(self) -> Iterator[NODE]:
        """Iterate all nodes contained in the graph."""

    def __contains__(self, obj: Union[NODE, EDGE]):
        """Check if an node or edge is contained in the graph."""
        return obj in self.nodes or obj in self.edges

    @property
    @abstractmethod
    def edges(self) -> Tuple[EDGE, ...]:
        """Return a tuple containing all edges of the graph."""

    @property
    @abstractmethod
    def nodes(self) -> Tuple[NODE, ...]:
        """Return a tuple containing all nodes in the graph."""

    @abstractmethod
    def copy(self) -> GraphInterface:
        """Return a deep copy of the graph."""

    @abstractmethod
    def subgraph(self, nodes: Tuple[NODE, ...]) -> GraphInterface:
        """Return a shallow copy of the graph containing the given nodes."""

    # Graph manipulation

    @abstractmethod
    def add_node(self, node: NODE):
        """Add a node to the graph."""

    def add_nodes_from(self, nodes: Iterable[NODE]):
        """Add multiple nodes to the graph (legacy)."""
        for node in nodes:
            self.add_node(node)

    @abstractmethod
    def add_edge(self, edge: EDGE):
        """Add a single edge to the graph."""

    def add_edges_from(self, edges: Iterable[EDGE]):
        """Add multiple edges to the graph (legacy)."""
        for edge in edges:
            self.add_edge(edge)

    @abstractmethod
    def remove_node(self, node: NODE):
        """Remove the given node from the graph."""

    def remove_nodes_from(self, nodes: Iterable[NODE]):
        """Remove all nodes from the given iterator."""
        for node in nodes:
            self.remove_node(node)

    @abstractmethod
    def remove_edge(self, edge: EDGE):
        """Remove the given edge from the graph."""

    def remove_edges_from(self, edges: Iterable[EDGE]):
        """Remove all nodes in the given tuple from the graph."""
        for edge in edges:
            self.remove_edge(edge)

    # Graph traversal

    @abstractmethod
    def iter_depth_first(self, source: NODE) -> Iterator[NODE]:
        """Iterate all nodes in dfs fashion."""

    @abstractmethod
    def iter_breadth_first(self, source: NODE) -> Iterator[NODE]:
        """Iterate all nodes in dfs fashion."""

    @abstractmethod
    def iter_postorder(self, source: NODE = None) -> Iterator[NODE]:
        """Iterate all nodes in post order."""

    @abstractmethod
    def iter_preorder(self, source: NODE = None) -> Iterator[NODE]:
        """Iterate all nodes in pre order."""

    @abstractmethod
    def iter_topological(self) -> Iterator[NODE]:
        """Iterate all nodes in topological order. Raises an error if the graph is not acyclic."""

    # Node relations

    @abstractmethod
    def get_predecessors(self, node: NODE) -> Tuple[NODE, ...]:
        """Return a tuple of parent nodes of the given node."""

    @abstractmethod
    def get_successors(self, node: NODE) -> Tuple[NODE, ...]:
        """Return a tuple of child nodes of the given node."""

    @abstractmethod
    def get_adjacent_nodes(self, node: NODE) -> Tuple[NODE, ...]:
        """Return a tuple of all nodes directly connected to the given node."""

    # Edges

    @abstractmethod
    def get_in_edges(self, node: NODE) -> Tuple[EDGE, ...]:
        """Return a tuple of all edges targeting the given node."""

    @abstractmethod
    def get_out_edges(self, node: NODE) -> Tuple[EDGE, ...]:
        """Return a tuple of all edges starting at the given node."""

    @abstractmethod
    def get_incident_edges(self, node: NODE) -> Tuple[EDGE, ...]:
        """Get all edges either starting or ending at the given node."""

    @abstractmethod
    def get_edge(self, source: NODE, sink: NODE) -> Optional[EDGE]:
        """Get the edge between the two given nodes, if any."""

    def in_degree(self, node: NODE) -> int:
        """Return the amount of edges pointing to the given node."""
        return len(self.get_predecessors(node))

    def out_degree(self, node: NODE) -> int:
        """Return the amount of edges starting at the given node."""
        return len(self.get_successors(node))

    # Paths

    @abstractmethod
    def has_path(self, source: NODE, sink: NODE) -> bool:
        """Check whether there is a valid path between the given nodes."""

    @abstractmethod
    def get_paths(self, source: NODE, sink: NODE) -> Iterator[Tuple[NODE, ...]]:
        """Iterate all paths between the given nodes (warning: expensive)."""

    @abstractmethod
    def get_shortest_path(self, source: NODE, sink: NODE) -> Tuple[NODE, ...]:
        """Return one of the shortest paths between source and sink."""
