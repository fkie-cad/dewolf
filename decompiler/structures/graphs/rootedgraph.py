"""Module implementing a rooted graph with buffered dominator tree."""
from __future__ import annotations

from typing import Iterable, Optional, Tuple

from networkx import MultiDiGraph, immediate_dominators

from .basic import BasicEdge
from .interface import EDGE, NODE, RootedGraphInterface
from .nxgraph import NetworkXGraph


class RootedGraph(NetworkXGraph[NODE, EDGE], RootedGraphInterface[NODE, EDGE]):
    """A graph implementation buffering a dominator tree."""

    def __init__(self, graph: Optional[MultiDiGraph] = None, root: Optional[NODE] = None):
        """Init a new empty instance."""
        super(RootedGraph, self).__init__(graph)
        self._root = root
        self._dominator_tree: Optional[NetworkXGraph] = None

    @property  # type: ignore
    def root(self) -> Optional[NODE]:  # type: ignore
        """Return the root of the graph."""
        return self._root

    @root.setter
    def root(self, value: NODE):
        """Set a new root for the graph."""
        assert value is None or value in self
        self._root = value
        self._dominator_tree = None

    @property
    def dominator_tree(self) -> NetworkXGraph:
        """Return the current dominator tree."""
        if not self._dominator_tree:
            self._dominator_tree = self.__refresh_dominator_tree()
        return self._dominator_tree

    def copy(self) -> RootedGraph:
        """Return a deep copy of the graph."""
        graph, node_dict = self._full_copy()
        root = node_dict[self._root] if self._root is not None else None
        graph.root = root
        return graph

    def find_common_dominator(self, *nodes: NODE) -> Optional[NODE]:
        """Find a common dominator for the given nodes."""
        assert self.root is not None
        tree = self.dominator_tree
        for node in tree.iter_breadth_first(self.root):
            if node in nodes:
                break
        else:
            raise ValueError("None of the passed nodes is part of the dominator tree.")
        dominator_guess: NODE = node  # type: ignore
        while dominator_guess is not None:
            if all((self.is_dominating(dominator_guess, node) for node in nodes)):
                return dominator_guess
            dominator_guess = tree.get_predecessors(dominator_guess)[0] if tree.get_predecessors(dominator_guess) else None

    def is_dominating(self, dominator: NODE, dominated: NODE) -> bool:
        """Check whether one node dominates another."""
        return self.dominator_tree.has_path(dominator, dominated)

    def strictly_dominated_by(self, dominator: NODE) -> Tuple[NODE]:
        """Return the list of nodes that are strictly dominated by dominator."""
        return self.dominator_tree.get_successors(dominator)

    def add_node(self, node: NODE):
        """Add the given node to the graph."""
        super(RootedGraph, self).add_node(node)
        self._dominator_tree = None
        if self._root is None:
            self._root = node

    def add_edge(self, edge: EDGE):
        """Add the given edge to the graph."""
        super(RootedGraph, self).add_edge(edge)
        if self._root is None:
            self._root = edge.source
        self._dominator_tree = None

    def remove_node(self, node: NODE):
        """Remove the node edge from the graph."""
        assert node is not self.root, "Can not remove the root node!"
        super(RootedGraph, self).remove_node(node)
        self._dominator_tree = None

    def remove_nodes_from(self, nodes: Iterable[NODE]):
        assert self.root not in nodes, "Can not remove the root node!"
        super(RootedGraph, self).remove_nodes_from(nodes)

    def remove_edge(self, edge: EDGE):
        """Remove the given edge from the graph."""
        super(RootedGraph, self).remove_edge(edge)
        self._dominator_tree = None

    def __eq__(self, other: object) -> bool:
        """Check if the given graph is equal to another instance."""
        return isinstance(other, RootedGraph) and super().__eq__(other) and self.root == other.root

    def __refresh_dominator_tree(self) -> NetworkXGraph:
        """Build up a new dominator tree."""
        dom_tree = NetworkXGraph()
        if not self.nodes:
            return dom_tree
        dominators = immediate_dominators(self._graph, self._root)
        for dominated, dominator in dominators.items():
            dom_tree.add_node(dominated)
            if dominated != dominator:
                dom_tree.add_edge(BasicEdge(dominator, dominated))
        return dom_tree
