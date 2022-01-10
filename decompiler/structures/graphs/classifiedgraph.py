"""Module implementing edge classification for NetworkXGraph."""
from __future__ import annotations

from collections import defaultdict
from enum import Enum, auto
from typing import DefaultDict, Dict, Set, Tuple

from .interface import EDGE, NODE
from .rootedgraph import RootedGraph


class EdgeProperty(Enum):
    """Possible properties of a given edge."""

    forward = auto()
    back = auto()
    cross = auto()
    retreating = auto()
    tree = auto()
    non_loop = auto()


class ClassifiedGraph(RootedGraph[NODE, EDGE]):
    """Graph implementing edge classification."""

    def __eq__(self, other: object) -> bool:
        """Check for equality of two graphs based on the labels of the nodes and egdes."""
        assert isinstance(other, ClassifiedGraph)
        return set(self) == set(other) and set(self.edges) == set(other.edges)

    @staticmethod
    def _has_tree_path(start: NODE, finish: NODE, parent_dict: Dict[NODE, NODE]) -> bool:
        """
        Compute whether the graph, whose edge set is described by parent_dict has a path from start to finish

        :param start: start BasicBlock of the path
        :param finish: end BasicBlock of the path
        :param parent_dict: Dictionary with entry 'node: parent of node'
        :return: whether there exists a path from start to finish where edges are given via parent_dict
        """
        current = start
        while current in parent_dict:
            current = parent_dict[current]
            if current == finish:
                return True
        return False

    def _find_property(
        self,
        parent: NODE,
        child: NODE,
        parent_dict: Dict[NODE, NODE],
        node_indices: Dict[NODE, int],
    ) -> EdgeProperty:
        """
        Computes the edge property of edge (parent, child)
        """
        if child in node_indices.keys():
            if self._has_tree_path(child, parent, parent_dict):
                return EdgeProperty.forward
            else:
                return EdgeProperty.cross
        else:
            if self.dominator_tree.has_path(child, parent):
                return EdgeProperty.back
            else:
                return EdgeProperty.retreating

    def classify_edges(self) -> Dict[EDGE, EdgeProperty]:
        """
        Computes for each edge the Edge Property, i.e., whether it is a tree-, forward-, cross-, back-, or retreating-edge

        :return: A dictionary where the set of keys is the set of edges and the value of a key, say edge e, is the edge property of e
        """
        node_indices: Dict[NODE, int] = dict()
        edge_properties: Dict[EDGE, EdgeProperty] = dict()
        parent_dict: Dict[NODE, NODE] = dict()

        index = len(self)
        visited_nodes = {self.root}
        stack = [(self.root, iter(self.get_successors(self.root)))]
        while stack:
            parent, children = stack[-1]
            try:
                child = next(children)
                if child in visited_nodes:
                    current_edge_property = self._find_property(parent, child, parent_dict, node_indices)
                    edge_properties[self.get_edge(parent, child)] = current_edge_property
                else:
                    edge_properties[self.get_edge(parent, child)] = EdgeProperty.tree
                    parent_dict[child] = parent
                    visited_nodes.add(child)
                    stack.append((child, iter(self.get_successors(child))))
            except StopIteration:
                node, _ = stack.pop()
                node_indices[node] = index
                index -= 1
        return edge_properties

    def back_edges(self) -> DefaultDict[NODE, Set[EDGE]]:
        """
        Compute the back-edges of the Control Flow Graph

        :return: dict where an entry with key = w has as value the set of all back-edges edges e_1=(v_1,w), e_2=(v_2,w),...,e_k=(v_k,w),
                 where w is the sink of. Thus, node w is the head of the loops that belongs to the back-edges.
        """
        edge_properties = self.classify_edges()
        back_edges_dict: DefaultDict[NODE, Set[EDGE]] = defaultdict(set)
        for edge in self.edges:
            if edge_properties[edge] == EdgeProperty.back:
                back_edges_dict[edge.sink].add(edge)
        return back_edges_dict

    def retreating_edges(self) -> Set[EDGE]:
        """
        Compute the set of retreating-edges of the Control Flow Graph

        :return: set of all retreating edges
        """
        edge_properties = self.classify_edges()
        retreating_edges: Set[EDGE] = set()
        for edge in self.edges:
            if edge_properties[edge] == EdgeProperty.retreating:
                retreating_edges.add(edge)
        return retreating_edges

    def loop_edges(self) -> Dict[NODE, Tuple[Set[EDGE], EdgeProperty]]:
        """
        Compute the set of all loop-entries, and assigns two each entry the set of back- resp. retreating-edges
        as well as the type of these edges.

        :return: A dictionary where each loop-entry is mapped to a tuple, where the first entry is the set of all back- resp. retreating
        edges and the second entry is the type of these edges.
        """
        edge_properties = self.classify_edges()
        loop_dict: Dict[NODE, Tuple[Set[EDGE], EdgeProperty]] = dict()
        for edge in self.edges:
            if edge_properties[edge] == EdgeProperty.back:
                if edge.sink not in loop_dict:
                    loop_dict[edge.sink] = (set(), EdgeProperty.back)
                loop_dict[edge.sink][0].add(edge)
            elif edge_properties[edge] == EdgeProperty.retreating:
                if edge.sink not in loop_dict:
                    loop_dict[edge.sink] = (set(), EdgeProperty.retreating)
                elif loop_dict[edge.sink][1] == EdgeProperty.back:
                    loop_dict[edge.sink] = (loop_dict[edge.sink][0], EdgeProperty.retreating)
                loop_dict[edge.sink][0].add(edge)
        return loop_dict
