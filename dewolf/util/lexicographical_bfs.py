from typing import Dict, Iterator, Optional

from dewolf.structures.graphs.cfg import BasicBlock
from dewolf.structures.interferencegraph import InterferenceGraph
from dewolf.structures.pseudo.expressions import Variable
from dewolf.util.insertion_ordered_set import InsertionOrderedSet
from networkx import DiGraph


class LexicographicalBFS:
    """Class to compute the lexicographical BFS of a given interference graph."""

    def __init__(self, interference_graph: InterferenceGraph):
        self.interference_graph = interference_graph
        self.labeling_graph = DiGraph()
        self.node_containing_variable: Dict[Variable, Optional[int]] = dict()

    def reverse_lexicographic_bfs(self) -> Iterator[Variable]:
        """
        This algorithm performs lexicographical BFS and returns the variables in reverse lexicographical order.
            - By order we mean the reverse visiting order.
            - If the interference graph is chordal, then for each vertex the set of all neighbors with an larger order is a clique.
            - We use the labeling graph as a doubly linked list to take track which vertex we should consider next,
              i.e., it is a directed path (in one direction v1 -> v2 -> v3 -> v4), where
              (a) the set of unordered variables, that are contained in the same node have the same lexicographical order.
              (b) an edge (u,v) means that the variables corresponding to u are lexicographical larger than the variables corresponding to v

        :return: A iterator of variables, in reverse lexicographical order.
        """
        all_nodes = InsertionOrderedSet()
        isolated_nodes = list()
        for node in self.interference_graph.nodes:
            if not self._has_neighbors(node):
                isolated_nodes.append(node)
            else:
                all_nodes.add(node)
        for node in isolated_nodes:
            all_nodes.add(node)
        if not all_nodes:
            return

        self.labeling_graph.add_node(0, variable_set=all_nodes)
        self.labeling_graph.graph["id"] = 1
        self.labeling_graph.graph["head"] = 0
        self.node_containing_variable = {variable: self.labeling_graph.graph["head"] for variable in self.interference_graph.nodes()}

        while self.labeling_graph.nodes():
            current_variable = self._get_lexicographical_largest_variable()
            self.node_containing_variable[current_variable] = None
            yield current_variable

            self._update_labeling_graph(current_variable)

    def _get_lexicographical_largest_variable(self) -> Variable:
        """
        This function returns the variable with the largest lexicographical order
            - If the node in the labeling graph that contains the variable with the largest lexicographical order is empty
              after removing this variable, then we remove it from the labeling graph and update the head.

        :return: The lexicographically largest variable
        """
        current_variable = self.labeling_graph.nodes[self.labeling_graph.graph["head"]]["variable_set"].pop()

        if not self.labeling_graph.nodes[self.labeling_graph.graph["head"]]["variable_set"]:
            next_head = list(self.labeling_graph.successors(self.labeling_graph.graph["head"]))
            self.labeling_graph.remove_node(self.labeling_graph.graph["head"])
            if next_head:
                self.labeling_graph.graph["head"] = next_head[0]
            else:
                self.labeling_graph.graph["head"] = None

        return current_variable

    def _update_labeling_graph(self, current_variable: Variable) -> None:
        """
        This function updates the labeling graph when we choose that `current_variable` is the variable we considered.

        :param current_variable: The variable that we considered.
        """
        nodes_with_changed_sets = set()
        for neighbor in self.interference_graph.neighbors(current_variable):
            node_containing_neighbor: Optional[int] = self.node_containing_variable[neighbor]
            if node_containing_neighbor is None:
                continue
            if node_containing_neighbor in nodes_with_changed_sets:
                predecessor_node = list(self.labeling_graph.predecessors(node_containing_neighbor))[0]
                self.labeling_graph.nodes[predecessor_node]["variable_set"].add(neighbor)
                self.node_containing_variable[neighbor] = predecessor_node
            else:
                self._insert_new_node_for_variable(neighbor)
                self.node_containing_variable[neighbor] = self.labeling_graph.graph["id"]
                self.labeling_graph.graph["id"] += 1
                nodes_with_changed_sets.add(node_containing_neighbor)

            self._remove_variable_from_previous_node(neighbor, node_containing_neighbor)

    def _insert_new_node_for_variable(self, variable: Variable) -> None:
        """
        This function insert a new node to the labeling graph, before the node that contains variable `variable`.
        This new node contains variable `variable`

        :param variable: The variable that we want to add to a new node.
        """
        node_containing_variable = self.node_containing_variable[variable]
        self.labeling_graph.add_node(self.labeling_graph.graph["id"], variable_set=InsertionOrderedSet([variable]))
        if node_containing_variable == self.labeling_graph.graph["head"]:
            self.labeling_graph.graph["head"] = self.labeling_graph.graph["id"]
        else:
            previous_node = list(self.labeling_graph.predecessors(node_containing_variable))[0]
            self.labeling_graph.add_edge(previous_node, self.labeling_graph.graph["id"])
            self.labeling_graph.remove_edge(previous_node, node_containing_variable)

        self.labeling_graph.add_edge(self.labeling_graph.graph["id"], node_containing_variable)

    def _remove_variable_from_previous_node(self, variable: Variable, previous_node: int) -> None:
        """
        This function removes the variable from the node `previous node` in the labeling graph.
        If the node is empty after removing the variable, we remove it from the labeling graph.

        :param variable: The variable that we want to delete from `prev_node`.
        :param previous_node: The node from which we want to remove the variable.
        """
        self.labeling_graph.nodes[previous_node]["variable_set"].remove(variable)
        if not self.labeling_graph.nodes[previous_node]["variable_set"]:
            successors = list(self.labeling_graph.successors(previous_node))
            predecessors = list(self.labeling_graph.predecessors(previous_node))
            if successors and predecessors:
                self.labeling_graph.add_edge(predecessors[0], successors[0])
            self.labeling_graph.remove_node(previous_node)

    def _has_neighbors(self, node: BasicBlock) -> bool:
        """Returns true if the node has neighbors and false otherwise."""
        return any(True for _ in self.interference_graph.neighbors(node))
