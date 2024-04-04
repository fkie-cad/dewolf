"""Module to handle the reaches attribute using graphs."""

from __future__ import annotations

from itertools import chain, permutations, product
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Set, Tuple

from decompiler.structures.pseudo.expressions import Constant
from decompiler.util.insertion_ordered_set import InsertionOrderedSet
from networkx import DiGraph, NetworkXUnfeasible, has_path, topological_sort, transitive_closure, weakly_connected_components

if TYPE_CHECKING:
    from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CaseNode, CodeNode, SwitchNode


class SiblingReachability:
    """Class that is able to sort siblings of sequence nodes."""

    def __init__(self, digraph: Optional[DiGraph] = None):
        """Initialize the sibling reachability with an empty graph."""
        self._sibling_reachability_graph: DiGraph = DiGraph() if digraph is None else digraph

    def __contains__(self, node: AbstractSyntaxTreeNode) -> bool:
        """Checks whether the node is a sibling."""
        return node in self._sibling_reachability_graph

    @property
    def nodes(self) -> Tuple[AbstractSyntaxTreeNode, ...]:
        """Return a tuple of all considered siblings."""
        return tuple(self._sibling_reachability_graph.nodes)

    def copy(self) -> SiblingReachability:
        """Returns a copy of the Sibling Reachability."""
        return SiblingReachability(self._sibling_reachability_graph.copy())

    @classmethod
    def compute_sibling_reachability_from(
        cls, reachability_graph: ReachabilityGraph, ast_nodes: Tuple[AbstractSyntaxTreeNode, ...]
    ) -> SiblingReachability:
        """Computes the sibling reachability using the code-node-reachability and descendant code nodes."""
        reachable_from: Dict[AbstractSyntaxTreeNode, InsertionOrderedSet[CodeNode]] = dict()
        descendant_from: Dict[AbstractSyntaxTreeNode, InsertionOrderedSet[CodeNode]] = dict()
        for child in ast_nodes:
            reachable_from[child], descendant_from[child] = reachability_graph.get_reachable_and_descendant_code_nodes_of(child)

        sibling_reachability: SiblingReachability = cls()
        sibling_reachability._add_nodes(ast_nodes)
        for child_1, child_2 in permutations(sibling_reachability._all_siblings(), 2):
            if reachable_from[child_1] & descendant_from[child_2]:
                sibling_reachability._add_first_node_reaches_second(child_1, child_2)
        return sibling_reachability

    def reachable_siblings_of(self, node: AbstractSyntaxTreeNode) -> InsertionOrderedSet[AbstractSyntaxTreeNode]:
        """Returns all siblings that are reachable from the given node."""
        return InsertionOrderedSet(self._sibling_reachability_graph.successors(node))

    def siblings_reaching(self, node: AbstractSyntaxTreeNode) -> InsertionOrderedSet[AbstractSyntaxTreeNode]:
        """Returns all siblings that are reaching the given node."""
        return InsertionOrderedSet(self._sibling_reachability_graph.predecessors(node))

    def merge_siblings_to(self, new_node: AbstractSyntaxTreeNode, merging_nodes: List[AbstractSyntaxTreeNode]):
        """Merges the nodes in merging_nodes to the ast node new_node in the sibling reachability graph."""
        assert all(node in self for node in merging_nodes), "All nodes that we want to merge must be siblings!"
        self._sibling_reachability_graph.add_node(new_node)
        for node in merging_nodes:
            self._sibling_reachability_graph.add_edges_from(((new_node, reachable) for reachable in self.reachable_siblings_of(node)))
            self._sibling_reachability_graph.add_edges_from(((reaching, new_node) for reaching in self.siblings_reaching(node)))
        if (new_node, new_node) in self._sibling_reachability_graph.edges:
            self._sibling_reachability_graph.remove_edge(new_node, new_node)
        self._sibling_reachability_graph.remove_nodes_from(merging_nodes)

    def remove_sibling(self, node: AbstractSyntaxTreeNode):
        """Removes a sibling from the sibling reachability."""
        self._sibling_reachability_graph.remove_node(node)

    def _all_siblings(self) -> InsertionOrderedSet[AbstractSyntaxTreeNode]:
        """Returns all siblings."""
        return InsertionOrderedSet(self._sibling_reachability_graph.nodes)

    def _add_nodes(self, all_nodes: Iterable[AbstractSyntaxTreeNode]):
        """Add all given nodes to the sibling reachability."""
        for node in all_nodes:
            self._sibling_reachability_graph.add_node(node)

    def _add_first_node_reaches_second(self, first_node: AbstractSyntaxTreeNode, second_node: AbstractSyntaxTreeNode):
        """Adds and edge such that the first node reaches the second AST node afterward."""
        self._sibling_reachability_graph.add_edge(first_node, second_node)

    def remove_reachability_between(self, nodes: List[AbstractSyntaxTreeNode]):
        """Remove the reachability between the given set of nodes"""
        for node1, node2 in permutations(nodes, 2):
            if self._sibling_reachability_graph.has_edge(node1, node2):
                self._sibling_reachability_graph.remove_edge(node1, node2)

    def reaches(self, node_1, node_2) -> bool:
        """Checks whether node_1 reaches node_2"""
        return (node_1, node_2) in self._sibling_reachability_graph.edges

    def sorted_nodes(self) -> Optional[Tuple[AbstractSyntaxTreeNode, ...]]:
        """Sorts the siblings in topological order."""
        try:
            return tuple(topological_sort(self._sibling_reachability_graph))
        except NetworkXUnfeasible:
            return None

    def transitive_closure(self) -> SiblingReachability:
        return SiblingReachability(transitive_closure(self._sibling_reachability_graph))

    def can_group_siblings(self, grouping_siblings: List[AbstractSyntaxTreeNode]):
        """Check whether the given siblings can be grouped into one node."""
        copy_sibling_reachability = self.copy()
        copy_sibling_reachability.merge_siblings_to("X", grouping_siblings)
        return copy_sibling_reachability.sorted_nodes() is not None


class ReachabilityGraph:
    """Class in charge of handling the code node reachability of Abstract-Syntax-Forests and Trees."""

    def __init__(self) -> None:
        """Initialize the reachability graph with an empty graph."""
        self._code_node_reachability_graph = DiGraph()

    @property
    def nodes(self) -> Tuple[CodeNode, ...]:
        """Return a tuple containing all nodes in the reachability graph."""
        return tuple(self._code_node_reachability_graph.nodes)

    @property
    def edges(self) -> InsertionOrderedSet[CodeNode]:
        """Return a set containing all edges in the reachability graph."""
        return InsertionOrderedSet(self._code_node_reachability_graph.edges)

    def reachable_from(self, code_node: CodeNode) -> InsertionOrderedSet[CodeNode]:
        """Returns a set of all code nodes reachable from the given code node."""
        return InsertionOrderedSet(self._code_node_reachability_graph.successors(code_node))

    def reaching(self, code_node: CodeNode) -> InsertionOrderedSet[CodeNode]:
        """Returns a set of all code nodes reaching the given code node."""
        return InsertionOrderedSet(self._code_node_reachability_graph.predecessors(code_node))

    def add_code_node(self, code_node: CodeNode):
        """Adds a code node to the reachability graph."""
        self._code_node_reachability_graph.add_node(code_node)

    def remove_code_node(self, code_node: CodeNode):
        """Removes a code node to the reachability graph."""
        self._code_node_reachability_graph.remove_node(code_node)

    def add_reachability(self, reaches: CodeNode, reachable: CodeNode):
        """Adds an edge (reaches, reachable) to the reachability graph to indicate that the node 'reaches' reaches the node 'reachable'."""
        self._code_node_reachability_graph.add_edge(reaches, reachable)

    def add_reachability_from(self, reachable_pairs: Iterable[Tuple[CodeNode, CodeNode]]):
        """Adds reachability for all given tuples."""
        for reaches, reachable in reachable_pairs:
            self._code_node_reachability_graph.add_edge(reaches, reachable)

    def contract_code_nodes(self, contracted: CodeNode, other_node: CodeNode):
        """Contract the given nodes into the code node contracted."""
        self._code_node_reachability_graph.add_edges_from(((contracted, reachable) for reachable in self.reachable_from(other_node)))
        self._code_node_reachability_graph.add_edges_from(((reaching, contracted) for reaching in self.reaching(other_node)))

    def add_reachability_for_fallthrough_cases(self, fallthrough_cases: List[CaseNode]):
        """Add reachability for all empty fallthrough cases. The last node is the only node that has a non-empty code node."""
        if len(fallthrough_cases) == 1:
            return
        assert all(case.child.is_empty_code_node for case in fallthrough_cases[:-1]), "Only the last case-child is not an empty code node."
        descendant_code_nodes = InsertionOrderedSet(fallthrough_cases[-1].get_descendant_code_nodes())

        for case_node1, case_node2 in zip(fallthrough_cases[:-1], fallthrough_cases[1:-1]):
            self.add_reachability(case_node1.child, case_node2.child)

        for code_node in descendant_code_nodes:
            self.add_reachability_from(
                (reaching, fallthrough_cases[0].child) for reaching in self.reaching(code_node) if reaching not in descendant_code_nodes
            )
            self.add_reachability(fallthrough_cases[-2].child, code_node)

    def get_reachable_and_descendant_code_nodes_of(
        self, node: AbstractSyntaxTreeNode
    ) -> Tuple[InsertionOrderedSet[CodeNode], InsertionOrderedSet[CodeNode]]:
        """Returns all descendant code nodes as well as all code nodes that are reachable from this node."""
        descendant_code_nodes: InsertionOrderedSet[CodeNode] = InsertionOrderedSet(node.get_descendant_code_nodes())
        reachable_code_nodes = self.get_nodes_reachable_from(descendant_code_nodes)
        return reachable_code_nodes, descendant_code_nodes

    def get_nodes_reachable_from(self, descendant_code_nodes: InsertionOrderedSet[CodeNode]) -> InsertionOrderedSet[CodeNode]:
        """Given a set of nodes, returns the nodes that are reachable from this set."""
        reachable_code_nodes: InsertionOrderedSet[CodeNode] = InsertionOrderedSet()
        for descendant in descendant_code_nodes:
            reachable_code_nodes.update(self.reachable_from(descendant))
        reachable_code_nodes -= descendant_code_nodes  # type: ignore
        return reachable_code_nodes

    def compute_sibling_reachability_of(self, ast_nodes: Tuple[AbstractSyntaxTreeNode, ...]) -> SiblingReachability:
        """Return the sibling reachability of the given set of siblings."""
        assert all(ast_nodes[0].parent == node.parent for node in ast_nodes[1:]), "All nodes must have the same parent."
        return SiblingReachability.compute_sibling_reachability_from(self, ast_nodes)

    def reaches(self, node_1, node_2) -> bool:
        """Checks whether node_1 reaches node_2"""
        return (node_1, node_2) in self.edges

    def remove_reachability_between(self, ast_nodes: Iterable[AbstractSyntaxTreeNode]):
        descendant_sets: List[Set[CodeNode]] = [set(node.get_descendant_code_nodes()) for node in ast_nodes]
        for descendant_set_1, descendant_set_2 in permutations(descendant_sets, 2):
            for node1, node2 in product(descendant_set_1, descendant_set_2):
                if self.reaches(node1, node2):
                    self._code_node_reachability_graph.remove_edge(node1, node2)


class SiblingReachabilityGraph:
    """Graph representation of the reaches attribute of a set of AST-nodes."""

    def __init__(self, sibling_reachability: SiblingReachability, ast_nodes: Optional[Tuple[AbstractSyntaxTreeNode]] = None) -> None:
        """
        Reachability Graph to handle the ordering of case-nodes.
        """
        self._case_node_reachability_graph = DiGraph()
        if ast_nodes is None:
            self._case_node_reachability_graph.add_nodes_from(sibling_reachability.nodes)
        else:
            self._case_node_reachability_graph.add_nodes_from(ast_nodes)

        for node in self.nodes:
            for reachable_node in sibling_reachability.reachable_siblings_of(node):
                if reachable_node in self.nodes:
                    self._case_node_reachability_graph.add_edge(node, reachable_node)

    @property
    def nodes(self) -> InsertionOrderedSet[AbstractSyntaxTreeNode]:
        """Return a set containing all nodes in the reachability graph."""
        return InsertionOrderedSet(self._case_node_reachability_graph.nodes)

    @property
    def edges(self) -> InsertionOrderedSet[AbstractSyntaxTreeNode]:
        """Return a set containing all edges in the reachability graph."""
        return InsertionOrderedSet(self._case_node_reachability_graph.edges)

    def in_degree(self, node: AbstractSyntaxTreeNode) -> int:
        """Return the amount of edges pointing to the given node."""
        return len(self._case_node_reachability_graph.in_edges(node))

    def out_degree(self, node: AbstractSyntaxTreeNode) -> int:
        """Return the amount of edges starting at the given node."""
        return len(self._case_node_reachability_graph.out_edges(node))

    def reachable_cases_of(self, node: AbstractSyntaxTreeNode) -> Tuple[CaseNode, ...]:
        """Returns a tuple of all case nodes reachable from the given case node."""
        return tuple(self._case_node_reachability_graph.successors(node))

    def cases_reaching(self, node: AbstractSyntaxTreeNode) -> Tuple[AbstractSyntaxTreeNode, ...]:
        """Returns a set of all case nodes reaching the given case node."""
        return tuple(self._case_node_reachability_graph.predecessors(node))

    def add_reachability(self, reaches: CaseNode, reachable: CaseNode):
        """Adds an edge (reaches, reachable) to the reachability graph to indicate that the node 'reaches' reaches the node 'reachable'."""
        assert (
            reaches in self._case_node_reachability_graph and reachable in self._case_node_reachability_graph
        ), "Both endpoints must be in the graph"
        self._case_node_reachability_graph.add_edge(reaches, reachable)

    def add_reachability_from(self, edges: Iterable[Tuple[AbstractSyntaxTreeNode, AbstractSyntaxTreeNode]]):
        """Adds reachability for all given tuples."""
        for edge in edges:
            self.add_reachability(*edge)

    def remove_reachability(self, edge: Tuple[AbstractSyntaxTreeNode, AbstractSyntaxTreeNode]):
        """Remove reachability for the given tuple."""
        self._case_node_reachability_graph.remove_edge(*edge)

    def remove_reachability_from(self, edges: List[Tuple[AbstractSyntaxTreeNode, AbstractSyntaxTreeNode]]):
        """Remove reachability for the given list of tuple."""
        for edge in edges:
            self.remove_reachability(edge)

    def has_path(self, source: AbstractSyntaxTreeNode, sink: AbstractSyntaxTreeNode, no_edge=False) -> bool:
        """
        Check whether there is a path from source to sink in the reachability graph.

        - If no-edge is True, we check whether there is a path between these two nodes that does not consist of a single edge,
          i.e., has length at least 2.
        - If no-edge is False, it is a normal has_path check.
        """
        assert source in self._case_node_reachability_graph.nodes, f"Source {source} not in the graph"
        assert sink in self._case_node_reachability_graph.nodes, f"Sink {sink} not in the graph."
        removed_edge = False
        if no_edge and sink in set(self.reachable_cases_of(source)):
            self.remove_reachability((source, sink))
            removed_edge = True
        path_exists = has_path(self._case_node_reachability_graph, source, sink)
        if removed_edge:
            self.add_reachability(source, sink)
        return path_exists

    def update_when_inserting_new_case_node(self, node: AbstractSyntaxTreeNode, switch: SwitchNode) -> None:
        """Update the sibling reachability when we add a case node to the given switch."""
        sibling = node if node in self.nodes else node.parent.parent
        self.add_reachability_from((switch, reachable) for reachable in self.reachable_cases_of(sibling))
        self.add_reachability_from((reaching, switch) for reaching in self.cases_reaching(sibling))
        if sibling == node:
            self._case_node_reachability_graph.remove_node(node)

    def topological_order(self) -> Tuple[AbstractSyntaxTreeNode]:
        """Compute a topological order of the reachability graph and returns None if none exist."""
        try:
            return tuple(topological_sort(self._case_node_reachability_graph))
        except NetworkXUnfeasible:
            raise ValueError(f"The reachability graph contains cycles.")

    def get_weakly_connected_components(self) -> Tuple[Set[CaseNode]]:
        """Returns all weakly connected components."""
        return tuple(weakly_connected_components(self._case_node_reachability_graph))

    def get_cross_nodes_of(self, considered_nodes: Iterable[AbstractSyntaxTreeNode]) -> List[AbstractSyntaxTreeNode]:
        """
        Returns a list of all cross nodes of the reachability graph that are contained in the given set of AST-nodes.

        -> A cross node is a node where the in-degree or out-degree is larger than one.
        """
        return [case for case in considered_nodes if self.in_degree(case) > 1 or self.out_degree(case) > 1]

    def component_is_too_complex_for_ordering(self, connected_component: List[AbstractSyntaxTreeNode]) -> Set[AbstractSyntaxTreeNode]:
        """
        Checks whether the possible nodes that are in the given component are too nested to bring them in order.
        If they are too nested, then we return the set of cross nodes.

        So far, we can handle:
            a) one cross node
            b) two cross nodes c1 and c2 (wlog c1 reaches c2) if every node that reaches c2 also reaches c1 or is on a c1,c2-path
                and every node that is reachable from c1 is also reachable from c2 or is on a c1,c2-path.
        """
        cross_nodes = self.get_cross_nodes_of(connected_component)
        if len(cross_nodes) > 2:
            return set(cross_nodes)
        if len(cross_nodes) <= 1:
            return set()

        if has_path(self._case_node_reachability_graph, cross_nodes[0], cross_nodes[1]):
            cross_node_1, cross_node_2 = cross_nodes
        else:
            cross_node_2, cross_node_1 = cross_nodes

        for node in connected_component:
            if self.in_degree(node) == 0 and not has_path(self._case_node_reachability_graph, node, cross_node_1):
                return set(cross_nodes)
            if self.out_degree(node) == 0 and not has_path(self._case_node_reachability_graph, cross_node_2, node):
                return set(cross_nodes)

        return set()

    def subgraph(self, nodes: Iterable[AbstractSyntaxTreeNode]) -> SiblingReachabilityGraph:
        """Computes the subgraph with the given node set."""
        subgraph = self.__class__(SiblingReachability())
        subgraph._case_node_reachability_graph.add_nodes_from(nodes)
        for node in subgraph.nodes:
            subgraph._case_node_reachability_graph.add_edges_from(
                (node, successor) for successor in self.reachable_cases_of(node) if successor in subgraph.nodes
            )

        return subgraph

    def reaches(self, node_1, node_2) -> bool:
        """Checks whether node_1 reaches node_2"""
        return (node_1, node_2) in self._case_node_reachability_graph.edges


class CaseDependencyGraph(SiblingReachabilityGraph):
    """Graph representation of the reaches attribute of a set of AST-nodes using only the necessary edges."""

    def __init__(self, sibling_reachability: SiblingReachability, ast_nodes: Optional[Tuple[AbstractSyntaxTreeNode]] = None):
        """Initialize the case dependency graph."""
        super().__init__(sibling_reachability, ast_nodes)

        self.remove_redundant_edges()

    def __contains__(self, node: AbstractSyntaxTreeNode) -> bool:
        return node in self._case_node_reachability_graph.nodes

    @classmethod
    def construct_case_dependency_for(cls, ast_nodes: Tuple[CaseNode], sibling_reachability: SiblingReachability) -> CaseDependencyGraph:
        """Construct the case-dependency graph given the sibling reachability of the case children."""
        case_dependency_graph = cls(SiblingReachability())
        case_dependency_graph._case_node_reachability_graph.add_nodes_from(ast_nodes)
        for case in ast_nodes:
            for reachable in sibling_reachability.reachable_siblings_of(case.child):
                if (parent := reachable.parent) not in case_dependency_graph:
                    continue
                case_dependency_graph.add_reachability(case, parent)

        case_dependency_graph.remove_redundant_edges()
        return case_dependency_graph

    def remove_redundant_edges(self) -> None:
        """
        We remove all redundant edges of the given graph, to make it as sparse as possible.

        -> An edge (a,b) is redundant if there exists an a,b-path of length at least two.
        -> Or equivalent: (a,b) is redundant if b is also reachable from a successor of a.
        """
        reachable_from_node: Dict[AbstractSyntaxTreeNode, Set[AbstractSyntaxTreeNode]] = dict()

        for node in reversed(self.topological_order()):
            successors = set(self.reachable_cases_of(node))
            reachable_from_node[node] = set(chain(*(reachable_from_node[succ] for succ in successors)))
            for succ in successors:
                if succ in reachable_from_node[node]:
                    self._case_node_reachability_graph.remove_edge(node, succ)
                else:
                    reachable_from_node[node].add(succ)

    def find_partial_order_of_cases(self) -> Iterable[Tuple[CaseNode, List[CaseNode]]]:
        """
        Return a partial ordering of the case nodes, i.e., order the case nodes that have a unique order.
        """
        pre_ordered_cases = {node: order for order, node in enumerate(topological_sort(self._case_node_reachability_graph))}
        considered_nodes = set()
        for case_node in pre_ordered_cases:
            if case_node in considered_nodes:
                continue
            new_considered_nodes, linear_order = self._get_linear_order_starting_at(case_node)
            considered_nodes.update(new_considered_nodes)
            yield case_node, linear_order

    def _get_linear_order_starting_at(self, case_node: CaseNode) -> Tuple[Set[CaseNode], List[CaseNode]]:
        """
        Gets the unique linear order starting at the given case node.

        - If the constant of the node is "add_to_previous_case", then something went wrong because we have no previous case.
        """
        if case_node.constant == Constant("add_to_previous_case"):
            raise ValueError(f"Can not merge the case node {case_node} with another one.")
        considered_nodes: Set[CaseNode] = {case_node}
        successors = list(self.reachable_cases_of(case_node))
        linear_order = [case_node]
        while len(successors) == 1:
            current_node = successors[0]
            if self.in_degree(current_node) > 1:
                break
            else:
                linear_order.append(current_node)
            considered_nodes.add(current_node)
            successors = list(self.reachable_cases_of(current_node))

        return considered_nodes, linear_order

    def get_too_nested_cases(self) -> Iterable[CaseNode]:
        """
        We return the nodes that are too nested

        If we have nodes, say c1, c2, c3, c4 and c5 s.t. c1 reaches c3 and c4, c2 reaches c3 and c5 and c3 reaches c4 and c5
        then it is impossible to sort the cases without adding too many additional conditions.
        """
        for connected_component in self.get_weakly_connected_components():
            yield from self.component_is_too_complex_for_ordering(list(connected_component))


class LinearOrderDependency(SiblingReachabilityGraph):
    """Graph representation of the connections of the linear-orders of the reaches attribute."""

    @classmethod
    def from_linear_dependency(
        cls, case_dependency_graph: CaseDependencyGraph, linear_ordering_starting_at: Dict[CaseNode, List[CaseNode]]
    ) -> LinearOrderDependency:
        """
        Construct a graph that tells us how the case nodes of the given switch node, where a unique linear order starts,
        depend on each other

        -> Given the case_dependency_graph, we merge all nodes that have a unique linear order to the node where
        these order starts
        -> All nodes in linear_ordering_starting_at[case_node] are contracted into case_node in the case_dependency_graph.
        """
        linear_dependency_graph = cls(SiblingReachability())
        for case_node in linear_ordering_starting_at:
            linear_dependency_graph._case_node_reachability_graph.add_node(case_node)
            last_node_in_order = linear_ordering_starting_at[case_node][-1]
            for successor in case_dependency_graph.reachable_cases_of(last_node_in_order):
                linear_dependency_graph._case_node_reachability_graph.add_edge(case_node, successor)
        return linear_dependency_graph

    def cross_nodes_are_too_nested(self, cross_nodes: List[CaseNode]) -> bool:
        """
        The function return true if the cross nodes are too nested, i.e., if the first cross node has an out-degree zero successor
        or the second cross node has an in-degree zero predecessor in the linear-order-dependency graph.
        """
        for node in self.reachable_cases_of(cross_nodes[0]):
            if self.out_degree(node) == 0:
                return True
        for node in self.cases_reaching(cross_nodes[1]):
            if self.in_degree(node) == 0:
                return True
        return False

    def substitute_case_node(self, replacee: CaseNode, replacement: CaseNode):
        """Substitute the given case node in the linear order dependency graph."""
        assert (
            replacee in self.nodes and replacement not in self.nodes
        ), f"The replacee node {replacee} must be in the order and the replacement {replacement} not."
        self._case_node_reachability_graph.add_node(replacement)
        self.add_reachability_from((replacement, reachable) for reachable in self.reachable_cases_of(replacee))
        self.add_reachability_from((reaching, replacement) for reaching in self.cases_reaching(replacee))
        self._case_node_reachability_graph.remove_node(replacee)
