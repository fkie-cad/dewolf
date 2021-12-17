from __future__ import annotations

from typing import Dict, Iterator, List, Optional, Set, Tuple

from dewolf.structures.ast.condition_symbol import ConditionSymbol
from dewolf.structures.ast.syntaxforest import AbstractSyntaxForest
from dewolf.structures.graphs.classifiedgraph import EdgeProperty
from dewolf.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock, TransitionCFG, TransitionEdge
from dewolf.structures.logic.logic_condition import LogicCondition
from dewolf.structures.pseudo import Assignment, Condition, Constant, Integer, OperationType, Variable


class AbnormalLoopRestructurer:
    """Base Class for structuring multiple entry and exit loops."""

    def __init__(self, t_cfg: TransitionCFG, asforest: AbstractSyntaxForest):
        """
        :param t_cfg: The TransitionCFG that contains the multiple entry/exit region we want to restructure
        :param asforest: The according asforest that belongs to the given transition graph.
        """
        self.t_cfg = t_cfg
        self.asforest = asforest
        self.current_region: Optional[TransitionCFG] = None

    def _construct_condition_nodes(self, new_variable: Variable, amount: int) -> Iterator[Tuple[TransitionBlock, LogicCondition]]:
        """
        Construct the conditional nodes, that decide at which entry we enter resp. at which exit we leave the cyclic region.

        :param new_variable: The new variable, which we use for comparison to choose the loop entry .
        :param amount: The number of conditions nodes we want to construct.
        :return: An Iterator of all condition nodes we need to restructure the cycle.
        """
        for index in range(amount):
            condition_node = self.t_cfg.create_ast_block(cn := self.asforest.factory.create_code_node([]))
            self.asforest.add_code_node(cn)

            condition_symbol: ConditionSymbol = self.asforest.condition_handler.add_condition(
                Condition(OperationType.equal, [new_variable, Constant(index, Integer.int32_t())])
            )

            yield condition_node, condition_symbol.symbol

    def _construct_code_nodes(self, new_variable: Variable, amount: int) -> Iterator[TransitionBlock]:
        """
        Construct the number of code nodes, that assign to the new "comparison" variable a value, which tells us where we enter the cycle.

        :param new_variable: The new variable to which we assign a value.
        :param amount: The number of code nodes we want to construct.
        :return: An Iterator of all code nodes that we need to restructure the cycle.
        """
        for index in range(amount):
            code_node = self.asforest.factory.create_code_node([Assignment(new_variable, Constant(index, Integer.int32_t()))])
            self.asforest.add_code_node(code_node)
            yield self.t_cfg.create_ast_block(code_node)

    def _add_edges_between_code_nodes_and(self, sink: TransitionBlock, code_nodes: List[TransitionBlock]) -> None:
        """
        Add an edge between each new code node and the new loop head 'new_head'
        """
        for node in code_nodes:
            self.t_cfg.add_edge(TransitionEdge(node, sink, self.asforest.condition_handler.get_true_value(), EdgeProperty.non_loop))

    def _add_edges_between_conditional_nodes(self, condition_nodes: List[Tuple[TransitionBlock, LogicCondition]]) -> None:
        """
        Adds an edge between the new conditional nodes, i.e., we have the given list of condition nodes and add an edge between the ith and
        ith+1 condition node which is the false-edge of the condition node. Thus, this edge has the negated condition of the source
        condition node of this edge.
        """
        for source, sink in zip(condition_nodes[:-1], condition_nodes[1:]):
            self.t_cfg.add_edge(TransitionEdge(source[0], sink[0], ~source[1], EdgeProperty.non_loop))


class AbnormalEntryRestructurer(AbnormalLoopRestructurer):
    """Class to handle the restructuring of abnormal entry loops."""

    def __init__(self, t_cfg: TransitionCFG, asforest: AbstractSyntaxForest):
        """
        self.entry_edges_to_loop_entry maps to each entry-node, i.e., node that has a predecessor outside the region,
            the set of ingoing edges from a predecessor outside the region.
        """
        super().__init__(t_cfg, asforest)
        self.entry_edges_to_loop_entry: Optional[Dict[TransitionBlock, Tuple[TransitionEdge]]] = None

    def restructure(self, head: TransitionBlock, current_region: TransitionCFG) -> TransitionBlock:
        """
        This function restructures multiple entry loops, by redirecting all loop entries to a new header and adding cascading conditions to
         start as an abnormal entry.
            1. We compute all entry nodes as well as the entry edges
            2. We add a new variable whose value tells us which entry we should choose.
            3. We construct conditional nodes to redirect the entries, as well as code nodes to set the value of the new variable.
            4. The new head of the cyclic region is the condition node that decides whether we enter the region through the original head.
            5. Restructure the region accordingly (cf. DREAM  Figure 12)

        :param head: The head of the multiple entry loop.
        :param current_region: The region of the multiple entry loop.
        """
        self.current_region = current_region
        self._initialize_abnormal_entries()

        number_of_entries: int = len(self.entry_edges_to_loop_entry)
        new_variable = Variable(f"entry_{head.name}", Integer.int32_t())

        condition_nodes: List[Tuple[TransitionBlock, LogicCondition]] = list(
            self._construct_condition_nodes(new_variable, number_of_entries - 1)
        )
        code_nodes: List[TransitionBlock] = list(self._construct_code_nodes(new_variable, number_of_entries))

        new_head: TransitionBlock = condition_nodes[0][0]
        self._update_transition_cfg(code_nodes, condition_nodes, head, new_head)
        self._update_loop_region_abnormal_entry(condition_nodes)

        return new_head

    def _update_transition_cfg(self, code_nodes, condition_nodes, head, new_head):
        """Updates the transition cfg such that the current loop region has no abnormal entry anymore."""
        self._add_edges_between_code_nodes_and(new_head, code_nodes)
        self._add_edges_between_conditional_nodes(condition_nodes)
        self._redirect_loop_edges(head, new_head)
        self._redirect_abnormal_entries(head, code_nodes, condition_nodes)

    def _initialize_abnormal_entries(self) -> None:
        """
        Initialize the dictionary that maps the abnormal entry nodes to their ingoing edges in the region.

        -> Initialize the entry_edges_to_loop_entry dictionary that maps to each entry node the set of entry edges,
                 i.e., v region node and w not in region, map v -> {(w,v),...}
        """
        self.entry_edges_to_loop_entry: Dict[TransitionBlock, Tuple[TransitionEdge]] = dict()
        for node in self.current_region.nodes:
            if entry_edges := tuple(edge for edge in self.t_cfg.get_in_edges(node) if edge.source not in self.current_region):
                self.entry_edges_to_loop_entry[node] = entry_edges

    def _redirect_loop_edges(self, old_head: TransitionBlock, new_head: TransitionBlock) -> None:
        """
        We redirect the back and retreating edges with sink 'old_head' to the node head 'new_head',
        i.e., each loop-edge will have the new head as sink.
        """
        for edge in self.t_cfg.get_in_edges(old_head):
            if edge.property != EdgeProperty.non_loop:
                self.t_cfg.substitute_edge(edge, edge.copy(sink=new_head))

    def _redirect_abnormal_entries(
        self,
        head: TransitionBlock,
        code_nodes: List[TransitionBlock],
        condition_nodes: List[Tuple[TransitionBlock, LogicCondition]],
    ) -> None:
        """
        This function adds the edges between the Condition nodes and the abnormal entries. Furthermore, it redirects the abnormal entry
        edges to the Code nodes.

        :param head: The original head of the loop region.
        :param code_nodes: The list of new Code nodes.
        :param condition_nodes: The list of new Condition nodes.
        """
        sorted_entries: List[TransitionBlock] = [head] + [node for node in self.entry_edges_to_loop_entry if node != head]
        extended_condition_nodes = condition_nodes + [(condition_nodes[-1][0], ~condition_nodes[-1][1])]
        for transition_block, condition_node, code_node in zip(sorted_entries, extended_condition_nodes, code_nodes):
            self.t_cfg.add_edge(TransitionEdge(condition_node[0], transition_block, condition_node[1], EdgeProperty.non_loop))
            for edge in self.entry_edges_to_loop_entry[transition_block]:
                self.t_cfg.substitute_edge(edge, edge.copy(sink=code_node))

        self._add_assignment_to_abnormal_entries(sorted_entries[1:], code_nodes[0].ast.instructions[0])

    def _add_assignment_to_abnormal_entries(self, sorted_abnormal_entries: List[TransitionBlock], assignment: Assignment):
        """Add the assignment new_variable = 0 after each entry, so that after the first loop entry, we always choose the correct entry."""
        for node in sorted_abnormal_entries:
            node.ast = self.asforest.add_instructions_after(node.ast, assignment)

    def _update_loop_region_abnormal_entry(self, condition_nodes: List[Tuple[TransitionBlock, LogicCondition]]) -> None:
        """This functions updates the loop region, i.e., it adds the condition nodes as well as their outgoing edges to the cfg."""
        for node, _ in condition_nodes:
            self.current_region.add_edges_from(self.t_cfg.get_out_edges(node))
        self.current_region.root = condition_nodes[0][0]


class AbnormalExitRestructurer(AbnormalLoopRestructurer):
    """Class to handle the restructuring of abnormal exit loops."""

    def __init__(self, t_cfg: TransitionCFG, asforest: AbstractSyntaxForest):
        """
        self.exit_edges_to_loop_successor maps to each loop successor the set of ingoing edges that have the source in the region.
        self.exit_nodes the set of all exit nodes of the region, i.e., all nodes that have a successor outside the region.
        """
        super().__init__(t_cfg, asforest)
        self.exit_edges_to_loop_successor: Optional[Dict[TransitionBlock, Tuple[TransitionEdge]]] = None
        self.exit_nodes: Optional[Set[TransitionBlock]] = None

    def restructure(self, head: TransitionBlock, current_region: TransitionCFG, loop_successors: List[TransitionBlock]) -> TransitionBlock:
        """
        This function restructures multiple exit loops, by redirecting all each abnormal exit to one exit node and use cascading condition
        nodes that transfer control to the original exit.

        :param current_region: The loop region.
        :param head: The head of the multiple exit loop
        :param loop_successors: The region of the multiple exit loop.
        """
        self.current_region = current_region
        self._find_abnormal_exits(loop_successors)

        number_of_successors: int = len(loop_successors)
        new_variable = Variable(f"exit_{head.name}", Integer.int32_t())

        condition_nodes: List[Tuple[TransitionBlock, LogicCondition]] = list(
            self._construct_condition_nodes(new_variable, number_of_successors - 1)
        )
        code_nodes: List[TransitionBlock] = list(self._construct_code_nodes(new_variable, number_of_successors))

        new_successor = condition_nodes[0][0]
        self._update_transition_cfg(code_nodes, condition_nodes, new_successor)
        self._update_loop_region_abnormal_exits(code_nodes)

        return new_successor

    def _find_abnormal_exits(self, loop_successors: List[TransitionBlock]):
        """
        This function finds for each of the given loop successor the set of ingoing edge
        Furthermore, we compute the set of exit nodes, i.e., nodes in the region that have an successor outside the region.

        -> Initialize the exit_edge_to_loop_successor dictionary that maps to each loop successor node the set of entry edges,
                 i.e., v loop successor and w in region, map v -> {(w,v),...}
        -> Initialize the set exit_nodes that contains all exit nodes of the region.
        """
        self.exit_edges_to_loop_successor: Dict[TransitionBlock, Set[TransitionEdge]] = dict()
        self.exit_nodes: Set[TransitionBlock] = set()
        for node in loop_successors:
            exit_edges = tuple(edge for edge in self.t_cfg.get_in_edges(node) if edge.source in self.current_region)
            self.exit_edges_to_loop_successor[node] = exit_edges
            self.exit_nodes.update(exit_edge.source for exit_edge in exit_edges)

    def _update_transition_cfg(
        self,
        code_nodes: List[TransitionBlock],
        condition_nodes: List[Tuple[TransitionBlock, LogicCondition]],
        new_successor: TransitionBlock,
    ):
        """Updates the transition cfg such that the current loop region has no abnormal exit anymore."""
        self._add_edges_between_code_nodes_and(new_successor, code_nodes)
        self._add_edges_between_conditional_nodes(condition_nodes)
        self._redirect_abnormal_exits(code_nodes, condition_nodes)

    def _redirect_abnormal_exits(self, code_nodes: List[TransitionBlock], condition_nodes: List[Tuple[TransitionBlock, LogicCondition]]):
        """
        Add the edges between the Condition nodes and the loop successors and between the loop exits and the Code nodes.

        :param code_nodes: The list of new Code nodes.
        :param condition_nodes: The list of new Condition nodes.
        """
        sorted_successors: List[TransitionBlock] = self._sort_loop_successors()
        extended_condition_nodes = condition_nodes + [(condition_nodes[-1][0], ~condition_nodes[-1][1])]
        for transition_block, condition_node, code_node in zip(reversed(sorted_successors), extended_condition_nodes, code_nodes):
            # We can not find the correct type, so we recompute it and set it to None temporary
            edge_property = None
            self.t_cfg.add_edge(TransitionEdge(condition_node[0], transition_block, condition_node[1], edge_property))
            for edge in self.exit_edges_to_loop_successor[transition_block]:
                self.t_cfg.substitute_edge(edge, edge.copy(sink=code_node, edge_property=EdgeProperty.non_loop))

    def _sort_loop_successors(self) -> List[TransitionBlock]:
        """This functions sorts the set of all loop successors according to the topological order of their predecessors."""
        sorted_successors = []
        all_successors = set(self.exit_edges_to_loop_successor.keys())
        for exit_node in (node for node in self.current_region.iter_topological() if node in self.exit_nodes):
            for loop_successor in (node for node in self.t_cfg.get_successors(exit_node) if node in all_successors):
                sorted_successors.append(loop_successor)
                all_successors.remove(loop_successor)
        sorted_successors.reverse()
        return sorted_successors

    def _update_loop_region_abnormal_exits(self, code_nodes: List[TransitionBlock]):
        """This functions updates the loop region, i.e., it adds the code nodes as well as their ingoing edges to the cfg."""
        for node in code_nodes:
            self.current_region.add_edges_from(self.t_cfg.get_in_edges(node))
