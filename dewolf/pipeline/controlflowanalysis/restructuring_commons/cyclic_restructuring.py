from __future__ import annotations

import logging
from typing import List, Optional, Union

from dewolf.pipeline.controlflowanalysis.restructuring_commons.abnormal_loops import AbnormalEntryRestructurer, AbnormalExitRestructurer
from dewolf.pipeline.controlflowanalysis.restructuring_commons.acyclic_restructuring import AcyclicRegionRestructurer
from dewolf.pipeline.controlflowanalysis.restructuring_commons.graphslice import GraphSlice
from dewolf.pipeline.controlflowanalysis.restructuring_commons.loop_structurer import LoopStructurer
from dewolf.structures.ast.ast_nodes import AbstractSyntaxTreeNode
from dewolf.structures.ast.syntaxforest import AbstractSyntaxForest
from dewolf.structures.graphs.classifiedgraph import EdgeProperty
from dewolf.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock, TransitionCFG
from dewolf.structures.pseudo import Break, Continue
from dewolf.util.insertion_ordered_set import InsertionOrderedSet


class CyclicRegionStructurer:
    """Class that restructures cyclic region."""

    def __init__(self, t_cfg: TransitionCFG, asforest: AbstractSyntaxForest):
        """
        self.t_cfg: The TransitionCFG in which we want to structure cyclic regions
        self.asforest: The corresponding Abstract Syntax Forest
        self.head: Optional[TransitionBlock]: The head of the cyclic region we want to structure.
        self.current_region: Optional[TransitionCFG]: The current loop region we consider.
        self._abnormal_entry_restructure: Class in charge of handling multiple entries
        self._abnormal_exit_restructure: Class in charge of handling multiple exits
        """
        self.t_cfg: TransitionCFG = t_cfg
        self.asforest: AbstractSyntaxForest = asforest
        self.head: Optional[TransitionBlock] = None
        self.current_region: Optional[TransitionCFG] = None
        self.abnormal_entry_restructurer = AbnormalEntryRestructurer(t_cfg, asforest)
        self.abnormal_exit_restructurer = AbnormalExitRestructurer(t_cfg, asforest)

    def restructure(self, head: TransitionBlock) -> bool:
        """
        Restructure the cyclic region with the given Head.

        1. Compute the loop-region
        2. Restructure abnormal entries, if necessary
        3. Compute the set of loop-successors
        4. Restructure abnormal exits, if necessary.
        5. Restructure acyclic loop-body
        6. Construct loop-region

        -> Return True if we change the graph due to multiple entry/exit restructuring.
        """
        self.head = head
        self.current_region = self._compute_loop_nodes()
        graph_changed = False

        if any(edge.property == EdgeProperty.retreating for edge in self.t_cfg.get_in_edges(self.head)):
            logging.info(f"Restructure Abnormal Entry in loop region with head {self.head}")
            self.head = self.abnormal_entry_restructurer.restructure(self.head, self.current_region)
            graph_changed = True

        loop_successors: List[TransitionBlock] = self._compute_loop_successors()
        if len(loop_successors) > 1:
            logging.info(f"Restructure Abnormal Exit in loop region with head {self.head}")
            loop_successors = [self.abnormal_exit_restructurer.restructure(self.head, self.current_region, loop_successors)]
            graph_changed = True

        original_loop_nodes = self.current_region.nodes
        self._prepare_current_region_for_acyclic_restructuring(loop_successors)
        AcyclicRegionRestructurer(self.current_region, self.asforest).restructure()
        restructured_loop_node = self._construct_refined_loop_ast()
        self.t_cfg.collapse_region(original_loop_nodes, restructured_loop_node)

        return graph_changed

    def _compute_loop_nodes(self) -> TransitionCFG:
        """
        Computes the cyclic region for the current head node.
            - Compute the set of latching nodes, i.e., the nodes that have the head as successor.
            - Compute the cyclic region
        """
        latching_nodes: List[TransitionBlock] = self._get_latching_nodes()
        return GraphSlice.compute_graph_slice_for_sink_nodes(self.t_cfg, self.head, latching_nodes, back_edges=False)

    def _get_latching_nodes(self):
        """Return all nodes with outgoing back-edges to the head node."""
        return [edge.source for edge in self.t_cfg.get_in_edges(self.head) if edge.property != EdgeProperty.non_loop]

    def _compute_loop_successors(self) -> List[TransitionBlock]:
        """Compute the set of exit nodes of the current loop region."""
        initial_successor_nodes = self._get_initial_loop_successor_nodes()
        return self._refine_initial_successor_nodes(initial_successor_nodes)

    def _get_initial_loop_successor_nodes(self) -> InsertionOrderedSet[TransitionBlock]:
        """Return the initial set of possible exit nodes for the current loop region."""
        initial_successor_nodes = InsertionOrderedSet()
        for node in self.current_region:
            for successor in self.t_cfg.get_successors(node):
                if successor not in self.current_region:
                    initial_successor_nodes.add(successor)
        return initial_successor_nodes

    def _refine_initial_successor_nodes(self, successor_nodes: InsertionOrderedSet[TransitionBlock]) -> List[TransitionBlock]:
        """
        Refine the set of exit nodes, to avoid unnecessary restructuring.

        :param successor_nodes: The initial set of successors.
        :return: The refined set of successor nodes.
        """
        while len(successor_nodes) > 1:
            new_successor_nodes: InsertionOrderedSet[TransitionBlock] = InsertionOrderedSet()
            for node in list(successor_nodes):
                if node != self.t_cfg.root and self._all_predecessors_in_current_region(node):
                    successor_nodes.remove(node)
                    self._add_node_to_current_region(node)
                    for successor in self.t_cfg.get_successors(node):
                        # One could check only add the real successors to the check list and then recompute afterwards
                        if successor not in self.current_region:
                            new_successor_nodes.add(successor)
                if len(new_successor_nodes) + len(successor_nodes) <= 1:
                    break
            if not new_successor_nodes:
                break
            successor_nodes.update(new_successor_nodes)
        return [succ_node for succ_node in successor_nodes if succ_node not in self.current_region]

    def _all_predecessors_in_current_region(self, node: TransitionBlock) -> bool:
        """Check whether all predecessors of node 'node' are contained in the current loop region."""
        return all((predecessor in self.current_region) for predecessor in self.t_cfg.get_predecessors(node))

    def _add_node_to_current_region(self, node: TransitionBlock) -> None:
        """
        Add the input node to the current loop region. Note that all predecessors of the node are contained in the current loop region.
        """
        self.current_region.add_node(node)
        self.current_region.add_edges_from(self.t_cfg.get_in_edges(node))
        self.current_region.add_edges_from((edge for edge in self.t_cfg.get_out_edges(node) if edge.sink in self.current_region))

    def _prepare_current_region_for_acyclic_restructuring(self, loop_successors: List[TransitionBlock]):
        """Add continue nodes for the loop-edges and break nodes for the exit edges to the loop region."""
        self._prepend_break_nodes(loop_successors)
        self._prepend_continue_nodes()

    def _prepend_break_nodes(self, loop_successors: List[TransitionBlock]) -> None:
        """
        Add break nodes for all predecessors (in the transition cfg) of the nodes in successors to the current region, i.e.,
        add the edges (node, break_node) to the current region if (node, successor) is in the transition cfg and successor in successors
        """
        for successor in loop_successors:
            self._prepend_node_with_interruption(Break(), successor)

    def _prepend_continue_nodes(self):
        """
        Add continue nodes for all predecessors of the head that are part of the graph slice to the current region, i.e.,
        add the edges (predecessor, continue_node) to the graph slice if (predecessor, head) in the CFG and predecessor in the region.
        """
        self._prepend_node_with_interruption(Continue(), self.head)

    def _prepend_node_with_interruption(self, interruption_statement: Union[Break, Continue], successor: TransitionBlock) -> None:
        """
        Add nodes of the given interruption, in our case continue or break statement, for all predecessors of the given input node
        'successor' that are part of the current region.
            - Add the edges (node, new_node) to the current region.
        """
        assert isinstance(self.current_region, TransitionCFG), "No current region to prepend nodes!"

        for edge in (e for e in self.t_cfg.get_in_edges(successor) if e.source in self.current_region):
            new_code_node = self.asforest.add_code_node([interruption_statement.copy()])
            new_node = self.current_region.create_ast_block(new_code_node)
            self.current_region.add_edge(edge.copy(sink=new_node, edge_property=EdgeProperty.non_loop))

    def _construct_refined_loop_ast(self) -> AbstractSyntaxTreeNode:
        """Construct an AST for the current cyclic region. Return the head of this Region."""
        endless_loop = self.asforest.add_endless_loop_with_body(self.current_region.root.ast)
        return LoopStructurer.refine_loop(self.asforest, root=endless_loop)
