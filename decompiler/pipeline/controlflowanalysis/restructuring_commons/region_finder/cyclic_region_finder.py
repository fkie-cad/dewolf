from __future__ import annotations

import logging
from abc import abstractmethod
from enum import Enum
from typing import List, Optional, Tuple, Type

from decompiler.pipeline.controlflowanalysis.restructuring_commons.graphslice import GraphSlice
from decompiler.pipeline.controlflowanalysis.restructuring_commons.region_finder.abnormal_loops import (
    AbnormalEntryRestructurer,
    AbnormalExitRestructurer,
)
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.graphs.classifiedgraph import EdgeProperty
from decompiler.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock, TransitionCFG
from decompiler.util.insertion_ordered_set import InsertionOrderedSet


class Strategy(Enum):
    """Restructuring Strategies for cyclic regions"""

    dream = "dream"


class CyclicRegionFinderFactory:
    @staticmethod
    def create(strategy: Strategy) -> Type[CyclicRegionFinder]:
        if strategy == Strategy.dream:
            return CyclicRegionFinderDream


class CyclicRegionFinder:
    """Class to find a restructurable cyclic region with a given head."""

    def __init__(self, t_cfg: TransitionCFG, asforest: AbstractSyntaxForest):
        self.t_cfg: TransitionCFG = t_cfg
        self.loop_region: Optional[TransitionCFG] = None

    @abstractmethod
    def find(self, head: TransitionBlock) -> Tuple[TransitionCFG, List[TransitionBlock]]:
        """Return a restrucutrable cyclic region with the given head together with the set of region successors."""


class CyclicRegionFinderDream(CyclicRegionFinder):
    """Class to find a restructurable cyclic region with a given head using the Dream approach."""

    def __init__(self, t_cfg: TransitionCFG, asforest: AbstractSyntaxForest):
        super().__init__(t_cfg, asforest)
        self.abnormal_entry_restructurer = AbnormalEntryRestructurer(t_cfg, asforest)
        self.abnormal_exit_restructurer = AbnormalExitRestructurer(t_cfg, asforest)

    def find(self, head: TransitionBlock) -> Tuple[TransitionCFG, List[TransitionBlock]]:
        """
        Find the cyclic loop-region with the given head.

        1. Compute the initial loop-region
        2. Restructure abnormal entries, if necessary
        3. Compute the set of loop-successors
        4. Restructure abnormal exits, if necessary.
        """
        self.loop_region = self._compute_initial_loop_nodes(head)

        if any(edge.property == EdgeProperty.retreating for edge in self.t_cfg.get_in_edges(head)):
            logging.info(f"Restructure Abnormal Entry in loop region with head {head}")
            self.abnormal_entry_restructurer.restructure(self.loop_region)

        loop_successors: List[TransitionBlock] = self._compute_loop_successors()
        if len(loop_successors) > 1:
            logging.info(f"Restructure Abnormal Exit in loop region with head {self.loop_region.root}")
            loop_successors = [self.abnormal_exit_restructurer.restructure(self.loop_region, loop_successors)]

        return self.loop_region, loop_successors

    def _compute_initial_loop_nodes(self, head: TransitionBlock) -> TransitionCFG:
        """
        Computes the cyclic region for the current head node.
            - Compute the set of latching nodes, i.e., the nodes that have the head as successor.
            - Compute the cyclic region
        """
        latching_nodes: List[TransitionBlock] = self._get_latching_nodes(head)
        return GraphSlice.compute_graph_slice_for_sink_nodes(self.t_cfg, head, latching_nodes, back_edges=False)

    def _get_latching_nodes(self, head: TransitionBlock):
        """Return all nodes with outgoing back-edges to the head node."""
        return [edge.source for edge in self.t_cfg.get_in_edges(head) if edge.property != EdgeProperty.non_loop]

    def _compute_loop_successors(self) -> List[TransitionBlock]:
        """Compute the set of exit nodes of the current loop region."""
        initial_successor_nodes = self._get_initial_loop_successor_nodes()
        return self._refine_initial_successor_nodes(initial_successor_nodes)

    def _get_initial_loop_successor_nodes(self) -> InsertionOrderedSet[TransitionBlock]:
        """Return the initial set of possible exit nodes for the current loop region."""
        initial_successor_nodes = InsertionOrderedSet()
        for node in self.loop_region:
            for successor in self.t_cfg.get_successors(node):
                if successor not in self.loop_region:
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
                        if successor not in self.loop_region:
                            new_successor_nodes.add(successor)
                if len(new_successor_nodes) + len(successor_nodes) <= 1:
                    break
            if not new_successor_nodes:
                break
            successor_nodes.update(new_successor_nodes)
        return [succ_node for succ_node in successor_nodes if succ_node not in self.loop_region]

    def _all_predecessors_in_current_region(self, node: TransitionBlock) -> bool:
        """Check whether all predecessors of node 'node' are contained in the current loop region."""
        return all((predecessor in self.loop_region) for predecessor in self.t_cfg.get_predecessors(node))

    def _add_node_to_current_region(self, node: TransitionBlock) -> None:
        """
        Add the input node to the current loop region. Note that all predecessors of the node are contained in the current loop region.
        """
        self.loop_region.add_node(node)
        self.loop_region.add_edges_from(self.t_cfg.get_in_edges(node))
        self.loop_region.add_edges_from((edge for edge in self.t_cfg.get_out_edges(node) if edge.sink in self.loop_region))
