from __future__ import annotations

import logging
from collections import defaultdict
from typing import DefaultDict, Dict, Optional, Set

from decompiler.pipeline.controlflowanalysis.restructuring_commons.ast_processor import AcyclicProcessor
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement import ConditionAwareRefinement
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_based_refinement import ConditionBasedRefinement
from decompiler.pipeline.controlflowanalysis.restructuring_commons.graphslice import GraphSlice
from decompiler.pipeline.controlflowanalysis.restructuring_commons.reachingconditions import compute_reaching_conditions
from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, SeqNode
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.graphs.interface import GraphInterface
from decompiler.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock, TransitionCFG
from decompiler.structures.logic.logic_condition import LogicCondition


class AcyclicRegionRestructurer:
    """Class in charge of restructuring acyclic regions."""

    MIN_REGION_SIZE = 3

    def __init__(self, t_cfg: TransitionCFG, asforest: AbstractSyntaxForest):
        """
        self.t_cfg: The TransitionCFG in which we want to structure an acyclic regions
        self.asforest: The corresponding Abstract Syntax Forest
        self.head: The head of the cyclic region we want to structure.
        self.current_region The current loop region we consider.
        """
        assert t_cfg.is_acyclic(), f"The given transition graph is not acyclic!"
        self.t_cfg: TransitionCFG = t_cfg
        self.asforest: AbstractSyntaxForest = asforest
        self.head: Optional[TransitionBlock] = None
        self.current_region: Optional[TransitionCFG] = None

    def restructure(self):
        """Restructure the acyclic transition graph."""
        while len(self.t_cfg) > 1:
            for node in self.t_cfg.iter_postorder():
                dominance_region: Set[TransitionBlock] = self._find_minimal_subset_for_restructuring(node)
                if self._is_restructurable(dominance_region, node):
                    self._construct_ast_for_region(dominance_region, node)
                    break
            else:
                raise RuntimeError(f"We are not able to restructure the remaining graph which has still {len(self.t_cfg)} nodes.")

    def _find_minimal_subset_for_restructuring(self, head: TransitionBlock) -> Set[TransitionBlock]:
        """
        Try to find a smaller subset of the dominance region that we can restructure
            - We search for possible exit nodes
            - A possible exit node of a region is a node that would separate the region into two sets.

        :param head: The head of the dominator tree
        :return: A smaller region that we can restructure if possible and the dominance region otherwise
        """
        dominance_region: Set[TransitionBlock] = set(self.t_cfg.dominator_tree.iter_postorder(head))
        if len(dominance_region) <= self.MIN_REGION_SIZE:
            return dominance_region
        region_subgraph: GraphInterface = self.t_cfg.subgraph(tuple(dominance_region))
        possible_exit_nodes = self._get_possible_exit_nodes(region_subgraph)

        for dominator, dominated_nodes in possible_exit_nodes.items():
            if len(smaller_region := dominance_region - dominated_nodes) >= self.MIN_REGION_SIZE and self._has_at_most_one_exit_node(
                smaller_region
            ):
                return smaller_region
        return dominance_region

    def _get_possible_exit_nodes(self, region_subgraph: GraphInterface) -> Dict[TransitionBlock, Set[TransitionBlock]]:
        """
        Computes the set of possible exits nodes for the given region, to find a smaller region for the restructuring.
            - For a possible exit node, the set of dominated vertices should be equal to the set of reachable vertices.
            - If an exit node has only one successor, then we do not consider it as an exit node.
              Considering these exit nodes has no benefit, because the region size only decreases by one and we get problems if this one
              node is a break or continue. Besides, this one node has the same reaching condition as the possible exit node.
        """
        topological_order = list(region_subgraph.iter_topological())
        dominated_by_node: DefaultDict[TransitionBlock, Set[TransitionBlock]] = defaultdict(set)
        reachability_of_node: DefaultDict[TransitionBlock, Set[TransitionBlock]] = defaultdict(set)
        possible_exit_nodes = list()
        for node in reversed(topological_order):
            self.__compute_reachability_and_dominance_for(node, dominated_by_node, reachability_of_node, region_subgraph)
            if (
                dominated_by_node[node]
                and dominated_by_node[node] == reachability_of_node[node]
                and self._has_more_than_one_successor(node)
            ):
                possible_exit_nodes.append(node)
        return {node: dominated_by_node[node] for node in reversed(possible_exit_nodes)}

    def __compute_reachability_and_dominance_for(
        self,
        node: TransitionBlock,
        dominated_by_node: DefaultDict[TransitionBlock, Set[TransitionBlock]],
        reachability_of_node: DefaultDict[TransitionBlock, Set[TransitionBlock]],
        region_subgraph: GraphInterface,
    ):
        """Compute the reachability and dominance for the given node in the given region using the precomputed sets of the successors."""
        for successor in region_subgraph.get_successors(node):
            reachability_of_node[node].update(reachability_of_node[successor])
            reachability_of_node[node].add(successor)
        for child in self.t_cfg.strictly_dominated_by(node):
            dominated_by_node[node].update(dominated_by_node[child])
            dominated_by_node[node].add(child)

    def _has_more_than_one_successor(self, node: TransitionBlock) -> bool:
        """Checks whether the given node has only one successor in the graph."""
        return len(self.t_cfg.get_successors(node)) > 1

    def _is_restructurable(self, dominance_region: Set[TransitionBlock], node: TransitionBlock) -> bool:
        """Checks whether the given acyclic region with given head can be restructured."""
        return self._is_large_enough_region(dominance_region) and (
            self._has_at_most_one_exit_node(dominance_region) or self._has_at_most_one_postdominator(node, dominance_region)
        )

    def _is_large_enough_region(self, region: Set[TransitionBlock]) -> bool:
        """Check whether we can restructure the acyclic region."""
        return (len(self.t_cfg) >= self.MIN_REGION_SIZE and len(region) >= self.MIN_REGION_SIZE) or (
            1 < len(self.t_cfg) < self.MIN_REGION_SIZE and len(region) > 1
        )

    def _has_at_most_one_postdominator(self, header: TransitionBlock, nodes: Set[TransitionBlock]) -> bool:
        """
        This function checks whether at most one vertex post-dominates the region consisting of the sets in nodes with head 'header'.

        :param header: The vertex of which we want to know whether it is post-dominated by at most one vertex.
        :param nodes: The set of nodes that are dominated by the header.
        :return: True, if the header is post-dominated by at most one vertex, and false otherwise.
        """
        region_successors = set(succ for node in nodes for succ in self.t_cfg.get_successors(node)) - nodes
        if len(region_successors) == 0:
            return True
        if len(region_successors) > 1:
            return False
        graph_slice: TransitionCFG = GraphSlice.compute_graph_slice_for_sink_nodes(self.t_cfg, header, list(region_successors))
        diff = set(graph_slice.nodes).symmetric_difference(nodes)
        return diff == region_successors

    def _has_at_most_one_exit_node(self, region_nodes: Set[TransitionBlock]) -> bool:
        """
        Checks whether at most one of the nodes in 'nodes' is an exit node of the region.
            - By exit node we mean nodes that have a successor outside the region.

        :param region_nodes: The set of nodes that we consider for possible exit nodes.
        :return: True, it we have at most one exit node, and False otherwise.
        """
        found_exit = False
        for node in region_nodes:
            if any(successor not in region_nodes for successor in self.t_cfg.get_successors(node)):
                if found_exit:
                    return False
                found_exit = True
        return True

    def _construct_ast_for_region(self, region: Set[TransitionBlock], head: TransitionBlock) -> None:
        """
        Structure a acyclic region, where 'head' is the header of the region.
            1. We compute the graph slice of this region as well as the reaching conditions of each node.
            2. We construct an initial AST, where each node of the graph slice is translated into one Code Node
            3. We refine the initial AST by applying the Condition Based Refinement (restructure if-else) and
               the Condition Aware Refinement (restructure Switches). Besides we do some pre- and post-processing.
        """
        self.current_region: TransitionCFG = GraphSlice.compute_graph_slice_for_region(self.t_cfg, head, region)

        reaching_conditions: Dict[TransitionBlock, LogicCondition] = compute_reaching_conditions(self.current_region, head, self.t_cfg)
        reachability_sets: Dict[TransitionBlock, Set[TransitionBlock]] = self._compute_reachability_sets()

        seq_node: SeqNode = self.asforest.construct_initial_ast_for_region(reaching_conditions, reachability_sets)

        if all(node.is_empty_code_node for node in seq_node.children):
            logging.warning(f"We restructured a graph with at least two nodes that contains no code.")
            self.asforest.remove_empty_nodes(seq_node)
            restructured_region_root = self.asforest.add_code_node()
        else:
            restructured_region_root = self._construct_refined_ast(seq_node)

        self.t_cfg.collapse_region(self.current_region.nodes, restructured_region_root)

    def _compute_reachability_sets(self) -> Dict[TransitionBlock, Set[TransitionBlock]]:
        """
        For each node in graph_slice we compute all nodes in graph_slice that are reachable from this node.

        :return: A dictionary, where we map to each node in graph slices all nodes in graph slices that are reachable from this node.
        """
        reachability_sets: Dict[TransitionBlock, Set[TransitionBlock]] = dict()
        for node in self.current_region.iter_postorder():
            reachability_sets[node] = set()
            for successor in self.current_region.get_successors(node):
                reachability_sets[node].add(successor)
                reachability_sets[node].update(reachability_sets[successor])
        return reachability_sets

    def _construct_refined_ast(self, seq_node_root: SeqNode) -> AbstractSyntaxTreeNode:
        """refines the initial AST of an acyclic region"""
        acyclic_processor = AcyclicProcessor(self.asforest)
        self.asforest.set_current_root(seq_node_root)
        acyclic_processor.preprocess_condition_refinement()
        ConditionBasedRefinement.refine(self.asforest)
        acyclic_processor.preprocess_condition_aware_refinement()
        ConditionAwareRefinement.refine(self.asforest)
        acyclic_processor.postprocess_condition_refinement()
        root = self.asforest.current_root
        self.asforest.remove_current_root()
        return root
