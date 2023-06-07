from __future__ import annotations

import logging
from itertools import product
from typing import Dict, Optional, Set

from decompiler.pipeline.controlflowanalysis.restructuring_commons.ast_processor import AcyclicProcessor
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement import ConditionAwareRefinement
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_based_refinement import ConditionBasedRefinement
from decompiler.pipeline.controlflowanalysis.restructuring_commons.graphslice import GraphSlice
from decompiler.pipeline.controlflowanalysis.restructuring_commons.reachingconditions import compute_reaching_conditions
from decompiler.pipeline.controlflowanalysis.restructuring_commons.region_finder import AcyclicRegionFinder
from decompiler.pipeline.controlflowanalysis.restructuring_commons.region_finder.acyclic_region_finder import (
    AcyclicRegionFinderFactory,
    Strategy,
)
from decompiler.pipeline.controlflowanalysis.restructuring_options import RestructuringOptions
from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, SeqNode, CodeNode
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock, TransitionCFG
from decompiler.structures.logic.logic_condition import LogicCondition


class AcyclicRegionRestructurer:
    """Class in charge of restructuring acyclic regions."""

    def __init__(self, t_cfg: TransitionCFG, asforest: AbstractSyntaxForest, options: RestructuringOptions):
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
        self.options: RestructuringOptions = options
        self._initialize_code_node_reachability()

    def _initialize_code_node_reachability(self):
        """Initialize the reachability of the code-nodes"""
        reachability_sets: Dict[CodeNode, Set[CodeNode]] = dict()
        descendant_code_of: Dict[TransitionBlock, Set[CodeNode]] = {node: set(node.ast.get_descendant_code_nodes()) for node in self.t_cfg}
        for node in self.t_cfg.iter_postorder():
            reachability_of_descendants: Set[CodeNode] = set()
            for successor in self.t_cfg.get_successors(node):
                reachability_of_descendants.update(descendant_code_of[successor])
                reachability_of_descendants.update(*(reachability_sets[descendant] for descendant in descendant_code_of[successor]))
            for descendant in descendant_code_of[node]:
                reachability_sets[descendant] = reachability_of_descendants

        for node, reachability_sets in reachability_sets.items():
            for reachable in reachability_sets:
                self.asforest._code_node_reachability_graph.add_reachability(node, reachable)

    def restructure(self):
        """Restructure the acyclic transition graph."""
        acyclic_region_finder: AcyclicRegionFinder = AcyclicRegionFinderFactory.create(Strategy.improved_dream)(self.t_cfg)
        while len(self.t_cfg) > 1:
            for node in self.t_cfg.iter_postorder():
                if restructurable_region := acyclic_region_finder.find(node):
                    self._construct_ast_for_region(restructurable_region, node)
                    break
            else:
                raise RuntimeError(f"We are not able to restructure the remaining graph which has still {len(self.t_cfg)} nodes.")

    def _construct_ast_for_region(self, region: Set[TransitionBlock], head: TransitionBlock) -> None:
        """
        Structure an acyclic region, where 'head' is the header of the region.
            1. We compute the graph slice of this region as well as the reaching conditions of each node.
            2. We construct an initial AST, where each node of the graph slice is translated into one Code Node
            3. We refine the initial AST by applying the Condition Based Refinement (restructure if-else) and
               the Condition Aware Refinement (restructure Switches). Besides, we do some pre- and post-processing.
        """
        self.current_region: TransitionCFG = GraphSlice.compute_graph_slice_for_region(self.t_cfg, head, region)

        reaching_conditions: Dict[TransitionBlock, LogicCondition] = compute_reaching_conditions(self.current_region, head, self.t_cfg)
        # reachability_sets: Dict[TransitionBlock, Set[TransitionBlock]] = self._compute_reachability_sets()

        seq_node: SeqNode = self.asforest.construct_initial_ast_for_region(reaching_conditions)

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
        if self.options.reconstruct_switch:
            ConditionAwareRefinement.refine(self.asforest)
        acyclic_processor.postprocess_condition_refinement()
        root = self.asforest.current_root
        self.asforest.remove_current_root()
        return root
