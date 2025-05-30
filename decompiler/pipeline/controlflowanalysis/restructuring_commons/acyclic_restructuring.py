from __future__ import annotations

import logging
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
from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CodeNode, ConditionNode, SeqNode
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.graphs.interface import GraphEdgeInterface, GraphInterface
from decompiler.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock, TransitionCFG, TransitionEdge
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import Comment
from decompiler.structures.pseudo.instructions import Goto, Label
from decompiler.util.decoration import DecoratedTransitionCFG


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

    def restructure(self):
        """Restructure the acyclic transition graph."""
        counter = 0
        DecoratedTransitionCFG.from_transition_cfg(self.t_cfg).export_plot(f"tcfg-{counter}.png")
        
        acyclic_region_finder: AcyclicRegionFinder = AcyclicRegionFinderFactory.create(Strategy.improved_dream)(self.t_cfg)
        while len(self.t_cfg) > 1:
            for node in self.t_cfg.iter_postorder():
                if restructurable_region := acyclic_region_finder.find(node):
                    changes = False
                    for block in restructurable_region:
                        edges = self.t_cfg.get_out_edges(block)
                        if len(edges) == 0:
                            continue
                        
                        e0, *e_rest = sorted(edges, key=lambda e: self.t_cfg.out_degree(e.sink) > 1)
                        edge: TransitionEdge
                        for edge in e_rest:
                            if self.t_cfg.out_degree(edge.sink) <= 1:
                                continue
                            
                            self.t_cfg.remove_edge(edge)
                            source: TransitionBlock = edge.source
                            target: TransitionBlock = edge.sink
                            
                            label = f"l{target.address}"
                            
                            seq_node = self.asforest._add_sequence_node_before(source.ast)
                            seq_node.reaching_condition = source.ast.reaching_condition
                            condition_node = self.asforest._add_condition_node_with(
                                edge.tag,
                                self.asforest.add_code_node([Goto(label)]),
                                None
                            )
                            self.asforest._add_edge(seq_node, condition_node)
                            seq_node._sorted_children = (source.ast, condition_node)
                            source.ast = seq_node
                            
                            if isinstance(target.ast, CodeNode):
                                target.ast.instructions.insert(0, Label(label))
                            else:
                                seq_node = self.asforest._add_sequence_node_before(target.ast)
                                # seq_node.reaching_condition = target.ast.reaching_condition
                                code_node = self.asforest.add_code_node([Label(label)])
                                self.asforest._add_edge(seq_node, code_node)
                                seq_node._sorted_children = (code_node, target.ast)
                                target.ast = seq_node
                                
                            changes |= True
                    
                    if changes:
                        counter += 1
                        DecoratedTransitionCFG.from_transition_cfg(self.t_cfg).export_plot(f"tcfg-{counter}.png")
                        break

                    self._construct_ast_for_region(restructurable_region, node)
                    counter += 1
                    DecoratedTransitionCFG.from_transition_cfg(self.t_cfg).export_plot(f"tcfg-{counter}.png")
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
        if self.options.reconstruct_switch:
            updated_switch_nodes = ConditionAwareRefinement.refine(self.asforest, self.options)
            for switch_node in updated_switch_nodes:
                for sequence_case in (c for c in switch_node.cases if isinstance(c.child, SeqNode)):
                    ConditionBasedRefinement.refine(self.asforest, sequence_case.child)
        acyclic_processor.postprocess_condition_refinement()
        root = self.asforest.current_root
        self.asforest.remove_current_root()
        return root
