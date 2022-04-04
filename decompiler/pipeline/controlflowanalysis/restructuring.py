"""
Module for pattern independent restructuring
"""
from __future__ import annotations

import logging
from typing import List, Optional

from decompiler.pipeline.controlflowanalysis.restructuring_commons.acyclic_restructuring import AcyclicRegionRestructurer
from decompiler.pipeline.controlflowanalysis.restructuring_commons.cyclic_restructuring import CyclicRegionStructurer
from decompiler.pipeline.controlflowanalysis.restructuring_commons.empty_basic_block_remover import EmptyBasicBlockRemover
from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.graphs.classifiedgraph import EdgeProperty
from decompiler.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock, TransitionCFG
from decompiler.task import DecompilerTask


class PatternIndependentRestructuring(PipelineStage):
    """Pattern independent restructuring"""

    name = "pattern-independent-restructuring"

    def __init__(self, tcfg: Optional[TransitionCFG] = None, asforest: Optional[AbstractSyntaxForest] = None):
        """
        Initialize the Pattern-Independent-Restructuring
            - We first restructure cyclic regions, by finding the back-edges and then restructuring the acyclic loop body.
            - When the graph is acyclic we restructure the remaining acyclic region.

        :param tcfg: The Transition Control-Flow-Graph that we want to restructure
        :param asforest: An asforest that we use to restructure the transition cfg
        """
        self.t_cfg: TransitionCFG = tcfg
        self.asforest: AbstractSyntaxForest = asforest

    def run(self, task: DecompilerTask):
        """
        Generate the abstract syntax tree for the given task based on the control flow graph.
        """
        EmptyBasicBlockRemover(task.graph).remove()
        from decompiler.util.decoration import DecoratedCFG
        DecoratedCFG.from_cfg(task.graph).export_plot(f"/home/eva/Projects/dewolf-decompiler/AST/input&cfg.png")
        self.t_cfg = TransitionCFG.generate(task.graph)
        self.asforest = AbstractSyntaxForest.generate_from_code_nodes([node.ast for node in self.t_cfg], self.t_cfg.condition_handler)

        self.restructure_cfg()

        assert len(self.t_cfg) == 1, f"The Transition Graph can only have one node after the restructuring."
        self.asforest.set_current_root(self.t_cfg.root.ast)
        assert (roots := len(self.asforest.get_roots)) == 1, f"After the restructuring the forest should have one root, but it has {roots}!"
        task._ast = AbstractSyntaxTree.from_asforest(self.asforest, self.asforest.current_root)
        task._cfg = None

    def restructure_cfg(self) -> None:
        """
        This function restructures the given control flow graph.
         - First, we restructure the cyclic regions
         - Second, after removing all cyclic regions we restructure the acyclic regions.

        In more detail, we search for loop-edges to find cyclic regions that we can restructure. As long as there are loop-edges we
        structure their corresponding loop-region.
        Afterwards, the remaining graph is acyclic and we restructure it.
        """
        # Basic Transformations
        if len(self.t_cfg) == 0:
            self._restructure_empty_cfg()
            return
        if len(self.t_cfg) == 1 and len(self.t_cfg.edges):
            self.t_cfg.root.ast = self.asforest.add_endless_loop_with_body(self.t_cfg.root.ast)
            return

        loop_heads: List[TransitionBlock] = self._get_loop_heads()
        loop_structurer = CyclicRegionStructurer(self.t_cfg, self.asforest)
        while loop_heads:
            head = loop_heads.pop()
            changed_t_cfg = loop_structurer.restructure(head)
            if changed_t_cfg:
                # Refresh the edge properties and loop_heads if we change the graph due to multiple Entry/Exit restructuring.
                self.t_cfg.refresh_edge_properties()
                loop_heads = self._get_loop_heads()

        AcyclicRegionRestructurer(self.t_cfg, self.asforest).restructure()

    def _restructure_empty_cfg(self):
        """Restructure the empty transition cfg."""
        code_node = self.asforest.add_code_node()
        self.t_cfg.add_node(TransitionBlock(0, code_node))
        logging.warning(f"The given control flow graph has no node and is therefore empty. Consider to have a look at the Binary.")

    def _get_loop_heads(self):
        """Returns the loop heads in reverse post-order."""
        loop_heads: List[TransitionBlock] = list()
        for node in self.t_cfg.iter_postorder():
            if any(edge.property != EdgeProperty.non_loop for edge in self.t_cfg.get_in_edges(node)):
                loop_heads.append(node)
        loop_heads.reverse()
        return loop_heads
