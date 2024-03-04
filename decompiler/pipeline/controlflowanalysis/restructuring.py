"""
Module for pattern independent restructuring
"""

from __future__ import annotations

import logging
from typing import List, Optional

from decompiler.pipeline.controlflowanalysis.restructuring_commons.acyclic_restructuring import AcyclicRegionRestructurer
from decompiler.pipeline.controlflowanalysis.restructuring_commons.cyclic_restructuring import CyclicRegionStructurer
from decompiler.pipeline.controlflowanalysis.restructuring_commons.empty_basic_block_remover import EmptyBasicBlockRemover
from decompiler.pipeline.controlflowanalysis.restructuring_options import LoopBreakOptions, RestructuringOptions
from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.ast.ast_nodes import CaseNode, CodeNode, SeqNode, SwitchNode
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.graphs.classifiedgraph import EdgeProperty
from decompiler.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock, TransitionCFG
from decompiler.structures.pseudo import Assignment, Constant, Integer, Variable
from decompiler.task import DecompilerTask
from decompiler.util.decoration import DecoratedAST, DecoratedCFG, DecoratedGraph


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
        self.options: Optional[RestructuringOptions] = None

    def run(self, task: DecompilerTask):
        """
        Generate the abstract syntax tree for the given task based on the control flow graph.
        """
        EmptyBasicBlockRemover(task.graph).remove()
        self.t_cfg = TransitionCFG.generate(task.graph)
        self.asforest = AbstractSyntaxForest.generate_from_code_nodes([node.ast for node in self.t_cfg], self.t_cfg.condition_handler)
        self.options = RestructuringOptions.generate(task.options)

        # DecoratedCFG.from_cfg(task.graph).export_plot("restructuring.png")

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
        loop_structurer = CyclicRegionStructurer(self.t_cfg, self.asforest, self.options)
        while loop_heads:
            head = loop_heads.pop()
            changed_t_cfg = loop_structurer.restructure(head)
            if changed_t_cfg:
                # Refresh the edge properties and loop_heads if we change the graph due to multiple Entry/Exit restructuring.
                self.t_cfg.refresh_edge_properties()
                loop_heads = self._get_loop_heads()

        AcyclicRegionRestructurer(self.t_cfg, self.asforest, self.options).restructure()
        self._fulfill_switch_options()

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

    def _fulfill_switch_options(self):
        """
        Make sure that all switch-options are fulfilled.

        - We have to first construct all switch nodes because we only know after the construction is done whether they are fulfilled or not.
        """
        for switch_node in self.asforest.get_switch_nodes_post_order():
            if len(switch_node.cases) < self.options.min_switch_cases or (
                self.options.allow_nested_switch is False and self._is_nested_switch(switch_node)
            ):
                self.asforest.replace_switch_by_conditions(switch_node)
            elif self.options.loop_break_strategy == LoopBreakOptions.structural_variable:
                self._handle_loop_breaks(switch_node)
        self.asforest.clean_up(self.t_cfg.root.ast)

    @staticmethod
    def _is_nested_switch(switch_node: SwitchNode) -> bool:
        """Check whether the given switch node has a predecessor that is also a switch node"""
        current_node = switch_node
        while current_node.parent:
            current_node = current_node.parent
            if isinstance(current_node, CaseNode):
                return True
        return False

    def _handle_loop_breaks(self, switch_node: SwitchNode):
        """Introduce the structural-variable for the loop-breaks in switch-cases."""
        break_variable = Variable("loop_break", Integer.int32_t())
        loop_breaks = [node for node in switch_node.get_descendant_code_nodes_interrupting_ancestor_loop() if node.does_end_with_break]
        if not loop_breaks:
            return
        for code_node in loop_breaks:
            code_node.instructions = self.__insert_strutural_assignment(code_node, break_variable)
            if self.__is_last_instruction_of_case(code_node):
                code_node.instructions = code_node.instructions[:-1]
        self.asforest.resolve_loop_breaks_in_switch(switch_node, break_variable)

    def __insert_strutural_assignment(self, code_node: CodeNode, break_variable: Variable):
        """Insert the assignment break_variable = 1."""
        return code_node.instructions[:-1] + [Assignment(break_variable, Constant(1, Integer.int32_t())), code_node.instructions[-1]]

    def __is_last_instruction_of_case(self, code_node: CodeNode):
        return isinstance(code_node.parent, CaseNode) or (
            isinstance(seq := code_node.parent, SeqNode) and code_node is seq.children[-1] and isinstance(seq.parent, CaseNode)
        )
