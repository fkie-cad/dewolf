from __future__ import annotations

from typing import List, Optional, Union

from decompiler.pipeline.controlflowanalysis.restructuring_commons.acyclic_restructuring import AcyclicRegionRestructurer
from decompiler.pipeline.controlflowanalysis.restructuring_commons.loop_structurer import LoopStructurer
from decompiler.pipeline.controlflowanalysis.restructuring_commons.region_finder import CyclicRegionFinder
from decompiler.pipeline.controlflowanalysis.restructuring_commons.region_finder.cyclic_region_finder import Strategy
from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.graphs.classifiedgraph import EdgeProperty
from decompiler.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock, TransitionCFG
from decompiler.structures.pseudo import Break, Continue


class CyclicRegionStructurer:
    """Class that restructures cyclic region."""

    def __init__(self, t_cfg: TransitionCFG, asforest: AbstractSyntaxForest):
        """
        self.t_cfg: The TransitionCFG in which we want to structure cyclic regions
        self.asforest: The corresponding Abstract Syntax Forest
        self.head: Optional[TransitionBlock]: The head of the cyclic region we want to structure.
        self.current_region: Optional[TransitionCFG]: The current loop region we consider.
        self.cyclic_region_finder: The class in charge of how to find a restructurable region.
        """
        self.t_cfg: TransitionCFG = t_cfg
        self.asforest: AbstractSyntaxForest = asforest
        self.current_region: Optional[TransitionCFG] = None
        self.cyclic_region_finder = CyclicRegionFinder.strategy(t_cfg, asforest, Strategy.dream)

    def restructure(self, head: TransitionBlock) -> bool:
        """
        Restructure the cyclic region with the given Head.

        1. Compute the loop region.
        2. Prepare the loop-body for restructuring
        3. Restructure acyclic loop-body
        4. Construct loop-region

        -> Return True if we change the graph due to multiple entry/exit restructuring.
        """
        number_of_nodes = len(self.t_cfg)
        self.current_region, loop_successors = self.cyclic_region_finder.find(head)
        graph_changed = number_of_nodes != len(self.t_cfg)

        original_loop_nodes = self.current_region.nodes
        self._prepare_current_region_for_acyclic_restructuring(loop_successors)
        AcyclicRegionRestructurer(self.current_region, self.asforest).restructure()
        restructured_loop_node = self._construct_refined_loop_ast()
        self.t_cfg.collapse_region(original_loop_nodes, restructured_loop_node)

        return graph_changed

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
        self._prepend_node_with_interruption(Continue(), self.current_region.root)

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
