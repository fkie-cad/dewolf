"""Module for removing go idioms"""

import os
import shelve
from typing import Callable, Generator, Iterator, List, Optional, Set, Tuple

from decompiler.pipeline.preprocessing.util import _unused_addresses, match_expression
from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import ConditionalEdge, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.graphs.nxgraph import NetworkXGraph
from decompiler.structures.graphs.rootedgraph import RootedGraph
from decompiler.structures.pseudo.expressions import Constant, Expression, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Comment, Phi
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import Integer
from decompiler.task import DecompilerTask
from networkx import MultiDiGraph, dominance_frontiers, reverse_view


class RemoveNoreturnBoilerplate(PipelineStage):
    """
    RemoveNoreturnBoilerplate finds and removes boilerplate related to non-returning functions.
    Caution: this stage changes code semantic
    """

    name = "remove-noreturn-boilerplate"

    def run(self, task: DecompilerTask):
        if task.options.getboolean(f"{self.name}.remove_noreturn_boilerplate", fallback=False):
            self._cfg = task.graph
            self._aggressive_removal_postdominators_merged_sinks()

    def _get_called_functions(self, instructions):
        """
        Helper method to iterate over all called functions in a list of instructions.
        """
        for instruction in instructions:
            if isinstance(instruction, Assignment) and isinstance(instruction.value, Call):
                yield instruction.value.function

    def _get_noreturn_nodes(self) -> Iterator[BasicBlock]:
        """
        Iterate leaf nodes of cfg, yield nodes containing a call to a non-returning funtion.
        """
        leaf_nodes = [x for x in self._cfg.nodes if self._cfg.out_degree(x) == 0]
        for node in leaf_nodes:
            if self._is_noreturn_node(node):
                yield node

    def _is_noreturn_node(self, node: BasicBlock) -> bool:
        """
        Check if node contains call to a non-returning function.
        """
        called_functions = list(self._get_called_functions(node.instructions))
        if len(called_functions) != 1:
            return False
        return called_functions[0].can_return == False

    def _patch_condition_edges(self, edges: List[ConditionalEdge]) -> None:
        """
        This method removes whatever was detected to be boilerplate.

        It works by changing the conditions leading to the boilerplate in a way, that it is never reached.
        """
        removed_nodes = set()
        for edge in edges:
            removed_nodes.update(self._cfg.iter_depth_first(edge.sink))

        for edge in edges:
            match edge:
                case TrueCase():
                    condition = self._get_constant_condition(False)
                case FalseCase():
                    condition = self._get_constant_condition(True)
                case _:
                    continue
            instructions = edge.source.instructions
            assert isinstance(instructions[-1], Branch)
            instructions.pop()
            instructions.append(Comment("Removed potential boilerplate code"))
            instructions.append(Branch(condition))

    def _get_constant_condition(self, value: bool):
        """
        Helper method creating a Pseudo condition that always evaluates to `True` or `False`, depending on `value`.
        """
        int_value = 1 if value else 0
        return Condition(
            OperationType.equal,
            [
                Constant(1, Integer.int32_t()),
                Constant(int_value, Integer.int32_t()),
            ],
        )

    def _aggressive_removal_postdominators_merged_sinks(self):
        if len(self._cfg) == 1:
            return  # do not remove the only node
        noreturn_nodes = list(self._get_noreturn_nodes())
        leaf_nodes = [x for x in self._cfg.nodes if self._cfg.out_degree(x) == 0]
        returning_leaf_nodes = [node for node in leaf_nodes if node not in noreturn_nodes]
        unused_addresses = _unused_addresses(cfg=self._cfg, amount=2)
        virtual_end_node = BasicBlock(address=unused_addresses[0])
        virtual_merged_noreturn_node = BasicBlock(address=unused_addresses[1])
        reversed_cfg_view: MultiDiGraph = self._cfg._graph.reverse(copy=False)
        reversed_cfg_shallow_copy = MultiDiGraph(reversed_cfg_view)
        reversed_cfg_shallow_copy.add_node(virtual_end_node)
        reversed_cfg_shallow_copy.add_node(virtual_merged_noreturn_node)
        for noreturn_node in noreturn_nodes:
            reversed_cfg_shallow_copy.add_edge(virtual_merged_noreturn_node, noreturn_node)
        reversed_cfg_shallow_copy.add_edge(virtual_end_node, virtual_merged_noreturn_node)
        for leaf_node in returning_leaf_nodes:
            reversed_cfg_shallow_copy.add_edge(virtual_end_node, leaf_node)
        post_dominance_frontier = dominance_frontiers(reversed_cfg_shallow_copy, virtual_end_node)
        condition_edges = set()
        wrapped_reverse_cfg = RootedGraph(reversed_cfg_shallow_copy, virtual_end_node)
        for post_dominator in post_dominance_frontier[virtual_merged_noreturn_node]:
            for edge_from_post_dominator in list(self._cfg.get_out_edges(post_dominator)):
                # for edge_from_post_dominator in self._cfg.get_out_edges(post_dominator):
                if wrapped_reverse_cfg.is_dominating(virtual_merged_noreturn_node, edge_from_post_dominator.sink):
                    condition_edges.add(edge_from_post_dominator)
        self._patch_condition_edges(list(condition_edges))
