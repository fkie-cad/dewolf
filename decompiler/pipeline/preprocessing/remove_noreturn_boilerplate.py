"""Module for removing go idioms"""

import os
import shelve
from typing import Callable, Generator, Iterator, List, Optional, Set, Tuple

from networkx import DiGraph, MultiDiGraph, dominance_frontiers, reverse_view
from decompiler.pipeline.preprocessing.util import match_expression

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import ConditionalEdge, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.graphs.nxgraph import NetworkXGraph
from decompiler.structures.graphs.rootedgraph import RootedGraph
from decompiler.structures.pseudo.expressions import Constant, Expression, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Comment, Phi
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import Integer
from decompiler.pipeline.preprocessing.util import _unused_addresses
from decompiler.task import DecompilerTask


class RemoveNoreturnBoilerplate(PipelineStage):
    """
    RemoveGoIdioms finds and removes go function prologues,
    Caution: this stage changes code semantic
    """

    name = "remove-noreturn-boilerplate"

    # def run(self, task: DecompilerTask):
    #     for basic_block in task.graph:
    #         for instruction in basic_block:
    #             print(instruction)

    def run(self, task: DecompilerTask):
        # TODO: remove True, make really configurable
        if task.options.getboolean(f"{self.name}.remove_noreturn_boilerplate", fallback=False) or True:
            self._cfg = task.graph
            self._aggressive_removal_postdominators_merged_sinks()
            # self._aggressive_removal_postdominators()
            # self._aggressive_removal()
            # self._non_aggressive_removal()

    def _non_aggressive_removal(self):
        if len(self._cfg) == 1:
            return  # do not remove the only node
        noreturn_nodes = list(self._get_noreturn_nodes())
        for node in noreturn_nodes:
            # # this might be too weak
            # if not any(self._are_ingoing_edges_conditional(node)):
            # This might be too strong
            if not all(self._are_ingoing_edges_conditional(node)):
                continue
            self._remove_boilerplate(node)

    def _get_called_functions(self, instructions):
        for instruction in instructions:
            if isinstance(instruction, Assignment) and isinstance(instruction.value, Call):
                yield instruction.value.function

    def _get_noreturn_nodes(self) -> Iterator[BasicBlock]:
        """
        Iterate leaf nodes of cfg, yield nodes containing canary check.
        """
        leaf_nodes = [x for x in self._cfg.nodes if self._cfg.out_degree(x) == 0]
        for node in leaf_nodes:
            if self._is_noreturn_node(node):
                yield node

    def _is_noreturn_node(self, node: BasicBlock) -> bool:
        """
        Check if node contains call to __stack_chk_fail
        """
        called_functions = list(self._get_called_functions(node.instructions))
        if len(called_functions) != 1:
            return False
        return called_functions[0].can_return == False

    def _are_ingoing_edges_conditional(self, node: BasicBlock):
        for in_edge in self._cfg.get_in_edges(node):
            predecessor = in_edge.source
            yield (len(predecessor.instructions) and isinstance(predecessor.instructions[-1], Branch))

    def _remove_boilerplate(self, node: BasicBlock):
        """
        Patch Branches to stack fail node.
        """
        for pred in self._cfg.get_predecessors(node):
            self._remove_empty_block_between(pred)
        self._cfg.remove_node(node)

    def _remove_empty_block_between(self, node: BasicBlock) -> None:
        """
        Removes empty nodes between stack fail and branch recursively.
        """
        if not node.is_empty():
            self._patch_branch_condition(node)
            return
        for pred in self._cfg.get_predecessors(node):
            self._remove_empty_block_between(pred)
        self._cfg.remove_node(node)

    def _patch_branch_condition(self, node: BasicBlock) -> None:
        """
        If stack fail node is reached via direct Branch, remove Branch.
        """
        branch_instruction = node.instructions[-1]
        if isinstance(branch_instruction, Branch):
            node.instructions = node.instructions[:-1]
            for edge in self._cfg.get_out_edges(node):
                self._cfg.substitute_edge(edge, UnconditionalEdge(edge.source, edge.sink))
            node.instructions.append(Comment("Removed potential boilerplate code"))
        else:
            raise RuntimeError("did not expect to reach canary check this way")

    ######################## super aggressive removal code below####
    # Idea remove everything that will always end in noreturn,
    # except if everything ends in noreturn
    # postdominance....
    # consider set of all no-return nodes N
    # consider set of all nodes postdominating any node of N. call it D
    # (or get an even larger set: consider set of all nodes which will always lead to one of the nodes in N)
    # consider set of all nodes which can (not must) reach a node in N. call it R.
    # There is the Postdominance frontier or s.th like that:
    # Nodes in R which are not in D and are immediately before a node in D. The connection will by construction be conditional. Remove this conditional path.

    def _aggressive_removal(self):
        if len(self._cfg) == 1:
            return  # do not remove the only node
        noreturn_nodes = list(self._get_noreturn_nodes())
        condition_edges = set()
        for node in noreturn_nodes:
            condition_edges.update(set(self._get_conditional_edges_to_patch(node)))
        self._patch_condition_edges(list(condition_edges))

    def _get_conditional_edges_to_patch(self, node: BasicBlock) -> Iterator[ConditionalEdge]:
        for in_edge in self._cfg.get_in_edges(node):
            if isinstance(in_edge, ConditionalEdge):
                yield in_edge
            else:
                for a in self._get_conditional_edges_to_patch(in_edge.source):
                    yield a

    def _patch_condition_edges(self, edges: List[ConditionalEdge]) -> None:
        for edge in edges:
            match edge:
                case TrueCase():
                    condition = self._get_constant_condition(False)
                case FalseCase():
                    condition = self._get_constant_condition(True)
                case _:
                    # TODO: logging
                    continue
            instructions = edge.source.instructions
            assert isinstance(instructions[-1], Branch)
            instructions.pop()
            instructions.append(Comment("Removed potential boilerplate code"))
            instructions.append(Branch(condition))

    # TODO: move to util
    def _get_constant_condition(self, value: bool):
        int_value = 1 if value else 0
        return Condition(
            OperationType.equal,
            [
                Constant(1, Integer.int32_t()),
                Constant(int_value, Integer.int32_t()),
            ],
        )

    ######################## super aggressive removal code (post dominator frontier edition) below ####

    def _aggressive_removal_postdominators(self):
        if len(self._cfg) == 1:
            return  # do not remove the only node
        noreturn_nodes = list(self._get_noreturn_nodes())
        leaf_nodes = [x for x in self._cfg.nodes if self._cfg.out_degree(x) == 0]
        virtual_end_node = BasicBlock(address=_unused_addresses(self._cfg)[0])
        # TODO: MultiDiGraph or DiGraph?
        reversed_cfg_view: MultiDiGraph = self._cfg._graph.reverse(copy=False)
        reversed_cfg_shallow_copy = MultiDiGraph(reversed_cfg_view)
        reversed_cfg_shallow_copy.add_node(virtual_end_node)
        for leaf_node in leaf_nodes:
            reversed_cfg_shallow_copy.add_edge(virtual_end_node, leaf_node)
        post_dominance_frontier = dominance_frontiers(reversed_cfg_shallow_copy, virtual_end_node)
        wrapped_reverse_cfg = RootedGraph(reversed_cfg_shallow_copy, virtual_end_node)
        condition_edges = set()
        for no_return_node in noreturn_nodes:
            for post_dominator in post_dominance_frontier[no_return_node]:
                for edge_from_post_dominator in self._cfg.get_out_edges(post_dominator):
                    if wrapped_reverse_cfg.is_dominating(no_return_node, edge_from_post_dominator.sink):
                        condition_edges.add(edge_from_post_dominator)
        self._patch_condition_edges(list(condition_edges))

    def _aggressive_removal_postdominators_merged_sinks(self):
        if len(self._cfg) == 1:
            return  # do not remove the only node
        noreturn_nodes = list(self._get_noreturn_nodes())
        leaf_nodes = [x for x in self._cfg.nodes if self._cfg.out_degree(x) == 0]
        returning_leaf_nodes = [node for node in leaf_nodes if node not in noreturn_nodes]
        unused_addresses = _unused_addresses(cfg=self._cfg, amount=2)
        virtual_end_node = BasicBlock(address=unused_addresses[0])
        virtual_merged_noreturn_node = BasicBlock(address=unused_addresses[1])
        # TODO: MultiDiGraph or DiGraph?
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
