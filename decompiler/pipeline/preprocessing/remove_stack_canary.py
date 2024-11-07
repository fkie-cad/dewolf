"""Module for removing ELF stack canaries."""

from typing import Iterator

from decompiler.pipeline.preprocessing.util import match_expression
from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.branches import BasicBlockEdgeCondition
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, UnconditionalEdge
from decompiler.structures.pseudo.instructions import Assignment, Branch
from decompiler.structures.pseudo.operations import Call, OperationType
from decompiler.task import DecompilerTask


class RemoveStackCanary(PipelineStage):
    """
    RemoveStackCanary finds and removes inlined stack canaries for ELF,
    based on _stack_chk_fail().
    Caution: this stage changes code semantic
    """

    name = "remove-stack-canary"
    STACK_FAIL_STR = "__stack_chk_fail"

    def run(self, task: DecompilerTask):
        if task.options.getboolean(f"{self.name}.remove_canary", fallback=False) and task.name != self.STACK_FAIL_STR:
            self._cfg = task.graph
            if len(self._cfg) == 1:
                return  # do not remove the only node
            for fail_node in list(self._contains_stack_check_fail()):
                self._patch_canary(fail_node)

    def _contains_stack_check_fail(self) -> Iterator[BasicBlock]:
        """
        Iterate leaf nodes of cfg, yield nodes containing canary check.
        """
        leaf_nodes = [x for x in self._cfg.nodes if self._cfg.out_degree(x) == 0]
        for node in leaf_nodes:
            if self._is_stack_chk_fail(node):
                yield node

    def _is_stack_chk_fail(self, node: BasicBlock) -> bool:
        """
        Check if node contains call to __stack_chk_fail
        """
        return any(self.STACK_FAIL_STR in str(inst) for inst in node.instructions) or self._reached_by_failed_canary_check(node)

    def _reached_by_failed_canary_check(self, node: BasicBlock) -> bool:
        """
        Determine if the given `node` is reached by a failed stack canary check.

        This function checks if any incoming edges to the `node` are conditional branches
        that failed a stack canary check. It examines the predecessor nodes to see if the
        branching condition corresponds to a failed comparison involving the canary value.

        Args:
            node (BasicBlock): The basic block to check if it is reached by a failed canary check.

        Returns:
            bool: Returns `True` if the node is reached by a failed canary check; otherwise, `False`.

        The function specifically looks for conditions that match the pattern *(fsbase+0x28),
        indicating a check involving a stack canary. It then verifies if the condition's operation
        and the type of the edge align with typical patterns of failed canary checks:
        - `equal` operation with `false` edge condition, or
        - `not_equal` operation with `true` edge condition.
        """
        pattern = ("fsbase", 0x28)
        for in_edge in self._cfg.get_in_edges(node):
            predecessor = in_edge.source
            if len(predecessor.instructions) and isinstance(predecessor.instructions[-1], Branch):
                condition = predecessor.instructions[-1].condition
                if not (condition.operation, in_edge.condition_type) in {
                    (OperationType.equal, BasicBlockEdgeCondition.false),
                    (OperationType.not_equal, BasicBlockEdgeCondition.true),
                }:
                    continue
                if match_expression(predecessor, condition.left, pattern) or match_expression(predecessor, condition.right, pattern):
                    return True
        return False

    def _patch_canary(self, node: BasicBlock):
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
        else:
            raise RuntimeError("did not expect to reach canary check this way")
