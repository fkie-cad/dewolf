"""Module for removing ELF stack canaries."""
from typing import Iterator

from dewolf.pipeline.stage import PipelineStage
from dewolf.structures.graphs.cfg import BasicBlock, UnconditionalEdge
from dewolf.structures.pseudo.instructions import Branch
from dewolf.task import DecompilerTask


class RemoveStackCanary(PipelineStage):
    """
    RemoveStackCanary finds and removes inlined stack canaries for ELF,
    based on _stack_chk_fail().
    Caution: this stage changes code semantic
    """

    name = "remove-stack-canary"
    STACK_FAIL_STR = "__stack_chk_fail"

    def run(self, task: DecompilerTask):
        if task.options.getboolean(f"{self.name}.remove_canary", fallback=False):
            self._cfg = task.graph
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
        for instr in [str(i) for i in node.instructions]:
            if self.STACK_FAIL_STR in instr:
                return True
        return False

    def _patch_canary(self, node: BasicBlock):
        """
        Patch Branches to stack fail node.
        """
        for pred in self._cfg.get_predecessors(node):
            self._patch_branch_condition(pred)
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
