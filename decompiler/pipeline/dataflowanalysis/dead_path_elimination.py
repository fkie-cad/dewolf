"""Module implementing the DeadPathElimination pipeline stage."""

from logging import info, warning
from typing import Iterator, Optional, Set, Union

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import BasicBlock, BasicBlockEdge, ControlFlowGraph, FalseCase, UnconditionalEdge
from decompiler.structures.pseudo.delogic_logic import DelogicConverter
from decompiler.structures.pseudo.instructions import Branch, GenericBranch, IndirectBranch, Phi
from decompiler.structures.pseudo.logic import BaseConverter
from decompiler.structures.pseudo.z3_logic import Z3Converter
from decompiler.task import DecompilerTask
from simplifier.world.nodes import WorldObject
from z3 import BoolRef


class DeadPathElimination(PipelineStage):
    """Removes dead paths from a control flow graph."""

    name = "dead-path-elimination"

    def __init__(self):
        """Initialize a new path elimination."""
        self._logic_converter: BaseConverter = Z3Converter()
        self._timeout: Optional[int] = None

    def run(self, task: DecompilerTask) -> None:
        """Run dead path elimination on the given task object."""
        self._timeout = task.options.getint(f"{self.name}.timeout_satisfiable")
        engine = task.options.getstring("logic-engine.engine")  # choice of z3 or delogic
        if engine == "delogic":
            self._logic_converter = DelogicConverter()
        if task.graph.root is None:
            warning(f"[{self.__class__.__name__}] Can not detect dead blocks because the cfg has no head.")
            return
        if not (dead_edges := set(self.find_unsatisfyable_edges(task.graph))):
            return
        self._remove_dead_edges(task.graph, dead_edges)

    def _fix_phi_origin_blocks_on_remove(self, dead_blocks: Set[BasicBlock], graph: ControlFlowGraph) -> None:
        """Remove dead blocks from Phi.origin_block"""
        for instruction in graph.instructions:
            if not isinstance(instruction, Phi):
                continue
            removed_phi_predecessors = [block for block in instruction.origin_block.keys() if block in dead_blocks]
            for block in removed_phi_predecessors:
                instruction.remove_from_origin_block(block)

    def _remove_dead_edges(self, cfg: ControlFlowGraph, dead_edges: Set[BasicBlockEdge]):
        """Remove the given set of edges from the graph, fixing edge conditions and removing unreachable blocks."""
        original_head: BasicBlock = cfg.root
        for dead_edge in dead_edges:
            self._remove_and_fix_edge(cfg, dead_edge)
        dead_blocks: Set[BasicBlock] = self._find_unreachable_blocks(cfg, original_head)
        self._fix_phi_origin_blocks_on_remove(dead_blocks, cfg)
        cfg.remove_nodes_from(dead_blocks)
        info(f"[{self.__class__.__name__}] Eliminated {len(dead_blocks)} basic blocks from {len(dead_edges)} dead edges.")

    def find_unsatisfyable_edges(self, graph: ControlFlowGraph) -> Iterator[BasicBlockEdge]:
        """Iterate all dead branches in the given control flow graph."""
        for branch_block in [node for node in graph if graph.out_degree(node) > 1]:
            branch_instruction = branch_block.instructions[-1]
            assert isinstance(branch_instruction, GenericBranch), f"Branching basic block without branch instruction at {branch_block.name}"
            if isinstance(branch_instruction, IndirectBranch):
                continue
            if dead_edge := self._get_invalid_branch_edge(graph, branch_block, branch_instruction):
                yield dead_edge

    def _get_invalid_branch_edge(self, graph: ControlFlowGraph, block: BasicBlock, instruction: Branch) -> Optional[BasicBlockEdge]:
        """Check the edges of the given branch for unsatisfyable branch conditions, returning a dead edge if any."""
        try:
            condition = self._logic_converter.convert(instruction, define_expr=True)
        except ValueError as value_error:
            warning(f"[{self.__class__.__name__}] {str(value_error)}")
            return
        for edge in graph.get_out_edges(block):
            if self._is_invalid_edge(edge, condition):
                return edge

    def _is_invalid_edge(self, edge: BasicBlockEdge, condition: Union[BoolRef, WorldObject]) -> bool:
        """
        Check whether the condition of the given branch is satisfyable or not.

        Returns a tuple of bools indicating the viability of the true and false branches.
        """
        if isinstance(edge, FalseCase):
            condition = self._logic_converter.negate(condition)
        return self._logic_converter.is_not_satisfiable(condition, timeout=self._timeout)

    @staticmethod
    def _find_unreachable_blocks(graph: ControlFlowGraph, head: BasicBlock) -> Set[BasicBlock]:
        """Return all blocks not reachable from the function start."""
        reachable_blocks: Set[BasicBlock] = set(graph.iter_postorder(head))
        return set(graph) - reachable_blocks

    @staticmethod
    def _remove_and_fix_edge(graph: ControlFlowGraph, dead_edge: BasicBlockEdge) -> None:
        """Fix a dead edge by removing the branch instruction and the edge while changing the edge type of the remaining edge."""
        graph.remove_edge(dead_edge)
        dead_edge.source.instructions = dead_edge.source.instructions[:-1]
        for edge in graph.get_out_edges(dead_edge.source):
            graph.substitute_edge(edge, UnconditionalEdge(edge.source, edge.sink))
