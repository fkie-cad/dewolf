from typing import Set

from dewolf.structures.graphs.basicblock import BasicBlock
from dewolf.structures.graphs.branches import UnconditionalEdge
from dewolf.structures.graphs.cfg import ControlFlowGraph
from dewolf.structures.pseudo.instructions import GenericBranch


class EmptyBasicBlockRemover:
    """Class that removes all removable empty basic blocks from the CFG."""

    def __init__(self, cfg: ControlFlowGraph):
        """
        Init a new instance.
        cfg: The cfg whose empty basic blocks we want to remove.
        not_deleted_empty_basic_blocks: Set of all empty basic blocks, that are leaves, we found but we could not remove so far.
        """
        self.cfg = cfg
        self.not_deleted_empty_basic_blocks: Set[BasicBlock] = set()

    def remove(self) -> None:
        """This function removes basic blocks that contain no instruction, if possible."""
        for basic_block in list(self.cfg.iter_postorder()):
            self._remove_branch_instructions_and_successors_when_successors_are_empty(basic_block)
            if basic_block.is_empty() and not self.cfg.get_edge(basic_block, basic_block):
                self._try_to_remove_empty_basic_block(basic_block)

        for basic_block in self.not_deleted_empty_basic_blocks:
            if all(pred.condition == BasicBlock.ControlFlowType.direct for pred in self.cfg.get_predecessors(basic_block)):
                if self.cfg.root == basic_block:
                    self.cfg.root = None
                self.cfg.remove_node(basic_block)

    def _remove_branch_instructions_and_successors_when_successors_are_empty(self, basic_block: BasicBlock):
        """
        This function removes the Branch instruction from the given basic block as well as all successors, if all successors are empty
        basic blocks (and therefore contained in the set 'not_deleted_empty_basic_blocks'), since we iterate the blocks in post order.
        """
        successors = set(self.cfg.get_successors(basic_block))
        if basic_block.instructions and successors <= self.not_deleted_empty_basic_blocks:
            self.cfg.remove_edges_from(self.cfg.get_out_edges(basic_block))
            if isinstance(branch_instr := basic_block.instructions[-1], GenericBranch):
                basic_block.instructions.remove(branch_instr)

    def _try_to_remove_empty_basic_block(self, basic_block: BasicBlock) -> None:
        """
        This function tries to delete the given empty basic block from the control flow graph.
        If this is possible we connect all predecessor nodes of the given basic block with all successor nodes of the given basic block.
            - If we have more that one successor, then the basic block can not be empty
            - If we have no successor, we only can remove the basic block when all ingoing edges are unconditional.
            - If we have exactly one successor, then the (basic_block, successor) edge must be direct.
        """
        assert basic_block.is_empty(), f"The given basic block {basic_block} should be empty."
        successors = self.cfg.get_successors(basic_block)
        assert len(successors) <= 1, f"Node {basic_block} is empty, but has more than one successor! This is not possible."

        if len(successors) == 1:
            successor = successors[0]
            assert isinstance(
                self.cfg.get_edge(basic_block, successor), UnconditionalEdge
            ), f"Node {basic_block} has out-degree 1 but is not unconditional"
            self._join_predecessors_to_successor(basic_block, successor)
        else:
            if self._has_non_direct_predecessor(basic_block):
                return self.not_deleted_empty_basic_blocks.add(basic_block)

        if basic_block == self.cfg.root:
            self.cfg.root = successors[0] if successors else None
        self.cfg.remove_node(basic_block)

    def _has_non_direct_predecessor(self, basic_block: BasicBlock) -> bool:
        """Checks whether the given basic block has a predecessor that is not direct. If this is the case we return True."""
        return any(pred.condition != BasicBlock.ControlFlowType.direct for pred in self.cfg.get_predecessors(basic_block))

    def _join_predecessors_to_successor(self, basic_block: BasicBlock, successor: BasicBlock):
        """
        Add an edge between each predecessor and the successor. If an edge (pred, succ), that we want to add to the cfg, is already contained
        in the cfg, then we merge these edges, by combining their information.
        """
        for pred in self.cfg.get_predecessors(basic_block):
            if self.cfg.get_edge(pred, successor):
                self._combine_parallel_edges(basic_block, pred, successor)
            else:
                new_edge = self.cfg.get_edge(pred, basic_block).copy(sink=successor)
                self.cfg.add_edge(new_edge)

    def _combine_parallel_edges(self, basic_block: BasicBlock, pred: BasicBlock, successor: BasicBlock):
        """
        Combine the edge (pred, successor) in the CFG with the new parallel edge that has the properties of edge (pred, basicblock).
        """
        assert pred.condition != BasicBlock.ControlFlowType.direct, f"Node {pred} can not have out-degree 2 and be direct."
        if self.cfg.out_degree(pred) == 2:
            self.cfg.substitute_edge(self.cfg.get_edge(pred, successor), UnconditionalEdge(pred, successor))
            pred.remove_instruction(pred.instructions[-1])
        else:
            assert pred.condition == BasicBlock.ControlFlowType.indirect and self.cfg.is_switch_node(
                pred
            ), f"Node {pred} has out-degree larger than 2 but is not indirect."
            self.cfg.get_edge(pred, successor).cases = self.cfg.get_edge(pred, successor).cases + self.cfg.get_edge(pred, basic_block).cases
