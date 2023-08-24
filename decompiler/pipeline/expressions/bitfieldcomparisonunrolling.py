from datetime import datetime
from logging import debug, warning
from typing import Any, List, Optional, Tuple

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo import Constant, Expression
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.instructions import Branch
from decompiler.structures.pseudo.operations import BinaryOperation, Condition, OperationType, UnaryOperation
from decompiler.task import DecompilerTask


class BitFieldComparisonUnrolling(PipelineStage):
    """
    Transform bit-field compiler optimization to readable comparison:

    var = 1 << amount;
    if ((var & 0b11010) != 0) { ... }

    // becomes:

    if ( amount == 1 || amount == 3 || amount == 4 ) { ... }

    This can subsequently be used to reconstruct switch-case statements.

    This stage requires expression-propagation PipelineStage, such that bit-shift
    gets forwarded into Branch.condition:

    if ( (1 << amount) & bit_mask) == 0) ) { ... }
    """

    name = "bit-field-comparison-unrolling"
    dependencies = ["expression-propagation"]

    def run(self, task: DecompilerTask):
        """Run the pipeline stage: Check all viable Branch-instructions."""
        worklist = []
        for block in task.graph:
            if (matched_instruction := self._unfold_cases(block)) is not None:
                switch_var, cases, is_negated = matched_instruction
                worklist.append((block, switch_var, cases, is_negated))
        for todo in worklist:
            self._modify_cfg(task.graph, *todo)

    def _modify_cfg(self, cfg: ControlFlowGraph, block: BasicBlock, switch_var: Variable, cases: List[int], is_negated_condition: bool):
        """
        Create a nested if blocks for each case in unfolded values.
        Note: with the Branch condition encountered so far (== 0x0), the node of the collected cases is adjacent to the FalseCase edge.
        However, negated conditions may exist. In this case, pass condition type (flag) and swap successor nodes accordingly.
        """
        debug("modifying cfg")
        true_edge, false_edge = self._tf_edges_from_block(cfg, block)
        other_node, case_node = true_edge.sink, false_edge.sink
        if is_negated_condition:
            other_node, case_node = case_node, other_node
        block.remove_instruction(block[-1])
        cfg.remove_edge(true_edge)
        cfg.remove_edge(false_edge)
        nested_if_blocks = [self._create_condition_block(cfg, switch_var, case_value) for case_value in cases]
        for pred, succ in zip(nested_if_blocks, nested_if_blocks[1:]):
            cfg.add_edge(TrueCase(pred, case_node))
            cfg.add_edge(FalseCase(pred, succ))
        # add edges for last and first block
        cfg.add_edge(TrueCase(nested_if_blocks[-1], case_node))
        cfg.add_edge(FalseCase(nested_if_blocks[-1], other_node))
        cfg.add_edge(UnconditionalEdge(block, nested_if_blocks[0]))

    def _create_condition_block(self, cfg: ControlFlowGraph, switch_var: Any, case_value: int) -> BasicBlock:
        """
        Create conditional block in CFG, e.g., `if (var == 0x42)`.
        """
        return cfg.create_block([Branch(condition=Condition(OperationType.equal, [switch_var, Constant(case_value)]))])

    def _tf_edges_from_block(self, cfg: ControlFlowGraph, block: BasicBlock) -> Tuple[TrueCase, FalseCase]:
        """
        Return TrueCase, FalseCase edges from conditional block (in that order).
        """
        match cfg.get_out_edges(block):
            case (TrueCase() as true_edge, FalseCase() as false_edge):
                pass
            case (FalseCase() as false_edge, TrueCase() as true_edge):
                pass
            case _:
                raise ValueError("Block does not have outgoing T/F edges.")
        return true_edge, false_edge

    def _unfold_cases(self, block: BasicBlock) -> Optional[Tuple[Any, List[int], bool]]:
        """
        Unfold Branch condition (checking bit field) into switch variable and list of case values.
        """
        if not len(block):
            return None
        if not isinstance(branch_instruction := block[-1], Branch):
            return None
        match branch_instruction.condition:
            case Condition(OperationType.equal, subexpr, Constant(value=0x0)):
                is_negated = False
            case Condition(OperationType.not_equal, subexpr, Constant(value=0x0)):
                is_negated = True
            case _:
                return None
        if (matched_expression := self._get_switch_var_and_bitfield(subexpr)) is not None:
            switch_var, bit_field = matched_expression
            cleaned_var = self._clean_variable(switch_var)
            case_values = self._get_values(bit_field)
            if cleaned_var and case_values:
                return cleaned_var, case_values, is_negated
        return None

    def _get_switch_var_and_bitfield(self, subexpr: Expression) -> Optional[Tuple[Any, Constant]]:
        """
        Match expression of folded switch case:
            a) ((1 << (cast)var) & 0xffffffff) & bit_field_constant
            b) (0x1 << ((1: ) ecx#1)) & 0xa50
        """
        match subexpr:
            case BinaryOperation(
                OperationType.bitwise_and,
                BinaryOperation(
                    OperationType.bitwise_and, BinaryOperation(OperationType.left_shift, Constant(value=1), switch_var), Constant()
                ),
                Constant() as bit_field,
            ) if bit_field.value != 0xFFFFFFFF:
                return switch_var, bit_field
            case BinaryOperation(
                OperationType.bitwise_and,
                BinaryOperation(OperationType.left_shift, Constant(value=1), switch_var),
                Constant() as bit_field,
            ) if bit_field.value != 0xFFFFFFFF:
                return switch_var, bit_field
            case _:
                debug(f"no match for {subexpr}")
                return None

    def _get_values(self, const: Constant) -> List[int]:
        """Return positions of set bits from integer Constant"""
        bitmask = const.value
        values = []
        if not isinstance(bitmask, int):
            warning("not an integer")
            return []
        for pos, bit in enumerate(bin(bitmask)[:1:-1]):
            if bit == "1":
                values.append(pos)
        return values

    def _clean_variable(self, expr: Expression) -> Optional[Variable]:
        """
        Remove cast from Variable.
        """
        if isinstance(expr, Variable):
            return expr
        if isinstance(expr, UnaryOperation) and expr.operation == OperationType.cast:
            if len(expr.requirements) == 1:
                return expr.requirements[0]
