from logging import warning
from typing import Any, List, Optional, Tuple

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo import Constant, Expression
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.instructions import Branch, Instruction
from decompiler.structures.pseudo.operations import BinaryOperation, Condition, OperationType, UnaryOperation
from decompiler.task import DecompilerTask
from decompiler.util.decoration import DecoratedCFG
from datetime import datetime


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
                switch_var, cases = matched_instruction
                worklist.append((block, switch_var, cases))
        for todo in worklist: 
            self._modify_cfg(task.graph, *todo)

    def _modify_cfg(self, cfg: ControlFlowGraph, block: BasicBlock, switch_var: Variable, cases: List[int]):
        """
        TODO: what about negated condition?
        """
        match cfg.get_out_edges(block):
            case (TrueCase() as true_edge, FalseCase() as false_edge):
                pass
            case (FalseCase() as false_edge, TrueCase() as true_edge):
                pass
            case _:
                raise ValueError("Branch does not have corresponding T/F edges.")
        # true_node, false_node = true_edge.sink, false_edge.sink
        false_node, true_node  = true_edge.sink, false_edge.sink # mind****
        block.remove_instruction(block[-1])
        cfg.remove_edge(true_edge)
        cfg.remove_edge(false_edge)
        nested_if_blocks = []
        for case_value in cases:
            new_block = cfg.create_block([Branch(condition=Condition(OperationType.equal, [switch_var, Constant(case_value)]))])
            nested_if_blocks.append(new_block)
        for pred, succ in zip(nested_if_blocks, nested_if_blocks[1:]):
            cfg.add_edge(TrueCase(pred, true_node))
            cfg.add_edge(FalseCase(pred, succ))
        cfg.add_edge(TrueCase(succ, true_node))
        cfg.add_edge(FalseCase(succ, false_node))
        cfg.add_edge(UnconditionalEdge(block, nested_if_blocks[0]))
        DecoratedCFG.from_cfg(cfg).export_plot(f"modified{datetime.now()}.png")

    def _unfold_cases(self, block: BasicBlock) -> Optional[Tuple[Any, List[int]]]:
        if not len(block):
            return None
        if (subexpr := self._get_subexpression_for_unrolling(block[-1])) is not None:
            if (matched_expression := self._get_switch_var_and_bitfield(subexpr)) is not None:
                switch_var, bit_field = matched_expression
                cleaned_var = self._clean_variable(switch_var)
                case_values = self._get_values(bit_field)
                if cleaned_var and case_values:
                    return cleaned_var, case_values
        return None

    def _clean_variable(self, expr: Expression) -> Optional[Variable]:
        if isinstance(expr, Variable):
            return expr
        if isinstance(expr, UnaryOperation) and expr.operation == OperationType.cast:
            if len(expr.requirements) == 1:
                return expr.requirements[0]

    def _get_subexpression_for_unrolling(self, instr: Instruction):
        match instr:
            case Branch(condition=Condition(OperationType.equal, subexpr, Constant(value=0x0))):
                return subexpr
            case _:
                return None

    def _get_switch_var_and_bitfield(self, subexpr: Expression) -> Optional[Tuple[Any, Constant]]:
        """
        Match expression of folded switch case:
            ((1 << (cast)var) & 0xffffffff)) & bit_field_constant)
        """
        match subexpr:
            case BinaryOperation(
                OperationType.bitwise_and,
                BinaryOperation(
                    OperationType.bitwise_and, BinaryOperation(OperationType.left_shift, Constant(value=1), switch_var), Constant()
                ),
                Constant() as bit_field,
            ):
                assert bit_field.value not in {0xFFFFFFFF, 0xFFFF}, "TODO"
                return switch_var, bit_field
            case _:
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
