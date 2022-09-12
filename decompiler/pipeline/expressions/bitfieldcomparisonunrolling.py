from logging import warning
from typing import Any, List, Optional, Tuple

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.pseudo import Constant, Expression
from decompiler.structures.pseudo.instructions import Branch
from decompiler.structures.pseudo.operations import BinaryOperation, Condition, OperationType
from decompiler.task import DecompilerTask
from decompiler.util.decoration import DecoratedCFG


class BitFieldComparisonUnrolling(PipelineStage):
    """
    Transform bit-field compiler optimization to readable comparison:

    var = 1 << amount;
    if ((var & 0b11010) != 0) { ... }

    // becomes:

    if ( amount == 1 || amount == 3 || amount == 4 ) { ... }

    This can subsequently be used to reconstruct switch-case statements.
    Requires expression-propagation PipelineStage, such that bit-shift
    gets forwarded into Branch.condition:

    if ( (1 << amount) & bit_mask) == 0) ) { ... }
    """

    name = "bit-field-comparison-unrolling"
    dependencies = ["expression-propagation"]

    def run(self, task: DecompilerTask):
        """Run the pipeline stage: Check all viable Branch-instructions."""
        for instr in task.graph.instructions:
            if isinstance(instr, Branch):
                replacement = self._unroll_condition(instr.condition)
                if replacement:
                    instr.substitute(instr.condition, replacement)
        DecoratedCFG.show_flowgraph(task.graph, "CFG after unrolling")  # TODO for debugging

    def _unroll_condition(self, cond: Condition) -> Optional[Condition]:
        """Handle the following case of Condition: ((var & bit_field) == 0)"""
        if cond.is_equality_with_constant_check():
            if (operands := self._left_or_right(cond, Constant)) is not None:
                expr, const = operands
                if const.value == 0x0:
                    return self._get_unrolled_condition(expr)
        return None

    def _get_unrolled_condition(self, expr: Expression) -> Optional[Condition]:
        """
        Unroll bit-field to ORed integer comparisions.
        Assume Expression is of the form ((1 << (cast)var) & 0xffffffff)) & bit_field_constant)
        """
        if isinstance(expr, BinaryOperation) and expr.operation == OperationType.bitwise_and:
            operands = self._left_or_right(expr, Constant)
            if operands is None:
                return None
            sub_expression, bit_field_constant = operands
            values = self._bitmask_values(bit_field_constant)
            var = self._get_bitshift_variable(sub_expression)
            if not values or not var:
                return None
            comparisons = [Condition(OperationType.equal, [var, Constant(val)]) for val in values]
            # TODO why cant I do this:
            # unrolled = Condition(OperationType.logical_or, comparisons)
            # this looks stupid:
            unrolled = Condition(OperationType.logical_or, [comparisons[0], comparisons[1]])
            for comp in comparisons[2:]:
                unrolled = Condition(OperationType.logical_or, [unrolled, comp])
            return unrolled
        return None

    def _bitmask_values(self, const: Constant) -> List[int]:
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

    def _get_bitshift_variable(self, expr: Expression) -> Optional[Expression]:
        """
        From Expression ( (1 << (cast)var) & 0xffffffff) ) extract var.
        Note: var might not be of type Variable, but rather UnaryOperation with cast.
        """
        if not isinstance(expr, BinaryOperation):
            return None
        # find and ignore ... & 0xffffffff
        if expr.operation == OperationType.bitwise_and and (operands := self._left_or_right(expr, Constant)) is not None:
            sub_expression, bit_mask_constant = operands
            if isinstance(sub_expression, BinaryOperation) and bit_mask_constant.value == 0xFFFFFFFF:
                # find bit-shift of 0x1
                if sub_expression.operation == OperationType.left_shift:
                    if isinstance(sub_expression.left, Constant) and sub_expression.left.value == 0x1:
                        return sub_expression.right
        return None

    def _left_or_right(self, bin_op: BinaryOperation, target_type_rhs: Any) -> Optional[Tuple]:
        """
        For BinaryOperation `a op b` return operands in canonical order: Expected type on right hand side.
        """
        if isinstance(bin_op.right, target_type_rhs):
            return bin_op.left, bin_op.right
        if isinstance(bin_op.left, target_type_rhs):
            return bin_op.right, bin_op.left
        return None
