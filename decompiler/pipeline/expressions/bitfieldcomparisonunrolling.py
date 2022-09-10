from typing import Dict, List

from logging import debug, warning

from simplifier.operations.bitwise import UnaryOperation
from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.graphs.expressiongraph import ExpressionGraph
from decompiler.structures.pseudo import Constant, Expression, Instruction, Operation, Phi, Variable
from decompiler.structures.pseudo.instructions import Branch
from decompiler.structures.pseudo.operations import BinaryOperation, Condition, OperationType, Operation
from decompiler.task import DecompilerTask
from decompiler.util.decoration import DecoratedCFG


class BitFieldComparisonUnrolling(PipelineStage):
    """"""

    name = "bit-field-comparison-unrolling"

    def run(self, task: DecompilerTask):
        """Run the pipeline stage"""
        debug("RUN MY PIPELINE STAGE")
        debug("INSTRUCTIONS:")
        for instr in task.graph.instructions:
            if isinstance(instr, Branch):
                debug(instr)
                replacement = self._check_condition(instr.condition)
                if replacement:
                    instr.substitute(instr.condition, replacement)
        DecoratedCFG.show_flowgraph(task.graph, "CFG after unrolling")

    def _check_condition(self, cond: Condition):
        if cond.is_equality_with_constant_check():
            if isinstance(cond.right, Constant) and cond.right.value == 0x0:
                debug("Right is 0") # POC only RHS case. Resolve with self._left_or_right (TODO)
                return self._get_unrolled_condition(cond.left)

    def _get_unrolled_condition(self, expr: Expression):
        if isinstance(expr, BinaryOperation):
            if expr.operation == OperationType.bitwise_and:
                values = self._bitmask_values(expr.right)
                var = self._get_bitshift_var(expr.left)
                print("RECONSTRUCT", var, "==", values)
                comparisons = [Condition(OperationType.equal, [var, Constant(val)]) for val in values]
                # TODO why cant I do this:
                # unrolled = Condition(OperationType.logical_or, comparisons)
                # this looks stupid:
                unrolled = Condition(OperationType.logical_or, [comparisons[0], comparisons[1]])
                for comp in comparisons[2:]:
                    unrolled = Condition(OperationType.logical_or, [unrolled, comp])
                return unrolled

    def _bitmask_values(self, const: Constant) -> List[int]:
        bitmask = const.value
        values = []
        if not isinstance(bitmask, int):
            warning("not a bitmask")
            return []
        for pos, bit in enumerate(bin(bitmask)[:1:-1]):
            if bit == "1":
                values.append(pos)
                print(pos)
        return values

    def _get_bitshift_var(self, expr: Expression):
        """ ignore bitmask 0xffffffff """
        print("EXTRACT BITSHIFT FROM:", expr, type(expr))
        for op in expr.operands:
            if isinstance(op, BinaryOperation) and OperationType.left_shift == op.operation:
                if isinstance(op.left, Constant) and op.left.value == 0x1:
                    return op.right

    def _left_or_right(self, bin_op: BinaryOperation, target_type_rhs):
        pass




