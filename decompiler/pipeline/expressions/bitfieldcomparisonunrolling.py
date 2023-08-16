from logging import warning
from typing import Any, List, Optional, Tuple

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.pseudo import Constant, Expression
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.instructions import Branch, Instruction
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

    This stage requires expression-propagation PipelineStage, such that bit-shift
    gets forwarded into Branch.condition:

    if ( (1 << amount) & bit_mask) == 0) ) { ... }
    """

    name = "bit-field-comparison-unrolling"
    dependencies = ["expression-propagation"]

    def run(self, task: DecompilerTask):
        """Run the pipeline stage: Check all viable Branch-instructions."""
        for instr in task.graph.instructions:
            if (replacement := self._handle_bit_field_instruction(instr)) is not None:
                task.graph.substitute_expression(instr, replacement)

    def _handle_bit_field_instruction(self, instr: Instruction) -> Optional[Instruction]:
        if (subexpr := self._get_subexpression_for_unrolling(instr)) is not None:
            switch_var, cases = self._unfold_expression(subexpr)
            print("switch_var", switch_var)
            for case in cases:
                print("case", case)
            comparisons = [Condition(OperationType.equal, [switch_var, Constant(value)]) for value in cases]
            # TODO why cant I do this:
            # unrolled = Condition(OperationType.logical_or, comparisons)
            # this looks stupid:
            replacement = Branch(condition=Condition(OperationType.logical_or, [comparisons[0], comparisons[1]]))
            # unrolled = Condition(OperationType.logical_or, [comparisons[0], comparisons[1]])
            # for comp in comparisons[2:]:
            #     unrolled = Condition(OperationType.logical_or, [unrolled, comp])
            # return unrolled
            return replacement
        return None

    def _get_subexpression_for_unrolling(self, instr: Instruction):
        match instr:
            case Branch(condition=Condition(OperationType.equal, subexpr, Constant(value=0x0))):
                return subexpr
            case _:
                return None

    def _unfold_expression(self, subexpr: Expression) -> Tuple[Any, List[int]]:
        switch_var, bit_field = self._get_switch_var_and_bitfield(subexpr)
        if bit_field is not None:
            return switch_var, self._get_values(bit_field)
        return None, []

    def _get_switch_var_and_bitfield(self, subexpr: Expression) -> Tuple[Any, Optional[Constant]]:
        """
        Match expression of folded switch case: 
            ((1 << (cast)var) & 0xffffffff)) & bit_field_constant)
        """
        match subexpr:
            case BinaryOperation(
                OperationType.bitwise_and,
                BinaryOperation(
                    OperationType.bitwise_and, 
                    BinaryOperation(
                        OperationType.left_shift, 
                        Constant(value=1), 
                        switch_var), 
                    Constant()
                ),
                Constant() as bit_field,
            ):
                return switch_var, bit_field
            case _:
                return None, None

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

