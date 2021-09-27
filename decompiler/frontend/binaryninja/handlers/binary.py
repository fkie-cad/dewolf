"""Module implementing the handler for binaryninja's binary operations."""
from functools import partial

from binaryninja import MediumLevelILInstruction, mediumlevelil
from dewolf.frontend.lifter import Handler
from dewolf.structures.pseudo import BinaryOperation, OperationType


class BinaryOperationHandler(Handler):
    """Handler lifting mlil binary operation to pseudo operations."""

    def register(self):
        """Register the handler at the parent lifter."""
        self._lifter.HANDLERS.update(
            {
                mediumlevelil.MediumLevelILAdd: partial(self.lift_binary_operation, OperationType.plus),
                mediumlevelil.MediumLevelILFadd: partial(self.lift_binary_operation, OperationType.plus),
                mediumlevelil.MediumLevelILAdc: partial(self._lift_binary_operation_with_carry, OperationType.plus),
                mediumlevelil.MediumLevelILSub: partial(self.lift_binary_operation, OperationType.minus),
                mediumlevelil.MediumLevelILFsub: partial(self.lift_binary_operation, OperationType.minus),
                mediumlevelil.MediumLevelILSbb: partial(self._lift_binary_operation_with_carry, OperationType.minus),
                mediumlevelil.MediumLevelILAnd: partial(self.lift_binary_operation, OperationType.bitwise_and),
                mediumlevelil.MediumLevelILOr: partial(self.lift_binary_operation, OperationType.bitwise_or),
                mediumlevelil.MediumLevelILXor: partial(self.lift_binary_operation, OperationType.bitwise_xor),
                mediumlevelil.MediumLevelILLsl: partial(self.lift_binary_operation, OperationType.left_shift),
                mediumlevelil.MediumLevelILLsr: partial(self.lift_binary_operation, OperationType.right_shift_us),
                mediumlevelil.MediumLevelILAsr: partial(self.lift_binary_operation, OperationType.right_shift),
                mediumlevelil.MediumLevelILRol: partial(self.lift_binary_operation, OperationType.left_rotate),
                mediumlevelil.MediumLevelILRor: partial(self.lift_binary_operation, OperationType.right_rotate),
                mediumlevelil.MediumLevelILMul: partial(self.lift_binary_operation, OperationType.multiply),
                mediumlevelil.MediumLevelILFmul: partial(self.lift_binary_operation, OperationType.multiply),
                mediumlevelil.MediumLevelILMuls_dp: partial(self.lift_binary_operation, OperationType.multiply),
                mediumlevelil.MediumLevelILMulu_dp: partial(self.lift_binary_operation, OperationType.multiply_us),
                mediumlevelil.MediumLevelILFdiv: partial(self.lift_binary_operation, OperationType.divide_float),
                mediumlevelil.MediumLevelILDivs: partial(self.lift_binary_operation, OperationType.divide),
                mediumlevelil.MediumLevelILDivs_dp: partial(self.lift_binary_operation, OperationType.divide),
                mediumlevelil.MediumLevelILDivu: partial(self.lift_binary_operation, OperationType.divide_us),
                mediumlevelil.MediumLevelILDivu_dp: partial(self.lift_binary_operation, OperationType.divide_us),
                mediumlevelil.MediumLevelILMods: partial(self.lift_binary_operation, OperationType.modulo),
                mediumlevelil.MediumLevelILMods_dp: partial(self.lift_binary_operation, OperationType.modulo),
                mediumlevelil.MediumLevelILModu: partial(self.lift_binary_operation, OperationType.modulo_us),
                mediumlevelil.MediumLevelILModu_dp: partial(self.lift_binary_operation, OperationType.modulo_us),
            }
        )

    def lift_binary_operation(self, op_type: OperationType, operation: MediumLevelILInstruction, **kwargs) -> BinaryOperation:
        """Lift the given binary operation (e.g. a + b, a % b, ..)"""
        return BinaryOperation(
            op_type,
            [self._lifter.lift(x, parent=operation) for x in operation.operands],
            vartype=self._lifter.lift(operation.expr_type, parent=operation),
        )

    def _lift_binary_operation_with_carry(self, op_type: OperationType, operation: MediumLevelILInstruction, **kwargs) -> BinaryOperation:
        """Lift the adc assembler instruction as two nested BinaryOperations."""
        operands = [self._lifter.lift(x, parent=operation) for x in operation.operands]
        return BinaryOperation(
            op_type,
            [operands[0], BinaryOperation(OperationType.plus, [operands[1], operands[2]])],
            vartype=self._lifter.lift(operation.expr_type, parent=operation),
        )
