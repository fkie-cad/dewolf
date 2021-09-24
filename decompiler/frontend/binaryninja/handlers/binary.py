from binaryninja import mediumlevelil, MediumLevelILOperation, MediumLevelILInstruction

from dewolf.frontend.lifter import Handler
from dewolf.structures.pseudo import OperationType, BinaryOperation


class BinaryOperationHandler(Handler):

    OPERATIONS = {
        MediumLevelILOperation.MLIL_ADD: OperationType.plus,
        MediumLevelILOperation.MLIL_ADC: OperationType.plus,
        MediumLevelILOperation.MLIL_SUB: OperationType.minus,
        MediumLevelILOperation.MLIL_SBB: OperationType.plus,
        MediumLevelILOperation.MLIL_MUL: OperationType.multiply,
        MediumLevelILOperation.MLIL_MULU_DP: OperationType.multiply_us,
        MediumLevelILOperation.MLIL_MULS_DP: OperationType.multiply,
        MediumLevelILOperation.MLIL_AND: OperationType.bitwise_and,
        MediumLevelILOperation.MLIL_OR: OperationType.bitwise_or,
        MediumLevelILOperation.MLIL_XOR: OperationType.bitwise_xor,
        MediumLevelILOperation.MLIL_LSL: OperationType.left_shift,
        MediumLevelILOperation.MLIL_ASR: OperationType.right_shift,
        MediumLevelILOperation.MLIL_LSR: OperationType.right_shift_us,
        MediumLevelILOperation.MLIL_DIVU: OperationType.divide_us,
        MediumLevelILOperation.MLIL_DIVU_DP: OperationType.divide_us,
        MediumLevelILOperation.MLIL_DIVS: OperationType.divide,
        MediumLevelILOperation.MLIL_DIVS_DP: OperationType.divide,
        MediumLevelILOperation.MLIL_MODU: OperationType.modulo_us,
        MediumLevelILOperation.MLIL_MODU_DP: OperationType.modulo_us,
        MediumLevelILOperation.MLIL_MODS: OperationType.modulo,
        MediumLevelILOperation.MLIL_MODS_DP: OperationType.modulo,
        MediumLevelILOperation.MLIL_ROL: OperationType.left_rotate,
        MediumLevelILOperation.MLIL_ROR: OperationType.right_rotate,
    }

    def register(self):
        self._lifter.HANDLERS.update(
            {
                mediumlevelil.MediumLevelILAdd: self.lift_binary_operation,
                mediumlevelil.MediumLevelILFadd: self.lift_binary_operation,
                mediumlevelil.MediumLevelILAdc: self._lift_binary_operation_with_carry,
                mediumlevelil.MediumLevelILSub: self.lift_binary_operation,
                mediumlevelil.MediumLevelILFsub: self.lift_binary_operation,
                mediumlevelil.MediumLevelILSbb: self._lift_binary_operation_with_carry,
                mediumlevelil.MediumLevelILAnd: self.lift_binary_operation,
                mediumlevelil.MediumLevelILOr: self.lift_binary_operation,
                mediumlevelil.MediumLevelILXor: self.lift_binary_operation,
                mediumlevelil.MediumLevelILLsl: self.lift_binary_operation,
                mediumlevelil.MediumLevelILLsr: self.lift_binary_operation,
                mediumlevelil.MediumLevelILAsr: self.lift_binary_operation,
                mediumlevelil.MediumLevelILRol: self.lift_binary_operation,
                mediumlevelil.MediumLevelILRor: self.lift_binary_operation,
                mediumlevelil.MediumLevelILMul: self.lift_binary_operation,
                mediumlevelil.MediumLevelILFmul: self.lift_binary_operation,
                mediumlevelil.MediumLevelILMuls_dp: self.lift_binary_operation,
                mediumlevelil.MediumLevelILMulu_dp: self.lift_binary_operation,
                mediumlevelil.MediumLevelILFdiv: self.lift_binary_operation,
                mediumlevelil.MediumLevelILDivs: self.lift_binary_operation,
                mediumlevelil.MediumLevelILDivs_dp: self.lift_binary_operation,
                mediumlevelil.MediumLevelILDivu: self.lift_binary_operation,
                mediumlevelil.MediumLevelILDivu_dp: self.lift_binary_operation,
                mediumlevelil.MediumLevelILMods: self.lift_binary_operation,
                mediumlevelil.MediumLevelILMods_dp: self.lift_binary_operation,
                mediumlevelil.MediumLevelILModu: self.lift_binary_operation,
                mediumlevelil.MediumLevelILModu_dp: self.lift_binary_operation,
            }
        )

    def lift_binary_operation(self, operation: MediumLevelILInstruction, **kwargs) -> BinaryOperation:
        """Lift the given constant value."""
        return BinaryOperation(
            self.OPERATIONS[operation.operation],
            [self._lifter.lift(x, parent=operation) for x in operation.operands],
            vartype=self._lifter.lift(operation.expr_type, parent=operation),
        )

    def _lift_binary_operation_with_carry(self, operation: MediumLevelILInstruction, **kwargs) -> BinaryOperation:
        """Lift the adc assembler instruction as two nested BinaryOperations."""
        operands = [self._lifter.lift(x, parent=operation) for x in operation.operands]
        return BinaryOperation(
            self.OPERATIONS[operation.operation],
            [operands[0], BinaryOperation(OperationType.plus, [operands[1], operands[2]])],
            vartype=self._lifter.lift(operation.expr_type, parent=operation),
        )
