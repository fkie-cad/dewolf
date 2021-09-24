"""Module implementing the UnaryOperationHandler."""
from binaryninja import mediumlevelil, MediumLevelILOperation, MediumLevelILInstruction

from dewolf.frontend.lifter import Handler
from dewolf.structures.pseudo import OperationType, UnaryOperation, Assignment


class UnaryOperationHandler(Handler):

    OPERATIONS = {
        MediumLevelILOperation.MLIL_NEG: OperationType.negate,
        MediumLevelILOperation.MLIL_NOT: OperationType.logical_not,
        MediumLevelILOperation.MLIL_ADDRESS_OF: OperationType.address,
        MediumLevelILOperation.MLIL_LOAD_SSA: OperationType.dereference,
        MediumLevelILOperation.MLIL_ZX: OperationType.cast,
        MediumLevelILOperation.MLIL_SX: OperationType.cast,
    }

    def register(self):
        self._lifter.HANDLERS.update(
            {
                mediumlevelil.MediumLevelILNeg: self.lift_unary_operation,
                mediumlevelil.MediumLevelILFneg: self.lift_unary_operation,
                mediumlevelil.MediumLevelILNot: self.lift_unary_operation,
                mediumlevelil.MediumLevelILSx: self.lift_unary_operation,
                mediumlevelil.MediumLevelILZx: self.lift_unary_operation,
                mediumlevelil.MediumLevelILLow_part: self.lift_unary_operation,
                mediumlevelil.MediumLevelILAddress_of: self.lift_unary_operation,
                mediumlevelil.MediumLevelILLoad: self.lift_unary_operation,
                mediumlevelil.MediumLevelILLoad_ssa: self.lift_unary_operation,
            }
        )

    def lift_unary_operation(self, operation: MediumLevelILInstruction) -> UnaryOperation:
        """Lift the given constant value."""
        return UnaryOperation(
            self.OPERATIONS[operation.operation],
            [self._lifter.lift(x) for x in operation.operands],
            vartype=self._lifter.lift(operation.expr_type),
        )

    def _lift_cast(self, instruction: MediumLevelILInstruction) -> UnaryOperation:
        """Lift a cast operation, casting one type to another."""
        return UnaryOperation(OperationType.cast, [self._lifter.lift(instruction.src)], vartype=self.lift_type(instruction.expr_type))

    def _lift_write_memory(self, instruction: MediumLevelILInstruction, **kwargs) -> Assignment:
        """Lift a write access to a memory location."""
        return Assignment(
            UnaryOperation(
                OperationType.dereference,
                [op := self._lifter.lift(instruction.dest)],
                vartype=op.type,
                writes_memory=instruction.dest_memory,
            ),
            self._lifter.lift(instruction.src),
        )
