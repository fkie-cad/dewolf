"""Module implementing the UnaryOperationHandler."""
from functools import partial

from binaryninja import MediumLevelILInstruction, MediumLevelILOperation, mediumlevelil
from dewolf.frontend.lifter import Handler
from dewolf.structures.pseudo import BinaryOperation, Constant, Operation, OperationType, UnaryOperation


class UnaryOperationHandler(Handler):
    def register(self):
        """Register the handling functions at the parent observer."""
        self._lifter.HANDLERS.update(
            {
                mediumlevelil.MediumLevelILNeg: partial(self.lift_unary_operation, OperationType.negate),
                mediumlevelil.MediumLevelILFneg: partial(self.lift_unary_operation, OperationType.negate),
                mediumlevelil.MediumLevelILNot: partial(self.lift_unary_operation, OperationType.bitwise_not),
                mediumlevelil.MediumLevelILSx: self.lift_cast,
                mediumlevelil.MediumLevelILZx: self.lift_cast,
                mediumlevelil.MediumLevelILLow_part: self.lift_cast,
                mediumlevelil.MediumLevelILFloat_conv: self.lift_cast,
                mediumlevelil.MediumLevelILAddress_of: partial(self.lift_unary_operation, OperationType.address),
                mediumlevelil.MediumLevelILAddress_of_field: self.lift_address_of_field,
                mediumlevelil.MediumLevelILLoad: partial(self.lift_unary_operation, OperationType.dereference),
                mediumlevelil.MediumLevelILLoad_ssa: partial(self.lift_unary_operation, OperationType.dereference),
            }
        )

    def lift_unary_operation(self, op_type: OperationType, operation: MediumLevelILOperation, **kwargs) -> UnaryOperation:
        """Lift the given constant value."""
        return UnaryOperation(
            op_type,
            [self._lifter.lift(x, parent=operation) for x in operation.operands],
            vartype=self._lifter.lift(operation.expr_type, parent=operation),
        )

    def lift_cast(self, cast: MediumLevelILInstruction, **kwargs) -> UnaryOperation:
        """Lift a cast operation, casting one type to another."""
        return UnaryOperation(OperationType.cast, [self._lifter.lift(cast.src, parent=cast)], vartype=self._lifter.lift(cast.expr_type))

    def lift_address_of_field(self, operation: mediumlevelil.MediumLevelILAddress_of_field, **kwargs) -> Operation:
        """Lift the address of field operation e.g. &(eax_#1:1)."""
        if operation.offset == 0:
            return self.lift_unary_operation(OperationType.address, operation)
        return BinaryOperation(
            OperationType.plus,
            [
                UnaryOperation(OperationType.address, [operand := self._lifter.lift(operation.src, parent=operation)]),
                Constant(operation.offset, vartype=operand.type.copy()),
            ],
            vartype=self._lifter.lift(operation.expr_type),
        )
