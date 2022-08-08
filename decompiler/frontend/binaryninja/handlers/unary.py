"""Module implementing the UnaryOperationHandler."""
from functools import partial

from binaryninja import MediumLevelILInstruction, MediumLevelILOperation, mediumlevelil
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import (
    BinaryOperation,
    Constant,
    GlobalVariable,
    Integer,
    Operation,
    OperationType,
    Pointer,
    UnaryOperation,
)


class UnaryOperationHandler(Handler):
    def register(self):
        """Register the handling functions at the parent observer."""
        self._lifter.HANDLERS.update(
            {
                mediumlevelil.MediumLevelILNeg: partial(self.lift_unary_operation, OperationType.negate),
                mediumlevelil.MediumLevelILFneg: partial(self.lift_unary_operation, OperationType.negate),
                mediumlevelil.MediumLevelILNot: partial(self.lift_unary_operation, OperationType.bitwise_not),
                mediumlevelil.MediumLevelILSx: self.lift_cast,
                mediumlevelil.MediumLevelILZx: self._lift_zx_operation,
                mediumlevelil.MediumLevelILLowPart: self.lift_cast,
                mediumlevelil.MediumLevelILFloatConv: self.lift_cast,
                mediumlevelil.MediumLevelILFloatToInt: self.lift_cast,
                mediumlevelil.MediumLevelILIntToFloat: self.lift_cast,
                mediumlevelil.MediumLevelILAddressOf: partial(self.lift_unary_operation, OperationType.address),
                mediumlevelil.MediumLevelILAddressOfField: self.lift_address_of_field,
                mediumlevelil.MediumLevelILLoad: partial(self.lift_unary_operation, OperationType.dereference),
                mediumlevelil.MediumLevelILLoadSsa: partial(self.lift_unary_operation, OperationType.dereference),
                mediumlevelil.MediumLevelILLoadStruct: self._lift_load_struct,
                mediumlevelil.MediumLevelILLoadStructSsa: self._lift_load_struct,
                mediumlevelil.MediumLevelILFtrunc: self._lift_ftrunc,
            }
        )

    def lift_unary_operation(self, op_type: OperationType, operation: MediumLevelILOperation, **kwargs) -> UnaryOperation:
        """Lift the given constant value."""
        operands = [self._lifter.lift(x, parent=operation) for x in operation.operands]
        if op_type == OperationType.dereference and isinstance(global_var := operands[0], GlobalVariable):
            return global_var
        return UnaryOperation(
            op_type,
            [self._lifter.lift(x, parent=operation) for x in operation.operands],
            vartype=self._lifter.lift(operation.expr_type, parent=operation),
        )

    def lift_cast(self, cast: mediumlevelil.MediumLevelILUnaryBase, **kwargs) -> UnaryOperation:
        """Lift a cast operation, casting one type to another."""
        return UnaryOperation(OperationType.cast, [self._lifter.lift(cast.src, parent=cast)], vartype=self._lifter.lift(cast.expr_type))

    def lift_address_of_field(self, operation: mediumlevelil.MediumLevelILAddressOfField, **kwargs) -> Operation:
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

    def _lift_zx_operation(self, instruction: MediumLevelILInstruction, **kwargs) -> UnaryOperation:
        """Lift zero-extension operation."""
        inner = self._lifter.lift(instruction.operands[0], parent=instruction)
        if isinstance(inner.type, Integer) and inner.type.is_signed:
            unsigned_type = Integer(size=inner.type.size, signed=False)
            return UnaryOperation(
                OperationType.cast,
                [UnaryOperation(OperationType.cast, [inner], unsigned_type)],
                vartype=self._lifter.lift(instruction.expr_type),
            )
        return self.lift_cast(instruction, **kwargs)

    def _lift_load_struct(self, instruction: mediumlevelil.MediumLevelILLoadStruct, **kwargs) -> UnaryOperation:
        """Lift a MLIL_LOAD_STRUCT_SSA instruction."""
        return UnaryOperation(
            OperationType.dereference,
            [
                BinaryOperation(
                    OperationType.plus,
                    [
                        UnaryOperation(OperationType.cast, [self._lifter.lift(instruction.src)], vartype=Pointer(Integer.char())),
                        Constant(instruction.offset),
                    ],
                    vartype=self._lifter.lift(instruction.src.expr_type),
                ),
            ],
            vartype=Pointer(self._lifter.lift(instruction.src.expr_type)),
        )

    def _lift_ftrunc(self, instruction: mediumlevelil.MediumLevelILFtrunc, **kwargs) -> UnaryOperation:
        """Lift a MLIL_FTRUNC operation."""
        return UnaryOperation(
            OperationType.cast,
            [self._lifter.lift(operand) for operand in instruction.operands],
            vartype=self._lifter.lift(instruction.expr_type),
        )
