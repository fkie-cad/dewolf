"""Module implementing the UnaryOperationHandler."""
import logging
from functools import partial
from typing import Union

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
from decompiler.structures.pseudo.complextypes import Struct
from decompiler.structures.pseudo.operations import MemberAccess


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
                mediumlevelil.MediumLevelILLoad: self.lift_dereference_or_global_variable,
                mediumlevelil.MediumLevelILLoadSsa: self.lift_dereference_or_global_variable,
                mediumlevelil.MediumLevelILLoadStruct: self._lift_load_struct,
                mediumlevelil.MediumLevelILLoadStructSsa: self._lift_load_struct,
                mediumlevelil.MediumLevelILFtrunc: self._lift_ftrunc,
            }
        )

    def lift_unary_operation(self, op_type: OperationType, operation: MediumLevelILOperation, **kwargs) -> UnaryOperation:
        """Lift unary operation."""
        return UnaryOperation(
            op_type,
            [self._lifter.lift(x, parent=operation) for x in operation.operands],
            vartype=self._lifter.lift(operation.expr_type, parent=operation),
        )

    def lift_dereference_or_global_variable(
        self, operation: Union[mediumlevelil.MediumLevelILLoad, mediumlevelil.MediumLevelILLoadSsa], **kwargs
    ) -> Union[GlobalVariable, UnaryOperation]:
        """Lift load operation which is used both to model dereference operation and global variable read."""
        load_operand: UnaryOperation = self._lifter.lift(operation.src, parent=operation)
        if load_operand and isinstance(global_variable := load_operand, GlobalVariable):
            global_variable.ssa_label = operation.ssa_memory_version
            return global_variable
        return UnaryOperation(
            OperationType.dereference,
            [load_operand],
            vartype=load_operand.type,
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

    def _lift_load_struct(self, instruction: mediumlevelil.MediumLevelILLoadStruct, **kwargs) -> MemberAccess:
        """Lift a MLIL_LOAD_STRUCT_SSA (struct member access e.g. var#n->x) instruction."""
        struct_variable = self._lifter.lift(instruction.src)
        struct_ptr: Pointer = self._lifter.lift(instruction.src.expr_type)
        struct_member = struct_ptr.type.get_member_by_offset(instruction.offset)
        return MemberAccess(vartype=struct_ptr, operands=[struct_variable], offset=struct_member.offset, member_name=struct_member.name)

    def _lift_ftrunc(self, instruction: mediumlevelil.MediumLevelILFtrunc, **kwargs) -> UnaryOperation:
        """Lift a MLIL_FTRUNC operation."""
        return UnaryOperation(
            OperationType.cast,
            [self._lifter.lift(operand) for operand in instruction.operands],
            vartype=self._lifter.lift(instruction.expr_type),
        )
