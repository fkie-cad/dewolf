"""Module implementing the AssignmentHandler for binaryninja."""
from functools import partial
from typing import Union

from binaryninja import mediumlevelil
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Constant,
    GlobalVariable,
    Integer,
    Operation,
    OperationType,
    Pointer,
    RegisterPair,
    UnaryOperation,
)


class AssignmentHandler(Handler):
    """Handler for assignments, split assignments as well as field accesses."""

    def register(self):
        """Register the handler with the parent ObserverLifter."""
        self._lifter.HANDLERS.update(
            {
                mediumlevelil.MediumLevelILSetVar: self.lift_assignment,
                mediumlevelil.MediumLevelILSetVarSsa: self.lift_assignment,
                mediumlevelil.MediumLevelILSetVarField: self.lift_set_field,
                mediumlevelil.MediumLevelILSetVarSsaField: self.lift_set_field,
                mediumlevelil.MediumLevelILSetVarSplit: self.lift_split_assignment,
                mediumlevelil.MediumLevelILSetVarSplitSsa: self.lift_split_assignment,
                mediumlevelil.MediumLevelILSetVarAliased: partial(self.lift_assignment, is_aliased=True),
                mediumlevelil.MediumLevelILSetVarAliasedField: partial(self.lift_set_field, is_aliased=True),
                mediumlevelil.MediumLevelILVarField: self.lift_get_field,
                mediumlevelil.MediumLevelILVarSsaField: self.lift_get_field,
                mediumlevelil.MediumLevelILVarAliasedField: partial(self.lift_get_field, is_aliased=True),
                mediumlevelil.MediumLevelILStore: self.lift_store,
                mediumlevelil.MediumLevelILStoreSsa: self.lift_store,
                mediumlevelil.MediumLevelILStoreStruct: self._lift_store_struct,
                mediumlevelil.MediumLevelILStoreStructSsa: self._lift_store_struct,
                mediumlevelil.MediumLevelILLowPart: self._lift_mask_high,
            }
        )

    def lift_assignment(self, assignment: mediumlevelil.MediumLevelILSetVar, is_aliased=False, **kwargs) -> Assignment:
        """Lift assignment operations (e.g. eax = ebx)."""
        return Assignment(
            self._lifter.lift(assignment.dest, is_aliased=is_aliased, parent=assignment),
            self._lifter.lift(assignment.src, parent=assignment),
        )

    def lift_set_field(self, assignment: mediumlevelil.MediumLevelILSetVarField, is_aliased=False, **kwargs) -> Assignment:
        """
        Lift an instruction writing to a subset of the given value.

        In case of lower register (offset 0) lift as contraction
        e.g. eax.al = .... <=> (char)eax  ....

        In case higher registers use masking
        e.g. eax.ah = x <=> eax = (eax & 0xffff00ff) + (x << 2)
        """
        if assignment.offset == 0 and self._lifter.is_omitting_masks:
            destination = self._lift_contraction(assignment, is_aliased=is_aliased, parent=assignment)
            value = self._lifter.lift(assignment.src)
        else:
            destination = self._lifter.lift(assignment.dest, is_aliased=is_aliased, parent=assignment)
            value = self._lift_masked_operand(assignment)
        return Assignment(destination, value)

    def lift_get_field(self, instruction: mediumlevelil.MediumLevelILVarField, is_aliased=False, **kwargs) -> Operation:
        """
        Lift an instruction accessing a field from the outside.
        e.g. x = eax.ah <=> x = eax & 0x0000ff00
        """
        source = self._lifter.lift(instruction.src, is_aliased=is_aliased, parent=instruction)
        cast_type = source.type.resize(instruction.size * self.BYTE_SIZE)
        if instruction.offset:
            return BinaryOperation(
                OperationType.bitwise_and,
                [source, Constant(self._get_all_ones_mask_for_type(instruction.size) << instruction.offset)],
                vartype=cast_type,
            )
        return UnaryOperation(OperationType.cast, [source], vartype=cast_type, contraction=True)

    def lift_store(self, assignment: mediumlevelil.MediumLevelILStoreSsa, **kwargs) -> Assignment:
        """Lift a store operation to pseudo (e.g. [ebp+4] = eax, or [global_var_label] = 25)."""
        return Assignment(
            self._lift_store_destination(assignment),
            self._lifter.lift(assignment.src),
        )

    def _lift_store_destination(self, store_assignment: mediumlevelil.MediumLevelILStoreSsa) -> Union[UnaryOperation, GlobalVariable]:
        """
        Lift destination operand of store operation which is used for modelling both assignments of dereferences and global variables.
        """
        memory_version = store_assignment.dest_memory
        store_destination = self._lifter.lift(store_assignment.dest, parent=store_assignment)
        if isinstance(store_destination, GlobalVariable):
            store_destination.ssa_label = memory_version
            return store_destination
        return UnaryOperation(OperationType.dereference, [store_destination], vartype=store_destination.type, writes_memory=memory_version)

    def _lift_contraction(self, assignment: mediumlevelil.MediumLevelILSetVarField, is_aliased=False, **kwargs) -> UnaryOperation:
        """
        Lift assignment to lower register part (offset 0 from register start) as contraction (cast)

        e.g.:
        eax.al = 10;
        becomes:
        (byte) eax = 10; // Assign(Cast([eax], byte, contraction=true), Constant(10))
        """
        destination_operand = self._lifter.lift(assignment.dest, is_aliased=is_aliased, parent=assignment)
        contraction_type = destination_operand.type.resize(assignment.size * self.BYTE_SIZE)
        return UnaryOperation(OperationType.cast, [destination_operand], vartype=contraction_type, contraction=True)

    def _lift_masked_operand(self, assignment: mediumlevelil.MediumLevelILSetVarField, is_aliased=False, **kwargs) -> BinaryOperation:
        """Lift the rhs value for subregister assignments (e.g. eax.ah = x <=> eax = (eax & 0xffff00ff) + (x << 2))."""
        return BinaryOperation(
            OperationType.bitwise_or,
            [
                BinaryOperation(
                    OperationType.bitwise_and,
                    [
                        self._lifter.lift(assignment.prev, parent=assignment, is_aliased=is_aliased),
                        Constant(
                            self._get_all_ones_mask_for_type(assignment.dest.var.type.width)
                            - self._get_all_ones_mask_for_type(assignment.size)
                            << (assignment.offset * self.BYTE_SIZE)
                        ),
                    ],
                    vartype=self._lifter.lift(assignment.src.expr_type, parent=assignment),
                ),
                BinaryOperation(
                    OperationType.left_shift,
                    [self._lifter.lift(assignment.src, parent=assignment), Constant(assignment.offset * self.BYTE_SIZE)],
                    vartype=self._lifter.lift(assignment.src.expr_type, parent=assignment),
                ),
            ],
            vartype=self._lifter.lift(assignment.expr_type, parent=assignment),
        )

    def _lift_mask_high(self, instruction: mediumlevelil.MediumLevelILSetVarField, **kwargs) -> BinaryOperation:
        """
        Lift an instruction masking the higher part of a value.
        e.g. eax.al = eax & 0x000000ff
        """
        return BinaryOperation(
            OperationType.bitwise_and,
            [op := self._lifter.lift(instruction.src, parent=instruction), Constant(self._get_all_ones_mask_for_type(instruction.size))],
            vartype=op.type.resize(instruction.size * self.BYTE_SIZE),
        )

    def _get_all_ones_mask_for_type(self, type_size: int, **kwargs) -> int:
        """Generate a bit mask for the given type_size."""
        return int(2 ** (type_size * self.BYTE_SIZE) - 1)

    def lift_split_assignment(self, assignment: mediumlevelil.MediumLevelILSetVarSplit, **kwargs) -> Assignment:
        """Lift an instruction writing to a register pair such as MUL instructions."""
        return Assignment(
            RegisterPair(
                high := self._lifter.lift(assignment.high, parent=assignment),
                low := self._lifter.lift(assignment.low, parent=assignment),
                vartype=high.type.resize((high.type.size + low.type.size)),
            ),
            self._lifter.lift(assignment.src, parent=assignment),
        )

    def _lift_store_struct(self, instruction: mediumlevelil.MediumLevelILStoreStruct, **kwargs) -> Assignment:
        """Lift a MLIL_STORE_STRUCT_SSA instruction to pseudo (e.g. object->field = x)."""
        vartype = self._lifter.lift(instruction.dest.expr_type)
        return Assignment(
            UnaryOperation(
                OperationType.dereference,
                [
                    BinaryOperation(
                        OperationType.plus,
                        [
                            UnaryOperation(OperationType.cast, [self._lifter.lift(instruction.dest)], vartype=Pointer(Integer.char())),
                            Constant(instruction.offset),
                        ],
                        vartype=vartype,
                    ),
                ],
                vartype=Pointer(vartype),
            ),
            self._lifter.lift(instruction.src),
        )
