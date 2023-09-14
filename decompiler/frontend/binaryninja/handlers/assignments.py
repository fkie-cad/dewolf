"""Module implementing the AssignmentHandler for binaryninja."""
import logging
from functools import partial

import binaryninja
from binaryninja import mediumlevelil
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Constant,
    Expression,
    GlobalVariable,
    Integer,
    Operation,
    OperationType,
    Pointer,
    RegisterPair,
    UnaryOperation,
)
from decompiler.structures.pseudo.complextypes import Struct, Union
from decompiler.structures.pseudo.operations import MemberAccess


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
                mediumlevelil.MediumLevelILStoreStruct: self.lift_store_struct,
                mediumlevelil.MediumLevelILStoreStructSsa: self.lift_store_struct,
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
        case 1: writing into struct member: book.title = value
                lift as struct_member(book, title, writes_memory) = value
        case 2: writing into lower register part (offset 0): eax.al = value
                lift as contraction (char) eax = value
        case 3: writing into higher register part: eax.ah = value
                lift using bit masking eax = (eax & 0xffff00ff) + (value << 2)
        """
        # case 1 (struct), avoid set field of named integers:
        dest_type = self._lifter.lift(assignment.dest.type)
        if isinstance(assignment.dest.type, binaryninja.NamedTypeReferenceType) and not (
                isinstance(dest_type, Pointer) and isinstance(dest_type.type, Integer)
        ):
            struct_variable = self._lifter.lift(assignment.dest, is_aliased=True, parent=assignment)
            destination = MemberAccess(
                offset=assignment.offset,
                member_name=struct_variable.type.get_member_by_offset(assignment.offset).name,
                operands=[struct_variable],
                writes_memory=assignment.ssa_memory_version,
            )
            value = self._lifter.lift(assignment.src)
        # case 2 (contraction):
        elif assignment.offset == 0 and self._lifter.is_omitting_masks:
            destination = self._lift_contraction(assignment, is_aliased=is_aliased, parent=assignment)
            value = self._lifter.lift(assignment.src)
        # case 3 (bit masking):
        else:
            destination = self._lifter.lift(assignment.dest, is_aliased=is_aliased, parent=assignment)
            value = self._lift_masked_operand(assignment)
        return Assignment(destination, value)

    def lift_get_field(self, instruction: mediumlevelil.MediumLevelILVarField, is_aliased=False, **kwargs) -> Operation:
        """
        Lift an instruction accessing a field from the outside.

        case 1: struct member read access e.g. (x = )book.title
                lift as (x = ) struct_member(book, title)
        case 2: accessing register portion e.g. (x = )eax.ah
                lift as (x = ) eax & 0x0000ff00
        (x = ) <- for the sake of example, only rhs expression is lifted here.
        """
        source = self._lifter.lift(instruction.src, is_aliased=is_aliased, parent=instruction)
        if isinstance(source.type, Struct) or isinstance(source.type, Union):
            return self._get_field_as_member_access(instruction, source, **kwargs)
        cast_type = source.type.resize(instruction.size * self.BYTE_SIZE)
        if instruction.offset:
            return BinaryOperation(
                OperationType.bitwise_and,
                [source, Constant(self._get_all_ones_mask_for_type(instruction.size) << instruction.offset)],
                vartype=cast_type,
            )
        return UnaryOperation(OperationType.cast, [source], vartype=cast_type, contraction=True)

    def _get_field_as_member_access(self, instruction: mediumlevelil.MediumLevelILVarField, source: Expression, **kwargs) -> MemberAccess:
        """Lift MLIL var_field as struct or union member read access."""
        if isinstance(source.type, Struct):
            member_name = source.type.get_member_by_offset(instruction.offset).name
        elif parent := kwargs.get("parent", None):
            parent_type = self._lifter.lift(parent.dest.type)
            member_name = source.type.get_member_by_type(parent_type).name
        else:
            logging.warning(f"Cannot get member name for instruction {instruction}")
            member_name = f"field_{hex(instruction.offset)}"
        return MemberAccess(
            offset=instruction.offset,
            member_name=member_name,
            operands=[source],
        )

    def lift_store(self, assignment: mediumlevelil.MediumLevelILStoreSsa, **kwargs) -> Assignment:
        """Lift a store operation to pseudo (e.g. [ebp+4] = eax, or [global_var_label] = 25)."""
        return Assignment(
            self._lift_store_destination(assignment),
            self._lifter.lift(assignment.src),
        )

    def _lift_store_destination(self, store_assignment: mediumlevelil.MediumLevelILStoreSsa) -> UnaryOperation | GlobalVariable:
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

    def lift_store_struct(self, instruction: mediumlevelil.MediumLevelILStoreStruct, **kwargs) -> Assignment:
        """Lift a MLIL_STORE_STRUCT_SSA instruction to pseudo (e.g. object->field = x)."""
        vartype = self._lifter.lift(instruction.dest.expr_type)
        struct_variable = self._lifter.lift(instruction.dest, is_aliased=True, parent=instruction)
        struct_member_access = MemberAccess(
            member_name=vartype.type.members.get(instruction.offset),
            offset=instruction.offset,
            operands=[struct_variable],
            vartype=vartype,
            writes_memory=instruction.dest_memory,
        )
        src = self._lifter.lift(instruction.src)
        return Assignment(struct_member_access, src)
