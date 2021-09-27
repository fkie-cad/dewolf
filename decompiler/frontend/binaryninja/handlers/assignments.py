"""Module implementing the AssignmentHandler for binaryninja."""
from functools import partial

from binaryninja import SetVar, mediumlevelil
from dewolf.frontend.lifter import Handler
from dewolf.structures.pseudo import Assignment, BinaryOperation, Constant, Operation, OperationType, RegisterPair, UnaryOperation


class AssignmentHandler(Handler):
    """Handler for assignments, split assignments as well as field accesses."""

    def register(self):
        """Register the handler with the parent ObserverLifter."""
        self._lifter.HANDLERS.update(
            {
                mediumlevelil.MediumLevelILSet_var: self.lift_assignment,
                mediumlevelil.MediumLevelILSet_var_ssa: self.lift_assignment,
                mediumlevelil.MediumLevelILSet_var_field: self.lift_set_field,
                mediumlevelil.MediumLevelILSet_var_ssa_field: self.lift_set_field,
                mediumlevelil.MediumLevelILSet_var_split: self.lift_split_assignment,
                mediumlevelil.MediumLevelILSet_var_split_ssa: self.lift_split_assignment,
                mediumlevelil.MediumLevelILSet_var_aliased: partial(self.lift_assignment, is_aliased=True),
                mediumlevelil.MediumLevelILSet_var_aliased_field: partial(self.lift_set_field, is_aliased=True),
                mediumlevelil.MediumLevelILVar_field: self.lift_get_field,
                mediumlevelil.MediumLevelILVar_ssa_field: self.lift_get_field,
                mediumlevelil.MediumLevelILVar_aliased_field: partial(self.lift_get_field, is_aliased=True),
                mediumlevelil.MediumLevelILStore_ssa: self.lift_store,
            }
        )

    def lift_assignment(self, assignment: SetVar, is_aliased=False, **kwargs) -> Assignment:
        """Lift assignment operations (e.g. eax = ebx)."""
        return Assignment(self._lifter.lift(assignment.dest, is_aliased=is_aliased, parent=assignment), self._lifter.lift(assignment.src))

    def lift_set_field(self, assignment: SetVar, is_aliased=False, **kwargs) -> Assignment:
        """
        Lift an instruction writing to a subset of the given value.

        In case of lower register (offset 0) lift as contraction
        E.g. eax.al = .... <=> (char)eax  ....

        In case higher registers use masking
        e.g. eax.ah = x <=> eax = (eax & 0xffff00ff) + (x << 2)
        """
        if assignment.offset == 0:
            destination = self._lift_contraction(assignment, is_aliased=is_aliased)
            value = self._lifter.lift(assignment.src)
        else:
            destination = self._lifter.lift(assignment.dest, is_aliased=is_aliased, parent=assignment)
            value = self._lift_masked_asignment(assignment)
        return Assignment(destination, value)

    def lift_get_field(self, instruction: mediumlevelil.MediumLevelILVar_field, is_aliased=False, **kwargs) -> Operation:
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

    def lift_store(self, assignment: mediumlevelil.MediumLevelILStore_ssa, **kwargs) -> Assignment:
        return Assignment(
            UnaryOperation(
                OperationType.dereference,
                [op := self._lifter.lift(assignment.dest, parent=assignment)],
                vartype=op.type,
                writes_memory=assignment.dest_memory,
            ),
            self._lifter.lift(assignment.src),
        )

    def _lift_contraction(self, assignment: SetVar, is_aliased=False, **kwargs) -> UnaryOperation:
        """
        We lift assignment to lower register part (offset 0 from register start) as contraction (cast)

        E.g.:
        eax.al = 10;
        becomes:
        (byte) eax = 10; // Assign(Cast([eax], byte, contraction=true), Constant(10))
        :param instruction: instruction of type MLIL_SET_VAR_FIELD
        """
        destination_operand = self._lifter.lift(assignment.dest, is_aliased=is_aliased, parent=SetVar)
        contraction_type = destination_operand.type.resize(assignment.size * self.BYTE_SIZE)
        return UnaryOperation(OperationType.cast, [destination_operand], vartype=contraction_type, contraction=True)

    def _lift_masked_asignment(self, assignment: SetVar, **kwargs) -> BinaryOperation:
        return BinaryOperation(
            OperationType.bitwise_or,
            [
                BinaryOperation(
                    OperationType.bitwise_and,
                    [
                        self._lifter.lift(assignment.prev, parent=assignment),
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

    def _lift_mask_high(self, instruction: mediumlevelil.MediumLevelILInstruction, **kwargs) -> BinaryOperation:
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

    def lift_split_assignment(self, assignment: mediumlevelil.MediumLevelILSet_var_split, **kwargs) -> Assignment:
        """Lift an instruction writing to a register pair."""
        return Assignment(
            RegisterPair(
                high := self._lifter.lift(assignment.high, parent=assignment),
                low := self._lifter.lift(assignment.low, parent=assignment),
                vartype=high.type.resize((high.type.size + low.type.size) * self.BYTE_SIZE),
            ),
            self._lifter.lift(assignment.src, parent=assignment),
        )
