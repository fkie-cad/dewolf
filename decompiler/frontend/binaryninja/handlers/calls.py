"""Module implementing the binaryninja CallHandler."""
from typing import List
from binaryninja import mediumlevelil, MediumLevelILInstruction

from dewolf.frontend.lifter import Handler
from dewolf.structures.pseudo import Call, Assignment, ListOperation, ImportedFunctionSymbol


class CallHandler(Handler):
    """Class lifting mlil calls to their pseudo counterparts."""

    def register(self):
        """Register the handler in its parent lifter."""
        self._lifter.HANDLERS.update({
            mediumlevelil.MediumLevelILCall: self.lift_call,
            mediumlevelil.MediumLevelILCall_ssa: self.lift_call_ssa,
            mediumlevelil.MediumLevelILCall_untyped: self.lift_call,
            mediumlevelil.MediumLevelILCall_untyped_ssa: self.lift_call_ssa,
            mediumlevelil.MediumLevelILSyscall: self.lift_syscall,
            mediumlevelil.MediumLevelILSyscall_ssa: self.lift_syscall_ssa,
            mediumlevelil.MediumLevelILSyscall_untyped: self.lift_syscall,
            mediumlevelil.MediumLevelILSyscall_untyped_ssa: self.lift_call_ssa,
            mediumlevelil.MediumLevelILTailcall: self.lift_call,
            mediumlevelil.MediumLevelILTailcall_ssa: self.lift_call_ssa,
            mediumlevelil.MediumLevelILTailcall_untyped: self.lift_call,
            mediumlevelil.MediumLevelILTailcall_untyped_ssa: self.lift_call_ssa,
            mediumlevelil.MediumLevelILIntrinsic: self.lift_intrinsic,
            mediumlevelil.MediumLevelILIntrinsic_ssa: self.lift_intrinsic,
        })

    def lift_call(self, call: MediumLevelILInstruction) -> Assignment:
        """Lift non-ssa mlil call instructions."""
        return Assignment(
            ListOperation([self._lifter.lift(output) for output in call.output]),
            Call(
                dest := self._lifter.lift(call.dest),
                [self._lifter.lift(parameter) for parameter in call.params],
                vartype=dest.type,
                meta_data={"param_names": self._lift_call_parameter_names(call)},
            )
        )

    def lift_call_ssa(self, call: MediumLevelILInstruction) -> Assignment:
        """Lift ssa mlil call instructions, remembering the new memory version."""
        return Assignment(
            ListOperation([self._lifter.lift(output) for output in call.output]),
            Call(
                dest := self._lifter.lift(call.dest),
                [self._lifter.lift(parameter) for parameter in call.params],
                vartype=dest.type,
                writes_memory=call.output_dest_memory,
                meta_data={"param_names": self._lift_call_parameter_names(call)},
            )
        )

    def lift_syscall(self, call: MediumLevelILInstruction) -> Assignment:
        """Lift non-ssa syscall instructions invoking system level functionality."""
        return Assignment(
            ListOperation([self._lifter.lift(output) for output in call.output]),
            Call(
                dest := ImportedFunctionSymbol('Syscall', value=-1),
                [self._lifter.lift(parameter) for parameter in call.params],
                vartype=dest.type,
                meta_data={"param_names": self._lift_call_parameter_names(call)},
            )
        )

    def lift_syscall_ssa(self, call: MediumLevelILInstruction) -> Assignment:
        """Lift ssa mlil syscall instructions, remembering the new memory version."""
        return Assignment(
            ListOperation([self._lifter.lift(output) for output in call.output]),
            Call(
                dest := ImportedFunctionSymbol('Syscall', value=-1),
                [self._lifter.lift(parameter) for parameter in call.params],
                vartype=dest.type,
                writes_memory=call.output_dest_memory,
                meta_data={"param_names": self._lift_call_parameter_names(call)},
            )
        )

    def lift_intrinsic(self, call: MediumLevelILInstruction) -> Assignment:
        """Lift operations not supported by mlil and modeled as intrinsic operations."""
        return Assignment(
            ListOperation([self._lifter.lift(value) for value in call.output]),
            Call(
                ImportedFunctionSymbol(str(call.intrinsic), value=-1),
                [self._lifter.lift(param) for param in call.params]
            )
        )

    @staticmethod
    def _lift_call_parameter_names(instruction: MediumLevelILInstruction) -> List[str]:
        """Lift parameter names of call from type string of instruction.dest.expr_type"""
        clean_type_string_of_parameters = instruction.dest.expr_type.get_string_after_name().strip("()")
        return [type_parameter.rsplit(" ", 1)[-1] for type_parameter in clean_type_string_of_parameters.split(",")]
