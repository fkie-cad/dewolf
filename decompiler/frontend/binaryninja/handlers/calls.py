"""Module implementing the binaryninja CallHandler."""
from functools import partial
from typing import List

from binaryninja import MediumLevelILInstruction, mediumlevelil
from dewolf.frontend.lifter import Handler
from dewolf.structures.pseudo import Assignment, Call, ImportedFunctionSymbol, IntrinsicSymbol, ListOperation


class CallHandler(Handler):
    """Class lifting mlil calls to their pseudo counterparts."""

    def register(self):
        """Register the handler in its parent lifter."""
        self._lifter.HANDLERS.update(
            {
                mediumlevelil.MediumLevelILCall: self.lift_call,
                mediumlevelil.MediumLevelILCall_ssa: partial(self.lift_call, ssa=True),
                mediumlevelil.MediumLevelILCall_untyped: self.lift_call,
                mediumlevelil.MediumLevelILCall_untyped_ssa: partial(self.lift_call, ssa=True),
                mediumlevelil.MediumLevelILSyscall: self.lift_syscall,
                mediumlevelil.MediumLevelILSyscall_ssa: partial(self.lift_syscall, ssa=True),
                mediumlevelil.MediumLevelILSyscall_untyped: self.lift_syscall,
                mediumlevelil.MediumLevelILSyscall_untyped_ssa: partial(self.lift_syscall, ssa=True),
                mediumlevelil.MediumLevelILTailcall: self.lift_call,
                mediumlevelil.MediumLevelILTailcall_ssa: partial(self.lift_call, ssa=True),
                mediumlevelil.MediumLevelILTailcall_untyped: self.lift_call,
                mediumlevelil.MediumLevelILTailcall_untyped_ssa: partial(self.lift_call, ssa=True),
                mediumlevelil.MediumLevelILIntrinsic: self.lift_intrinsic,
                mediumlevelil.MediumLevelILIntrinsic_ssa: partial(self.lift_intrinsic, ssa=True),
            }
        )

    def lift_call(self, call: mediumlevelil.MediumLevelILCall, ssa: bool = False, **kwargs) -> Assignment:
        """Lift mlil call instructions, remembering the new memory version."""
        return Assignment(
            ListOperation([self._lifter.lift(output, parent=call) for output in call.output]),
            Call(
                dest := self._lifter.lift(call.dest, parent=call),
                [self._lifter.lift(parameter, parent=call) for parameter in call.params],
                vartype=dest.type,
                writes_memory=call.output_dest_memory if ssa else None,
                meta_data={"param_names": self._lift_call_parameter_names(call)},
            ),
        )

    def lift_syscall(self, call: mediumlevelil.MediumLevelILSyscall, ssa: bool = False, **kwargs) -> Assignment:
        """Lift a syscall instructions invoking system level functionality."""
        return Assignment(
            ListOperation([self._lifter.lift(output, parent=call) for output in call.output]),
            Call(
                dest := ImportedFunctionSymbol("Syscall", value=-1),
                [self._lifter.lift(parameter, parent=call) for parameter in call.params],
                vartype=dest.type,
                writes_memory=call.output_dest_memory if ssa else None,
                meta_data={"param_names": self._lift_call_parameter_names(call)},
            ),
        )

    def lift_intrinsic(self, call: mediumlevelil.MediumLevelILIntrinsic, ssa: bool = False, **kwargs) -> Assignment:
        """Lift operations not supported by mlil and modeled as intrinsic operations."""
        return Assignment(
            ListOperation([self._lifter.lift(value, parent=call) for value in call.output]),
            Call(
                IntrinsicSymbol(str(call.intrinsic)),
                [self._lifter.lift(param, parent=call) for param in call.params],
                writes_memory=call.output_dest_memory if ssa else None,
            ),
        )

    @staticmethod
    def _lift_call_parameter_names(instruction: MediumLevelILInstruction) -> List[str]:
        """Lift parameter names of call from type string of instruction.dest.expr_type"""
        clean_type_string_of_parameters = instruction.dest.expr_type.get_string_after_name().strip("()")
        return [type_parameter.rsplit(" ", 1)[-1] for type_parameter in clean_type_string_of_parameters.split(",")]
