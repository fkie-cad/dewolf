"""Module implementing the binaryninja CallHandler."""

from functools import partial
from typing import List

from binaryninja import FunctionType, PointerType, Tailcall, mediumlevelil
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Assignment, Call, ImportedFunctionSymbol, IntrinsicSymbol, ListOperation


class CallHandler(Handler):
    """Class lifting mlil calls to their pseudo counterparts."""

    def register(self):
        """Register the handler in its parent lifter."""
        self._lifter.HANDLERS.update(
            {
                mediumlevelil.MediumLevelILCall: self.lift_call,
                mediumlevelil.MediumLevelILCallSsa: partial(self.lift_call, ssa=True),
                mediumlevelil.MediumLevelILCallUntyped: self.lift_call,
                mediumlevelil.MediumLevelILCallUntypedSsa: partial(self.lift_call, ssa=True),
                mediumlevelil.MediumLevelILSyscall: self.lift_syscall,
                mediumlevelil.MediumLevelILSyscallSsa: partial(self.lift_syscall, ssa=True),
                mediumlevelil.MediumLevelILSyscallUntyped: self.lift_syscall,
                mediumlevelil.MediumLevelILSyscallUntypedSsa: partial(self.lift_syscall, ssa=True),
                mediumlevelil.MediumLevelILTailcall: self.lift_call,
                mediumlevelil.MediumLevelILTailcallSsa: partial(self.lift_call, ssa=True),
                mediumlevelil.MediumLevelILTailcallUntyped: self.lift_call,
                mediumlevelil.MediumLevelILTailcallUntypedSsa: partial(self.lift_call, ssa=True),
                mediumlevelil.MediumLevelILIntrinsic: self.lift_intrinsic,
                mediumlevelil.MediumLevelILIntrinsicSsa: partial(self.lift_intrinsic, ssa=True),
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
                meta_data={"param_names": self._lift_call_parameter_names(call), "is_tailcall": isinstance(call, Tailcall)},
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
                meta_data={"param_names": self._lift_syscall_parameter_names(call)},
            ),
        )

    def lift_intrinsic(self, call: mediumlevelil.MediumLevelILIntrinsic, ssa: bool = False, **kwargs) -> Assignment:
        """
        Lift operations not supported by mlil and modeled as intrinsic operations.

        e.g. temp0_1#2 = _mm_add_epi32(zmm1#2, zmm5#1)
        """
        return Assignment(
            ListOperation([self._lifter.lift(value, parent=call) for value in call.output]),
            Call(
                IntrinsicSymbol(str(call.intrinsic)),
                [self._lifter.lift(param, parent=call) for param in call.params],
            ),
        )

    @staticmethod
    def _lift_call_parameter_names(instruction: mediumlevelil.MediumLevelILCall) -> List[str]:
        """Lift parameter names of call by iterating over the function parameters where the call is pointing to (if available)"""
        if (
            instruction.dest.expr_type is None
            or not isinstance(instruction.dest.expr_type, PointerType)
            or not isinstance(instruction.dest.expr_type.target, FunctionType)
        ):
            return []
        return [param.name for param in instruction.dest.expr_type.target.parameters]

    @staticmethod
    def _lift_syscall_parameter_names(instruction: mediumlevelil.MediumLevelILSyscall) -> List[str]:
        """Lift syscall identifier (e.G. sys_open) from a syscall instruction"""
        return [str(instruction).split("syscall(")[1].split(" ")[0]]
