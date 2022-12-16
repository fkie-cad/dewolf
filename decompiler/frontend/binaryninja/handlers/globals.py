"""Module implementing the ConstantHandler for the binaryninja frontend."""
from typing import Union, Optional

from binaryninja import DataVariable, Endianness, MediumLevelILInstruction, BinaryView, PointerType
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Constant, GlobalVariable, OperationType, UnaryOperation


class GlobalHandler(Handler):
    """Handle for global variables."""

    # Dict translating endianness between the binaryninja enum and pythons literals
    Endian = {Endianness.LittleEndian: "little", Endianness.BigEndian: "big"}

    def register(self):
        """Register the handler at its parent lifter."""
        self._lifter.HANDLERS.update({DataVariable: self.lift_global_variable})

    def lift_global_variable(self, variable: DataVariable, view: Optional[BinaryView], 
        parent: Optional[MediumLevelILInstruction] = None, **kwargs
    ) -> Union[GlobalVariable, UnaryOperation]:
        if not variable.name:
            return Constant(variable.value, vartype=self._lifter.lift(variable.type))

        # When a global pointer points to a global variable, we probably need to lift 
        # the inital value as well, other wise we would only get a pointer which points to a address (where the global variable lives)
        # (Maybe there is a better way to check if the current variable is a pointer?)
        if isinstance(variable.type, PointerType):
            ref_var = view.get_data_var_at(variable.value)
            initial_value = self._lifter.lift(ref_var, view=view)
        else:
            initial_value = Constant(variable.value)
        return UnaryOperation(
            OperationType.address,
            [
                GlobalVariable(
                    variable.name,
                    self._lifter.lift(variable.type),
                    ssa_label=parent.ssa_memory_version if parent else 0,
                    initial_value=initial_value
                )
            ],
        )
