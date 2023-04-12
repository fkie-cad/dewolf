"""Module implementing the ConstantHandler for the binaryninja frontend."""
from typing import Optional, Union

from binaryninja import BinaryView, DataVariable, Endianness, MediumLevelILInstruction, PointerType
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import (
    Constant,
    GlobalVariable,
    OperationType,
    UnaryOperation,
)


class GlobalHandler(Handler):
    """Handle for global variables."""

    # Dict translating endianness between the binaryninja enum and pythons literals
    Endian = {Endianness.LittleEndian: "little", Endianness.BigEndian: "big"}

    def register(self):
        """Register the handler at its parent lifter."""
        self._lifter.HANDLERS.update({DataVariable: self.lift_global_variable})

    def lift_global_variable(self, variable: DataVariable, view: BinaryView, 
        parent: Optional[MediumLevelILInstruction] = None, **kwargs
    ) -> UnaryOperation:
        """Lift global variables with basic types (pointer are possible)"""
        return UnaryOperation(
            OperationType.address,
                [
                    GlobalVariable(
                    variable.name if variable.name else "data_" + f"{variable.address:x}",
                    self._lifter.lift(variable.type),
                    ssa_label=parent.ssa_memory_version if parent else 0,
                    initial_value=self._get_initial_value(variable, view)
                )
            ],
        )

    
    def _get_initial_value(self, variable: DataVariable, view: BinaryView) -> Union[UnaryOperation, Constant]:
        """Return initial value of data variable"""
        if isinstance(variable.type, PointerType) and variable.value != 0 and variable.address != variable.value:
            return self._lifter.lift(view.get_data_var_at(variable.value), view=view)
        else:
            return Constant(variable.value)
