"""Module implementing the ConstantHandler for the binaryninja frontend."""
from typing import Union, Optional

from binaryninja import DataVariable, Endianness, MediumLevelILInstruction, BinaryView, PointerType, FunctionType
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Constant, GlobalVariable, OperationType, UnaryOperation, ImportedFunctionSymbol, Pointer, Integer


class GlobalHandler(Handler):
    """Handle for global variables."""

    # Dict translating endianness between the binaryninja enum and pythons literals
    Endian = {Endianness.LittleEndian: "little", Endianness.BigEndian: "big"}

    def register(self):
        """Register the handler at its parent lifter."""
        self._lifter.HANDLERS.update({DataVariable: self.lift_global_variable})

    def lift_global_variable(self, variable: DataVariable, view: BinaryView, 
        parent: Optional[MediumLevelILInstruction] = None, **kwargs
    ) -> Union[ImportedFunctionSymbol, Constant, UnaryOperation]:
        """Lift global variables with basic types (pointer are possible, but not void pointer)"""
        if not variable.name:
            return Constant(
                value=variable.value.decode("utf-8") if isinstance(variable.value, bytes) else variable.value, 
                vartype=self._lifter.lift(variable.type)
            )
        if isinstance(variable.type, PointerType) and isinstance(variable.type.target, FunctionType):
            return ImportedFunctionSymbol(variable.name, variable.address, vartype=Pointer(Integer.char())) 

        return UnaryOperation(
            OperationType.address,
                [
                    GlobalVariable(
                    variable.name + "_" + view.get_sections_at(variable.address)[0].name[1:],
                    self._lifter.lift(variable.type),
                    ssa_label=parent.ssa_memory_version if parent else 0,
                    initial_value=self._lifter.lift(view.get_data_var_at(variable.value), view=view) if isinstance(variable.type, PointerType) \
                    else Constant(variable.value)
                )
            ],
        )
       