"""Module implementing the ConstantHandler for the binaryninja frontend."""
from typing import Optional, Union

from binaryninja import BinaryView, DataVariable, Endianness, FunctionType, MediumLevelILInstruction, PointerType
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Constant, GlobalVariable, ImportedFunctionSymbol, Integer, OperationType, Pointer, UnaryOperation


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
        """Lift global variables with basic types (pointer are possible)"""
        if not variable.name and isinstance(variable.value, bytes): # will only catch const char[x] stuff; may be better checking variable.type for ArrayType
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
                    variable.name if variable.name else "data_" + f"{variable.address:x}",
                    self._lifter.lift(variable.type),
                    ssa_label=parent.ssa_memory_version if parent else 0,
                    initial_value=self._lifter.lift(view.get_data_var_at(variable.value), view=view) if isinstance(variable.type, PointerType) \
                    and variable.value != 0 else Constant(variable.value) # pointer can point to NULL as well
                )
            ],
        )
        