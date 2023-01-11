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
        """Lift global variables, the following cases can occur:
            - global variable has no name
                ==> lift as constant
            - global variable has a 'simple' (int, char etc.) type
                ==> lift as pointer, pointing to the global variable 
            - global variable is a function pointer 
                ==> lift as Function symbol 
            - global variable is a pointer pointing to something else
                ==> lift as pointer, pointing to the global variable + lift the value of global variable aswell 
        """
        y = view.get_sections_at(variable.address)

        if not variable.name:
            return Constant(variable.value, vartype=self._lifter.lift(variable.type))

        if not isinstance(variable.type, PointerType): # Not a ptr
            return UnaryOperation(
            OperationType.address,
            [
                GlobalVariable(
                    variable.name + "@" + view.get_sections_at(variable.address)[0].name[1:],
                    self._lifter.lift(variable.type),
                    ssa_label=parent.ssa_memory_version if parent else 0,
                    initial_value=Constant(variable.value)
                )
            ],
        )

        if isinstance(variable.type.target, FunctionType):
            return ImportedFunctionSymbol(variable.name, variable.address, vartype=Pointer(Integer.char())) 

        ref_var = view.get_data_var_at(variable.value)
        return UnaryOperation( # Case ptr
            OperationType.address,
            [
                GlobalVariable(
                    variable.name + "@" + view.get_sections_at(variable.address)[0].name[1:],
                    self._lifter.lift(variable.type),
                    ssa_label=parent.ssa_memory_version if parent else 0,
                    initial_value=self._lifter.lift(ref_var, view=view) if ref_var else Constant(variable.value) # else: case void* (could be done with above case)
                )
            ],
        )