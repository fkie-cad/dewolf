"""Module implementing the ConstantHandler for the binaryninja frontend."""
from typing import Union, Optional

from binaryninja import DataVariable, Endianness, MediumLevelILInstruction, BinaryView, PointerType, FunctionType, Type
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
        """Lift global variables with different types.

            For clarity all cases:
                1. Variable does not have a name 
                    - lift as Constand, try to decode the value if value are bytes (string), otherwise raw value

                2. Variable is a function pointer 
                    - lift as ImportedFunctionSymbol (what about a normal function pointer? Maybe more checks about type)

                3. Variable is a pointer itself 
                    - check the value of the pointer

                    3.1 Variable points to known type
                        - lift the value itself as a datavariable 
                    
                    3.2 Variable points to unknown type
                        - try to lift a string (char*), if there is one, otherwise lift as raw bytes (void*) 

                4. Variable is a "normal variable"
                    - try to lift as the type specified 

                    - if the type is void, lift as char* 
        """
        if not variable.name:
            return Constant(
                variable.value.decode("utf-8") if isinstance(variable.value, bytes) else variable.value, 
                vartype=self._lifter.lift(variable.type)
            )
        if isinstance(variable.type, PointerType) and isinstance(variable.type.target, FunctionType):
            return ImportedFunctionSymbol(variable.name, variable.address, vartype=Pointer(Integer.char())) 
        if isinstance(variable.type, PointerType):
            return self._lift_global_ptr(variable, view, parent)
        return self._lift_global_variable(variable, view, parent)
    
    def _lift_global_ptr(self, variable: DataVariable, view: BinaryView, 
        parent: Optional[MediumLevelILInstruction] = None):
        """Lift a global variable with a pointer type"""
        ref_var = view.get_data_var_at(variable.value)
        if not ref_var:
            return self._lift_global_ptr_with_unknown_ref_type(variable, view, parent)
            
        return UnaryOperation(
            OperationType.address,
            [
                GlobalVariable(
                    variable.name + "_" + view.get_sections_at(variable.address)[0].name[1:],
                    self._lifter.lift(variable.type),
                    ssa_label=parent.ssa_memory_version if parent else 0,
                    initial_value=self._lifter.lift(ref_var, view=view)
                )
            ],
        )

    def _lift_global_ptr_with_unknown_ref_type(self, variable: DataVariable, view: BinaryView, 
        parent: Optional[MediumLevelILInstruction] = None):
        """Lift a global void pointer, if pointing to a string, cast as char pointer"""
        string = view.get_string_at(variable.value)

        return UnaryOperation(
            OperationType.address,
            [
                GlobalVariable(
                    variable.name + "_" + view.get_sections_at(variable.address)[0].name[1:],
                    self._lifter.lift(Type.pointer(view.arch, Type.char()) if string else variable.type),
                    ssa_label=parent.ssa_memory_version if parent else 0,
                    initial_value=Constant(string.value) if string else self._get_raw_bytes(view, variable.value)
                )
            ],
        )

    def _lift_global_variable(self, variable: DataVariable, view: BinaryView, 
        parent: Optional[MediumLevelILInstruction] = None):
        """Lift a global variable with a non pointer type."""
        if "void" in [x.text for x in variable.type.get_tokens()]:
            return GlobalVariable(
                    variable.name + "_" + view.get_sections_at(variable.address)[0].name[1:],
                    vartype=self._lifter.lift(view.parse_type_string("char*")[0]),
                    ssa_label=parent.ssa_memory_version if parent else 0,
                    initial_value=self._get_raw_bytes(view, variable.address)
                )

        return UnaryOperation(
            OperationType.address,
            [
                GlobalVariable(
                    variable.name + "_" + view.get_sections_at(variable.address)[0].name[1:],
                    self._lifter.lift(variable.type),
                    ssa_label=parent.ssa_memory_version if parent else 0,
                    initial_value=Constant(variable.value)
                )
            ],
        )

    def _get_raw_bytes(self, view: BinaryView, addr: int) -> bytes:
        """ Returns raw bytes after a given address to the next data structure or section"""
        if next_data_var := view.get_next_data_var_after(addr):
            return view.read(addr, next_data_var.address - addr)
        else:
            return view.read(addr, view.get_sections_at(addr)[0].end)