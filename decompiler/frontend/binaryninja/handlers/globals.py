"""Module implementing the ConstantHandler for the binaryninja frontend."""
from typing import Optional, Tuple

from binaryninja import BinaryView, DataVariable, Endianness, MediumLevelILInstruction, Type
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Constant, GlobalVariable, OperationType, UnaryOperation, ImportedFunctionSymbol, Integer, Pointer, StringSymbol, Symbol
from binaryninja.types import (
    ArrayType,
    BoolType,
    CharType,
    FloatType,
    FunctionType,
    IntegerType,
    PointerType,
    VoidType,
)


class GlobalHandler(Handler):
    """Handle for global variables."""

    # Dict translating endianness between the binaryninja enum and pythons literals
    Endian = {Endianness.LittleEndian: "little", Endianness.BigEndian: "big"}

    def __init__(self, lifter):
        super().__init__(lifter)
        self._datavariable_types = {
            CharType: self._lift_basic_type,
            IntegerType: self._lift_basic_type,
            FloatType: self._lift_basic_type,
            BoolType: self._lift_basic_type,
            VoidType: self._lift_void_type,
            ArrayType: self._lift_constant_type,
            PointerType: self._lift_pointer_type,
        }

    def register(self):
        """Register the handler at its parent lifter."""
        self._lifter.HANDLERS.update({DataVariable: self.lift_global_variable})

    def lift_global_variable(self, variable: DataVariable, view: BinaryView, 
        parent: Optional[MediumLevelILInstruction] = None, caller_addr: int = 0, **kwargs
    ) -> UnaryOperation:
        """Lift global variables with basic types (pointer are possible)"""
        if not self._addr_in_section(view, variable.address):
            return Constant(variable.address, vartype=Integer(view.address_size*8, False))

        if caller_addr == variable.address:
            return self._lifter.lift(variable.symbol) if variable.symbol else \
            Symbol("data_" + f"{variable.address:x}", variable.address, vartype=Integer.uint32_t())

        return self._datavariable_types[type(variable.type)](variable, view, parent)


    def _lift_constant_type(self, variable: DataVariable, view: BinaryView, parent: Optional[MediumLevelILInstruction] = None):
        """Lift a constant datavariable directly into code (mostly strings)"""
        return StringSymbol(str(variable.value)[2:-1].rstrip("\\x00"), variable.address, vartype=Pointer(Integer.char(), view.address_size * 8))

    
    def _lift_pointer_type(self, variable: DataVariable, view: BinaryView, parent: Optional[MediumLevelILInstruction] = None):
        """Lift a pointer as an Functionpointer, if the value is an FunctionType, otherwise as basic type"""
        if isinstance(variable.type.target, FunctionType):
            return ImportedFunctionSymbol(variable.name, variable.address, vartype=Pointer(Integer.char(), view.address_size * 8))
        if isinstance(variable.type.target, VoidType):
            init_value, type = self._get_unknown_value(variable.value, view)
        else:
            init_value, type = self._lifter.lift(view.get_data_var_at(variable.value), view=view, caller_addr=variable.address), self._lifter.lift(variable.type)
        return UnaryOperation(
        OperationType.address,
            [
                GlobalVariable(
                name=self._lifter.lift(variable.symbol).name if variable.symbol else "data_" + f"{variable.address:x}",
                vartype=self._lifter.lift(type),
                ssa_label=parent.ssa_memory_version if parent else 0,
                initial_value=init_value
                )
            ],
        )


    def _lift_basic_type(self, variable: DataVariable, view: BinaryView, parent: Optional[MediumLevelILInstruction] = None):
        """Lift basic type"""
        if isinstance(variable.type, VoidType):
            value, type = self._get_unknown_value(variable.address, view)
        else: 
            value, type = Constant(variable.value), variable.type,
        return UnaryOperation(
            OperationType.address,
                [
                    GlobalVariable(
                    name=self._lifter.lift(variable.symbol).name if variable.symbol else "data_" + f"{variable.address:x}",
                    vartype=self._lifter.lift(type),
                    ssa_label=parent.ssa_memory_version if parent else 0,
                    initial_value=value
                )
            ],
        )

    def _lift_void_type(self, variable: DataVariable, view: BinaryView, parent: Optional[MediumLevelILInstruction] = None):
        value, type = self._get_unknown_value(variable.address, view)
        return GlobalVariable(
                    name=self._lifter.lift(variable.symbol).name if variable.symbol else "data_" + f"{variable.address:x}",
                    vartype=self._lifter.lift(type),
                    ssa_label=parent.ssa_memory_version if parent else 0,
                    initial_value=value
                )

    def _get_unknown_value(self, addr: int, view: BinaryView):
        """Return initial value of a unknown address"""
        if datavariable := view.get_data_var_at(addr):
            return self._lifter.lift(datavariable, view=view, caller_addr=addr), datavariable.type
        elif (data := self._get_different_string_types_at(addr, view)) and data[0] != "":
            return data[0], Type.pointer(view.arch, data[1])
        else:
            return self._get_raw_bytes(addr, view), Type.pointer(view.arch, Type.void())
            

    def _get_raw_bytes(self, addr: int, view: BinaryView) -> bytes:
        """ Returns raw bytes after a given address to the next data structure or section"""
        if (next_data_var := view.get_next_data_var_after(addr)) is not None:
            return view.read(addr, next_data_var.address - addr)
        else:
            return view.read(addr, view.get_sections_at(addr)[0].end)


    def _get_different_string_types_at(self, addr: int, view: BinaryView) -> Tuple[str, Type]:
        """Tries to extract different string types at addr."""
        types = [Type.char(), Type.wide_char(2), Type.wide_char(4)]
        string = ""
        for type in types:
            string = self._get_string_at(view, addr, type)
            if string != "":
                break
        # show w_chat id (L"..")
        return string, Type.char()

    def _get_string_at(self, view: BinaryView, addr: int, type: Type) -> str:
        """Read string with specified width from location."""
        data_var = DataVariable(view, addr, Type.array(type, self._get_size_of_data_var(view, addr, type.width)), False)
        try:
            string:str = data_var.value.decode("ascii")
        except:
            return ""
        if not string.isprintable() or len(string) == 0:
            return ""
        return '"' + string + '"'

    def _get_size_of_data_var(self, view: BinaryView, addr: int, width: int):
        """Returns the size of variable """
        size = 0
        match width:
            case 1:
                read = view.reader(addr).read8
            case 2:
                read = view.reader(addr).read16
            case 4:
                read = view.reader(addr).read32
            case _:
                raise ValueError("Width not supported for reading raw bytes")

        while read() != 0x00:
            size += 1
        
        return size


    def _addr_in_section(self, view: BinaryView, addr: int) -> bool:
        """Returns True if address is contained in a section, False otherwise"""
        for _, section in view.sections.items():
            if addr >= section.start and addr <= section.end:
                return True
        return False
 