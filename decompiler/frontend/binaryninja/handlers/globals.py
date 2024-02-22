"""Module implementing the ConstantHandler for the binaryninja frontend."""

from typing import Callable, Optional, Tuple, Union

from binaryninja import BinaryView, DataVariable, Endianness, MediumLevelILInstruction, Type, SectionSemantics
from binaryninja.types import (
    ArrayType,
    BoolType,
    CharType,
    FloatType,
    FunctionType,
    IntegerType,
    NamedTypeReferenceType,
    PointerType,
    Type,
    VoidType,
)
from decompiler.frontend.binaryninja.handlers.constants import BYTE_SIZE
from decompiler.frontend.binaryninja.handlers.symbols import GLOBAL_VARIABLE_PREFIX
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import (
    Constant,
    GlobalVariable,
    ImportedFunctionSymbol,
    Integer,
    OperationType,
    Pointer,
    Symbol,
    UnaryOperation,
)


class GlobalHandler(Handler):
    """Handler for global variables."""

    # Dict translating endianness between the binaryninja enum and pythons literals
    Endian = {Endianness.LittleEndian: "little", Endianness.BigEndian: "big"}

    def __init__(self, lifter):
        super().__init__(lifter)
        self._lift_datavariable_by_type: dict[Type, Callable] = {
            CharType: self._lift_basic_type,
            IntegerType: self._lift_basic_type,
            FloatType: self._lift_basic_type,
            BoolType: self._lift_basic_type,
            VoidType: self._lift_void_type,
            ArrayType: self._lift_constant_type,
            PointerType: self._lift_pointer_type,
            NamedTypeReferenceType: self._lift_named_type_ref,
        }

    def register(self):
        """Register the handler at its parent lifter."""
        self._lifter.HANDLERS.update({DataVariable: self.lift_global_variable})

    def lift_global_variable(
        self, variable: DataVariable, view: BinaryView, parent: Optional[MediumLevelILInstruction] = None, caller_addr: int = None, **kwargs
    ) -> Union[Symbol, UnaryOperation, GlobalVariable]:
        """Lift global variables via datavariable type"""
        if not self._addr_in_section(view, variable.address): # BNinja error case: nullptr/small numbers 
            return Constant(variable.address, vartype=Integer(view.address_size * BYTE_SIZE, False))

        if caller_addr == variable.address: # recursive ptr check (depth 1)
            return (
                self._lifter.lift(variable.symbol)
                if variable.symbol
                else Symbol(GLOBAL_VARIABLE_PREFIX + f"{variable.address:x}", variable.address, vartype=Integer.uint32_t())
            )

        return self._lift_datavariable_by_type[type(variable.type)](variable, view, parent)

    def _lift_constant_type(
        self, variable: DataVariable, view: BinaryView, parent: Optional[MediumLevelILInstruction] = None
    ) -> GlobalVariable:
        """Lift constant data type (strings and jump tables) into code"""
        # TODO: Benötigt ArrayType um eine jump table darzustellen => Gibt kein Konzept dafür im Decompiler
        type = Pointer(Integer.char(), view.address_size * BYTE_SIZE)
        return GlobalVariable(
            name=variable.name if variable.name else GLOBAL_VARIABLE_PREFIX + f"{variable.address:x}",
            vartype=type,
            ssa_label=parent.ssa_memory_version if parent else 0,
            initial_value=Constant(value=str(variable.value.rstrip(b"\x00"))[2:-1], vartype=type),
            is_constant=self._addr_in_ro_section(view, variable.address)
        )

    def _lift_pointer_type(self, variable: DataVariable, view: BinaryView, parent: Optional[MediumLevelILInstruction] = None):
        """Lift pointer as:
        1. Function pointer: If bninja already knows it's a function pointer.
        2. Type pointer: As normal type pointer (there _should_ be a datavariable at the pointers dest.)
        3. Void pointer: Try to extract a datavariable (recover type of void* directly), string (char*) or raw bytes (void*) at the given address
        """
        if isinstance(variable.type.target, FunctionType):
            return ImportedFunctionSymbol(variable.name, variable.address, vartype=Pointer(Integer.char(), view.address_size * BYTE_SIZE))
        if isinstance(variable.type.target, VoidType):
            init_value, type = self._get_unknown_value(variable.value, view, variable.address)
            if not isinstance(type, PointerType):  # Fix type to be a pointer (happens when a datavariable is at the dest.)
                type = Type.pointer(view.arch, type)
            type = self._lifter.lift(type)
        else:
            init_value, type = (
                self._lifter.lift(view.get_data_var_at(variable.value), view=view, caller_addr=variable.address),
                self._lifter.lift(type),
            )
        return UnaryOperation(
            OperationType.address,
            [
                GlobalVariable(
                    name=self._lifter.lift(variable.symbol).name if variable.symbol else GLOBAL_VARIABLE_PREFIX + f"{variable.address:x}",
                    vartype=type,
                    ssa_label=parent.ssa_memory_version if parent else 0,
                    initial_value=Constant(value=init_value, vartype=type),
                    is_constant=self._addr_in_ro_section(view, variable.address)
                )
            ],
        )

    def _lift_basic_type(
        self, variable: DataVariable, view: BinaryView, parent: Optional[MediumLevelILInstruction] = None
    ) -> UnaryOperation:
        """Lift basic known type"""
        type = self._lifter.lift(variable.type)
        return UnaryOperation(
            OperationType.address,
            [
                GlobalVariable(
                    name=self._lifter.lift(variable.symbol).name if variable.symbol else GLOBAL_VARIABLE_PREFIX + f"{variable.address:x}",
                    vartype=type,
                    ssa_label=parent.ssa_memory_version if parent else 0,
                    initial_value=Constant(value=variable.value, vartype=type),
                    is_constant=self._addr_in_ro_section(view, variable.address)
                )
            ],
        )

    def _lift_void_type(
        self, variable: DataVariable, view: BinaryView, parent: Optional[MediumLevelILInstruction] = None
    ) -> GlobalVariable:
        "Lift unknown type, by checking the value at the given address. Will always be lifted as a pointer. Try to extract datavariable, string or bytes as value"
        value, type = self._get_unknown_value(variable.address, view, variable.address)
        type = self._lifter.lift(type)
        return GlobalVariable(
            name=self._lifter.lift(variable.symbol).name if variable.symbol else GLOBAL_VARIABLE_PREFIX + f"{variable.address:x}",
            vartype=type,
            ssa_label=parent.ssa_memory_version if parent else 0,
            initial_value=Constant(value=value, vartype=type),
            is_constant=self._addr_in_ro_section(view, variable.address)
        )

    def _lift_named_type_ref(
        self, variable: DataVariable, view: BinaryView, parent: Optional[MediumLevelILInstruction] = None
    ) -> GlobalVariable:
        """Lift a named custom type (Enum, Structs)"""
        return Constant(
            "Unknown value", self._lifter.lift(variable.type)
        )  # BNinja error, need to check with the issue to get the correct value

    def _get_unknown_value(self, addr: int, view: BinaryView, caller_addr: int = 0):
        """Return symbol, datavariable, address, string or raw bytes at given address."""
        if datavariable := view.get_data_var_at(addr):
            return self._lifter.lift(datavariable, view=view, caller_addr=caller_addr), datavariable.type 
        if not self._addr_in_section(view, addr):
            return addr, Type.pointer(view.arch, Type.void())
        if (data := self._get_different_string_types_at(addr, view)) and data[0] is not None:
            data, type = data[0], Type.pointer(view.arch, data[1])
        else:
            data, type = self._get_raw_bytes(addr, view), Type.pointer(view.arch, Type.void())
        return data, type

    def _get_raw_bytes(self, addr: int, view: BinaryView) -> bytes:
        """Returns raw bytes as hex string after a given address to the next data structure or section"""
        if (next_data_var := view.get_next_data_var_after(addr)) is not None:
            return view.read(addr, next_data_var.address - addr)
        return view.read(addr, view.get_sections_at(addr)[0].end)


    def _get_different_string_types_at(self, addr: int, view: BinaryView) -> Tuple[Optional[str], Type]:
        """Extract string with char/wchar16/wchar32 type if there is one"""
        types: list[Type] = [Type.char(), Type.wide_char(2), Type.wide_char(4)]
        for type in types:
            string = self._get_string_at(view, addr, type.width)
            if string != None:
                break
        return string, type

    def _get_string_at(self, view: BinaryView, addr: int, width: int) -> Optional[str]:
        """Read string with specified width from location. Explanation for the magic parsing:
        - we read 1, 2 or 4 long integers which should be interpreted as a byte in ASCII range (while Loop; can't use chr() for checking)
        - afterwards we convert bytes array manually to a string by removing the "bytearray(...)" parts from the string
        - this string now consists of readable chars (A, b), escaped hex values (\\x17) and control chars (\n, \t)
        - we consider a it a string, if it only consists of readable chars + control chars
        """
        raw_bytes = bytearray()
        match width:
            case 1:
                read = view.reader(addr).read8
            case 2:
                read = view.reader(addr).read16
            case 4:
                read = view.reader(addr).read32
            case _:
                raise ValueError("Width not supported for reading bytes")

        while (byte := read()) is not None and byte != 0x00:
            if byte > 127:
                return None
            raw_bytes.append(byte)

        string = str(raw_bytes)[12:-2]
        if len(string) < 2 or string.find("\\x") != -1:
            return None

        return string

    def _addr_in_section(self, view: BinaryView, addr: int) -> bool:
        """Returns True if address is contained in a section, False otherwise"""
        for _, section in view.sections.items():
            if addr >= section.start and addr <= section.end:
                return True
        return False

    def _addr_in_ro_section(self, view: BinaryView, addr: int) -> bool:
        """Returns True if address is contained in a read only section, False otherwise"""
        for _, section in view.sections.items():
            if addr >= section.start and addr <= section.end and section.semantics == SectionSemantics.ReadOnlyDataSectionSemantics:
                return True
        return False
