"""Module implementing the ConstantHandler for the binaryninja frontend."""

from typing import Callable, Optional, Tuple, Union

from binaryninja import BinaryView, DataVariable, Endianness, MediumLevelILInstruction, SectionSemantics, Type
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
from decompiler.structures.pseudo import ArrayType as Array
from decompiler.structures.pseudo import (
    Constant,
    ConstantComposition,
    CustomType,
    Expression,
    GlobalVariable,
    ImportedFunctionSymbol,
    Integer,
    OperationType,
    Pointer,
    Symbol,
    UnaryOperation,
)

"""
    Lift a given address inside of a binary by BNinjas DataVariable type.
    If some code references a address, bninja stores the information about the address inside of a DataVariable (dv).
    A dv has a type (which may be wrong/or set by a user) and a value (which can be anything).

    We lift according to the type (bninjas) of the dv:
        - CharType, FloatType, IntegerType, BoolType
            - basic C types (char, int, float, ...)
            => just lift as the given type
            ==> Addition since Version 4.0: Check if variable references something, if yes, try to lift as pointer
        - VoidType
            - when bninja does not know the size of a variable (e.g. int array) it represents it as a void dv
            => C does not have a concept of void
            => lift as a void* with raw escaped bytes as value (still not C conformant, but better)
            ==> if we create a pointer, the caller (instruction) must remove the '&' operator
        - ArrayType
            - Strings (char [], wchar_16[], ...)
            => Lift as given type (array)
            => BNinja changes the .value field frequently and is not consistent (any; mostly bytes, list or string)
        - PointerType
            - pointer to something (basic type, void*, function pointer)
            => If the pointer points to some basic type, there _should_ be a dv at the value address 
            ==> trust bninja lift normally
            => If a void*, then we try determine the value via get_unknown_pointer_value
        - NamedTypeReferenceType
            - enum/structs
            => not supported currently
            => has a BNinja bug when accessing certain PDB enum types

    MISC:
        - ._callers will be empty for each call of lift_global_variable 
        except when an caller calls the lifter with kwargs = {callers = [..]}
        => get_unknown_value does exactly this to keep track of all callers for a chain of global variables
        (The call stack will be lifter.lift, lift_global_variable, lifter.lift, lift_global_variable, ...)
"""


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
            ArrayType: self._lift_array_type,
            PointerType: self._lift_pointer_type,
            NamedTypeReferenceType: self._lift_named_type_ref,
        }
        self._lifted_globals: dict[int, GlobalVariable] = {}
        self._view: Optional[BinaryView] = None
        self._callers: list[int] = []

    def register(self):
        """Register the handler at its parent lifter."""
        self._lifter.HANDLERS.update({DataVariable: self.lift_global_variable})

    def _get_gvar_name(self, bninjaName: Optional[str], addr: int) -> str:
        lifted_names = [v.name for v in self._lifted_globals.values()]
        if bninjaName is None:
            return GLOBAL_VARIABLE_PREFIX + f"{addr:x}"
        if bninjaName in lifted_names:
            return bninjaName + "_" + f"{addr:x}"  # @Reviewer: Other ideas for distinct name?
        return bninjaName

    def _build_global_variable(self, name: Optional[str], type: Type, addr: int, init_value, ssa_label: Optional[int]) -> GlobalVariable:
        vname = self._get_gvar_name(name, addr)

        match init_value:
            case Expression():
                vinit_value = init_value
            case int() | float() | bytes():
                vinit_value = Constant(value=init_value, vartype=type)
            case _:
                raise TypeError(f"Type violation: '{init_value}'")

        self._lifted_globals[addr] = GlobalVariable(
            name=vname, vartype=type, initial_value=vinit_value, ssa_label=ssa_label, is_constant=self.addr_in_ro_section(self._view, addr)
        )
        return self._lifted_globals[addr]

    def lift_global_variable(
        self, variable: DataVariable, view: BinaryView, parent: Optional[MediumLevelILInstruction] = None, callers: list[int] = [], **kwargs
    ) -> Union[Constant, Symbol, GlobalVariable]:
        """Lift global variables via datavariable type"""
        # Save view for all internal used functions
        if not self._view:
            self._view = view

        # Safe list of callers before
        self._callers = callers

        # If addr was already lifted: Return lifted GlobalVariable with updated SSA
        if variable.address in self._lifted_globals.keys():
            return (
                self._lifted_globals[variable.address].copy(ssa_label=parent.ssa_memory_version)
                if parent
                else self._lifted_globals[variable.address]
            )

        # BNinja error cases: nullptr/small numbers (0, -12...)
        if not self.addr_in_section(view, variable.address):
            return Constant(variable.address, vartype=Integer(view.address_size * BYTE_SIZE, False))

        # Check if there is a cycle between GlobalVariables initial_value
        if variable.address in self._callers:
            return (
                self._lifter.lift(variable.symbol)
                if variable.symbol
                else Symbol(GLOBAL_VARIABLE_PREFIX + f"{variable.address:x}", variable.address, vartype=Integer.uint32_t())
            )

        return self._lift_datavariable_by_type[type(variable.type)](variable, parent)

    def _lift_array_type(self, variable: DataVariable, parent: Optional[MediumLevelILInstruction] = None) -> GlobalVariable:
        """Lift constant data type (strings and jump tables) into code"""
        type = self._lifter.lift(variable.type)
        match variable.value:
            case bytes():  # BNinja corner case: C-Strings (8Bit) are represented as python Bytes
                value = [Constant(x, type.type) for x in str(variable.value.rstrip(b"\x00"))[2:-1]]
            case _:
                value = [Constant(x, type.type) for x in variable.value]

        return self._build_global_variable(
            name=variable.name,
            type=type,
            addr=variable.address,
            init_value=ConstantComposition(value, type),
            ssa_label=parent.ssa_memory_version if parent else 0,
        )

    def _lift_basic_type(self, variable: DataVariable, parent: Optional[MediumLevelILInstruction] = None) -> GlobalVariable:
        """Lift basic C type found by BNinja (int, float, char, ...)"""
        # If variable references something in address space, then lift it as a pointer (BNinja 4.0 "Error")
        if [x for x in variable.data_refs_from]:
            return self._lifter.lift(
                DataVariable(self._view, variable.address, Type.pointer(self._view, Type.void()), False), view=self._view, parent=parent
            )

        type = self._lifter.lift(variable.type)
        return self._build_global_variable(
            name=self._lifter.lift(variable.symbol).name if variable.symbol else None,
            type=type,
            addr=variable.address,
            init_value=Constant(variable.value, type),
            ssa_label=parent.ssa_memory_version if parent else 0,
        )

    def _lift_void_type(self, variable: DataVariable, parent: Optional[MediumLevelILInstruction] = None) -> GlobalVariable:
        "Lift unknown type, by checking the value at the given address. Will always be lifted as a pointer. Try to extract datavariable, string or bytes as value"
        value, type = self.get_unknown_value(variable, self._view)
        return self._build_global_variable(
            name=self._lifter.lift(variable.symbol).name if variable.symbol else None,
            type=type,
            addr=variable.address,
            init_value=value,
            ssa_label=parent.ssa_memory_version if parent else 0,
        )

    def _lift_pointer_type(
        self, variable: DataVariable, parent: Optional[MediumLevelILInstruction] = None
    ) -> Union[GlobalVariable, Symbol]:
        """Lift pointer as:
        1. Function pointer: If Bninja already knows it's a function pointer.
        2. Type pointer: As normal type pointer (there _should_ be a datavariable at the pointers dest.)
        3. Void pointer: Try to extract a datavariable (recover type of void* directly), string (char*) or raw bytes (void*) at the given address
        """
        match variable.type.target:
            case FunctionType():  # BNinja knows it's a imported function pointer
                return ImportedFunctionSymbol(
                    variable.name, variable.address, vartype=Pointer(Integer.char(), self._view.address_size * BYTE_SIZE)
                )
            case VoidType():  # BNinja knows it's a pointer pointing at something
                # Extract the initial_value and type from the location where the pointer is pointing to
                init_value, type = self.get_unknown_pointer_value(variable, self._view)
            case _:
                self._callers.append(variable.address)
                init_value, type = (
                    self._lifter.lift(self._view.get_data_var_at(variable.value), view=self._view, callers=self._callers),
                    self._lifter.lift(variable.type),
                )
        return self._build_global_variable(
            name=self._lifter.lift(variable.symbol).name if variable.symbol else None,
            type=type,
            addr=variable.address,
            init_value=init_value,
            ssa_label=parent.ssa_memory_version if parent else 0,
        )

    def _lift_named_type_ref(self, variable: DataVariable, parent: Optional[MediumLevelILInstruction] = None):
        """Lift a named custom type (Enum, Structs)"""
        return Constant(
            "Unknown value", self._lifter.lift(variable.type)
        )  # BNinja error, need to check with the issue to get the correct value + entry for structs

    def get_unknown_value(self, dv: DataVariable, view: BinaryView):
        """Return string or bytes at dv.address(!) (dv.type must be void)"""
        if (data := self._get_different_string_types_at(dv.address, view)) and data[0] is not None:
            type = Array(self._lifter.lift(data[1]), len(data[0]))
            data = ConstantComposition([Constant(x, type.type) for x in data[0]], type)
        else:
            data, type = self.get_raw_bytes(dv.address, view), Pointer(CustomType.void())
        return data, type

    def get_unknown_pointer_value(self, dv: DataVariable, view: BinaryView):
        """Return symbol, datavariable, address, string or raw bytes for a value of a datavariable(!) (dv should be a pointer)."""
        if not self.addr_in_section(view, dv.value):
            return dv.value, Pointer(CustomType.void())

        if datavariable := view.get_data_var_at(dv.value):
            self._callers.append(dv.address)
            type = self._lifter.lift(datavariable.type)
            value = self._lifter.lift(datavariable, view=view, callers=self._callers)
            if not isinstance(type, (Pointer, Array)):
                type = Pointer(type, self._view.address_size * BYTE_SIZE)
            value = UnaryOperation(
                OperationType.address,
                [value],
                vartype=value.type,
            )
            return value, type

        if (data := self._get_different_string_types_at(dv.value, view)) and data[
            0
        ] is not None:  # Implicit pointer removal if called from a pointer value, does NOT need to be a UnaryOperation
            vtype = Array(self._lifter.lift(data[1]), len(data[0]))
            vdata = ConstantComposition([Constant(x, vtype.type) for x in data[0]], vtype)
            data = self._build_global_variable(None, vtype, dv.value, vdata, None)
            type = Pointer(vtype, self._view.address_size * BYTE_SIZE)
            return (
                UnaryOperation(
                    OperationType.address,
                    [data],
                    vartype=data.type,
                ),
                type,
            )
        else:
            data, type = self.get_raw_bytes(dv.value, view), Pointer(CustomType.void())
        return data, type

    def get_raw_bytes(self, addr: int, view: BinaryView) -> bytes:
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

    def addr_in_section(self, view: BinaryView, addr: int) -> bool:
        """Returns True if address is contained in a section, False otherwise"""
        for _, section in view.sections.items():
            if addr >= section.start and addr <= section.end:
                return True
        return False

    def addr_in_ro_section(self, view: BinaryView, addr: int) -> bool:
        """Returns True if address is contained in a read only section, False otherwise"""
        for _, section in view.sections.items():
            if addr >= section.start and addr <= section.end and section.semantics == SectionSemantics.ReadOnlyDataSectionSemantics:
                return True
        return False
