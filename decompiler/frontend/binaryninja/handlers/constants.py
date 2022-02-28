"""Module implementing the ConstantHandler for the binaryninja frontend."""
from typing import List, Optional, Union

from binaryninja import BinaryView, DataVariable, Endianness
from binaryninja import Symbol as bSymbol
from binaryninja import SymbolType, TypeClass, mediumlevelil
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import (
    Constant,
    FunctionSymbol,
    GlobalVariable,
    ImportedFunctionSymbol,
    Integer,
    OperationType,
    Pointer,
    Symbol,
    Type,
    UnaryOperation,
)


class ConstantHandler(Handler):

    # Dict translating endianness between the binaryninja enum and pythons literals
    Endian = {Endianness.LittleEndian: "little", Endianness.BigEndian: "big"}

    def register(self):
        """Register the handler at its parent lifter."""
        self._lifter.HANDLERS.update(
            {
                mediumlevelil.MediumLevelILConst: self.lift_constant,
                mediumlevelil.MediumLevelILFloatConst: self.lift_constant,
                mediumlevelil.MediumLevelILExternPtr: self.lift_pointer,
                mediumlevelil.MediumLevelILConstPtr: self.lift_pointer,
                mediumlevelil.MediumLevelILImport: self.lift_pointer,
                int: self.lift_literal,
            }
        )

    def lift_constant(self, constant: mediumlevelil.MediumLevelILConst, **kwargs) -> Constant:
        """Lift the given constant value."""
        return Constant(constant.constant, vartype=self._lifter.lift(constant.expr_type))

    def lift_symbol(self, import_constant: mediumlevelil.MediumLevelILImport, **kwargs) -> ImportedFunctionSymbol:
        """Lift a symbol by returning its name."""
        symbol = self._get_symbol(import_constant.function.view, import_constant.constant)
        return ImportedFunctionSymbol(
            symbol.name.split("@")[0] if symbol.type == SymbolType.ImportAddressSymbol else symbol.name,
            import_constant.constant,
            Pointer(Integer.char()),
        )

    def lift_pointer(self, constant: mediumlevelil.MediumLevelILConstPtr, **kwargs) -> Constant:
        """Helper method translating a pointer to address and binary view."""
        return self._lift_bn_pointer(constant.constant, constant.function.source_function.view)

    def lift_literal(self, value: int, **kwargs) -> Constant:
        """Lift the given literal, which is most likely an artefact from shift operations and the like."""
        return Constant(value, vartype=Integer.int32_t())

    def _lift_bn_pointer(self, address: int, bv: BinaryView):
        """Lift the given binaryninja pointer object to a pseudo pointer."""
        if address == 0:
            # TODO: hack - Binja thinks that 0 is a null pointer, even though it may be just integer 0.
            return Constant(0, vartype=Integer.uint64_t() if bv.address_size == 8 else Integer.uint32_t())
        if symbol := self._get_symbol(bv, address):
            if symbol.type == SymbolType.FunctionSymbol:
                return FunctionSymbol(symbol.name, address, vartype=Pointer(Integer.char()))
            if symbol.type in (SymbolType.ImportedFunctionSymbol, SymbolType.ExternalSymbol):
                return ImportedFunctionSymbol(symbol.name, address, vartype=Pointer(Integer.char()))
            return self._lift_global_variable(bv, None, address)

        if string := bv.get_string_at(address, partial=True) or bv.get_ascii_string_at(address, min_length=2):
            return Constant(address, Pointer(Integer.char()), Constant(string.value, Integer.char()))

        return self._lift_constant(instruction)

    def _lift_symbol_pointer(self, address: int, symbol: bSymbol) -> Optional[Symbol]:
        """Try to lift a pointer at the given address with a Symbol as a symbol pointer."""
        if symbol.type == SymbolType.FunctionSymbol:
            return FunctionSymbol(symbol.name, address, vartype=Pointer(Integer.char()))
        if symbol.type in (SymbolType.ImportedFunctionSymbol, SymbolType.ExternalSymbol):
            return ImportedFunctionSymbol(symbol.name, address, vartype=Pointer(Integer.char()))

    def _lift_global_variable(self, bv: BinaryView, parent_addr: int, addr: int) -> Union[Constant, GlobalVariable, Symbol, UnaryOperation]:
        """Lift a global variable."""
        if (variable := bv.get_data_var_at(addr)) is None:
            return self._lift_no_data_var(bv, addr)

        variable_name = self._get_global_var_name(bv, addr)
        vartype = self._lifter.lift(variable.type)
        if "jump_table" in variable_name:
            return self._lift_jump_table(bv, variable_name, vartype, addr)

        if parent_addr == addr:
            return self._lift_recursion_pointer(variable_name, vartype, addr)

        # Retrieve the initial value of the global variable if there is any
        type_tokens = [t.text for t in variable.type.tokens]
        initial_value = self._get_initial_value(bv, variable, addr, type_tokens)

        # Create the global variable.
        # Convert all void and void* to char* for the C compiler.
        if "void" in type_tokens:
            vartype = self._lifter.lift(bv.parse_type_string("char*")[0])
        return UnaryOperation(
            OperationType.address,
            [GlobalVariable(variable_name, vartype=vartype, ssa_label=0, initial_value=initial_value)],
            vartype=Pointer(vartype),
        )

    def _lift_no_data_var(self, bv: BinaryView, addr: int) -> Union[Constant, Symbol]:
        """Lift a string or bytes when bv.get_data_var(addr) is None."""
        if string := bv.get_string_at(addr):
            return Constant(addr, Pointer(Integer.char()), Constant(string.value, Integer.char()))
        # TODO: hack - Binja thinks that 0 is a null pointer, even though it may be just integer 0. Thus we lift this as a NULL Symbol
        if self._get_pointer(bv, addr) == 0:
            return Symbol("NULL", 0)
        # return as raw bytes for now.
        return Constant(addr, Pointer(Integer.char()), Constant(self._get_bytes(bv, addr), Integer.char()))

    def _lift_jump_table(self, bv: BinaryView, variable_name: str, vartype: Type, addr: int) -> UnaryOperation:
        """Lift a jump table."""
        # TODO: hack - otherwise the whole jumptable is set as initial_value
        return UnaryOperation(
            OperationType.address,
            [GlobalVariable(variable_name, ssa_label=0, vartype=vartype, initial_value=addr)],
            vartype=Pointer(vartype),
        )

    def _lift_recursion_pointer(self, variable_name: str, vartype: Type, addr: int) -> GlobalVariable:
        """Lift a recursion pointer."""
        # We have cases like:
        # void* __dso_handle = __dso_handle
        # Prevent unlimited recursion and return the pointer.
        vartype = Integer.uint64_t() if bv.address_size == 8 else Integer.uint32_t()
        return GlobalVariable(variable_name, vartype=vartype, ssa_label=0, initial_value=addr)

    def _get_initial_value(self, bv: BinaryView, variable: DataVariable, addr: int, type_tokens: List[str]) -> Union[str, int, bytes]:
        """Retrieve the initial value of the global variable if there is any."""
        initial_value = None
        if variable.type == variable.type.void():
            # If there is no type, just retrieve all the bytes from the current to the next address where a data variable is present.
            initial_value = self._get_bytes(bv, addr)
        elif variable.type.type_class == TypeClass.IntegerTypeClass:
            initial_value = self._get_integer(bv, addr, variable.type.width)
        else:
            # If pointer type, convert indirect_pointer to a label, otherwise leave it as it is.
            if "*" in type_tokens:
                indirect_ptr_addr = self._get_pointer(bv, addr)
                initial_value = self._lift_global_variable(bv, addr, indirect_ptr_addr)
            else:
                initial_value = bv.read(addr, variable.type.width)
        return initial_value

    @staticmethod
    def _get_symbol(bv: BinaryView, address: int) -> Optional[bSymbol]:
        """Retrieve the symbol at the given location, if any."""
        if symbol := bv.get_symbol_at(address):
            return symbol
        elif function := bv.get_function_at(address):
            return function.symbol
        return None

    def _get_global_var_name(self, bv: BinaryView, addr: int) -> str:
        """Get a name for the GlobalVariable."""
        if (symbol := bv.get_symbol_at(addr)) is not None:
            # If there is an existing symbol, use it as the name
            # Replace characters in the name with equivalents to conform to C's variable naming convention.
            name = symbol.name.replace(".", "_")
            if symbol.type == SymbolType.ImportAddressSymbol:
                # In Binja, ImportAddressSymbol will always reference a DataSymbol of the same name
                # To prevent name conflicts, we add a _1 to the name to make it a different variable.
                name += "_1"
            return name
        return f"data_{addr:x}"

    def _get_bytes(self, bv: BinaryView, addr: int) -> bytes:
        """Given an address, retrive all bytes from the current data point to the next data point."""
        next_data_var_addr = None
        next_data_var = bv.get_next_data_var_after(addr)
        if next_data_var is not None:
            next_data_var_addr = next_data_var.address
        # No data point after this, so read till the end of this section instead.
        else:
            next_data_var_addr = bv.get_sections_at(addr)[0].end
        num_bytes = next_data_var_addr - addr
        return bv.read(addr, num_bytes)

    def _get_pointer(self, bv: BinaryView, addr: int) -> int:
        """Retrieve and convert a value at an address from bytes to an integer."""
        raw_value = bv.read(addr, bv.arch.address_size)
        return int.from_bytes(raw_value, ConstantHandler.Endian[bv.endianness])

    def _get_integer(self, bv: BinaryView, addr: int, size: int) -> int:
        """Retrieve and convert a value at an address from bytes to an integer specified size."""
        raw_value = bv.read(addr, size)
        return int.from_bytes(raw_value, ConstantHandler.Endian[bv.endianness])
