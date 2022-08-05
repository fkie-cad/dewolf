"""Module implementing the ConstantHandler for the binaryninja frontend."""
from typing import List, Union

from binaryninja import BinaryView, DataVariable, Endianness, SymbolType, TypeClass
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Constant, GlobalVariable, Integer, OperationType, Pointer, Symbol, Type, UnaryOperation


class GlobalHandler(Handler):
    """Handle for global variables."""

    # Dict translating endianness between the binaryninja enum and pythons literals
    Endian = {Endianness.LittleEndian: "little", Endianness.BigEndian: "big"}

    def register(self):
        """Register the handler at its parent lifter."""
        self._lifter.HANDLERS.update({DataVariable: self.lift_global_variable})

    def lift_global_variable(self, variable: DataVariable, **kwargs) -> Union[UnaryOperation, GlobalVariable]:
        """Lift a global variable.
        kwargs should contain 2 keys:
        parent_addr: an address in int if this is a recursive pointer, None otherwise.
        bv: BinaryNinja BinaryView object."""
        bv = kwargs["bv"]
        parent_addr = kwargs["parent_addr"]
        addr = variable.address

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
        # since store(global) -- *(global) -- is used by Binja to access a global variable's value, we lift
        # int... VAR as &VAR  -> *(&VAR) -> VAR in the decompiled code
        # void... VAR as VAR  -> *(VAR) will actually access the data the global variable points to
        # Convert all void and void* to char* for the C compiler.
        if "void" in type_tokens and "*" not in type_tokens:
            vartype = self._lifter.lift(bv.parse_type_string("char*")[0])
            return GlobalVariable(variable_name, vartype=vartype, ssa_label=0, initial_value=initial_value)
        else:
            if "void" in type_tokens and "*" in type_tokens:
                vartype = self._lifter.lift(bv.parse_type_string("char*")[0])
            else:
                vartype = self._lifter.lift(variable.type)
            return UnaryOperation(
                OperationType.address,
                [GlobalVariable(variable_name, vartype=vartype, ssa_label=0, initial_value=initial_value)],
                vartype=Pointer(vartype),
            )

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
        if variable.type == variable.type.void():
            # If there is no type, just retrieve all the bytes from the current to the next address where a data variable is present.
            return self._get_bytes(bv, addr)
        elif variable.type.type_class == TypeClass.IntegerTypeClass:
            return self._get_value(bv, addr, variable.type.width)
        else:
            # If pointer type, convert indirect_pointer to a label, otherwise leave it as it is.
            if "*" in type_tokens:
                indirect_ptr_addr = self._get_value(bv, addr, bv.arch.address_size)
                if (var2 := bv.get_data_var_at(indirect_ptr_addr)) is not None:
                    return self.lift_global_variable(var2, bv=bv, parent_addr=addr)
                else:
                    return self._lift_no_data_var(bv, indirect_ptr_addr)
            else:
                return bv.read(addr, variable.type.width)
        return None

    def _lift_no_data_var(self, bv: BinaryView, addr: int) -> Union[Constant, Symbol]:
        """Lift a string or bytes when bv.get_data_var(addr) is None."""
        if string := bv.get_string_at(addr):
            return Constant(addr, Pointer(Integer.char()), Constant(string.value, Integer.char()))
        # TODO: hack - Binja thinks that 0 is a null pointer, even though it may be just integer 0. Thus we lift this as a NULL Symbol
        if self._get_value(bv, addr, bv.arch.address_size) == 0:
            return Symbol("NULL", 0)
        # return as raw bytes for now.
        return Constant(addr, Pointer(Integer.char()), Constant(self._get_bytes(bv, addr), Integer.char()))

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

    def _get_value(self, bv: BinaryView, addr: int, size: int) -> int:
        """Retrieve and convert a value at an address from bytes to an integer specified size."""
        raw_value = bv.read(addr, size)
        return int.from_bytes(raw_value, GlobalHandler.Endian[bv.endianness])

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
