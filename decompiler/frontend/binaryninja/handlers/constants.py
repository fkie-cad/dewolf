from typing import Optional, Union

from binaryninja import mediumlevelil, BinaryView, Symbol as bSymbol, SymbolType, DataVariable, Endianness

from dewolf.frontend.lifter import Handler
from dewolf.structures.pseudo import Constant, Pointer, Integer, FunctionSymbol, ImportedFunctionSymbol, Symbol, UnaryOperation, GlobalVariable, OperationType, CustomType


class ConstantHandler(Handler):

    Endian = {
        Endianness.LittleEndian: "little",
        Endianness.BigEndian: "big"
    }

    def register(self):
        self._lifter.HANDLERS.update({
            mediumlevelil.MediumLevelILConst: self.lift_constant,
            mediumlevelil.MediumLevelILExtern_ptr: self.lift_pointer,
            mediumlevelil.MediumLevelILConst_ptr: self.lift_pointer,
            mediumlevelil.MediumLevelILImport: self.lift_symbol,
            int: self.lift_literal
        })

    def lift_constant(self, constant: mediumlevelil.MediumLevelILConst) -> Constant:
        """Lift the given constant value."""
        return Constant(constant.constant, vartype=self._lifter.lift(constant.expr_type))

    def lift_symbol(self, import_constant: mediumlevelil.MediumLevelILImport) -> ImportedFunctionSymbol:
        """Lift a symbol by returning its name."""
        symbol = self._get_symbol(import_constant)
        return ImportedFunctionSymbol(
            symbol.name.split("@")[0] if symbol.type == SymbolType.ImportAddressSymbol else symbol.name,
            import_constant.constant,
            Pointer(Integer.char())
        )

    def lift_pointer(self, constant: mediumlevelil.MediumLevelILConst_ptr) -> Constant:
        return self._lift_bn_pointer(constant.constant, constant.function.source_function.view)

    def lift_literal(self, value: int) -> Constant:
        return Constant(value, vartype=Integer.int32_t())

    def _lift_bn_pointer(self, address: int, bv: BinaryView):
        if symbol := self._get_symbol(bv, address):
            if symbol_pointer := self._lift_symbol_pointer(address, symbol):
                return symbol_pointer
            if variable := bv.get_data_var_at(address):
                return self._lift_global_variable(variable, symbol)
            return Symbol("NULL", 0)
        if isinstance(address, int) and (string := bv.get_string_at(address, partial=True)):
            return Constant(address, Pointer(Integer.char()), Constant(string.value, Integer.char()))
        return Constant(address, vartype=Pointer(CustomType.void()))

    def _lift_symbol_pointer(self, address: int, symbol: bSymbol) -> Optional[Symbol]:
        if symbol.type == SymbolType.FunctionSymbol:
            return FunctionSymbol(symbol.name, address, vartype=Pointer(Integer.char()))
        if symbol.type in (SymbolType.ImportedFunctionSymbol, SymbolType.ImportAddressSymbol, SymbolType.ExternalSymbol):
            return ImportedFunctionSymbol(symbol.name, address, vartype=Pointer(Integer.char()))

    def _lift_global_variable(self, variable: DataVariable, symbol: bSymbol) -> Union[Symbol, UnaryOperation]:
        """Lift a global variable"""
        if variable is None:
            # TODO: hack - Binja thinks that 0 is a null pointer, even though it may be just integer 0. Thus we lift this as a NULL Symbol
            return Symbol("NULL", 0)
        # TODO: hack - otherwise the whole jumptable is set as initial_value
        initial_value = symbol.address if "jump_table" in symbol.name else self._get_initial_value(variable)
        if "*" in variable.type.tokens:
            initial_value = self._lift_global_variable(int.from_bytes(initial_value, self.Endian[variable.view]), variable.view)
        return UnaryOperation(
            OperationType.address,
            [GlobalVariable(variable.name, vartype=self._lifter.lift(variable.type), ssa_label=0, initial_value=initial_value)],
            vartype=Pointer(self._lifter.lift(variable.type)),
        )

    def _get_initial_value(self, variable: DataVariable) -> Union[str, int]:
        # Retrieve the initial value of the global variable if there is any
        bv: BinaryView = variable.view
        if variable.type == variable.type.void():
            # If there is no type, just retrieve all the bytes from the current to the next address where a data variable is present.
            return bv.read(variable.address, bv.get_next_data_var_after(variable.address).address - variable.address)
        # Handle general case
        type_width = variable.type.width
        return bv.read(variable.address, type_width)

    @staticmethod
    def _get_symbol(bv: BinaryView, address: int) -> Optional[bSymbol]:
        if symbol := bv.get_symbol_at(address):
            return symbol
        elif function := bv.get_function_at(address):
            return function.symbol
        return None