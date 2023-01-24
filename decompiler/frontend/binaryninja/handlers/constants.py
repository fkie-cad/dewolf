"""Module implementing the ConstantHandler for the binaryninja frontend."""
import logging
from typing import List, Optional, Union

from binaryninja import BinaryView
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
    def register(self):
        """Register the handler at its parent lifter."""
        self._lifter.HANDLERS.update(
            {
                mediumlevelil.MediumLevelILConst: self.lift_constant,
                mediumlevelil.MediumLevelILFloatConst: self.lift_constant,
                mediumlevelil.MediumLevelILExternPtr: self.lift_constant_pointer,
                mediumlevelil.MediumLevelILConstPtr: self.lift_constant_pointer,
                mediumlevelil.MediumLevelILImport: self.lift_constant_pointer,
                int: self.lift_literal,
            }
        )

    def lift_constant(self, constant: mediumlevelil.MediumLevelILConst, **kwargs) -> Constant:
        """Lift the given constant value."""
        return Constant(constant.constant, vartype=self._lifter.lift(constant.expr_type))

    def lift_literal(self, value: int, **kwargs) -> Constant:
        """Lift the given literal, which is most likely an artefact from shift operations and the like."""
        return Constant(value, vartype=Integer.int32_t())

    def lift_constant_pointer(self, pointer: mediumlevelil.MediumLevelILConstPtr, **kwargs) -> Union[Constant, Symbol, UnaryOperation]:
        bv = pointer.function.source_function.view
        address = pointer.constant

        if address == 0:
            # TODO: hack - Binja thinks that 0 is a null pointer, even though it may be just integer 0.
            return Constant(0, vartype=Integer.uint64_t() if bv.address_size == 8 else Integer.uint32_t())

        symbol = self._get_symbol(bv, address)

        if symbol is not None and symbol.type in (
            SymbolType.ImportedFunctionSymbol,
            SymbolType.ExternalSymbol,
            SymbolType.FunctionSymbol,
            SymbolType.ImportAddressSymbol,
        ):
            retval = self._lift_symbol_pointer(bv, address, symbol)
            if retval is None:
                logging.error(f"lifted symbol ptr to None {address=} {symbol=}")
                raise ValueError("lifted to None")
            return retval

        if (
            not isinstance(pointer, mediumlevelil.MediumLevelILImport)
            and (symbol is None or symbol.type != SymbolType.DataSymbol)
            and (string := bv.get_string_at(address, partial=True) or bv.get_ascii_string_at(address, min_length=2))
        ):
            return Constant(address, Pointer(Integer.char()), Constant(string.value, Integer.char()))

        if (variable := bv.get_data_var_at(address)) is not None:
            return self._lifter.lift(variable, bv=bv, parent_addr=None)
        raise ValueError("Lift pointer to None")
        #return Constant(address, Pointer(Integer(pointer.size * 8))) # TODO maybe?

    def _lift_symbol_pointer(self, bv: BinaryView, address: int, symbol: bSymbol) -> Optional[Union[Symbol, UnaryOperation]]:
        """Try to lift a pointer at the given address with a Symbol as a symbol pointer."""
        # symbol containing custom function name, e.g. lookup
        if symbol.type == SymbolType.FunctionSymbol:
            return FunctionSymbol(symbol.name, address, vartype=Pointer(Integer.char()))
        # symbol containing c function name, Win API name (tailcall), etc. e.g. memset
        if symbol.type in (SymbolType.ImportedFunctionSymbol, SymbolType.ExternalSymbol):
            return ImportedFunctionSymbol(symbol.name, address, vartype=Pointer(Integer.char()))
        # IAT entry or .got entry
        if symbol.type == SymbolType.ImportAddressSymbol:
            # if it is .got entry, then it points at the external global variable or function
            # so we try to get the symbol on that address, lift it and lift .got entry as an address of that (lifted) symbol
            pointer_value = bv.read_pointer(symbol.address)
            global_data_pointed_by_symbol = bv.get_data_var_at(pointer_value)
            if global_data_pointed_by_symbol:
                lifted_global_var = self._lifter.lift(global_data_pointed_by_symbol, bv=bv, parent_addr=symbol.address)
                return UnaryOperation(OperationType.address, [lifted_global_var])
            else:
                # otherwise it is an IAT entry -> construct ImportedFunctionSymbol with the same name.
                return ImportedFunctionSymbol(symbol.name, symbol.address, vartype=Pointer(Integer.char()))

    @staticmethod
    def _get_symbol(bv: BinaryView, address: int) -> Optional[bSymbol]:
        """Retrieve the symbol at the given location, if any."""
        if symbol := bv.get_symbol_at(address):
            return symbol
        elif function := bv.get_function_at(address):
            return function.symbol
        return None
