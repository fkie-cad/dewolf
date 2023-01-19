"""Module implementing lifting of binaryninja symbols."""
from typing import Union
from logging import warning

from binaryninja import CoreSymbol
from binaryninja import Symbol as bSymbol
from binaryninja import SymbolType
from decompiler.frontend.lifter import Handler, ObserverLifter
from decompiler.structures.pseudo import Constant, FunctionSymbol, ImportedFunctionSymbol, Integer, Symbol, GlobalVariable


class SymbolHandler(Handler):
    """Handler for phi instructions emitted by binaryninja."""

    def __init__(self, lifter: ObserverLifter):
        super().__init__(lifter)
        self.SYMBOL_MAP = {
            SymbolType.FunctionSymbol: FunctionSymbol,
            SymbolType.ImportAddressSymbol: ImportedFunctionSymbol,
            SymbolType.ImportedFunctionSymbol: ImportedFunctionSymbol,
            SymbolType.DataSymbol: Symbol,
            SymbolType.ImportedDataSymbol: Symbol,
            SymbolType.ExternalSymbol: ImportedFunctionSymbol,
            SymbolType.LibraryFunctionSymbol: Symbol,
        }

    def register(self):
        """Register the handler at the parent lifter."""
        self._lifter.HANDLERS.update(
            {
                CoreSymbol: self.lift_symbol,
                bSymbol: self.lift_symbol,
            }
        )

    def lift_symbol(self, symbol: CoreSymbol, **kwargs,) -> Union[GlobalVariable, Constant]:
        """Lift the given symbol from binaryninja MLIL."""
        if not (symbol_type := self.SYMBOL_MAP.get(symbol.type, None)):
            warning(f"[Lifter] Can not handle symbols of type {symbol.type}, falling back to constant lifting.")
            return Constant(symbol.address, vartype=Integer.uint32_t())
        return symbol_type(symbol.name, symbol.address, vartype=Integer.uint32_t())
