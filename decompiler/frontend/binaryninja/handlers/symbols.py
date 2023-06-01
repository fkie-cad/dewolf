"""Module implementing lifting of binaryninja symbols."""
from logging import warning
from typing import Union

from binaryninja import CoreSymbol
from binaryninja import Symbol as bSymbol
from binaryninja import SymbolType
from decompiler.frontend.lifter import Handler, ObserverLifter
from decompiler.structures.pseudo import Constant, FunctionSymbol, GlobalVariable, ImportedFunctionSymbol, Symbol

MAX_SYMBOL_NAME_LENGTH = 64
GLOBAL_VARIABLE_PREFIX = "data_"

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
            return Constant(symbol.address)
        return symbol_type(self._purge_symbol_name(symbol.short_name[:], symbol.address), symbol.address)

    def _purge_symbol_name(self, name: str, addr: int) -> str:
        """Purge invalid chars from symbol names or lift as data_addr if name is too long"""
        if name[:2] == "??" or len(name) > MAX_SYMBOL_NAME_LENGTH: # strip useless PDB debug names which start with `??`
            return GLOBAL_VARIABLE_PREFIX + f"{hex(addr)}"
        return name.translate({
            ord(' '): '_', 
            ord("'"): "", 
            ord('.'): "_", 
            ord('`'): "",
            })
