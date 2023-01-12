"""Module implementing lifting of binaryninja symbols."""
from typing import Union, Optional
from logging import warning

from binaryninja import CoreSymbol, BinaryView, MediumLevelILInstruction
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

    def lift_symbol(self, symbol: CoreSymbol, view: BinaryView, parent: Optional[MediumLevelILInstruction] = None, **kwargs,) -> Union[GlobalVariable, Constant]:
        """Lift the given symbol from binaryninja MLIL."""
        if symbol.type == SymbolType.DataSymbol:
            return GlobalVariable(
                symbol.name[:-2] if symbol.name.find(".0") != -1 else symbol.name, # purge ".0" from str, because bninja handles it as a symbol
                vartype=self._lifter.lift(view.parse_type_string("char*")[0]), # cast to char*, because symbol does not have a type 
                ssa_label=parent.ssa_memory_version if parent else 0, # give correct ssa_label if there is one
                initial_value=self._get_raw_bytes(view, symbol.address)
                )

        if not (symbol_type := self.SYMBOL_MAP.get(symbol.type, None)):
            warning(f"[Lifter] Can not handle symbols of type {symbol.type}, falling back to constant lifting.")
            return Constant(symbol.address, vartype=Integer.uint32_t())
        return symbol_type(symbol.name, symbol.address, vartype=Integer.uint32_t())

    def _get_raw_bytes(self, view: BinaryView, addr: int) -> bytes:
        """ Returns raw bytes after a given address to the next data structure (or section)"""
        if next_data_var := view.get_next_data_var_after(addr):
            return view.read(addr, next_data_var.address - addr)
        else:
            return view.read(addr, view.get_sections_at(addr)[0].end)
