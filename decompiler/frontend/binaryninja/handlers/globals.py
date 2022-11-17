"""Module implementing the ConstantHandler for the binaryninja frontend."""
from typing import List, Union

from binaryninja import BinaryView, DataVariable, Endianness, SymbolType, TypeClass
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Constant, CustomType, GlobalVariable, Integer, OperationType, Pointer, Symbol, Type, UnaryOperation


class GlobalHandler(Handler):
    """Handle for global variables."""

    # Dict translating endianness between the binaryninja enum and pythons literals
    Endian = {Endianness.LittleEndian: "little", Endianness.BigEndian: "big"}

    def register(self):
        """Register the handler at its parent lifter."""
        self._lifter.HANDLERS.update({DataVariable: self.lift_global_variable})

    def lift_global_variable(self, variable: DataVariable, **kwargs) -> GlobalVariable:
        if not variable.name:
            return Constant(variable.value, vartype=self._lifter.lift(variable.type))
        return GlobalVariable(variable.name, self._lifter.lift(variable.type), 0, initial_value=Constant(variable.value))
