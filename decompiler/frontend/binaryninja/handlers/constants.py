"""Module implementing the ConstantHandler for the binaryninja frontend."""

import math
from typing import Union

from binaryninja import DataVariable, SymbolType, Type, mediumlevelil
from decompiler.frontend.binaryninja.handlers.globals import addr_in_section
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import (
    Constant,
    CustomType,
    GlobalVariable,
    Integer,
    NotUseableConstant,
    OperationType,
    Pointer,
    Symbol,
    UnaryOperation, FunctionSymbol,
)

BYTE_SIZE = 8


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
                mediumlevelil.MediumLevelILConstData: self.lift_constant_data,
                int: self.lift_integer_literal,
            }
        )

    def lift_constant(self, constant: mediumlevelil.MediumLevelILConst, **kwargs):
        """Lift the given constant value."""
        if constant.constant in [math.inf, -math.inf, math.nan]:
            return NotUseableConstant(str(constant.constant))
        if isinstance(constant.constant, int) and addr_in_section(constant.function.view, constant.constant):
            return self.lift_constant_pointer(constant)
        return Constant(constant.constant, vartype=self._lifter.lift(constant.expr_type))

    @staticmethod
    def lift_integer_literal(value: int, **kwargs) -> Constant:
        """Lift the given literal, which is most likely an artefact from shift operations and the like."""
        return Constant(value, vartype=Integer.int32_t())

    def lift_constant_data(self, pointer: mediumlevelil.MediumLevelILConstData, **kwargs) -> Constant:
        """Lift data as a non mute able constant string (register string)"""
        return NotUseableConstant(str(pointer))

    def lift_constant_pointer(self, pointer: mediumlevelil.MediumLevelILConstPtr, **kwargs) -> Union[GlobalVariable, Symbol]:
        """Lift the given constant pointer, e.g. &0x80000."""
        view = pointer.function.view

        if variable := view.get_data_var_at(pointer.constant):
            res = self._lifter.lift(variable, view=view, parent=pointer)

        elif (symbol := view.get_symbol_at(pointer.constant)) and symbol.type != SymbolType.DataSymbol:
            if isinstance(result := self._lifter.lift(symbol), FunctionSymbol):
                try:
                    result.can_return = view.get_function_at(pointer.constant).can_return.value
                    return result
                except Exception:
                    pass
            return result

        elif function := view.get_function_at(pointer.constant):
            if isinstance(result := self._lifter.lift(function.symbol), FunctionSymbol):
                result.can_return = function.can_return.value
            return result

        else:
            res = self._lifter.lift(DataVariable(view, pointer.constant, Type.void(), False), view=view, parent=pointer)

        if isinstance(res, Constant):  # BNinja Error case handling
            return res

        if isinstance(pointer, mediumlevelil.MediumLevelILImport):  # Temp fix for '&'
            return res

        return UnaryOperation(
            OperationType.address,
            [res],
            vartype=res.type,
        )
