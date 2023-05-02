"""Module implementing the ConstantHandler for the binaryninja frontend."""
from binaryninja import BinaryView, DataVariable, SectionSemantics, SymbolType, Type, mediumlevelil
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Constant, GlobalVariable, Integer, Pointer, StringSymbol


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
                int: self.lift_integer_literal,
            }
        )

    def lift_constant(self, constant: mediumlevelil.MediumLevelILConst, **kwargs) -> Constant:
        """Lift the given constant value."""
        return Constant(constant.constant, vartype=self._lifter.lift(constant.expr_type))

    @staticmethod
    def lift_integer_literal(value: int, **kwargs) -> Constant:
        """Lift the given literal, which is most likely an artefact from shift operations and the like."""
        return Constant(value, vartype=Integer.int32_t())

    def lift_constant_pointer(self, pointer: mediumlevelil.MediumLevelILConstPtr, **kwargs):
        """Lift the given constant pointer, e.g. &0x80000."""
        view = pointer.function.view

        if variable := view.get_data_var_at(pointer.constant):
            return self._lifter.lift(variable, view=view, parent=pointer)

        if (symbol := view.get_symbol_at(pointer.constant)) and symbol.type != SymbolType.DataSymbol:
            return self._lifter.lift(symbol)

        if function := view.get_function_at(pointer.constant):
            return self._lifter.lift(function.symbol)

        variable = DataVariable(view, pointer.constant, Type.void(), False)
        global_variable = self._lifter.lift(variable, view=view, parent=pointer)

        return self._propagate_global_string(global_variable, variable, view)

    def _propagate_global_string(self, globalVariable: GlobalVariable, variable: DataVariable, view: BinaryView) -> StringSymbol:
        """Propagate a constant string into code, if it's a char* and in a read only section"""
        if not self._in_read_only_section(variable.address, view) or str(globalVariable.type) == "void *":
            return globalVariable
        return StringSymbol(globalVariable.initial_value, variable.address, vartype=Pointer(Integer.char(), view.address_size * 8))

    def _in_read_only_section(self, addr: int, view: BinaryView) -> bool:
        """Returns True if address is contained in a read only section, False otherwise"""
        for _, section in view.sections.items():
            if addr >= section.start and addr <= section.end and section.semantics == SectionSemantics.ReadOnlyDataSectionSemantics:
                return True
        return False