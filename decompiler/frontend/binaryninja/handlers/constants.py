"""Module implementing the ConstantHandler for the binaryninja frontend."""
from binaryninja import mediumlevelil
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Constant, Integer


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

    def lift_constant_pointer(self, pointer: mediumlevelil.MediumLevelILConstPtr, **kwargs) -> Constant:
        """Lift the given constant pointer, e.g. &0x80000."""
        view = pointer.function.view
        if variable := view.get_data_var_at(pointer.constant):
            return self._lifter.lift(variable, parent=pointer)
        if symbol := view.get_symbol_at(pointer.constant):
            return self._lifter.lift(symbol)
        if function := view.get_function_at(pointer.constant):
            return self._lifter.lift(function.symbol)
        string = view.get_string_at(pointer.constant, partial=True) or view.get_ascii_string_at(pointer.constant, min_length=2)
        return Constant(pointer.constant, vartype=self._lifter.lift(pointer.expr_type), pointee=string)
