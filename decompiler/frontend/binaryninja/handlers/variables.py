from binaryninja import Variable as bVariable, SSAVariable, MediumLevelILVar, MediumLevelILVar_ssa, MediumLevelILVar_split_ssa, MediumLevelILVar_aliased, FunctionParameter

from dewolf.frontend.lifter import Handler
from dewolf.structures.pseudo import Variable as Variable, RegisterPair


class VariableHandler(Handler):

    def register(self):
        self._lifter.HANDLERS.update({
            bVariable: self.lift_variable,
            SSAVariable: self.lift_variable_ssa,
            FunctionParameter: self.lift_variable,
            MediumLevelILVar: self.lift_variable_operation,
            MediumLevelILVar_ssa: self.lift_variable_operation,
            MediumLevelILVar_split_ssa: self.lift_register_pair,
            MediumLevelILVar_aliased: self.lift_variable_aliased,
        })
        self._lifter.lift_variable = self.lift_variable
        self._lifter.lift_variable_ssa = self.lift_variable_ssa

    def lift_variable(self, variable: bVariable, is_aliased: bool = True) -> Variable:
        print(f'{variable} - {is_aliased}')
        return Variable(variable.name, self._lifter.lift(variable.type), ssa_label=0, is_aliased=is_aliased)

    def lift_variable_ssa(self, variable: SSAVariable, is_aliased: bool = False) -> Variable:
        print(f'{variable} - {is_aliased}')
        return Variable(variable.var.name, self._lifter.lift(variable.var.type), ssa_label=variable.version, is_aliased=is_aliased)

    def lift_variable_aliased(self, variable: MediumLevelILVar_aliased) -> Variable:
        return self.lift_variable_ssa(variable.src, is_aliased=True)

    def lift_variable_operation(self, variable: MediumLevelILVar) -> Variable:
        return self._lifter.lift(variable.src)

    def lift_register_pair(self, pair: MediumLevelILVar_split_ssa) -> RegisterPair:
        """Lift register pair expression"""
        return RegisterPair(
            high := self._lifter.lift(pair.high),
            low := self._lifter.lift(pair.low),
            vartype=high.type.resize((high.type.size + low.type.size) * self.BYTE_SIZE),
        )