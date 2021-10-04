"""Module implementing variable lifting for the binaryninja observer lifer."""
from typing import Optional

from binaryninja import (
    FunctionParameter,
    MediumLevelILInstruction,
    MediumLevelILVar,
    MediumLevelILVar_aliased,
    MediumLevelILVar_split_ssa,
    MediumLevelILVar_ssa,
    SSAVariable,
)
from binaryninja import Variable as bVariable
from dewolf.frontend.lifter import Handler
from dewolf.structures.pseudo import RegisterPair
from dewolf.structures.pseudo import Variable as Variable


class VariableHandler(Handler):
    """Handler for binaryninja's variable objects."""

    def register(self):
        """Register the handler at the parent lifter."""
        self._lifter.HANDLERS.update(
            {
                bVariable: self.lift_variable,
                SSAVariable: self.lift_variable_ssa,
                FunctionParameter: self.lift_variable,
                MediumLevelILVar: self.lift_variable_operation,
                MediumLevelILVar_ssa: self.lift_variable_operation_ssa,
                MediumLevelILVar_split_ssa: self.lift_register_pair,
                MediumLevelILVar_aliased: self.lift_variable_aliased,
            }
        )
        self._lifter.lift_variable = self.lift_variable
        self._lifter.lift_variable_ssa = self.lift_variable_ssa

    def lift_variable(
        self, variable: bVariable, is_aliased: bool = True, parent: Optional[MediumLevelILInstruction] = None, **kwargs
    ) -> Variable:
        """Lift the given non-ssa variable, annotating the memory version pf the parent instruction, if available."""
        return Variable(
            variable.name, self._lifter.lift(variable.type), ssa_label=parent.ssa_memory_version if parent else 0, is_aliased=is_aliased
        )

    def lift_variable_ssa(self, variable: SSAVariable, is_aliased: bool = False, **kwargs) -> Variable:
        """Lift the given ssa variable by its name and its current version."""
        return Variable(variable.var.name, self._lifter.lift(variable.var.type), ssa_label=variable.version, is_aliased=is_aliased)

    def lift_variable_aliased(self, variable: MediumLevelILVar_aliased, **kwargs) -> Variable:
        """Lift the given MediumLevelILVar_aliased operation."""
        return self._lifter.lift(variable.src, is_aliased=True, parent=variable)

    def lift_variable_operation(self, variable: MediumLevelILVar, **kwargs) -> Variable:
        """Lift the given MediumLevelILVar operation."""
        return self._lifter.lift(variable.src, parent=variable)

    def lift_variable_operation_ssa(self, variable: MediumLevelILVar, **kwargs) -> Variable:
        """Lift the given MediumLevelILVar_ssa operation."""
        return self._lifter.lift(variable.src, parent=variable)

    def lift_register_pair(self, pair: MediumLevelILVar_split_ssa, **kwargs) -> RegisterPair:
        """Lift register pair expression (e.g. eax:edx)."""
        return RegisterPair(
            high := self._lifter.lift(pair.high, parent=pair),
            low := self._lifter.lift(pair.low, parent=pair),
            vartype=high.type.resize((high.type.size + low.type.size)),
        )
