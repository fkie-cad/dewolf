"""Module implementing variable lifting for the binaryninja observer lifer."""

from typing import Optional

from binaryninja import (
    FunctionParameter,
    MediumLevelILInstruction,
    MediumLevelILVar,
    MediumLevelILVarAliased,
    MediumLevelILVarSplitSsa,
    MediumLevelILVarSsa,
    SSAVariable,
)
from binaryninja import Variable as bVariable
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import RegisterPair
from decompiler.structures.pseudo import Variable as Variable
from decompiler.structures.pseudo import VariableProvenance


class VariableHandler(Handler):
    """Handler for binaryninja's variable objects."""

    def register(self):
        """Register the handler at the parent lifter."""
        self._lifter.HANDLERS.update(
            {
                bVariable: self.lift_variable,
                SSAVariable: self.lift_variable_ssa,
                FunctionParameter: self.lift_function_parameter,
                MediumLevelILVar: self.lift_variable_operation,
                MediumLevelILVarSsa: self.lift_variable_operation_ssa,
                MediumLevelILVarSplitSsa: self.lift_register_pair,
                MediumLevelILVarAliased: self.lift_variable_aliased,
            }
        )
        self._lifter.lift_variable = self.lift_variable
        self._lifter.lift_variable_ssa = self.lift_variable_ssa

    def lift_variable(
        self, variable: bVariable, is_aliased: bool = True, parent: Optional[MediumLevelILInstruction] = None, **kwargs
    ) -> Variable:
        """Lift the given non-ssa variable, annotating the memory version of the parent instruction, if available."""
        return Variable(
            variable.name,
            self._lifter.lift(variable.type),
            ssa_label=parent.ssa_memory_version if parent else 0,
            is_aliased=is_aliased,
            origin=self._variable_provenance(variable)
        )

    def lift_function_parameter(self, variable: FunctionParameter) -> Variable:
        """Lift a function parameter variable used by function declaration and function pointers"""
        return Variable(variable.name, self._lifter.lift(variable.type))

    def lift_variable_ssa(self, variable: SSAVariable, is_aliased: bool = False, **kwargs) -> Variable:
        """Lift the given ssa variable by its name and its current version, stamping its provenance (see _variable_provenance)."""
        return Variable(
            variable.var.name,
            self._lifter.lift(variable.var.type),
            ssa_label=variable.version,
            is_aliased=is_aliased,
            origin=self._variable_provenance(variable.var, variable)
        )

    def _variable_provenance(self, bnv: bVariable, ssa_variable: Optional[SSAVariable] = None) -> Optional[VariableProvenance]:
        """Build provenance (storage location + DWARF source name) from a Binary Ninja variable.

        def_address is the binary address of the SSA version's defining instruction, so it is set
        only when ssa_variable is given: the real def address (has_real_def=True) if one exists,
        else the function start as a fallback for version-0/parameters (has_real_def=False). It
        stays None for the non-SSA case. Provenance is optional metadata: any failure returns None
        and never breaks lifting.

        Consumed by external tooling that maps dewolf variables to DWARF source variables using the
        variable NAME as a join key, so do not rename lifted variables without coordinating.
        """
        try:
            function = bnv.function.start if bnv.function else None
            source_type = bnv.source_type.name
            storage = bnv.storage
        except Exception:
            return None
        def_address, has_real_def = None, False
        if ssa_variable is not None and bnv.function is not None:
            try:
                definition = bnv.function.mlil.ssa_form.get_ssa_var_definition(ssa_variable)
            except Exception:
                definition = None
            if definition is not None:
                def_address, has_real_def = definition.address, True
            else:
                def_address = function  # version 0 / parameter: no defining instruction
        origin = VariableProvenance(
            source_type=source_type, storage=storage, def_address=def_address, function=function, has_real_def=has_real_def
        )
        origin.source_name = self._resolve_source_name(origin, bnv)
        return origin

    def _resolve_source_name(self, origin: VariableProvenance, bnv: bVariable) -> Optional[str]:
        """Look up the matching C source-variable name for this variable via DWARF."""
        try:
            function = bnv.function
            if function is None:
                return None
            return self._lifter.dwarf.source_name(origin, function.name, self._lifter.bv.arch.get_reg_name)
        except Exception:
            return None

    def lift_variable_aliased(self, variable: MediumLevelILVarAliased, **kwargs) -> Variable:
        """Lift the given MediumLevelILVar_aliased operation."""
        return self._lifter.lift(variable.src, is_aliased=True, parent=variable)

    def lift_variable_operation(self, variable: MediumLevelILVar, **kwargs) -> Variable:
        """Lift the given MediumLevelILVar operation."""
        return self._lifter.lift(variable.src, parent=variable)

    def lift_variable_operation_ssa(self, variable: MediumLevelILVar, **kwargs) -> Variable:
        """Lift the given MediumLevelILVar_ssa operation."""
        return self._lifter.lift(variable.src, parent=variable)

    def lift_register_pair(self, pair: MediumLevelILVarSplitSsa, **kwargs) -> RegisterPair:
        """Lift register pair expression (e.g. eax:edx)."""
        return RegisterPair(
            high := self._lifter.lift(pair.high, parent=pair),
            low := self._lifter.lift(pair.low, parent=pair),
            vartype=high.type.resize((high.type.size + low.type.size)),
        )
