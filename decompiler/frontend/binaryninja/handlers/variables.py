"""Module implementing variable lifting for the binaryninja observer lifer."""

from typing import Optional

from binaryninja import (
    FunctionParameter,
    MediumLevelILInstruction,
    MediumLevelILVar,
    MediumLevelILVarAliased,
    MediumLevelILVarPhi,
    MediumLevelILVarSplitSsa,
    MediumLevelILVarSsa,
    SSAVariable,
)
from binaryninja import Variable as bVariable
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import RegisterPair
from decompiler.structures.pseudo import Variable as Variable
from decompiler.structures.pseudo import VariableProvenance

from ..dwarf import SourceMatch
from ..parameter_sources import canonical_register


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
        variable NAME as a join key, so do not rename lifted variables without coordinating. The
        matched source variable is stored as source_name (its C name) and source_id (its identity).
        """
        try:
            function = bnv.function.start if bnv.function else None
            source_type = bnv.source_type.name
            storage = bnv.storage
        except Exception:
            return None
        def_address, has_real_def, definition = None, False, None
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
        match = self._resolve_source(origin, bnv, self._lookup_pc(origin, definition))
        if match is not None:
            origin.source_name, origin.source_id = match.name, match.die_offset
        return origin

    def _lookup_pc(self, origin: VariableProvenance, definition) -> Optional[int]:
        """The address at which the variable's DWARF location is looked up.

        A real definition is looked up right after its defining instruction: that is where a DWARF
        location-list range for the newly written value begins, while at the instruction itself
        DWARF still describes the register's previous occupant. A phi is no instruction - its value
        is live at the start of its block, which is where it is looked up. Without a real definition
        (version 0) it is the function entry.
        """
        if not origin.has_real_def or origin.def_address is None or isinstance(definition, MediumLevelILVarPhi):
            return origin.def_address
        try:
            return origin.def_address + (self._lifter.bv.get_instruction_length(origin.def_address) or 0)
        except Exception:
            return origin.def_address

    def _resolve_source(self, origin: VariableProvenance, bnv: bVariable, lookup_pc: Optional[int]) -> Optional[SourceMatch]:
        """Look up the C source variable of this variable via DWARF (by location, see dwarf.py).

        A register without a real definition (version 0) that matches nothing is a value arriving at
        function entry and is named by the entry-parameter source (see parameter_sources.py).
        """
        try:
            function = bnv.function
            if function is None:
                return None
            bv = self._lifter.bv
            match = self._lifter.dwarf.source_match(origin, bv.start, lookup_pc, bv.arch.get_reg_name)
            if match is not None:
                return match
            if origin.source_type == "RegisterVariableSourceType" and origin.def_address is not None and not origin.has_real_def:
                register = canonical_register(bv.arch, bv.arch.get_reg_name(origin.storage))
                return self._lifter.parameter_source.entry_parameter(function.start, register, function.name)
            return None
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
