"""Module implementing variable lifting for the binaryninja observer lifer."""

from dataclasses import replace
from typing import Dict, List, Optional, Set, Tuple

from binaryninja import (
    FunctionParameter,
    MediumLevelILInstruction,
    MediumLevelILMemPhi,
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


class VariableHandler(Handler):
    """Handler for binaryninja's variable objects."""

    def __init__(self, lifter):
        super().__init__(lifter)
        self._aliased_vars: Dict[int, Set[bVariable]] = {}  # function start -> its aliased variables

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
        self._lifter.aliased_version_origins = self.aliased_version_origins

    def lift_variable(
        self, variable: bVariable, is_aliased: bool = True, parent: Optional[MediumLevelILInstruction] = None, **kwargs
    ) -> Variable:
        """Lift the given non-ssa variable, annotating the memory version of the parent instruction, if available."""
        ssa_label = parent.ssa_memory_version if parent else 0
        # an aliased variable (e.g. in &x) is the SSA version x#ssa_label: give it that version's provenance
        ssa_variable = SSAVariable(variable, ssa_label) if parent and self._is_aliased(variable) else None
        return Variable(
            variable.name,
            self._lifter.lift(variable.type),
            ssa_label=ssa_label,
            is_aliased=is_aliased,
            origin=self._variable_provenance(variable, ssa_variable)
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

        value_address is set only when ssa_variable is given (see _value_address); it stays None for
        the non-SSA case. Provenance is optional metadata: any failure returns None and never breaks lifting.

        Consumed by external tooling that maps dewolf variables to DWARF source variables using the
        variable NAME as a join key, so do not rename lifted variables without coordinating.
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
            if definition is None and ssa_variable.version > 0 and self._is_aliased(bnv):
                # aliased versions written through memory (call, store, mem-phi) only have a memory definition
                definition = self._memory_definition(bnv.function, ssa_variable.version)
            if definition is not None:
                def_address, has_real_def = definition.address, True
            else:
                def_address = function  # version 0 / parameter: no defining instruction
        origin = VariableProvenance(
            source_type=source_type,
            storage=storage,
            function=function,
            has_real_def=has_real_def,
            value_address=self._value_address(def_address, definition if has_real_def else None),
        )
        uses = self._use_addresses(bnv, ssa_variable, def_address, origin.value_address)
        origin.source_name = self._resolve_source_name(origin, bnv, uses)
        origin.name_via = ("dwarf",) if origin.source_name is not None else ()
        try:
            origin.dwarf_storage_names = self._lifter.dwarf.storage_names(origin, bnv.function.name, self._lifter.bv.arch.get_reg_name)
        except Exception:
            origin.dwarf_storage_names = frozenset()
        return origin

    def _value_address(self, def_address: Optional[int], definition) -> Optional[int]:
        """Return the first address at which the value defined at def_address is live.

        DWARF describes the state before an instruction executes, so a written value only exists from the
        next instruction on. Phis and parameters already hold their value at def_address.
        """
        if def_address is None:
            return None
        if definition is None or isinstance(definition, (MediumLevelILVarPhi, MediumLevelILMemPhi)):
            return def_address
        try:
            length = self._lifter.bv.get_instruction_length(def_address)
        except Exception:
            return None
        return def_address + length if length else None

    @staticmethod
    def _use_addresses(bnv: bVariable, ssa_variable: Optional[SSAVariable], def_address, value_address) -> List[int]:
        """Addresses of the instructions reading this SSA version; the value is in its storage right before each.

        Skipped: phi uses (the value only flows along an edge), uses in the defining instruction itself
        (there the storage still holds the previous value) and uses where the storage already holds another
        version (Binary Ninja may place a use after the instruction that actually reads it).
        """
        if ssa_variable is None or bnv.function is None:
            return []
        try:
            uses = bnv.function.mlil.ssa_form.get_ssa_var_uses(ssa_variable)
        except Exception:
            return []
        skip = {value_address} if def_address == value_address else {def_address, value_address}
        return sorted({use.address for use in uses if VariableHandler._holds_version(use, ssa_variable)} - skip)

    @staticmethod
    def _holds_version(use: MediumLevelILInstruction, ssa_variable: SSAVariable) -> bool:
        """Return whether the storage holds exactly this SSA version right before the (non-phi) use."""
        if isinstance(use, (MediumLevelILVarPhi, MediumLevelILMemPhi)):
            return False
        try:
            return use.get_ssa_var_version(ssa_variable.var) == ssa_variable.version
        except Exception:
            return False

    def aliased_version_origins(self, function) -> Dict[Tuple[str, int], VariableProvenance]:
        """Provenance of each aliased variable at each memory version, also for versions only preprocessing creates."""
        try:
            ssa = function.mlil.ssa_form
            versions = {k for i in ssa.instructions for k in (i.ssa_memory_version, i.ssa_memory_version_after)}
            origins = {(v.name, k): self._variable_provenance(v, SSAVariable(v, k)) for v in self._aliased(function) for k in versions}
        except Exception:
            return {}
        return {key: origin for key, origin in origins.items() if origin is not None}

    def _is_aliased(self, bnv: bVariable) -> bool:
        """Return whether the variable lives in memory, i.e. its SSA versions are memory versions."""
        try:
            return bnv.function is not None and bnv in self._aliased(bnv.function)
        except Exception:
            return False

    def _aliased(self, function) -> Set[bVariable]:
        if function.start not in self._aliased_vars:
            self._aliased_vars[function.start] = set(function.mlil.ssa_form.aliased_vars)
        return self._aliased_vars[function.start]

    @staticmethod
    def _memory_definition(function, version: int) -> Optional[MediumLevelILInstruction]:
        try:
            return function.mlil.ssa_form.get_ssa_memory_definition(version)
        except Exception:
            return None

    def _resolve_source_name(self, origin: VariableProvenance, bnv: bVariable, uses: List[int] = ()) -> Optional[str]:
        """Look up the matching C source-variable name for this variable via DWARF."""
        try:
            function = bnv.function
            if function is None:
                return None
            names = self._dwarf_names(origin, function.name, uses)
            if len(names) == 1:
                return next(iter(names))
            name = self._parameter_source_name_by_index(origin, bnv, function)
            origin.dwarf_ambiguous = name is None and len(names) > 1
            return name
        except Exception:
            return None

    def _dwarf_names(self, origin: VariableProvenance, function_name: str, uses: List[int]) -> Set[str]:
        """Source variables DWARF places in the storage at value_address and at every use address.

        One value, so every address must agree: the result is the intersection of the matches. An address
        without any match is a DWARF gap and ignored; disagreeing addresses return all names (ambiguous).
        """
        matches = []
        for address in (origin.value_address, *uses):
            names = self._lifter.dwarf.source_names(replace(origin, value_address=address), function_name, self._lifter.bv.arch.get_reg_name)
            if names:
                matches.append(names)
        if not matches:
            return set()
        return set.intersection(*matches) or set.union(*matches)

    def _parameter_source_name_by_index(self, origin: VariableProvenance, bnv: bVariable, function) -> Optional[str]:
        """Name a register parameter by its position among the function's parameters.

        Applies to register-typed parameters. Binary Ninja resolves the calling convention, so the
        parameter's index in function.parameter_vars lines up with the DWARF formal-parameter order and
        the position gives its source name. The parameter is identified by Binary Ninja variable
        equality, so this fires for the parameter itself and not for later reuses of the same register;
        the count-equality guard lives in DwarfVariableResolver.parameter_name_by_index.
        """
        if origin.source_type != "RegisterVariableSourceType":
            return None
        parameters = list(function.parameter_vars)
        for index, parameter in enumerate(parameters):
            # BN equality distinguishes the parameter from later reuses of the same register (which
            # share its storage but are distinct variables), so this fires only for the parameter itself.
            if parameter == bnv:
                return self._lifter.dwarf.parameter_name_by_index(function.name, index, len(parameters))
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
