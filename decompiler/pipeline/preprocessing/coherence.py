"""Module implementing frontend data harmonization."""

from collections import defaultdict
from dataclasses import replace
from itertools import chain
from logging import info
from typing import DefaultDict, Dict, Iterator, List, Optional, Set, Tuple

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.expressions import Variable, VariableProvenance
from decompiler.structures.pseudo.instructions import Assignment
from decompiler.task import DecompilerTask
from decompiler.util.name_inheritance import iter_variable_occurrences


class Coherence(PipelineStage):
    """This module is utilized to enforce a coherent dataset from the frontend."""

    name = "coherence"

    def run(self, task: DecompilerTask) -> None:
        """Run the pipeline stage in the given task, harmonizing varibale information."""
        variables = self._collect_variables(task.graph)
        self.enforce_same_types(variables)
        self.enforce_same_aliased_value(variables)
        # source names: every occurrence, so all occurrences of an SSA variable share one origin
        occurrences = self._collect_all_occurrences(task.graph)
        self.enforce_same_source_name(occurrences)
        self.infer_source_names_from_copies(task.graph, occurrences)

    def _collect_variables(self, cfg: ControlFlowGraph) -> Dict[str, Dict[int, List[Variable]]]:
        """
        Returns a directory organizing all variables in the given cfg.

        e.g. {'eax': {1: [var, var], ... }, .. }
        """
        variables = {}
        for variable in self._iter_variables(cfg):
            if variable.name not in variables:
                variables[variable.name] = {variable.ssa_label: [variable]}
            else:
                if variable.ssa_label not in variables[variable.name]:
                    variables[variable.name][variable.ssa_label] = [variable]
                else:
                    variables[variable.name][variable.ssa_label].append(variable)
        return variables

    def _iter_variables(self, cfg: ControlFlowGraph) -> Iterator[Variable]:
        """Iterate all occurrences of all variables in the given cfg."""
        for instruction in cfg.instructions:
            for variable in chain(instruction.requirements, instruction.definitions):
                yield variable

    def enforce_same_types(self, variables: Dict[str, Dict[int, List[Variable]]]) -> None:
        """Check and enforce that each combination of name and variable version has"""
        for variable_name in variables.keys():
            for variable_version, variable_instances in variables[variable_name].items():
                variable_types = {instance.type for instance in variable_instances}
                if len(variable_types) > 1:
                    self._set_variables_type(variable_instances)
                    info(
                        f"[{self.name}] Harmonized {variable_name}#{variable_version} to type {variable_instances[0].type} from {variable_types}."
                    )

    def enforce_same_aliased_value(self, variables: Dict[str, Dict[int, List[Variable]]]) -> None:
        """Check and enforce that each a variable name identifies a variable as either aliased or unalised."""
        for variable_name in variables.keys():
            aliased_values = (
                variable.is_aliased for variable_instances in variables[variable_name].values() for variable in variable_instances
            )
            is_aliased = next(aliased_values)
            for aliased_value in aliased_values:
                if aliased_value != is_aliased:
                    self._set_variables_aliased(
                        [instance for variable_instances in variables[variable_name].values() for instance in variable_instances]
                    )
                    info(f"[{self.name}] Set variable {variable_name} to be aliased in all of its instances.")
                    break

    def enforce_same_source_name(self, variables: Dict[str, Dict[int, List[Variable]]]) -> None:
        """Harmonize the DWARF source name across all SSA versions of a variable name.

        All SSA versions sharing a base name are versions of one Binary Ninja variable, i.e. the same
        source variable; a version resolving to None is usually just a per-def-site DWARF lookup gap.
        So if the resolved source names among a name's versions all agree, propagate that name onto the
        versions that lack it, tagged name_via=("coherence",). If they conflict (BN merged what DWARF
        splits), leave them untouched - we do not fabricate a source name. Existing names are never
        overwritten and keep their own name_via.

        The origin object may be shared (Variable.copy() shares it by reference), so it is never mutated:
        each filled SSA version gets one fresh record (dataclasses.replace of an existing origin of that
        version, keeping its location fields, or a minimal VariableProvenance) bound to all its occurrences.
        An unnamed occurrence of an already named version (same SSA variable) is bound to that version's origin.
        """
        for variable_name, versions in variables.items():
            source_names = {self._source_name(instance) for instances in versions.values() for instance in instances} - {None}
            if len(source_names) != 1:
                continue
            (source_name,) = source_names
            for instances in versions.values():
                named = [instance for instance in instances if self._source_name(instance) is not None]
                if not named and self._dwarf_ambiguous(instances):
                    continue  # DWARF saw several source variables here: not 100% sure, so no name
                if not named and self._shared_storage(instances):
                    continue  # DWARF puts several source variables in this storage: siblings' name may not hold here
                if named:
                    origin = named[0].origin
                else:
                    base = next((instance.origin for instance in instances if instance.origin is not None), None)
                    if base is None:
                        origin = VariableProvenance(source_name=source_name, name_via=("coherence",))
                    else:
                        origin = replace(base, source_name=source_name, name_via=("coherence",))
                for instance in instances:
                    if self._source_name(instance) is None:
                        instance.origin = origin
            info(f"[{self.name}] Harmonized source name of {variable_name} to '{source_name}' across its versions.")

    def infer_source_names_from_copies(self, cfg: ControlFlowGraph, variables: Dict[str, Dict[int, List[Variable]]]) -> None:
        """Name an unnamed SSA variable from a plain copy with a named one: name_via=("copy",).

        Rule: for a plain copy `a#i = b#j` (an Assignment, not a Phi, whose destination and value are both
        non-aliased local Variables - no GlobalVariable, no cast/operation, no constant), if exactly one
        side has a source name, that name is a candidate for the other side. Candidates are collected over
        the whole CFG first; an SSA variable is named only if it has exactly one candidate name (any
        conflict -> no name). Only names existing before this step (dwarf / coherence) are used as
        sources, so inference is one hop and never chains. Existing names are never overwritten.
        """
        known: Dict[Tuple[str, Optional[int]], Optional[str]] = {
            (name, ssa_label): self._version_source_name(instances)
            for name, versions in variables.items()
            for ssa_label, instances in versions.items()
        }
        candidates: DefaultDict[Tuple[str, Optional[int]], Set[str]] = defaultdict(set)
        for instruction in cfg.instructions:
            if not self._is_plain_copy(instruction):
                continue
            destination = (instruction.destination.name, instruction.destination.ssa_label)
            value = (instruction.value.name, instruction.value.ssa_label)
            if destination == value:
                continue
            destination_name, value_name = known.get(destination), known.get(value)
            if destination_name is None and value_name is not None:
                candidates[destination].add(value_name)
            elif value_name is None and destination_name is not None:
                candidates[value].add(destination_name)
        for (name, ssa_label), names in candidates.items():
            if len(names) != 1:
                continue
            (source_name,) = names
            instances = variables[name][ssa_label]
            if any(self._source_name(instance) is not None for instance in instances) or self._dwarf_ambiguous(instances):
                continue
            if self._has_storage_names(instances):
                continue  # DWARF uses this storage for a source variable: a copy name is only safe for pure temporaries
            base = next((instance.origin for instance in instances if instance.origin is not None), None)
            if base is None:
                origin = VariableProvenance(source_name=source_name, name_via=("copy",))
            else:
                origin = replace(base, source_name=source_name, name_via=("copy",))
            for instance in instances:
                instance.origin = origin
            info(f"[{self.name}] Named {name}#{ssa_label} '{source_name}' from a copy.")

    @staticmethod
    def _is_plain_copy(instruction) -> bool:
        """Check whether the instruction is `a = b` with a, b non-aliased local Variables (no phi, no cast)."""
        if type(instruction) is not Assignment:
            return False
        # type(...) is Variable excludes GlobalVariable and RegisterPair
        return all(type(side) is Variable and not side.is_aliased for side in (instruction.destination, instruction.value))

    @staticmethod
    def _shared_storage(instances: List[Variable]) -> bool:
        return any(instance.origin is not None and len(instance.origin.dwarf_storage_names) > 1 for instance in instances)

    @staticmethod
    def _has_storage_names(instances: List[Variable]) -> bool:
        return any(instance.origin is not None and instance.origin.dwarf_storage_names for instance in instances)

    @staticmethod
    def _dwarf_ambiguous(instances: List[Variable]) -> bool:
        return any(instance.origin is not None and instance.origin.dwarf_ambiguous for instance in instances)

    @staticmethod
    def _source_name(variable: Variable) -> Optional[str]:
        return variable.origin.source_name if variable.origin is not None else None

    def _version_source_name(self, instances: List[Variable]) -> Optional[str]:
        """The source name of one SSA variable, or None if unnamed or (defensively) its occurrences disagree."""
        names = {self._source_name(instance) for instance in instances} - {None}
        return names.pop() if len(names) == 1 else None

    def _collect_all_occurrences(self, cfg: ControlFlowGraph) -> Dict[str, Dict[Optional[int], List[Variable]]]:
        """Like _collect_variables, but every Variable object in the cfg (no deduplication by equality)."""
        variables: Dict[str, Dict[Optional[int], List[Variable]]] = {}
        for variable in iter_variable_occurrences(cfg.instructions):
            variables.setdefault(variable.name, {}).setdefault(variable.ssa_label, []).append(variable)
        return variables

    def _set_variables_type(self, variables: List[Variable]) -> None:
        """Harmonize the variable type of the given non-empty list of variables."""
        group_type = variables[0].type
        for variable in variables:
            variable._type = group_type

    def _set_variables_aliased(self, variables: List) -> None:
        """Set all variables in the given list as aliased."""
        for variable in variables:
            variable.is_aliased = True
