"""Module implementing frontend data harmonization."""
from itertools import chain
from logging import info
from typing import Dict, Iterator, List

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.expressions import Variable
from decompiler.task import DecompilerTask


class Coherence(PipelineStage):
    """This module is utilized to enforce a coherent dataset from the frontend."""

    name = "coherence"

    def run(self, task: DecompilerTask) -> None:
        """Run the pipeline stage in the given task, harmonizing varibale information."""
        variables = self._collect_variables(task.graph)
        self.enforce_same_types(variables)
        self.enforce_same_aliased_value(variables)

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

    def _set_variables_type(self, variables: List[Variable]) -> None:
        """Harmonize the variable type of the given non-empty list of variables."""
        group_type = variables[0].type
        for variable in variables:
            variable._type = group_type.copy()

    def _set_variables_aliased(self, variables: List) -> None:
        """Set all variables in the given list as aliased."""
        for variable in variables:
            variable.is_aliased = True
