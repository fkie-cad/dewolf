from collections import defaultdict
from itertools import chain
from typing import Dict, List, Optional, Set, Tuple

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.expressions import GlobalVariable, Variable, VariableProvenance
from decompiler.structures.pseudo.instructions import MemPhi, Phi
from decompiler.task import DecompilerTask
from decompiler.util.name_inheritance import synthesized_version_origin


class MemPhiConverter(PipelineStage):
    name = "mem-phi-converter"

    def __init__(self):
        self._cfg: ControlFlowGraph
        self._aliased_variables: Set[Variable]
        self._version_origins: Dict[Tuple[str, Optional[int]], VariableProvenance] = {}
        self._source_names: Dict[str, Set[str]] = {}
        self._lifted_origins: Dict[Tuple[str, int], VariableProvenance] = {}

    def run(self, task: DecompilerTask):
        """Converts memory φ-functions to regular φ-functions


        - if there are aliased variables in the function, we convert every single memory phi function into phi functions
        for these variables.
        - in case the program does not have any aliased variables, meaning no variable associated with memory φ-function,
         (e.g. memory φ-functions are result of calls to functions that does not manipulate any variables, e.g. printf()),
         we simply remove all the occurrences of memory φ-functions
        """
        self._cfg = task.graph
        self._lifted_origins = task.aliased_version_origins
        self._collect_aliased_variables()
        if self._aliased_variables:
            self._replace_mem_phis_with_phis()
        else:
            self._remove_all_mem_phis()

    def _collect_aliased_variables(self) -> None:
        """
        Collects all unique aliased variables (without ssa-labels) present in the cfg.

        Aliased variables are associated with memory in binary ninja, meaning that they do change there ssa labels
        when memory version is updated; which does not necessarily affects the variable itself. Some examples are variables,
        whose references are given as arguments to function calls or pointers.

        :param cfg: control flow graph, for which we compute the set of aliased variables
        :return aliased_variables: set of aliased variables used in this graph
        """
        self._aliased_variables = set()
        self._version_origins = {}
        source_names: Dict[str, Set[str]] = defaultdict(set)
        for instruction in self._cfg.instructions:
            for variable in chain(instruction.requirements, instruction.definitions):
                if not variable.is_aliased:
                    continue
                if variable.origin is not None and variable.origin.source_name is not None:
                    source_names[variable.name].add(variable.origin.source_name)
                    self._version_origins.setdefault((variable.name, variable.ssa_label), variable.origin)
                var_copy = variable.copy()
                var_copy.unsubscript()
                self._aliased_variables.add(var_copy)
        self._source_names = source_names

    def _replace_mem_phis_with_phis(self) -> None:
        """
        Replaces every memory φ-function instruction in the graph with regular φ-functgit ions for aliased variables.

        E.g. aliased_variables = {v, w};
             mem#5 = φ(mem#4, mem#3);
                      |
                      v
             v#5 = φ(v#4, v#3)
             w#5 = φ(w#4, v#3)

        :param cfg: control flow graph
        :param aliased_variables: set of aliased variables contained in this cfg
        """
        for basic_block in self._cfg.nodes:
            for instruction in basic_block.instructions:
                if isinstance(instruction, MemPhi):
                    phis = instruction.create_phi_functions_for_variables(self._aliased_variables)
                    self._bind_version_origins(phis)
                    basic_block.replace_instruction(instruction, phis)
                    break

    def _bind_version_origins(self, phis: List[Phi]) -> None:
        """Give each phi variable the provenance of its own SSA version (evaluation-only metadata)."""
        for phi in phis:
            for variable in chain([phi.destination], phi.value.operands):
                key = (variable.name, variable.ssa_label)
                variable.origin = synthesized_version_origin(key, self._version_origins, self._lifted_origins, self._source_names[variable.name], variable.origin)

    def _remove_all_mem_phis(self) -> None:
        """
        Removes all the memory φ-functions from the cfg.

        :param cfg: current control flow graph
        """
        for basic_block in self._cfg.nodes:
            for instruction in basic_block.instructions:
                if isinstance(instruction, MemPhi):
                    basic_block.remove_instruction(instruction)
