from collections import defaultdict
from itertools import chain
from typing import Dict, Optional, Set

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.expressions import GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import MemPhi, Phi
from decompiler.task import DecompilerTask


class MemPhiConverter(PipelineStage):
    name = "mem-phi-converter"

    def __init__(self):
        self._cfg: ControlFlowGraph
        self._aliased_variables: Set[Variable]

    def run(self, task: DecompilerTask):
        """Converts memory φ-functions to regular φ-functions


        - if there are aliased variables in the function, we convert every single memory phi function into phi functions
        for these variables.
        - in case the program does not have any aliased variables, meaning no variable associated with memory φ-function,
         (e.g. memory φ-functions are result of calls to functions that does not manipulate any variables, e.g. printf()),
         we simply remove all the occurrences of memory φ-functions
        """
        self._cfg = task.graph
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
        source_names: Dict[str, Set[str]] = defaultdict(set)
        for instruction in self._cfg.instructions:
            for variable in chain(instruction.requirements, instruction.definitions):
                if not variable.is_aliased:
                    continue
                if variable.origin is not None and variable.origin.source_name is not None:
                    source_names[variable.name].add(variable.origin.source_name)
                var_copy = variable.copy()
                var_copy.unsubscript()
                self._aliased_variables.add(var_copy)
        # Versions of one aliased name disagreeing on their DWARF source (BN merged what DWARF splits):
        # the set kept one arbitrarily, so drop the guess rather than stamping it onto every phi.
        for template in self._aliased_variables:
            if len(source_names[template.name]) > 1:
                template.origin = None

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
                    basic_block.replace_instruction(instruction, phis)
                    break

    def _remove_all_mem_phis(self) -> None:
        """
        Removes all the memory φ-functions from the cfg.

        :param cfg: current control flow graph
        """
        for basic_block in self._cfg.nodes:
            for instruction in basic_block.instructions:
                if isinstance(instruction, MemPhi):
                    basic_block.remove_instruction(instruction)
