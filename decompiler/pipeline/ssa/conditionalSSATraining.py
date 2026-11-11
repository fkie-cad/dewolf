import os
import json
import traceback
from itertools import combinations
from typing import DefaultDict, Dict, List, Optional

from decompiler.pipeline.ssa.conditional_attribute_helper import (
    CandidatePair,
    PhiPairs,
    TrainingAttributeHelper,
    get_phi_pairs,
    source_identity,
    variablesAreInterfering,
)
from decompiler.pipeline.ssa.phi_dependency_resolver import PhiDependencyResolver
from decompiler.pipeline.ssa.phi_lifting import PhiFunctionLifter
from decompiler.pipeline.ssa.variable_renaming import remove_interference_between_related_variables
from decompiler.structures.graphs.cfg import BasicBlock
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import Phi
from decompiler.task import DecompilerTask

# Upper bound for the number of variable pairs checked for interference per function (see
# _interfering_pairs); above it the function's interfering pairs are written as null (unknown).
MAX_INTERFERENCE_CHECKS = 2_000_000


class ConditionalOutOfSSATraining:
    """
    Custom Out-of-SSA stage which extracts the attribute vectors of every candidate variable pair and
    saves them to a file.

    The result file (``ConditionalResultPath``) holds::

        {"variables": [[display name, [source_id, source_name] or null], ...],
         "pairs": [[x index, y index, f_1, ..., f_18], ...],
         "interfering": [[i, j], ...] or null}

    ``pairs`` are all pairs between local variables the conditional renamer would score, one per
    occurrence, labeled or not: a pair is labeled iff both variables have a source (goal 1 iff the
    sources are equal).
    ``interfering`` are the variable pairs that may not share a name (variablesAreInterfering), among
    variables that are connected by candidate pairs. Which functions are used for training, and how
    the rows are weighted, is decided by the pipeline (cvpipeline/features.py).

    Pairs with a global variable are left out. The renamer scores them too, but they are no training
    data: a global never counts as labeled (it has no storage location from the lifter) and
    out-of-SSA does not rename it. They are the bulk of a function's pairs (over 80 % in a sample),
    so keeping them would make every count of unlabeled pairs a count of globals.
    """

    def __init__(
        self,
        task: DecompilerTask,
        _phi_fuctions_of: DefaultDict[BasicBlock, List[Phi]],
    ):
        self.task = task
        self.cfg = task.cfg
        self._phi_functions_of = _phi_fuctions_of
        self.error_log_path = str(os.environ["ConditionalErrorLogPath"])
        self.result_path = str(os.environ["ConditionalResultPath"])

    def perform(self) -> None:
        # We need to get the phi_pairs before lifting
        phi_pairs = get_phi_pairs(self.task.cfg)
        #Start as if it would be a normal conditional out of SSA run to achieve the same state of the CFG and Interference graph as in a normal conditional.
        PhiDependencyResolver(self._phi_functions_of).resolve()
        interference_graph = InterferenceGraph(self.task.cfg)
        PhiFunctionLifter(self.task.graph, interference_graph, self._phi_functions_of).lift()
        # as ConditionalVariableRenamer does with its graph: variables joined by a Relation do not interfere
        remove_interference_between_related_variables(self.task.graph, interference_graph)

        try:
            self._extract_and_write(phi_pairs, interference_graph)
        except Exception as e:
            with open(self.error_log_path, "a") as error_file:
                error_file.write(f"Error while processing task {self.task}: {e}\n")

    def _extract_and_write(self, phi_pairs: PhiPairs, interference_graph: InterferenceGraph) -> None:
        helper = TrainingAttributeHelper(phi_pairs, interference_graph)

        def log_instruction_error(assign, _) -> None:
            with open(self.error_log_path, "a") as error_file:
                error_file.write(f"Error while processing instruction {assign}: {traceback.format_exc()}\n")

        pairs: List[CandidatePair] = [
            pair
            for pair in helper.iter_candidate_pairs(self.task.cfg, on_error=log_instruction_error)
            if not isinstance(pair.x, GlobalVariable) and not isinstance(pair.y, GlobalVariable)
        ]
        index: Dict[Variable, int] = {}
        for pair in pairs:
            for variable in (pair.x, pair.y):
                index.setdefault(variable, len(index))
        variables = list(index)  # dicts keep insertion order: variables[i] has index i

        data = {
            "variables": [[f"{v.name}#{v.ssa_label}", _source_json(v)] for v in variables],
            "pairs": [[index[pair.x], index[pair.y], *pair.vector] for pair in pairs],
            "interfering": self._interfering_pairs(interference_graph, variables, pairs, index),
        }
        tmp_path = self.result_path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(data, f)
        os.replace(tmp_path, self.result_path)

    def _interfering_pairs(
        self, interference_graph: InterferenceGraph, variables: List[Variable], pairs: List[CandidatePair], index: Dict[Variable, int]
    ) -> Optional[List[List[int]]]:
        """The pairs of variables that may not share a name, restricted to variables in the same connected
        component of the candidate-pair graph (only those can end up in one class). None if that would
        take more than MAX_INTERFERENCE_CHECKS checks or a check fails."""
        parent = list(range(len(variables)))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        for pair in pairs:
            root_x, root_y = find(index[pair.x]), find(index[pair.y])
            if root_x != root_y:
                parent[root_y] = root_x
        components: Dict[int, List[int]] = {}
        for i in range(len(variables)):
            components.setdefault(find(i), []).append(i)
        if sum(len(c) * (len(c) - 1) // 2 for c in components.values()) > MAX_INTERFERENCE_CHECKS:
            return None
        try:
            return [
                [i, j]
                for component in components.values()
                for i, j in combinations(component, 2)
                if variablesAreInterfering(interference_graph, variables[i], variables[j])
            ]
        except Exception:
            with open(self.error_log_path, "a") as error_file:
                error_file.write(f"Error while collecting interfering pairs of {self.task}: {traceback.format_exc()}\n")
            return None


def _source_json(variable: Variable) -> Optional[list]:
    source = source_identity(variable)
    return None if source is None else list(source)
