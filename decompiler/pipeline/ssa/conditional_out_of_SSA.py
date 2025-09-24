import gc
from typing import DefaultDict, List

from decompiler.pipeline.ssa.metric_helper import MetricHelper
from decompiler.pipeline.ssa.phi_dependency_resolver import PhiDependencyResolver
from decompiler.pipeline.ssa.phi_lifting import PhiFunctionLifter
from decompiler.pipeline.ssa.variable_renaming import ConditionalVariableRenamer
from decompiler.structures.graphs.cfg import BasicBlock
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.instructions import Phi
from decompiler.task import DecompilerTask


class ConditionalOutOfSSA:

    def __init__(
        self,
        task: DecompilerTask,
        _phi_fuctions_of: DefaultDict[BasicBlock, List[Phi]],
        strong: float = 1,
        mid: float = 0.5,
        weak: float = 0.1,
        strategy: int = 3,
    ):
        """
        strong/ weak/ mid: Values for the corresponding edges
        """
        self.task = task
        self.cfg = task.cfg
        self.strongDep = strong
        self.midDep = mid
        self.weakDep = weak
        self._phi_functions_of = _phi_fuctions_of
        self.strategy = strategy

    def perform(self):
        self._metric_helper = MetricHelper(self.task.cfg)
        PhiDependencyResolver(self._phi_functions_of).resolve()
        self.interference_graph = InterferenceGraph(self.task.cfg)
        PhiFunctionLifter(self.task.graph, self.interference_graph, self._phi_functions_of).lift()
        ConditionalVariableRenamer(
            self.task, self.interference_graph, self._metric_helper, self.strongDep, self.midDep, self.weakDep, self.strategy
        ).rename()
