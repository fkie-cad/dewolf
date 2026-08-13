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
        parms: list[float] = [0,0,0,0], #TODO: add trained coefficients and intercept here
        intercept: float = 0.0,
        strategy: int = 0,
    ):
        """
        params: List of parameters from the logistic regression model
        intercept: Intercept from the logistic regression model
        """
        self.task = task
        self.cfg = task.cfg
        self.params = parms
        self.intercept = intercept
        self._phi_functions_of = _phi_fuctions_of
        self.strategy = strategy

    def perform(self):
        PhiDependencyResolver(self._phi_functions_of).resolve()
        self.interference_graph = InterferenceGraph(self.task.cfg)
        PhiFunctionLifter(self.task.graph, self.interference_graph, self._phi_functions_of).lift() #no more phi functions from this point on
        ConditionalVariableRenamer(
            self.task, self.interference_graph, self.params, self.intercept, self.strategy
        ).rename()
