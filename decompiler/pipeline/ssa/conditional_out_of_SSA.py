from typing import DefaultDict, List

from decompiler.pipeline.ssa.conditional_attribute_helper import get_phi_pairs
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
        parms: list[float] = [
            -0.14254326745979062,
            0.3320831141616175,
            1.5271139949880213,
            1.991088101974919,
            0.516479465908587,
            -1.5734535975921078,
            0.1989580731918738,
            0.39415666158123647,
            -0.16202441485769442,
            -0.1600031357442977,
            0.15216994527078326,
            0.0,
            0.020523316541731576,
            0.0,
            -0.5209695240054403,
            0.0,
        ],
        intercept: float = -0.7731497659886425,
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
        phi_pairs = get_phi_pairs(self.task.cfg)
        PhiDependencyResolver(self._phi_functions_of).resolve()
        self.interference_graph = InterferenceGraph(self.task.cfg)
        PhiFunctionLifter(
            self.task.graph, self.interference_graph, self._phi_functions_of
        ).lift()  # no more phi functions from this point on
        ConditionalVariableRenamer(self.task, self.interference_graph, self.params, self.intercept, phi_pairs, self.strategy).rename()
