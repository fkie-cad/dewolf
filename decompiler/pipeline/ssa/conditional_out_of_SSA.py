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
            0.01503987020997377, 
            0.41540590717620035, 
            1.3602003989877633, 
            1.9777705400625902, 
            0.5742951097396733, 
            -1.0536650267354408, 
            -0.13758028768914904, 
            0.05617376449520245, 
            0.4993614018565643, 
            0.09050405693323627, 
            0.13483824342778672, 
            -0.5575677214819728, 
            0.52412111735048, 
            0.0, 
            -0.8431282877532653, 
            0.0
        ],
        intercept: float = -0.20635133227011618,
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
        PhiFunctionLifter(self.task.graph, self.interference_graph, self._phi_functions_of).lift() #no more phi functions from this point on
        ConditionalVariableRenamer(
            self.task, self.interference_graph, self.params, self.intercept, phi_pairs, self.strategy
        ).rename()
