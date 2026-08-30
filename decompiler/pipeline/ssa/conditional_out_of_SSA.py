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
        parms: list[float] = [ -1.2444065535639945, 0.3963338481489265, 1.637596558976258, 1.9163834174609498, -0.7696621475806927, -1.846893769648208, 2.7466202322291724, 0.2804041669995089, -0.14625881668273844, -0.723839836827344, -0.15701287000676167, 0.0, -0.026220472916631363, 0.0, 0.0, 0.0],
        intercept: float = -1.2904320719530116,
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
