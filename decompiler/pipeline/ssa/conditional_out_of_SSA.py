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
        parms: list[float] = [-0.6253492760504956, 0.5951661423368272, 1.9944794993936195, 1.390527007986582, -0.002961881471296021, -0.6253505741850781, 1.3235157911840238, 0.7095078869498519, -0.18232889323310886, -0.4012665014235144, -0.26828521733590455, 0.0, 0.0, 0.0, 0.0, 0.0],
        intercept: float = -1.1246830223693014,
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
