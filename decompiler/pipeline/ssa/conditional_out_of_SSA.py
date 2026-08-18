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
        parms: list[float] = [ -1.3901324035743863, 2.2071815353779347, 0.5702879296764318, 4.018223766501149, 0.9256244181465493, -2.5080453236068716, 3.07605041869229, -0.5607221883989606, 0.22358629781738318, -0.9803925213278151, -0.7553703722781673, -0.16535496570625535, 0.0, 0.0, 0.0, 0.0 ],
        intercept: float = -3.1048554529687693,
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
