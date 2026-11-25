import json
from dataclasses import dataclass
from pathlib import Path
from typing import DefaultDict, List, Optional, Union

from decompiler.pipeline.ssa.conditional_attribute_helper import FEATURES, get_phi_pairs
from decompiler.pipeline.ssa.phi_dependency_resolver import PhiDependencyResolver
from decompiler.pipeline.ssa.phi_lifting import PhiFunctionLifter
from decompiler.pipeline.ssa.variable_renaming import ConditionalVariableRenamer
from decompiler.structures.graphs.cfg import BasicBlock
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.instructions import Phi
from decompiler.task import DecompilerTask

BUNDLED_WEIGHTS_FILE = Path(__file__).with_name("conditional_weights.json")


@dataclass(frozen=True)
class ConditionalWeights:
    """The model of the conditional out-of-SSA renaming, see load_conditional_weights."""

    coefficients: List[float]
    intercept: float
    strategy: int
    min_kept_score: Optional[float] = None


def load_conditional_weights(path: Union[str, Path, None] = None) -> ConditionalWeights:
    """
    Load the weights of the conditional out-of-SSA renaming from a JSON file (None or "" -> the bundled file).

    Format (a JSON object):
        - features: the feature names in the order of the feature vector; must be exactly
          conditional_attribute_helper.FEATURES, otherwise a ValueError is raised.
        - coefficients: one number per feature, same order.
        - intercept: number.
        - strategy: how ConditionalVariableRenamer.create_variable_classes splits the dependency graph (0-4).
        - min_kept_score: lower bound for the scores of kept dependency-graph edges, or null (no lower bound).
    Other keys (e.g. description, trained) are documentation only and ignored.
    The score of a variable pair is intercept + sum(coefficient * feature); pairs with score > 0 become edges.
    """
    path = Path(path) if path else BUNDLED_WEIGHTS_FILE
    with open(path) as file:
        data = json.load(file)
    features = tuple(data.get("features", ()))
    if features != FEATURES:
        raise ValueError(f"Conditional out-of-SSA weights file {path}: features {list(features)} do not match {list(FEATURES)}")
    coefficients = [float(c) for c in data["coefficients"]]
    if len(coefficients) != len(FEATURES):
        raise ValueError(f"Conditional out-of-SSA weights file {path}: expected {len(FEATURES)} coefficients, got {len(coefficients)}")
    min_kept_score = data.get("min_kept_score")
    return ConditionalWeights(
        coefficients=coefficients,
        intercept=float(data["intercept"]),
        strategy=int(data["strategy"]),
        min_kept_score=None if min_kept_score is None else float(min_kept_score),
    )


class ConditionalOutOfSSA:
    """
    Conditional out-of-SSA:
        - Remove the circular dependency of the Phi-functions.
        - Lift the Phi-functions to their predecessor basic blocks.
        - Rename the variables according to the dependency graph scored with the given weights.
    """

    def __init__(
        self,
        task: DecompilerTask,
        phi_functions_of: DefaultDict[BasicBlock, List[Phi]],
        weights: Optional[ConditionalWeights] = None,
    ):
        """weights: the model to use; None -> the file given by the option out-of-ssa-translation.conditional_weights."""
        self.task = task
        self._phi_functions_of = phi_functions_of
        if weights is None:
            weights = load_conditional_weights(task.options.getstring("out-of-ssa-translation.conditional_weights", fallback=""))
        self.weights = weights

    def perform(self):
        phi_pairs = get_phi_pairs(self.task.cfg)
        PhiDependencyResolver(self._phi_functions_of).resolve()
        self.interference_graph = InterferenceGraph(self.task.cfg)
        PhiFunctionLifter(self.task.graph, self.interference_graph, self._phi_functions_of).lift()  # no more phi functions from here on
        ConditionalVariableRenamer(
            self.task,
            self.interference_graph,
            self.weights.coefficients,
            self.weights.intercept,
            phi_pairs,
            self.weights.strategy,
            self.weights.min_kept_score,
        ).rename()
