"""Module for constructing the weighted dependency graph of the conditional out-of-SSA renaming."""

from typing import Dict, Iterator, Optional, Tuple

from decompiler.pipeline.ssa.conditional_attribute_helper import ConditionalAttributeHelper, Feature, PhiPairs
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.expressions import Variable
from networkx import MultiGraph

# A node of the dependency graph: a tuple of variables that are treated as one (contracted) variable.
DependencyNode = Tuple[Variable, ...]


def _collect_variables(cfg: ControlFlowGraph) -> Iterator[Variable]:
    """Yield all variables contained in the given control flow graph."""
    for instruction in cfg.instructions:
        for subexpression in instruction.subexpressions():
            if isinstance(subexpression, Variable):
                yield subexpression


def dependency_graph_from_cfg(
    cfg: ControlFlowGraph,
    coefficients: Dict[Feature, float],
    intercept: float,
    phi_pairs: PhiPairs,
    min_kept_score: Optional[float] = None,
) -> MultiGraph:
    """
    Construct the dependency graph of the given CFG, i.e. adds an edge between two variables if they depend on each other.

    The score of a candidate pair is the linear model (coefficients, intercept) applied to its feature vector.
    Pairs with score <= 0 get no edge. Pairs that may not share a name are separated later (create_variable_classes).
    Kept scores are raised to at least min_kept_score (None: no lower bound). If a pair occurs several times, its edge keeps
    the highest score.
    """
    dependency_graph = MultiGraph()
    for variable in _collect_variables(cfg):
        dependency_graph.add_node((variable,))

    helper = ConditionalAttributeHelper(phi_pairs)
    for (variable_1, variable_2), vector in helper.iter_edge_data(cfg):
        score = sum(coefficients[feature] * vector.get(feature, 0) for feature in Feature) + intercept
        if score <= 0:
            continue
        if min_kept_score is not None:
            score = max(score, min_kept_score)
        existing_score = 0.0
        if dependency_graph.has_edge((variable_1,), (variable_2,)):
            existing_score = next(iter(dependency_graph.get_edge_data((variable_1,), (variable_2,)).values()))["score"]
            # Re-add the edge instead of updating it, the position of the edge in the graph determines later orders.
            dependency_graph.remove_edge((variable_1,), (variable_2,))
        dependency_graph.add_edge((variable_1,), (variable_2,), score=max(score, existing_score))

    return dependency_graph
