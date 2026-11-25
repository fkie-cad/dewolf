from typing import Iterator, Optional

from decompiler.pipeline.ssa.conditional_attribute_helper import ConditionalAttributeHelper, PhiPairs, variablesAreInterfering
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import UnaryOperation
from decompiler.structures.pseudo.expressions import Variable
from networkx import MultiGraph


def _collect_variables(cfg: ControlFlowGraph) -> Iterator[Variable]:
    """
    Yields all variables contained in the given control flow graph.
    """
    for instruction in cfg.instructions:
        for subexpression in instruction.subexpressions():
            if (isinstance(subexpression, Variable)) and (not isinstance(subexpression, UnaryOperation)):
                yield subexpression


def dependency_graph_from_cfg(
    cfg: ControlFlowGraph,
    parameters: list[float],
    intercept: float,
    phi_pairs: PhiPairs,
    ifg: InterferenceGraph,
    min_kept_score: Optional[float] = None,
) -> MultiGraph:
    """
    Construct the dependency graph of the given CFG, i.e. adds an edge between two variables if they depend on each other.

    The score of a candidate pair is the linear model (parameters, intercept) applied to its feature vector.
    Pairs with score <= 0 and interfering pairs get no edge. Kept scores are raised to at least min_kept_score
    (None: no lower bound).
    """
    dependency_graph = MultiGraph()
    for variable in _collect_variables(cfg):
        dependency_graph.add_node((variable,))

    helper = ConditionalAttributeHelper(phi_pairs)
    for vector, (a, b) in helper.iter_edge_data(cfg):
        score = sum(p * v for p, v in zip(parameters, vector)) + intercept
        if score <= 0 or variablesAreInterfering(ifg, a, b):
            continue

        existing_score = 0.0
        if min_kept_score is not None:
            score = max(score, min_kept_score)
        if dependency_graph.has_edge((a,), (b,)):
            existing_score = next(iter(dependency_graph.get_edge_data((a,), (b,)).values()))["score"]
            dependency_graph.remove_edge((a,), (b,))

        dependency_graph.add_edge((a,), (b,), score=max(score, existing_score))

    return dependency_graph
