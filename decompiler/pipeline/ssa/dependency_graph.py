from typing import Iterator

from networkx import MultiGraph
from decompiler.pipeline.ssa.conditional_attribute_helper import ConditionalAttributeHelper, PhiPairs, variablesAreInterfering
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import UnaryOperation
from decompiler.structures.pseudo.expressions import Variable

# legacy code, not used anymore, but maybe useful in the future
#def decorate_dependency_graph(dependency_graph: MultiDiGraph, interference_graph: InterferenceGraph) -> DecoratedGraph:
#    """
#    Creates a decorated graph from the given dependency and interference graphs.
#
#    This function constructs a new graph where:
#    - Variables are represented as nodes.
#    - Dependencies between variables are represented as directed edges.
#    - Interferences between variables are represented as red, undirected edges.
#    """
#    decorated_graph = MultiDiGraph()
#    for node in dependency_graph.nodes:
#        decorated_graph.add_node(hash(node), label="\n".join(map(lambda n: f"{n}: {n.type}, aliased: {n.is_aliased}", node)))
#    for u, v, data in dependency_graph.edges.data():
#        decorated_graph.add_edge(hash(u), hash(v), label=f"{data['score']}")
#    for nodes in networkx.weakly_connected_components(dependency_graph):
#        for node_1, node_2 in combinations(nodes, 2):
#            if any(interference_graph.has_edge(pair[0], pair[1]) for pair in itertools.product(node_1, node_2)):
#                decorated_graph.add_edge(hash(node_1), hash(node_2), color="red", dir="none")
#
#    return DecoratedGraph(decorated_graph)

#def _assignments_in_cfg(cfg: ControlFlowGraph) -> Iterator[Assignment]:
#    """Yield all interesting assignments for the dependency graph."""
#    for instr in cfg.instructions:
#        if isinstance(instr, Assignment):
#            yield instr

# Any edge scoring below this is dropped entirely; anything above it is floored to this
# value. Matches the original `scorev = max(scorev, 0.05)` behavior.
_MIN_KEPT_SCORE = 0.05


def _collect_variables(cfg: ControlFlowGraph) -> Iterator[Variable]:
    """
    Yields all variables contained in the given control flow graph.
    """
    for instruction in cfg.instructions:
        for subexpression in instruction.subexpressions():
            if (isinstance(subexpression, Variable)) and (not isinstance(subexpression, UnaryOperation)):
                yield subexpression

def dependency_graph_from_cfg(
        cfg: ControlFlowGraph, parameters: list[float], intercept: float, phi_pairs: PhiPairs, ifg: InterferenceGraph) -> MultiGraph:
    """
        Construct the dependency graph of the given CFG, i.e. adds an edge between two variables if they depend on each other.
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
        score = max(score, _MIN_KEPT_SCORE)
        if dependency_graph.has_edge((a,), (b,)):
            existing_score = next(iter(dependency_graph.get_edge_data((a,), (b,)).values()))["score"]
            dependency_graph.remove_edge((a,), (b,))
 
        dependency_graph.add_edge((a,), (b,), score=max(score, existing_score))

    return dependency_graph
