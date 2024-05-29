import itertools
from itertools import combinations
from typing import Iterator

import networkx
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import Expression, Operation, OperationType
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.instructions import Assignment
from decompiler.util.decoration import DecoratedGraph
from networkx import MultiDiGraph


def _decorate_dependency_graph(dependency_graph: MultiDiGraph, interference_graph: InterferenceGraph) -> DecoratedGraph:
    """
    Creates a decorated graph from the given dependency and interference graphs.

    This function constructs a new graph where:
    - Variables are represented as nodes.
    - Dependencies between variables are represented as directed edges.
    - Interferences between variables are represented as red, undirected edges.
    """
    decorated_graph = MultiDiGraph()
    for node in dependency_graph.nodes:
        decorated_graph.add_node(hash(node), label="\n".join(map(lambda n: f"{n}: {n.type}, aliased: {n.is_aliased}", node)))
    for u, v, data in dependency_graph.edges.data():
        decorated_graph.add_edge(u, v, label=f"{data['score']}")
    for nodes in networkx.weakly_connected_components(dependency_graph):
        for node_1, node_2 in combinations(nodes, 2):
            if any(interference_graph.has_edge(pair[0], pair[1]) for pair in itertools.product(node_1, node_2)):
                decorated_graph.add_edge(hash(node_1), hash(node_2), color="red", dir="none")

    return DecoratedGraph(decorated_graph)


def dependency_graph_from_cfg(cfg: ControlFlowGraph) -> MultiDiGraph:
    """
    Construct the dependency graph of the given CFG, i.e. adds an edge between two variables if they depend on each other.
        - Add an edge the definition to at most one requirement for each instruction.
        - All variables that where not defined via Phi-functions before have out-degree of at most 1, because they are defined at most once.
        - Variables that are defined via Phi-functions can have one successor for each required variable of the Phi-function.
    """
    dependency_graph = MultiDiGraph()

    for variable in _collect_variables(cfg):
        dependency_graph.add_node((variable,))
    for instruction in _assignments_in_cfg(cfg):
        defined_variables = instruction.definitions
        for used_variable, score in _expression_dependencies(instruction.value).items():
            if score > 0:
                dependency_graph.add_edges_from((((dvar,), (used_variable,)) for dvar in defined_variables), score=score)

    return dependency_graph


def _collect_variables(cfg: ControlFlowGraph) -> Iterator[Variable]:
    """
    Yields all variables contained in the given control flow graph.
    """
    for instruction in cfg.instructions:
        for subexpression in instruction.subexpressions():
            if isinstance(subexpression, Variable):
                yield subexpression


def _assignments_in_cfg(cfg: ControlFlowGraph) -> Iterator[Assignment]:
    """Yield all interesting assignments for the dependency graph."""
    for instr in cfg.instructions:
        if isinstance(instr, Assignment):
            yield instr


def _expression_dependencies(expression: Expression) -> dict[Variable, float]:
    """
    Calculate the dependencies of an expression in terms of its constituent variables.

    This function analyzes the given `expression` and returns a dictionary mapping each
    `Variable` to a float score representing its contribution or dependency weight within
    the expression.
    The scoring mechanism accounts for different types of operations and
    penalizes nested operations to reflect their complexity.
    """
    match expression:
        case Variable():
            return {expression: 1.0}
        case Operation():
            if expression.operation in {
                OperationType.call,
                OperationType.address,
                OperationType.dereference,
                OperationType.member_access,
            }:
                return {}

            operands_dependencies = list(filter(lambda d: d, (_expression_dependencies(operand) for operand in expression.operands)))
            dependencies: dict[Variable, float] = {}
            for deps in operands_dependencies:
                for var in deps:
                    score = deps[var]
                    score /= len(operands_dependencies)
                    score *= 0.5  # penalize operations, so that expressions like (a + (a + (a + (a + a)))) gets a lower score than just (a)

                    if var not in dependencies:
                        dependencies[var] = score
                    else:
                        dependencies[var] += score

            return dependencies
        case _:
            return {}
