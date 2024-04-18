from functools import reduce
from typing import Iterator

from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo import Expression, Operation, OperationType
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.instructions import Assignment
from networkx import MultiDiGraph


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
    match expression:
        case Variable():
            return {expression: 1.0}
        case Operation():
            operation_type_penalty = {
                OperationType.call: 0,
                OperationType.address: 0,
                OperationType.dereference: 0,
                OperationType.member_access: 0,
            }.get(expression.operation, 0.5)

            operands_dependencies = (_expression_dependencies(operand) for operand in expression.operands)
            dependencies: dict[Variable, float] = reduce(dict.__or__, operands_dependencies, {})
            for var in dependencies:
                dependencies[var] /= len(dependencies)
                dependencies[var] *= operation_type_penalty
            return dependencies
        case _:
            return {}
