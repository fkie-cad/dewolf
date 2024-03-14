from functools import reduce
from typing import Iterable, Iterator, Set

from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo import Expression, Operation, OperationType
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.instructions import Assignment
from networkx import DiGraph, weakly_connected_components


def _assignments_in_cfg(cfg: ControlFlowGraph) -> Iterator[Assignment]:
    """Yield all interesting assignments for the dependency graph."""
    for instr in cfg.instructions:
        # ignores assignments with multiple values... These are currently poorly defined, so idk how they need to be handled
        if isinstance(instr, Assignment) and isinstance(instr.destination, Variable):
            yield instr


class DependencyGraph(DiGraph):
    def __init__(self):
        super().__init__()

    @classmethod
    def from_cfg(cls, cfg: ControlFlowGraph):
        """
        Construct the dependency graph of the given CFG, i.e. adds an edge between two variables if they depend on each other.
            - Add an edge the definition to at most one requirement for each instruction.
            - All variables that where not defined via Phi-functions before have out-degree of at most 1, because they are defined at most once.
            - Variables that are defined via Phi-functions can have one successor for each required variable of the Phi-function.
        """
        dependency_graph = cls()

        for instruction in _assignments_in_cfg(cfg):
            defined_variable = instruction.destination
            dependency_graph.add_node(defined_variable)

            for used_variable, score in _expression_dependencies(instruction.value).items():
                if used_variable.type == defined_variable.type:
                    dependency_graph.add_edge(defined_variable, used_variable, score=score)

        return dependency_graph

    def get_components(self) -> Iterable[Set[Variable]]:
        """Returns the weakly connected components of the dependency graph."""
        for component in weakly_connected_components(self):
            yield set(component)


def _expression_dependencies(expression: Expression) -> dict[Variable, float]:
    match expression:
        case Variable():
            return {expression: 1.0}
        case Operation():
            operation_type_penalty = {
                OperationType.call: 0.5,
                OperationType.address: 0,
                OperationType.dereference: 0,
                OperationType.member_access: 0,
            }.get(expression.operation, 1.0)

            dependencies: dict[Variable, float] = reduce(dict.__or__, (_expression_dependencies(operand) for operand in expression.operands))
            for var in dependencies:
                dependencies[var] /= len(dependencies)
                dependencies[var] *= operation_type_penalty
            return dependencies
        case _:
            return {}
