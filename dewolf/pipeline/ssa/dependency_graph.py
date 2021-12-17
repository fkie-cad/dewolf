from typing import Iterable, List, Optional, Set

from dewolf.structures.graphs.cfg import ControlFlowGraph
from dewolf.structures.interferencegraph import InterferenceGraph
from dewolf.structures.pseudo.expressions import Variable
from dewolf.structures.pseudo.instructions import Assignment
from dewolf.structures.pseudo.operations import Call
from networkx import DiGraph, weakly_connected_components


def _non_call_assignments(cfg: ControlFlowGraph) -> Iterable[Assignment]:
    """Yield all interesting assignments for the dependency graph."""
    for instr in cfg.instructions:
        if isinstance(instr, Assignment) and isinstance(instr.destination, Variable) and not isinstance(instr.value, Call):
            yield instr


class DependencyGraph(DiGraph):
    def __init__(self, interference_graph: Optional[InterferenceGraph] = None):
        super().__init__()
        self.add_nodes_from(interference_graph.nodes)
        self.interference_graph = interference_graph

    @classmethod
    def from_cfg(cls, cfg: ControlFlowGraph, interference_graph: InterferenceGraph):
        """
        Construct the dependency graph of the given CFG, i.e. adds an edge between two variables if they depend on each other.
            - Add an edge the definition to at most one requirement for each instruction.
            - All variables that where not defined via Phi-functions before have out-degree at most 1, because they are defined at most once
            - Variables that are defined via Phi-functions can have one successor for each required variable of the Phi-function.
        """
        dependency_graph = cls(interference_graph)
        for instruction in _non_call_assignments(cfg):
            defined_variable = instruction.destination
            if isinstance(instruction.value, Variable):
                if dependency_graph._variables_can_have_same_name(defined_variable, instruction.value):
                    dependency_graph.add_edge(defined_variable, instruction.requirements[0], strength="high")
            elif len(instruction.requirements) == 1:
                if dependency_graph._variables_can_have_same_name(defined_variable, instruction.requirements[0]):
                    dependency_graph.add_edge(defined_variable, instruction.requirements[0], strength="medium")
            else:
                if non_interfering_variable := dependency_graph._non_interfering_requirements(instruction.requirements, defined_variable):
                    dependency_graph.add_edge(defined_variable, non_interfering_variable, strength="low")
        return dependency_graph

    def _non_interfering_requirements(self, requirements: List[Variable], defined_variable: Variable) -> Optional[Variable]:
        """Get the unique non-interfering requirement if it exists, otherwise we return None."""
        non_interfering_requirement = None
        for required_variable in requirements:
            if self._variables_can_have_same_name(defined_variable, required_variable):
                if non_interfering_requirement:
                    return None
                non_interfering_requirement = required_variable
        return non_interfering_requirement

    def _variables_can_have_same_name(self, source: Variable, sink: Variable) -> bool:
        """
        Two variable can have the same name, if they have the same type, are both aliased or both non-aliased variables, and if they
        do not interfere.

        :param source: The potential source vertex.
        :param sink: The potential sink vertex
        :return: True, if the given variables can have the same name, and false otherwise.
        """
        if self.interference_graph.are_interfering(source, sink) or source.type != sink.type or source.is_aliased != sink.is_aliased:
            return False
        if source.is_aliased and sink.is_aliased and source.name != sink.name:
            return False
        return True

    def get_components(self) -> Iterable[Set[Variable]]:
        """Returns the weakly connected components of the dependency graph."""
        for component in weakly_connected_components(self):
            yield set(component)
