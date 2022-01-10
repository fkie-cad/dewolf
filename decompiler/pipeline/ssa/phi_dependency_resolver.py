"""Module for removing circular dependency of Phi-functions in Out of SSA."""
import logging
from typing import Dict, List

from decompiler.pipeline.ssa.phi_dependency_graph import PhiDependencyGraph
from decompiler.structures.graphs.cfg import BasicBlock
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.instructions import Assignment, Phi
from networkx import topological_sort


class PhiDependencyResolver:
    """This class resolves circular dependency on Phi-functions by inserting copies of certain variables."""

    def __init__(self, phi_functions: Dict[BasicBlock, List[Phi]]):
        """The dict phi_functions maps to each basic block the list of Phi-functions it contains."""
        self._phi_functions_of = phi_functions

    def resolve(self) -> None:
        """
        This function resolves the circular dependency of phi functions, by replacing every phi-function a#0 = phi(a#1, a#2,...,a#k), that
        is contained in a directed fvs of the dependency graph of the Phi-functions, by the phi-function copy_a#0 = phi(a#1, a#2,...,a#k).

        Furthermore, it sorts the phi-functions according to their topological order.
        """
        for basic_block, phi_instructions in self._phi_functions_of.items():
            dependency_graph = PhiDependencyGraph(phi_instructions)
            directed_fvs = dependency_graph.compute_directed_feedback_vertex_set_of()

            for phi_function in directed_fvs:
                self._remove_dependency_of(phi_function, basic_block, dependency_graph)

            topological_order = self._get_topological_order_for(dependency_graph)

            self._sort_phi_functions_using(topological_order, basic_block)

    def _remove_dependency_of(self, phi_function: Phi, basic_block: BasicBlock, dependency_graph: PhiDependencyGraph):
        """
        Remove the circular dependency due to the given phi-function.

        - Create a new Phi-instruction that only differs from the input Phi-function by its definition, i.e.,
          the new definition is copy_{phi_function.definitions[0]}, and replace the old one by the new one.
        - Add the definition 'phi_function.definitions = new_phi_function.definitions' to the basic block after the last Phi-function
          of this basic block, to preserve the semantics.

        - Attention: One has to split the update of the dependency graph because networkx does not recognize the phi-function as a node
          anymore. Even if I iterate over the nodes and then check whether the node is in the graph, it returns False (most of the time,
          sometimes it returns True and I get an error later when computing the topological order).

        :param phi_function: The Phi-function that we want to replace.
        :param basic_block: The basic block where we replace the Phi-function.
        :param dependency_graph: The phi-dependency graph that belongs to this basic block.
        """
        successors = dependency_graph.successors(phi_function)
        dependency_graph.remove_node(phi_function)

        variable = phi_function.definitions[0]
        copy_variable = Variable("copy_" + variable.name, variable.type, variable.ssa_label, variable.is_aliased)
        phi_function.rename_destination(variable, copy_variable)

        dependency_graph.add_edges_from([(phi_function, succ) for succ in successors])

        self._add_definition_to_cfg(variable, copy_variable, basic_block)

    def _add_definition_to_cfg(self, definition: Variable, value: Variable, basic_block: BasicBlock):
        """
        Adds the definition 'definition=value' to the basic block because we replaced in the Phi-function that defined 'value' the
        definition by 'definition'.

        :param definition: The left-hand-side of the Assignment we want to insert.
        :param value: The right-hand-side of the Assignment we want to insert.
        :param basic_block: The basic block where we want to insert the definition after the last Phi-function.
        """
        assignment = Assignment(definition, value)
        basic_block.instructions.insert(len(self._phi_functions_of[basic_block]), assignment)

    def _get_topological_order_for(self, dependency_graph: PhiDependencyGraph) -> List[Phi]:
        """Chooses among the possible topological orders the one that minimizes the introduction of new interferences."""

        return list(topological_sort(dependency_graph))

    def _sort_phi_functions_using(self, sorted_phi_functions: List[Phi], basic_block: BasicBlock) -> None:
        """
        This function updates the dictionary 'self._phi_functions_of' as well as the Control Flow Graph.
        In both, we sort the Phi-functions according to the list 'sorted_phi_functions'.

        :param sorted_phi_functions: The list of Phi-functions of the current basic block in topological order.
        :param basic_block: The basic block where we want to change the order of the Phi-functions.
        """
        if len(sorted_phi_functions) != len(self._phi_functions_of[basic_block]):
            error_message = (
                f"The length of our ordered list of Phi-functions {sorted_phi_functions} is different from our original list "
                f"of Phi-functions {self._phi_functions_of[basic_block]}"
            )
            logging.error(error_message)
            raise ValueError(error_message)

        self._phi_functions_of[basic_block] = sorted_phi_functions
        basic_block.instructions[: len(sorted_phi_functions)] = sorted_phi_functions
