from typing import Dict, List

from dewolf.structures.pseudo.expressions import Variable
from dewolf.structures.pseudo.instructions import Phi
from dewolf.util.insertion_ordered_set import InsertionOrderedSet
from networkx import DiGraph, dfs_postorder_nodes


class PhiDependencyGraph(DiGraph):
    """Class for the Dependency Graph of a given list of Phi-instructions."""

    def __init__(self, phi_instructions: List[Phi] = None):
        super().__init__()
        self._construct_dependency_graph_of(phi_instructions if phi_instructions else [])

    def _construct_dependency_graph_of(self, phi_instructions: List[Phi]) -> None:
        """
        Constructs the graph that has as vertex set the set of phi_functions and adds an edge (Phi_1, Phi_2) to the graph when the variable
        that is defined in Phi-function Phi_2 is used in Phi_1.

        :param phi_instructions: A list of Phi-functions whose dependency graph we want to compute.
        :return: The dependency graph of the given list of Phi-functions.
        """
        self.add_nodes_from(phi_instructions)

        phi_instruction_defining: Dict[Variable, Phi] = {phi_inst.definitions[0]: phi_inst for phi_inst in phi_instructions}
        for phi_inst in phi_instructions:
            self.add_edges_from(
                [
                    (phi_inst, phi_instruction_defining[variable])
                    for variable in phi_inst.requirements
                    if variable in phi_instruction_defining.keys() and phi_inst != phi_instruction_defining[variable]
                ]
            )

    def compute_directed_feedback_vertex_set_of(self) -> InsertionOrderedSet[Phi]:
        """
        This function computes a directed feedback vertex (directed fvs) set of a given graph.
        -> Since this problem is NP-hard, we only compute an approximate solution.

        :return: A directed fvs of the input graph.
        """
        directed_fvs = InsertionOrderedSet()
        topological_order = list(dfs_postorder_nodes(self))
        topological_order.reverse()

        smaller_order = set()
        for phi_function in topological_order:
            if set(self.successors(phi_function)) & smaller_order:
                directed_fvs.add(phi_function)
            else:
                smaller_order.add(phi_function)

        return directed_fvs

    def update_dependency_graph(self, phi_function: Phi, new_phi_function: Phi) -> None:
        """
        This function updates the dependency graph when we replace the Phi-function 'phi_function' by the Phi-function 'new_phi_function',
        where 'new_phi_function' only differs from 'phi_function' by its left-hand-side, i.e., the definition.
            - Only the definition differs in the two Phi-functions
            - The new defined variable is not used in any other Phi-function.

        :param phi_function:  The Phi-function we want to replace.
        :param new_phi_function: The replacee Phi-function.
        :return: The updated dependency graph.
        """
        self.add_node(new_phi_function)
        self.add_edges_from([(new_phi_function, successor) for successor in self.successors(phi_function)])
        self.remove_node(phi_function)
