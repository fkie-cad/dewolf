"""Module for removing unnecessary Phi-functions in Out of SSA."""

from typing import Dict, Iterator, List

from decompiler.pipeline.ssa.phi_dependency_graph import PhiDependencyGraph
from decompiler.structures.graphs.cfg import BasicBlock
from decompiler.structures.pseudo.instructions import Assignment, Phi


class PhiFunctionCleaner:
    """This class removes Phi-functions that are not needed, because all operands are equal."""

    def __init__(self, phi_functions: Dict[BasicBlock, List[Phi]]):
        """The dict phi_functions maps to each basic block the list of Phi-functions it contains."""
        self._phi_functions_of = phi_functions

    def clean_up(self) -> None:
        """
        This functions removes Phi-functions where all operands on the right-hand-side are the same:
        """
        for basic_block in self._phi_functions_of.keys():
            self._remove_unnecessary_phi_functions_of(basic_block)

    def _remove_unnecessary_phi_functions_of(self, basic_block: BasicBlock) -> None:
        """
        This functions removes Phi-functions of basic block 'basic_block' where all operands on the right-hand-side are the same,
        but only if the one operand is not defined in another Phi-function of the same block:
            - The program must not be in SSA-form, however, since all variables that are defined in a Phi-function of the same basic block
              interfere, all these variables are different.
            - If the definition of the phi-function, where all operands are the same, is equal to the one operand,
              then we delete the Phi-function.
            - If the definition of the phi-function, where all operands are the same, is not equal to the one operand,
              then we delete the Phi-function and add the assignment 'definition = operand' after the last Phi-function, if possible.
        """
        dependency_graph = PhiDependencyGraph(self._phi_functions_of[basic_block])

        removable_phi_functions = set(self._get_removable_phi_functions_and_remove_trivial(basic_block, dependency_graph))

        removable_phi_functions_degree_zero = [
            phi_function for phi_function in removable_phi_functions if dependency_graph.out_degree(phi_function) == 0
        ]

        while removable_phi_functions_degree_zero:
            phi_function = removable_phi_functions_degree_zero.pop()
            new_instruction = Assignment(phi_function.definitions[0], phi_function.value.operands[0])
            basic_block.instructions.insert(dependency_graph.number_of_nodes(), new_instruction)
            basic_block.remove_instruction(phi_function)
            for predecessor in dependency_graph.predecessors(phi_function):
                if dependency_graph.out_degree(predecessor) == 1 and predecessor in removable_phi_functions:
                    removable_phi_functions_degree_zero.append(predecessor)
            dependency_graph.remove_node(phi_function)

        self._phi_functions_of[basic_block] = [
            phi_function for phi_function in self._phi_functions_of[basic_block] if phi_function in dependency_graph.nodes()
        ]

    def _get_removable_phi_functions_and_remove_trivial(self, basic_block, dependency_graph) -> Iterator[Phi]:
        """
        Remove all trivial Phi-functions, i.e., Phi-functions where all operands on the RHS and LHS are the same.
        Furthermore, return all non-trivial Phi-functions where all RHS operands are the same.
        """
        for phi_function in self._phi_functions_of[basic_block]:
            rhs_operands = set(phi_function.value.operands)
            if len(rhs_operands) == 1:
                if rhs_operands == set(phi_function.definitions):
                    basic_block.remove_instruction(phi_function)
                    dependency_graph.remove_node(phi_function)
                else:
                    yield phi_function
