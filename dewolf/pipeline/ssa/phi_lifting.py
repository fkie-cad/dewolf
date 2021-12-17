"""Module for removing Phi-functions by lifting in Out of SSA."""
import logging
from typing import DefaultDict, Iterator, List, Optional

from dewolf.structures.graphs.cfg import BasicBlock, ControlFlowGraph, UnconditionalEdge
from dewolf.structures.interferencegraph import InterferenceGraph
from dewolf.structures.pseudo.expressions import Constant, Variable
from dewolf.structures.pseudo.instructions import Assignment, Phi


class PhiFunctionLifter:
    """This class is in charge of removing the Phi-functions by lifting."""

    def __init__(self, cfg: ControlFlowGraph, interference_graph: InterferenceGraph, phi_functions: DefaultDict[BasicBlock, List[Phi]]):
        """
        :param cfg: The control flow graph whose phi-functions we want to lift
        :param interference_graph: In interference graph of the given control-flow graph
        :param phi_functions: A dictionary that maps to each basic block its list of Phi-functions.
        """
        self._cfg = cfg
        self.interference_graph = interference_graph
        self._phi_functions_of: DefaultDict[BasicBlock, List[Phi]] = phi_functions

    def lift(self) -> None:
        """
        This function removes the Phi functions by lifting their information to the predecessors of the basic block that contains the
        Phi-function that we want to lift.

        If the edge between the predecessor block and the basic block that contains the phi-function is not an unconditional edge,
        then we have to insert a basic block.
        """
        for basic_block in self._phi_functions_of:
            self._lift_phi_functions_of(basic_block)
            self._remove_phi_instructions_of(basic_block)

    def _lift_phi_functions_of(self, basic_block: BasicBlock) -> None:
        """
        This functions lifts the phi-instructions of basic block 'basic_block' to its predecessor blocks.

        - Note that the phi-functions do not have a circular dependency and are ordered accordingly (we have to do this before),
          i.e., no variable that is defined by a Phi-function is used in a 'later' phi-function.

        :param basic_block: The basic block whose phi-instructions we want to remove.
        """
        for predecessor in self._get_predecessors(basic_block):
            new_instructions: List[Assignment] = self._compute_instructions_for(predecessor, basic_block)
            if not new_instructions:
                continue

            edge = self._cfg.get_edge(predecessor, basic_block)
            if predecessor is not None and isinstance(edge, UnconditionalEdge):
                predecessor.instructions.extend(new_instructions)
            else:
                new_basic_block = self._insert_basic_block_before(basic_block, new_instructions)
                if predecessor:
                    self._cfg.substitute_edge(edge, edge.copy(sink=new_basic_block))

            self._update_interference_graph_after_lifting(new_instructions)

    def _get_predecessors(self, basic_block: BasicBlock) -> Iterator[Optional[BasicBlock]]:
        """
        Returns all predecessors of the given basic block, i.e., all vertices where we have to lift the Phi-functions.

        -> Note, if a Phi-function is on top of the head, then one predecessor is None.
        """
        yield from list(self._cfg.get_predecessors(basic_block))
        if self._phi_functions_of[basic_block] and None in self._phi_functions_of[basic_block][0].origin_block:
            yield None

    def _insert_basic_block_before(self, basic_block: BasicBlock, new_instructions: List[Assignment]) -> BasicBlock:
        """
        Inserts a basic block before 'basic_block' that contains as instructions the list 'new_instructions'.
        Besides, we return the new added basic block.
        """
        new_basic_block = self._cfg.create_block(new_instructions)
        self._cfg.add_edge(UnconditionalEdge(new_basic_block, basic_block))
        return new_basic_block

    def _update_interference_graph_after_lifting(self, new_instructions: List[Assignment]) -> None:
        """
        After lifting the Phi-functions, the interference graph changes, but only locally. The variable that is defined by a Phi-function
        can now interfere with some of the values of the other Phi-functions of the same basic block.

        :param new_instructions: The set of new instructions, which lead to a change of the interference graph.
        """
        assigned_variables = [instruction.destination for instruction in new_instructions[:-1]]
        for number, instruction in enumerate(new_instructions):
            if isinstance(instruction.value, Variable):
                for index in range(number):
                    self.interference_graph.add_edge(assigned_variables[index], instruction.value)

    def _compute_instructions_for(self, predecessor: Optional[BasicBlock], basic_block: BasicBlock) -> List[Assignment]:
        """
        Computes the Assignments that we have to add to the basic block 'predecessor' when we lift the list of Phi-functions basic block
        `basic_block`.
        -> If the assignment would be 'a#2 = a#2' than we do not add this assignment.
        -> If the Phi-function is on top of the head and only has one predecessor, then we have to insert a new node before the head.
           In this case, the predecessor is None.

        :param predecessor: The basic block where we want to insert the Assignments.
        :param basic_block: The Basic block that contains the Phi-functions that we want to lift.
        :return: The list of Assignments that we add to the basic block 'predecessor'.
        """
        new_instructions = list()
        constant_assignments = list()
        defined_variables = set()
        for phi_inst in self._phi_functions_of[basic_block]:
            definition = phi_inst.definitions[0]
            value = phi_inst.origin_block[predecessor]
            if value in defined_variables:
                error_message = (
                    f"the phi-function {phi_inst} uses value {value} which is defined by a previous Phi-function of the same "
                    f"basic block, therefore, lifting the Phi-functions in this order {self._phi_functions_of[basic_block]} is not correct."
                )
                logging.error(error_message)
                raise ValueError(error_message)
            defined_variables.add(definition)
            if definition != value:
                if isinstance(value, Constant):
                    constant_assignments.append(Assignment(definition, value))
                else:
                    new_instructions.append(Assignment(definition, value))
        return new_instructions + constant_assignments

    def _remove_phi_instructions_of(self, basic_block: BasicBlock) -> None:
        """
        This function removes the Phi-functions of basic block 'basic_block' from the list of instructions.
        """
        for phi_inst in self._phi_functions_of[basic_block]:
            basic_block.remove_instruction(phi_inst)
