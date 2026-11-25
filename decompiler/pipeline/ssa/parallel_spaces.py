"""Module for the parallel copy spaces of the Boissinot et al. Out of SSA."""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import DefaultDict, Dict, List, Mapping, Optional, Set

from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.instructions import Assignment, Phi

COPY_SUFFIX = "__copy__"  # TODO find a reliable way to avoid collisions


class ParallelSpaces:
    """
    Class that collects the parallel copies of every basic block and inserts them as sequential copies into the CFG.

    Each basic block has two spaces: the copies directly after its Phi-functions and the copies at the end of the block.
    """

    @dataclass
    class _BlockSpaces:
        """The two parallel copy spaces of one basic block."""

        after_phi_assigns: List[Assignment] = field(default_factory=list)
        end_of_block_assigns: List[Assignment] = field(default_factory=list)

    def __init__(self, phi_functions: Mapping[BasicBlock, List[Phi]]):
        """The dict phi_functions maps to each basic block the list of Phi-functions it contains."""
        self._block_spaces_of: DefaultDict[int, ParallelSpaces._BlockSpaces] = defaultdict(ParallelSpaces._BlockSpaces)
        self._phi_count_of: DefaultDict[int, int] = defaultdict(int)
        for basic_block, phi_instructions in phi_functions.items():
            self._phi_count_of[basic_block.address] = len(phi_instructions)

    def add_after_phi_assign(self, basic_block_address: int, assignment: Assignment) -> None:
        """Add the given copy to the space after the Phi-functions of the basic block with the given address."""
        self._block_spaces_of[basic_block_address].after_phi_assigns.append(assignment)

    def add_end_of_block_assign(self, basic_block_address: int, assignment: Assignment) -> None:
        """Add the given copy to the space at the end of the basic block with the given address."""
        self._block_spaces_of[basic_block_address].end_of_block_assigns.append(assignment)

    def insert_into_cfg(self, cfg: ControlFlowGraph) -> None:
        """Insert the assignments from the parallel spaces into the CFG."""
        for basic_block in cfg:
            phi_count = self._phi_count_of[basic_block.address]
            block_spaces = self._block_spaces_of[basic_block.address]

            basic_block.instructions = (
                basic_block.instructions[:phi_count] + block_spaces.after_phi_assigns + basic_block.instructions[phi_count:]
            )

            basic_block.instructions.extend(block_spaces.end_of_block_assigns)

    def remove_nop_copies(self) -> None:
        """Remove all assignments of the form x = x from the parallel spaces."""
        for block_spaces in self._block_spaces_of.values():
            block_spaces.after_phi_assigns = self._remove_nop_copies_from(block_spaces.after_phi_assigns)
            block_spaces.end_of_block_assigns = self._remove_nop_copies_from(block_spaces.end_of_block_assigns)

    def sequentialize(self) -> None:
        """Replace the parallel copies of every space by sequential copies."""
        for block_spaces in self._block_spaces_of.values():
            block_spaces.after_phi_assigns = self._sequentialize(block_spaces.after_phi_assigns)
            block_spaces.end_of_block_assigns = self._sequentialize(block_spaces.end_of_block_assigns)

    def _remove_nop_copies_from(self, assignments: List[Assignment]) -> List[Assignment]:
        """Returns the assignments that are NOT of the form x = x."""
        return [assignment for assignment in assignments if assignment.destination != assignment.value]

    def _sequentialize(self, assignments: List[Assignment]) -> List[Assignment]:
        """
        Returns the parallel copy as a sequence of copies, as described in the paper of Boissinot et al.

        A copy whose destination is not read by another copy can be emitted right away. If only cycles are left, one variable of the
        cycle is saved in a temporary variable to break it.
        """
        current_location: Dict[Variable, Optional[Variable]] = dict()  # the variable that currently holds the value of a variable
        source_of: Dict[Variable, Optional[Variable]] = dict()  # the variable that is copied into a variable
        unprocessed_destinations: List[Variable] = list()  # all destinations, a cycle is broken at the ones not assigned yet
        free_destinations: List[Variable] = list()  # destinations whose current value is no longer needed, so they can be overwritten
        sequence: List[Assignment] = []

        for assignment in assignments:
            current_location[assignment.destination] = None
            source_of[assignment.value] = None

        for assignment in assignments:
            current_location[assignment.value] = assignment.value
            source_of[assignment.destination] = assignment.value
            unprocessed_destinations.append(assignment.destination)

        for assignment in assignments:
            if current_location[assignment.destination] is None:
                free_destinations.append(assignment.destination)

        assigned_destinations: Set[Variable] = set()
        while unprocessed_destinations:
            while free_destinations:
                destination = free_destinations.pop()
                source = source_of[destination]
                location = current_location[source]
                sequence.append(Assignment(destination, location))
                current_location[source] = destination
                if source == location and source_of[source] is not None:
                    free_destinations.append(source)

                assigned_destinations.add(destination)

            variable = unprocessed_destinations.pop()
            if variable not in assigned_destinations:
                temporary = self._create_temporary_for(variable)
                sequence.append(Assignment(temporary, variable))
                current_location[variable] = temporary
                free_destinations.append(variable)

        return sequence

    def _create_temporary_for(self, variable: Variable) -> Variable:
        """Returns a new variable that saves the value of the given variable while a cycle of copies is resolved."""
        return Variable(variable.name + COPY_SUFFIX, variable.type, None, variable.is_aliased, None, variable.tags)
