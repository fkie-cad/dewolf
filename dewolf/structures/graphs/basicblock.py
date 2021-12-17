"""Module defining the BasicBlock class utilized in ControlFlowGraphs."""
from __future__ import annotations

from enum import Enum
from itertools import chain
from typing import TYPE_CHECKING, Dict, Iterator, List, Sequence, Set, Union

from dewolf.structures.graphs.interface import GraphNodeInterface
from dewolf.structures.pseudo import Assignment, Branch, Expression, GenericBranch, IndirectBranch, Instruction, Phi, Variable

if TYPE_CHECKING:
    from dewolf.structures.graphs.cfg import ControlFlowGraph


class BasicBlock(GraphNodeInterface):
    """Implementation of a node representing a basic block."""

    class ControlFlowType(Enum):
        direct = 0
        conditional = 1
        indirect = 2

    def __init__(self, address: int, instructions: List[Instruction] = None, graph: ControlFlowGraph = None):
        """
        Init a new block BasicBlock.

        address -- The address the basic block is at (-1 indicates to take an unique one)
        instructions -- A list of instructions contained in the block
        graph -- The cfg object to report changes to."""
        self._address: int = address
        self._instructions: List[Instruction] = [] if not instructions else instructions
        # Two dicts are used to buffer information about the instructions contained:
        # _var_to_definitions -- maps variables to a list of instructions defining them
        # _var_to_usages -- maps variables to a list of instructions utilizing them
        self._var_to_definitions: Dict[Variable, List[Instruction]] = {}
        self._var_to_usages: Dict[Variable, List[Instruction]] = {}
        self._graph: ControlFlowGraph = graph
        self._update()

    def __iter__(self) -> Iterator[Instruction]:
        """Iterate all instructions in the basic block."""
        yield from self._instructions

    def __str__(self) -> str:
        """Return a string representation of all instructions in the basic block."""
        return "\n".join((f"{instruction}" for instruction in self))

    def __repr__(self) -> str:
        """Return a debug representation of the block."""
        return f"BasicBlock({hex(self.address)}, len={len(self._instructions)})"

    def __eq__(self, other: object) -> bool:
        """Basic Blocks can be equal based on their contained instructions and addresses."""
        return isinstance(other, BasicBlock) and self._instructions == other._instructions and self._address == other._address

    def __hash__(self) -> int:
        """
        Basic Blocks should hash the same even then in different graphs.

        Since addresses are supposed to be unique,
        they are used for hashing in order to identify the same Block with different instruction as equal.
        """
        return hash(self._address)

    def __contains__(self, instruction) -> bool:
        """Check if the given instruction is contained in the basic block."""
        return instruction in self._instructions

    def __len__(self) -> int:
        """Return the amount of instructions in the basic block."""
        return len(self._instructions)

    def __getitem__(self, i: int) -> Instruction:
        """Return the instruction at index i."""
        return self._instructions[i]

    def __setitem__(self, i: int, instruction: Instruction):
        """Set the instruction at the given index."""
        self._instructions[i] = instruction
        self._update()

    @property
    def instructions(self) -> List[Instruction]:
        """Return a list of instructions."""
        return self._instructions

    @instructions.setter
    def instructions(self, instructions: List[Instruction]):
        """Set the list of instructions."""
        self._instructions = instructions
        self._update()

    @property
    def address(self) -> int:
        """Return the address of the block."""
        return self._address

    @property
    def name(self) -> int:
        """Return the 'name' of the block (legacy)."""
        return self._address

    @property
    def condition(self) -> ControlFlowType:
        """Return the effect of the block on the control flow."""
        if self._instructions and isinstance(self._instructions[-1], Branch):
            return self.ControlFlowType.conditional
        if self._instructions and isinstance(self._instructions[-1], IndirectBranch):
            return self.ControlFlowType.indirect
        return self.ControlFlowType.direct

    @property
    def definitions(self) -> Set[Variable]:
        """Return a set of all variables defined in the block."""
        return set(self._var_to_definitions.keys())

    @property
    def dependencies(self) -> Set[Variable]:
        """Return a set of all dependencies."""
        return set(self._var_to_usages.keys()) - set(self._var_to_definitions.keys())

    @property
    def variables(self) -> Set[Variable]:
        """Return a set of all variables contained in the instructions of the block."""
        return set(chain(self._var_to_definitions.keys(), self._var_to_usages.keys()))

    def copy(self) -> BasicBlock:
        """Return a deep copy of the node."""
        return BasicBlock(self._address, [instruction.copy() for instruction in self._instructions], graph=self._graph)

    def add_instruction(self, instruction: Instruction, index=-1) -> None:
        """Add an instruction at the end of at the given index."""
        self._instructions.insert(index if index >= 0 else len(self), instruction)
        self._update()

    def add_instruction_where_possible(self, instruction: Instruction) -> None:
        """Add an instruction at the first possible location."""
        if isinstance(instruction, GenericBranch):
            assert not isinstance(self._instructions[-1], GenericBranch), "There can only be one Branch instruction in a BasicBlock"
            return self.add_instruction(instruction)
        earliest_indices = [0]
        if not isinstance(instruction, Phi):
            earliest_indices = [
                max([index + 1 for index, instruction in enumerate(self._instructions) if isinstance(instruction, Phi)], default=0)
            ]
        if requirements := set(instruction.requirements) & set(self._var_to_definitions):
            required_definitions = [self.get_definitions(requirement) for requirement in requirements]
            wait_for = [instruction for defining_instructions in required_definitions for instruction in defining_instructions]
            earliest_indices.extend([self._instructions.index(instruction) + 1 for instruction in wait_for])
        self.add_instruction(instruction, max(earliest_indices))

    def remove_instruction(self, instruction: Union[int, Instruction]) -> None:
        """Remove the given instruction from the block."""
        if isinstance(instruction, Instruction):
            self._instructions.remove(instruction)
        elif isinstance(instruction, int):
            self._instructions.remove(self._instructions[instruction])
        else:
            raise ValueError(f"Invalid argument to remove_instruction {instruction}")
        self._update()

    def replace_instruction(self, replacee: Instruction, replacement: Union[Instruction, Sequence[Instruction]]):
        """Replace the given instruction with a list of instruction."""
        if isinstance(replacement, Instruction):
            self._instructions[self._instructions.index(replacee)] = replacement
        else:
            index: int = self._instructions.index(replacee)
            self._instructions = self._instructions[:index] + [x for x in replacement] + self._instructions[index + 1 :]
        self._update()

    def is_empty(self) -> bool:
        """Check if this basic block is empty."""
        return len(self._instructions) == 0

    def _update(self) -> None:
        """Update the definitions and dependencies of the block."""
        definitions: Dict[Variable, List[Instruction]] = {}
        dependencies: Dict[Variable, List[Instruction]] = {}
        for instruction in self._instructions:
            if isinstance(instruction, Assignment):
                for defined_value in instruction.definitions:
                    definitions[defined_value] = definitions.get(defined_value, []) + [instruction]
            for dependency in instruction.requirements:
                dependencies[dependency] = dependencies.get(dependency, []) + [instruction]
        # set internal structures and notify the graph
        self._var_to_definitions = definitions
        self._var_to_usages = dependencies
        if self._graph:
            self._graph.notify(self)

    def substitute(self, replacee: Expression, replacement: Expression) -> None:
        """Substitute the given expression by another in the entire block."""
        if replacee in self._instructions:
            self.replace_instruction(replacee, replacement)
        else:
            for instruction in self._instructions:
                instruction.substitute(replacee, replacement)
            self._update()

    def get_definitions(self, variable: Variable) -> List[Instruction]:
        """Return a list containing all definitions of the given variable in the block."""
        return self._var_to_definitions.get(variable, [])

    def get_usages(self, variable: Variable) -> List[Instruction]:
        """Return a list with all instructions utilizing the given variable."""
        return self._var_to_usages.get(variable, [])

    def subexpressions(self) -> Iterator[Union[Expression, Instruction]]:
        """Iterate all subexpressions in the block."""
        expressions: List[Expression] = []
        for instruction in self._instructions:
            yield instruction
            expressions.extend(instruction)
        while expressions and (head := expressions.pop()):
            yield head
            expressions.extend(head)
