"""Module defining the BasicBlock class utilized in ControlFlowGraphs."""

from __future__ import annotations

from enum import Enum
from itertools import chain
from typing import TYPE_CHECKING, Dict, Iterator, List, Sequence, Set, Union

from decompiler.structures.graphs.interface import GraphNodeInterface
from decompiler.structures.pseudo import Assignment, Branch, Expression, GenericBranch, IndirectBranch, Instruction, Phi, Variable

if TYPE_CHECKING:
    from decompiler.structures.graphs.cfg import ControlFlowGraph


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
        self._graph: ControlFlowGraph = graph

    def __iter__(self) -> Iterator[Instruction]:
        """Iterate all instructions in the basic block."""
        yield from self._instructions

    def __str__(self) -> str:
        """Return a string representation of the block"""
        # Note: Returning a string representation of all instructions here can be pretty expensive.
        # Because most code does not expect this, we choose to simply return the cheap repr instead.
        return repr(self)

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

    @property
    def instructions(self) -> List[Instruction]:
        """Return a list of instructions."""
        return self._instructions

    @instructions.setter
    def instructions(self, instructions: List[Instruction]):
        """Set the list of instructions."""
        self._instructions = instructions

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

    def copy(self) -> BasicBlock:
        """Return a deep copy of the node."""
        return BasicBlock(self._address, [instruction.copy() for instruction in self._instructions], graph=self._graph)

    def add_instruction(self, instruction: Instruction, index=-1) -> None:
        """Add an instruction at the end of at the given index."""
        self._instructions.insert(index if index >= 0 else len(self), instruction)

    def remove_instruction(self, instruction: Union[int, Instruction]) -> None:
        """Remove the given instruction from the block."""
        if isinstance(instruction, Instruction):
            self._instructions.remove(instruction)
        elif isinstance(instruction, int):
            self._instructions.remove(self._instructions[instruction])
        else:
            raise ValueError(f"Invalid argument to remove_instruction {instruction}")

    def replace_instruction(self, replacee: Instruction, replacement: Union[Instruction, Sequence[Instruction]]):
        """Replace the given instruction with a list of instruction."""
        if isinstance(replacement, Instruction):
            self._instructions[self._instructions.index(replacee)] = replacement
        else:
            index: int = self._instructions.index(replacee)
            self._instructions = self._instructions[:index] + [x for x in replacement] + self._instructions[index + 1 :]

    def is_empty(self) -> bool:
        """Check if this basic block is empty."""
        return len(self._instructions) == 0

    def substitute(self, replacee: Expression, replacement: Expression) -> None:
        """Substitute the given expression by another in the entire block."""
        if replacee in self._instructions:
            self.replace_instruction(replacee, replacement)
        else:
            for instruction in self._instructions:
                instruction.substitute(replacee, replacement)

    def subexpressions(self) -> Iterator[Union[Expression, Instruction]]:
        """Iterate all subexpressions in the block."""
        expressions: List[Expression] = []
        for instruction in self._instructions:
            yield instruction
            expressions.extend(instruction)
        while expressions and (head := expressions.pop()):
            yield head
            expressions.extend(head)
