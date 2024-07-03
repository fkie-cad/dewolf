"""Module defining a control flow graph with the graph interface."""

from __future__ import annotations

from itertools import chain
from typing import Dict, Iterator, List, Optional, Set

from decompiler.structures.pseudo import Assignment, Condition, Expression, Instruction, Variable
from networkx import DiGraph

from ..pseudo.locations import InstructionLocation
from .basicblock import BasicBlock
from .branches import (
    BasicBlockEdge,
    BasicBlockEdgeCondition,
    ConditionalEdge,
    FalseCase,
    IndirectEdge,
    SwitchCase,
    TrueCase,
    UnconditionalEdge,
)
from .classifiedgraph import ClassifiedGraph


class ControlFlowGraph(ClassifiedGraph[BasicBlock, BasicBlockEdge]):
    """Class representing an control flow graph based on the base graph."""

    def __init__(self, graph: Optional[DiGraph] = None, root: Optional[BasicBlock] = None):
        """
        Init a new empty control flow graph.

        graph -- The DiGraph contained in the cfg. Can be used to create initialized graphs.
        root -- The root node of the graph.
        """
        super().__init__(graph, root)

    def __getitem__(self, address: int) -> BasicBlock:
        """Return a block at the given address."""
        for block in self:
            if block.address == address:
                return block
        raise ValueError(f"The CFG does not contain a block with address {address}!")

    def create_block(self, instructions: Optional[List[Instruction]] = None) -> BasicBlock:
        """Create a BasicBlock at an unique address."""
        address = -1
        addresses = {block.address for block in self}
        while address in addresses:
            address -= 1
        block = BasicBlock(address, instructions=instructions, graph=self)
        self.add_node(block)
        return block

    @property
    def instructions(self) -> Iterator[Instruction]:
        """Iterate all instructions in the basic block."""
        for block in self.nodes:
            yield from block

    @property
    def instruction_locations(self) -> Iterator[InstructionLocation]:
        for block in self.nodes:
            for index, _ in enumerate(block):
                yield InstructionLocation(block, index)

    def add_node(self, block: BasicBlock):
        """Add a node to the block, setting it as head if there is none defined."""
        assert isinstance(block, BasicBlock)
        block._graph = self
        super().add_node(block)

    def remove_node(self, block: BasicBlock):
        """Remove the given node from the graph, given it is not the head node."""
        super().remove_node(block)

    def remove_instruction(self, instruction: Instruction):
        """Remove the given instruction from the cfg once."""
        for block in self:
            if instruction in block:
                block.remove_instruction(instruction)
                break

    def subexpressions(self) -> Iterator[Expression]:
        """Iterate all subexpressions in the graph."""
        for edge in self.edges:
            yield from edge.subexpressions()
        for node in self:
            yield from node.subexpressions()

    def substitute_expression(self, replacee: Expression, replacement: Expression):
        """Substitute an expression in the complete cfg."""
        for basic_block in self:
            basic_block.substitute(replacee, replacement)
        for edge in self.edges:
            edge.substitute(replacee, replacement)

    def substitute_block(self, replacee: BasicBlock, replacement: BasicBlock):
        """Substitute one BasicBlock with another, maintaining edges."""
        in_edges = self.get_in_edges(replacee)
        out_edges = self.get_out_edges(replacee)
        self.remove_node(replacee)
        self.add_node(replacement)
        for edge in in_edges:
            new_edge = edge.copy(sink=replacement)
            self.add_edge(new_edge)
        for edge in out_edges:
            new_edge = edge.copy(source=replacement)
        self.add_edge(new_edge)

    def substitute_edge(self, replacee: BasicBlockEdge, replacement: BasicBlockEdge):
        """Replace a rich edge with another edge."""
        self.remove_edge(replacee)
        self.add_edge(replacement)

    def is_conditional_node(self, block: BasicBlock) -> bool:
        """Check if the given block ends with conditional branches."""
        return all([isinstance(edge, (TrueCase, FalseCase)) for edge in self.get_out_edges(block)])

    def is_switch_node(self, block: BasicBlock) -> bool:
        """Check whether the given block ends SwitchCases."""
        return all([isinstance(edge, SwitchCase) for edge in self.get_out_edges(block)])

    def copy(self) -> ControlFlowGraph:
        """Generate a copy of the current graph."""
        graph = super().copy()
        return graph
