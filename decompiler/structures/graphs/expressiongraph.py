"""Module defining the ExpressionGraph used for various pipeline stages."""

from __future__ import annotations

from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo import BaseAssignment, Call, Expression, Instruction, ListOperation, OperationType, UnaryOperation
from networkx import DiGraph


class ExpressionGraph(DiGraph):
    """Graph based on the dependency relation between Expressions."""

    @classmethod
    def from_cfg(cls, cfg: ControlFlowGraph) -> ExpressionGraph:
        """Create an ExpressionGraph from the given ControlFlowGraph."""
        graph = cls()
        for instruction in cfg.instructions:
            graph.add_instruction(instruction)
        return graph

    def add_instruction(self, instruction: Instruction):
        """Add the given ssa-instruction to the ExpressionGraph."""
        if isinstance(instruction, BaseAssignment):
            for value in instruction.value if isinstance(instruction.value, ListOperation) else [instruction.value]:
                self.add_expression(value)
                self.add_edge(instruction, value)
            for definition in instruction.destination if isinstance(instruction.destination, ListOperation) else [instruction.destination]:
                self.add_expression(definition)
                self.add_edge(definition, instruction)
        else:
            self.add_expression(instruction)

    def add_expression(self, expression: Expression):
        """Add Expressions and their subexpressions to the graph recursively."""
        self.add_node(expression)
        for subexpression in expression:
            self.add_expression(subexpression)
            self.add_edge(expression, subexpression)

    def export(self) -> DiGraph:
        """Export a printable version of the graph."""
        buffer_graph = DiGraph()
        for start, end in self.edges:
            buffer_graph.add_node(hash(start), label=repr(start), **self.nodes[start])
            buffer_graph.add_node(hash(end), label=repr(end), **self.nodes[end])
            buffer_graph.add_edge(hash(start), hash(end))
        return buffer_graph

    @staticmethod
    def is_sink(node: Expression) -> bool:
        """Check whether the given Expression is a sink - e.g. can not be removed from the graph."""
        return (
            (isinstance(node, Instruction) and not isinstance(node, BaseAssignment))
            or (isinstance(node, BaseAssignment) and isinstance(node.value, Call))
            or (
                isinstance(node, BaseAssignment)
                and isinstance(node.destination, UnaryOperation)
                and node.destination.operation == OperationType.dereference
            )
        )
