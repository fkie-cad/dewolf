"""Module implementing horizontal type propagation as a pipeline stage."""
from __future__ import annotations

from collections import Counter, defaultdict
from enum import Enum
from itertools import chain
from logging import info
from typing import DefaultDict, Iterator, List, Set, Tuple

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.expressions import Expression, Variable
from decompiler.structures.pseudo.instructions import BaseAssignment, Instruction
from decompiler.structures.pseudo.typing import CustomType, Float, Integer, Pointer, Type, UnknownType
from decompiler.task import DecompilerTask
from networkx import DiGraph, Graph, connected_components


class TypeGraph(DiGraph):
    """Graph class modeling type-relations between expressions."""

    class EdgeType(Enum):
        """A enumerator for type labels utilized in TypeGraph."""

        assignment = 0
        subexpression = 1

    def __init__(self, **attr):
        """Generate a new TypeGraph, appending a dict for usage tracking."""
        super().__init__(**attr)
        self._usages: DefaultDict[Expression, Set] = defaultdict(set)

    @classmethod
    def from_cfg(cls, cfg: ControlFlowGraph) -> TypeGraph:
        """Generate a TypeGraph by parsing the given ControlFlowGraph."""
        graph = cls()
        for instruction in cfg.instructions:
            graph.add_instruction(instruction)
        return graph

    def add_instruction(self, instruction: Instruction) -> None:
        """Add the given instruction to the TypeGraph."""
        for top_level_expression in instruction:
            self.add_expression(top_level_expression, instruction)
        if isinstance(instruction, BaseAssignment):
            self.add_edge(self._make_node(instruction.destination), self._make_node(instruction.value), label=self.EdgeType.assignment)

    def add_expression(self, expression: Expression, parent: Instruction):
        """
        Add the given expression to the TypeGraph, remembering their usages and variables.

        expression -- The expression to be added to the  graph.
        parent -- The instruction utilizing the given expression.
        """
        todo = [expression]
        while todo:
            head = todo.pop()
            self.add_node(self._make_node(head), **{str(id(head)): head})
            self._usages[self._make_node(head)].add(parent)
            children = list(head)
            todo.extend(children)
            for sub_expression in children:
                self.add_edge(self._make_node(sub_expression), self._make_node(head), label=self.EdgeType.subexpression)

    def iter_equivalence_groups(self) -> Iterator[List[Expression]]:
        """Iterate ann groups connected by equivalence relations."""
        equivalence_edges = [(start, end) for start, end, data in self.edges(data=True) if data["label"] == self.EdgeType.assignment]
        equivalence_subgraph = self._undirected_edge_subgraph(equivalence_edges)
        for equivalence_group in connected_components(equivalence_subgraph):
            yield list(chain.from_iterable((self.nodes[node].values() for node in equivalence_group)))

    def _undirected_edge_subgraph(self, edges: List[Tuple[Expression, Expression]]) -> Graph:
        """Generate an undirected subgraph ferom the given list of edges."""
        graph = Graph()
        graph.add_edges_from(edges)
        return graph

    def __iter__(self) -> Iterator[List[Expression]]:
        """Iterate all expressions contained in the graph."""
        for node in self:
            yield self.nodes[node].values()

    @staticmethod
    def _make_node(expression: Expression):
        if isinstance(expression, Variable):
            return expression.name
        return id(expression)


class TypePropagation(PipelineStage):
    """Implements type propagation based on a set of heuristics."""

    name = "type-propagation"

    def run(self, task: DecompilerTask):
        """
        Run type propagation on the given task object.

        We assume there are two types of propagation: Assignment (horizontal) and Operation (vertical).
        Operation-Level propagation is directly implemented into pseudo.Operands through a recursive lookup.
        """
        graph = TypeGraph.from_cfg(task.graph)
        self.propagate(graph)

    def propagate(self, graph: TypeGraph):
        """Implement horizontal propagation among equivalence classes."""
        types = set()
        for equivalence_group in graph.iter_equivalence_groups():
            common_type = self._get_common_type(equivalence_group)
            types.add(common_type)
            self._propagate_type(graph, equivalence_group, common_type)
        info(f"[{self.name}]Propagated {len(types)} different types")

    @staticmethod
    def _propagate_type(graph: TypeGraph, expressions: List[Expression], type: Type):
        """Propagate the given type into the given set of expressions."""
        for expression in expressions:
            if hasattr(expression, "_type"):
                expression._type = type

    @staticmethod
    def _get_common_type(expressions: List[Expression]) -> Type:
        """Get the common type for the given set of expressions."""
        histogram = Counter((expression.type for expression in expressions))
        most_common_types = sorted(histogram.keys(), reverse=True, key=lambda x: (histogram[x], str(x)))
        if UnknownType() in most_common_types:
            most_common_types.remove(UnknownType())
        for filtered_type in filter(TypePropagation._is_non_primitive_type, most_common_types):
            return filtered_type
        if most_common_types:
            return most_common_types[0]
        return UnknownType()

    @staticmethod
    def _is_non_primitive_type(type: Type) -> bool:
        """Check if the given type is primitive, so ew can ignore it."""
        if isinstance(type, Integer) and not isinstance(type, Float):
            return False
        if isinstance(type, Pointer) and type.type == CustomType.void():
            return False
        return True
