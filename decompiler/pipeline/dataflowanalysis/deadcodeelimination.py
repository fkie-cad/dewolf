"""Module implementing code elimination based on Hols et al."""

from collections import defaultdict, namedtuple
from typing import DefaultDict, Optional, Set

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.expressions import GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import Assignment, BaseAssignment, Instruction, Relation
from decompiler.structures.pseudo.operations import BinaryOperation, Call, ListOperation, OperationType, UnaryOperation
from decompiler.task import DecompilerTask
from networkx import DiGraph, dfs_tree

CfgPosition = namedtuple("CfgPosition", ["block", "index"])


class DependencyGraph(DiGraph):
    """Graph modeling the dataflow dependencies between variables."""

    SINK_LABEL = "sink"

    def __init__(self, cfg: ControlFlowGraph):
        """Generate a new dependency graph, containing a label representing sinks."""
        super().__init__()
        self._cfg: ControlFlowGraph = cfg
        self._points_to: DefaultDict[Variable, Set[str]] = defaultdict(set)
        self.add_node(self.SINK_LABEL)

    @classmethod
    def from_cfg(cls, cfg: ControlFlowGraph):
        """Generate a dependency graph based on the given cfg."""
        graph = cls(cfg)
        for block in cfg:
            for index, instruction in enumerate(block.instructions):
                graph.add_instruction(instruction, CfgPosition(block, index))
        return graph

    def add_instruction(self, instruction: Instruction, position: CfgPosition):
        """Add the given instruction to the dependency graph."""
        if self._is_sink(instruction):
            self._mark_as_sink(instruction)
        if isinstance(instruction, BaseAssignment):
            self._add_assignment(instruction, position)
        self._handle_pointers(instruction, position)

    def _handle_pointers(self, instruction: Instruction, position: CfgPosition):
        """Handle the pointers in the given instruction at the given location."""
        required_pointers = [requirement for requirement in instruction.requirements if requirement in self._points_to]
        # if the instruction is an assignment ..
        if isinstance(instruction, BaseAssignment):
            # .. check whether it assigns an address of a variable to a pointer
            if self._is_pointer_assignment(instruction):
                if not isinstance(instruction.value.operand, BinaryOperation):
                    self._points_to[instruction.destination].add(instruction.value.operand.name)
            # .. and propagate the _points_to property to the destination value
            for required_pointer in required_pointers:
                self._points_to[instruction.destination].update(self._points_to[required_pointer])
        # for each used variable which points to another variable ..
        for required_pointer in required_pointers:
            for pointee_name in self._points_to[required_pointer]:
                if pointee := self._get_latest_pointee(pointee_name, position):
                    # .. add edges to the latest pointee values
                    self.add_edge(str(required_pointer), str(pointee))

    def _mark_as_sink(self, instruction: Instruction):
        """Mark the given instruction as a sink by creating an edge."""
        for dependency in instruction.requirements:
            self.add_edge(self.SINK_LABEL, str(dependency))
        if isinstance(instruction, Relation):
            self.add_edge(self.SINK_LABEL, str(instruction.destination))

    def _add_assignment(self, assignment: BaseAssignment, position: CfgPosition):
        """
        Add the dataflow dependency information represented by the given assignment.

        Also, adds cross-edges between descendants of variables with the same name if they are aliased.
        """
        for defined_variable in assignment.definitions:
            self.add_node(str(defined_variable), instruction=assignment, position=position)
            for required_variable in assignment.requirements:
                self.add_edge(str(defined_variable), str(required_variable))
            if isinstance(defined_variable, GlobalVariable):
                self.add_edge(self.SINK_LABEL, str(defined_variable))

    def find_dead_variables(self) -> Set[str]:
        """Iterate all dead variables in the graph based on their name to prevent type mismatches."""
        sink_connected_components = set(dfs_tree(self, source=self.SINK_LABEL).nodes)
        return set([x for x in self.nodes - {"sink"} if "instruction" in self.nodes[x] and x not in sink_connected_components])

    def _get_latest_pointee(self, varname: str, position: CfgPosition) -> Optional[Variable]:
        """Get the most recently defined variable with the given name at the given location."""
        visited = set()
        todo = [position.block]
        while todo and (head := todo.pop()):
            visited.add(head)
            for instruction in reversed(head.instructions if head != position.block else head.instructions[: position.index]):
                for defined_value in instruction.definitions:
                    if varname in str(defined_value):
                        return defined_value
            todo.extend((predecessor for predecessor in self._cfg.get_predecessors(head) if predecessor not in visited))

    @staticmethod
    def _is_sink(instruction: Instruction) -> bool:
        """Check if the given instruction is a sink."""
        if not isinstance(instruction, Assignment):
            return True
        return any(
            (
                isinstance(instruction.value, Call),
                isinstance(instruction.destination, UnaryOperation) and instruction.destination.operation == OperationType.dereference,
            )
        )

    @staticmethod
    def _is_pointer_assignment(assignment: BaseAssignment) -> bool:
        """Check if the given assignment assigns an address of an variable."""
        return isinstance(assignment.value, UnaryOperation) and assignment.value.operation == OperationType.address


class DeadCodeElimination(PipelineStage):
    """Implements dead code elimination based on graph reachablity"""

    name = "dead-code-elimination"

    def __init__(self):
        """Create a new DeadCodeElimination instance remembering all altered call instructions."""
        self._replaced_calls = set()

    def run(self, task: DecompilerTask):
        """Execute the PipelineStage on the current ControlFlowGraph."""
        dependency_graph = DependencyGraph.from_cfg(task.graph)
        for dead_variable in (dead_variables := dependency_graph.find_dead_variables()):
            self.remove_dead_variable(dead_variable, dependency_graph, dead_variables)

    def remove_dead_variable(self, variable: str, dependency_graph: DependencyGraph, dead_variables: Set[str]):
        """Remove the given dead variable with information provided by the dependency graph."""
        instruction = dependency_graph.nodes[variable]["instruction"]
        if not isinstance(instruction.value, Call):
            dependency_graph.nodes[variable]["position"].block.remove_instruction(instruction)
        elif instruction not in self._replaced_calls:
            dependency_graph.nodes[variable]["position"].block.replace_instruction(
                instruction, [self._get_replacement_call_for_dead_variable_assignment(dead_variables, instruction)]
            )
            self._replaced_calls.add(instruction)

    @staticmethod
    def _get_replacement_call_for_dead_variable_assignment(dead_variables: Set[str], assignment: Assignment) -> Assignment:
        """generate a replacement assignment for the given call, considering dead return values."""
        if isinstance(assignment.destination, Variable) or (
            isinstance(assignment.destination, ListOperation)
            and all([str(operand) in dead_variables for operand in assignment.destination])
        ):
            return Assignment(ListOperation([]), assignment.value.copy())
        return assignment
