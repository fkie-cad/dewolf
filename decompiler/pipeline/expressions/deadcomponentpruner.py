"""Module implementing Dead code elimination based on ExpressionGraphs."""
from typing import Iterator

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.graphs.expressiongraph import ExpressionGraph
from decompiler.structures.pseudo import Assignment, Call, Expression, Instruction, ListOperation, Variable
from decompiler.task import DecompilerTask
from networkx import dfs_tree


class DeadComponentPruner(PipelineStage):
    """Class designed to Remove dead components from a given ExpressionGraph."""

    name = "dead-component-pruner"

    def run(self, task: DecompilerTask):
        """Run the DeadComponentPruner, removing dead instructions."""
        self.prune(ExpressionGraph.from_cfg(task.graph), task.graph)

    def prune(self, graph: ExpressionGraph, cfg: ControlFlowGraph):
        """Remove all instructions not reachable from sink nodes from the given cfg."""
        alive = set(self._iter_alive_instructions(graph))
        for dead_expression in [node for node in graph.nodes if node not in alive]:
            if isinstance(dead_expression, Instruction):
                cfg.remove_instruction(dead_expression)
            elif isinstance(dead_expression, Variable):
                self._remove_variable(dead_expression, cfg)

    @staticmethod
    def _iter_alive_instructions(graph: ExpressionGraph) -> Iterator[Expression]:
        """Iterate all nodes reachable from sink instructions."""
        sink_instructions = [expression for expression in graph.nodes if graph.is_sink(expression)]
        for sink in sink_instructions:
            yield from dfs_tree(graph, source=sink)

    @staticmethod
    def _remove_variable(variable: Variable, cfg: ControlFlowGraph):
        """Remove the variable from the given graph, altering the definition if a call is involved."""
        for call_assignment in (
            definition for definition in cfg.get_definitions(variable) if isinstance(definition.value, Call)
        ):  # type: Assignment
            if call_assignment.destination == variable:
                call_assignment.substitute(variable, ListOperation([]))
            else:
                call_assignment.destination.operands.remove(variable)
