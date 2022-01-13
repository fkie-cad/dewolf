from typing import Dict, List

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.expressiongraph import ExpressionGraph
from decompiler.structures.pseudo import Constant, Expression, Instruction, Operation, Phi, Variable
from decompiler.task import DecompilerTask


class GraphExpressionFolding(PipelineStage):
    """Class defining a combination of expression-propagation and dead code elimination."""

    name = "graph-expression-folding"

    def __init__(self):
        """Create an empty GraphExpressionFolding object."""
        self._task: DecompilerTask = None
        self._graph: ExpressionGraph = None
        self._substitutions: Dict[Expression, Expression] = {}

    def run(self, task: DecompilerTask):
        """Run the pipeline stage, generating an ExpressionGraph."""
        self._task = task
        self._graph = ExpressionGraph.from_cfg(task.graph)
        self._substitutions = {}
        self.fold()

    def fold(self):
        """Fold identity groups onto a single expression."""
        self._find_identities()
        self._apply_substitutions()

    def _find_identities(self):
        """Find the identity groups in the graph, returning a dict with substitutions."""
        todo = [node for node in self._graph if isinstance(node, Variable)]
        while todo and (head := todo.pop()):
            group = self._explore_identity_group(head)
            todo = [x for x in todo if x not in group]
            self._handle_identity_group(group)

    def _explore_identity_group(self, expression: Expression) -> List[Expression]:
        """Explore the identity group the given expression belongs to, returning a list."""
        group = []
        todo = [expression]
        while todo and (head := todo.pop()):
            group.append(head)
            if isinstance(head, Operation):
                continue
            todo.extend([x for x in self._graph.successors(head) if not isinstance(x, Phi)])
        return group

    def _handle_identity_group(self, group: List[Expression]):
        """Handle the identity group, removing instructions and yielding substitution tuples."""
        if len(group) == 1:
            return
        identity = self._find_identity(group)
        for expression in group:
            if isinstance(expression, Instruction):
                self._task.graph.remove_instruction(expression)
            elif expression != identity:
                self._substitutions[expression] = identity

    def _find_identity(self, group: List[Expression]):
        """Return the identity of the given group of expressions."""
        if operations := list(filter(lambda x: isinstance(x, Operation), group)):
            assert len(operations) == 1
            return operations[0]
        if params := list(filter(lambda x: x in self._task.function_parameters, group)):
            return params[0]
        if constants := list(filter(lambda x: isinstance(x, Constant), group)):
            assert len(constants) == 1
            return constants[0]
        if identities := [self._substitutions[x] for x in group if x in self._substitutions]:
            return identities[0]
        return group[-1]

    def _apply_substitutions(self):
        """Apply the given directory containing substitutions."""
        for replacee, replacement in self._substitutions.items():
            for dependency in (dependency for dependency in replacement.requirements if dependency in self._substitutions):
                replacement.substitute(dependency, self._substitutions[dependency])
            self._task.graph.substitute_expression(replacee, replacement)
