"""Module implementing common subexpression elimination on ExpressionGraphs."""
from typing import Iterator, List

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.graphs.expressiongraph import ExpressionGraph
from decompiler.structures.pseudo import Expression, Variable
from decompiler.task import DecompilerTask


class EdgePruner(PipelineStage):
    """Class designed to remove common subexpressions from a given ControlFlowGraph."""

    name = "edge-pruner"

    options = {
        "minimum_occurrences": "The amount of occurrences a expression must reach to be eliminated.",
        "minimum_complexity": "The minimum complexity of an expression to be considered.",
        "threshold": "Minimum value for the product of occurrences and complexity for elimination.",
    }

    def __init__(self):
        """Create an DeadComponentPruner object based on the given graph."""
        self._i = 0
        self._min_occurrences: int = 0
        self._min_complexity: int = 0
        self._threshold: int = 0

    def run(self, task: DecompilerTask):
        """Run the DeadComponentPruner, removing dead instructions."""
        self._min_occurrences = task.options.getint(f"{self.name}.minimum_occurrences", fallback=2)
        self._min_complexity = task.options.getint(f"{self.name}.minimum_complexity", fallback=2)
        self._threshold = task.options.getint(f"{self.name}.threshold", fallback=5)
        self.prune(ExpressionGraph.from_cfg(task.graph), task.graph)

    def prune(self, graph: ExpressionGraph, cfg: ControlFlowGraph):
        """Remove all instructions not reachable from sink nodes from the given cfg."""
        candidates = sorted(self._find_candidates(graph), key=lambda x: x.complexity, reverse=True)
        while candidates and (candidate := candidates.pop()):
            if self.eliminate(cfg, candidate):
                candidates = self._filter_subexpressions(candidate, candidates)

    def eliminate(self, cfg: ControlFlowGraph, expression: Expression):
        """Eliminate the given subexpression from the graph by a new variable and add and definition to the cfg."""
        new_var = Variable(f"c{self._i}", vartype=expression.type, ssa_label=0)
        cfg.substitute_expression(expression, new_var)
        cfg.add_definition(new_var, expression)
        self._i += 1

    def _find_candidates(self, graph: ExpressionGraph) -> Iterator[Expression]:
        """Find candidates for elimination in the given ExpressionGraph."""
        for expression in graph.nodes:
            if expression.complexity >= self._min_complexity:
                dependencies = list(graph.predecessors(expression))
                if len(dependencies) >= self._min_occurrences and len(dependencies) * expression.complexity > self._threshold:
                    yield expression

    @staticmethod
    def _filter_subexpressions(filter_expression: Expression, candidates: Iterator[Expression]) -> List[Expression]:
        """Filter all subexpressions of the given subexpression from the list."""
        subexpressions = filter_expression.subexpressions()
        return [expression for expression in candidates if expression not in subexpressions]
