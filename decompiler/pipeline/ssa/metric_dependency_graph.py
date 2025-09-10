from typing import Iterator, List

from networkx import DiGraph
from networkx.algorithms.components import strongly_connected_components
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.expressions import Expression, Variable
from decompiler.structures.pseudo.instructions import Assignment
from decompiler.structures.pseudo.operations import Operation, OperationType


class MetricDependencyGraph:

    def __init__(self, cfg: ControlFlowGraph) -> None:
        self._map = dict()

        dep_graph = DiGraph()
        for var in self._collect_variables(cfg):
           dep_graph.add_node(var) 

        for assg in self._assignments_in_cfg(cfg):
            defined_variables = assg.definitions
            for dep in self._expression_dependencies(assg.value):
                dep_graph.add_edges_from((((dvar,), (dep,)) for dvar in defined_variables))

        idx = 0
        for scc in strongly_connected_components(dep_graph):
            for v in scc:
                self._map[v] = idx
            idx += 1



    def test(self, a: Variable, b: Variable) -> bool:
        if ref := self._map.get(a):
            return ref == self._map.get(b)

        return False


    def _collect_variables(self, cfg: ControlFlowGraph) -> Iterator[Variable]:
        for instruction in cfg.instructions:
            for subexpression in instruction.subexpressions():
                if isinstance(subexpression, Variable):
                    yield subexpression

    def _assignments_in_cfg(self, cfg: ControlFlowGraph) -> Iterator[Assignment]:
        for instr in cfg.instructions:
            if isinstance(instr, Assignment):
                yield instr


    def _expression_dependencies(self, e: Expression) -> Iterator[Expression]:
        stack:List[Expression] = [e]
        opertation_types = {
            OperationType.call,
            OperationType.address,
            OperationType.dereference,
            OperationType.member_access,
        }
        while len(stack): 
            expression = stack.pop()
            match expression:
                case Variable():
                    yield expression
                case Operation():
                    if expression not in opertation_types:
                        for operand in expression.operands:
                            stack.extend(operand)
