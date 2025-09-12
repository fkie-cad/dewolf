from typing import Dict, Iterator, Optional, Set

import networkx as nx
from networkx import DiGraph
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo import Expression, Operation, OperationType
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.instructions import Assignment
from decompiler.structures.pseudo.operations import UnaryOperation
from decompiler.util.decoration import DecoratedGraph

class MetricDependencyGraph:
    """
    Build a dependency graph (variables -> used variables), compute SCCs,
    and expose convenience helpers for checking whether variables share SCCs.
    """
    def __init__(self, cfg: ControlFlowGraph, build_decorated_cfg: bool = False) -> None:
        self._ssa_to_scc: Dict[Variable, int] = {}
        self.decorated_graph: Optional[DecoratedGraph] = None

        dependency_graph = self._build_dependency_graph(cfg)
        if build_decorated_cfg:
            self._build_decorated_cfg(dependency_graph)

        self._init_components(dependency_graph)

 
    def _build_dependency_graph(self, cfg: ControlFlowGraph) -> DiGraph:
        """
        Build variable dependency edges: for assignment d := expr, add edges (d -> used_var)
        """
        dependency_graph = DiGraph()
        variables: Set[Variable] = set(self._collect_variables(cfg))
        dependency_graph.add_nodes_from(variables)

        edges = []
        for assign in self._assignments_in_cfg(cfg):
            defined_variables = tuple(assign.definitions)
            used_vars = set(self._used_variables(assign.value))
            for dvar in defined_variables:
                for u in used_vars:
                    edges.append((dvar, u))

        dependency_graph.add_edges_from(edges)
        return dependency_graph


    def _build_decorated_cfg(self, dependency_graph: DiGraph) -> None:
        """
        Build a small DiGraph for exporting/plotting.
        """
        d = DiGraph()
        mapping = {}
        for idx, node in enumerate(dependency_graph.nodes()):
            node_id = f"n{idx}"
            mapping[node] = node_id
            d.add_node(node_id, label=str(node))

        for u, v in dependency_graph.edges():
            d.add_edge(mapping[u], mapping[v])

        self.decorated_graph = DecoratedGraph(d)

    def _init_components(self, dependency_graph: DiGraph) -> None:
        """
        Compute SCCs and populate _ssa_to_scc mapping.
        Uses enumerate for predictable ordering; logs results rather than printing.
        """
        idx:int  = 0
        for scc in nx.strongly_connected_components(dependency_graph):
            for v in scc:
                self._ssa_to_scc[v] = idx
            idx += 1

   
    def _used_variables(self, expr: Optional[Expression]) -> Iterator[Variable]:
        """
        Yield Variables used inside expr. Non-recursive stack-based traversal to avoid deep recursion.
        Skip specific operation types that we don't want to inspect.
        """

        skip_ops = {
            OperationType.call,
            OperationType.address,
            OperationType.dereference,
            OperationType.member_access,
        }

        stack = [expr]
        while stack:
            node = stack.pop()
            if isinstance(node, Variable) and not isinstance(node, UnaryOperation):
                yield node
            elif isinstance(node, Operation) and node.operation not in skip_ops:
                stack.extend(node.operands)

    def _collect_variables(self, cfg: ControlFlowGraph) -> Iterator[Variable]:
        """
        Iterate once over instructions and yield variables found in subexpressions.
        """
        for instruction in cfg.instructions:
            for subexpression in instruction.subexpressions():
                if isinstance(subexpression, Variable) and not isinstance(subexpression, UnaryOperation):
                    yield subexpression

    def _assignments_in_cfg(self, cfg: ControlFlowGraph) -> Iterator[Assignment]:
        for instr in cfg.instructions:
            if isinstance(instr, Assignment):
                yield instr


    def vars_are_connected_strongly(self, a: Variable, b: Variable) -> bool:
        """
        Return True if a and b belong to the same SCC.
        If a is not present in the mapping, return False.
        """
        ref = self._ssa_to_scc.get(a)
        if ref is None:
            return False

        return ref == self._ssa_to_scc.get(b)

    def export_ascii(self) -> str:
        if not self.decorated_graph:
            raise RuntimeError("DecoratedGraph not build.")

        return self.decorated_graph.export_ascii()

    def print(self) -> None:
        print(self.export_ascii())

    def plot(self, path: str) -> None:
        if not self.decorated_graph:
            raise RuntimeError("DecoratedGraph not build.")

        self.decorated_graph.export_plot(path)
