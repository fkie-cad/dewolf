from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Set, Tuple

import networkx as nx
from networkx import DiGraph, is_directed_acyclic_graph
from pathlib import Path
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo import Expression, Operation, OperationType
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.instructions import Assignment, Phi
from decompiler.structures.pseudo.operations import UnaryOperation
from decompiler.util.decoration import DecoratedGraph
"""
TODO move this inside dependency_graph_from_cfg of decompiler/pipeline/ssa/dependency_graph.py
See
    commit  893c51aa9f6f62d94c36fd86e7b529aee2081317
    commit  bbe4e70d17c31f8dcea18a17bd6c2e002e25ca09
    file    decompiler/pipeline/ssa/conditional_out_of_SSA.py
    file    decompiler/pipeline/ssa/dependency_graph.py
    file    decompiler/pipeline/ssa/metric_dependency_graph.py
    file    decompiler/pipeline/ssa/variable_renaming.py

"""

class MetricHelper:

    @dataclass
    class _PlaceHolderEntry:
        id: Optional[int]
        ref: Optional[Variable] = None

    def __init__(self, cfg:ControlFlowGraph, build_decorated_cfgs: bool = False) -> None:
        self._decorated_dep: Optional[DecoratedGraph] = None
        self._decorated_dep_after: Optional[DecoratedGraph] = None 

        self._build_decorated_cfgs = build_decorated_cfgs
        self._placeholder: Dict[Variable, MetricHelper._PlaceHolderEntry] = dict()

        vars = set(self.variables_in_cfg(cfg))
        asigns = list(self.assignments_in_cfg(cfg))
        phi_vars = self._phi_vars(asigns)

        # set properties
        self._ssa_variable_count = len(vars)

        # build placeholders
        self._init_placeholder(vars)
        dependency_graph = self._build_dependency_graph(asigns)

        if self._build_decorated_cfgs:
            self._decorated_dep = self._build_decorated_cfg(dependency_graph) 

        #self._process_phi_vars(dependency_graph, phi_vars)
        self._process_sccs(dependency_graph)
        self._process_sinks(dependency_graph, phi_vars)

        if self._build_decorated_cfgs:
            self._decorated_dep_after = self._build_decorated_cfg(dependency_graph)


    def _init_placeholder(self, vars: Set[Variable]):
        for i, var in enumerate(vars):
            self._placeholder[var] = self._PlaceHolderEntry(i)


    def _find_root(self, var: Variable) -> Variable: 
        entry = self._placeholder[var]
        path = []
        while entry.ref:
            path.append(var)
            var = entry.ref
            entry = self._placeholder[var]

        for v in path:
            self._placeholder[v].ref = var

        return var 

    def _get_placeholder_id(self, var: Variable) -> Optional[int]: 
        entry = self._placeholder.get(self._find_root(var))
        if entry:
            return entry.id
        return None

    def _merge_placeholder(self, *vars: Variable) -> None:
        main_root = self._find_root(vars[0])

        for var in vars[1:]:
            root = self._find_root(var)
            if root == main_root:
                continue

            entry = self._placeholder[root]
            entry.ref = main_root
            entry.id = None

    def _phi_vars(self, asigns: List[Assignment]) -> List[Variable]:
        ret = []
        for asign in asigns: 
            if isinstance(asign, Phi):
                ret.append(asign.destination)

        return ret


    def _build_dependency_graph(self, asigns: List[Assignment]) -> DiGraph:
        """
        Build variable dependency edges: for assignment d := expr, add edges (d -> used_var)
        """
        edges = []
        dependency_graph = DiGraph()

        for assign in asigns:
            defined_variables = tuple(assign.definitions)
            used_vars = set(self.variables_in_expr(assign.value))
            for dvar in defined_variables:
                for u in used_vars:
                    edges.append((dvar, u))

        dependency_graph.add_edges_from(edges)
        return dependency_graph

    def _process_phi_vars(self, dependency_graph: DiGraph, phi_vars: List[Variable]):
        for var in phi_vars:
            if var in dependency_graph.nodes:
                for suc in dependency_graph.successors(var):
                    self._merge_placeholder(var, suc)


    def _process_sccs(self, dependency_graph: DiGraph) -> None:
        for scc in list(nx.strongly_connected_components(dependency_graph)):
            if len(scc) > 1:
                dependency_graph.remove_nodes_from(scc)
                self._merge_placeholder(*scc)

    def _calc_descendants_topo(self, dag: DiGraph) -> Tuple[Dict[Variable, Set[Variable]], Dict[Variable, int]]:
        topo = list(nx.topological_sort(dag))
        topo_index = {n:i for i,n in enumerate(topo)}

        descendants = dict() 
        for u in reversed(topo):
            descendants_u = set()
            for succ in dag.successors(u):
                descendants_u |= {succ}
                descendants_u |= descendants[succ]

            descendants[u] = descendants_u 
        return descendants, topo_index

    def _find_sink_for_var(self,var_successors: List[Variable], descendants: Dict[Variable, Set[Variable]], topo_index: Dict[Variable, int]) -> Optional[Variable]:
        inter = set()
        for succ in var_successors:
            inter &= descendants[succ]

        if inter:
            return min(inter, key=lambda x: topo_index[x])

        return None

    def _extract_nodes(self, dag: DiGraph, phi_var: Variable, sink_var:Variable) -> Set[Variable]:
        reachable_from_phi_var = set(nx.descendants(dag, phi_var))
        reachable_from_phi_var.add(phi_var)

        can_reach_sink_var = set(nx.ancestors(dag, sink_var))
        can_reach_sink_var.add(sink_var)

        return reachable_from_phi_var & can_reach_sink_var
    
    def _process_sinks(self, dependency_graph: DiGraph, phi_vars: List[Variable]):
        dependency_graph.remove_edges_from(nx.selfloop_edges(dependency_graph))
        wwc_graphs= [dependency_graph.subgraph(c) for c in nx.weakly_connected_components(dependency_graph)] #type: ignore
        wwc_descendants_topo = dict() 

        for phi_var in phi_vars:
            for i, wwc_graph in enumerate(wwc_graphs):
                if phi_var in wwc_graph.nodes:
                    descendants_topo = wwc_descendants_topo.get(i)
                    if not descendants_topo:
                        descendants_topo = self._calc_descendants_topo(wwc_graph) #type: ignore
                        wwc_descendants_topo[i] = descendants_topo

                    sink = self._find_sink_for_var(list(wwc_graph.successors(phi_var)), *descendants_topo) #type: ignore
                    if sink:
                        nodes = self._extract_nodes(wwc_graph, phi_var, sink) #type: ignore
                        if nodes:
                            self._merge_placeholder(*nodes)
                    break

    def _build_decorated_cfg(self, dependency_graph: DiGraph) -> DecoratedGraph:
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

        return DecoratedGraph(d)


    def vars_are_connected_strongly(self, a: Variable, b: Variable) -> bool:
        """
        Return True if a and b belong to the same SCC.
        If a is not present in the mapping, return False.
        """
        ref = self._get_placeholder_id(a)
        if ref is None:
            return False

        return ref == self._get_placeholder_id(b)

    @property
    def ssa_variable_count(self):
        return self._ssa_variable_count

    @staticmethod
    def variables_in_cfg(cfg: ControlFlowGraph) -> Iterator[Variable]:
        """
        Iterate once over instructions and yield variables found in subexpressions.
        """
        for instruction in cfg.instructions:
            for subexpression in instruction.subexpressions():
                if isinstance(subexpression, Variable) and not isinstance(subexpression, UnaryOperation):
                    yield subexpression

    @staticmethod
    def assignments_in_cfg(cfg: ControlFlowGraph) -> Iterator[Assignment]:
        for instr in cfg.instructions:
            if isinstance(instr, Assignment):
                yield instr

    @staticmethod
    def variables_in_expr(expr: Optional[Expression]) -> Iterator[Variable]:
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

    def _placeholder_to_str(self) -> str:
        placeholder_to_var = defaultdict(list)
        
        # Build mapping
        for var in self._placeholder.keys():
            pid = self._get_placeholder_id(var)
            placeholder_to_var[pid].append(var)
    
        lines = []
        for pid, vars_list in placeholder_to_var.items():
            grouped = [", ".join(f"{k.name}#{k.ssa_label}" for k in vars_list[i:i+20])
                for i in range(0, len(vars_list), 20)]
            formatted = "\n\t".join(grouped)
            lines.append(f"{pid}:\n\t{formatted}")
    
        return "\n".join(lines)


    def print(self) -> None:
        if not (self._decorated_dep_after and self._decorated_dep):
            raise RuntimeError("DecoratedGraph not build.")

        print('-'*100)
        print("Dependency Graph before:")
        print(self._decorated_dep.export_ascii())
        print("Dependency Graph after:")
        print(self._decorated_dep_after.export_ascii())
        print("PlaceHolder:")
        print(self._placeholder_to_str())
        print('-'*100)

    def export_plot(self, path: str) -> None:
        if not (self._decorated_dep_after and self._decorated_dep):
            raise RuntimeError("DecoratedGraph not build.")

        _path = Path(path)
        if not _path.is_dir():
            raise RuntimeError("Given path is not a directory.")

        self._decorated_dep.export_plot(str(_path / "dep_graph.png"))
        self._decorated_dep_after.export_plot(str(_path / "dep_graph_afer.png"))
        with open(_path / "placeholder.txt", 'w') as f:
            f.write(self._placeholder_to_str())
