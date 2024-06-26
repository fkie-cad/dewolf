"""Module implementing the DeadLoopElimination pipeline stage."""

from logging import info, warning
from typing import Dict, Generator, Optional, Tuple, Union

from decompiler.pipeline.preprocessing.util import _init_basicblocks_of_definition, init_maps
from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.graphs.interface import GraphEdgeInterface, GraphInterface
from decompiler.structures.maps import DefMap, UseMap
from decompiler.structures.pseudo.delogic_logic import DelogicConverter
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Branch, GenericBranch, IndirectBranch, Phi
from decompiler.structures.pseudo.logic import BaseConverter
from decompiler.structures.pseudo.operations import Condition
from decompiler.structures.pseudo.z3_logic import Z3Converter
from decompiler.task import DecompilerTask

from .dead_path_elimination import DeadPathElimination


class DeadLoopElimination(DeadPathElimination, PipelineStage):
    """
    Removes dead loops from a control flow graph.
    Edge removal functionality is taken from DeadPathElimination.
    """

    name = "dead-loop-elimination"

    def __init__(self):
        """Initialize a new loop elimination."""
        self._logic_converter: BaseConverter = Z3Converter()
        self._use_map: Optional[UseMap] = None
        self._def_map: Optional[DefMap] = None
        self._bb_of_def: Optional[Dict[Variable, BasicBlock]] = None
        self._dom_tree: Optional[GraphInterface] = None
        self._timeout: Optional[int] = None

    def run(self, task: DecompilerTask) -> None:
        """Run dead loop elimination on the given task object."""
        self._timeout = task.options.getint(f"{self.name}.timeout_satisfiable")
        engine = task.options.getstring("logic-engine.engine")  # choice of z3 or delogic
        if engine == "delogic":
            self._logic_converter = DelogicConverter()
        if not task.graph.root:
            warning(f"[{self.__class__.__name__}] Can not detect dead blocks because the cfg has no head.")
            return
        self._dom_tree = task.graph.dominator_tree
        self._def_map, self._use_map = init_maps(task.graph)
        self._bb_of_def = _init_basicblocks_of_definition(task.graph)
        if not (dead_edges := set(self.find_prunable_edges(task.graph))):
            return
        self._remove_dead_edges(task.graph, dead_edges)

    def find_prunable_edges(self, graph: ControlFlowGraph) -> Generator[GraphEdgeInterface, None, None]:
        """Iterate all dead branches in the given control flow graph."""
        for branch_block in [node for node in graph if graph.out_degree(node) > 1]:
            branch_instruction = branch_block.instructions[-1]
            assert isinstance(branch_instruction, GenericBranch), f"Branching basic block without branch instruction at {branch_block.name}"
            if isinstance(branch_instruction, IndirectBranch):
                continue
            if dead_edge := self._get_prunable_branch_edge(graph, branch_block, branch_instruction):
                yield dead_edge

    def _get_prunable_branch_edge(self, graph: ControlFlowGraph, block: BasicBlock, instruction: Branch) -> Optional[GraphEdgeInterface]:
        """
        Check if branch edge is prunable by
         * check if condition depends on phi-functions
         * extract constants that were propagated into phi-functions (we need ExpressionPropagation stage beforehand)
         * if multiple constants exits in one phi function, check if we got an unique upstream constant
         * check if current block dominates all other SSA-variables of phi-function
         * replace branch condition operands by the resolved constants
         * evaluate condition with z3
         * if one branch edge is unsatisfiable on first visit
           and we can never reach the current block again when
           we follow the satisfiable edge: we mark the unsatisfiable edge as prunable.
        """
        if not (phi_dependencies := self._get_phi_dependency_of_branch_condition(instruction)):
            return None
        substituted_constants = self._resolve_phi_values(phi_dependencies, block)
        patched_condition = self._get_patched_condition(instruction, substituted_constants)
        if sat_unsat_edges := self._evaluate_branch_condition(graph, block, patched_condition):
            sat_edge, unsat_edge = sat_unsat_edges
            # check reachability of current block
            if not graph.has_path(sat_edge.sink, sat_edge.source):  # we never come back
                return unsat_edge
        return None

    def _evaluate_branch_condition(
        self, graph: ControlFlowGraph, block: BasicBlock, condition: Condition
    ) -> Optional[Tuple[GraphEdgeInterface, GraphEdgeInterface]]:
        """
        Evaluate Branch.condition with z3 and return (satisfiable edge, unsatisfiable edge) if one edge is unsatisfiable.
        """
        try:
            condition = self._logic_converter.convert(condition, define_expr=True)
        except ValueError as value_error:
            warning(f"[{self.__class__.__name__}] {str(value_error)}")
            return None
        out_edges = graph.get_out_edges(block)
        assert len(out_edges) == 2, "expect two edges for Branch"
        sat_edge, unsat_edge = None, None
        for edge in out_edges:
            # we need one sat and one unsat edge for pruning
            if self._is_invalid_edge(edge, condition):
                assert not unsat_edge, "two unsat branches on first visit"
                unsat_edge = edge
            else:
                sat_edge = edge
        return (sat_edge, unsat_edge) if unsat_edge else None

    def _get_phi_dependency_of_branch_condition(self, branch: Branch) -> Dict[Variable, Phi]:
        """
        If Branch condition depends on a phi-function return mapping of Variable:Phi
        :param branch -- Branch instruction
        :return: Dictionary mapping Variables in Branch.requirement to Phi
        """
        phi_dependencies = {}
        for requirement in branch.requirements:
            if requirement.is_aliased:
                continue  # skip if aliased
            location = self._def_map.get(requirement)
            if location is not None and isinstance(location.instruction, Phi):
                phi_dependencies[requirement] = location.instruction
        return phi_dependencies

    def _resolve_phi_values(self, dependency_dict: Dict[Variable, Phi], block: BasicBlock) -> Dict[Variable, Union[Variable, Constant]]:
        """
        In a mapping of Variable -> Phi try to replace Phi with a Constant,
        where Constant is a possible and unique upstream Value of the given phi-function.
        :param dependency_dict -- mapping of variable to its assigned phi-function
        :param block -- current basic block
        :return: Mapping of variable to its resolved constant where possible
        """
        resolved_consts = {}
        for requirement, phi in dependency_dict.items():
            if const := self._get_unique_upstream_value(phi, block):
                resolved_consts[requirement] = const
        return resolved_consts

    def _get_unique_upstream_value(self, phi: Phi, block: BasicBlock) -> Optional[Union[Variable, Constant]]:
        """
        If phi-function contains a unique upstream value (constant/variable) return this value.
        :param phi -- Phi-function to extract upstream value from
        :param block -- current BasicBlock
        :return: If phi contains unique upstream value return it
        """
        unique_upstream_value = None
        if not phi.origin_block:
            info("missing origin_block property in Phi (skipping)")
            return None
        for var_block, var in phi.origin_block.items():
            if not (isinstance(var, Constant) or isinstance(var, Variable)):
                continue
            if var_block == block or not self._dom_tree.has_path(block, var_block):
                if not unique_upstream_value:
                    unique_upstream_value = var
                else:
                    info("phi contains more than one upstream value (skipping)")
                    return None
        return unique_upstream_value

    def _get_patched_condition(self, instruction: Branch, const_dict: Dict[Variable, Constant]) -> Condition:
        """
        For a given Branch instruction with mapping Variable -> Constant,
        replace (in a copy) all occurrences of variables in Branch.condition with their resolved Constant.
        :return: new Condition
        """
        patched_condition = instruction.condition.copy()
        for var, const in const_dict.items():
            patched_condition.substitute(var, const)
        return patched_condition
