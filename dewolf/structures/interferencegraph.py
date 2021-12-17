"""Class for the Interference Graph"""
from __future__ import annotations

from itertools import combinations
from typing import Iterable, List, Set, Tuple

from dewolf.pipeline.commons.livenessanalysis import LivenessAnalysis
from dewolf.structures.graphs.cfg import ControlFlowGraph
from dewolf.structures.pseudo.expressions import Variable
from dewolf.structures.pseudo.instructions import Instruction, Phi
from dewolf.util.insertion_ordered_set import InsertionOrderedSet
from networkx import Graph


class InterferenceGraph(Graph):
    def __init__(self, cfg: ControlFlowGraph = None):
        """
        Initialize the Interference Graph given a control flow graph.

        :param cfg: The control flow graph whose interference graph we want to construct.
        """
        super().__init__()
        if not cfg:
            cfg = ControlFlowGraph()
        self._construct_interference_graph(cfg)

    def are_interfering(self, *variables: Variable) -> bool:
        """Checks whether the given variables interfere."""
        return any(self.has_edge(variable_1, variable_2) for variable_1, variable_2 in combinations(variables, 2))

    def get_interfering_variables(self, *variables: Variable) -> Iterable[Tuple[Variable, Variable]]:
        """Returns all variable pairs that interfere in the given set of variables"""
        for variable_1, variable_2 in combinations(variables, 2):
            if self.has_edge(variable_1, variable_2):
                yield variable_1, variable_2

    def get_subgraph_of(self, variable_group: InsertionOrderedSet[Variable]) -> InterferenceGraph:
        """
        Computes the Interference graph that only has the vertices in 'variable_group' as vertices

        :param variable_group: The vertices whose subgraph we want to compute.
        :return: Returns the subgraph of the interference graph that contains exactly the variables (vertices) that are contained in the
        set 'variable_group'.
        """
        subgraph = InterferenceGraph()
        subgraph.add_nodes_from((node for node in variable_group if node in self.nodes))
        for node1, node2 in combinations(subgraph.nodes, 2):
            if self.are_interfering(node1, node2):
                subgraph.add_edge(node1, node2)
        return subgraph

    def contract_independent_set(self, variables: List[Variable]) -> None:
        """
        Contract the given set of variables if they are an independent set to a node with the given name. Otherwise, we raise an error.

        :param variables: Set of variables we want to contract.
        """
        remaining_variable = variables[0]
        for variable in variables[1:]:
            for neighbor in self.neighbors(variable):
                if neighbor == remaining_variable:
                    raise ValueError(f"The given set of variables is not an independent set. At least two variables interfere!")
                self.add_edge(remaining_variable, neighbor)
            self.remove_node(variable)

    def _construct_interference_graph(self, cfg: ControlFlowGraph) -> None:
        """
        Constructs the interference graph of a given control flow graph.

        :param cfg: The control flow graph whose interference graph we want to compute
        """
        liveness_analysis = LivenessAnalysis(cfg)
        self._create_interference(liveness_analysis.live_out_of(None))
        for basicblock in cfg:
            self._create_interference(liveness_analysis.live_in_of(basicblock))
            self._create_interference(liveness_analysis.live_out_of(basicblock))
            current_live_set = liveness_analysis.live_out_of(basicblock)
            non_phi_instructions = [i for i in basicblock.instructions if not isinstance(i, Phi)]
            for instruction in reversed(non_phi_instructions):
                current_live_set = self._update_interference_graph_live_set_regarding(instruction, current_live_set)

            dead_phi_function_definitions = liveness_analysis.defs_phi_of(basicblock) - liveness_analysis.live_in_of(basicblock)
            self._interference_graph_add_edges(dead_phi_function_definitions, liveness_analysis.live_in_of(basicblock))

    def _create_interference(self, variables: InsertionOrderedSet[Variable]) -> None:
        """
        Adds an edge between every pair of variables in the set 'variables' to the interference graph.

        :param variables: A set of variables that pairwise interfere with each other.
        """
        for var in variables:
            self.add_node(var)

        for first_variable, second_variable in combinations(variables, 2):
            self.add_edge(first_variable, second_variable)

    def _interference_graph_add_edges(self, new_variables: Set[Variable], current_variables: InsertionOrderedSet[Variable]) -> None:
        """
        Adds an edge between every variable in 'new_variables' and 'current_variables' to the interference graph,
        i.e., for each var_1 in new_variables and each var_2 in current_variables we add the edge (var_1, var_2) to the interference graph.
        Furthermore, for each pair of variables in `new_variables` we add an edge to the interference graph.

        :param new_variables: The set of variables that we add to the set of live variables.
        :param current_variables: The set of variables that were live.
        """
        for new_var in new_variables:
            self.add_node(new_var)
            for current_var in current_variables:
                self.add_edge(new_var, current_var)

        for new_var, current_var in combinations(new_variables, 2):
            self.add_edge(new_var, current_var)

    def _update_interference_graph_live_set_regarding(
        self, instruction: Instruction, current_live_set: InsertionOrderedSet[Variable]
    ) -> InsertionOrderedSet[Variable]:
        """
        This functions computes the set of variables that is live before instruction 'instruction' and adds an edge between all these
        variables.
        More precisely, we compute the set of variables (new_variables) that are live before the instruction but not after the instruction,
        and the set of variables that is no longer live before the instruction (removed_variables cap current_live_set). We have to be
        careful with variables that are not used and contained in 'removed_variables'. These are only live at this certain point.

        :param instruction: The instruction we consider.
        :param current_live_set: the set of variables that is live after instruction 'instruction'
        :return: The set of variables that are live before instruction 'instruction'
        """
        new_variables = InsertionOrderedSet(instruction.requirements) - current_live_set
        removed_variables = InsertionOrderedSet(instruction.definitions)
        if unused_variables := removed_variables - current_live_set:
            self._interference_graph_add_edges(unused_variables, current_live_set)
        current_live_set -= removed_variables
        if new_variables:
            self._interference_graph_add_edges(new_variables, current_live_set)
        current_live_set.update(new_variables)
        return current_live_set
