from __future__ import annotations

from itertools import combinations
from typing import Dict, Iterator, Set

from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.instructions import Assignment, Instruction
from decompiler.util.insertion_ordered_set import InsertionOrderedSet
from networkx import topological_sort


class ValueInterferenceGraph(InterferenceGraph):
    def __init__(self, cfg: ControlFlowGraph = None): #type: ignore
        """
        Initialize the Interference Graph given a control flow graph.

        :param cfg: The control flow graph whose interference graph we want to construct.
        """
        self._value_classes:Dict[Variable, Variable] = dict()
        self._build_variable_classes(cfg)
        super().__init__(cfg)

    def _is_copy_assignment(self, instr: Instruction) -> bool:
        if isinstance(instr, Assignment):
            if len(instr.definitions) == 1 and len(instr.requirements) == 1:
                if isinstance(instr.definitions[0], Variable) and isinstance(instr.requirements[0], Variable):
                    return True
        return False

    def _collect_variables(self, cfg: ControlFlowGraph) -> Iterator[Variable]:
        for instruction in cfg.instructions:
            for subexpression in instruction.subexpressions():
                if isinstance(subexpression, Variable):
                    yield subexpression

    def _build_variable_classes(self, cfg:ControlFlowGraph) -> None:
        for var in self._collect_variables(cfg):
            self._value_classes[var] = var

        basic_block: BasicBlock
        for basic_block in topological_sort(cfg.dominator_tree._graph): #type: ignore
            for instr in basic_block:
                if self._is_copy_assignment(instr):
                    self._value_classes[instr.definitions[0]] = self._value_classes[instr.requirements[0]]

    def _create_interference(self, variables: InsertionOrderedSet[Variable]) -> None:
        """
        Adds an edge between every pair of variables in the set 'variables' to the interference graph.

        :param variables: A set of variables that pairwise interfere with each other.
        """
        for var in variables:
            self.add_node(var)

        for first_variable, second_variable in combinations(variables, 2):
            if self._value_classes[first_variable] != self._value_classes[second_variable]:
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
                if self._value_classes[new_var] != self._value_classes[current_var]:
                    self.add_edge(new_var, current_var)

        for new_var, current_var in combinations(new_variables, 2):
            if self._value_classes[new_var] != self._value_classes[current_var]:
                self.add_edge(new_var, current_var)

