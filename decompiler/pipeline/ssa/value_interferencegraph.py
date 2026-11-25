"""Module for the value based interference graph of the Boissinot et al. Out of SSA."""

from __future__ import annotations

from itertools import combinations
from typing import Dict, Iterator, Set

from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import Assignment, Instruction
from decompiler.util.insertion_ordered_set import InsertionOrderedSet
from networkx import topological_sort


def can_be_in_same_class(variable_1: Variable, variable_2: Variable) -> bool:
    """
    Returns True if the two variables may be in the same class, False otherwise.

    The criteria are:
        - Global variables and normal variables do not get mixed.
        - Global variables in one class have to have the same name.
        - The type of all variables in one class has to be identical.
        - The variables either have to be all aliased or all non-aliased.
        - If both variables are aliased they have to have the same name.
    """
    if isinstance(variable_1, GlobalVariable) and isinstance(variable_2, GlobalVariable) and (variable_1.name != variable_2.name):
        return False
    elif isinstance(variable_1, GlobalVariable) != isinstance(variable_2, GlobalVariable):
        return False
    elif variable_1.type != variable_2.type:
        return False
    elif variable_1.is_aliased != variable_2.is_aliased:
        return False
    elif variable_1.is_aliased and variable_2.is_aliased and (variable_1.name != variable_2.name):
        return False
    return True


class ValueInterferenceGraph(InterferenceGraph):
    """
    Interference graph where variables with the same value do not interfere.

    Two variables are not connected by an edge if one is a copy of the other and they can be in the same class
    (see can_be_in_same_class), despite possible live range interference.
    """

    def __init__(self, cfg: ControlFlowGraph = None):  # type: ignore
        """
        Initialize the Interference Graph given a control flow graph. Inserts edges between all variables interfering by our definition of
        interference (see function can_be_in_same_class).

        :param cfg: The control flow graph whose interference graph we want to construct.
        """
        self._value_classes: Dict[Variable, Variable] = dict()
        self._build_variable_classes(cfg)
        super().__init__(cfg)

    def _is_copy_assignment(self, instruction: Instruction) -> bool:
        """Returns True if the instruction is an assignment between two variables."""
        return (
            isinstance(instruction, Assignment)
            and isinstance(instruction.value, Variable)
            and isinstance(instruction.destination, Variable)
        )

    def _collect_variables(self, cfg: ControlFlowGraph) -> Iterator[Variable]:
        """Yields all variables present in the given control flow graph."""
        for instruction in cfg.instructions:
            for subexpression in instruction.subexpressions():
                if isinstance(subexpression, Variable):
                    yield subexpression

    def _build_variable_classes(self, cfg: ControlFlowGraph) -> None:
        """
        Build a value class for every variable.

        If there is a copy assignment, the variables have the same value at that point and therefore do not interfere, despite possible
        live range interference. For two variables to be in the same value class, can_be_in_same_class has to return True.
        """
        for variable in self._collect_variables(cfg):
            self._value_classes[variable] = variable

        basic_block: BasicBlock
        for basic_block in topological_sort(cfg.dominator_tree._graph):  # type: ignore
            for instruction in basic_block:
                if self._is_copy_assignment(instruction) and can_be_in_same_class(instruction.value, instruction.destination):
                    self._value_classes[instruction.destination] = self._value_classes[instruction.value]  # type: ignore

    def _create_interference(self, variables: InsertionOrderedSet[Variable]) -> None:
        """
        Adds an edge between every pair of variables in the set 'variables' to the interference graph.

        :param variables: A set of variables that pairwise interfere with each other.
        """
        for variable in variables:
            self.add_node(variable)

        for first_variable, second_variable in combinations(variables, 2):
            if self._value_classes[first_variable] != self._value_classes[second_variable]:
                self.add_edge(first_variable, second_variable)

    def _interference_graph_add_edges(self, new_variables: Set[Variable], current_variables: InsertionOrderedSet[Variable]) -> None:
        """
        Adds an edge between every variable in 'new_variables' and 'current_variables' to the interference graph,
        i.e., for each var_1 in new_variables and each var_2 in current_variables we add the edge (var_1, var_2) to the interference graph.
        Furthermore, for each pair of variables in `new_variables` we add an edge to the interference graph.

        Variables of the same value class do not get an edge.

        :param new_variables: The set of variables that we add to the set of live variables.
        :param current_variables: The set of variables that were live.
        """
        for new_variable in new_variables:
            self.add_node(new_variable)
            for current_variable in current_variables:
                if self._value_classes[new_variable] != self._value_classes[current_variable]:
                    self.add_edge(new_variable, current_variable)

        for first_variable, second_variable in combinations(new_variables, 2):
            if self._value_classes[first_variable] != self._value_classes[second_variable]:
                self.add_edge(first_variable, second_variable)
