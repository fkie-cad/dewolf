from __future__ import annotations

from itertools import combinations
from typing import Dict, Iterator, Set

from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import Variable, GlobalVariable
from decompiler.structures.pseudo.instructions import Assignment, Instruction
from decompiler.util.insertion_ordered_set import InsertionOrderedSet
from networkx import topological_sort

def doVarCheckClassToghetherPossible(var1: Variable, var2: Variable) -> bool:
        """Returns true, if var1 and var2 do not interfere based on our 'newly' found criteria:
            Global Variable and normal variables do not get mixed.
            Global variables in one class have to have the same name.
            The type of all variables in one class has to be identical.
            The variables either have to be all aliased or all non-aliased.
            If both variables are aliased they have to have the same name.
            """
        if isinstance(var1, GlobalVariable) and isinstance(var2, GlobalVariable) and (var1.name != var2.name):
            return False
        elif isinstance(var1, GlobalVariable) != isinstance(var2, GlobalVariable):
            return False
        elif var1.type != var2.type:
            return False
        elif var1.is_aliased != var2.is_aliased:
            return False
        elif var1.is_aliased and var2.is_aliased and (var1.name != var2.name):
            return False
        return True

class ValueInterferenceGraph(InterferenceGraph):
    def __init__(self, cfg: ControlFlowGraph = None): #type: ignore
        """
        Initialize the Interference Graph given a control flow graph. Inserts edges between all variables interfering by our 'newly' found definition of interference. (see function doVarCheckClassToghetherPossible)

        :param cfg: The control flow graph whose interference graph we want to construct.
        """
        self._value_classes:Dict[Variable, Variable] = dict()
        self._build_variable_classes(cfg)
        super().__init__(cfg)

    def _is_copy_assignment(self, instr: Instruction) -> bool:
        """Returns true if instr is an assignment between two VARIABLES"""
        if isinstance(instr, Assignment):
            if isinstance(instr.value, Variable) and isinstance(instr.destination, Variable): 
                return True
        return False

    def _collect_variables(self, cfg: ControlFlowGraph) -> Iterator[Variable]:
        """Yields all variables present in the given control flow graph."""
        for instruction in cfg.instructions:
            for subexpression in instruction.subexpressions():
                if isinstance(subexpression, Variable):
                    yield subexpression

    def _build_variable_classes(self, cfg:ControlFlowGraph) -> None:
        """We build a class for every variable. If there's a copy assignment then the variables have the same value at that point and therefore do not interfere,
        despite possible live range interferance.
        For two variables to not inferbere because of the aforementioned criterion doVarCheckClassTogetherPossible has to return true."""
        for var in self._collect_variables(cfg):
            self._value_classes[var] = var

        basic_block: BasicBlock
        for basic_block in topological_sort(cfg.dominator_tree._graph): #type: ignore
            for instr in basic_block:
                if self._is_copy_assignment(instr) and doVarCheckClassToghetherPossible(instr.value, instr.destination):
                    instr: Assignment
                    #if (not isinstance(instr.value,GlobalVariable) and (not isinstance(instr.destination,GlobalVariable))):
                    self._value_classes[instr.destination] = self._value_classes[instr.value] #type:ignore
                    #elif isinstance(instr.value,GlobalVariable) and isinstance(instr.destination,GlobalVariable) and (instr.destination.name == instr.value.name):
                        #self._value_classes[instr.destination] = self._value_classes[instr.value] #type:ignore

        
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

