"""Module for renaming variables in Out of SSA."""

import itertools
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import combinations
from operator import attrgetter
from typing import DefaultDict, Dict, Iterable, Iterator, List, Optional, Set, Tuple, Union

import networkx
from decompiler.pipeline.ssa.dependency_graph import dependency_graph_from_cfg
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import BaseAssignment, Instruction, Relation
from decompiler.structures.pseudo.typing import Type
from decompiler.task import DecompilerTask
from decompiler.util.decoration import DecoratedGraph
from decompiler.util.insertion_ordered_set import InsertionOrderedSet
from decompiler.util.lexicographical_bfs import LexicographicalBFS
from networkx import Graph, MultiDiGraph, connected_components


@dataclass
class LabelCounter:
    """Class that count how often a label occurs."""

    occurrences: DefaultDict[int, int] = field(default_factory=lambda: defaultdict(int))

    def occurrence_of_class(self, class_label: int) -> int:
        """Returns the occurrence of the given class"""
        return self.occurrences[class_label]

    def increase_occurrence_of_class(self, class_label: int) -> None:
        """increases the occurrence of the given class"""
        self.occurrences[class_label] += 1

    def get_most_occurring_class_from(self, possible_classes: Set[int]) -> Optional[int]:
        """Returns the class most occurring class under the given set of classes."""
        occurrence = 0
        chosen_color = None
        for color in possible_classes:
            if color in self.occurrences and self.occurrence_of_class(color) > occurrence:
                occurrence = self.occurrence_of_class(color)
                chosen_color = color
        return chosen_color


@dataclass
class ClassDistribution:
    """Class that keeps track of how a given variable name is distributed among the classes."""

    distribution_of: DefaultDict[str, LabelCounter] = field(default_factory=lambda: defaultdict(LabelCounter))

    def increase_occurrence_of(self, variable: str, class_label: int) -> None:
        """Increases the number of occurrences of variables with the name `variable` in class `class_label` by one."""
        self.distribution_of[variable].increase_occurrence_of_class(class_label)


@dataclass
class VariableClassesHandler:
    """
    A helper dataclass to correctly update the variable classes
    """

    variable_class: DefaultDict[int, Set[Variable]]
    color_class_of: Dict[Variable, int] = field(default_factory=dict)
    class_distribution: ClassDistribution = field(default_factory=ClassDistribution)

    def add_variable_to_class(self, variable: Variable, var_class: int):
        """Adds the given variable to the given dataclass and updates all helpers."""
        self.color_class_of[variable] = var_class
        self.variable_class[var_class].add(variable)
        self.class_distribution.increase_occurrence_of(variable.name, var_class)

    def clean_up_helpers(self):
        """Empties the helper variables."""
        self.color_class_of = dict()
        self.class_distribution = ClassDistribution()

    def get_distribution_of(self, variable: str) -> LabelCounter:
        """
        Returns for the given variable-name its distribution among the different classes.

        These information are saved in an object of type LabelCounter.
        """
        return self.class_distribution.distribution_of[variable]


class VariableRenamer:
    """Base class for variable renaming"""

    def __init__(self, task: DecompilerTask, interference_graph: InterferenceGraph):
        self.cfg = task.graph
        self.interference_graph = interference_graph

        self.variable_for_function_arg: Dict[str, Variable] = self._get_function_argument_variables(task.function_parameters)
        self._add_interference_for_function_args()
        self._variables_contracted_to: Dict[Variable, List[Variable]] = {var: [var] for var in self.interference_graph}
        self._contract_variables_that_need_same_name()

        self.renaming_map: Dict[Variable, Variable] = dict()
        self.new_variable_name = "var_"
        self.check_variable_name()

    def check_variable_name(self):
        """Checks whether the chosen variable name is valid."""
        if self.new_variable_name in self.variable_for_function_arg:
            error_message = (
                f"We need to think of a different name than {self.new_variable_name} for the replacement variable, "
                f"because an function argument has the same name."
            )
            logging.error(error_message)
            raise NameError(error_message)

    def rename(self):
        """
        This function replaces in each instruction a variable by the variable in replacement_for_variable[variable].
        """
        for instruction in self.cfg.instructions:
            for variable in instruction.requirements + instruction.definitions:
                self._replace_variable_in_instruction(variable, instruction)

        self._remove_redundant_assignments()

    def _replace_variable_in_instruction(self, variable: Variable, instruction: Instruction) -> None:
        """Replace the given variable in the given instruction"""
        if variable.ssa_label is None:
            return
        replacement_variable = self.renaming_map[variable].copy()
        replacement_variable.ssa_name = variable.copy()
        instruction.substitute(variable, replacement_variable)
        if isinstance(instruction, Relation):
            instruction.rename(variable, replacement_variable)

    def _remove_redundant_assignments(self):
        """
        This function remove Assignments of the form 'var_1 = var_1' which occur because we rename some variables.
        """
        for basic_block in self.cfg.nodes:
            new_instructions = list()
            for instruction in basic_block.instructions:
                if not isinstance(instruction, BaseAssignment):
                    new_instructions.append(instruction)
                elif instruction.destination != instruction.value:
                    if isinstance(instruction, Relation):
                        raise ValueError(f"In Relation {instruction} not all variables have the same name after renaming!")
                    new_instructions.append(instruction)
            basic_block.instructions = new_instructions

    def _get_function_argument_variables(self, function_parameters: List[Variable]) -> Dict[str, Variable]:
        """
        This function returns for each function argument variable, the variable with the smallest
        SSA-value that has the same name, i.e., the first usage of this variable.

        :return: A dictionary that maps each function argument to the SSA-variable with the same name, used first.
        """
        function_argument_variables: Dict[str, Variable] = dict()
        for variable in self.interference_graph.nodes:
            if variable.name in [var.name for var in function_parameters]:
                if (
                    variable.name not in function_argument_variables.keys()
                    or function_argument_variables[variable.name].ssa_label > variable.ssa_label
                ):
                    function_argument_variables[variable.name] = variable
        return function_argument_variables

    def _add_interference_for_function_args(self):
        """Make sure that the function arguments do not get the same name, i.e., add an edge between them in the interference graph."""
        for arg1, arg2 in combinations(self.variable_for_function_arg.values(), 2):
            self.interference_graph.add_edge(arg1, arg2)

    def _contract_variables_that_need_same_name(self) -> None:
        """
        Initialize the dictionary that maps to each variable the set of variable that must have the same name.

        We do this for
        -> Relations
        """
        dependency_graph = self.create_same_name_dependency_graph()

        for connected_component in connected_components(dependency_graph):
            connected_component = sorted(connected_component, key=attrgetter("ssa_label"))
            self.interference_graph.contract_independent_set(connected_component)
            self._variables_contracted_to[connected_component[0]] = connected_component

    def create_same_name_dependency_graph(self):
        """Returns a graph that adds an edge between two variables if they should get the same name."""
        graph = Graph()
        for relation in [instruction for instruction in self.cfg.instructions if isinstance(instruction, Relation)]:
            graph.add_edge(relation.destination, relation.value)
        return graph

    def compute_new_name_for_each_variable(self):
        """
        This function computes the new variable name for each color class.
        """
        counter: int = 0
        for variable_class in self._variable_classes_handler.variable_class.values():
            new_variable, counter = self._new_variable_name_for(variable_class, counter)
            for variable in variable_class:
                if isinstance(variable, GlobalVariable):
                    # do not rename global variables - retain their symbols where present.
                    tmp = variable.copy()
                    tmp.ssa_label = None
                    self.renaming_map[variable] = tmp
                else:
                    self.renaming_map[variable] = new_variable

    def _new_variable_name_for(self, variable_class: Set[Variable], counter: int) -> Tuple[Variable, int]:
        """
        This function computes the new variable name for the class (set) of input variables

        :param variable_class: The color class whose new name we want to compute.
        :param counter: The counter for the variable name.
        :return: The new variable name.
        """
        if argument_set := set(self.variable_for_function_arg.values()).intersection(variable_class):
            if len(argument_set) > 1:
                error_message = f"All input arguments should interfere, but the arguments in {argument_set} are in the same color class."
                logging.error(error_message)
                raise ValueError(error_message)
            argument = argument_set.pop()
            new_variable = Variable(argument.name, argument.type)
        else:
            variable, *_ = variable_class
            new_variable = Variable(f"{self.new_variable_name}{counter}", variable.type, is_aliased=variable.is_aliased)
            counter += 1

        return new_variable, counter


class SimpleVariableRenamer(VariableRenamer):
    """
    A simple renaming strategy, that renames each SSA-Variable by the non SSA-variable whose name consists of the variable name
    together with the SSA-label, i.e., the SSA-variable v#3 is replaced by the non SSA-variable v_3.
    """

    def __init__(self, task: DecompilerTask, interference_graph: InterferenceGraph):
        super().__init__(task, interference_graph)
        self._generate_renaming_map()

    def _generate_renaming_map(self):
        """
        This function simply renames a SSA-variable to a non SSA-variable by adding the label to the name
        """
        for variable in self.interference_graph.nodes:
            for v in self._variables_contracted_to[variable]:
                self.renaming_map[v] = Variable(f"{variable.name}_{variable.ssa_label}", variable.type)

        for argument, variable in self.variable_for_function_arg.items():
            self.renaming_map[variable] = Variable(argument, variable.type)


class MinimalVariableRenamer(VariableRenamer):
    """
    A minimal renaming strategy, that renames the SSA-variables such that the total number of non SSA-variables is (almost) minimal.
    Therefore, we construct color-classes by using lexicographical BFS on the interference graph. When the interference graph is chordal
    this leads to a minimum number of possible variables.
    """

    def __init__(self, task, interference_graph: InterferenceGraph):
        """
        self._color_classes is a dictionary where the set of keys is the set of colors
        and to each color we assign the set of variables of this color.
        """
        super().__init__(task, interference_graph)
        self._variable_classes_handler: VariableClassesHandler = VariableClassesHandler(defaultdict(set))
        self._generate_renaming_map()

    def _generate_renaming_map(self):
        """
        We want to find a minimal number of variables for the replacement:
            - Compute the class of variables that can have the same name using lexicographical BFS

        :return: A dictionary that assigns each SSA-variable its new, non SSA-variable.
        """
        self._compute_color_classes()
        self.compute_new_name_for_each_variable()

    def _compute_color_classes(self):
        """
        This function computes a coloring for the interference graph, i.e., a collection of variable sets (color classes) that are pairwise
        disjoint and whose union is the set of all variables, s.t. each color class is an independent set in the interference graph.

         - It is optimal if the interference graph is chordal.
         - Otherwise it is a simple greedy algorithm.
         - We only color two variables with the same color, if they have the same type.
        """
        for variables in self._groupable_variables():
            self._add_color_classes_for(variables)

    def _groupable_variables(self) -> Iterator[InsertionOrderedSet[Variable]]:
        """
        This groups the variables in the interference graph according to their capability of getting the same name.
        More precisely, we have one group for each pair (type, not_aliased) and (name, aliased).

        :return: A list of sets, that contain variables that can have the same name, if they do not interfere.
        """
        variables_of_type: DefaultDict[Union[Type, str], InsertionOrderedSet[Variable]] = defaultdict(InsertionOrderedSet)
        for variable in self.interference_graph.nodes():
            if variable.is_aliased:
                variables_of_type[variable.name].add(variable)
            else:
                variables_of_type[variable.type].add(variable)
        yield from variables_of_type.values()

    def _add_color_classes_for(self, variables: InsertionOrderedSet[Variable]):
        """
        Compute a coloring for the variables in `variables` and add it to the color classes dictionary.
        """
        interference_subgraph = self.interference_graph.get_subgraph_of(variables)
        lex_bfs = LexicographicalBFS(interference_subgraph)

        self._variable_classes_handler.clean_up_helpers()
        for variable in lex_bfs.reverse_lexicographic_bfs():
            variable_color = self._get_optimal_color_for(variable, interference_subgraph)
            for var in self._variables_contracted_to[variable]:
                self._variable_classes_handler.add_variable_to_class(var, variable_color)

    def _get_optimal_color_for(self, variable: Variable, interference_subgraph: InterferenceGraph) -> int:
        """We compute the optimal color for the given variable."""
        possible_colors = set(self._get_possible_colors(interference_subgraph.neighbors(variable)))
        amount_usage_color: LabelCounter = self._variable_classes_handler.get_distribution_of(variable.name)
        chosen_color = amount_usage_color.get_most_occurring_class_from(possible_colors)
        return min(possible_colors) if chosen_color is None else chosen_color

    def _get_possible_colors(self, neighborhood: Iterable[Variable]) -> Set[int]:
        """Returns the set of possible colors for a variable that has the given set of variables as neighbours."""
        interfering_classes = set(self._classes_of(neighborhood))
        for color in self._variable_classes_handler.color_class_of.values():
            if color not in interfering_classes:
                yield color
        yield len(self._variable_classes_handler.variable_class)

    def _classes_of(self, neighborhood: Iterable[Variable]) -> Iterable[Variable]:
        """Returns the classes of the given set of variables"""
        for neighbor in neighborhood:
            if neighbor in self._variable_classes_handler.color_class_of:
                yield self._variable_classes_handler.color_class_of[neighbor]


class ConditionalVariableRenamer(VariableRenamer):
    """
    A renaming strategy that renames the SSA-variables, such that only variables that have a relation with each other can get the same name.
    Therefore, we construct a dependency-graph with weights, telling us how likely these two variables are the same variable, i.e.,
    copy-assignments are more likely to be identically than complicated computations.
    """

    def __init__(self, task, interference_graph: InterferenceGraph):
        """
        self._color_classes is a dictionary where the set of keys is the set of colors
        and to each color we assign the set of variables of this color.
        """
        super().__init__(task, interference_graph.copy())

        dependency_graph = dependency_graph_from_cfg(task.graph)

        mapping: dict[tuple[Variable], tuple[Variable, ...]] = {}
        for variable in self.interference_graph.nodes():
            contracted = tuple(self._variables_contracted_to[variable])
            for var in contracted:
                mapping[(var,)] = contracted

        # Merge nodes which need to be contracted from self._variables_contracted_to
        dependency_graph = networkx.relabel_nodes(dependency_graph, mapping)

        dependency_graph.edge = dependency_graph.edges(data=True)
        while True:
            for u, v, _ in sorted(dependency_graph.edges(data=True), key=lambda edge: edge[2]["score"], reverse=True):
                if u == v:  # self loop
                    continue

                variables = u + v
                if interference_graph.are_interfering(*variables):
                    continue
                if u[0].type != v[0].type:
                    continue
                if u[0].is_aliased != v[0].is_aliased:
                    continue

                break
            else:
                # We didn't find any remaining nodes to contract, break outer loop
                break

            networkx.relabel_nodes(dependency_graph, {u: (*u, *v), v: (*u, *v)}, copy=False)

        self._variable_classes_handler = VariableClassesHandler(defaultdict(set))
        for i, vars in enumerate(dependency_graph.nodes):
            for var in vars:
                self._variable_classes_handler.add_variable_to_class(var, i)

        self.compute_new_name_for_each_variable()

    def _decorate_graph(self, dependency_graph: MultiDiGraph, path: str):
        decorated_graph = MultiDiGraph()
        for node in dependency_graph.nodes:
            decorated_graph.add_node(hash(node), label="\n".join(map(lambda n: f"{n}: {n.type}, aliased: {n.is_aliased}", node)))
        for u, v, data in dependency_graph.edges.data():
            decorated_graph.add_edge(u, v, label=f"{data['score']}")
        for nodes in networkx.weakly_connected_components(dependency_graph):
            for node_1, node_2 in combinations(nodes, 2):
                if any(self.interference_graph.has_edge(pair[0], pair[1]) for pair in itertools.product(node_1, node_2)):
                    decorated_graph.add_edge(hash(node_1), hash(node_2), color="red", dir="none")

        DecoratedGraph(decorated_graph).export_plot(path, type="svg")

    def _variables_can_have_same_name(self, source: Variable, sink: Variable) -> bool:
        """
        Two variable can have the same name, if they have the same type, are both aliased or both non-aliased variables, and if they
        do not interfere.

        :param source: The potential source vertex.
        :param sink: The potential sink vertex
        :return: True, if the given variables can have the same name, and false otherwise.
        """
        if self.interference_graph.are_interfering(source, sink) or source.type != sink.type or source.is_aliased != sink.is_aliased:
            return False
        if source.is_aliased and sink.is_aliased and source.name != sink.name:
            return False
        return True
