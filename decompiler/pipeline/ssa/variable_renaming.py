"""Module for renaming variables in Out of SSA."""

import logging
import random
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import chain, combinations
from logging import debug
from operator import attrgetter
from typing import DefaultDict, Dict, Iterable, Iterator, List, Optional, Set, Tuple, Union

import networkx as nx
import numpy as np
from decompiler.pipeline.ssa.conditional_attribute_helper import Feature, PhiPairs
from decompiler.pipeline.ssa.dependency_graph import DependencyNode, dependency_graph_from_cfg
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import BaseAssignment, Instruction, Relation
from decompiler.structures.pseudo.typing import Type
from decompiler.task import DecompilerTask
from decompiler.util.insertion_ordered_set import InsertionOrderedSet
from decompiler.util.lexicographical_bfs import LexicographicalBFS
from networkx import Graph, MultiGraph, connected_components, has_path, minimum_cut, selfloop_edges, shortest_path_length, subgraph_view
from scipy.optimize import Bounds, LinearConstraint, milp


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
        if variable not in self.renaming_map:
            return
        replacement_variable = self.renaming_map[variable].copy()
        if variable.ssa_label is not None:
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
            for v in self._variables_contracted_to[variable]:  # variables joined to the argument by Relations get its name too
                self.renaming_map[v] = Variable(argument, variable.type)


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


@dataclass
class StCut:
    """A minimum s-t-cut of a dependency graph, separating the nodes `source` and `sink`."""

    source: DependencyNode
    sink: DependencyNode
    source_side: Set[DependencyNode]
    sink_side: Set[DependencyNode]
    weight: float


class ConditionalVariableRenamer(VariableRenamer):
    """
    A renaming strategy that renames the SSA-variables, such that only variables that have a relation with each other can get the same name.
    Therefore, we construct a dependency-graph with weights, telling us how likely these two variables are the same variable, i.e.,
    copy-assignments are more likely to be identically than complicated computations.
    """

    # Score of the edges between variables connected by a Relation, so that they are (almost) never separated.
    RELATION_SCORE = 2**40
    # Strategies 2 and 3 only consider paths up to this length (relative to the approximate diameter) in the LP.
    PATH_LENGTH_FACTOR = 0.1
    PATH_LENGTH_OFFSET = 4
    # Strategy 3 adds the paths of this many interfering pairs to the LP in each round.
    PAIRS_PER_ROUND = 10
    # Number of nodes from which the diameter approximation computes the shortest paths.
    DIAMETER_SAMPLES = 8

    def __init__(
        self,
        task: DecompilerTask,
        interference_graph: InterferenceGraph,
        coefficients: Dict[Feature, float],
        intercept: float,
        phi_pairs: PhiPairs,
        strategy: int = 0,
        min_kept_score: Optional[float] = None,
    ):
        """
        :param task: The decompiler task whose variables we want to rename.
        :param interference_graph: The interference graph of the control flow graph of the task.
        :param coefficients: The coefficients of the linear model that scores variable pairs, per feature.
        :param intercept: The intercept of the linear model.
        :param phi_pairs: The ordered pairs of variables that co-occurred in a phi function, see get_phi_pairs.
        :param strategy: How the dependency graph is split into variable classes, see create_variable_classes.
        :param min_kept_score: Lower bound for the scores of the kept dependency-graph edges (None: no lower bound).
        """
        super().__init__(task, interference_graph.copy())
        self.coefficients = coefficients
        self.intercept = intercept
        self.phi_pairs = phi_pairs
        self.strategy = strategy
        self.min_kept_score = min_kept_score
        self.corrected_interference_pairs = 0
        # The renamer works on the given, uncontracted graph (the base class contracted a copy).
        self.interference_graph = interference_graph
        self.task = task
        self._generate_renaming_map(task.graph)

    def _generate_renaming_map(self, cfg: ControlFlowGraph) -> None:
        """
        Generate the renaming map for SSA variables.

        This function constructs a dependency graph from the given CFG, merges contracted variables,
        creates variable classes, and computes new names for each variable. The process ensures that
        only variables with specific relationships can share the same name, as determined by the
        dependency graph.

        :param cfg: The control flow graph from which the dependency graph is derived.
        """
        dependency_graph = dependency_graph_from_cfg(cfg, self.coefficients, self.intercept, self.phi_pairs, self.min_kept_score)
        dependency_graph = self.merge_contracted_variables(dependency_graph)
        dependency_graph = self.create_variable_classes(dependency_graph)
        self._create_renaming_map(self._extract_classes(dependency_graph))

    def merge_contracted_variables(self, dependency_graph: MultiGraph) -> MultiGraph:
        """Pseudo-contract the variables connected by a Relation, i.e., connect them by an edge that is (almost) never cut."""
        for instruction in self.cfg.instructions:
            if isinstance(instruction, Relation) and instruction.destination != instruction.value:
                dependency_graph.add_edge((instruction.destination,), (instruction.value,), score=self.RELATION_SCORE)
        return dependency_graph

    def create_variable_classes(self, dependency_graph: MultiGraph) -> Graph:
        """
        Split the dependency graph such that no connected component contains two variables that must be separated.

        The connected components of the returned graph are the variable classes. The strategy is selected by the weights file:
        - 0: compute every needed s-t-cut and apply the lightest first. An s-t-cut is only applied if still necessary.
        - 1: apply the s-t-cuts one after another, without sorting by weight -> lower runtime, but worse approximation factor.
        - 2: use an LP solver to compute a multicut. Due to runtime constraints only paths up to a certain dynamic length are
             considered; the remaining pairs (connected by long paths) are separated by s-t-cuts.
        - 3: round-based version of strategy 2. Enumerating the paths of all pairs is expensive, solving the LP comparatively cheap,
             so the paths of only a few pairs are added in each round, until the LP solution separates all pairs.
        - 4: greedy merging. Merge along the edges in order of decreasing score whenever the two classes contain no pair that must be
             separated. No cuts, no LP.
        """
        strategies = {
            0: self._cut_lightest_first,
            1: self._cut_in_order,
            2: self._cut_by_lp,
            3: self._cut_by_lp_in_rounds,
            4: self._merge_greedily,
        }
        if self.strategy not in strategies:
            raise Exception("This Multicut Algorithm is currently not implemented")
        return strategies[self.strategy](dependency_graph)

    def _cut_lightest_first(self, dependency_graph: MultiGraph) -> Graph:
        """Strategy 0: compute the s-t-cuts of all interfering pairs of a component, then apply the needed ones, lightest first."""
        graph = self._to_simple_graph(dependency_graph)
        for component in list(connected_components(graph)):
            component_graph = self._component_view(graph, component)
            cuts = [self._minimum_cut(component_graph, source, sink) for source, sink in self._interfering_pairs(component_graph)]
            cuts.sort(key=attrgetter("weight"))
            for cut in cuts:
                if has_path(component_graph, cut.source, cut.sink):
                    self._remove_edges_between(graph, cut.source_side, cut.sink_side)
        return graph

    def _cut_in_order(self, dependency_graph: MultiGraph) -> Graph:
        """Strategy 1: separate the interfering pairs of each component by s-t-cuts, one after another."""
        graph = self._to_simple_graph(dependency_graph)
        for component in list(connected_components(graph)):
            component_graph = self._component_view(graph, component)
            for source, sink in self._interfering_pairs(component_graph):
                if has_path(component_graph, source, sink):
                    cut = self._minimum_cut(component_graph, source, sink)
                    self._remove_edges_between(graph, cut.source_side, cut.sink_side)
        return graph

    def _cut_by_lp(self, dependency_graph: MultiGraph) -> Graph:
        """Strategy 2: separate the interfering pairs of each component by a multicut computed with an LP solver."""
        graph = self._to_simple_graph(dependency_graph)
        for component in list(connected_components(graph)):
            self._cut_component_by_lp(graph, component)
        self._separate_remaining_pairs(graph)
        return graph

    def _cut_component_by_lp(self, graph: Graph, component: Set[DependencyNode]) -> None:
        """Remove the edges of a multicut that separates all short paths between the interfering pairs of the given component."""
        component_graph = self._component_view(graph, component)
        edges, weights = self._edges_and_scores(component_graph)
        if not edges:
            return
        interfering_pairs = self._interfering_pairs(component_graph)
        diameter = self._approximate_diameter(component_graph)
        paths = []
        for source, sink in interfering_pairs:
            paths.extend(self._short_paths(component_graph, source, sink, diameter))
        if not paths:
            return
        graph.remove_edges_from(self._solve_multicut_lp(self._encode_paths(paths, edges), weights, edges))

    def _cut_by_lp_in_rounds(self, dependency_graph: MultiGraph) -> Graph:
        """Strategy 3: like strategy 2, but the LP only contains the paths of a few interfering pairs per round."""
        graph = self._to_simple_graph(dependency_graph)
        for component in list(connected_components(graph)):
            self._cut_component_by_lp_in_rounds(graph, component)
        self._separate_remaining_pairs(graph)
        return graph

    def _cut_component_by_lp_in_rounds(self, graph: Graph, component: Set[DependencyNode]) -> None:
        """
        Add the short paths of some interfering pairs to the LP and solve it, until the LP solution also separates all pairs whose paths
        were not added yet, or no pair with a short path is left. Then the edges of the last solution are removed.
        """
        component_graph = self._component_view(graph, component)
        edges, weights = self._edges_and_scores(component_graph)
        if not edges:
            return
        interfering_pairs = list(self._interfering_pairs(component_graph))
        if not interfering_pairs:
            return
        constraint_rows = []
        next_pair_index = 0
        diameter = self._approximate_diameter(component_graph)
        # Deterministic seed, so that the LP solver always gets the same input for the same graph.
        random.seed(hash(tuple(sorted(weights))))
        removed_edges = []
        while round_paths := self._paths_of_next_round(component_graph, interfering_pairs, next_pair_index, diameter):
            constraint_rows.extend(self._encode_paths(round_paths, edges))
            removed_edges = self._solve_multicut_lp(constraint_rows, weights, edges)
            remaining_graph = Graph(component_graph)
            remaining_graph.remove_edges_from(removed_edges)
            next_pair_index = self._index_of_connected_pair(remaining_graph, interfering_pairs)
            if next_pair_index is None:
                break
        graph.remove_edges_from(removed_edges)

    def _paths_of_next_round(
        self,
        component_graph: Graph,
        interfering_pairs: List[Tuple[DependencyNode, DependencyNode]],
        next_pair_index: int,
        diameter: int,
    ) -> List[List[Tuple[DependencyNode, DependencyNode]]]:
        """
        Remove up to PAIRS_PER_ROUND pairs from the given list (starting with the given index, then at random) and return their short
        paths. If none of them has a short path, take further pairs until one has.
        """
        paths = []
        for _ in range(min(self.PAIRS_PER_ROUND, len(interfering_pairs))):
            source, sink = interfering_pairs.pop(next_pair_index)
            paths.extend(self._short_paths(component_graph, source, sink, diameter))
            if interfering_pairs:
                next_pair_index = random.randint(0, len(interfering_pairs) - 1)
        while not paths and interfering_pairs:
            source, sink = interfering_pairs.pop(random.randint(0, len(interfering_pairs) - 1))
            paths.extend(self._short_paths(component_graph, source, sink, diameter))
        return paths

    def _merge_greedily(self, dependency_graph: MultiGraph) -> Graph:
        """
        Strategy 4: agglomerative merging.

        Starting from singletons, merge along the edges in order of decreasing score (relations first, they carry the huge relation score)
        whenever the two current classes contain no pair that must be separated. Returns a forest whose components are the classes.
        """
        graph = self._to_simple_graph(dependency_graph)
        parent = {node: node for node in graph.nodes}
        members = {node: [node] for node in graph.nodes}
        result = Graph()
        result.add_nodes_from(graph.nodes)
        for node_1, node_2, score in sorted(graph.edges(data="score"), key=self._greedy_edge_order):
            root_1, root_2 = self._find_root(parent, node_1), self._find_root(parent, node_2)
            if root_1 == root_2:
                continue
            if any(self._must_separate(member_1, member_2) for member_1 in members[root_1] for member_2 in members[root_2]):
                continue
            if len(members[root_1]) < len(members[root_2]):
                root_1, root_2 = root_2, root_1
            parent[root_2] = root_1
            members[root_1].extend(members.pop(root_2))
            result.add_edge(node_1, node_2, score=score)
        return result

    @staticmethod
    def _greedy_edge_order(edge: Tuple[DependencyNode, DependencyNode, float]) -> Tuple[float, List[str]]:
        """Sort key for strategy 4: decreasing score, ties broken by the names of the end nodes (independent of the hash seed)."""
        node_1, node_2, score = edge
        return -score, sorted((f"{node_1[0].name}#{node_1[0].ssa_label}", f"{node_2[0].name}#{node_2[0].ssa_label}"))

    @staticmethod
    def _find_root(parent: Dict[DependencyNode, DependencyNode], node: DependencyNode) -> DependencyNode:
        """Return the root of the union-find tree of the given node, halving the path on the way."""
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    @staticmethod
    def _to_simple_graph(dependency_graph: MultiGraph) -> Graph:
        """
        Remove the self-loops (they do not add any value, but cause problems for the cuts) and merge parallel edges into one edge
        with the highest score.
        """
        dependency_graph.remove_edges_from(list(selfloop_edges(dependency_graph)))
        graph = Graph()
        graph.add_nodes_from(dependency_graph.nodes())
        for node_1, node_2, data in dependency_graph.edges(data=True):
            if graph.has_edge(node_1, node_2):
                graph[node_1][node_2]["score"] = max(graph[node_1][node_2]["score"], data["score"])
            else:
                graph.add_edge(node_1, node_2, score=data["score"])
        return graph

    def _must_separate(self, node_1: DependencyNode, node_2: DependencyNode) -> bool:
        """
        True iff the two (contracted) nodes may not share a name: they interfere, differ in type or aliasing, or mix (different) globals.

        This must stay the same rule as conditional_attribute_helper.cannot_share_name.
        """
        variable_1, variable_2 = node_1[0], node_2[0]
        if variable_1.type is None or variable_2.type is None:
            raise Exception("Encountered a None type variable in the SSA-Stage!")
        if self.interference_graph.are_interfering(*node_1, *node_2):
            return True
        if variable_1.type != variable_2.type:
            return True
        if (variable_1.is_aliased != variable_2.is_aliased) or (
            variable_1.is_aliased and variable_2.is_aliased and variable_1.name != variable_2.name
        ):
            return True
        if isinstance(variable_1, GlobalVariable) != isinstance(variable_2, GlobalVariable):
            return True
        if isinstance(variable_1, GlobalVariable) and isinstance(variable_2, GlobalVariable) and variable_1.name != variable_2.name:
            return True
        return False

    def _interfering_pairs(self, graph: Graph) -> List[Tuple[DependencyNode, DependencyNode]]:
        """Return all pairs of nodes in the same connected component of the given graph that must be separated."""
        interfering_pairs = []
        for component in connected_components(graph):
            # A component is a set, whose order depends on the hash seed, so take its nodes in the order of the graph.
            for node_1, node_2 in combinations([node for node in graph if node in component], 2):
                if self._must_separate(node_1, node_2):
                    interfering_pairs.append((node_1, node_2))
        return interfering_pairs

    @staticmethod
    def _component_view(graph: Graph, component: Set[DependencyNode]) -> Graph:
        """
        Return a view of the subgraph induced by the given component that iterates its nodes and edges in the order of the graph.
        graph.subgraph(component) iterates over the component set for small components, so its order would depend on the hash seed.
        """
        return subgraph_view(graph, filter_node=component.__contains__)

    @staticmethod
    def _minimum_cut(graph: Graph, source: DependencyNode, sink: DependencyNode) -> StCut:
        """Compute a minimum s-t-cut of the given graph, weighted by the edge scores."""
        weight, (source_side, sink_side) = minimum_cut(graph, source, sink, capacity="score")
        return StCut(source, sink, source_side, sink_side, weight)

    @staticmethod
    def _remove_edges_between(graph: Graph, side_1: Set[DependencyNode], side_2: Set[DependencyNode]) -> None:
        """Remove all edges of the given graph between the two given sets of nodes."""
        graph.remove_edges_from([(node_1, node_2) for node_1 in side_1 for node_2 in graph.neighbors(node_1) if node_2 in side_2])

    def _separate_remaining_pairs(self, graph: Graph) -> None:
        """Separate the interfering pairs that the LP missed because of the path length condition by s-t-cuts (usually only a few)."""
        for source, sink in self._interfering_pairs(graph):
            if has_path(graph, source, sink):
                self.corrected_interference_pairs += 1
                cut = self._minimum_cut(graph, source, sink)
                self._remove_edges_between(graph, cut.source_side, cut.sink_side)

    @staticmethod
    def _edges_and_scores(graph: Graph) -> Tuple[List[Tuple[DependencyNode, DependencyNode]], List[float]]:
        """Return the edges of the given graph and their scores, in the same order."""
        edges_with_scores = list(graph.edges(data="score"))
        return [(node_1, node_2) for node_1, node_2, _ in edges_with_scores], [score for _, _, score in edges_with_scores]

    def _short_paths(
        self, graph: Graph, source: DependencyNode, sink: DependencyNode, diameter: int
    ) -> List[List[Tuple[DependencyNode, DependencyNode]]]:
        """Return all simple paths (as lists of edges) between source and sink whose length is bounded relative to the diameter."""
        return list(nx.all_simple_edge_paths(graph, source, sink, self.PATH_LENGTH_FACTOR * diameter + self.PATH_LENGTH_OFFSET))

    @staticmethod
    def _encode_paths(
        paths: List[List[Tuple[DependencyNode, DependencyNode]]], edges: List[Tuple[DependencyNode, DependencyNode]]
    ) -> List[List[float]]:
        """Encode the paths as rows of the LP constraint matrix: one entry per edge, set to 1 iff the edge is part of the path."""
        rows = []
        for path in paths:
            row = np.zeros(len(edges)).tolist()
            for edge in path:
                if edge in edges:
                    row[edges.index(edge)] = 1
                else:
                    row[edges.index((edge[1], edge[0]))] = 1
            rows.append(row)
        return rows

    @staticmethod
    def _solve_multicut_lp(
        rows: List[List[float]], weights: List[float], edges: List[Tuple[DependencyNode, DependencyNode]]
    ) -> List[Tuple[DependencyNode, DependencyNode]]:
        """Return the edges of minimum total weight such that each path (row) contains at least one of them."""
        constraint = LinearConstraint(rows, np.ones((len(rows),)), np.inf)
        result = milp(c=weights, integrality=np.ones(len(weights)), bounds=Bounds(0, 1), constraints=constraint)
        if not result.success:
            raise Exception("Something went wrong while solving the LP")
        if result.status != 0:
            debug(f"LP-Solver: Status: {result.status}; Bound: {result.mip_dual_bound}")
        return [edges[index] for index, selected in enumerate(result.x) if selected == 1]

    def _approximate_diameter(self, graph: Graph) -> int:
        """Approximate the diameter of the given graph by the longest shortest path from some nodes, chosen with a fixed seed."""
        if graph.number_of_edges() == 0 or graph.number_of_nodes() == 0:
            return 0
        nodes = sorted(graph.nodes(), key=lambda node: f"{node[0].name}{node[0].ssa_label}")
        random.seed(str([(node[0].name, node[0].ssa_label) for node in nodes]))  # a str seed does not depend on the hash seed
        maximum = 0
        for _ in range(self.DIAMETER_SAMPLES):
            path_lengths = shortest_path_length(graph, nodes[random.randint(0, len(nodes) - 1)])
            maximum = max(max(path_lengths.values()), maximum)
        return maximum

    @staticmethod
    def _index_of_connected_pair(graph: Graph, pairs: List[Tuple[DependencyNode, DependencyNode]]) -> Optional[int]:
        """Return the index of the first pair that is still connected in the given graph, or None if there is none."""
        for index, (source, sink) in enumerate(pairs):
            if has_path(graph, source, sink):
                return index
        return None

    def _extract_classes(self, dependency_graph: Graph) -> List[List[Variable]]:
        """Return the variable classes, i.e., the variables of each connected component of the dependency graph, split by type."""
        # A component is a set, so order its nodes by their position in the graph: the first variable names the class,
        # and the iteration order of a set of variables depends on the hash seed of the process.
        position = {node: index for index, node in enumerate(dependency_graph.nodes)}
        classes = []
        for component in connected_components(dependency_graph):
            variables = list(chain(*sorted(component, key=position.__getitem__)))
            types = list(dict.fromkeys(variable.type for variable in variables))
            if len(types) <= 1:
                classes.append(variables)
            else:  # Should not occur, but a class must have one type.
                for variable_type in types:
                    classes.append([variable for variable in variables if variable.type == variable_type])
        return classes

    def _create_renaming_map(self, classes: List[List[Variable]]) -> None:
        """Give all variables of a class the same new name, the name of a global variable or function argument if it contains one."""
        suffix_counter = 0
        assigned_names = set()
        variable_for_function_arg: Dict[str, Variable] = self._get_function_argument_variables(self.task.function_parameters)
        function_arg_for_variable: Dict[Variable, str] = {variable: name for name, variable in variable_for_function_arg.items()}
        for variable_class in classes:
            global_variables = [variable for variable in variable_class if isinstance(variable, GlobalVariable)]
            if global_variables:
                self._rename_to_global_variable(variable_class, global_variables[0])
                continue
            new_name = self._class_name(variable_class, function_arg_for_variable)
            while new_name in assigned_names:
                new_name = f"{new_name}__{suffix_counter}"
                suffix_counter += 1
            assigned_names.add(new_name)
            for variable in variable_class:
                self.renaming_map[variable] = Variable(new_name, variable.type, None, variable.is_aliased, variable, variable.tags)

    def _rename_to_global_variable(self, variable_class: List[Variable], global_variable: GlobalVariable) -> None:
        """Rename all variables of the given class to the given global variable."""
        for variable in variable_class:
            self.renaming_map[variable] = GlobalVariable(
                global_variable.name,
                global_variable.type,
                global_variable.initial_value,
                None,
                global_variable.is_aliased,
                variable,
                global_variable.is_constant,
                global_variable.tags,
            )

    @staticmethod
    def _class_name(variable_class: List[Variable], function_arg_for_variable: Dict[Variable, str]) -> str:
        """Return the name of the function argument in the class if there is one, otherwise the name of its first variable."""
        for variable in variable_class:
            if variable in function_arg_for_variable:
                return function_arg_for_variable[variable]
        return variable_class[0].name
