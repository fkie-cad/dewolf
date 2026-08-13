"""Module for renaming variables in Out of SSA."""

import logging
import random
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass, field
from itertools import chain, combinations
from logging import debug
from operator import attrgetter, itemgetter
from typing import DefaultDict, Dict, Iterable, Iterator, List, Optional, Set, Tuple, Union

import networkx as nx
import numpy as np
from decompiler.pipeline.ssa.dependency_graph import _collect_variables, dependency_graph_from_cfg
from decompiler.pipeline.ssa.metric_helper import MetricHelper
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import BaseAssignment, Instruction, Relation
from decompiler.structures.pseudo.typing import Type
from decompiler.task import DecompilerTask
from decompiler.util.decoration import DecoratedCFG
from decompiler.util.insertion_ordered_set import InsertionOrderedSet
from decompiler.util.lexicographical_bfs import LexicographicalBFS
from networkx import (
    Graph,
    MultiDiGraph,
    MultiGraph,
    connected_components,
    has_path,
    minimum_cut,
    relabel_nodes,
    selfloop_edges,
    shortest_path_length,
    subgraph,
)
from scipy.optimize import Bounds, LinearConstraint, milp
import os
import json

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

def writeDictToPath(path : str,dictIn :Dict):
    if path != None and dictIn != None:
        names = {a.name:b.name for a,b in dictIn.items()}
        with open(path,mode="w") as f: #Note: this trncates the file, so the path has to be up to date, else the old data is lost!
            json.dump(names, f)
    else:
        raise Exception(f"Got incorrect parameters: Path = {path}, dict = {dictIn}")


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
        env = os.getenv("SSA_DICT_OUT")
        if env:
            writeDictToPath(str(env),self.renaming_map)

        for instruction in self.cfg.instructions:
            for variable in instruction.requirements + instruction.definitions:
                self._replace_variable_in_instruction(variable, instruction)

        self._remove_redundant_assignments()

    def _replace_variable_in_instruction(self, variable: Variable, instruction: Instruction) -> None:
        """Replace the given variable in the given instruction"""
        if variable not in self.renaming_map:
            return
        replacement_variable = self.renaming_map[variable].copy()
        # carry the lifted variable's provenance (incl. matched DWARF source_name) onto the renamed
        # variable, so the C source variable is readable directly from renamed_var.origin. A renamed
        # variable merges a whole SSA renaming class; each occurrence keeps the provenance of the
        # specific SSA variable it replaced (so conflicting merges stay visible). Independent of
        # ssa_name, so set outside the ssa_label guard (also covers the Relation.rename path below).
        replacement_variable.origin = variable.origin
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


class StCutStorage:
    def __init__(self, s: Tuple[Variable], t: Tuple[Variable], part1: list[tuple[Variable]], part2: list[tuple[Variable]], weight: int):
        self.s = s
        self.t = t
        self.part1 = part1
        self.part2 = part2
        self.weight = weight


class ConditionalVariableRenamer(VariableRenamer):
    """
    A renaming strategy that renames the SSA-variables, such that only variables that have a relation with each other can get the same name.
    Therefore, we construct a dependency-graph with weights, telling us how likely these two variables are the same variable, i.e.,
    copy-assignments are more likely to be identically than complicated computations.
    """

    def __init__(
        self,
        task: DecompilerTask,
        interference_graph: InterferenceGraph,
        parameters: list[float],
        intercept: float,
        strat: int = 0, #DETERMINISM
    ):
        super().__init__(task, interference_graph.copy())
        self.params = parameters
        self.intercept = intercept
        self.strat = strat
        self.correctedInterferencePairs = 0
        self.interference_graph = interference_graph
        self.task = task
        self.helpvalue = pow(2, 40) #We give this value to edges between variables which are connected in a relation, this makes it very very unlikely that they get separated in different classes
        self._generate_renaming_map(task.graph)

    def _generate_renaming_map(self, cfg: ControlFlowGraph):
        """
        Generate the renaming map for SSA variables.

        This function constructs a dependency graph from the given CFG, merges contracted variables,
        creates variable classes, and computes new names for each variable. The process ensures that
        only variables with specific relationships can share the same name, as determined by the
        dependency graph.

        :param cfg: The control flow graph from which the dependency graph is derived.
        """
        dependency_graph = dependency_graph_from_cfg(cfg, self.params, self.intercept, self.interference_graph)
        dependency_graph = self.merge_contracted_variables(dependency_graph)

        dependency_graph = self.create_variable_classes(dependency_graph)

        #The following assert is very useful for debugging, therefore it still has its place in the code
        # assert (self.checkResult(dependency_graph))

        self.createRenamingMap(self.extractClasses(dependency_graph))


    def extractClasses(self, dependency_graph: Graph) -> List[List[Variable]]:
        """Extracts variables, which can have the same name out of the dependency graph i.e. the connected components of the 'new' dependency graph"""
        res = []
        for comp in connected_components(dependency_graph):
            conComp = list(chain(*comp))
            types = set([x.type for x in conComp])
            if len(types) <= 1: #sanity check
                res.append(list(chain(*comp)))
            else: #Split the connected component by type. This shuold not occur, but you never know ...
                for x in types:
                    typeX = [y for y in conComp if y.type == x]
                    res.append(typeX)

        return res

    def checkResult(self, dependency_graph: MultiGraph):
        for comp in connected_components(dependency_graph):
            compVars = []
            for tup in comp:
                for var in tup:
                    compVars.append(var)
            if self.interference_graph.are_interfering(*compVars):
                raise Exception(f"Two Variables in one connected component are interfering!")
        return True

    def merge_contracted_variables(self, dependency_graph: MultiGraph):
        """Here variables connected by a relation are pseudo-contracted to one variable"""
        for instr in self.cfg.instructions:
            if isinstance(instr, Relation) and (instr.destination != instr.value):
                dependency_graph.add_edge((instr.destination,), (instr.value,), score=self.helpvalue)

        return dependency_graph

    def multiGraphToGraph(self, dependency_graph: MultiGraph) -> Graph:
        res = Graph()
        res.add_nodes_from(dependency_graph.nodes())
        for u, v, d in dependency_graph.edges(data=True):
            if res.has_edge(u, v):
                res[u][v]["score"] = max(res[u][v]["score"], d["score"])
            else:
                res.add_edge(u, v, score=d["score"])
        return res

    def getInterferingPairs(self, dependency_graph: Graph):
        interferingPairs = list()
        for zhk in connected_components(dependency_graph):
            for var1, var2 in combinations(zhk, 2):
                var1: Tuple[Variable] 
                var2: Tuple[Variable]
                if self.interference_graph.are_interfering(*var1, *var2):
                    interferingPairs.append((var1, var2))
                elif var1[0].type != var2[0].type:
                    interferingPairs.append((var1,var2))
                elif (var1[0].is_aliased != var2[0].is_aliased) or (var1[0].is_aliased and var2[0].is_aliased and (var1[0].name != var2[0].name)):
                    interferingPairs.append((var1,var2))
                elif isinstance(var1[0], GlobalVariable) != isinstance(var2[0], GlobalVariable):
                    interferingPairs.append((var1,var2))
                elif (isinstance(var1[0],GlobalVariable) and  isinstance(var2[0],GlobalVariable) and (var1[0].name != var2[0].name)):
                    interferingPairs.append((var1,var2))

                if(var1[0].type == None) or (var2[0].type == None):
                    raise Exception("Encountered a None type variable in the SSA-Stage!")

        return interferingPairs

    def create_variable_classes(self, dependency_graph: MultiGraph):
        """Create the variable classes based on the given dependency graph.
           We created 3 strategies for this, which can be selected by the user.
           - first strategy: calculation of every needed s-t-cut and application of lightest (weight) first. An s-t-cut is only applied if necessary
           - second strategy: simple application of s-t-cuts one after another, no sorting by weight --> lower runtime, but worse approximation factor
           - third strategy: use LP-Solver to calculate MultiCut. Due to runtime constraints only paths up to a certain dynamic lenght are considred, the remaining variables (connected by long paths) are devided by sepperate s-t-cuts.
           - fourth strategy: optimized version of strategy 3. Iterating all possible pairs is expensive, solving the LP is comparatively cheap, therefore we do a round-based approach, to reduce the paths we have to iterate.
           """
        match self.strat:

            case 0:

                dependency_graph.remove_edges_from(list(selfloop_edges(dependency_graph)))
                # remove loops, as they cause problems but don't add any value in our situation
                dependency_graph = self.multiGraphToGraph(dependency_graph)

                zhkList = list(connected_components(dependency_graph))
                for zhk in zhkList:
                    cuts = []
                    interferingPairs = self.getInterferingPairs(dependency_graph.subgraph(zhk))
                    for pair in interferingPairs: #compute all needed s-t-cuts and sort them by weight, 
                        weight, (part1, part2) = minimum_cut(dependency_graph.subgraph(zhk), pair[0], pair[1], capacity="score")
                        cuts.append(StCutStorage(pair[0], pair[1], part1, part2, weight))
                    cuts.sort(key=attrgetter("weight"))
                    del interferingPairs
                    #apply only the needed cuts, starting with the lightest one
                    for x in cuts:
                        x: StCutStorage
                        if has_path(dependency_graph.subgraph(zhk), x.s, x.t):
                            dependency_graph.remove_edges_from(
                                [(u, v) for u in x.part1 for v in dependency_graph.neighbors(u) if v in x.part2]
                            ) 
                            dependency_graph.remove_edges_from(
                                [(u, v) for u in x.part2 for v in dependency_graph.neighbors(u) if v in x.part1]
                            )
                        # assert not has_path(dependency_graph,x.s,x.t)

                return dependency_graph

            case 1: 

                dependency_graph.remove_edges_from(
                    list(selfloop_edges(dependency_graph))
                )  # remove loops, as they cause problems but don't add any value in our situation
                dependency_graph = self.multiGraphToGraph(dependency_graph)

                zhkList = list(connected_components(dependency_graph))
                #calculate all needed s-t-cuts and apply them one after another
                for zhk in zhkList:
                    interferingPairs = self.getInterferingPairs(dependency_graph.subgraph(zhk))
                    for pair in interferingPairs:
                        if has_path(dependency_graph.subgraph(zhk), pair[0], pair[1]):
                            _, (part1, part2) = minimum_cut(dependency_graph.subgraph(zhk), pair[0], pair[1], capacity="score")

                            edges = [(u, v) for u in part1 for v in dependency_graph.neighbors(u) if v in part2]
                            edges.extend([(u, v) for u in part2 for v in dependency_graph.neighbors(u) if v in part1])
                            dependency_graph.remove_edges_from(edges)

                return dependency_graph

            case 2: 
                dependency_graph.remove_edges_from(
                    list(selfloop_edges(dependency_graph))
                )  # remove loops, as they cause problems but don't add any value in our situation
                dependency_graph = self.multiGraphToGraph(dependency_graph)

                zhkList = list(connected_components(dependency_graph))
                zhkList = [x for x in zhkList if len(x) > 0] #empty zhk's can somehow occur
                for zhk in zhkList:

                    edges = list(dependency_graph.subgraph(zhk).edges(data=True))
                    if len(edges) == 0:
                        continue
                    interferingPairs = self.getInterferingPairs(dependency_graph.subgraph(zhk))
                    weights = [edge[2]["score"] for edge in edges]
                    edges = list(dependency_graph.subgraph(zhk).edges())

                    paths = []

                    dia = self.getDiameterApproximation(dependency_graph.subgraph(zhk)) #This is the base for our path lenght condition

                    for x in interferingPairs:
                        #get all paths form a to b in the zhk, which path lenght not longer than constant * diameter
                        paths.extend(list(nx.all_simple_edge_paths(dependency_graph.subgraph(zhk), x[0], x[1], 0.1 * dia + 4)))
                    if len(paths) == 0:
                        continue

                    pathsEncoded = []
                    #Encode the paths as a matrix for the LP-Solver: each path is a row. Every row has an entry for each edge. The entries are set to 1 if the edge is part of this path.
                    for path in paths:
                        row = np.zeros(len(edges)).tolist()
                        for edge in path:
                            if edge in edges:
                                row[edges.index(edge)] = 1
                            else:
                                row[edges.index((edge[1], edge[0]))] = 1

                        pathsEncoded.append(row)
                    #solve LP
                    lc = LinearConstraint(pathsEncoded, np.ones((len(paths),)), np.inf) #At least one of the edges in each path has to be removed by the LP-Solver, so 1 is the lower bound
                    res = milp(c=weights, integrality=np.ones(len(weights)), bounds=Bounds(0, 1), constraints=lc)
                    
                    remedges = [] #edges which the LP-Solver wants to remove
                    if res.success:
                        if res.status != 0:
                            debug(f"LP-Solver: Status: {res.status}; Bound: {res.mip_dual_bound}")
                        for i in range(len(res.x)):
                            if res.x[i] == 1:
                                remedges.append(edges[i])
                        dependency_graph.remove_edges_from(remedges)
                    else:
                        raise Exception("Something went wrong while solving the LP")

                #Check if the Diameter condition missed some of the interfering pairs, if so we perform a simple s-t-cut for them, as they are not too many
                ifp = self.getInterferingPairs(dependency_graph)
                for pair in ifp:
                    if has_path(dependency_graph, pair[0], pair[1]):
                        self.correctedInterferencePairs += 1
                        _, (part1, part2) = minimum_cut(dependency_graph, pair[0], pair[1], capacity="score")

                        edges = [(u, v) for u in part1 for v in dependency_graph.neighbors(u) if v in part2]
                        edges.extend([(u, v) for u in part2 for v in dependency_graph.neighbors(u) if v in part1])
                        dependency_graph.remove_edges_from(edges)
                return dependency_graph

            case 3:

                dependency_graph.remove_edges_from(
                    list(selfloop_edges(dependency_graph))
                )  # remove loops, as they cause problems but don't add any value in our situation
                dependency_graph = self.multiGraphToGraph(dependency_graph)

                zhkList = list(connected_components(dependency_graph))
                zhkList = [x for x in zhkList if len(x) > 0] #empty zhk's can somehow occur
                for zhk in zhkList:

                    edges = list(dependency_graph.subgraph(zhk).edges(data=True))
                    if len(edges) == 0:
                        continue
                    interferingPairs = list(self.getInterferingPairs(dependency_graph.subgraph(zhk)))
                    if len(interferingPairs) == 0:
                        continue

                    weights = [edge[2]["score"] for edge in edges]
                    edges = list(dependency_graph.subgraph(zhk).edges())

                    pathsEncoded = []
                    colisionIndex = 0
                    newRoundNeeded = True #Variable to control if we need to do another round of path generation i.e. are there any interfering paris left which are still interfering
                    dia = self.getDiameterApproximation(dependency_graph.subgraph(zhk))
                    random.seed(hash(tuple(sorted(weights)))) #Deterministic random seed, so that the LP-Solver always gets the same input for the same graph
                    while newRoundNeeded:
                        currentPaths = [] #Paths considered in this round
                        for _ in range(min(10, len(interferingPairs))): #consider the paths of 10 interfering pairs in each round
                            ifP = interferingPairs.pop(colisionIndex)
                            currentPaths.extend(list(nx.all_simple_edge_paths(dependency_graph.subgraph(zhk), ifP[0], ifP[1],0.1 * dia+4)))
                            if len(interferingPairs) > 0:
                                colisionIndex = random.randint(0, len(interferingPairs) - 1)

                        while (len(currentPaths) == 0) and (len(interferingPairs) != 0):
                            ifP = interferingPairs.pop(random.randint(0, len(interferingPairs) - 1))
                            currentPaths.extend(list(nx.all_simple_edge_paths(dependency_graph.subgraph(zhk), ifP[0], ifP[1], 0.1 * dia + 4)))

                        if len(currentPaths) == 0:
                            newRoundNeeded = False

                        #build the matrix for the LP-Solver, just like in strategy 2, but only for the paths of this round
                        for path in currentPaths:
                            row = np.zeros(len(edges)).tolist()
                            for edge in path:
                                if edge in edges:
                                    row[edges.index(edge)] = 1
                                else:
                                    row[edges.index((edge[1], edge[0]))] = 1
                            pathsEncoded.append(row)

                        if newRoundNeeded:
                            #LP-Solver like in strategy 2
                            lc = LinearConstraint(pathsEncoded, np.ones((len(pathsEncoded))), np.inf)
                            res = milp(c=weights, integrality=np.ones(len(weights)), bounds=Bounds(0, 1), constraints=lc)

                            #Check if no interfering pairs are left, if so we can stop, else we have to do another round of path generation
                            testGraph = Graph(dependency_graph.subgraph(zhk))
                            remedges = []
                            if res.success:
                                for i in range(len(res.x)):
                                    if res.x[i] == 1:
                                        remedges.append(edges[i])
                                testGraph.remove_edges_from(remedges)

                                index = self.checkIfPathExists(testGraph, interferingPairs)
                                if index == -1:
                                    #no interfering pairs left
                                    dependency_graph.remove_edges_from(remedges)
                                    newRoundNeeded = False
                                else:
                                    #start the next round with the interfering pair found in this round, as we know that it is still interfering.
                                    colisionIndex = index

                            else:
                                raise Exception("Something went wrong while solving the LP")
                
                #Resolve interferences which are not covered due to the path length condition, by applying a simple s-t-cut for them
                failCount = 0 #This number usually does not get too high, as the path lenght condition covers the vast majority of interfering pairs
                for pair in self.getInterferingPairs(dependency_graph):
                    if has_path(dependency_graph, pair[0], pair[1]):
                        self.correctedInterferencePairs += 1
                        _, (part1, part2) = minimum_cut(dependency_graph, pair[0], pair[1], capacity="score")
                        failCount += 1
                        edges = [(u, v) for u in part1 for v in dependency_graph.neighbors(u) if v in part2]
                        edges.extend([(u, v) for u in part2 for v in dependency_graph.neighbors(u) if v in part1])
                        dependency_graph.remove_edges_from(edges)
                return dependency_graph

            case _:
                raise Exception("This Multicut Algorithm is currently not implemented")

    def getDiameterApproximation(self, dependencyGraph: Graph):
        #Return an approximation of the diameter of the given graph, by calculating the shortest path length from 8 random nodes and returning the maximum of these lengths
        if (len(list(dependencyGraph.edges())) == 0) or (len(list(dependencyGraph.nodes())) == 0):
            return 0
        else:
            nodes = sorted(list(dependencyGraph.nodes()),key=lambda y: f"{y[0].name}{y[0].ssa_label}")
            random.seed(hash(tuple(nodes)))
            maximum = 0
            for _ in range(8):
                sssp = shortest_path_length(dependencyGraph, nodes[random.randint(0, len(nodes) - 1)])
                maximum = max([max(sssp.values()), maximum])
            return maximum

    def checkIfPathExists(self, dependencyGraph: Graph, pairs: List[Tuple[Tuple[Variable]]]):
        for pair in pairs:
            if has_path(dependencyGraph, pair[0], pair[1]):
                return pairs.index(pair)
        return -1

    def createRenamingMap(self, classes: List[List[Variable]]):
        count = 0
        assignedNames = [] #List of all assigned names, to avoid duplicates
        variable_for_function_arg: Dict[str, Variable] = self._get_function_argument_variables(self.task.function_parameters)
        function_arg_for_variable: Dict[Variable, str] = {v: k for k, v in variable_for_function_arg.items()}

        for varclass in classes:
            glob: List[GlobalVariable] = [k for k in varclass if isinstance(k, GlobalVariable)]
            if len(glob) != 0: #Is there a global variable in the class? If so, we use the name of the global variable for all variables in this class.
                for var in varclass: 
                    self.renaming_map[var] = GlobalVariable(
                        glob[0].name, glob[0].type, glob[0].initial_value, None, glob[0].is_aliased, var, glob[0].is_constant, glob[0].tags
                    )
            else:
                new_name = None
                # check if a function arg is in class
                for var in varclass:
                    if var in function_arg_for_variable:
                        new_name = function_arg_for_variable[var]
                        break

                # else use first name of class
                if new_name == None:
                    for var in varclass:
                        new_name = var.name
                        break

                if new_name == None:
                    new_name = f"var#{hash(frozenset(varclass))[0:5]}"

                while new_name in assignedNames:
                    new_name = f"{new_name}__{count}"
                    count += 1
                assignedNames.append(new_name)

                for var in varclass:
                    self.renaming_map[var] = Variable(new_name, var.type, None, var.is_aliased, var, var.tags)
