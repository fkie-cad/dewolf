"""Module for renaming variables in Out of SSA."""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import combinations, chain
from operator import attrgetter, itemgetter
from typing import DefaultDict, Dict, Iterable, Iterator, List, Optional, Set, Tuple, Union
import networkx as nx
import numpy as np
import secrets
from copy import deepcopy
from logging import debug
from scipy.optimize import milp, Bounds, LinearConstraint
from decompiler.pipeline.ssa.dependency_graph import dependency_graph_from_cfg, decorate_dependency_graph, _collect_variables
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import BaseAssignment, Instruction, Relation
from decompiler.structures.pseudo.typing import Type
from decompiler.task import DecompilerTask
from decompiler.util.insertion_ordered_set import InsertionOrderedSet
from decompiler.util.lexicographical_bfs import LexicographicalBFS
from networkx import Graph, MultiDiGraph, connected_components, shortest_path_length ,MultiGraph, has_path, minimum_cut, relabel_nodes, selfloop_edges, subgraph
from decompiler.util.decoration import DecoratedCFG

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
        def __init__(self,s : Tuple[Variable], t : Tuple[Variable], part1 : list[tuple[Variable]], part2 :list[tuple[Variable]], weight :int):
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

    
    def __init__(self, task: DecompilerTask, interference_graph: InterferenceGraph, strong : float, mid: float, weak: float, strat :int = 1):
        """
        self._color_classes is a dictionary where the set of keys is the set of colors
        and to each color we assign the set of variables of this color.
        """

        super().__init__(task, interference_graph.copy())
        self.strongDep = strong
        self.midDep = mid
        self.weakDep = weak
        self.strat = strat
        self.correctedInterferencePairs = 0
        self.interference_graph = interference_graph
        self.task = task
        self.helpvalue = pow(2,40)
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
        dependency_graph = dependency_graph_from_cfg(cfg,self.strongDep,self.midDep,self.weakDep,self.interference_graph)
        #dependency_graph = MultiGraph(dependency_graph)
        dependency_graph = self.merge_contracted_variables(dependency_graph)

        dependency_graph = self.replaceSymbolicValuesWithConcreteDependencyNumbers(dependency_graph,self.strongDep,self.midDep, self.weakDep)

        dependency_graph = self.create_variable_classes(dependency_graph)

        #assert (self.checkResult(dependency_graph))
 
        self.createRenamingMap(self.extractClasses(dependency_graph))

    def replaceSymbolicValuesWithConcreteDependencyNumbers(self, dependency_graph : Graph, strong : float, mid : float, weak : float):
        for edge in dependency_graph.edges(data=True):
            match edge[2]["a"]:
                case self.strongDep:
                    edge[2]["score"] = strong
                case self.midDep:
                    edge[2]["score"] = mid
                case self.weakDep:
                    edge[2]["score"] = weak
                case self.helpvalue:
                    edge[2]["score"] = self.helpvalue
        return dependency_graph
    
    def extractClasses(self,dependency_graph : Graph) -> List[List[Variable]]:
        """Extracts variables, which can have the same name out of the dependency graph"""
        res = []
        for comp in connected_components(dependency_graph):
            res.append(list(chain(*comp)))
        return res
    
    def checkResult(self, dependency_graph : MultiGraph ):
        for comp in connected_components(dependency_graph):
            compVars = []
            for tup in comp:
                for var in tup:
                    compVars.append(var)
            if self.interference_graph.are_interfering(*compVars):
                raise Exception(f"Two Variables in one connected component are interfering!")
        return True


    def merge_contracted_variables(self, dependency_graph: MultiGraph):
        """Here we handle variables, which have get the same."""
        for instr in self.cfg.instructions:
            if isinstance(instr,Relation) and (instr.destination != instr.value):
                dependency_graph.add_edge((instr.destination,),(instr.value,),a=self.helpvalue)

        return dependency_graph    

    def multiGraphToGraph(self, dependency_graph: MultiGraph) -> Graph:
        res = Graph()
        for node in dependency_graph.nodes():
            res.add_node(node)
        for u,v,d in dependency_graph.edges(data=True):
            if res.has_edge(u,v):
                val = res.get_edge_data(u,v)["score"]
                res.remove_edge(u,v)
                val += d["score"]
                res.add_edge(u,v,score=val)
            else:
                res.add_edge(u,v,score=d["score"])
        return res
    
    def getInterferingPairs(self,dependency_graph: Graph):
        interferingPairs = list()
        for zhk in connected_components(dependency_graph):
            for var1, var2 in combinations(zhk,2):
                if self.interference_graph.are_interfering(*var1,*var2):
                    interferingPairs.append((var1,var2))
        return interferingPairs

    def create_variable_classes(self, dependency_graph: MultiGraph):
        """Create the variable classes based on the given dependency graph."""
        match self.strat:

            case 0: #Greedy Multicut through s-t-Cuts
            
                dependency_graph.remove_edges_from(list(selfloop_edges(dependency_graph))) #remove loops, as they cause problems but don't add any value in our situation
                dependency_graph = self.multiGraphToGraph(dependency_graph)

                zhkList = list(connected_components(dependency_graph))
                for zhk in zhkList:
                    cuts = []
                    interferingPairs = self.getInterferingPairs(dependency_graph.subgraph(zhk))
                    for pair in interferingPairs:
                        weight, (part1, part2) = minimum_cut(dependency_graph.subgraph(zhk),pair[0],pair[1],capacity="score")
                    
                        #edges = {(u, v) for u in part1 for v in dependency_graph.neighbors(u) if v in part2}
                        cuts.append(StCutStorage(pair[0],pair[1],part1,part2,weight))
                        cuts.sort(key=attrgetter("weight"))
                    for x in cuts:
                        x : ConditionalVariableRenamer.StCutStorage
                        if has_path(dependency_graph.subgraph(zhk),x.s,x.t):
                            dependency_graph.remove_edges_from([(u, v) for u in x.part1 for v in dependency_graph.neighbors(u) if v in x.part2]) #remove the edges of the cut
                        #assert not has_path(dependency_graph,x.s,x.t)

                return dependency_graph
            
            case 1: #simple combination of mulitcuts; lower runtime than 0 but approximation factor is worse

                dependency_graph.remove_edges_from(list(selfloop_edges(dependency_graph))) #remove loops, as they cause problems but don't add any value in our situation
                dependency_graph = self.multiGraphToGraph(dependency_graph)

                zhkList = list(connected_components(dependency_graph))
                for zhk in zhkList:
                    cuts = []
                    interferingPairs = self.getInterferingPairs(dependency_graph.subgraph(zhk))
                    for pair in interferingPairs:
                        if has_path(dependency_graph.subgraph(zhk),pair[0],pair[1]):
                            _, (part1, part2) = minimum_cut(dependency_graph.subgraph(zhk),pair[0],pair[1],capacity="score")
                    
                            edges = [(u, v) for u in part1 for v in dependency_graph.neighbors(u) if v in part2]
                            dependency_graph.remove_edges_from(edges)


                return dependency_graph

            case 2: #use LP-Solver to calculate Quasi-optimal solution for MultiCut; because we want to keep the runtime in bounds the solution is only quasi-optimal with a few pairs of interfering variables being not seperated optimally
                dependency_graph.remove_edges_from(list(selfloop_edges(dependency_graph))) #remove loops, as they cause problems but don't add any value in our situation
                dependency_graph = self.multiGraphToGraph(dependency_graph)

                zhkList = list(connected_components(dependency_graph))
                zhkList = [x for x in zhkList if len(x) > 0]
                for zhk in zhkList:

                    edges = list(dependency_graph.subgraph(zhk).edges(data=True))
                    if len(edges) == 0: continue
                    interferingPairs = self.getInterferingPairs(dependency_graph.subgraph(zhk))
                    weights = [edge[2]["score"] for edge in edges]
                    edges = list(dependency_graph.subgraph(zhk).edges())

                    paths = []

                    dia = self.getDiameterApproximation(dependency_graph.subgraph(zhk))
                    for x in interferingPairs:
                        paths.extend(list(nx.all_simple_edge_paths(dependency_graph.subgraph(zhk),x[0],x[1],0.075*dia)))
                    if len(paths) == 0:
                        continue
                    pathsEncoded = []
                    for path in paths:
                        entry = np.zeros(len(edges)).tolist()
                        for edge in path:
                            if edge in edges:
                                entry[edges.index(edge)] = 1
                            else:
                                entry[edges.index((edge[1],edge[0]))] = 1

                        pathsEncoded.append(entry)
                    
                    lc = LinearConstraint(pathsEncoded,np.ones((len(paths),)),np.inf)
                    res = milp(c = weights,integrality=np.ones(len(weights)),bounds=Bounds(0,1),constraints=lc)
                    remedges = []
                    if (res.success):
                        if res.status != 0:
                            debug(f"LP-Solver: Status: {res.status}; Bound: {res.mip_dual_bound}")
                        for i in range(len(res.x)):
                            if res.x[i] == 1:
                                remedges.append(edges[i])
                        dependency_graph.remove_edges_from(remedges)
                    else:
                        raise Exception("Something went wrong while solving the LP")
                ifp = self.getInterferingPairs(dependency_graph)
                for pair in ifp:
                    if has_path(dependency_graph,pair[0],pair[1]):
                        self.correctedInterferencePairs += 1
                        _, (part1, part2) = minimum_cut(dependency_graph,pair[0],pair[1],capacity="score")
                    
                        edges = [(u, v) for u in part1 for v in dependency_graph.neighbors(u) if v in part2]
                        dependency_graph.remove_edges_from(edges)
                return dependency_graph

            case 3: 
                
                dependency_graph.remove_edges_from(list(selfloop_edges(dependency_graph))) #remove loops, as they cause problems but don't add any value in our situation
                dependency_graph = self.multiGraphToGraph(dependency_graph)

                zhkList = list(connected_components(dependency_graph))
                zhkList = [x for x in zhkList if len(x) > 0]
                for zhk in zhkList:
                    
                    edges = list(dependency_graph.subgraph(zhk).edges(data=True))
                    if len(edges) == 0: continue
                    interferingPairs = list(self.getInterferingPairs(dependency_graph.subgraph(zhk)))
                    if len(interferingPairs) == 0: continue

                    weights = [edge[2]["score"] for edge in edges]
                    edges = list(dependency_graph.subgraph(zhk).edges())

                    pathsEncoded = []
                    colisionIndex = 0
                    newRoundNeeded = True
                    dia = self.getDiameterApproximation(dependency_graph.subgraph(zhk))
                    while newRoundNeeded:
                        currentPaths = []
                        for _ in range(min(10,len(interferingPairs))):
                            ifP = interferingPairs.pop(colisionIndex)
                            currentPaths.extend(list(nx.all_simple_edge_paths(dependency_graph.subgraph(zhk),ifP[0],ifP[1],0.075*dia)))
                            if len(interferingPairs) > 0:
                                colisionIndex = secrets.randbelow(len(interferingPairs))
                        
                        while (len(currentPaths) == 0) and (len(interferingPairs) != 0):
                            ifP = interferingPairs.pop(secrets.randbelow(len(interferingPairs)))
                            currentPaths.extend(list(nx.all_simple_edge_paths(dependency_graph.subgraph(zhk),ifP[0],ifP[1],0.075*dia)))
                        
                        if len(currentPaths) == 0:
                            newRoundNeeded = False
                        
                        
                        for path in currentPaths:
                            entry = np.zeros(len(edges)).tolist()
                            for edge in path:
                                if edge in edges:
                                    entry[edges.index(edge)] = 1
                                else:
                                    entry[edges.index((edge[1],edge[0]))] = 1
                            pathsEncoded.append(entry)
                        
                        if newRoundNeeded:
                            lc = LinearConstraint(pathsEncoded,np.ones((len(pathsEncoded))),np.inf)
                            res = milp(c = weights,integrality=np.ones(len(weights)),bounds=Bounds(0,1),constraints=lc)

                            testGraph = Graph(dependency_graph.subgraph(zhk))
                            remedges = []
                            if (res.success):
                                for i in range(len(res.x)):
                                    if res.x[i] == 1:
                                        remedges.append(edges[i])
                                testGraph.remove_edges_from(remedges)
                                                      
                                index = self.checkIfPathExists(testGraph,interferingPairs)
                                if index == -1:
                                    dependency_graph.remove_edges_from(remedges)
                                    newRoundNeeded = False
                                else:
                                    colisionIndex = index

                            else:
                                raise Exception("Something went wrong while solving the LP")
                    

                for pair in self.getInterferingPairs(dependency_graph):
                    if has_path(dependency_graph,pair[0],pair[1]):
                        self.correctedInpyinstrumentterferencePairs += 1
                        _, (part1, part2) = minimum_cut(dependency_graph,pair[0],pair[1],capacity="score")
                    
                        edges = [(u, v) for u in part1 for v in dependency_graph.neighbors(u) if v in part2]
                        dependency_graph.remove_edges_from(edges)
                return dependency_graph

            case _: 
                raise Exception("This Multicut Algorithm is currently not implemented")
                
    def getDiameterApproximation(self,dependencyGraph : Graph):
        if (len(list(dependencyGraph.edges())) == 0) or (len(list(dependencyGraph.nodes())) == 0):
            return 0
        else:
            nodes = list(dependencyGraph.nodes())
            maximum = 0
            for _ in range(5):
                sssp = shortest_path_length(dependencyGraph,nodes[secrets.randbelow(len(nodes))])
                maximum = max([max(sssp.values()),maximum])
            return maximum

    def checkIfPathExists(self, dependencyGraph : Graph, pairs : List[Tuple[Tuple[Variable]]]):
        for pair in pairs:
            if has_path(dependencyGraph,pair[0],pair[1]):
                return pairs.index(pair)
        return -1

    def createRenamingMap(self,classes : List[List[Variable]]):
        count = 0
        assignedNames = []
        variable_for_function_arg: Dict[str, Variable] = self._get_function_argument_variables(self.task.function_parameters)
        function_arg_for_variable: Dict[Variable, str] = {v: k for k, v in variable_for_function_arg.items()}

        for varclass in classes:
                glob: List[GlobalVariable] = [k for k in varclass if isinstance(k,GlobalVariable)]
                if len(glob) != 0:
                        for var in varclass:
                            self.renaming_map[var] = GlobalVariable(glob[0].name, glob[0].type, glob[0].initial_value, None, glob[0].is_aliased, var, glob[0].is_constant, glob[0].tags)
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
                        raise Exception("Found no suitable name for connected component")
                    
                    if new_name in assignedNames:
                        new_name = f"{new_name}__{count}"
                        count += 1
                    assignedNames.append(new_name)

                    for var in varclass:
                        self.renaming_map[var] = Variable(new_name, var.type, None, var.is_aliased, var, var.tags)
