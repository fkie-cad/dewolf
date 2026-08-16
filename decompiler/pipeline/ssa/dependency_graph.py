import itertools
from itertools import combinations
from typing import Iterator

import networkx
import networkx as nx
from decompiler.pipeline.ssa.metric_helper import MetricHelper
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import Call, Expression, ListOperation, Operation, OperationType, TernaryExpression, UnaryOperation
from decompiler.structures.pseudo.expressions import Constant, GlobalVariable, NotUseableConstant, Symbol, Variable
from decompiler.structures.pseudo.instructions import Assignment
from decompiler.util.decoration import DecoratedGraph
from networkx import MultiDiGraph, MultiGraph, to_undirected
from itertools import product

# legacy code, not used anymore, but maybe useful in the future
#def decorate_dependency_graph(dependency_graph: MultiDiGraph, interference_graph: InterferenceGraph) -> DecoratedGraph:
#    """
#    Creates a decorated graph from the given dependency and interference graphs.
#
#    This function constructs a new graph where:
#    - Variables are represented as nodes.
#    - Dependencies between variables are represented as directed edges.
#    - Interferences between variables are represented as red, undirected edges.
#    """
#    decorated_graph = MultiDiGraph()
#    for node in dependency_graph.nodes:
#        decorated_graph.add_node(hash(node), label="\n".join(map(lambda n: f"{n}: {n.type}, aliased: {n.is_aliased}", node)))
#    for u, v, data in dependency_graph.edges.data():
#        decorated_graph.add_edge(hash(u), hash(v), label=f"{data['score']}")
#    for nodes in networkx.weakly_connected_components(dependency_graph):
#        for node_1, node_2 in combinations(nodes, 2):
#            if any(interference_graph.has_edge(pair[0], pair[1]) for pair in itertools.product(node_1, node_2)):
#                decorated_graph.add_edge(hash(node_1), hash(node_2), color="red", dir="none")
#
#    return DecoratedGraph(decorated_graph)


def dependency_graph_from_cfg(
    cfg: ControlFlowGraph, parameters: list[float], intercept: float, ifg: InterferenceGraph) -> MultiGraph:
    """
        Construct the dependency graph of the given CFG, i.e. adds an edge between two variables if they depend on each other.
    """
    dependency_graph = MultiGraph()
    for variable in _collect_variables(cfg):
        dependency_graph.add_node((variable,))

    for instruction in _assignments_in_cfg(cfg):
        instruction : Assignment
        lhs = instruction.destination
        rhs = instruction.value

        #Insertion and deduplication of edges in the dependency graph. If an edge already exists, we keep the one with the higher score.
        for (a, b), scorev in _expression_dependencies(lhs, rhs, parameters, intercept):
            a : Variable
            b : Variable
            scorev : float
            
            if (scorev > 0) and not (ifg.are_interfering(a,b)) and not (variablesAreInterfering(ifg, a, b)):
                scorev = max(scorev,0.05)
                if dependency_graph.has_edge((a,), (b,)):
                    exScore = dependency_graph.get_edge_data((a,), (b,),"score",0)
                    dependency_graph.remove_edge((a,), (b,))
                    if scorev < exScore:
                        scorev = exScore
                dependency_graph.add_edge((a,), (b,), score=scorev)
    return dependency_graph

def variablesAreInterfering(interference_graph: InterferenceGraph, var_X: Variable,var_Y: Variable) -> bool:
    if interference_graph.are_interfering(*var_X, *var_Y):
        return True
    elif var_X.type != var_Y.type:
        return True
    elif (var_X.is_aliased != var_Y.is_aliased) or (var_X.is_aliased and var_Y.is_aliased and (var_X.name != var_Y.name)):
        return True
    elif isinstance(var_X, GlobalVariable) != isinstance(var_Y, GlobalVariable):
        return True
    elif (isinstance(var_X,GlobalVariable) and  isinstance(var_Y,GlobalVariable) and (var_X.name != var_Y.name)):
        return True

    if(var_X.type == None) or (var_Y.type == None):
        raise Exception("Encountered a None type variable in the SSA-Stage!")
    
    return False


def _collect_variables(cfg: ControlFlowGraph) -> Iterator[Variable]:
    """
    Yields all variables contained in the given control flow graph.
    """
    for instruction in cfg.instructions:
        for subexpression in instruction.subexpressions():
            if (isinstance(subexpression, Variable)) and (not isinstance(subexpression, UnaryOperation)):
                yield subexpression


def _assignments_in_cfg(cfg: ControlFlowGraph) -> Iterator[Assignment]:
    """Yield all interesting assignments for the dependency graph."""
    for instr in cfg.instructions:
        if isinstance(instr, Assignment):
            yield instr


def getVariablesAndConstants(expr : Expression):
        badOperations = [OperationType.dereference, OperationType.address, OperationType.dereference, OperationType.call, OperationType.pointer, OperationType.ternary, OperationType.list_op, OperationType.field, OperationType.member_access]
        vars = []
        consts = []
        hasBadOperations = False
        for component in expr.subexpressions():
            if isinstance(component, Variable):
                vars.append(component)
            elif isinstance(component, Constant):
                consts.append(component)
            elif isinstance(component, Operation):
                component:Operation
                if component.operation in badOperations:
                    hasBadOperations = True
        return vars, consts, hasBadOperations


def _expression_dependencies(lhs: Expression, rhs: Expression, parameters: list[float], intercept: float) -> list[tuple[Variable, Variable], float]:
    """
    Calculate the dependencies of an expression in terms of its constituent variables.
    We use different attributes to describe the strength of the dependency. 
    The order of the attributes has to be the SAME as in the ConditionalSSATraining class and in the FEATURES list in the conditionalTrainingRunner.py file. 
    """
    result = []
    if (lhs is None) or (rhs is None):
        return result
    vlhs, _, bO1 = getVariablesAndConstants(lhs)
    vrhs, crhs, bO2 = getVariablesAndConstants(rhs)
    vrhs : list[Variable]
    vlhs : list[Variable]

    if (len(vlhs) == 0) or (len(vrhs) == 0):
        return result

    for x, y in product(vlhs, vrhs):
        edgeScore = 0

        # --- Attributes ---
        #Attirbute 1: is_strong --> if the assignment has roughly the form x = y with x and y being two variables
        if (len(vrhs) == 1) and (len(crhs) == 0) and (len(vlhs) == 1) and (not bO1) and (not bO2):
            edgeScore += parameters[0]

        #Attribute 2: is_mid --> if the assignment has roughly the form x = y + c with c being a constant. Further there shouldn't be a cast, a copy or pointer arithmetic in the rhs Expression.
        if (edgeScore == 0) and (len(vrhs) == 1) and (len(crhs) == 1) and (len(vlhs) == 1) and (not bO1) and (not bO2):
            edgeScore += parameters[1]

        #Attribute 3: same_base_name --> if all participating variables have the same base name (var.name)
        if x.name == y.name:
            edgeScore += parameters[2]

        #Attribute 4: same_storage --> if all participating variables have the same storage (var.ssa_name.origin)
        if (x.origin and y.origin): #origin is not alyways set --> variables inserted by the compiler
            if (x.origin.source_type == y.origin.source_type) and (x.origin.storage == y.origin.storage):
                edgeScore += parameters[3]


        edgeScore += intercept
        result.append(((x, y), edgeScore))

    return result
