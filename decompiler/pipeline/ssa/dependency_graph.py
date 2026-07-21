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
    cfg: ControlFlowGraph, strong: float, mid: float, weak: float, ifg: InterferenceGraph) -> MultiGraph:
    """
        Construct the dependency graph of the given CFG, i.e. adds an edge between two variables if they depend on each other.
        Types of dependencies:
        - strong: assignments of the form x = y
        - mid: assignments of the form x = y + 5
        - weak: everything else (e.g. x = y + z, x = y + 5 * z, x = f(y), etc.)
    """
    dependency_graph = MultiGraph()
    for variable in _collect_variables(cfg):
        dependency_graph.add_node((variable,))

    for instruction in _assignments_in_cfg(cfg):
        instruction : Assignment
        defined_variables = instruction.definitions
        for used_variable, scorev in _expression_dependencies(instruction.value, strong, mid, weak).items():
            if (scorev > 0) and not (ifg.are_interfering(*defined_variables, used_variable)) and not (variablesAreInterfering(ifg, defined_variables[0], used_variable)):
                for dvar in defined_variables:
                        dependency_graph.add_edge((dvar,), (used_variable,), score=scorev)
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


def _get_base_operands(expression: list[Expression]) -> list:
    """
    Recursively collects all base operands (variables and constants) from the given expression list.
    expression: The right hand side of an assignment, which can be a complex expression.
    Returns a list of base operands found in the expression.
    """
    islow = False
    parts = list()
    remains = list()
    remains.extend(expression)

    while len(remains) != 0:
        exp = remains.pop()

        if isinstance(exp, GlobalVariable):
            pass #We do not want dependencys form or to global variables, but we need them as a node otherwise they are merged into a class of non interfering variables
        elif isinstance(exp, Variable):
            parts.append(exp)
        elif (isinstance(exp, Constant)) and (not isinstance(exp, (Symbol, NotUseableConstant, GlobalVariable))):
            parts.append(exp)
        elif isinstance(exp, Operation) and (
            (not isinstance(exp, (ListOperation, UnaryOperation, Call, TernaryExpression)))
            or (isinstance(exp, UnaryOperation) and ((exp.operation == OperationType.cast)))
        ):
            remains += exp.operands
        elif isinstance(exp, Operation) and (
            (
                isinstance(exp, UnaryOperation)
                and (
                    (exp.operation == OperationType.dereference)
                    or (exp.operation == OperationType.address)
                    or (exp.operation == OperationType.pointer)
                )
            )
        ): #Pointer arithmetic is not a strong dependency, but we still want to know about it, so we treat it as a weak dependency, this is expressed by islow
            remains += exp.operands
            islow = True
        elif isinstance(exp, Call):
            remains += exp.parameters
            islow = True
    return list(set(parts)), islow #if islow is True, then all dependencies are weak, even if there is only one variable in the expression


def _expression_dependencies(expression: Expression, strong: float, mid: float, weak: float) -> dict[Variable, float]:
    """
    Calculate the dependencies of an expression in terms of its constituent variables.

    This function analyzes the given expression and returns a dictionary mapping each
    Variable to a float score representing its contribution/ dependency weight within
    the expression.
    """
    operands_dependencies, low = _get_base_operands([expression])
    #if low is True the function tells us that even if there is only one variable in the expression, it should be treated as a weak dependency
    if (len(operands_dependencies) == 1) and (isinstance(operands_dependencies[0], Variable)):
        if not low:
            return {operands_dependencies[0]: strong}
        else:
            return {operands_dependencies[0]: weak}
    elif len(operands_dependencies) > 1:
        vars = [var for var in operands_dependencies if isinstance(var, Variable)] # assignments in the form of x = y + 5 earns a mid dependency, everything else is a weak dependency.
        if (len(vars) == 1) and (not low):
            return {vars[0]: mid}
        else:
            return {x: weak for x in vars}
    else:
        return {}
