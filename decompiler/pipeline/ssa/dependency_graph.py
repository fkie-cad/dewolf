import itertools
from itertools import combinations
from typing import Iterator

import networkx as nx
import networkx
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import Expression, Operation, OperationType,ListOperation,UnaryOperation,Call,TernaryExpression
from decompiler.structures.pseudo.expressions import Variable, Constant, GlobalVariable,Symbol,NotUseableConstant
from decompiler.structures.pseudo.instructions import Assignment
from decompiler.util.decoration import DecoratedGraph
from networkx import MultiDiGraph, to_undirected, MultiGraph


def decorate_dependency_graph(dependency_graph: MultiDiGraph, interference_graph: InterferenceGraph) -> DecoratedGraph:
    """
    Creates a decorated graph from the given dependency and interference graphs.

    This function constructs a new graph where:
    - Variables are represented as nodes.
    - Dependencies between variables are represented as directed edges.
    - Interferences between variables are represented as red, undirected edges.
    """
    decorated_graph = MultiDiGraph()
    for node in dependency_graph.nodes:
        decorated_graph.add_node(hash(node), label="\n".join(map(lambda n: f"{n}: {n.type}, aliased: {n.is_aliased}", node)))
    for u, v, data in dependency_graph.edges.data():
        decorated_graph.add_edge(hash(u), hash(v), label=f"{data['score']}")
    for nodes in networkx.weakly_connected_components(dependency_graph):
        for node_1, node_2 in combinations(nodes, 2):
            if any(interference_graph.has_edge(pair[0], pair[1]) for pair in itertools.product(node_1, node_2)):
                decorated_graph.add_edge(hash(node_1), hash(node_2), color="red", dir="none")

    return DecoratedGraph(decorated_graph)

def dependency_graph_from_cfg(cfg: ControlFlowGraph, strong: float, mid :float, weak: float, ifg : InterferenceGraph) -> MultiGraph:
    """
    Construct the dependency graph of the given CFG, i.e. adds an edge between two variables if they depend on each other.
        - Add an edge the definition to at most one requirement for each instruction.
        - All variables that where not defined via Phi-functions before have out-degree of at most 1, because they are defined at most once.
        - Variables that are defined via Phi-functions can have one successor for each required variable of the Phi-function.
    """
    dependency_graph = MultiGraph()
    for variable in _collect_variables(cfg):
        dependency_graph.add_node((variable,))
    for instruction in _assignments_in_cfg(cfg):
        defined_variables = instruction.definitions
        for used_variable, score in _expression_dependencies(instruction.value,strong,mid,weak).items():
            if (score > 0) and  not (ifg.are_interfering(*defined_variables,used_variable)):
                for dvar in defined_variables:
                    if (score != weak) or (not foo(dvar,used_variable)):
                        dependency_graph.add_edge((dvar,),(used_variable,),a=score)
                    else:
                        dependency_graph.add_edge((dvar,),(used_variable,),a=mid)
                #dependency_graph.add_edges_from((((dvar,), (used_variable,),"a",score) if  else ((dvar,), (used_variable,),"a",mid) for dvar in defined_variables ))
    return dependency_graph

def foo(a,b):
    return False


def _collect_variables(cfg: ControlFlowGraph) -> Iterator[Variable]:
    """
    Yields all variables contained in the given control flow graph.
    """
    for instruction in cfg.instructions:
        for subexpression in instruction.subexpressions():
            if (isinstance(subexpression, Variable)) and (not isinstance(subexpression,UnaryOperation)):
                yield subexpression


def _assignments_in_cfg(cfg: ControlFlowGraph) -> Iterator[Assignment]:
    """Yield all interesting assignments for the dependency graph."""
    for instr in cfg.instructions:
        if isinstance(instr, Assignment):
            yield instr

def _get_base_operands(expression :list [Expression]) -> list:
    islow = False
    parts = list()
    remains = list()
    remains.extend(expression)

    while len(remains) != 0:
        exp = remains.pop()
        
        if isinstance(exp,GlobalVariable):
                parts.append(exp)
        elif isinstance(exp,Variable):
                parts.append(exp)
        elif (isinstance(exp, Constant)) and (not isinstance(exp,(Symbol,NotUseableConstant,GlobalVariable))):
                parts.append(exp)
        elif isinstance(exp, Operation) and ((not isinstance(exp,(ListOperation,UnaryOperation,Call,TernaryExpression))) or (isinstance(exp,UnaryOperation) and ((exp.operation == OperationType.cast )))):
                remains += exp.operands
        elif isinstance(exp, Operation) and ((not isinstance(exp,(ListOperation,Call,TernaryExpression))) or (isinstance(exp,UnaryOperation) and ((exp.operation == OperationType.dereference ) or (exp.operation == OperationType.address) or (exp.operation == OperationType.pointer)))):
                remains += exp.operands
                islow = True
        elif isinstance(exp,Call):
                remains += exp.parameters
                islow = True
    return list(set(parts)), islow


def _expression_dependencies(expression: Expression, strong : float, mid: float, weak : float) -> dict[Variable, float]:
    """
    Calculate the dependencies of an expression in terms of its constituent variables.

    This function analyzes the given `expression` and returns a dictionary mapping each
    `Variable` to a float score representing its contribution or dependency weight within
    the expression.
    """
    operands_dependencies, low = _get_base_operands([expression])
    if (len(operands_dependencies) == 1) and (isinstance(operands_dependencies[0],Variable)):
        if not low:
            return {operands_dependencies[0] : strong}
        else: 
                return {operands_dependencies[0] : weak}
    elif (len(operands_dependencies) > 1):
        vars = [var for var in operands_dependencies if isinstance(var,Variable)]
        if (len(vars) == 1) and (not low):
            return {vars[0] : mid}
        else: 
            return {x : weak for x in vars}
    else: 
        return {}
