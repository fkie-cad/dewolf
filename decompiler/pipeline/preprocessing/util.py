"""Helper functions for modules in the preprocessing pipeline."""

from collections import defaultdict
from typing import Callable, DefaultDict, Dict, Optional, Set, Tuple

from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.maps import DefMap, UseMap
from decompiler.structures.pseudo.expressions import Constant, Expression, Variable
from decompiler.structures.pseudo.instructions import Assignment
from decompiler.structures.pseudo.operations import BinaryOperation, OperationType, UnaryOperation


def _init_maps(cfg: ControlFlowGraph) -> Tuple[DefMap, UseMap]:
    """
    Initialize the UseMap and DefMap of a given control flow graph.

    :param cfg: The control flow graphs whose use- and def-maps we want to compute.
    :return: A tuple(def_map, use_map) where def_map is the DefMap of the given control flow graph and use_map is the UseMap of the given
    control flow graph.
    """
    def_map = DefMap()
    use_map = UseMap()
    for instruction in cfg.instructions:
        def_map.add(instruction)
        use_map.add(instruction)
    return def_map, use_map


def _init_basicblocks_of_definition(cfg: ControlFlowGraph) -> Dict[Variable, BasicBlock]:
    """
    We compute for each variable the basic blocks where it is defined. This must be unique, since we are in SSA-Form

    :param cfg: Control Flow Graph
    :return: Dictionary that has as key a defined variable and as value the cfg node where the variable is defined
    """
    basicblock_of_definition = dict()
    for node in cfg.nodes:
        for instruction in node.instructions:
            for variable in instruction.definitions:
                if variable in basicblock_of_definition.keys():
                    raise ValueError(
                        f"Variable {variable} is defined twice. Once in basic block {basicblock_of_definition[variable]} and once in basic "
                        f"block {node}"
                    )
                basicblock_of_definition[variable] = node
    return basicblock_of_definition


def _init_basicblocks_usages_variable(cfg: ControlFlowGraph) -> DefaultDict[Variable, Set[BasicBlock]]:
    """
    We compute for each variable the basic blocks where it is used.

    :param cfg: Control Flow Graph
    :return: Dictionary that has as key a used variable and as value the set of cfg nodes where the variable is used
    """
    basicblocks_usages_variable: DefaultDict[Variable, Set[BasicBlock]] = defaultdict(set)
    for node in cfg.nodes:
        for instruction in node.instructions:
            for variable in instruction.requirements:
                basicblocks_usages_variable[variable].add(node)
    return basicblocks_usages_variable


def _get_last_definition(node: BasicBlock, var: Variable, max_instr_num: int) -> Optional[Tuple[int, Expression]]:
    for index in reversed(range(max_instr_num + 1)):
        instruction = node.instructions[index]
        if isinstance(instruction, Assignment) and instruction.destination == var:
            return index, instruction.value
    return None


def match_expression(node: BasicBlock, expression: Expression, pattern, instr_num=None):
    if not isinstance(pattern, tuple):
        if isinstance(pattern, Callable):
            return pattern(expression)
        else:
            return isinstance(expression, Variable) and expression.name == pattern

    if instr_num is None:
        instr_num = len(node.instructions) - 1

    inner_pattern, deref_offset = pattern
    match expression:
        case Variable() if instr_num > 0:
            last_def = _get_last_definition(node, expression, instr_num - 1)
            if last_def is not None:
                definition_instruction_num, defined_value = last_def
                # important: dont use inner_pattern here
                return match_expression(node, defined_value, pattern, definition_instruction_num)
        case UnaryOperation(OperationType.dereference, BinaryOperation(OperationType.plus, inner_expression, Constant(value=deref_offset))):
            return match_expression(node, inner_expression, inner_pattern, instr_num)
        case UnaryOperation(
            OperationType.dereference, BinaryOperation(OperationType.minus, inner_expression, Constant(value=neg_deref_offset))
        ):
            return match_expression(node, inner_expression, inner_pattern, instr_num)
        case UnaryOperation(OperationType.dereference, inner_expression) if deref_offset == 0:
            return match_expression(node, inner_expression, inner_pattern, instr_num)

    return False
