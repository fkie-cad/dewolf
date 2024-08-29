"""Helper functions for modules in the preprocessing pipeline."""

from collections import defaultdict
from typing import Callable, DefaultDict, Dict, List, Optional, Set, Tuple

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


def _unused_addresses(cfg: ControlFlowGraph, amount: int = 1) -> List[int]:
    """Returns a list with the specified amount of addresses, which are not used by any block of the given CFG."""
    used_addresses = {c.address for c in cfg.nodes}
    address = -1

    addresses = list()

    for _ in range(amount):
        while address in used_addresses:
            address -= 1
        used_addresses.add(address)
        addresses.append(address)

    return addresses


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
    """This helper method finds a variable's last definition within a Block. Only instructions up to `max_instr_num` are considered.
    It returns the instructions position and the assigned value if a definition exists and none otherwise."""
    for index in reversed(range(max_instr_num + 1)):
        instruction = node.instructions[index]
        if isinstance(instruction, Assignment) and instruction.destination == var:
            return index, instruction.value
    return None


def match_expression(node: BasicBlock, expression: Expression, pattern, instr_num=None):
    """This function checks whether the given `expression` matches the specified `pattern`.

    The function uses recursion to check whether the provided `expression` matches the given `pattern`. 
    It also considers the instructions defined earlier in the provided `node` (a `BasicBlock`) to resolve variable definitions.

    Args:
        node (BasicBlock): The basic block containing instructions that define variables and their usage.
        expression (Expression): The expression to be matched against the `pattern`.
        pattern (tuple or Callable or str): The pattern used for matching. 
            Patterns are nested tuples representing the structure of expressions, constants, and operations. 
            The innermost (first) entry in a pattern is either:
              - A string representing a variable name to be matched exactly.
              - A function (Callable) that takes an `expression` and returns `True` if the expression matches some criteria, `False` otherwise.
            The rest of the entries are constants representing offsets or operations to be dereferenced. 
            For example:
              - (self._match_r14, 0x10) 
              - ((("gsbase", 0), -4), 0x8) 
            The latter pattern represents an expression equivalent to *(*(*(gsbase+0) - 4) + 8).
        instr_num (int, optional): The instruction number to start searching backwards for variable definitions. 
            If not provided, it defaults to the last instruction in the `node`.

    Returns:
        bool: Returns `True` if the `expression` matches the specified `pattern`, `False` otherwise.

    The function operates as follows:
    - If the pattern is not a tuple, it checks if it's a callable or a string:
      - If callable, it calls the pattern function with `expression`.
      - If string, it checks if the `expression` is a `Variable` and its name matches the string.
    - If the pattern is a tuple, it extracts the inner pattern and dereference offset and tries to match:
      - If the expression is a `Variable` and there are earlier instructions, it retrieves the last definition of the variable and recursively checks.
      - If the expression involves dereferencing with specific operations (plus or minus with constants), it adjusts and continues matching.
      - It also handles simple dereferences when the offset is zero.
    - The function returns `False` if no match is found according to the above rules.
    """
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
