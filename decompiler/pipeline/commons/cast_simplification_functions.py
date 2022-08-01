from typing import Iterator, Tuple

from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Constant,
    DataflowObject,
    Expression,
    Instruction,
    Integer,
    OperationType,
    Type,
    UnaryOperation,
    Variable,
)

MAX_REGISTER_SIZE = 64


def simplify_casts_in_instruction(instruction: Instruction):
    """
    Applies various rules in order to simplify instruction with respect to cast operations contained in it
    since e.g. various casts that we often get on 64-bit come not from the source code, but from compiler tying to fit
    variables in larger registers
    """
    _merge_larger_casts_into_smaller(instruction)
    _replace_contraction_with_var_where_possible(instruction)
    _replace_contraction_with_cast(instruction)
    _remove_cast_to_largest_register(instruction)
    _remove_casts_of_subexpressions_to_the_same_type(instruction)
    _remove_casts_where_type_of_var_is_same_to_casted(instruction)


def _merge_larger_casts_into_smaller(instruction: Instruction):
    """
    Replace (larger_type)(smaller type) var with (smaller_type) var
    but only for expressions that come from zero/sign extension but not from contraction (contraction field of cast set to true,
    "cuts" the lowest bytes of a variable)
    :param instruction: instruction with contractions and casts
    """
    for expr in _find_cast_subexpressions(instruction):
        if _is_cast(expr.operand):
            cast_operand = expr.operand
            if not (expr.contraction or cast_operand.contraction):
                if _is_larger_int_type(expr.type, cast_operand.type):
                    instruction.substitute(expr, cast_operand)


def _replace_contraction_with_var_where_possible(instruction: Instruction):
    """
    Replace (1byte-contract)(larger_type)(smaller type) var(1byte) with var(1byte) var
    But do not replace (x byte-contract)(larger_type)(smaller type) var(y byte) with var(y byte) if contraction size does not match
    variable size
    And do not replace if smallest cast type is smaller as var type and size of contraction type
    :param instruction: instruction with contractions and casts
    """
    for expr in _find_cast_subexpressions(instruction):
        if _is_cast(expr.operand) and expr.contraction:
            if expr.type.size < expr.operand.type.size:
                if expr.type.size == expr.operand.operand.type.size:
                    instruction.substitute(expr, expr.operand.operand)


def _replace_contraction_with_cast(instruction: Instruction):
    """
    If no other possibility to get rid of contraction, replace it with cast to the same type
    if operand is also the cast, and replacement resulted in (contract type A) (type A) -> (type A) (type A),
    merge two casts to the same one (type A)

    E.g. (contract 4 bytes) (var:long) -> (int) (var:long)
         (contract 4 bytes) (var:int) (var:long) -> (int)(int) (var:long) -> (int) (var long)
    :param instruction: instruction potentially containing field accesses and casts
    """
    for expr in _find_cast_subexpressions(instruction):
        if expr.contraction:
            expr.contraction = False
            if _is_cast(expr.operand) and expr.operand.type == expr.type:
                instruction.substitute(expr, expr.operand)


def _remove_cast_to_largest_register(instruction: Instruction):
    """
    Motivated by implicit conversion when assigning smaller type variable to larger type
    we transform
    (unsigned long) (unsigned/signed int) var to (unsigned/signed int) var
    cause in the C code when doing
    long x = y:int // long x = sx.q(y) == long x = (long) y
    unsigned long x = y:unsigned int // long x = zx.q(y) == unsigned long x = (unsigned long) y
    :param instruction: instruction potentially containing field accesses and casts

    Currently only for 64 bit.

    Mandatory the last step, after no expression propagation is performed
    """
    for _, expr in _find_cast_subexpressions_filter_bitwise_binops_parents(instruction):
        if expr.type.size == MAX_REGISTER_SIZE:
            instruction.substitute(expr, expr.operand)


def _remove_casts_of_subexpressions_to_the_same_type(instruction: Instruction):
    """Replaces (int) ((int) var + x) with (int) (var + x)"""
    for expr in _find_cast_subexpressions(instruction):
        for subexpr in _find_cast_subexpressions(expr):
            if expr.type == subexpr.type:
                expr.substitute(subexpr, subexpr.operand)


def _remove_casts_where_type_of_var_is_same_to_casted(instruction: Instruction):
    """Replaces (int) var:int with var:int"""
    for expr in _find_cast_subexpressions(instruction):
        if expr.operand.type == expr.type:
            instruction.substitute(expr, expr.operand)


def _find_cast_subexpressions(expression: DataflowObject) -> Iterator[UnaryOperation]:
    """Yield all subexpressions of the given expression or instruction."""
    todo = [expression]
    while todo and (subexpression := todo.pop()):
        todo.extend(subexpression)
        if not (isinstance(expression, Assignment) and expression.destination == subexpression) and _is_cast(
                subexpression):
            yield subexpression


def _find_cast_subexpressions_filter_bitwise_binops_parents(expression: DataflowObject) -> Iterator[Tuple[UnaryOperation]]:
    """Yield all subexpressions of the given expression or instruction."""
    todo = [expression]
    operations_to_not_remove_casts = {OperationType.right_shift, OperationType.left_shift,
                                      OperationType.right_shift_us, OperationType.bitwise_and,
                                      OperationType.bitwise_or, OperationType.bitwise_xor}
    while todo:
        current_expr = todo.pop()
        for subexpression in current_expr:
            if not isinstance(subexpression, Variable) and not isinstance(subexpression, Constant):
                todo.append(subexpression)
            if _is_cast(subexpression) and not (
                                isinstance(current_expr, BinaryOperation) and current_expr.operation in operations_to_not_remove_casts):
                yield current_expr, subexpression

def _is_cast(expression: Expression) -> bool:
    """
    :param expression: expression to be tested
    :return: true if expression is cast operation false otherwise
    """
    return isinstance(expression, UnaryOperation) and expression.operation == OperationType.cast


def _is_larger_int_type(type1: Type, type2: Type) -> bool:
    """
    Compare two types of the same sign
    :param type1: first type to compare
    :param type2: second type two compare
    :return: true, if they have same sign and first is larger than the second, false otherwise
    """
    if type1.size > type2.size and isinstance(type1, Integer) and isinstance(type2, Integer):
        if type1.is_signed == type2.is_signed:
            return True
