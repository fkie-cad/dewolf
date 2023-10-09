import operator
from functools import partial
from typing import Callable, Optional

from decompiler.structures.pseudo import Constant, Integer, OperationType
from decompiler.util.integer_util import normalize_int


def constant_fold(operation: OperationType, constants: list[Constant]) -> Constant:
    """
    Fold operation with constants as operands.

    :param operation: The operation.
    :param constants: All constant operands of the operation.
    :return: A constant representing the result of the operation.
    """

    if operation not in _OPERATION_TO_FOLD_FUNCTION:
        raise ValueError(f"Constant folding not implemented for operation '{operation}'.")

    return _OPERATION_TO_FOLD_FUNCTION[operation](constants)


def _constant_fold_arithmetic_binary(
        constants: list[Constant],
        fun: Callable[[int, int], int],
        norm_sign: Optional[bool] = None
) -> Constant:
    """
    Fold an arithmetic binary operation with constants as operands.

    :param constants: A list of exactly 2 constant operands.
    :param fun: The binary function to perform on the constants.
    :param norm_sign: Optional boolean flag to indicate if/how to normalize the input constants to 'fun':
        - None (default): no normalization
        - True:  normalize inputs, interpreted as signed values
        - False: normalize inputs, interpreted as unsigned values
    :return: A constant representing the result of the operation.
    """

    if len(constants) != 2:
        raise ValueError(f"Expected exactly 2 constants to fold, got {len(constants)}.")
    if not all(constant.type == constants[0].type for constant in constants):
        raise ValueError(f"Can not fold constants with different types: {(constant.type for constant in constants)}")
    if not all(isinstance(constant.type, Integer) for constant in constants):
        raise ValueError(f"All constants must be integers, got {list(constant.type for constant in constants)}.")

    left, right = constants

    left_value = left.value
    right_value = right.value
    if norm_sign is not None:
        left_value = normalize_int(left_value, left.type.size, norm_sign)
        right_value = normalize_int(right_value, right.type.size, norm_sign)

    return Constant(
        normalize_int(fun(left_value, right_value), left.type.size, left.type.signed),
        left.type
    )


def _constant_fold_arithmetic_unary(constants: list[Constant], fun: Callable[[int], int]) -> Constant:
    """
    Fold an arithmetic unary operation with a constant operand.

    :param constants: A list containing a single constant operand.
    :param fun: The unary function to perform on the constant.
    :return: A constant representing the result of the operation.
    """

    if len(constants) != 1:
        raise ValueError("Expected exactly 1 constant to fold")
    if not isinstance(constants[0].type, Integer):
        raise ValueError(f"Constant must be of type integer: {constants[0].type}")

    return Constant(normalize_int(fun(constants[0].value), constants[0].type.size, constants[0].type.signed), constants[0].type)


def _constant_fold_shift(constants: list[Constant], fun: Callable[[int, int], int], signed: bool) -> Constant:
    """
    Fold a shift operation with constants as operands.

    :param constants: A list of exactly 2 constant operands.
    :param fun: The shift function to perform on the constants.
    :param signed: Boolean flag indicating whether the shift is signed.
    This is used to normalize the sign of the input constant to simulate unsigned shifts.
    :return: A constant representing the result of the operation.
    """

    if len(constants) != 2:
        raise ValueError("Expected exactly 2 constants to fold")
    if not all(isinstance(constant.type, Integer) for constant in constants):
        raise ValueError("All constants must be integers")

    left, right = constants

    shifted_value = fun(
        normalize_int(left.value, left.type.size, left.type.signed and signed),
        right.value
    )
    return Constant(
        normalize_int(shifted_value, left.type.size, left.type.signed),
        left.type
    )


_OPERATION_TO_FOLD_FUNCTION: dict[OperationType, Callable[[list[Constant]], Constant]] = {
    OperationType.minus: partial(_constant_fold_arithmetic_binary, fun=operator.sub),
    OperationType.plus: partial(_constant_fold_arithmetic_binary, fun=operator.add),
    OperationType.multiply: partial(_constant_fold_arithmetic_binary, fun=operator.mul, norm_sign=True),
    OperationType.multiply_us: partial(_constant_fold_arithmetic_binary, fun=operator.mul, norm_sign=False),
    OperationType.divide: partial(_constant_fold_arithmetic_binary, fun=operator.floordiv, norm_sign=True),
    OperationType.divide_us: partial(_constant_fold_arithmetic_binary, fun=operator.floordiv, norm_sign=False),
    OperationType.negate: partial(_constant_fold_arithmetic_unary, fun=operator.neg),
    OperationType.left_shift: partial(_constant_fold_shift, fun=operator.lshift, signed=True),
    OperationType.right_shift: partial(_constant_fold_shift, fun=operator.rshift, signed=True),
    OperationType.right_shift_us: partial(_constant_fold_shift, fun=operator.rshift, signed=False),
    OperationType.bitwise_or: partial(_constant_fold_arithmetic_binary, fun=operator.or_),
    OperationType.bitwise_and: partial(_constant_fold_arithmetic_binary, fun=operator.and_),
    OperationType.bitwise_xor: partial(_constant_fold_arithmetic_binary, fun=operator.xor),
    OperationType.bitwise_not: partial(_constant_fold_arithmetic_unary, fun=operator.inv),
}


FOLDABLE_OPERATIONS = _OPERATION_TO_FOLD_FUNCTION.keys()
