import operator
from functools import partial
from typing import Callable, Optional

from decompiler.structures.pseudo import Constant, Integer, OperationType, Type
from decompiler.util.integer_util import normalize_int

# Exceptions of these three types indicate that an operation is not suitable for constant folding.
# They do NOT indicate that the input was malformed in any way.
# The idea is that the caller of constant_fold does not need to verify that folding is possible.
# If malformed input was provided, a ValueError will used raised instead.


class UnsupportedOperationType(Exception):
    """Indicates that the specified Operation is not supported"""
    pass


class UnsupportedValueType(Exception):
    """Indicates that the value type of one constant is not supported."""
    pass


class UnsupportedMismatchedSizes(Exception):
    """Indicates that folding of different sized constants is not supported for the specified operation."""
    pass


class MalformedInput(Exception):
    """Indicates that the input is malformed in some way."""
    pass


def constant_fold(operation: OperationType, constants: list[Constant], result_type: Type) -> Constant:
    """
    Fold operation with constants as operands.

    :param operation: The operation.
    :param constants: All constant operands of the operation.
        Count of operands must be compatible with the specified operation type.
    :param result_type: What type the folded constant should have.
    :return: A constant representing the result of the operation.
    :raises:
        UnsupportedOperationType: Thrown if the specified operation is not supported.
        UnsupportedValueType: Thrown if constants contain value of types not supported. Currently only ints are supported.
        UnsupportedMismatchedSizes: Thrown if constants types have different sizes and folding of different sized
            constants is not supported for the specified operation.
        MalformedInput: Thrown on malformed input.
    """

    if operation not in _OPERATION_TO_FOLD_FUNCTION:
        raise UnsupportedOperationType(f"Constant folding not implemented for operation '{operation}'.")

    if not all(isinstance(v, int) for v in [c.value for c in constants]):  # For now we only support integer value folding
        raise UnsupportedValueType(f"Constant folding is not implemented for non int constant values: {[c.value for c in constants]}")

    return Constant(
        normalize_int(
            _OPERATION_TO_FOLD_FUNCTION[operation](constants),
            result_type.size,
            isinstance(result_type, Integer) and result_type.signed
        ),
        result_type
    )


def _constant_fold_arithmetic_binary(
        constants: list[Constant],
        fun: Callable[[int, int], int],
        norm_sign: Optional[bool] = None
) -> int:
    """
    Fold an arithmetic binary operation with constants as operands.

    :param constants: A list of exactly 2 constant values.
    :param fun: The binary function to perform on the constants.
    :param norm_sign: Optional boolean flag to indicate if/how to normalize the input constants to 'fun':
        - None (default): no normalization
        - True: normalize inputs, interpreted as signed values
        - False: normalize inputs, interpreted as unsigned values
    :return: The result of the operation.
    :raises:
        UnsupportedMismatchedSizes: Thrown if constants types have different sizes and folding of different sized
            constants is not supported for the specified operation.
        MalformedInput: Thrown on malformed input.
    """

    if len(constants) != 2:
        raise MalformedInput(f"Expected exactly 2 constants to fold, got {len(constants)}.")
    if not all(constant.type.size == constants[0].type.size for constant in constants):
        raise UnsupportedMismatchedSizes(f"Can not fold constants with different sizes: {[constant.type for constant in constants]}")

    left, right = constants

    left_value = left.value
    right_value = right.value
    if norm_sign is not None:
        left_value = normalize_int(left_value, left.type.size, norm_sign)
        right_value = normalize_int(right_value, right.type.size, norm_sign)

    return fun(left_value, right_value)


def _constant_fold_arithmetic_unary(constants: list[Constant], fun: Callable[[int], int]) -> int:
    """
    Fold an arithmetic unary operation with a constant operand.

    :param constants: A list containing a single constant operand.
    :param fun: The unary function to perform on the constant.
    :return: The result of the operation.
    :raises:
        MalformedInput: Thrown on malformed input.
    """

    if len(constants) != 1:
        raise MalformedInput("Expected exactly 1 constant to fold")

    return fun(constants[0].value)


def _constant_fold_shift(constants: list[Constant], fun: Callable[[int, int], int], signed: bool) -> int:
    """
    Fold a shift operation with constants as operands.

    :param constants: A list of exactly 2 constant operands.
    :param fun: The shift function to perform on the constants.
    :param signed: Boolean flag indicating whether the shift is signed.
    This is used to normalize the sign of the input constant to simulate unsigned shifts.
    :return: The result of the operation.
    :raises:
        MalformedInput: Thrown on malformed input.
    """

    if len(constants) != 2:
        raise MalformedInput("Expected exactly 2 constants to fold")

    left, right = constants

    return fun(
        normalize_int(left.value, left.type.size, left.type.signed and signed),
        right.value
    )


_OPERATION_TO_FOLD_FUNCTION: dict[OperationType, Callable[[list[Constant]], int]] = {
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
