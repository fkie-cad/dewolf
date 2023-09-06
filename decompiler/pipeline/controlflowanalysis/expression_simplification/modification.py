from typing import Callable, Optional

from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Integer, OperationType


def multiply_int_with_constant(expression: Expression, constant: Constant) -> Expression:
    """
    Multiply an integer expression with an integer constant.

    :param expression: The integer expression to be multiplied.
    :param constant: The constant value to multiply the expression by.
    :return: A simplified expression representing the multiplication result.
    """

    if not isinstance(expression.type, Integer):
        raise ValueError(f"Expression must have integer type, got {expression.type}.")
    if not isinstance(constant.type, Integer):
        raise ValueError(f"Constant must have integer type, got {constant.type}.")
    if expression.type != constant.type:
        raise ValueError(f"Expression and constant type must equal. {expression.type} != {constant.type}")

    if isinstance(expression, Constant):
        return constant_fold(OperationType.multiply, [expression, constant])
    else:
        return BinaryOperation(OperationType.multiply, [expression, constant])


_FOLD_HANDLER: dict[OperationType, Callable[[list[Constant]], Constant]] = {
    OperationType.minus: lambda constants: _constant_fold_arithmetic_binary(constants, lambda x, y: x - y),
    OperationType.plus: lambda constants: _constant_fold_arithmetic_binary(constants, lambda x, y: x + y),
    OperationType.multiply: lambda constants: _constant_fold_arithmetic_binary(constants, lambda x, y: x * y, True),
    OperationType.multiply_us: lambda constants: _constant_fold_arithmetic_binary(constants, lambda x, y: x * y, False),
    OperationType.divide: lambda constants: _constant_fold_arithmetic_binary(constants, lambda x, y: x // y, True),
    OperationType.divide_us: lambda constants: _constant_fold_arithmetic_binary(constants, lambda x, y: x // y, False),
    OperationType.negate: lambda constants: _constant_fold_arithmetic_unary(constants, lambda value: -value),
    OperationType.left_shift: lambda constants: _constant_fold_shift(constants, lambda value, shift, size: value << shift),
    OperationType.right_shift: lambda constants: _constant_fold_shift(constants, lambda value, shift, size: value >> shift),
    OperationType.right_shift_us: lambda constants: _constant_fold_shift(
        constants, lambda value, shift, size: normalize_int(value >> shift, size - shift, False)
    ),
    OperationType.bitwise_or: lambda constants: _constant_fold_arithmetic_binary(constants, lambda x, y: x | y),
    OperationType.bitwise_and: lambda constants: _constant_fold_arithmetic_binary(constants, lambda x, y: x & y),
    OperationType.bitwise_xor: lambda constants: _constant_fold_arithmetic_binary(constants, lambda x, y: x ^ y),
    OperationType.bitwise_not: lambda constants: _constant_fold_arithmetic_unary(constants, lambda x: ~x),
}


FOLDABLE_OPERATIONS = _FOLD_HANDLER.keys()


def constant_fold(operation: OperationType, constants: list[Constant]) -> Constant:
    """
    Fold operation with constants as operands.

    :param operation: The operation.
    :param constants: All constant operands of the operation.
    :return: A constant representing the result of the operation.
    """

    if operation not in _FOLD_HANDLER:
        raise ValueError(f"Constant folding not implemented for operation '{operation}'.")

    return _FOLD_HANDLER[operation](constants)


def _constant_fold_arithmetic_binary(
        constants: list[Constant],
        fun: Callable[[int, int], int],
        norm_sign: Optional[bool] = None
) -> Constant:
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
    if len(constants) != 1:
        raise ValueError("Expected exactly 1 constant to fold")
    if not isinstance(constants[0].type, Integer):
        raise ValueError(f"Constant must be of type integer: {constants[0].type}")

    return Constant(normalize_int(fun(constants[0].value), constants[0].type.size, constants[0].type.signed), constants[0].type)


def _constant_fold_shift(constants: list[Constant], fun: Callable[[int, int, int], int]) -> Constant:
    if len(constants) != 2:
        raise ValueError("Expected exactly 2 constants to fold")
    if not all(isinstance(constant.type, Integer) for constant in constants):
        raise ValueError("All constants must be integers")

    left, right = constants

    return Constant(normalize_int(fun(left.value, right.value, left.type.size), left.type.size, left.type.signed), left.type)


def normalize_int(v: int, size: int, signed: bool) -> int:
    """
    Normalizes an integer value to a specific size and signedness.

    This function takes an integer value 'v' and normalizes it to fit within
    the specified 'size' in bits by discarding overflowing bits. If 'signed' is
    true, the value is treated as a signed integer.

    :param v: The value to be normalized.
    :param size: The desired bit size for the normalized integer.
    :param signed: True if the integer should be treated as signed.
    :return: The normalized integer value.
    """
    value = v & ((1 << size) - 1)
    if signed and value & (1 << (size - 1)):
        return value - (1 << size)
    else:
        return value
