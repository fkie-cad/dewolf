from contextlib import nullcontext

import pytest
from decompiler.pipeline.controlflowanalysis.expression_simplification.modification import FOLDABLE_OPERATIONS, constant_fold
from decompiler.structures.pseudo import Constant, Float, Integer, OperationType


def _c_i32(value: int) -> Constant:
    return Constant(value, Integer.int32_t())


def _c_u32(value: int) -> Constant:
    return Constant(value, Integer.uint32_t())


def _c_i16(value: int) -> Constant:
    return Constant(value, Integer.int16_t())


def _c_float(value: float) -> Constant:
    return Constant(value, Float.float())


@pytest.mark.parametrize(
    ["operation"],
    [(operation,) for operation in OperationType if operation not in FOLDABLE_OPERATIONS]
)
def test_constant_fold_invalid_operations(operation: OperationType):
    with pytest.raises(ValueError):
        constant_fold(operation, [])


@pytest.mark.parametrize(
    ["operation", "constants", "result", "context"],
    [
        (OperationType.plus, [_c_i32(3), _c_i32(4)], _c_i32(7), nullcontext()),
        (OperationType.plus, [_c_i32(2147483647), _c_i32(1)], _c_i32(-2147483648), nullcontext()),
        (OperationType.plus, [_c_u32(2147483658), _c_u32(2147483652)], _c_u32(14), nullcontext()),
        (OperationType.plus, [_c_u32(3), _c_i32(4)], None, pytest.raises(ValueError)),
        (OperationType.plus, [_c_i32(3), _c_i16(4)], None, pytest.raises(ValueError)),
        (OperationType.plus, [_c_i32(3)], None, pytest.raises(ValueError)),
        (OperationType.plus, [_c_i32(3), _c_i32(3), _c_i32(3)], None, pytest.raises(ValueError)),

        (OperationType.minus, [_c_i32(3), _c_i32(4)], _c_i32(-1), nullcontext()),
        (OperationType.minus, [_c_i32(-2147483648), _c_i32(1)], _c_i32(2147483647), nullcontext()),
        (OperationType.minus, [_c_u32(3), _c_u32(4)], _c_u32(4294967295), nullcontext()),
        (OperationType.minus, [_c_u32(3), _c_i32(4)], None, pytest.raises(ValueError)),
        (OperationType.minus, [_c_i32(3), _c_i16(4)], None, pytest.raises(ValueError)),
        (OperationType.minus, [_c_i32(3)], None, pytest.raises(ValueError)),
        (OperationType.minus, [_c_i32(3), _c_i32(3), _c_i32(3)], None, pytest.raises(ValueError)),

        (OperationType.multiply, [_c_i32(3), _c_i32(4)], _c_i32(12), nullcontext()),
        (OperationType.multiply, [_c_i32(-1073741824), _c_i32(2)], _c_i32(-2147483648), nullcontext()),
        (OperationType.multiply, [_c_u32(3221225472), _c_u32(2)], _c_u32(2147483648), nullcontext()),
        (OperationType.multiply, [_c_u32(3), _c_i32(4)], None, pytest.raises(ValueError)),
        (OperationType.multiply, [_c_i32(3), _c_i16(4)], None, pytest.raises(ValueError)),
        (OperationType.multiply, [_c_i32(3)], None, pytest.raises(ValueError)),
        (OperationType.multiply, [_c_i32(3), _c_i32(3), _c_i32(3)], None, pytest.raises(ValueError)),

        (OperationType.multiply_us, [_c_i32(3), _c_i32(4)], _c_i32(12), nullcontext()),
        (OperationType.multiply_us, [_c_i32(-1073741824), _c_i32(2)], _c_i32(-2147483648), nullcontext()),
        (OperationType.multiply_us, [_c_u32(3221225472), _c_u32(2)], _c_u32(2147483648), nullcontext()),
        (OperationType.multiply_us, [_c_u32(3), _c_i32(4)], None, pytest.raises(ValueError)),
        (OperationType.multiply_us, [_c_i32(3), _c_i16(4)], None, pytest.raises(ValueError)),
        (OperationType.multiply_us, [_c_i32(3)], None, pytest.raises(ValueError)),
        (OperationType.multiply_us, [_c_i32(3), _c_i32(3), _c_i32(3)], None, pytest.raises(ValueError)),

        (OperationType.divide, [_c_i32(12), _c_i32(4)], _c_i32(3), nullcontext()),
        (OperationType.divide, [_c_i32(-2147483648), _c_i32(2)], _c_i32(-1073741824), nullcontext()),
        (OperationType.divide, [_c_u32(3), _c_i32(4)], None, pytest.raises(ValueError)),
        (OperationType.divide, [_c_i32(3), _c_i16(4)], None, pytest.raises(ValueError)),
        (OperationType.divide, [_c_i32(3)], None, pytest.raises(ValueError)),
        (OperationType.divide, [_c_i32(3), _c_i32(3), _c_i32(3)], None, pytest.raises(ValueError)),

        (OperationType.divide_us, [_c_i32(12), _c_i32(4)], _c_i32(3), nullcontext()),
        (OperationType.divide_us, [_c_i32(-2147483648), _c_i32(2)], _c_i32(1073741824), nullcontext()),
        (OperationType.divide_us, [_c_u32(3), _c_i32(4)], None, pytest.raises(ValueError)),
        (OperationType.divide_us, [_c_i32(3), _c_i16(4)], None, pytest.raises(ValueError)),
        (OperationType.divide_us, [_c_i32(3)], None, pytest.raises(ValueError)),
        (OperationType.divide_us, [_c_i32(3), _c_i32(3), _c_i32(3)], None, pytest.raises(ValueError)),

        (OperationType.negate, [_c_i32(3)], _c_i32(-3), nullcontext()),
        (OperationType.negate, [_c_i32(-2147483648)], _c_i32(-2147483648), nullcontext()),
        (OperationType.negate, [], None, pytest.raises(ValueError)),
        (OperationType.negate, [_c_i32(3), _c_i32(3)], None, pytest.raises(ValueError)),

        (OperationType.left_shift, [_c_i32(3), _c_i32(4)], _c_i32(48), nullcontext()),
        (OperationType.left_shift, [_c_i32(1073741824), _c_i32(1)], _c_i32(-2147483648), nullcontext()),
        (OperationType.left_shift, [_c_u32(1073741824), _c_u32(1)], _c_u32(2147483648), nullcontext()),
        (OperationType.left_shift, [_c_i32(3)], None, pytest.raises(ValueError)),
        (OperationType.left_shift, [_c_i32(3), _c_i32(3), _c_i32(3)], None, pytest.raises(ValueError)),

        (OperationType.right_shift, [_c_i32(32), _c_i32(4)], _c_i32(2), nullcontext()),
        (OperationType.right_shift, [_c_i32(-2147483648), _c_i32(1)], _c_i32(-1073741824), nullcontext()),
        (OperationType.right_shift, [_c_u32(2147483648), _c_u32(1)], _c_u32(1073741824), nullcontext()),
        (OperationType.right_shift, [_c_i32(3)], None, pytest.raises(ValueError)),
        (OperationType.right_shift, [_c_i32(3), _c_i32(3), _c_i32(3)], None, pytest.raises(ValueError)),

        (OperationType.right_shift_us, [_c_i32(32), _c_i32(4)], _c_i32(2), nullcontext()),
        (OperationType.right_shift_us, [_c_i32(-2147483648), _c_i32(1)], _c_i32(1073741824), nullcontext()),
        (OperationType.right_shift_us, [_c_u32(2147483648), _c_u32(1)], _c_u32(1073741824), nullcontext()),
        (OperationType.right_shift_us, [_c_i32(3)], None, pytest.raises(ValueError)),
        (OperationType.right_shift_us, [_c_i32(3), _c_i32(3), _c_i32(3)], None, pytest.raises(ValueError)),

        (OperationType.bitwise_or, [_c_i32(85), _c_i32(34)], _c_i32(119), nullcontext()),
        (OperationType.bitwise_or, [_c_i32(-2147483648), _c_i32(1)], _c_i32(-2147483647), nullcontext()),
        (OperationType.bitwise_or, [_c_u32(2147483648), _c_u32(1)], _c_u32(2147483649), nullcontext()),
        (OperationType.bitwise_or, [_c_u32(3), _c_i32(4)], None, pytest.raises(ValueError)),
        (OperationType.bitwise_or, [_c_i32(3), _c_i16(4)], None, pytest.raises(ValueError)),
        (OperationType.bitwise_or, [_c_i32(3)], None, pytest.raises(ValueError)),
        (OperationType.bitwise_or, [_c_i32(3), _c_i32(3), _c_i32(3)], None, pytest.raises(ValueError)),

        (OperationType.bitwise_and, [_c_i32(85), _c_i32(51)], _c_i32(17), nullcontext()),
        (OperationType.bitwise_and, [_c_i32(-2147483647), _c_i32(3)], _c_i32(1), nullcontext()),
        (OperationType.bitwise_and, [_c_u32(2147483649), _c_u32(3)], _c_u32(1), nullcontext()),
        (OperationType.bitwise_and, [_c_u32(3), _c_i32(4)], None, pytest.raises(ValueError)),
        (OperationType.bitwise_and, [_c_i32(3), _c_i16(4)], None, pytest.raises(ValueError)),
        (OperationType.bitwise_and, [_c_i32(3)], None, pytest.raises(ValueError)),
        (OperationType.bitwise_and, [_c_i32(3), _c_i32(3), _c_i32(3)], None, pytest.raises(ValueError)),

        (OperationType.bitwise_xor, [_c_i32(85), _c_i32(51)], _c_i32(102), nullcontext()),
        (OperationType.bitwise_xor, [_c_i32(-2147483647), _c_i32(-2147483646)], _c_i32(3), nullcontext()),
        (OperationType.bitwise_xor, [_c_u32(2147483649), _c_u32(2147483650)], _c_u32(3), nullcontext()),
        (OperationType.bitwise_xor, [_c_u32(3), _c_i32(4)], None, pytest.raises(ValueError)),
        (OperationType.bitwise_xor, [_c_i32(3), _c_i16(4)], None, pytest.raises(ValueError)),
        (OperationType.bitwise_xor, [_c_i32(3)], None, pytest.raises(ValueError)),
        (OperationType.bitwise_xor, [_c_i32(3), _c_i32(3), _c_i32(3)], None, pytest.raises(ValueError)),

        (OperationType.bitwise_not, [_c_i32(6)], _c_i32(-7), nullcontext()),
        (OperationType.bitwise_not, [_c_i32(-2147483648)], _c_i32(2147483647), nullcontext()),
        (OperationType.bitwise_not, [_c_u32(2147483648)], _c_u32(2147483647), nullcontext()),
        (OperationType.bitwise_not, [], None, pytest.raises(ValueError)),
        (OperationType.bitwise_not, [_c_i32(3), _c_i32(3)], None, pytest.raises(ValueError)),
    ]
)
def test_constant_fold(operation: OperationType, constants: list[Constant], result: Constant, context):
    with context:
        assert constant_fold(operation, constants) == result
