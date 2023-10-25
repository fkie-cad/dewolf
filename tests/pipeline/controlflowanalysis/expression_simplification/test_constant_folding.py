from contextlib import nullcontext
from typing import Optional

import pytest
from decompiler.pipeline.controlflowanalysis.expression_simplification.constant_folding import (
    FOLDABLE_OPERATIONS,
    IncompatibleOperandCount,
    UnsupportedMismatchedSizes,
    UnsupportedOperationType,
    UnsupportedValueType,
    constant_fold,
)
from decompiler.structures.pseudo import Constant, Float, Integer, OperationType, Type


def _c_i32(value: int) -> Constant:
    return Constant(value, Integer.int32_t())


def _c_u32(value: int) -> Constant:
    return Constant(value, Integer.uint32_t())


def _c_i16(value: int) -> Constant:
    return Constant(value, Integer.int16_t())


def _c_float(value: float) -> Constant:
    return Constant(value, Float.float())


@pytest.mark.parametrize(["operation"], [(operation,) for operation in OperationType if operation not in FOLDABLE_OPERATIONS])
def test_constant_fold_invalid_operations(operation: OperationType):
    with pytest.raises(UnsupportedOperationType):
        constant_fold(operation, [], Integer.int32_t())


@pytest.mark.parametrize(
    ["operation", "constants", "result_type", "expected_result", "context"],
    [
        (OperationType.plus, [_c_i32(0), _c_i32(0)], Integer.int32_t(), _c_i32(0), nullcontext()),
        (OperationType.plus, [_c_float(0.0), _c_float(0.0)], Float.float(), _c_float(0.0), pytest.raises(UnsupportedValueType)),
        (OperationType.plus, [_c_i32(0), _c_float(0.0)], Integer.int32_t(), _c_i32(0), pytest.raises(UnsupportedValueType)),
    ]
)
def test_constant_fold_invalid_operations(operation: OperationType):
    with pytest.raises(UnsupportedOperationType):
        constant_fold(operation, [], Integer.int32_t())


@pytest.mark.parametrize(
    ["operation", "constants", "result_type", "expected_result", "context"],
    [
        (OperationType.plus, [_c_i32(0), _c_i32(0)], Integer.int32_t(), _c_i32(0), nullcontext()),
        (OperationType.plus, [_c_float(0.0), _c_float(0.0)], Float.float(), _c_float(0.0), pytest.raises(UnsupportedValueType)),
        (OperationType.plus, [_c_i32(0), _c_float(0.0)], Integer.int32_t(), _c_i32(0), pytest.raises(UnsupportedValueType)),
    ]
)
def test_constant_fold_invalid_value_type(
        operation: OperationType,
        constants: list[Constant],
        result_type: Type,
        expected_result: Optional[Constant],
        context
):
    with context:
        assert constant_fold(operation, constants, result_type) == expected_result


@pytest.mark.parametrize(
    ["operation", "constants", "result_type", "expected_result", "context"],
    [
        (OperationType.plus, [_c_i32(3), _c_i32(4)], Integer.int32_t(), _c_i32(7), nullcontext()),
        (OperationType.plus, [_c_i32(2147483647), _c_i32(1)], Integer.int32_t(), _c_i32(-2147483648), nullcontext()),
        (OperationType.plus, [_c_u32(2147483658), _c_u32(2147483652)], Integer.uint32_t(), _c_u32(14), nullcontext()),
        (OperationType.plus, [_c_u32(3), _c_i32(4)], Integer.int32_t(), _c_i32(7), nullcontext()),
        (OperationType.plus, [_c_i32(3), _c_i16(4)], Integer.int32_t(), None, pytest.raises(UnsupportedMismatchedSizes)),
        (OperationType.plus, [_c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.plus, [_c_i32(3), _c_i32(3), _c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.minus, [_c_i32(3), _c_i32(4)], Integer.int32_t(), _c_i32(-1), nullcontext()),
        (OperationType.minus, [_c_i32(-2147483648), _c_i32(1)], Integer.int32_t(), _c_i32(2147483647), nullcontext()),
        (OperationType.minus, [_c_u32(3), _c_u32(4)], Integer.uint32_t(), _c_u32(4294967295), nullcontext()),
        (OperationType.minus, [_c_u32(3), _c_i32(4)], Integer.int32_t(), _c_i32(-1), nullcontext()),
        (OperationType.minus, [_c_i32(3), _c_i16(4)], Integer.int32_t(), None, pytest.raises(UnsupportedMismatchedSizes)),
        (OperationType.minus, [_c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.minus, [_c_i32(3), _c_i32(3), _c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.multiply, [_c_i32(3), _c_i32(4)], Integer.int32_t(), _c_i32(12), nullcontext()),
        (OperationType.multiply, [_c_i32(-1073741824), _c_i32(2)], Integer.int32_t(), _c_i32(-2147483648), nullcontext()),
        (OperationType.multiply, [_c_u32(3221225472), _c_u32(2)], Integer.uint32_t(), _c_u32(2147483648), nullcontext()),
        (OperationType.multiply, [_c_u32(3), _c_i32(4)], Integer.int32_t(), _c_i32(12), nullcontext()),
        (OperationType.multiply, [_c_i32(3), _c_i16(4)], Integer.int32_t(), None, pytest.raises(UnsupportedMismatchedSizes)),
        (OperationType.multiply, [_c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.multiply, [_c_i32(3), _c_i32(3), _c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.multiply_us, [_c_i32(3), _c_i32(4)], Integer.int32_t(), _c_i32(12), nullcontext()),
        (OperationType.multiply_us, [_c_i32(-1073741824), _c_i32(2)], Integer.int32_t(), _c_i32(-2147483648), nullcontext()),
        (OperationType.multiply_us, [_c_u32(3221225472), _c_u32(2)], Integer.uint32_t(), _c_u32(2147483648), nullcontext()),
        (OperationType.multiply_us, [_c_u32(3), _c_i32(4)], Integer.int32_t(), _c_i32(12), nullcontext()),
        (OperationType.multiply_us, [_c_i32(3), _c_i16(4)], Integer.int32_t(), None, pytest.raises(UnsupportedMismatchedSizes)),
        (OperationType.multiply_us, [_c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.multiply_us, [_c_i32(3), _c_i32(3), _c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.divide, [_c_i32(12), _c_i32(4)], Integer.int32_t(), _c_i32(3), nullcontext()),
        (OperationType.divide, [_c_i32(-2147483648), _c_i32(2)], Integer.int32_t(), _c_i32(-1073741824), nullcontext()),
        (OperationType.divide, [_c_u32(3), _c_i32(4)], Integer.int32_t(), _c_i32(0), nullcontext()),
        (OperationType.divide, [_c_i32(3), _c_i16(4)], Integer.int32_t(), None, pytest.raises(UnsupportedMismatchedSizes)),
        (OperationType.divide, [_c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.divide, [_c_i32(3), _c_i32(3), _c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.divide_us, [_c_i32(12), _c_i32(4)], Integer.int32_t(), _c_i32(3), nullcontext()),
        (OperationType.divide_us, [_c_i32(-2147483648), _c_i32(2)], Integer.int32_t(), _c_i32(1073741824), nullcontext()),
        (OperationType.divide_us, [_c_u32(3), _c_i32(4)], Integer.int32_t(), _c_i32(0), nullcontext()),
        (OperationType.divide_us, [_c_i32(3), _c_i16(4)], Integer.int32_t(), None, pytest.raises(UnsupportedMismatchedSizes)),
        (OperationType.divide_us, [_c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.divide_us, [_c_i32(3), _c_i32(3), _c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.negate, [_c_i32(3)], Integer.int32_t(), _c_i32(-3), nullcontext()),
        (OperationType.negate, [_c_i32(-2147483648)], Integer.int32_t(), _c_i32(-2147483648), nullcontext()),
        (OperationType.negate, [], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.negate, [_c_i32(3), _c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.left_shift, [_c_i32(3), _c_i32(4)], Integer.int32_t(), _c_i32(48), nullcontext()),
        (OperationType.left_shift, [_c_i32(1073741824), _c_i32(1)], Integer.int32_t(), _c_i32(-2147483648), nullcontext()),
        (OperationType.left_shift, [_c_u32(1073741824), _c_u32(1)], Integer.uint32_t(), _c_u32(2147483648), nullcontext()),
        (OperationType.left_shift, [_c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.left_shift, [_c_i32(3), _c_i32(3), _c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.right_shift, [_c_i32(32), _c_i32(4)], Integer.int32_t(), _c_i32(2), nullcontext()),
        (OperationType.right_shift, [_c_i32(-2147483648), _c_i32(1)], Integer.int32_t(), _c_i32(-1073741824), nullcontext()),
        (OperationType.right_shift, [_c_u32(2147483648), _c_u32(1)], Integer.uint32_t(), _c_u32(1073741824), nullcontext()),
        (OperationType.right_shift, [_c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.right_shift, [_c_i32(3), _c_i32(3), _c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.right_shift_us, [_c_i32(32), _c_i32(4)], Integer.int32_t(), _c_i32(2), nullcontext()),
        (OperationType.right_shift_us, [_c_i32(-2147483648), _c_i32(1)], Integer.int32_t(), _c_i32(1073741824), nullcontext()),
        (OperationType.right_shift_us, [_c_u32(2147483648), _c_u32(1)], Integer.uint32_t(), _c_u32(1073741824), nullcontext()),
        (OperationType.right_shift_us, [_c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.right_shift_us, [_c_i32(3), _c_i32(3), _c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.bitwise_or, [_c_i32(85), _c_i32(34)], Integer.int32_t(), _c_i32(119), nullcontext()),
        (OperationType.bitwise_or, [_c_i32(-2147483648), _c_i32(1)], Integer.int32_t(), _c_i32(-2147483647), nullcontext()),
        (OperationType.bitwise_or, [_c_u32(2147483648), _c_u32(1)], Integer.uint32_t(), _c_u32(2147483649), nullcontext()),
        (OperationType.bitwise_or, [_c_u32(3), _c_i32(4)], Integer.int32_t(), _c_i32(7), nullcontext()),
        (OperationType.bitwise_or, [_c_i32(3), _c_i16(4)], Integer.int32_t(), None, pytest.raises(UnsupportedMismatchedSizes)),
        (OperationType.bitwise_or, [_c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.bitwise_or, [_c_i32(3), _c_i32(3), _c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.bitwise_and, [_c_i32(85), _c_i32(51)], Integer.int32_t(), _c_i32(17), nullcontext()),
        (OperationType.bitwise_and, [_c_i32(-2147483647), _c_i32(3)], Integer.int32_t(), _c_i32(1), nullcontext()),
        (OperationType.bitwise_and, [_c_u32(2147483649), _c_u32(3)], Integer.uint32_t(), _c_u32(1), nullcontext()),
        (OperationType.bitwise_and, [_c_u32(3), _c_i32(4)], Integer.int32_t(), _c_i32(0), nullcontext()),
        (OperationType.bitwise_and, [_c_i32(3), _c_i16(4)], Integer.int32_t(), None, pytest.raises(UnsupportedMismatchedSizes)),
        (OperationType.bitwise_and, [_c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.bitwise_and, [_c_i32(3), _c_i32(3), _c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.bitwise_xor, [_c_i32(85), _c_i32(51)], Integer.int32_t(), _c_i32(102), nullcontext()),
        (OperationType.bitwise_xor, [_c_i32(-2147483647), _c_i32(-2147483646)], Integer.int32_t(), _c_i32(3), nullcontext()),
        (OperationType.bitwise_xor, [_c_u32(2147483649), _c_u32(2147483650)], Integer.uint32_t(), _c_u32(3), nullcontext()),
        (OperationType.bitwise_xor, [_c_u32(3), _c_i32(4)], Integer.int32_t(), _c_i32(7), nullcontext()),
        (OperationType.bitwise_xor, [_c_i32(3), _c_i16(4)], Integer.int32_t(), None, pytest.raises(UnsupportedMismatchedSizes)),
        (OperationType.bitwise_xor, [_c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.bitwise_xor, [_c_i32(3), _c_i32(3), _c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.bitwise_not, [_c_i32(6)], Integer.int32_t(), _c_i32(-7), nullcontext()),
        (OperationType.bitwise_not, [_c_i32(-2147483648)], Integer.int32_t(), _c_i32(2147483647), nullcontext()),
        (OperationType.bitwise_not, [_c_u32(2147483648)], Integer.uint32_t(), _c_u32(2147483647), nullcontext()),
        (OperationType.bitwise_not, [], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
        (OperationType.bitwise_not, [_c_i32(3), _c_i32(3)], Integer.int32_t(), None, pytest.raises(IncompatibleOperandCount)),
    ],
)
def test_constant_fold(
        operation: OperationType,
        constants: list[Constant],
        result_type: Type,
        expected_result: Optional[Constant],
        context
):
    with context:
        assert constant_fold(operation, constants, result_type) == expected_result
