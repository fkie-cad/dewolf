import pytest
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.collapse_nested_constants import CollapseNestedConstants
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Integer, Operation, OperationType, Variable
from decompiler.structures.visitors.substitute_visitor import SubstituteVisitor


def _var_i32(name: str) -> Variable:
    return Variable(name, Integer.int32_t())


def _c_i32(value: int) -> Constant:
    return Constant(value, Integer.int32_t())


def _plus(e0: Expression, e1: Expression) -> BinaryOperation:
    return BinaryOperation(OperationType.plus, [e0, e1])


def _mul(e: Expression, factor: Expression) -> BinaryOperation:
    return BinaryOperation(OperationType.multiply, [e, factor])


def _mul_us(e: Expression, factor: Expression) -> BinaryOperation:
    return BinaryOperation(OperationType.multiply_us, [e, factor])


def _bit_and(e0: Expression, e1: Expression) -> BinaryOperation:
    return BinaryOperation(OperationType.bitwise_and, [e0, e1])


def _bit_xor(e0: Expression, e1: Expression) -> BinaryOperation:
    return BinaryOperation(OperationType.bitwise_xor, [e0, e1])


def _bit_or(e0: Expression, e1: Expression) -> BinaryOperation:
    return BinaryOperation(OperationType.bitwise_or, [e0, e1])


@pytest.mark.parametrize(
    ["operation", "possible_results"],
    [
        (  # plus
            _plus(_plus(_c_i32(7), _c_i32(11)), _c_i32(42)),
            {
                _plus(_plus(_c_i32(0), _c_i32(0)), _c_i32(60)),
                _plus(_plus(_c_i32(0), _c_i32(60)), _c_i32(0)),
                _plus(_plus(_c_i32(60), _c_i32(0)), _c_i32(0)),
            },
        ),
        (
            _plus(_plus(_var_i32("a"), _c_i32(2)), _plus(_var_i32("b"), _c_i32(3))),
            {
                _plus(_plus(_var_i32("a"), _c_i32(5)), _plus(_var_i32("b"), _c_i32(0))),
                _plus(_plus(_var_i32("a"), _c_i32(0)), _plus(_var_i32("b"), _c_i32(5))),
            },
        ),
        (  # multiply
            _mul(_mul(_c_i32(7), _c_i32(11)), _c_i32(2)),
            {
                _mul(_mul(_c_i32(1), _c_i32(1)), _c_i32(154)),
                _mul(_mul(_c_i32(1), _c_i32(154)), _c_i32(1)),
                _mul(_mul(_c_i32(154), _c_i32(1)), _c_i32(1)),
            },
        ),
        (
            _mul(_mul(_var_i32("a"), _c_i32(2)), _mul(_var_i32("b"), _c_i32(3))),
            {
                _mul(_mul(_var_i32("a"), _c_i32(6)), _mul(_var_i32("b"), _c_i32(1))),
                _mul(_mul(_var_i32("a"), _c_i32(1)), _mul(_var_i32("b"), _c_i32(6))),
            },
        ),
        (  # multiply_us
            _mul_us(_mul_us(_c_i32(7), _c_i32(11)), _c_i32(2)),
            {
                _mul_us(_mul_us(_c_i32(1), _c_i32(1)), _c_i32(154)),
                _mul_us(_mul_us(_c_i32(1), _c_i32(154)), _c_i32(1)),
                _mul_us(_mul_us(_c_i32(154), _c_i32(1)), _c_i32(1)),
            },
        ),
        (
            _mul_us(_mul_us(_var_i32("a"), _c_i32(2)), _mul_us(_var_i32("b"), _c_i32(3))),
            {
                _mul_us(_mul_us(_var_i32("a"), _c_i32(6)), _mul_us(_var_i32("b"), _c_i32(1))),
                _mul_us(_mul_us(_var_i32("a"), _c_i32(1)), _mul_us(_var_i32("b"), _c_i32(6))),
            },
        ),
        (  # bitwise_and
            _bit_and(_bit_and(_c_i32(7), _c_i32(11)), _c_i32(2)),
            {
                _bit_and(_bit_and(_c_i32(-1), _c_i32(-1)), _c_i32(2)),
                _bit_and(_bit_and(_c_i32(-1), _c_i32(2)), _c_i32(-1)),
                _bit_and(_bit_and(_c_i32(2), _c_i32(-1)), _c_i32(-1)),
            },
        ),
        (
            _bit_and(_bit_and(_var_i32("a"), _c_i32(2)), _bit_and(_var_i32("b"), _c_i32(3))),
            {
                _bit_and(_bit_and(_var_i32("a"), _c_i32(2)), _bit_and(_var_i32("b"), _c_i32(-1))),
                _bit_and(_bit_and(_var_i32("a"), _c_i32(-1)), _bit_and(_var_i32("b"), _c_i32(2))),
            },
        ),
        (  # bitwise_xor
            _bit_xor(_bit_xor(_c_i32(7), _c_i32(11)), _c_i32(2)),
            {
                _bit_xor(_bit_xor(_c_i32(0), _c_i32(0)), _c_i32(14)),
                _bit_xor(_bit_xor(_c_i32(0), _c_i32(14)), _c_i32(0)),
                _bit_xor(_bit_xor(_c_i32(14), _c_i32(0)), _c_i32(0)),
            },
        ),
        (
            _bit_xor(_bit_xor(_var_i32("a"), _c_i32(2)), _bit_xor(_var_i32("b"), _c_i32(3))),
            {
                _bit_xor(_bit_xor(_var_i32("a"), _c_i32(1)), _bit_xor(_var_i32("b"), _c_i32(0))),
                _bit_xor(_bit_xor(_var_i32("a"), _c_i32(0)), _bit_xor(_var_i32("b"), _c_i32(1))),
            },
        ),
        (  # bitwise_or
            _bit_or(_bit_or(_c_i32(7), _c_i32(11)), _c_i32(2)),
            {
                _bit_or(_bit_or(_c_i32(0), _c_i32(0)), _c_i32(15)),
                _bit_or(_bit_or(_c_i32(0), _c_i32(15)), _c_i32(0)),
                _bit_or(_bit_or(_c_i32(15), _c_i32(0)), _c_i32(0)),
            },
        ),
        (
            _bit_or(_bit_or(_var_i32("a"), _c_i32(2)), _bit_or(_var_i32("b"), _c_i32(3))),
            {
                _bit_or(_bit_or(_var_i32("a"), _c_i32(3)), _bit_or(_var_i32("b"), _c_i32(0))),
                _bit_or(_bit_or(_var_i32("a"), _c_i32(0)), _bit_or(_var_i32("b"), _c_i32(3))),
            },
        ),
    ],
)
def test_collect_terms(operation: Operation, possible_results: set[Expression]):
    collect_terms = CollapseNestedConstants()

    for i in range(100):
        substitutions = collect_terms.apply(operation)
        if not substitutions:
            break

        for replacee, replacement in substitutions:
            new_operation = operation.accept(SubstituteVisitor.identity(replacee, replacement))
            if new_operation is not None:
                operation = new_operation
    else:
        raise RuntimeError("Max iterations exceeded")

    assert operation in possible_results
