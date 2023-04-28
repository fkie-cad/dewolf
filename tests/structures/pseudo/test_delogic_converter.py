import pytest
from decompiler.structures.pseudo.delogic_logic import DelogicConverter
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Branch, Return
from decompiler.structures.pseudo.logic import BaseConverter
from decompiler.structures.pseudo.operations import BinaryOperation, Condition, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import Float, Integer, Pointer
from simplifier.world.nodes import Variable as WorldVariable

var_a = Variable("a", Integer.int32_t())
var_b = Variable("b", Integer.int32_t())
var_x = Variable("x", Integer.int32_t())
var_y = Variable("y", Integer.int32_t())
const_1 = Constant(1, Integer.int32_t())


@pytest.fixture
def converter():
    return DelogicConverter()


def test_unsupported(converter):
    with pytest.raises(ValueError):
        converter.convert(Return([Variable("x")]))
    with pytest.raises(ValueError):
        converter.convert(UnaryOperation(OperationType.address, [Variable("x")]))


def test_constant(converter):
    w = converter._world
    assert converter.convert(Constant(6, Integer.int32_t())) == w.constant(6, 32)
    assert converter.convert(Constant(7.2, Float.float())) == w.constant(7.2, 32)
    with pytest.raises(ValueError):
        converter.convert(Constant("hello", Pointer(Integer.uint8_t())))


@pytest.mark.parametrize(
    "to_parse, output",
    [
        (Variable("x", Integer.int32_t(), ssa_label=0), "x#0"),
        (Variable("x", Integer.int32_t(), ssa_label=1), "x#1"),
        (Variable("x", Integer.int32_t(), ssa_label=None), "x"),
        (Variable("x", Float.float(), ssa_label=1), "x#1"),
    ],
)
def test_variable(converter, to_parse, output):
    """When generating a variable, we can not transpose ssa labels or type information."""
    w = converter._world
    assert converter.convert(to_parse) == WorldVariable(w, output, 32)


@pytest.mark.parametrize(
    "to_parse, output",
    [
        (UnaryOperation(OperationType.negate, [var_x.copy()]), "(~ x@32)"),
        (UnaryOperation(OperationType.cast, [var_x.copy()]), "x@32"),
        (UnaryOperation(OperationType.logical_not, [Variable("x", Integer(1))]), "(! x@1)"),
    ],
)
def test_unary_operation(converter, to_parse, output):
    w = converter._world
    assert converter.convert(to_parse) == w.from_string(output)


@pytest.mark.parametrize(
    "to_parse, output",
    [
        (UnaryOperation(OperationType.dereference, [Variable("x", Integer.int32_t(), ssa_label=1)]), "*(x#1)"),
        (UnaryOperation(OperationType.dereference, [Variable("x", Integer.int32_t(), ssa_label=None)]), "*(x)"),
    ],
)
def test_unary_dereference(converter, to_parse, output):
    w = converter._world
    assert converter.convert(to_parse) == WorldVariable(w, output, 32)


@pytest.mark.parametrize(
    "to_parse, output",
    [
        ("(!= 0@32 0@32)", BaseConverter.UNSAT),
        ("(== 0@32 0@32)", BaseConverter.SAT),
    ],
)
def test_check(converter, to_parse, output):
    """Test the check() function."""
    w = converter._world
    condition = w.from_string(to_parse)
    assert converter.check(condition) == output


def test_binary_operation(converter):
    w = converter._world
    a = w.variable("a", 32)
    b = w.variable("b", 32)
    assert converter.convert(BinaryOperation(OperationType.plus, [var_a.copy(), var_b.copy()])) == w.signed_add(a, b)
    assert converter.convert(BinaryOperation(OperationType.minus, [var_a.copy(), var_b.copy()])) == w.signed_sub(a, b)
    assert converter.convert(BinaryOperation(OperationType.multiply, [var_a.copy(), var_b.copy()])) == w.signed_mul(a, b)
    assert converter.convert(BinaryOperation(OperationType.bitwise_xor, [var_a.copy(), var_b.copy()])) == w.bitwise_xor(a, b)
    assert converter.convert(BinaryOperation(OperationType.bitwise_or, [var_a.copy(), var_b.copy()])) == w.bitwise_or(a, b)
    assert converter.convert(BinaryOperation(OperationType.bitwise_and, [var_a.copy(), var_b.copy()])) == w.bitwise_and(a, b)
    assert converter.convert(BinaryOperation(OperationType.divide, [var_a.copy(), var_b.copy()])) == w.signed_div(a, b)
    assert converter.convert(BinaryOperation(OperationType.modulo, [var_a.copy(), var_b.copy()])) == w.signed_mod(a, b)
    assert converter.convert(BinaryOperation(OperationType.left_shift, [var_a.copy(), var_b.copy()])) == w.shift_left(a, b)
    assert converter.convert(BinaryOperation(OperationType.right_shift, [var_a.copy(), var_b.copy()])) == w.shift_right(a, b)
    assert converter.convert(BinaryOperation(OperationType.left_rotate, [var_a.copy(), var_b.copy()])) == w.rotate_left(a, b)
    assert converter.convert(BinaryOperation(OperationType.right_rotate, [var_a.copy(), var_b.copy()])) == w.rotate_right(a, b)


def test_branch(converter):
    """Check that all possible branch types (BinaryOperation, Expression, Variable) are handled correctly."""
    w = converter._world
    x = w.variable("x", 32)
    one = w.constant(1, 32)

    branch1 = converter.convert(Branch(Condition(OperationType.equal, [var_x.copy(), const_1.copy()])))
    branch2 = converter.convert(Branch(Condition(OperationType.not_equal, [var_x.copy(), const_1.copy()])))
    branch3 = converter.convert(Branch(Condition(OperationType.less, [var_x.copy(), const_1.copy()])))
    branch4 = converter.convert(Branch(Condition(OperationType.less_or_equal, [var_x.copy(), const_1.copy()])))
    branch5 = converter.convert(Branch(Condition(OperationType.greater, [var_x.copy(), const_1.copy()])))
    branch6 = converter.convert(Branch(Condition(OperationType.greater_or_equal, [var_x.copy(), const_1.copy()])))

    assert branch1 == w.bool_equal(x, one)
    assert branch2 == w.bool_unequal(x, one)
    assert branch3 == w.signed_lt(x, one)
    assert branch4 == w.signed_le(x, one)
    assert branch5 == w.signed_gt(x, one)
    assert branch6 == w.signed_ge(x, one)


def test_multiple_ops(converter):
    w = converter._world
    x = w.variable("x", 32)
    y = w.variable("y", 32)
    one = w.constant(1, 32)

    condition1 = converter.convert(
        Condition(
            OperationType.bitwise_and,
            [
                Condition(OperationType.equal, [var_x.copy(), const_1.copy()]),
                Condition(OperationType.not_equal, [var_y.copy(), const_1.copy()]),
            ],
        ),
    )
    condition2 = converter.convert(
        Condition(
            OperationType.bitwise_xor,
            [
                Condition(OperationType.equal, [var_x.copy(), const_1.copy()]),
                Condition(OperationType.not_equal, [var_y.copy(), const_1.copy()]),
            ],
        ),
    )
    condition3 = converter.convert(
        Condition(
            OperationType.bitwise_or,
            [
                Condition(OperationType.equal, [var_x.copy(), const_1.copy()]),
                Condition(OperationType.not_equal, [var_y.copy(), const_1.copy()]),
            ],
        ),
    )

    assert condition1 == w.bitwise_and(w.bool_equal(x, one), w.bool_unequal(y, one))
    assert condition2 == w.bitwise_xor(w.bool_equal(one, x), w.bool_unequal(one, y))
    assert condition3 == w.bitwise_or(w.bool_equal(x, one), w.bool_unequal(one, y))
