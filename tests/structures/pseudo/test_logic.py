import pytest
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Branch, Return
from decompiler.structures.pseudo.logic import Z3Converter
from decompiler.structures.pseudo.operations import BinaryOperation, Condition, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import Float, Integer, Pointer
from z3 import And, BitVec, BitVecVal, Bool, BoolRef, Not, Or, Real, RotateLeft, RotateRight

var_a = Variable("a", Integer.int32_t())
var_b = Variable("b", Integer.int32_t())
var_x = Variable("x", Integer.int32_t())
var_y = Variable("y", Integer.int32_t())
const_1 = Constant(1, Integer.int32_t())


@pytest.fixture
def converter():
    return Z3Converter()


def test_unsupported(converter):
    with pytest.raises(ValueError):
        converter.convert(Return([Variable("x")]))
    with pytest.raises(ValueError):
        converter.convert(UnaryOperation(OperationType.dereference, [Variable("x")]))
    with pytest.raises(ValueError):
        converter.convert(UnaryOperation(OperationType.address, [Variable("x")]))


def test_constant(converter):
    assert converter.convert(Constant(6, Integer.int32_t())) == BitVecVal(6, 32, ctx=converter.context)
    assert converter.convert(Constant(7.2, Float.float())) == BitVecVal(7.2, 32, ctx=converter.context)
    with pytest.raises(ValueError):
        converter.convert(Constant("hello", Pointer(Integer.uint8_t())))


def test_variable(converter):
    """When generating a variable, we can not transpose ssa labels or type information."""
    assert converter.convert(Variable("x", Integer.int32_t(), ssa_label=0)) == BitVec("x", 32, ctx=converter.context)
    assert converter.convert(Variable("x", Integer.int32_t(), ssa_label=1)) == BitVec("x", 32, ctx=converter.context)
    assert converter.convert(Variable("x", Float.float(), ssa_label=1)) == BitVec("x", 32, ctx=converter.context)


def test_unary_operation(converter):
    assert converter.convert(UnaryOperation(OperationType.negate, [var_x.copy()])) == -BitVec("x", 32, ctx=converter.context)
    assert converter.convert(UnaryOperation(OperationType.logical_not, [Variable("x", Integer(1))])) == ~BitVec(
        "x", 1, ctx=converter.context
    )


def test_binary_operation(converter):
    bit_vec_a = BitVec("a", 32, ctx=converter.context)
    bit_vec_b = BitVec("b", 32, ctx=converter.context)
    assert converter.convert(BinaryOperation(OperationType.plus, [var_a.copy(), var_b.copy()])) == bit_vec_a + bit_vec_b
    assert converter.convert(BinaryOperation(OperationType.minus, [var_a.copy(), var_b.copy()])) == bit_vec_a - bit_vec_b
    assert converter.convert(BinaryOperation(OperationType.multiply, [var_a.copy(), var_b.copy()])) == bit_vec_a * bit_vec_b
    assert converter.convert(BinaryOperation(OperationType.divide, [var_a.copy(), var_b.copy()])) == bit_vec_a / bit_vec_b
    assert converter.convert(BinaryOperation(OperationType.modulo, [var_a.copy(), var_b.copy()])) == bit_vec_a % bit_vec_b
    assert converter.convert(BinaryOperation(OperationType.bitwise_xor, [var_a.copy(), var_b.copy()])) == bit_vec_a ^ bit_vec_b
    assert converter.convert(BinaryOperation(OperationType.bitwise_or, [var_a.copy(), var_b.copy()])) == bit_vec_a | bit_vec_b
    assert converter.convert(BinaryOperation(OperationType.bitwise_and, [var_a.copy(), var_b.copy()])) == bit_vec_a & bit_vec_b
    assert converter.convert(BinaryOperation(OperationType.left_shift, [var_a.copy(), var_b.copy()])) == bit_vec_a << bit_vec_b
    assert converter.convert(BinaryOperation(OperationType.right_shift, [var_a.copy(), var_b.copy()])) == bit_vec_a >> bit_vec_b
    assert converter.convert(BinaryOperation(OperationType.left_rotate, [var_a.copy(), var_b.copy()])) == RotateLeft(bit_vec_a, bit_vec_b)
    assert converter.convert(BinaryOperation(OperationType.right_rotate, [var_a.copy(), var_b.copy()])) == RotateRight(bit_vec_a, bit_vec_b)


def test_branch(converter):
    """Check that all possible branch types (BinaryOperation, Expression, Variable) are handled correctly."""
    assert str(converter.convert(Branch(Condition(OperationType.equal, [var_x.copy(), const_1.copy()])))) == str(
        BitVec("x", 32) == BitVecVal(1, 32)
    )
    assert str(converter.convert(Branch(Condition(OperationType.not_equal, [var_x.copy(), const_1.copy()])))) == str(
        BitVec("x", 32) != BitVecVal(1, 32)
    )
    assert str(converter.convert(Branch(Condition(OperationType.less, [var_x.copy(), const_1.copy()])))) == str(
        BitVec("x", 32) < BitVecVal(1, 32)
    )
    assert str(converter.convert(Branch(Condition(OperationType.less_or_equal, [var_x.copy(), const_1.copy()])))) == str(
        BitVec("x", 32) <= BitVecVal(1, 32)
    )
    assert str(converter.convert(Branch(Condition(OperationType.greater, [var_x.copy(), const_1.copy()])))) == str(
        BitVec("x", 32) > BitVecVal(1, 32)
    )
    assert str(converter.convert(Branch(Condition(OperationType.greater_or_equal, [var_x.copy(), const_1.copy()])))) == str(
        BitVec("x", 32) >= BitVecVal(1, 32)
    )


def test_boolref_ops(converter):
    assert (
        str(
            converter.convert(
                Condition(
                    OperationType.bitwise_and,
                    [
                        Condition(OperationType.equal, [var_x.copy(), const_1.copy()]),
                        Condition(OperationType.not_equal, [var_y.copy(), const_1.copy()]),
                    ],
                )
            )
        )
        == "And(1 == x, 1 != y)"
    )
    assert (
        str(
            converter.convert(
                Condition(
                    OperationType.bitwise_xor,
                    [
                        Condition(OperationType.equal, [var_x.copy(), const_1.copy()]),
                        Condition(OperationType.not_equal, [var_y.copy(), const_1.copy()]),
                    ],
                )
            )
        )
        == "Xor(1 == x, 1 != y)"
    )
    assert (
        str(
            converter.convert(
                Condition(
                    OperationType.bitwise_or,
                    [
                        Condition(OperationType.equal, [var_x.copy(), const_1.copy()]),
                        Condition(OperationType.not_equal, [var_y.copy(), const_1.copy()]),
                    ],
                )
            )
        )
        == "Or(1 == x, 1 != y)"
    )


def test_ensure_same_sort(converter):
    """Make sure that we can transform when the first operand is a bool."""
    var = Variable("a", Integer.int64_t())
    const_m1 = Constant(1, Integer.int64_t())
    const = Constant(1, Integer.char())
    assert (
        str(converter.convert(Condition(OperationType.less_us, [Condition(OperationType.equal, [var, const_m1]), const])))
        == "ULT(If(1 == a, 1, 0), Extract(0, 0, 1))"
    )


class TestSatisfiability:
    """Class implementing test for SAT checking."""

    converter = Z3Converter()
    x = {
        1: Bool("x1", ctx=converter.context),
        2: Bool("x2", ctx=converter.context),
    }
    a = BitVec("a", 32, ctx=converter.context)
    b = Real("x", ctx=converter.context)
    const = {
        15: BitVecVal(15, 32, ctx=converter.context),
        20: BitVecVal(20, 32, ctx=converter.context),
    }

    @pytest.mark.parametrize(
        "term, is_sat",
        [
            ((x[1], x[2]), True),
            ([And(x[1], x[2]), Or(Not(x[1]), Not(x[2]))], False),
            ([a < const[20], a == const[20]], False),
            ([a < const[20], a == const[15]], True),
            ([2 ** b == 3], False),
        ],
    )
    def test_is_satisfiable(self, term: BoolRef, is_sat: bool):
        assert self.converter.is_satisfiable(term) == is_sat

    @pytest.mark.parametrize(
        "term, is_unsat",
        [
            ((x[1], x[2]), False),
            ([And(x[1], x[2]), Or(Not(x[1]), Not(x[2]))], True),
            ([a < const[20], a == const[20]], True),
            ([a < const[20], a == const[15]], False),
            ([2 ** b == 3], False),
        ],
    )
    def test_is_not_satisfiable(self, term: BoolRef, is_unsat: bool):
        assert self.converter.is_not_satisfiable(term) == is_unsat
