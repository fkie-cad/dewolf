from functools import partial

import pytest
from decompiler.structures.pseudo import Assignment
from decompiler.structures.pseudo.expressions import Constant, FunctionSymbol, Variable
from decompiler.structures.pseudo.operations import (
    ArrayInfo,
    BinaryOperation,
    Call,
    Condition,
    ListOperation,
    MemberAccess,
    OperationType,
    TernaryExpression,
    UnaryOperation,
)
from decompiler.structures.pseudo.typing import Integer, Pointer

a = Variable("a", Integer.int32_t(), 0)
b = Variable("b", Integer.int32_t(), 1)
c = Variable("c", Integer.int32_t(), 2)
ptr = Variable("ptr", Pointer(Integer.int32_t()), 0)

neg = OperationType.negate
add = OperationType.plus
sub = OperationType.minus
div = OperationType.divide
udiv = OperationType.divide_us
cast = OperationType.cast
deref = OperationType.dereference


def test_substitute():
    # -a.substitute(a,b) -> -b
    op = UnaryOperation(neg, [a])
    op.substitute(a, b)
    assert str(op) == "-(b#1)"
    # *(a + c).substitute(a, b) -> *(b + c)
    # *(b + c).substitute(c, a) -> *(b + a)
    # and check if ArrayInfo is updated
    op = UnaryOperation(deref, [BinaryOperation(add, [a, c])], array_info=ArrayInfo(a, c))
    op.substitute(a, b)
    assert str(op.array_info.base) == "b#1"
    assert str(op) == "*(b#1 + c#2)"
    op.substitute(c, a)
    assert str(op.array_info.index) == "a#0"
    assert str(op) == "*(b#1 + a#0)"
    # a+a.substitute(a, c) -> c+c
    op = BinaryOperation(add, [a, a])
    op.substitute(a, c)
    assert str(op) == "c#2 + c#2"
    # a/b.substitute(a, c) -> c/b
    op = BinaryOperation(div, [a, b])
    op.substitute(a, c)
    assert str(op) == "c#2 / b#1"
    # a/b.substitute(a, c) -> c u/ b
    op = BinaryOperation(udiv, [a, b])
    op.substitute(a, c)
    assert str(op) == "c#2 u/ b#1"
    # a+(a+b).substitute(a, c) -> c+(c+b)
    op = BinaryOperation(add, [a, BinaryOperation(add, [a, b])])
    op.substitute(a, c)
    assert str(op) == "c#2 + (c#2 + b#1)"
    # -((a+b)).substitute(a+b, c) -> -(c)"""
    op = UnaryOperation(neg, [BinaryOperation(add, [a, b])])
    op.substitute(BinaryOperation(add, [a, b]), c)
    assert str(op) == "-(c#2)"
    op = ListOperation([a, b])
    op.substitute(a, c)
    assert str(op) == "c#2,b#1"
    op = ListOperation([c, c])
    op.substitute(c, b)
    assert str(op) == "b#1,b#1"
    op = ListOperation([BinaryOperation(add, [a, a]), b])
    op.substitute(a, c)
    assert str(op) == "c#2 + c#2,b#1"
    op = BinaryOperation(add, [BinaryOperation(add, [a, a]), b])
    op.substitute(a, BinaryOperation(add, [b, c]))
    assert str(op) == "((b#1 + c#2) + (b#1 + c#2)) + b#1"
    op = MemberAccess(operands=[a], member_name="x", offset=0, vartype=Integer.int32_t())
    op.substitute(a, b)
    assert str(op) == "b#1.x"


def test_substitute_loop():
    op = BinaryOperation(add, [b, Constant(1)])
    op.substitute(b, BinaryOperation(add, [b, Constant(1)]))
    assert op == BinaryOperation(add, [BinaryOperation(add, [b, Constant(1)]), Constant(1)])


def test_complexity():
    assert UnaryOperation(neg, [BinaryOperation(add, [a, b])]).complexity == 2
    assert UnaryOperation(neg, [UnaryOperation(neg, [a])]).complexity == 1
    assert BinaryOperation(add, [a, BinaryOperation(add, [a, b])]).complexity == 3
    assert BinaryOperation(add, [Constant(2), BinaryOperation(add, [a, b])]).complexity == 3
    assert ListOperation([a, b]).complexity == 2
    assert ListOperation([]).complexity == 0
    assert ListOperation([a, BinaryOperation(add, [a, b])]).complexity == 3
    assert ListOperation([a, BinaryOperation(add, [b, c])]).complexity == 3
    assert ListOperation([Constant(2), a]).complexity == 2
    assert UnaryOperation(OperationType.cast, [a]).complexity == 1
    assert UnaryOperation(OperationType.cast, [UnaryOperation(OperationType.cast, [a])]).complexity == 1
    assert (
        UnaryOperation(OperationType.cast, [UnaryOperation(OperationType.negate, [UnaryOperation(OperationType.cast, [a])])]).complexity
        == 1
    )
    assert MemberAccess(operands=[a], member_name="x", offset=0, vartype=Integer.int32_t()).complexity == 1


def test_requirements():
    assert set(UnaryOperation(neg, [BinaryOperation(add, [a, b])]).requirements) == {a, b}
    assert UnaryOperation(neg, [UnaryOperation(neg, [a])]).requirements == [a]
    assert set(BinaryOperation(add, [a, BinaryOperation(add, [a, b])]).requirements) == {a, b}
    assert set(BinaryOperation(add, [Constant(2), BinaryOperation(add, [a, b])]).requirements) == {a, b}
    assert set(ListOperation([a, b]).requirements) == {a, b}
    assert ListOperation([]).requirements == []
    assert set(ListOperation([a, BinaryOperation(add, [a, b])]).requirements) == {a, b}
    assert set(ListOperation([a, BinaryOperation(add, [b, c])]).requirements) == {a, b, c}
    assert ListOperation([Constant(2), a]).requirements == [a]
    assert MemberAccess(operands=[a], member_name="x", offset=0, vartype=Integer.int32_t()).requirements == [a]


def test_repr():
    assert (
        repr(UnaryOperation(neg, [BinaryOperation(add, [a, b])]))
        == "negate [plus [a#0 (type: int aliased: False),b#1 (type: int aliased: False)] int] int"
    )
    assert (
        repr(UnaryOperation(neg, [BinaryOperation(udiv, [a, b])]))
        == "negate [divide_us [a#0 (type: int aliased: False),b#1 (type: int aliased: False)] int] int"
    )
    assert (
        repr(UnaryOperation(neg, [BinaryOperation(div, [a, b])]))
        == "negate [divide [a#0 (type: int aliased: False),b#1 (type: int aliased: False)] int] int"
    )
    assert repr(UnaryOperation(neg, [UnaryOperation(neg, [a])])) == "negate [negate [a#0 (type: int aliased: False)] int] int"
    assert (
        repr(BinaryOperation(add, [a, BinaryOperation(add, [a, b])]))
        == "plus [a#0 (type: int aliased: False),plus [a#0 (type: int aliased: False),b#1 (type: int aliased: False)] int] int"
    )
    assert (
        repr(BinaryOperation(add, [Constant(2, Integer.int32_t()), BinaryOperation(add, [a, b])]))
        == "plus [2 type: int,plus [a#0 (type: int aliased: False),b#1 (type: int aliased: False)] int] int"
    )
    assert repr(ListOperation([a, Constant(2, Integer.int32_t())])) == "list_op [a#0 (type: int aliased: False),2 type: int] int"
    assert repr(ListOperation([])) == "list_op [] unknown type"
    assert (
        repr(ListOperation([a, BinaryOperation(add, [a, b])]))
        == "list_op [a#0 (type: int aliased: False),plus [a#0 (type: int aliased: False),b#1 (type: int aliased: False)] int] int"
    )
    assert repr(UnaryOperation(cast, [a])) == "cast [a#0 (type: int aliased: False)] int"
    assert repr(UnaryOperation(cast, [a], contraction=True)) == "cast [a#0 (type: int aliased: False)] int contract"
    assert (
        repr(UnaryOperation(OperationType.dereference, [BinaryOperation(add, [a, b])]))
        == "dereference [plus [a#0 (type: int aliased: False),b#1 (type: int aliased: False)] int] int"
    )
    assert (
        repr(UnaryOperation(OperationType.dereference, [BinaryOperation(add, [a, b])], array_info=ArrayInfo(a, b)))
        == "dereference [plus [a#0 (type: int aliased: False),b#1 (type: int aliased: False)] int] int"
        " ArrayInfo(base=a#0 (type: int aliased: False), index=b#1 (type: int aliased: False), confidence=False)"
    )
    assert (
        repr(UnaryOperation(OperationType.dereference, [BinaryOperation(add, [a, b])], array_info=ArrayInfo(a, b, True)))
        == "dereference [plus [a#0 (type: int aliased: False),b#1 (type: int aliased: False)] int] int"
        " ArrayInfo(base=a#0 (type: int aliased: False), index=b#1 (type: int aliased: False), confidence=True)"
    )


def test_operand_ambiguity():
    """Ensure overloaded operands are treated correctly."""
    assert UnaryOperation(OperationType.dereference, [Constant(1)]) != UnaryOperation(OperationType.multiply, [Constant(1)])
    assert UnaryOperation(neg, [Constant(1)]) != UnaryOperation(sub, [Constant(1)])


def test_str():
    assert str(UnaryOperation(neg, [a])) == "-(a#0)"
    assert str(UnaryOperation(cast, [a], Integer.int64_t())) == "(long) a#0"
    assert str(BinaryOperation(add, [a, b])) == "a#0 + b#1"
    assert str(BinaryOperation(div, [a, b])) == "a#0 / b#1"
    assert str(BinaryOperation(udiv, [a, b])) == "a#0 u/ b#1"
    assert str(ListOperation([a, b])) == "a#0,b#1"
    assert str(MemberAccess(operands=[a], member_name="x", offset=0, vartype=Integer.int32_t())) == "a#0.x"
    assert str(MemberAccess(operands=[ptr], member_name="x", offset=0, vartype=Integer.int32_t())) == "ptr#0->x"


def test_iter():
    """Iterating an operation should always return all of its operands."""
    assert list(UnaryOperation(neg, [a])) == [a]
    assert list(BinaryOperation(add, [a, Constant(2)])) == [a, Constant(2)]
    assert list(BinaryOperation(add, [Constant(2), BinaryOperation(add, [a, b])])) == [Constant(2), BinaryOperation(add, [a, b])]


def test_copy():
    """Test if copying an Operation results in the operands being copied as well."""
    original = UnaryOperation(neg, [a])
    copy = original.copy()
    assert id(original) != id(copy) and original == copy
    assert id(original.operands) != id(copy.operands) and original.operands == copy.operands
    assert id(original.operands[0]) != id(copy.operands[0])
    original = ListOperation([a, b])
    copy = original.copy()
    assert id(original) != id(copy) and original == copy
    assert id(original.operands) != id(copy.operands) and original.operands == copy.operands
    assert id(original.operands[0]) != id(copy.operands[0])
    original = BinaryOperation(add, [a, Constant(0)])
    copy = original.copy()
    assert id(original) != id(copy) and original == copy
    assert id(original.operands) != id(copy.operands) and original.operands == copy.operands
    assert id(original.operands[0]) != id(copy.operands[0])
    assert id(original.operands[1]) != id(copy.operands[1])
    original = BinaryOperation(div, [a, Constant(0)])
    copy = original.copy()
    assert id(original) != id(copy) and original == copy
    assert id(original.operands) != id(copy.operands) and original.operands == copy.operands
    assert id(original.operands[0]) != id(copy.operands[0])
    assert id(original.operands[1]) != id(copy.operands[1])
    original = BinaryOperation(udiv, [a, Constant(0)])
    assert copy.is_signed is True
    copy = original.copy()
    assert id(original) != id(copy) and original == copy
    assert id(original.operands) != id(copy.operands) and original.operands == copy.operands
    assert id(original.operands[0]) != id(copy.operands[0])
    assert id(original.operands[1]) != id(copy.operands[1])
    assert copy.is_signed is False
    original = UnaryOperation(OperationType.cast, [Variable("x")], Integer.int32_t(), contraction=True)
    copy = original.copy()
    assert id(copy) != id(original)
    assert copy == UnaryOperation(OperationType.cast, [Variable("x")], Integer.int32_t(), contraction=True)
    original.contraction = False
    copy = original.copy()
    assert id(copy) != id(original) and copy == UnaryOperation(OperationType.cast, [Variable("x")], Integer.int32_t(), contraction=False)
    assert copy == UnaryOperation(OperationType.cast, [Variable("x")], Integer.int32_t())
    original = UnaryOperation(
        OperationType.dereference,
        [BinaryOperation(OperationType.plus, [base := Variable("arg"), index := Variable("x")])],
        array_info=ArrayInfo(base, index, True),
    )

    copy = original.copy()
    assert id(copy) != id(original)
    assert copy == UnaryOperation(
        OperationType.dereference,
        [BinaryOperation(OperationType.plus, [base := Variable("arg"), index := Variable("x")])],
        array_info=ArrayInfo(base, index, True),
    )
    original.array_info.confidence = False
    assert copy != original
    original = UnaryOperation(
        OperationType.dereference,
        [BinaryOperation(OperationType.plus, [base := Variable("arg"), index := Variable("x")])],
        array_info=ArrayInfo(base, index, False),
    )
    copy = original.copy()
    assert id(copy) != id(original)
    assert copy == UnaryOperation(
        OperationType.dereference,
        [BinaryOperation(OperationType.plus, [base := Variable("arg"), index := Variable("x")])],
        array_info=ArrayInfo(base, index, False),
    )
    original.array_info.index = Variable("y")
    assert copy != original
    original = MemberAccess(operands=[a], member_name="x", offset=0, vartype=Integer.int32_t(), writes_memory=1)
    copy = original.copy()
    assert copy == original
    assert id(copy) != original
    assert copy == MemberAccess(operands=[a], member_name="x", offset=0, vartype=Integer.int32_t(), writes_memory=1)


def test_member_access_properties():
    member_access = MemberAccess(operands=[a], member_name="x", offset=4, vartype=Integer.int32_t(), writes_memory=1)
    assert member_access.member_name == "x"
    assert member_access.member_offset == 4
    assert member_access.struct_variable == a
    assert member_access.is_write_access()
    assert not member_access.is_read_access()
    member_access = MemberAccess(operands=[a], member_name="x", offset=4, vartype=Integer.int32_t(), writes_memory=None)
    assert not member_access.is_write_access()
    assert member_access.is_read_access()


func = FunctionSymbol("func", 0x42)

eq = partial(Condition, OperationType.equal)
neq = partial(Condition, OperationType.not_equal)
lt = partial(Condition, OperationType.less)
ult = partial(Condition, OperationType.less_us)
lte = partial(Condition, OperationType.less_or_equal)
ulte = partial(Condition, OperationType.less_or_equal_us)
gt = partial(Condition, OperationType.greater)
ugt = partial(Condition, OperationType.greater_us)
gte = partial(Condition, OperationType.greater_or_equal)
ugte = partial(Condition, OperationType.greater_or_equal_us)


class TestCondition:
    def test_str(self):
        assert str(eq([a, b])) == "a#0 == b#1"
        assert str(neq([a, Constant(4)])) == "a#0 != 0x4"
        assert str(lt([a, BinaryOperation(add, [b, c])])) == "a#0 < (b#1 + c#2)"
        assert str(ult([a, BinaryOperation(add, [b, c])])) == "a#0 u< (b#1 + c#2)"
        assert str(gt([a, b])) == "a#0 > b#1"
        assert str(ugt([a, b])) == "a#0 u> b#1"
        assert str(lte([a, b])) == "a#0 <= b#1"
        assert str(ulte([a, b])) == "a#0 u<= b#1"
        assert str(gte([a, b])) == "a#0 >= b#1"
        assert str(ugte([a, b])) == "a#0 u>= b#1"

    def test_negate(self):
        assert eq([a, b]).negate() == neq([a, b])
        assert lt([a, b]).negate() == gte([a, b])
        assert ult([a, b]).negate() == ugte([a, b])
        assert lte([a, b]).negate() == gt([a, b])
        assert ulte([a, b]).negate() == ugt([a, b])
        assert neq([a, b]).negate() == eq([a, b])
        assert gt([a, b]).negate() == lte([a, b])
        assert ugt([a, b]).negate() == ulte([a, b])
        assert gte([a, b]).negate() == lt([a, b])
        assert ugte([a, b]).negate() == ult([a, b])

    def test_negate_raises_error(self):
        with pytest.raises(KeyError):
            non_condition_operation = OperationType.dereference
            Condition(non_condition_operation, [a, b]).negate()

    def test_equality_with_constant(self):
        assert not eq([a, b]).is_equality_with_constant_check()
        assert not lte([Constant(2), a]).is_equality_with_constant_check()
        assert eq([a, Constant(4)]).is_equality_with_constant_check()

    def test_variable_equality_with_constant(self):
        assert eq([a, Constant(4)]).is_variable_equality_with_constant_check(a)
        assert not eq([b, Constant(4)]).is_variable_equality_with_constant_check(a)

    def test_iter(self):
        """Check that a condition yields its operands upon iteration."""
        assert list(eq([a, b])) == list(neq([a, b])) == [a, b]
        assert list(eq([a, Constant(2)])) == [a, Constant(2)]

    def test_copy(self):
        """Check whether copying a condition results in all nested expressions being copied."""
        original = lte([Constant(2), a])
        copy = original.copy()
        assert id(original) != id(copy) and original == copy
        assert id(original.operands) != id(copy.operands) and original.operands == copy.operands
        assert id(original.operands[0]) != id(copy.operands[0])
        assert id(original.operands[1]) != id(copy.operands[1])
        assert copy.is_signed is True

        original = ulte([Constant(2), a])
        copy = original.copy()
        assert id(original) != id(copy) and original == copy
        assert id(original.operands) != id(copy.operands) and original.operands == copy.operands
        assert id(original.operands[0]) != id(copy.operands[0])
        assert id(original.operands[1]) != id(copy.operands[1])
        assert copy.is_signed is False


class TestTernaryExpression:
    def test_complexity(self):
        assert TernaryExpression(lte([a, b]), Constant(0), Constant(1)).complexity == 4
        assert TernaryExpression(lte([a, b]), a, b).complexity == 4

    def test_requirements(self):
        assert set(TernaryExpression(lte([a, b]), Constant(0), Constant(1)).requirements) == {a, b}
        assert set(TernaryExpression(lte([a, b]), a, b).requirements) == {a, b}

    def test_properties(self):
        t1 = TernaryExpression(lte([a, b]), Constant(0), Constant(1))
        assert t1.condition == lte([a, b])
        assert t1.true == Constant(0)
        assert t1.false == Constant(1)
        t2 = TernaryExpression(c, a, b)
        assert t2.condition == c
        assert t2.true == a
        assert t2.false == b

    def test_iter(self):
        """Iterating a TernaryExpression should yield 3 terms."""
        assert list(TernaryExpression(lte([a, b]), Constant(0), Constant(1))) == [lte([a, b]), Constant(0), Constant(1)]

    def test_copy(self):
        """Test that all three subexpressions are copied correctly."""
        original = TernaryExpression(lte([a, b]), Constant(0), Constant(1))
        copy = original.copy()
        assert id(original) != id(copy) and original == copy
        assert id(original.operands) != id(copy.operands) and original.operands == copy.operands
        assert id(original.operands[0]) != id(copy.operands[0])
        assert id(original.operands[1]) != id(copy.operands[1])


class TestCall:
    def test_str(self):
        op = Call(FunctionSymbol("func", 0), [])
        assert str(op) == "func()"
        op = Call(a, [])
        assert str(op) == "a#0()"
        op = Call(FunctionSymbol("func", 0), [a])
        assert str(op) == "func(a#0)"
        op = Call(FunctionSymbol("func", 0), [a, b, c])
        assert str(op) == "func(a#0, b#1, c#2)"
        assert str(Call(FunctionSymbol("func", 0), [Constant("string")])) == 'func("string")'
        assert str(Assignment(ListOperation([]), Call(FunctionSymbol("func", 0), [Constant(1)]))) == "func(0x1)"
        assert str(Assignment(ListOperation([a.copy()]), Call(FunctionSymbol("func", 0), [Constant(1)]))) == "a#0 = func(0x1)"

    def test_requirements(self):
        assert Call(FunctionSymbol("func", 0), []).requirements == []
        assert Call(FunctionSymbol("func", 0), [a]).requirements == [a]
        assert Call(FunctionSymbol("func", 0), [Constant(2)]).requirements == []
        assert Call(FunctionSymbol("func", 0), [Constant(2), a]).requirements == [a]
        assert set(Call(FunctionSymbol("func", 0), [b, a]).requirements) == {b, a}
        assert Call(FunctionSymbol("func", 0), [BinaryOperation(add, [c, c])]).requirements == [c]
        assert Call(a, [a]).requirements == [a]
        assert set(Call(a, [b]).requirements) == {a, b}
        assert set(Call(a, [a, b]).requirements) == {a, b}

    def test_complexity(self):
        assert Call(FunctionSymbol("func", 0), []).complexity == 0
        assert Call(FunctionSymbol("func", 0), [a]).complexity == 1
        assert Call(FunctionSymbol("func", 0), [Constant(2)]).complexity == 1
        assert Call(FunctionSymbol("func", 0), [Constant(2), a]).complexity == 2
        assert Call(FunctionSymbol("func", 0), [b, a]).complexity == 2
        assert Call(a, [b, b]).complexity == 2
        assert Call(a, [BinaryOperation(add, [c, c])]).complexity == 2

    def test_repr(self):
        assert repr(Call(func, [])) == "func "
        assert repr(Call(func, [a])) == "func a#0 (type: int aliased: False)"
        assert repr(Call(func, [Constant(2, Integer.int32_t())])) == "func 2 type: int"
        assert repr(Call(func, [Constant(2, Integer.int32_t()), a])) == "func 2 type: int,a#0 (type: int aliased: False)"
        assert repr(Call(func, [b, a])) == "func b#1 (type: int aliased: False),a#0 (type: int aliased: False)"
        assert (
            repr(Call(func, [BinaryOperation(add, [c, c])]))
            == "func plus [c#2 (type: int aliased: False),c#2 (type: int aliased: False)] int"
        )

    def test_parameters(self):
        assert Call(FunctionSymbol("func", 0), []).parameters == []
        assert Call(b, [a]).parameters == [a]
        assert Call(b, [Constant(2)]).parameters == [Constant(2)]
        assert Call(FunctionSymbol("func", 0), [Constant(2), a]).parameters == [Constant(2), a]
        assert Call(FunctionSymbol("func", 0), [b, a]).parameters == [b, a]
        assert Call(FunctionSymbol("func", 0), [b, b]).parameters == [b, b]
        assert Call(FunctionSymbol("func", 0), [BinaryOperation(add, [c, c])]).parameters == [BinaryOperation(add, [c, c])]

    def test_iter(self):
        """Test that the function expression and all operands are returned during iteration."""
        assert list(Call(FunctionSymbol("func", 0), [a, b, Constant(0)])) == [FunctionSymbol("func", 0), a, b, Constant(0)]

    def test_copy(self):
        """Check if all subexpressions (also the function expression) is copied correctly."""
        original = Call(FunctionSymbol("func", 0), [a, b, Constant(0)], meta_data={"test": "meta_data"})
        copy = original.copy()
        assert id(original) != id(copy) and original == copy
        assert id(original.operands) != id(copy.operands) and original.operands == copy.operands
        assert id(original.operands[0]) != id(copy.operands[0])
        assert id(original.operands[1]) != id(copy.operands[1])
        assert id(original.operands[2]) != id(copy.operands[2])
        assert copy.meta_data is not None
        assert id(original.meta_data) != id(copy.meta_data)
