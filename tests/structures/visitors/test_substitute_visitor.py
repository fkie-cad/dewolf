import pytest
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Branch,
    Call,
    Condition,
    DataflowObject,
    Integer,
    OperationType,
    RegisterPair,
    Return,
    Variable,
)
from decompiler.structures.visitors.substitute_visitor import SubstituteVisitor

_i32 = Integer.int32_t()

_a = Variable("a", Integer.int32_t(), 0)
_b = Variable("b", Integer.int32_t(), 1)
_c = Variable("c", Integer.int32_t(), 2)
_d = Variable("d", Integer.int32_t(), 3)


@pytest.mark.parametrize(
    ["obj", "result", "visitor"],
    [
        (
            o := Variable("v", _i32, 0),
            r := Variable("x", _i32, 1),
            SubstituteVisitor.identity(o, r)
        ),
        (
            o := Variable("v", _i32, 0),
            r := Variable("x", _i32, 1),
            SubstituteVisitor.equality(o, r)
        ),
        (
            o := Variable("v", _i32, 0),
            o,
            SubstituteVisitor.identity(Variable("v", _i32, 0), Variable("x", _i32, 1))
        ),
        (
            o := Variable("v", _i32, 0),
            r := Variable("x", _i32, 1),
            SubstituteVisitor.equality(Variable("v", _i32, 0), r)
        ),
        (
            Assignment(a := Variable("a"), b := Variable("b")),
            Assignment(a, c := Variable("c")),
            SubstituteVisitor.identity(b, c)
        ),
        (
            BinaryOperation(OperationType.multiply, [a := Variable("a"), b := Variable("b")]),
            BinaryOperation(OperationType.multiply, [a, c := Variable("c")]),
            SubstituteVisitor.identity(b, c)
        ),
        (
            RegisterPair(a := Variable("a"), b := Variable("b")),
            RegisterPair(a, c := Variable("c")),
            SubstituteVisitor.identity(b, c)
        ),
        (
            Call(f := Variable("f"), [a := Variable("a")]),
            Call(f, [b := Variable("b")]),
            SubstituteVisitor.identity(a, b)
        ),
        (
            Call(f := Variable("f"), [a := Variable("a")]),
            Call(g := Variable("g"), [a]),
            SubstituteVisitor.identity(f, g)
        ),
        (
            Branch(a := Condition(OperationType.equal, [])),
            Branch(b := Condition(OperationType.not_equal, [])),
            SubstituteVisitor.identity(a, b)
        ),
        (
            Return([a := Variable("a")]),
            Return([b := Variable("b")]),
            SubstituteVisitor.identity(a, b)
        ),
    ]
)
def test_substitute(obj: DataflowObject, result: DataflowObject, visitor: SubstituteVisitor):
    new = obj.accept(visitor)
    if new is not None:
        obj = new

    assert obj == result
