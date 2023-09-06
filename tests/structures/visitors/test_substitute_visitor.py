import pytest
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Branch,
    Call,
    Constant,
    DataflowObject,
    Integer,
    Phi,
    Pointer,
    RegisterPair,
    Return,
    UnaryOperation,
    Variable,
)
from decompiler.structures.pseudo.operations import ArrayInfo, Condition, OperationType
from decompiler.structures.visitors.substitute_visitor import SubstituteVisitor

_i32 = Integer.int32_t()
_p_i32 = Pointer(Integer.int32_t())

_a = Variable("a", Integer.int32_t(), 0)
_b = Variable("b", Integer.int32_t(), 1)
_c = Variable("c", Integer.int32_t(), 2)
_d = Variable("d", Integer.int32_t(), 3)


@pytest.mark.parametrize(
    ["initial_obj", "expected_result", "visitor"],
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
            Assignment(a := Variable("a"), b := Variable("b")),
            Assignment(c := Variable("c"), b),
            SubstituteVisitor.identity(a, c)
        ),
        (
            UnaryOperation(OperationType.dereference, [a := Variable("a")]),
            UnaryOperation(OperationType.dereference, [b := Variable("b")]),
            SubstituteVisitor.identity(a, b)
        ),
        (
            UnaryOperation(
                OperationType.dereference,
                [BinaryOperation(OperationType.plus, [a := Variable("a", _p_i32), Constant(4, _i32)])],
                array_info=ArrayInfo(a, 1)
            ),
            UnaryOperation(
                OperationType.dereference,
                [BinaryOperation(OperationType.plus, [b := Variable("b", _p_i32), Constant(4, _i32)])],
                array_info=ArrayInfo(b, 1)
            ),
            SubstituteVisitor.identity(a, b)
        ),
        (
            UnaryOperation(
                OperationType.dereference,
                [BinaryOperation(
                    OperationType.plus,
                    [
                        a := Variable("a", _p_i32),
                        BinaryOperation(OperationType.multiply, [b := Variable("b", _i32), Constant(4, _i32)])
                    ]
                )],
                array_info=ArrayInfo(a, b)
            ),
            UnaryOperation(
                OperationType.dereference,
                [BinaryOperation(
                    OperationType.plus,
                    [
                        a := Variable("a", _p_i32),
                        BinaryOperation(OperationType.multiply, [c := Variable("c", _i32), Constant(4, _i32)])
                    ]
                )],
                array_info=ArrayInfo(a, c)
            ),
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
            Phi(
                a3 := Variable("a", _i32, 3),
                [
                    a2 := Variable("a", _i32, 2),
                    a1 := Variable("a", _i32, 1)
                ],
                {
                    BasicBlock(2): a2,
                    BasicBlock(1): a1,
                }
            ),
            Phi(
                a3,
                [
                    a2,
                    a0 := Variable("a", _i32, 0)
                ],
                {
                    BasicBlock(2): a2,
                    BasicBlock(1): a0,
                }
            ),
            SubstituteVisitor.identity(a1, a0)
        ),
        (
            Phi(
                a3 := Variable("a", _i32, 3),
                [
                    a2 := Variable("a", _i32, 2),
                    a1 := Variable("a", _i32, 1)
                ],
                {
                    BasicBlock(2): a2,
                    BasicBlock(1): a1,
                }
            ),
            Phi(
                a4 := Variable("a", _i32, 4),
                [
                    a2,
                    a1
                ],
                {
                    BasicBlock(2): a2,
                    BasicBlock(1): a0,
                }
            ),
            SubstituteVisitor.identity(a3, a4)
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
def test_substitute(initial_obj: DataflowObject, expected_result: DataflowObject, visitor: SubstituteVisitor):
    result = initial_obj.accept(visitor)
    if result is None:
        result = initial_obj

    assert result == expected_result
