import pytest
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Call,
    DataflowObject,
    IndirectBranch,
    Integer,
    ListOperation,
    OperationType,
    RegisterPair,
    Return,
    UnaryOperation,
    Variable,
)

_a = Variable("a", Integer.int32_t(), 0)
_b = Variable("b", Integer.int32_t(), 1)


@pytest.mark.parametrize(
    ["obj", "expected_requirements"],
    [
        (_a, [_a]),
        (_r := RegisterPair(_a, _b), [_r, _a, _b]),
        (Assignment(_a, _b), [_b]),
        (Assignment(ListOperation([_a]), _b), [_b]),
        (Assignment(UnaryOperation(OperationType.cast, [_a], contraction=True), _b), [_b]),
        (Assignment(UnaryOperation(OperationType.dereference, [_a]), _b), [_a, _b]),
        (IndirectBranch(_a), [_a]),
        (Return([_a, _b]), [_a, _b]),
        (ListOperation([_a, _b]), [_a, _b]),
        (BinaryOperation(OperationType.plus, [_a, _b]), [_a, _b]),
        (Call(_a, [_b]), [_a, _b]),
        (BinaryOperation(OperationType.plus, [_a, _a]), [_a, _a]),
    ],
)
def test_requirements(obj: DataflowObject, expected_requirements: list[Variable]):
    assert list(obj.requirements_iter) == expected_requirements
