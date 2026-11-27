"""Tests for the feature vectors of the conditional out-of-SSA mode."""

import pytest
from decompiler.pipeline.ssa.conditional_attribute_helper import ConditionalAttributeHelper, Feature, get_phi_pairs
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Call,
    Constant,
    FunctionSymbol,
    Integer,
    OperationType,
    Pointer,
    UnaryOperation,
    Variable,
)

INT = Integer.int32_t()
ARGUMENT = Variable("a", INT, 0)
OTHER = Variable("b", INT, 0)
RESULT = Variable("x", INT, 0)


POINTER = Variable("p", Pointer(INT), 0)
NODE = Variable("n", Pointer(INT), 0)
FUNCTION_POINTER = Variable("fp", Pointer(INT), 0)
USE_KINDS = (Feature.use_direct, Feature.use_call, Feature.use_memory, Feature.use_address)
STRONG_MID_DEF_BY_USAGE = (Feature.is_strong, Feature.is_mid, Feature.def_by_usage)
DIRECT, CALL, MEMORY, ADDRESS = (1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)


def _call(*arguments) -> Call:
    return Call(FunctionSymbol("f", 0x42), list(arguments) or [ARGUMENT], INT)


def _plus(left, right) -> BinaryOperation:
    return BinaryOperation(OperationType.plus, [left, right])


def _vectors(value, destination=RESULT) -> dict:
    """Return the feature vector of each pair (destination, rhs variable) for the assignment destination = value."""
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, [Assignment(destination, value)]))
    return {pair[1]: vector for pair, vector in ConditionalAttributeHelper(get_phi_pairs(cfg)).iter_edge_data(cfg)}


def _use_kinds(value) -> dict:
    """Return the four use-kind entries of each pair (x, rhs variable) for the assignment x = value."""
    return {variable: tuple(vector.get(feature, 0) for feature in USE_KINDS) for variable, vector in _vectors(value).items()}


@pytest.mark.parametrize(
    "value, expected",
    [
        (ARGUMENT, {ARGUMENT: DIRECT}),
        (_plus(ARGUMENT, Constant(1, INT)), {ARGUMENT: DIRECT}),
        (UnaryOperation(OperationType.cast, [ARGUMENT], INT), {ARGUMENT: DIRECT}),
        (_call(), {ARGUMENT: CALL}),
        (_plus(_call(), Constant(1, INT)), {ARGUMENT: CALL}),
        (UnaryOperation(OperationType.cast, [_call()], INT), {ARGUMENT: CALL}),
        (_plus(_call(), OTHER), {ARGUMENT: CALL, OTHER: DIRECT}),
        (UnaryOperation(OperationType.dereference, [ARGUMENT], INT), {ARGUMENT: MEMORY}),
        (_call(UnaryOperation(OperationType.dereference, [ARGUMENT], INT)), {ARGUMENT: (0, 1, 1, 0)}),
        (UnaryOperation(OperationType.address, [ARGUMENT], Pointer(INT)), {ARGUMENT: ADDRESS}),
        (_plus(ARGUMENT, _call()), {ARGUMENT: (1, 1, 0, 0)}),
        (
            UnaryOperation(OperationType.dereference, [BinaryOperation(OperationType.plus, [POINTER, Constant(8, INT)])], INT),
            {POINTER: MEMORY},
        ),
        (BinaryOperation(OperationType.member_access, [NODE, Constant(8, INT)], INT), {NODE: MEMORY}),
        (Call(FUNCTION_POINTER, [ARGUMENT], INT), {FUNCTION_POINTER: CALL, ARGUMENT: CALL}),
        (
            Call(UnaryOperation(OperationType.dereference, [FUNCTION_POINTER], INT), [ARGUMENT], INT),
            {FUNCTION_POINTER: (0, 1, 1, 0), ARGUMENT: CALL},
        ),
    ],
)
def test_use_kinds(value, expected):
    """Every kind of operation on the path to an occurrence is set (multi-hot), occurrences are united, other operations are transparent."""
    assert _use_kinds(value) == expected


def test_use_kinds_are_zero_for_other_pairs():
    """Following-definition and same-source pairs have no use kinds."""
    first, second, third = Variable("y", INT, 0), Variable("y", INT, 1), Variable("y", INT, 2)
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, [Assignment(second, _call(first)), Assignment(third, _call(second))]))
    for _, vector in ConditionalAttributeHelper(get_phi_pairs(cfg)).iter_edge_data(cfg):
        if Feature.following_definitions in vector or Feature.same_rhs_source in vector:
            assert not any(feature in vector for feature in USE_KINDS)


@pytest.mark.parametrize(
    "value, variable, expected",
    [
        # (is_strong, is_mid, def_by_usage)
        (ARGUMENT, ARGUMENT, (1, 0, 1)),
        (UnaryOperation(OperationType.cast, [ARGUMENT], INT), ARGUMENT, (1, 0, 1)),
        (_plus(ARGUMENT, Constant(1, INT)), ARGUMENT, (0, 1, 1)),
        (_call(), ARGUMENT, (0, 0, 0)),
        (UnaryOperation(OperationType.dereference, [ARGUMENT], INT), ARGUMENT, (0, 0, 0)),
        # a variable used both directly and in a call is not a direct use only
        (_plus(ARGUMENT, _call()), ARGUMENT, (0, 0, 0)),
        # the callee is not a constant: x = f(a) + 1 has exactly one constant, but a is used in a call
        (_plus(_call(), Constant(1, INT)), ARGUMENT, (0, 0, 0)),
        # x = *p + b: p is bad, but b is used directly; there are two variables, so the vector stays 0 for both
        (_plus(UnaryOperation(OperationType.dereference, [POINTER], INT), OTHER), OTHER, (0, 0, 0)),
        # bad operations without a: x = a + *0x1234 and x = a + g() keep is_mid and def_by_usage for a
        (_plus(ARGUMENT, UnaryOperation(OperationType.dereference, [Constant(0x1234, Pointer(INT))], INT)), ARGUMENT, (0, 1, 1)),
        (_plus(ARGUMENT, Call(FunctionSymbol("g", 0x43), [], INT)), ARGUMENT, (0, 0, 1)),
    ],
)
def test_strong_mid_and_def_by_usage_depend_on_the_rhs_variable(value, variable, expected):
    """is_strong, is_mid and def_by_usage look at the use of the pair's rhs variable and need exactly one rhs variable."""
    vector = _vectors(value)[variable]
    assert tuple(vector.get(feature, 0) for feature in STRONG_MID_DEF_BY_USAGE) == expected


def test_def_by_usage_with_repeated_direct_uses():
    """x = a * 2 + a - 3 has one variable with direct uses only: def_by_usage but neither strong nor mid."""
    value = BinaryOperation(
        OperationType.minus, [_plus(BinaryOperation(OperationType.multiply, [ARGUMENT, Constant(2, INT)]), ARGUMENT), Constant(3, INT)]
    )
    vector = _vectors(value)[ARGUMENT]
    assert tuple(vector.get(feature, 0) for feature in STRONG_MID_DEF_BY_USAGE) == (0, 0, 1)


def test_lhs_bad_operation_still_clears_the_vector():
    """The lhs checks stay: a dereferenced destination clears is_strong, is_mid and def_by_usage."""
    destination = UnaryOperation(OperationType.dereference, [POINTER], INT)
    vector = _vectors(ARGUMENT, destination)[ARGUMENT]
    assert tuple(vector.get(feature, 0) for feature in STRONG_MID_DEF_BY_USAGE) == (0, 0, 0)


@pytest.mark.parametrize(
    "value, constant_count",
    [
        (_call(), 0),
        (_plus(_call(), Constant(1, INT)), 1),
        (_call(Constant(5, INT), ARGUMENT), 1),
    ],
)
def test_callee_is_not_a_constant(value, constant_count):
    """The function symbol of a call is not counted as a constant."""
    helper = ConditionalAttributeHelper(set())
    assert helper._get_expression_info(value).constant_count == constant_count
