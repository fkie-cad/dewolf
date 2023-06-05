from math import inf

import pytest as pytest
from decompiler.structures.pseudo import (
    BinaryOperation,
    Branch,
    Condition,
    Constant,
    Float,
    Integer,
    NotUseableConstant,
    OperationType,
    Variable,
)
from decompiler.structures.pseudo.logic import BaseConverter
from decompiler.structures.pseudo.z3_logic import Z3Converter
from z3 import BoolRef


def _get_condition_branch(second_operand):
    return Branch(
        Condition(OperationType.not_equal,
            [
                Constant(42, Integer.int32_t()),
                second_operand,
            ],
        )
    )

def _generate_instr_bool_as_numbers(op: OperationType) -> Branch:
    return Branch(
        Condition(
            OperationType.not_equal,
            [
                BinaryOperation(
                    op,
                    [
                        Condition(OperationType.greater_us, [Variable("a"), Constant(64)]),
                        Condition(OperationType.less_or_equal_us, [Variable("b"), Constant(63)]),
                    ],
                ),
                Constant(-1),
            ],
        )
    )


@pytest.mark.parametrize(
    "instr",
    [
        _generate_instr_bool_as_numbers(OperationType.minus),
        _generate_instr_bool_as_numbers(OperationType.plus),
        _generate_instr_bool_as_numbers(OperationType.multiply),
        _generate_instr_bool_as_numbers(OperationType.divide),
        _generate_instr_bool_as_numbers(OperationType.left_shift),
        _generate_instr_bool_as_numbers(OperationType.right_shift),
        _generate_instr_bool_as_numbers(OperationType.modulo),
    ],
)
def test_instruction_conv(instr):
    logic_converter: BaseConverter = Z3Converter()
    condition = logic_converter.convert(instr, define_expr=True)
    # Assert typing
    assert isinstance(condition, BoolRef)
    # Assert z3 compatible
    logic_converter.check(condition)

def test_logic_converter_z3():
    logic_converter: BaseConverter = Z3Converter()
    instr1 = _get_condition_branch(Constant(inf, Float.double()))
    instr2 = _get_condition_branch(NotUseableConstant(str(inf)))

    # Not handled by 'Dead Path Elimination' yields OverflowError
    with pytest.raises(OverflowError):
        logic_converter.convert(instr1, define_expr=True)

    # Covered by 'Dead Path Elimination' yields ValueError (will be skipped for z3 stuff)
    with pytest.raises(ValueError):
        logic_converter.convert(instr2, define_expr=True)