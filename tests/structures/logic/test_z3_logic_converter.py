import pytest as pytest
from decompiler.structures.pseudo import BinaryOperation, Branch, Condition, Constant, OperationType, Variable
from decompiler.structures.pseudo.logic import BaseConverter
from decompiler.structures.pseudo.z3_logic import Z3Converter
from z3 import BoolRef


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
    try:
        condition = logic_converter.convert(instr, define_expr=True)
    except Exception:
        assert False
    # Assert typing
    assert isinstance(condition, BoolRef)
    # Assert z3 compatible
    logic_converter.check(condition)
