from typing import List, Tuple

import pytest as pytest
from decompiler.structures.logic.z3_implementations import Z3Implementation
from decompiler.structures.logic.z3_logic import PseudoZ3LogicCondition, Z3LogicCondition
from decompiler.structures.pseudo import BinaryOperation, Condition, Constant, Integer, OperationType, Variable
from z3 import UGT, ULE, And, BitVec, BitVecVal, Bool, BoolRef, BoolVal, Context, Not, Or, simplify

context = Context()

b_x = [Bool(f"x{i}", ctx=context) for i in [0, 1, 2, 3, 4, 5, 6]]
z3_x = [Z3LogicCondition.initialize_symbol(f"x{i}", context) for i in [0, 1, 2, 3, 4, 5, 6, 7, 8]]
true_value = Z3LogicCondition.initialize_true(context)
false_value = Z3LogicCondition.initialize_false(context)

z3_variable = BitVec("|a + 0x5,['eax#3']|", 32, ctx=context)
const_5 = BitVecVal(5, 32, ctx=context)
const10 = BitVecVal(10, 32, ctx=context)
const_20 = BitVecVal(20, 32, ctx=context)
var_l_5 = PseudoZ3LogicCondition(z3_variable < const_5).simplify()
var_le_5 = PseudoZ3LogicCondition(z3_variable <= const_5).simplify()
var_l_20 = PseudoZ3LogicCondition(z3_variable < const_20).simplify()
var_eq_5 = PseudoZ3LogicCondition(z3_variable == const_5).simplify()
var_ule_10 = PseudoZ3LogicCondition(ULE(z3_variable, const10)).simplify()
var_ugt_10 = PseudoZ3LogicCondition(UGT(z3_variable, const10)).simplify()

constant_5 = Constant(5, Integer.int32_t())

var_a = Variable(
    "a", Integer.int32_t(), ssa_label=None, is_aliased=False, ssa_name=Variable("eax", Integer.int32_t(), ssa_label=3, is_aliased=False)
)
var_b = Variable(
    "b", Integer.int32_t(), ssa_label=None, is_aliased=False, ssa_name=Variable("edx", Integer.int32_t(), ssa_label=5, is_aliased=False)
)


def _get_is_instance_test_case(true_val=False, false_val=False, symbol=False, and_f=False, or_f=False, neg_symbol=False):
    return [
        (true_value, true_val),
        (false_value, false_val),
        (z3_x[1].copy(), symbol),
        (z3_x[1].copy() | z3_x[2].copy(), or_f),
        (z3_x[1].copy() & z3_x[2].copy(), and_f),
        (~z3_x[1].copy(), neg_symbol),
    ]


def _get_operation_instances() -> List[Tuple[BoolRef, BoolRef]]:
    return [(b_x[1], b_x[2]), (And(b_x[1], b_x[2]), b_x[3]), (b_x[1], Or(b_x[2], Not(b_x[3])))]


def _get_normal_forms(form):
    terms = [
        ~z3_x[1].copy(),
        (~z3_x[1].copy() | z3_x[2].copy()) & (z3_x[3].copy() | ~z3_x[1].copy()),
        (~z3_x[1].copy() | z3_x[2].copy()) & (z3_x[3].copy() | ~z3_x[1].copy()) & (z3_x[4].copy() | (z3_x[2].copy() & z3_x[3].copy())),
        (z3_x[2].copy() & ~z3_x[1].copy()) | (z3_x[3].copy() & ~z3_x[1].copy()),
        z3_x[1].copy()
        | (z3_x[2].copy() & ~(z3_x[1].copy()))
        | (z3_x[3].copy() & ~(z3_x[1].copy() | z3_x[2].copy()))
        | (z3_x[5].copy() & z3_x[4].copy() & ~z3_x[1].copy()),
        ((z3_x[2].copy() | z3_x[4].copy()) & ~z3_x[1].copy()) | ((z3_x[3].copy() | z3_x[4].copy()) & (z3_x[5].copy() | ~z3_x[1].copy())),
    ]
    if form == "cnf":
        result = [
            ~z3_x[1].copy(),
            (z3_x[2].copy() | ~z3_x[1].copy()) & (z3_x[3].copy() | ~z3_x[1].copy()),
            (z3_x[2].copy() | ~z3_x[1].copy())
            & (z3_x[3].copy() | ~z3_x[1].copy())
            & (z3_x[2].copy() | z3_x[4].copy())
            & (z3_x[3].copy() | z3_x[4].copy()),
            (z3_x[2].copy() | z3_x[3].copy()) & ~z3_x[1].copy(),
            (z3_x[1].copy() | z3_x[2].copy() | z3_x[3].copy() | z3_x[5].copy())
            & (z3_x[1].copy() | z3_x[4].copy() | z3_x[2].copy() | z3_x[3].copy()),
            (z3_x[2].copy() | z3_x[3].copy() | z3_x[4].copy())
            & (~z3_x[1].copy() | z3_x[3].copy() | z3_x[4].copy())
            & (~z3_x[1].copy() | z3_x[5].copy()),
        ]
    elif form == "dnf":
        result = [
            ~z3_x[1].copy(),
            ~z3_x[1].copy() | (z3_x[3].copy() & z3_x[2].copy()),
            (z3_x[3].copy() & z3_x[2].copy()) | (z3_x[4].copy() & ~z3_x[1].copy()),
            (z3_x[2].copy() & ~z3_x[1].copy()) | (z3_x[3].copy() & ~z3_x[1].copy()),
            z3_x[1].copy() | z3_x[2].copy() | z3_x[3].copy() | (z3_x[5].copy() & z3_x[4].copy()),
        ]
    else:
        raise ValueError(f"wrong input")
    return [(term, normal_form) for term, normal_form in zip(terms, result)]


class TestZ3LogicCondition:
    """Test the z3-logic condition."""

    # Part implemented in the ConditionInterface
    @pytest.mark.parametrize(
        "z3_term, length",
        [
            (Z3LogicCondition.initialize_true(context), 0),
            (Z3LogicCondition.initialize_false(context), 0),
            (z3_x[1].copy(), 1),
            (~z3_x[1].copy(), 1),
            (z3_x[1].copy() | z3_x[2].copy(), 2),
            (z3_x[1].copy() & z3_x[2].copy(), 2),
            ((z3_x[1].copy() & z3_x[2].copy()) | z3_x[3].copy(), 3),
            ((z3_x[1].copy() & z3_x[2].copy()) | (z3_x[1].copy() & z3_x[3].copy()), 4),
        ],
    )
    def test_len(self, z3_term, length):
        assert len(z3_term) == length

    @pytest.mark.parametrize(
        "z3_term, result",
        _get_is_instance_test_case(symbol=True, neg_symbol=True) + [(~(z3_x[1].copy() | z3_x[2].copy()), False)],
    )
    def test_is_literal(self, z3_term, result):
        assert z3_term.is_literal == result

    @pytest.mark.parametrize(
        "z3_term, result",
        [
            (z3_x[1].copy(), True),
            (~z3_x[1].copy(), True),
            (z3_x[1].copy() | z3_x[2].copy(), True),
            (~z3_x[1].copy() | z3_x[2].copy(), True),
            ((~z3_x[1].copy() | z3_x[2].copy() | z3_x[3].copy()).simplify(), True),
            (z3_x[1].copy() & z3_x[2].copy(), False),
            ((z3_x[1].copy() | z3_x[2].copy()) & z3_x[3].copy(), False),
            ((z3_x[1].copy() & z3_x[2].copy()) | z3_x[3].copy(), False),
        ],
    )
    def test_is_disjunction_of_literals(self, z3_term, result):
        assert z3_term.is_disjunction_of_literals == result

    @pytest.mark.parametrize(
        "z3_term, result",
        [
            (z3_x[1].copy(), True),
            (~z3_x[1].copy(), True),
            (z3_x[1].copy() | z3_x[2].copy(), True),
            (~z3_x[1].copy() | z3_x[2].copy(), True),
            ((~z3_x[1].copy() | z3_x[2].copy() | z3_x[3].copy()).simplify(), True),
            (z3_x[1].copy() & z3_x[2].copy(), True),
            ((z3_x[1].copy() | z3_x[2].copy()) & z3_x[3].copy(), True),
            ((z3_x[1].copy() | ~z3_x[2].copy()) & ~z3_x[3].copy(), True),
            ((z3_x[1].copy() & z3_x[2].copy()) | z3_x[3].copy(), False),
            (((z3_x[1].copy() & z3_x[2].copy()) | z3_x[3].copy()) & z3_x[4].copy(), False),
        ],
    )
    def test_is_cnf_form(self, z3_term, result):
        assert z3_term.is_cnf_form == result

    @pytest.mark.parametrize(
        "term1, term2, result",
        [
            (
                (z3_x[1].copy() & ~z3_x[1].copy())
                | ~z3_x[2].copy()
                | (z3_x[3].copy() & (z3_x[4].copy() | ~z3_x[4].copy()))
                | ~(z3_x[5].copy() & z3_x[2].copy() & ~z3_x[1].copy())
                | (~(z3_x[5].copy() & ~z3_x[5].copy()) & z3_x[1].copy())
                | ~(z3_x[3].copy() | ~z3_x[3].copy()),
                z3_x[1].copy() | ~z3_x[5].copy() | ~z3_x[2].copy() | z3_x[3].copy(),
                True,
            ),
            (
                z3_x[1].copy()
                | (z3_x[2].copy() & ~z3_x[1].copy())
                | (z3_x[3].copy() & ~(z3_x[1].copy() | z3_x[2].copy()))
                | (z3_x[5].copy() & z3_x[4].copy() & ~z3_x[1].copy()),
                z3_x[1].copy() | z3_x[2].copy() | z3_x[3].copy() | (z3_x[5].copy() & z3_x[4].copy()),
                True,
            ),
            (
                z3_x[1].copy()
                | (z3_x[2].copy() & ~z3_x[1].copy())
                | (z3_x[3].copy() & ~(z3_x[1].copy() | z3_x[2].copy()))
                | (z3_x[5].copy() & z3_x[4].copy() & ~z3_x[1].copy()),
                (z3_x[1].copy() | z3_x[2].copy() | z3_x[3].copy() | z3_x[5].copy())
                & (z3_x[1].copy() | z3_x[4].copy() | z3_x[2].copy() | z3_x[3].copy()),
                True,
            ),
            (z3_x[1].copy() & z3_x[2].copy(), z3_x[1].copy() & z3_x[2].copy() & z3_x[3].copy(), False),
            (z3_x[1].copy() & z3_x[2].copy(), (z3_x[1].copy() & z3_x[2].copy()) | z3_x[1].copy(), False),
        ],
    )
    def test_is_equivalent_to(self, term1, term2, result):
        assert term1.is_equivalent_to(term2) == result

    @pytest.mark.parametrize(
        "term1, term2, result",
        [
            (z3_x[1].copy(), z3_x[1].copy() | z3_x[2].copy(), True),
            (z3_x[1].copy(), z3_x[1].copy() & z3_x[2].copy(), False),
            (
                (z3_x[1].copy() | z3_x[2].copy()) & (~z3_x[1].copy() | z3_x[3].copy()),
                (z3_x[1].copy() & z3_x[3].copy()) | (~z3_x[1].copy() & z3_x[2].copy()) | (z3_x[1].copy() & z3_x[4].copy()),
                True,
            ),
            (
                (z3_x[1].copy() | z3_x[2].copy()) & (~z3_x[1].copy() | z3_x[3].copy()),
                (z3_x[1].copy() & z3_x[3].copy()) | (z3_x[1].copy() & z3_x[2].copy()) | (z3_x[1].copy() & z3_x[4].copy()),
                False,
            ),
        ],
    )
    def test_does_imply(self, term1, term2, result):
        assert term1.does_imply(term2) == result

    @pytest.mark.parametrize(
        "term1, term2, result",
        [
            (true_value, false_value, False),
            (false_value, true_value, False),
            (z3_x[1].copy() & ~z3_x[1].copy(), true_value, False),
            (z3_x[1].copy() | ~z3_x[1].copy(), false_value, False),
            (z3_x[1].copy(), ~z3_x[1].copy(), True),
            (z3_x[1].copy() | z3_x[2].copy(), ~z3_x[1].copy() & ~z3_x[2].copy(), True),
            (z3_x[1].copy() & z3_x[2].copy(), ~(z3_x[1].copy() & z3_x[2].copy()), True),
            (z3_x[1].copy() | z3_x[2].copy(), (~z3_x[1].copy() & ~z3_x[2].copy()) | z3_x[1].copy(), False),
            (z3_x[1].copy() & z3_x[2].copy(), (~z3_x[1].copy() | ~z3_x[2].copy()) & z3_x[1].copy(), False),
        ],
    )
    def test_is_complementary_to(self, term1, term2, result):
        assert term1.is_complementary_to(term2) == result

    # Specific part of Z3ConditionInterface

    @pytest.mark.parametrize(
        "z3_term",
        [
            (BoolVal(True, ctx=context)),
            (BoolVal(False, ctx=context)),
            (b_x[1]),
            (Not(b_x[1])),
            (And(b_x[1], b_x[2])),
            (Or(b_x[1], b_x[2])),
            (And(Or(b_x[1], b_x[2]), b_x[3])),
        ],
    )
    def test_init(self, z3_term):
        cond = Z3LogicCondition(z3_term)
        assert cond._condition == z3_term

    def test_initialize_symbol(self):
        new_context = Context()
        cond = Z3LogicCondition.initialize_symbol("x1", new_context)
        assert cond._condition == Bool("x1", ctx=new_context)

    def test_initialize_true(self):
        new_context = Context()
        cond = Z3LogicCondition.initialize_true(new_context)
        assert cond._condition == BoolVal(True, ctx=new_context)

    def test_initialize_false(self):
        new_context = Context()
        cond = Z3LogicCondition.initialize_false(new_context)
        assert cond._condition == BoolVal(False, ctx=new_context)

    @pytest.mark.parametrize("term1, term2", _get_operation_instances())
    def test_and(self, term1, term2):
        cond = Z3LogicCondition(term1) & Z3LogicCondition(term2)
        assert cond._condition == And(term1, term2)

    @pytest.mark.parametrize("term1, term2", _get_operation_instances())
    def test_or(self, term1, term2):
        cond = Z3LogicCondition(term1) | Z3LogicCondition(term2)
        assert cond._condition == Or(term1, term2)

    @pytest.mark.parametrize("term1, term2", _get_operation_instances())
    def test_negate(self, term1, term2):
        cond = ~Z3LogicCondition(term1)
        assert cond._condition == Not(term1)

    @pytest.mark.parametrize(
        "z3_term, string",
        [
            (BoolVal(True, ctx=context), "true"),
            (BoolVal(False, ctx=context), "false"),
            (
                Or(
                    And(b_x[1]),
                    Not(b_x[2]),
                    And(b_x[3], Or(Not(b_x[4]))),
                    Not(And(b_x[5], b_x[2], Not(b_x[1]))),
                    And(Not(And(b_x[5], Not(b_x[5]))), b_x[1]),
                    Not(Or(b_x[3], Not(b_x[3]))),
                ),
                "(x1 | !x2 | (x3 & !x4) | !(x5 & x2 & !x1) | (!(x5 & !x5) & x1) | !(x3 | !x3))",
            ),
            (
                Or(
                    And(b_x[1], Not(b_x[1])),
                    Not(b_x[2]),
                    And(b_x[3], Or(b_x[4], Not(b_x[4]))),
                    Not(And(b_x[5], b_x[2], Not(b_x[1]))),
                    And(Not(And(b_x[5], Not(b_x[5]))), b_x[1]),
                    Not(Or(b_x[3], Not(b_x[3]))),
                ),
                "((x1 & !x1) | !x2 | (x3 & (x4 | !x4)) | !(x5 & x2 & !x1) | (!(x5 & !x5) & x1) | !(x3 | !x3))",
            ),
        ],
    )
    def test_string(self, z3_term, string):
        cond = Z3LogicCondition(z3_term)
        assert str(cond) == string

    @pytest.mark.parametrize("term, result", _get_is_instance_test_case(true_val=True))
    def test_is_true(self, term, result):
        assert term.is_true == result

    @pytest.mark.parametrize("term, result", _get_is_instance_test_case(false_val=True))
    def test_is_false(self, term, result):
        assert term.is_false == result

    @pytest.mark.parametrize("term, result", _get_is_instance_test_case(or_f=True))
    def test_is_disjunction(self, term, result):
        assert term.is_disjunction == result

    @pytest.mark.parametrize("term, result", _get_is_instance_test_case(and_f=True))
    def test_is_conjunction(self, term, result):
        assert term.is_conjunction == result

    @pytest.mark.parametrize("term, result", _get_is_instance_test_case(neg_symbol=True))
    def test_is_negation(self, term, result):
        assert term.is_negation == result

    @pytest.mark.parametrize(
        "term, operands",
        [
            (true_value, []),
            (false_value, []),
            (z3_x[1].copy(), []),
            (z3_x[1].copy() | z3_x[2].copy(), [z3_x[1].copy(), z3_x[2].copy()]),
            (z3_x[1].copy() & z3_x[2].copy(), [z3_x[1].copy(), z3_x[2].copy()]),
            (~z3_x[1].copy(), [z3_x[1].copy()]),
            ((z3_x[1].copy() | z3_x[2].copy()) & z3_x[3].copy(), [z3_x[1].copy() | z3_x[2].copy(), z3_x[3].copy()]),
        ],
    )
    def test_operands(self, term, operands):
        assert [str(op) for op in term.operands] == [str(op) for op in operands]

    @pytest.mark.parametrize(
        "term, result",
        [
            (BoolVal(True, ctx=context), False),
            (BoolVal(False, ctx=context), False),
            (Not(b_x[1]), False),
            (And(b_x[1], b_x[2]), False),
            (Or(Not(b_x[1]), b_x[1]), False),
            (b_x[1], True),
        ],
    )
    def test_is_symbol(self, term, result):
        """Check whether the object is a symbol."""
        cond = Z3LogicCondition(term)
        assert cond.is_symbol == result

    @pytest.mark.parametrize(
        "term1, term2, result",
        [
            (b_x[1], b_x[2], False),
            (b_x[1], Not(b_x[1]), False),
            (b_x[1], And(b_x[1]), False),
            (b_x[1], Or(b_x[1]), False),
            (BitVecVal(1, 32), BitVecVal(3, 32), False),
            (BitVecVal(2, 32), BitVecVal(2, 32), True),
            (And(b_x[1], b_x[2], b_x[2]), And(b_x[1], b_x[1], b_x[2]), False),
            (And(b_x[1], And(b_x[2], b_x[3])), And(And(b_x[1], b_x[2]), b_x[3]), True),
            (And(b_x[1], b_x[2], b_x[2]), And(b_x[1], b_x[2]), False),
            (And(b_x[1], b_x[2]), And(b_x[1], b_x[1], b_x[2]), False),
            (And(b_x[1], b_x[2]), And(b_x[2], b_x[1]), True),
            (And(b_x[1], Or(b_x[2], b_x[3])), And(Or(b_x[3], b_x[2]), b_x[1]), True),
        ],
    )
    def test_is_equal_to(self, term1, term2, result):
        cond1 = Z3LogicCondition(term1)
        cond2 = Z3LogicCondition(term2)
        assert cond1.is_equal_to(cond2) == result

    @pytest.mark.parametrize(
        "term1, term2, result",
        [
            (b_x[1], Bool(f"x2", ctx=Context()), False),
            (b_x[1], Bool(f"x1", ctx=Context()), True),
            (b_x[1], Not(Bool(f"x1", ctx=Context())), False),
            (BoolVal(True, ctx=context), BoolVal(True, Context()), True),
            (BoolVal(False, ctx=context), BoolVal(False, Context()), True),
            (BoolVal(False, ctx=context), BoolVal(True, Context()), False),
            (
                And(b_x[1], And(b_x[2], b_x[3])),
                And(And(Bool(f"x1", ctx=(new_ctx := Context())), Bool(f"x2", new_ctx)), Bool(f"x3", new_ctx)),
                True,
            ),
            (And(b_x[1], b_x[2]), And(Bool(f"x2", new_ctx := Context()), Bool(f"x1", new_ctx)), True),
            (
                And(b_x[1], Or(b_x[2], b_x[3])),
                And(Or(Bool(f"x3", new_ctx := Context()), Bool(f"x2", new_ctx)), Bool(f"x1", new_ctx)),
                True,
            ),
        ],
    )
    def test_is_equal_to_different_context(self, term1, term2, result):
        cond1 = Z3LogicCondition(term1)
        cond2 = Z3LogicCondition(term2)
        assert cond1.is_equal_to(cond2) == result and cond1.context != cond2.context

    @pytest.mark.parametrize("term, cnf_term", _get_normal_forms("cnf"))
    def test_to_cnf(self, term, cnf_term):
        """Bring condition tag into cnf-form."""
        assert term.to_cnf().is_equal_to(cnf_term)

    @pytest.mark.parametrize("term, dnf_term", _get_normal_forms("dnf"))
    def test_to_dnf(self, term, dnf_term):
        """Bring condition tag into cnf-form."""
        assert term.to_dnf().is_equal_to(dnf_term)

    @pytest.mark.parametrize(
        "term, simplified",
        [
            (
                z3_x[1].copy()
                & ~z3_x[2].copy()
                & (z3_x[3].copy() | ~(z3_x[4].copy() & z3_x[2].copy()))
                & ~(z3_x[5].copy() & z3_x[2].copy() & ~z3_x[1].copy()),
                z3_x[1].copy() & ~z3_x[2].copy(),
            ),
            (
                z3_x[1].copy()
                | (z3_x[2].copy() & ~z3_x[1].copy())
                | (z3_x[3].copy() & ~(z3_x[1].copy() | z3_x[2].copy()))
                | (z3_x[5].copy() & z3_x[4].copy() & ~z3_x[1].copy()),
                z3_x[1].copy() | z3_x[2].copy() | z3_x[3].copy() | (z3_x[5].copy() & z3_x[4].copy()),
            ),
            (
                (z3_x[1].copy() & ~z3_x[1].copy())
                | ~z3_x[2].copy()
                | (z3_x[3].copy() & (z3_x[4].copy() | ~z3_x[4].copy()))
                | ~(z3_x[5].copy() & z3_x[2].copy() & ~z3_x[1].copy())
                | (~(z3_x[5].copy() & ~z3_x[5].copy()) & z3_x[1].copy())
                | ~(z3_x[3].copy() | ~z3_x[3].copy()),
                z3_x[1].copy() | ~z3_x[5].copy() | ~z3_x[2].copy() | z3_x[3].copy(),
            ),
        ],
    )
    def test_simplify(self, term, simplified):
        cond = term.simplify()
        assert cond.is_equal_to(simplified)

    @pytest.mark.parametrize(
        "term, result",
        [
            (true_value, []),
            (false_value, []),
            (z3_x[1].copy(), [z3_x[1].copy()]),
            (~z3_x[1].copy(), [z3_x[1].copy()]),
            (
                z3_x[1].copy()
                & ~z3_x[2].copy()
                & (z3_x[3].copy() | ~(z3_x[4].copy() & z3_x[2].copy()))
                & ~(z3_x[5].copy() & z3_x[2].copy() & ~z3_x[1].copy()),
                [
                    z3_x[1].copy(),
                    z3_x[2].copy(),
                    z3_x[3].copy(),
                    z3_x[4].copy(),
                    z3_x[2].copy(),
                    z3_x[5].copy(),
                    z3_x[2].copy(),
                    z3_x[1].copy(),
                ],
            ),
        ],
    )
    def test_get_symbols(self, term, result):
        assert [str(symbol) for symbol in term.get_symbols()] == [str(symbol) for symbol in result]

    @pytest.mark.parametrize(
        "term, result",
        [
            (true_value, []),
            (false_value, []),
            (z3_x[1].copy(), [z3_x[1].copy()]),
            (~z3_x[1].copy(), [~z3_x[1].copy()]),
            (z3_x[1].copy() | z3_x[2].copy(), [z3_x[1].copy(), z3_x[2].copy()]),
            (~z3_x[1].copy() | z3_x[2].copy(), [~z3_x[1].copy(), z3_x[2].copy()]),
            (z3_x[1].copy() & z3_x[2].copy(), [z3_x[1].copy(), z3_x[2].copy()]),
            (
                z3_x[1].copy()
                & ~z3_x[2].copy()
                & (z3_x[3].copy() | ~(z3_x[4].copy() & z3_x[2].copy()))
                & ~(z3_x[5].copy() & z3_x[2].copy() & ~z3_x[1].copy()),
                [
                    z3_x[1].copy(),
                    ~z3_x[2].copy(),
                    z3_x[3].copy(),
                    z3_x[4].copy(),
                    z3_x[2].copy(),
                    z3_x[5].copy(),
                    z3_x[2].copy(),
                    ~z3_x[1].copy(),
                ],
            ),
        ],
    )
    def test_get_literals(self, term, result):
        assert [str(literal) for literal in term.get_literals()] == [str(literal) for literal in result]

    def test_get_literals_error(self):
        term = Z3LogicCondition(Or(And(b_x[1], BitVec("a", 32, context) < const_5), b_x[3]))
        with pytest.raises(AssertionError):
            list(term.get_literals())

    @pytest.mark.parametrize(
        "term, condition, result",
        [
            (true_value, z3_x[2].copy(), true_value),
            (false_value, z3_x[2].copy(), false_value),
            (z3_x[2].copy(), z3_x[2].copy(), true_value),
            (z3_x[2].copy(), z3_x[3].copy(), z3_x[2].copy()),
            (z3_x[1].copy() | z3_x[2].copy(), z3_x[2].copy(), true_value),
        ],
    )
    def test_substitute_by_true_basics(self, term, condition, result):
        assert term.substitute_by_true(condition) == result

    @pytest.mark.parametrize(
        "condition, result",
        [
            (
                (z3_x[1].copy() | z3_x[2].copy() | z3_x[3].copy()) & (z3_x[4].copy() | z3_x[5].copy()) & z3_x[6].copy() & z3_x[7].copy(),
                true_value,
            ),
            (z3_x[6].copy(), (z3_x[1].copy() | z3_x[2].copy() | z3_x[3].copy()) & (z3_x[4].copy() | z3_x[5].copy()) & z3_x[7].copy()),
            (z3_x[4].copy() | z3_x[5].copy(), (z3_x[1].copy() | z3_x[2].copy() | z3_x[3].copy()) & z3_x[6].copy() & z3_x[7].copy()),
            (z3_x[6].copy() & (z3_x[4].copy() | z3_x[5].copy()), (z3_x[1].copy() | z3_x[2].copy() | z3_x[3].copy()) & z3_x[7].copy()),
            (z3_x[6].copy() & z3_x[7].copy(), (z3_x[1].copy() | z3_x[2].copy() | z3_x[3].copy()) & (z3_x[4].copy() | z3_x[5].copy())),
            (
                z3_x[1].copy() | z3_x[2].copy(),
                (z3_x[1].copy() | z3_x[2].copy() | z3_x[3].copy()) & (z3_x[4].copy() | z3_x[5].copy()) & z3_x[6].copy() & z3_x[7].copy(),
            ),
            (
                (z3_x[1].copy() | z3_x[2].copy() | z3_x[3].copy())
                & (z3_x[4].copy() | z3_x[5].copy())
                & z3_x[6].copy()
                & z3_x[7].copy()
                & z3_x[8].copy(),
                true_value,
            ),
        ],
    )
    def test_substitute_by_true(self, condition, result):
        term = (z3_x[1].copy() | z3_x[2].copy() | z3_x[3].copy()) & (z3_x[4].copy() | z3_x[5].copy()) & z3_x[6].copy() & z3_x[7].copy()
        term.substitute_by_true(condition)
        assert term.simplify() == result.simplify()

    @pytest.mark.parametrize(
        "term, condition_map, result",
        [
            (z3_x[1].copy() & z3_x[2].copy(), {z3_x[1].copy(): var_eq_5, z3_x[2].copy(): var_ule_10}, z3_x[1].copy()),
            (z3_x[1].copy() & z3_x[2].copy(), {z3_x[1].copy(): var_l_5, z3_x[2].copy(): var_ule_10}, z3_x[1].copy() & z3_x[2].copy()),
            (z3_x[1].copy() & z3_x[2].copy(), {z3_x[1].copy(): var_l_20, z3_x[2].copy(): var_ule_10}, z3_x[2].copy()),
            (z3_x[1].copy() & ~z3_x[2].copy(), {z3_x[1].copy(): var_l_20, z3_x[2].copy(): var_ugt_10}, ~z3_x[2].copy()),
        ],
    )
    def test_remove_redundancy(self, term, condition_map, result):
        assert term.remove_redundancy(condition_map) == result

    @pytest.mark.parametrize(
        "term, bound1, bound2,  result",
        [
            (And(b_x[1], b_x[2], b_x[3], b_x[4]), 3, 10, True),
            (
                Or(b_x[1], And(b_x[2], Not(b_x[1])), And(b_x[3], Not(Or(b_x[1], b_x[2]))), And(And(b_x[5], b_x[4], Not(b_x[1])))),
                5,
                10,
                True,
            ),
            (
                Or(b_x[1], And(b_x[2], Not(b_x[1])), And(b_x[3], Not(Or(b_x[1], b_x[2]))), And(And(b_x[5], b_x[4], Not(b_x[1])))),
                6,
                10,
                False,
            ),
            (
                Or(b_x[1], And(b_x[2], Not(b_x[1])), And(b_x[3], Not(Or(b_x[1], b_x[2]))), And(And(b_x[5], b_x[4], Not(b_x[1])))),
                6,
                8,
                True,
            ),
            (
                Or(b_x[1], And(b_x[2], Not(b_x[1])), And(b_x[3], Not(Or(b_x[1], b_x[2]))), And(And(b_x[5], b_x[4], Not(b_x[1])))),
                6,
                9,
                False,
            ),
        ],
    )
    def test_too_large_to_simplify(self, term, bound1, bound2, result):
        assert Z3Implementation(True, bound1, bound2)._too_large_to_fully_simplify(term) == result

    @pytest.mark.parametrize(
        "term, new_term",
        [
            (b_x[1], b_x[1]),
            (BoolVal(True, ctx=context), BoolVal(True, ctx=context)),
            (BoolVal(False, ctx=context), BoolVal(False, ctx=context)),
            (
                Not(
                    And(
                        BitVec("a", 32, context) < BitVecVal(4, 32, context),
                        Or(BitVec("a", 32, context) > const10, Not(BitVec("a", 32, context) == const_20)),
                    )
                ),
                Or(
                    Not(BitVec("a", 32, context) < BitVecVal(4, 32, context)),
                    And(Not(BitVec("a", 32, context) > const10), BitVec("a", 32, context) == const_20),
                ),
            ),
            (Not(And(b_x[1], b_x[2], Not(b_x[3]))), Or(Not(b_x[1]), Not(b_x[2]), b_x[3])),
            (Not(Or(b_x[1], b_x[2], Not(b_x[3]))), And(Not(b_x[1]), Not(b_x[2]), b_x[3])),
            (Not(Not(And(b_x[1], b_x[2], Not(b_x[3])))), And(b_x[1], b_x[2], Not(b_x[3]))),
            (
                And(
                    b_x[1],
                    Not(b_x[2]),
                    Or(b_x[3], Not(And(b_x[4], b_x[2]))),
                    Not(And(b_x[5], b_x[2], Not(b_x[1]))),
                ),
                And(
                    b_x[1],
                    Not(b_x[2]),
                    Or(b_x[3], Or(Not(b_x[4]), Not(b_x[2]))),
                    Or(Not(b_x[5]), Not(b_x[2]), b_x[1]),
                ),
            ),
            (
                Or(
                    And(BoolVal(False, ctx=context)),
                    Not(b_x[2]),
                    And(b_x[3], BoolVal(True, ctx=context)),
                    Not(And(b_x[5], b_x[2], Not(b_x[1]))),
                    And(Not(BoolVal(False, ctx=context)), b_x[1]),
                    Not(BoolVal(True, ctx=context)),
                ),
                Or(
                    And(BoolVal(False, ctx=context)),
                    Not(b_x[2]),
                    And(b_x[3], BoolVal(True, ctx=context)),
                    Or(Not(b_x[5]), Not(b_x[2]), b_x[1]),
                    And(BoolVal(True, ctx=context), b_x[1]),
                    BoolVal(False, ctx=context),
                ),
            ),
        ],
    )
    def test_resolve_negation(self, term, new_term):
        assert Z3Implementation(True)._resolve_negation(term) == new_term

    @pytest.mark.parametrize(
        "term, result",
        [
            (
                Z3LogicCondition(
                    Or(
                        And(b_x[1]),
                        Not(b_x[2]),
                        And(b_x[3], Or(Not(b_x[4]))),
                        Not(And(b_x[5], b_x[2], Not(b_x[1]))),
                        And(Not(And(b_x[5], Not(b_x[5]))), b_x[1]),
                        Not(Or(b_x[3], Not(b_x[3]))),
                    )
                ),
                "(a < 0x1 | b == 0x2 | (c <= 0x3 & d <= 0x4) | !(e >= 0x5 & b != 0x2 & a >= 0x1) | (!(e >= 0x5 & e < 0x5) & a < 0x1) | "
                "!(c <= 0x3 | c > 0x3))",
            ),
            (
                Z3LogicCondition(
                    Or(
                        And(b_x[1], Not(b_x[1])),
                        Not(b_x[2]),
                        And(b_x[3], Or(b_x[4], Not(b_x[4]))),
                        Not(And(b_x[5], b_x[2], Not(b_x[1]))),
                        And(Not(And(b_x[5], Not(b_x[5]))), b_x[1]),
                        Not(Or(b_x[3], Not(b_x[3]))),
                    )
                ),
                "((a < 0x1 & a >= 0x1) | b == 0x2 | (c <= 0x3 & (d > 0x4 | d <= 0x4)) | !(e >= 0x5 & b != 0x2 & a >= 0x1) | "
                "(!(e >= 0x5 & e < 0x5) & a < 0x1) | !(c <= 0x3 | c > 0x3))",
            ),
        ],
    )
    def test_rich_string_representation(self, term, result):
        condition_map = {
            z3_x[1].copy(): Condition(OperationType.less, [Variable("a"), Constant(1)]),
            z3_x[2].copy(): Condition(OperationType.not_equal, [Variable("b"), Constant(2)]),
            z3_x[3].copy(): Condition(OperationType.less_or_equal, [Variable("c"), Constant(3)]),
            z3_x[4].copy(): Condition(OperationType.greater, [Variable("d"), Constant(4)]),
            z3_x[5].copy(): Condition(OperationType.greater_or_equal, [Variable("e"), Constant(5)]),
        }
        assert term.rich_string_representation(condition_map) == result


class TestPseudoZ3LogicCondition:
    @pytest.mark.parametrize(
        "condition, result",
        [
            (Condition(OperationType.equal, [var_a, constant_5]), "5 == a,eax#3"),
            (
                Condition(OperationType.less_or_equal, [BinaryOperation(OperationType.plus, [var_a, constant_5]), constant_5]),
                "5 >= a + 0x5,['eax#3']",
            ),
            (
                Condition(OperationType.greater_or_equal_us, [BinaryOperation(OperationType.plus, [var_a, var_b]), constant_5]),
                "UGE(a + b,['eax#3', 'edx#5'], 5)",
            ),
        ],
    )
    def test_initialize_from_condition(self, condition, result):
        new_context = Context()
        cond = PseudoZ3LogicCondition.initialize_from_condition(condition, new_context)
        assert str(cond) == result and cond.context == new_context

    def test_initialize_from_formula(self):
        pass

    @pytest.mark.parametrize(
        "term, result",
        [
            (PseudoZ3LogicCondition(Not(ULE(z3_variable, const_5))), PseudoZ3LogicCondition(Not(simplify(ULE(z3_variable, const_5))))),
            (
                PseudoZ3LogicCondition(And(b_x[1], Or(b_x[3], Not(And(b_x[4], b_x[2]))), Not(And(b_x[5], b_x[2], Not(b_x[1]))))),
                PseudoZ3LogicCondition(And(b_x[1], Or(b_x[3], Not(And(b_x[4], b_x[2]))))),
            ),
        ],
    )
    def test_simplify(self, term, result):
        assert term.simplify() == result

    @pytest.mark.parametrize(
        "expression, result",
        [
            (constant_5, "5"),
            (var_a, "a,eax#3"),
            (BinaryOperation(OperationType.plus, [var_a, constant_5]), "a + 0x5,['eax#3']"),
            (BinaryOperation(OperationType.plus, [var_a, var_b]), "a + b,['eax#3', 'edx#5']"),
        ],
    )
    def test_convert_expression(self, expression, result):
        z3_expression = Z3Implementation(False).convert_expression(expression)
        z3_expression_5 = Z3Implementation(False).convert_expression(expression, 5)
        assert str(z3_expression) == result and z3_expression.size() == 32
        assert str(z3_expression_5) == result and z3_expression_5.size() == 5
