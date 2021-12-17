import pytest
from dewolf.structures.logic.logic_condition import generate_logic_condition_class, generate_pseudo_logic_condition_class
from dewolf.structures.logic.z3_logic import PseudoZ3LogicCondition, Z3LogicCondition
from dewolf.structures.pseudo import BinaryOperation, Condition, Constant, Integer, OperationType, Variable
from z3 import UGT, ULE, And, BitVec, BitVecVal, Bool, BoolVal, Not, Or

LogicCondition = generate_logic_condition_class(Z3LogicCondition)
PseudoLogicCondition = generate_pseudo_logic_condition_class(PseudoZ3LogicCondition)
context = LogicCondition.generate_new_context()
z3_symbol = [Bool(f"x{i}", ctx=context) for i in [0, 1, 2, 3, 4, 5, 6]]
logic_x = [LogicCondition.initialize_symbol(f"x{i}", context) for i in [0, 1, 2, 3, 4, 5, 6, 7, 8]]

z3_variable = BitVec("|a + 0x5,['eax#3']|", 32, ctx=context)
var_l_5 = PseudoLogicCondition(z3_variable < BitVecVal(5, 32, ctx=context)).simplify()
var_l_20 = PseudoLogicCondition(z3_variable < BitVecVal(20, 32, ctx=context)).simplify()
var_eq_5 = PseudoLogicCondition(z3_variable == BitVecVal(5, 32, ctx=context)).simplify()
var_ule_10 = PseudoLogicCondition(ULE(z3_variable, BitVecVal(10, 32, ctx=context))).simplify()
var_ugt_10 = PseudoLogicCondition(UGT(z3_variable, BitVecVal(10, 32, ctx=context))).simplify()

constant_5 = Constant(5, Integer.int32_t())

var_a = Variable(
    "a", Integer.int32_t(), ssa_label=None, is_aliased=False, ssa_name=Variable("eax", Integer.int32_t(), ssa_label=3, is_aliased=False)
)
var_b = Variable(
    "b", Integer.int32_t(), ssa_label=None, is_aliased=False, ssa_name=Variable("edx", Integer.int32_t(), ssa_label=5, is_aliased=False)
)


def _get_is_instance_test_case(true_value=False, false_value=False, symbol=False, and_f=False, or_f=False, neg_symbol=False):
    return [
        (LogicCondition.initialize_true(LogicCondition.generate_new_context()), true_value),
        (LogicCondition.initialize_false(LogicCondition.generate_new_context()), false_value),
        (logic_x[1].copy(), symbol),
        (logic_x[1].copy() | logic_x[2].copy(), or_f),
        (logic_x[1].copy() & logic_x[2].copy(), and_f),
        (~logic_x[1].copy(), neg_symbol),
    ]


def _get_normal_forms(form):
    terms = [
        ~logic_x[1].copy(),
        (~logic_x[1].copy() | logic_x[2].copy()) & (logic_x[3].copy() | ~logic_x[1].copy()),
        (~logic_x[1].copy() | logic_x[2].copy())
        & (logic_x[3].copy() | ~logic_x[1].copy())
        & (logic_x[4].copy() | (logic_x[2].copy() & logic_x[3].copy())),
        (logic_x[2].copy() & ~logic_x[1].copy()) | (logic_x[3].copy() & ~logic_x[1].copy()),
        logic_x[1].copy()
        | (logic_x[2].copy() & ~(logic_x[1].copy()))
        | (logic_x[3].copy() & ~(logic_x[1].copy() | logic_x[2].copy()))
        | (logic_x[5].copy() & logic_x[4].copy() & ~logic_x[1].copy()),
        ((logic_x[2].copy() | logic_x[4].copy()) & ~logic_x[1].copy())
        | ((logic_x[3].copy() | logic_x[4].copy()) & (logic_x[5].copy() | ~logic_x[1].copy())),
    ]
    if form == "cnf":
        result = [
            ~logic_x[1].copy(),
            (logic_x[2].copy() | ~logic_x[1].copy()) & (logic_x[3].copy() | ~logic_x[1].copy()),
            (logic_x[2].copy() | ~logic_x[1].copy())
            & (logic_x[3].copy() | ~logic_x[1].copy())
            & (logic_x[2].copy() | logic_x[4].copy())
            & (logic_x[4].copy() | logic_x[3].copy()),
            (logic_x[2].copy() | logic_x[3].copy()) & ~logic_x[1].copy(),
            (logic_x[1].copy() | logic_x[2].copy() | logic_x[3].copy() | logic_x[5].copy())
            & (logic_x[1].copy() | logic_x[4].copy() | logic_x[2].copy() | logic_x[3].copy()),
            (logic_x[2].copy() | logic_x[3].copy() | logic_x[4].copy())
            & (~logic_x[1].copy() | logic_x[3].copy() | logic_x[4].copy())
            & (~logic_x[1].copy() | logic_x[5].copy()),
        ]
    elif form == "dnf":
        result = [
            Not(z3_symbol[1]),
            Or(Not(z3_symbol[1]), And(z3_symbol[3], z3_symbol[2])),
            Or(And(z3_symbol[3], z3_symbol[2]), And(z3_symbol[4], Not(z3_symbol[1]))),
            Or(And(z3_symbol[2], Not(z3_symbol[1])), And(z3_symbol[3], Not(z3_symbol[1]))),
            Or(z3_symbol[1], z3_symbol[2], z3_symbol[3], And(z3_symbol[5], z3_symbol[4])),
        ]
    else:
        raise ValueError(f"wrong input")
    return [(term, normal_form) for term, normal_form in zip(terms, result)]


class TestLogicConditionZ3:
    """All function that defined in the interface, are tested using Z3ConditionInterface."""

    def test_init_basic(self):
        """Test that init works."""
        new_member = LogicCondition(Bool("x1"))
        assert str(new_member) == "x1" and isinstance(new_member, LogicCondition)

    def test_init(self):
        """Test that init brings to cnf."""
        new_member = LogicCondition(Or(z3_symbol[1], And(z3_symbol[2], z3_symbol[3])))
        assert str(new_member) == "((x1 | x2) & (x1 | x3))" and isinstance(new_member, LogicCondition)

    def test_initialize_true(self):
        """Test true initialization"""
        true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
        assert true_value.is_true and isinstance(true_value, LogicCondition)

    def test_initialize_false(self):
        """Test false initialization"""
        false_value = LogicCondition.initialize_false(LogicCondition.generate_new_context())
        assert false_value.is_false and isinstance(false_value, LogicCondition)

    def test_initialize_symbol(self):
        """Test symbol initialization"""
        symbol = LogicCondition.initialize_symbol("x1", LogicCondition.generate_new_context())
        assert str(symbol) == "x1" and isinstance(symbol, LogicCondition)

    def test_and(self):
        """Test and method."""
        new_term = LogicCondition(And(z3_symbol[1], z3_symbol[2])) & LogicCondition(And(z3_symbol[2], z3_symbol[3]))
        assert str(new_term) == "(x1 & x2 & x3)" and isinstance(new_term, LogicCondition)

    def test_iand(self):
        """Test iand method."""
        term = LogicCondition(z3_symbol[1]) & LogicCondition(z3_symbol[2])
        term &= LogicCondition(And(z3_symbol[2], z3_symbol[3]))
        assert str(term) == "(x1 & x2 & x3)" and isinstance(term, LogicCondition)

    def test_or(self):
        """Test or method."""
        new_term = LogicCondition(And(z3_symbol[1], z3_symbol[2])) | LogicCondition(And(z3_symbol[2], z3_symbol[3]))
        assert str(new_term) == "((x1 | x3) & x2)" and isinstance(new_term, LogicCondition)

    def test_ior(self):
        """Test ior method."""
        term = LogicCondition(And(z3_symbol[1], z3_symbol[2]))
        term |= LogicCondition(And(z3_symbol[2], z3_symbol[3]))
        assert str(term) == "((x1 | x3) & x2)" and isinstance(term, LogicCondition)

    def test_invert(self):
        """negation works"""
        term = ~LogicCondition(And(z3_symbol[1], z3_symbol[2]))
        assert str(term) == "(!x1 | !x2)" and isinstance(term, LogicCondition)

    @pytest.mark.parametrize(
        "z3_term, operands",
        [
            (LogicCondition.initialize_true(LogicCondition.generate_new_context()), []),
            (LogicCondition.initialize_false(LogicCondition.generate_new_context()), []),
            (LogicCondition(z3_symbol[1]), []),
            (
                LogicCondition(z3_symbol[1]) | LogicCondition(z3_symbol[2]),
                [LogicCondition(z3_symbol[1]), LogicCondition(z3_symbol[2])],
            ),
            (
                LogicCondition(z3_symbol[1]) & LogicCondition(z3_symbol[2]),
                [LogicCondition(z3_symbol[1]), LogicCondition(z3_symbol[2])],
            ),
            (~LogicCondition.initialize_symbol("x1", LogicCondition.generate_new_context()), [LogicCondition(z3_symbol[1])]),
            (
                (LogicCondition(z3_symbol[1]) | LogicCondition(z3_symbol[2])) & LogicCondition(z3_symbol[3]),
                [LogicCondition(z3_symbol[1]) | LogicCondition(z3_symbol[2]), LogicCondition(z3_symbol[3])],
            ),
        ],
    )
    def test_operands(self, z3_term, operands):
        assert [str(op) for op in z3_term.operands] == [str(op) for op in operands]

    @pytest.mark.parametrize(
        "term, result",
        _get_is_instance_test_case(true_value=True),
    )
    def test_is_true(self, term, result):
        assert term.is_true == result

    @pytest.mark.parametrize(
        "term, result",
        _get_is_instance_test_case(false_value=True),
    )
    def test_is_false(self, term, result):
        assert term.is_false == result

    @pytest.mark.parametrize(
        "term, result",
        _get_is_instance_test_case(or_f=True),
    )
    def test_is_disjunction(self, term, result):
        assert term.is_disjunction == result

    @pytest.mark.parametrize(
        "term, result",
        _get_is_instance_test_case(and_f=True),
    )
    def test_is_conjunction(self, term, result):
        assert term.is_conjunction == result

    @pytest.mark.parametrize(
        "term, result",
        _get_is_instance_test_case(neg_symbol=True),
    )
    def test_is_negation(self, term, result):
        assert term.is_negation == result

    @pytest.mark.parametrize(
        "term, result",
        _get_is_instance_test_case(symbol=True),
    )
    def test_is_symbol(self, term, result):
        assert term.is_symbol == result

    @pytest.mark.parametrize(
        "term1, term2, result",
        [
            (logic_x[1].copy(), logic_x[2].copy(), False),
            (logic_x[1].copy(), ~logic_x[1].copy(), False),
            (logic_x[1].copy() & logic_x[2].copy(), logic_x[1].copy() & logic_x[2].copy(), True),
            (logic_x[1].copy() & logic_x[2].copy(), logic_x[2].copy(), False),
            (logic_x[1].copy() & logic_x[2].copy(), logic_x[2].copy() & logic_x[1].copy(), True),
            (
                logic_x[1].copy() & (logic_x[2].copy() | logic_x[3].copy()),
                (logic_x[3].copy() | logic_x[2].copy()) & logic_x[1].copy(),
                True,
            ),
        ],
    )
    def test_is_equal_to(self, term1, term2, result):
        assert term1.is_equal_to(term2) == result

    @pytest.mark.parametrize("term, result", _get_normal_forms("cnf"))
    def test_to_cnf(self, term, result):
        """Each term is in cnf-form, so we do not have to do the computation."""
        assert term.is_equal_to(result)

    @pytest.mark.parametrize("term, result", _get_normal_forms("dnf"))
    def test_to_dnf(self, term, result):
        dnf_term = term.to_dnf()
        assert dnf_term.z3.is_equal(dnf_term._condition, result)

    @pytest.mark.parametrize(
        "term, simplified",
        [
            (
                logic_x[1].copy()
                & ~logic_x[2].copy()
                & (logic_x[3].copy() | ~(logic_x[4].copy() & logic_x[2].copy()))
                & ~(logic_x[5].copy() & logic_x[2].copy() & ~logic_x[1].copy()),
                logic_x[1].copy() & ~logic_x[2].copy(),
            ),
            (
                logic_x[1].copy()
                | (logic_x[2].copy() & ~logic_x[1].copy())
                | (logic_x[3].copy() & ~(logic_x[1].copy() | logic_x[2].copy()))
                | (logic_x[5].copy() & logic_x[4].copy() & ~logic_x[1].copy()),
                logic_x[1].copy() | logic_x[2].copy() | logic_x[3].copy() | (logic_x[5].copy() & logic_x[4].copy()),
            ),
            (
                (logic_x[1].copy() & ~logic_x[1].copy())
                | ~logic_x[2].copy()
                | (logic_x[3].copy() & (logic_x[4].copy() | ~logic_x[4].copy()))
                | ~(logic_x[5].copy() & logic_x[2].copy() & ~logic_x[1].copy())
                | (~(logic_x[5].copy() & ~logic_x[5].copy()) & logic_x[1].copy())
                | ~(logic_x[3].copy() | ~logic_x[3].copy()),
                logic_x[1].copy() | ~logic_x[5].copy() | ~logic_x[2].copy() | logic_x[3].copy(),
            ),
        ],
    )
    def test_simplify(self, term, simplified):
        """Each term is simplified, so we do not have to call it."""
        assert term == simplified

    @pytest.mark.parametrize(
        "term, result",
        [
            (LogicCondition.initialize_true(LogicCondition.generate_new_context()), []),
            (LogicCondition.initialize_false(LogicCondition.generate_new_context()), []),
            (logic_x[1].copy(), [logic_x[1].copy()]),
            (~logic_x[1].copy(), [logic_x[1].copy()]),
            (
                logic_x[1].copy() & ~logic_x[2].copy() & (logic_x[3].copy() | ~logic_x[4].copy()) & (logic_x[5].copy() | logic_x[3].copy()),
                [logic_x[1].copy(), logic_x[2].copy(), logic_x[3].copy(), logic_x[4].copy(), logic_x[5].copy(), logic_x[3].copy()],
            ),
        ],
    )
    def test_get_symbols(self, term, result):
        assert set(str(symbol) for symbol in term.get_symbols()) == set(str(symbol) for symbol in result)

    @pytest.mark.parametrize(
        "term, result",
        [
            (LogicCondition.initialize_true(LogicCondition.generate_new_context()), []),
            (LogicCondition.initialize_false(LogicCondition.generate_new_context()), []),
            (logic_x[1].copy(), [logic_x[1].copy()]),
            (~logic_x[1].copy(), [~logic_x[1].copy()]),
            (logic_x[1].copy() | logic_x[2].copy(), [logic_x[1].copy(), logic_x[2].copy()]),
            (~logic_x[1].copy() | logic_x[2].copy(), [~logic_x[1].copy(), logic_x[2].copy()]),
            (logic_x[1].copy() & logic_x[2].copy(), [logic_x[1].copy(), logic_x[2].copy()]),
            (
                logic_x[1].copy()
                & ~logic_x[2].copy()
                & (logic_x[3].copy() | ~logic_x[4].copy())
                & (~logic_x[5].copy() | ~logic_x[3].copy()),
                [logic_x[1].copy(), ~logic_x[2].copy(), logic_x[3].copy(), ~logic_x[4].copy(), ~logic_x[5].copy(), ~logic_x[3].copy()],
            ),
        ],
    )
    def test_get_literals(self, term, result):
        assert set(str(literal) for literal in term.get_literals()) == set(str(literal) for literal in result)

    @pytest.mark.parametrize(
        "term, condition, result",
        [
            (
                LogicCondition.initialize_true(context),
                logic_x[2].copy(),
                LogicCondition.initialize_true(context),
            ),
            (
                LogicCondition.initialize_false(context),
                logic_x[2].copy(),
                LogicCondition.initialize_false(context),
            ),
            (logic_x[2].copy(), logic_x[2].copy(), LogicCondition.initialize_true(context)),
            (logic_x[2].copy(), logic_x[3].copy(), logic_x[2].copy()),
        ],
    )
    def test_substitute_by_true_basics(self, term, condition, result):
        assert term.substitute_by_true(condition) == result

    @pytest.mark.parametrize(
        "condition, result",
        [
            (
                (logic_x[1].copy() | logic_x[2].copy() | logic_x[3].copy())
                & (logic_x[4].copy() | logic_x[5].copy())
                & logic_x[6].copy()
                & logic_x[7].copy(),
                LogicCondition.initialize_true(LogicCondition.generate_new_context()),
            ),
            (
                logic_x[6].copy(),
                (logic_x[1].copy() | logic_x[2].copy() | logic_x[3].copy()) & (logic_x[4].copy() | logic_x[5].copy()) & logic_x[7].copy(),
            ),
            (
                logic_x[4].copy() | logic_x[5].copy(),
                (logic_x[1].copy() | logic_x[2].copy() | logic_x[3].copy()) & logic_x[6].copy() & logic_x[7].copy(),
            ),
            (
                logic_x[6].copy() & (logic_x[4].copy() | logic_x[5].copy()),
                (logic_x[1].copy() | logic_x[2].copy() | logic_x[3].copy()) & logic_x[7].copy(),
            ),
            (
                logic_x[6].copy() & logic_x[7].copy(),
                (logic_x[1].copy() | logic_x[2].copy() | logic_x[3].copy()) & (logic_x[4].copy() | logic_x[5].copy()),
            ),
            (
                logic_x[1].copy() | logic_x[2].copy(),
                (logic_x[1].copy() | logic_x[2].copy() | logic_x[3].copy())
                & (logic_x[4].copy() | logic_x[5].copy())
                & logic_x[6].copy()
                & logic_x[7].copy(),
            ),
            (
                (logic_x[1].copy() | logic_x[2].copy() | logic_x[3].copy())
                & (logic_x[4].copy() | logic_x[5].copy())
                & logic_x[6].copy()
                & logic_x[7].copy()
                & logic_x[8].copy(),
                (logic_x[1].copy() | logic_x[2].copy() | logic_x[3].copy())
                & (logic_x[4].copy() | logic_x[5].copy())
                & logic_x[6].copy()
                & logic_x[7].copy(),
            ),
        ],
    )
    def test_substitute_by_true(self, condition, result):
        term = (
            (logic_x[1].copy() | logic_x[2].copy() | logic_x[3].copy())
            & (logic_x[4].copy() | logic_x[5].copy())
            & logic_x[6].copy()
            & logic_x[7].copy()
        )
        term.substitute_by_true(condition)
        assert term == result

    @pytest.mark.parametrize(
        "term, condition_map, result",
        [
            (logic_x[1].copy() & logic_x[2].copy(), {logic_x[1].copy(): var_eq_5, logic_x[2].copy(): var_ule_10}, logic_x[1].copy()),
            (
                logic_x[1].copy() & logic_x[2].copy(),
                {logic_x[1].copy(): var_l_5, logic_x[2].copy(): var_ule_10},
                logic_x[1].copy() & logic_x[2].copy(),
            ),
            (logic_x[1].copy() & logic_x[2].copy(), {logic_x[1].copy(): var_l_20, logic_x[2].copy(): var_ule_10}, logic_x[2].copy()),
            (logic_x[1].copy() & ~logic_x[2].copy(), {logic_x[1].copy(): var_l_20, logic_x[2].copy(): var_ugt_10}, ~logic_x[2].copy()),
        ],
    )
    def test_remove_redundancy(self, term, condition_map, result):
        term.remove_redundancy(condition_map)
        assert term == result

    @pytest.mark.parametrize(
        "term, bound, result",
        [
            (LogicCondition.initialize_true(LogicCondition.generate_new_context()), 100, BoolVal(True)),
            (LogicCondition.initialize_false(LogicCondition.generate_new_context()), 100, BoolVal(False)),
            (
                (~logic_x[1].copy() | logic_x[2].copy())
                & (logic_x[3].copy() | ~logic_x[1].copy())
                & (logic_x[4].copy() | (logic_x[2].copy() & logic_x[3].copy())),
                100,
                Or(And(z3_symbol[3], z3_symbol[2]), And(z3_symbol[4], Not(z3_symbol[1]))),
            ),
            (
                (logic_x[2].copy() & ~logic_x[1].copy()) | (logic_x[3].copy() & ~logic_x[1].copy()),
                100,
                And(Or(z3_symbol[2], z3_symbol[3]), Not(z3_symbol[1])),
            ),
            (
                logic_x[1].copy()
                | (logic_x[2].copy() & ~logic_x[1].copy())
                | (logic_x[3].copy() & ~(logic_x[1].copy() | logic_x[2].copy()))
                | (logic_x[5].copy() & logic_x[4].copy() & ~logic_x[1].copy()),
                100,
                Or(z3_symbol[1], z3_symbol[2], z3_symbol[3], And(z3_symbol[5], z3_symbol[4])),
            ),
            (
                (~logic_x[1].copy() | logic_x[2].copy())
                & (logic_x[3].copy() | ~logic_x[1].copy())
                & (logic_x[4].copy() | (logic_x[2].copy() & logic_x[3].copy())),
                5,
                And(
                    Or(Not(z3_symbol[1]), z3_symbol[2]),
                    Or(z3_symbol[3], Not(z3_symbol[1])),
                    Or(z3_symbol[4], z3_symbol[2]),
                    Or(z3_symbol[4], z3_symbol[3]),
                ),
            ),
        ],
    )
    def test_simplify_to_shortest(self, term, bound, result):

        assert term.z3.is_equal(term.simplify_to_shortest(bound)._condition, result)

    @pytest.mark.parametrize(
        "term, result",
        [
            (
                logic_x[1].copy()
                & ~logic_x[2].copy()
                & (logic_x[3].copy() | ~logic_x[4].copy())
                & (logic_x[5].copy() | ~logic_x[3].copy()),
                "(a < 0x1 & b == 0x2 & (c <= 0x3 | d <= 0x4) & (e >= 0x5 | c > 0x3))",
            ),
            (
                (logic_x[1].copy() | ~logic_x[2].copy())
                & (logic_x[2].copy() | logic_x[5].copy())
                & (logic_x[2].copy() | ~logic_x[4].copy())
                & logic_x[3].copy(),
                "((a < 0x1 | b == 0x2) & (b != 0x2 | e >= 0x5) & (b != 0x2 | d <= 0x4) & c <= 0x3)",
            ),
        ],
    )
    def test_rich_string_representation(self, term, result):
        condition_map = {
            logic_x[1].copy(): Condition(OperationType.less, [Variable("a"), Constant(1)]),
            logic_x[2].copy(): Condition(OperationType.not_equal, [Variable("b"), Constant(2)]),
            logic_x[3].copy(): Condition(OperationType.less_or_equal, [Variable("c"), Constant(3)]),
            logic_x[4].copy(): Condition(OperationType.greater, [Variable("d"), Constant(4)]),
            logic_x[5].copy(): Condition(OperationType.greater_or_equal, [Variable("e"), Constant(5)]),
        }
        assert term.rich_string_representation(condition_map) == result


class TestPseudoLogicCondition:
    @pytest.mark.parametrize(
        "condition, result",
        [
            (Condition(OperationType.equal, [var_a, constant_5]), "a,eax#3 == 5"),
            (
                Condition(OperationType.less_or_equal, [BinaryOperation(OperationType.plus, [var_a, constant_5]), constant_5]),
                "a + 0x5,['eax#3'] <= 5",
            ),
            (
                Condition(OperationType.greater_or_equal_us, [BinaryOperation(OperationType.plus, [var_a, var_b]), constant_5]),
                "ULE(5, a + b,['eax#3', 'edx#5'])",
            ),
        ],
    )
    def test_initialize_from_condition(self, condition, result):
        cond = PseudoLogicCondition.initialize_from_condition(condition, LogicCondition.generate_new_context())
        assert str(cond) == result and isinstance(cond, PseudoLogicCondition)

    def test_initialize_from_formula(self):
        pass

    @pytest.mark.parametrize(
        "term, result, string",
        [
            (
                PseudoLogicCondition(Not(ULE(z3_variable, BitVecVal(5, 32, context)))),
                PseudoLogicCondition(Not(ULE(z3_variable, BitVecVal(5, 32, context)))),
                "!(Extract(31, 3, |a + 0x5,['eax#3']|) == 0 & ULE(Extract(2, 0, |a + 0x5,['eax#3']|), 5))",
            ),
            (
                PseudoLogicCondition(
                    And(
                        z3_symbol[1],
                        Or(z3_symbol[3], Not(And(z3_symbol[4], z3_symbol[2]))),
                        Not(And(z3_symbol[5], z3_symbol[2], Not(z3_symbol[1]))),
                    )
                ),
                PseudoLogicCondition(z3_symbol[1])
                & (PseudoLogicCondition(z3_symbol[3]) | ~(PseudoLogicCondition(z3_symbol[4]) & PseudoLogicCondition(z3_symbol[2]))),
                "(x1 & (x3 | !(x4 & x2)))",
            ),
        ],
    )
    def test_simplify(self, term, result, string):
        assert term == result and str(term) == string and isinstance(term, PseudoLogicCondition)
