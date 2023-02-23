from typing import List, Tuple

import pytest
from decompiler.structures.ast.condition_symbol import ConditionHandler, ConditionSymbol
from decompiler.structures.logic.custom_logic import CustomLogicCondition, PseudoCustomLogicCondition
from decompiler.structures.pseudo import BinaryOperation, Condition, Constant, Integer, OperationType, Variable
from simplifier.world.nodes import TmpVariable, WorldObject
from simplifier.world.world import World


class MockConditionHandler(ConditionHandler):
    def add_condition(self, condition: Condition) -> ConditionSymbol:
        """Adds a condition to the condition map."""
        symbol = self._get_next_symbol()
        z3_condition = PseudoCustomLogicCondition.initialize_from_condition(condition, self._logic_context)
        condition_symbol = ConditionSymbol(condition, symbol, z3_condition)
        self._condition_map[symbol] = condition_symbol
        return condition_symbol

    def _get_next_symbol(self) -> CustomLogicCondition:
        """Get the next unused symbol name."""
        self._symbol_counter += 1
        return CustomLogicCondition.initialize_symbol(f"x{self._symbol_counter}", self._logic_context)


def b_x(i: int, world: World) -> WorldObject:
    return world.variable(f"x{i}", 1)


def custom_x(i: int, world: World) -> CustomLogicCondition:
    return CustomLogicCondition.initialize_symbol(f"x{i}", world)


def true_value(world: World) -> CustomLogicCondition:
    return CustomLogicCondition.initialize_true(world)


def false_value(world: World) -> CustomLogicCondition:
    return CustomLogicCondition.initialize_false(world)


def custom_variable(world: World, name: str = "a + 0x5,['eax#3']", size: int = 32) -> WorldObject:
    return world.variable(name, size)


def custom_constant(world: World, const: int, size=32) -> WorldObject:
    return world.constant(const, size)


def lower(variable: WorldObject, const: int) -> PseudoCustomLogicCondition:
    custom_condition = variable.world.signed_lt(variable, custom_constant(variable.world, const))
    return PseudoCustomLogicCondition(custom_condition)


def lower_eq(variable: WorldObject, const: int) -> PseudoCustomLogicCondition:
    custom_condition = variable.world.signed_lq(variable, custom_constant(variable.world, const))
    return PseudoCustomLogicCondition(custom_condition)


def equal(variable: WorldObject, const: int) -> PseudoCustomLogicCondition:
    custom_condition = variable.world.bool_equal(variable, custom_constant(variable.world, const))
    return PseudoCustomLogicCondition(custom_condition)


def u_lower_eq(variable: WorldObject, const: int) -> PseudoCustomLogicCondition:
    custom_condition = variable.world.unsigned_le(variable, custom_constant(variable.world, const))
    return PseudoCustomLogicCondition(custom_condition)


def u_greater(variable: WorldObject, const: int) -> PseudoCustomLogicCondition:
    custom_condition = variable.world.unsigned_gt(variable, custom_constant(variable.world, const))
    return PseudoCustomLogicCondition(custom_condition)


constant_4 = Constant(4, Integer.int32_t())
constant_5 = Constant(5, Integer.int32_t())
constant_10 = Constant(10, Integer.int32_t())
constant_20 = Constant(20, Integer.int32_t())

var_a = Variable(
    "a", Integer.int32_t(), ssa_label=None, is_aliased=False, ssa_name=Variable("eax", Integer.int32_t(), ssa_label=3, is_aliased=False)
)
var_b = Variable(
    "b", Integer.int32_t(), ssa_label=None, is_aliased=False, ssa_name=Variable("edx", Integer.int32_t(), ssa_label=5, is_aliased=False)
)


def _get_is_instance_test_case(
    world: World, true_val=False, false_val=False, symbol=False, and_f=False, or_f=False, neg_symbol=False
) -> List[Tuple[CustomLogicCondition, bool]]:
    return [
        (true_value(world), true_val),
        (false_value(world), false_val),
        (custom_x(1, world), symbol),
        (custom_x(1, world) | custom_x(2, world), or_f),
        (custom_x(1, world) & custom_x(2, world), and_f),
        (~custom_x(1, world), neg_symbol),
    ]


def _get_operation_instances(world: World) -> List[Tuple[WorldObject, WorldObject]]:
    return [
        (b_x(1, world), b_x(2, world)),
        (world.bitwise_and(b_x(1, world), b_x(2, world)), b_x(3, world)),
        (b_x(1, world), world.bitwise_or(b_x(2, world), world.bitwise_negate(b_x(3, world)))),
    ]


def _get_normal_forms(form):
    init_world = World()
    terms = [
        ~custom_x(1, init_world),
        (~custom_x(1, init_world) | custom_x(2, init_world)) & (custom_x(3, init_world) | ~custom_x(1, init_world)),
        (~custom_x(1, init_world) | custom_x(2, init_world))
        & (custom_x(3, init_world) | ~custom_x(1, init_world))
        & (custom_x(4, init_world) | (custom_x(2, init_world) & custom_x(3, init_world))),
        (custom_x(2, init_world) & ~custom_x(1, init_world)) | (custom_x(3, init_world) & ~custom_x(1, init_world)),
        custom_x(1, init_world)
        | (custom_x(2, init_world) & ~(custom_x(1, init_world)))
        | (custom_x(3, init_world) & ~(custom_x(1, init_world) | custom_x(2, init_world)))
        | (custom_x(5, init_world) & custom_x(4, init_world) & ~custom_x(1, init_world)),
        ((custom_x(2, init_world) | custom_x(4, init_world)) & ~custom_x(1, init_world))
        | ((custom_x(3, init_world) | custom_x(4, init_world)) & (custom_x(5, init_world) | ~custom_x(1, init_world))),
    ]
    if form == "cnf":
        cnf_world = World()
        result = [
            ~custom_x(1, cnf_world),
            (custom_x(2, cnf_world) | ~custom_x(1, cnf_world)) & (custom_x(3, cnf_world) | ~custom_x(1, cnf_world)),
            CustomLogicCondition.conjunction_of(
                [
                    (custom_x(2, cnf_world) | ~custom_x(1, cnf_world)),
                    (custom_x(3, cnf_world) | ~custom_x(1, cnf_world)),
                    (custom_x(2, cnf_world) | custom_x(4, cnf_world)),
                    (custom_x(3, cnf_world) | custom_x(4, cnf_world)),
                ]
            ),
            (custom_x(2, cnf_world) | custom_x(3, cnf_world)) & ~custom_x(1, cnf_world),
            CustomLogicCondition.disjunction_of(
                [custom_x(1, cnf_world), custom_x(2, cnf_world), custom_x(3, cnf_world), custom_x(5, cnf_world)]
            )
            & CustomLogicCondition.disjunction_of(
                [custom_x(1, cnf_world), custom_x(4, cnf_world), custom_x(2, cnf_world), custom_x(3, cnf_world)]
            ),
            CustomLogicCondition.conjunction_of(
                [
                    CustomLogicCondition.disjunction_of([custom_x(2, cnf_world), custom_x(3, cnf_world), custom_x(4, cnf_world)]),
                    CustomLogicCondition.disjunction_of([~custom_x(1, cnf_world), custom_x(3, cnf_world), custom_x(4, cnf_world)]),
                    ~custom_x(1, cnf_world) | custom_x(5, cnf_world),
                ]
            ),
        ]
    elif form == "dnf":
        dnf_world = World()
        result = [
            ~custom_x(1, dnf_world),
            ~custom_x(1, dnf_world) | (custom_x(3, dnf_world) & custom_x(2, dnf_world)),
            (custom_x(3, dnf_world) & custom_x(2, dnf_world)) | (custom_x(4, dnf_world) & ~custom_x(1, dnf_world)),
            (custom_x(2, dnf_world) & ~custom_x(1, dnf_world)) | (custom_x(3, dnf_world) & ~custom_x(1, dnf_world)),
            CustomLogicCondition.disjunction_of(
                [custom_x(1, dnf_world), custom_x(2, dnf_world), custom_x(3, dnf_world), (custom_x(5, dnf_world) & custom_x(4, dnf_world))]
            ),
            CustomLogicCondition.disjunction_of(
                [
                    custom_x(2, dnf_world) & ~custom_x(1, dnf_world),
                    custom_x(4, dnf_world) & ~custom_x(1, dnf_world),
                    custom_x(3, dnf_world) & ~custom_x(1, dnf_world),
                    custom_x(3, dnf_world) & custom_x(5, dnf_world),
                    custom_x(4, dnf_world) & custom_x(5, dnf_world),
                ]
            ),
        ]
    else:
        raise ValueError(f"wrong input")
    return [(term, normal_form) for term, normal_form in zip(terms, result)]


class TestCustomLogicCondition:
    """Test the z3-logic condition."""

    # Part implemented in the ConditionInterface
    @pytest.mark.parametrize(
        "world, term, length",
        [
            (world := World(), CustomLogicCondition.initialize_true(world), 0),
            (world := World(), CustomLogicCondition.initialize_false(world), 0),
            (world := World(), custom_x(1, world), 1),
            (world := World(), ~custom_x(1, world), 1),
            (world := World(), custom_x(1, world) | custom_x(2, world), 2),
            (world := World(), custom_x(1, world) & custom_x(2, world), 2),
            (world := World(), (custom_x(1, world) & custom_x(2, world)) | custom_x(3, world), 3),
            (world := World(), (custom_x(1, world) & custom_x(2, world)) | (custom_x(1, world) & custom_x(3, world)), 4),
        ],
    )
    def test_len(self, world, term, length):
        assert len(term) == length

    @pytest.mark.parametrize(
        "term, result",
        _get_is_instance_test_case(world := World(), symbol=True, neg_symbol=True) + [(~(custom_x(1, world) | custom_x(2, world)), False)],
    )
    def test_is_literal(self, term: CustomLogicCondition, result: bool):
        assert term.is_literal == result

    @pytest.mark.parametrize(
        "world, term, result",
        [
            (world := World(), custom_x(1, world), True),
            (world := World(), ~custom_x(1, world), True),
            (world := World(), custom_x(1, world) | custom_x(2, world), True),
            (world := World(), ~custom_x(1, world) | custom_x(2, world), True),
            (world := World(), (~custom_x(1, world) | custom_x(2, world) | custom_x(3, world)).simplify(), True),
            (world := World(), custom_x(1, world) & custom_x(2, world), False),
            (world := World(), (custom_x(1, world) | custom_x(2, world)) & custom_x(3, world), False),
            (world := World(), (custom_x(1, world) & custom_x(2, world)) | custom_x(3, world), False),
        ],
    )
    def test_is_disjunction_of_literals(self, world, term, result):
        assert term.is_disjunction_of_literals == result

    @pytest.mark.parametrize(
        "world, term, result",
        [
            (world := World(), custom_x(1, world), True),
            (world := World(), ~custom_x(1, world), True),
            (world := World(), custom_x(1, world) | custom_x(2, world), True),
            (world := World(), ~custom_x(1, world) | custom_x(2, world), True),
            (world := World(), (~custom_x(1, world) | custom_x(2, world) | custom_x(3, world)).simplify(), True),
            (world := World(), custom_x(1, world) & custom_x(2, world), True),
            (world := World(), (custom_x(1, world) | custom_x(2, world)) & custom_x(3, world), True),
            (world := World(), (custom_x(1, world) | ~custom_x(2, world)) & ~custom_x(3, world), True),
            (world := World(), (custom_x(1, world) & custom_x(2, world)) | custom_x(3, world), False),
            (world := World(), ((custom_x(1, world) & custom_x(2, world)) | custom_x(3, world)) & custom_x(4, world), False),
        ],
    )
    def test_is_cnf_form(self, world, term, result):
        assert term.is_cnf_form == result

    @pytest.mark.parametrize(
        "world, term1, term2, result",
        [
            (
                world := World(),
                CustomLogicCondition.disjunction_of(
                    (
                        (custom_x(1, world) & ~custom_x(1, world)),
                        ~custom_x(2, world),
                        (custom_x(3, world) & (custom_x(4, world) | ~custom_x(4, world))),
                        ~(custom_x(5, world) & custom_x(2, world) & ~custom_x(1, world)),
                        (~(custom_x(5, world) & ~custom_x(5, world)) & custom_x(1, world)),
                        ~(custom_x(3, world) | ~custom_x(3, world)),
                    )
                ),
                custom_x(1, world) | ~custom_x(5, world) | ~custom_x(2, world) | custom_x(3, world),
                True,
            ),
            (
                world := World(),
                custom_x(1, world)
                | (custom_x(2, world) & ~custom_x(1, world))
                | (custom_x(3, world) & ~(custom_x(1, world) | custom_x(2, world)))
                | (custom_x(5, world) & custom_x(4, world) & ~custom_x(1, world)),
                custom_x(1, world) | custom_x(2, world) | custom_x(3, world) | (custom_x(5, world) & custom_x(4, world)),
                True,
            ),
            (
                world := World(),
                custom_x(1, world)
                | (custom_x(2, world) & ~custom_x(1, world))
                | (custom_x(3, world) & ~(custom_x(1, world) | custom_x(2, world)))
                | (custom_x(5, world) & custom_x(4, world) & ~custom_x(1, world)),
                (custom_x(1, world) | custom_x(2, world) | custom_x(3, world) | custom_x(5, world))
                & (custom_x(1, world) | custom_x(4, world) | custom_x(2, world) | custom_x(3, world)),
                True,
            ),
            (
                world := World(),
                custom_x(1, world) & custom_x(2, world),
                custom_x(1, world) & custom_x(2, world) & custom_x(3, world),
                False,
            ),
            (
                world := World(),
                custom_x(1, world) & custom_x(2, world),
                (custom_x(1, world) & custom_x(2, world)) | custom_x(1, world),
                False,
            ),
        ],
    )
    def test_is_equivalent_to(self, world, term1, term2, result):
        assert term1.is_equivalent_to(term2) == result

    @pytest.mark.parametrize(
        "world, term1, term2, result",
        [
            (world := World(), custom_x(1, world), custom_x(1, world) | custom_x(2, world), True),
            (world := World(), custom_x(1, world), custom_x(1, world) & custom_x(2, world), False),
            (
                world := World(),
                (custom_x(1, world) | custom_x(2, world)) & (~custom_x(1, world) | custom_x(3, world)),
                (custom_x(1, world) & custom_x(3, world))
                | (~custom_x(1, world) & custom_x(2, world))
                | (custom_x(1, world) & custom_x(4, world)),
                True,
            ),
            (
                world := World(),
                (custom_x(1, world) | custom_x(2, world)) & (~custom_x(1, world) | custom_x(3, world)),
                (custom_x(1, world) & custom_x(3, world))
                | (custom_x(1, world) & custom_x(2, world))
                | (custom_x(1, world) & custom_x(4, world)),
                False,
            ),
        ],
    )
    def test_does_imply(self, world, term1, term2, result):
        assert term1.does_imply(term2) == result

    @pytest.mark.parametrize(
        "world, term1, term2, result",
        [
            (world := World(), true_value(world), false_value(world), False),
            (world := World(), false_value(world), true_value(world), False),
            (world := World(), custom_x(1, world) & ~custom_x(1, world), true_value(world), False),
            (world := World(), custom_x(1, world) | ~custom_x(1, world), false_value(world), False),
            (world := World(), custom_x(1, world), ~custom_x(1, world), True),
            (world := World(), custom_x(1, world) | custom_x(2, world), ~custom_x(1, world) & ~custom_x(2, world), True),
            (world := World(), custom_x(1, world) & custom_x(2, world), ~(custom_x(1, world) & custom_x(2, world)), True),
            (
                world := World(),
                custom_x(1, world) | custom_x(2, world),
                (~custom_x(1, world) & ~custom_x(2, world)) | custom_x(1, world),
                False,
            ),
            (
                world := World(),
                custom_x(1, world) & custom_x(2, world),
                (~custom_x(1, world) | ~custom_x(2, world)) & custom_x(1, world),
                False,
            ),
        ],
    )
    def test_is_complementary_to(self, world, term1, term2, result):
        assert term1.is_complementary_to(term2) == result

    @pytest.mark.parametrize(
        "world, term",
        [
            (world := World(), world.constant(1, 1)),
            (world := World(), world.constant(0, 1)),
            (world := World(), b_x(1, world)),
            (world := World(), world.bitwise_negate(b_x(1, world))),
            (world := World(), world.bitwise_and(b_x(1, world), b_x(2, world))),
            (world := World(), world.bitwise_or(b_x(1, world), b_x(2, world))),
            (world := World(), world.bitwise_and(world.bitwise_or(b_x(1, world), b_x(2, world)), b_x(3, world))),
        ],
    )
    def test_init(self, world, term):
        cond = CustomLogicCondition(term)
        assert cond._condition == term

    def test_initialize_symbol(self):
        world = World()
        cond = CustomLogicCondition.initialize_symbol("x1", world)
        assert cond._condition == World().variable("x1", 1)

    def test_initialize_true(self):
        world = World()
        cond = CustomLogicCondition.initialize_true(world)
        assert cond._condition == World().constant(1, 1)

    def test_initialize_false(self):
        world = World()
        cond = CustomLogicCondition.initialize_false(world)
        assert cond._condition == World().constant(0, 1)

    @pytest.mark.parametrize("term1, term2", _get_operation_instances(world := World()))
    def test_and(self, term1, term2):
        cond = CustomLogicCondition(term1) & CustomLogicCondition(term2)
        assert World.compare(cond._condition, World().bitwise_and(term1, term2))

    @pytest.mark.parametrize("term1, term2", _get_operation_instances(world := World()))
    def test_or(self, term1, term2):
        cond = CustomLogicCondition(term1) | CustomLogicCondition(term2)
        assert World.compare(cond._condition, World().bitwise_or(term1, term2))

    @pytest.mark.parametrize("term1, term2", _get_operation_instances(world := World()))
    def test_negate(self, term1, term2):
        cond = ~CustomLogicCondition(term1)
        assert World.compare(cond._condition, World().bitwise_negate(term1))

    @pytest.mark.parametrize(
        "world, term, string",
        [
            (world := World(), world.constant(1, 1), "true"),
            (world := World(), world.constant(0, 1), "false"),
            (
                world := World(),
                world.bitwise_or(
                    world.bitwise_and(b_x(1, world)),
                    world.bitwise_negate(b_x(2, world)),
                    world.bitwise_and(b_x(3, world), world.bitwise_or(world.bitwise_negate(b_x(4, world)))),
                    world.bitwise_negate(world.bitwise_and(b_x(5, world), b_x(2, world), world.bitwise_negate(b_x(1, world)))),
                    world.bitwise_and(
                        world.bitwise_negate(world.bitwise_and(b_x(5, world), world.bitwise_negate(b_x(5, world)))),
                        b_x(1, world),
                    ),
                    world.bitwise_negate(world.bitwise_or(b_x(3, world), world.bitwise_negate(b_x(3, world)))),
                ),
                "(x1 | ~x2 | (x3 & ~x4) | ~(x5 & x2 & ~x1) | (~(x5 & ~x5) & x1) | ~(x3 | ~x3))",
            ),
            (
                world := World(),
                world.bitwise_or(
                    world.bitwise_and(b_x(1, world), world.bitwise_negate(b_x(1, world))),
                    world.bitwise_negate(b_x(2, world)),
                    world.bitwise_and(b_x(3, world), world.bitwise_or(b_x(4, world), world.bitwise_negate(b_x(4, world)))),
                    world.bitwise_negate(world.bitwise_and(b_x(5, world), b_x(2, world), world.bitwise_negate(b_x(1, world)))),
                    world.bitwise_and(
                        world.bitwise_negate(world.bitwise_and(b_x(5, world), world.bitwise_negate(b_x(5, world)))),
                        b_x(1, world),
                    ),
                    world.bitwise_negate(world.bitwise_or(b_x(3, world), world.bitwise_negate(b_x(3, world)))),
                ),
                "((x1 & ~x1) | ~x2 | (x3 & (x4 | ~x4)) | ~(x5 & x2 & ~x1) | (~(x5 & ~x5) & x1) | ~(x3 | ~x3))",
            ),
        ],
    )
    def test_string(self, world, term, string):
        cond = CustomLogicCondition(term)
        assert str(cond) == string

    @pytest.mark.parametrize("term, result", _get_is_instance_test_case(world=World(), true_val=True))
    def test_is_true(self, term, result):
        assert term.is_true == result

    @pytest.mark.parametrize("term, result", _get_is_instance_test_case(world=World(), false_val=True))
    def test_is_false(self, term, result):
        assert term.is_false == result

    @pytest.mark.parametrize("term, result", _get_is_instance_test_case(world=World(), or_f=True))
    def test_is_disjunction(self, term, result):
        assert term.is_disjunction == result

    @pytest.mark.parametrize("term, result", _get_is_instance_test_case(world=World(), and_f=True))
    def test_is_conjunction(self, term, result):
        assert term.is_conjunction == result

    @pytest.mark.parametrize("term, result", _get_is_instance_test_case(world=World(), neg_symbol=True))
    def test_is_negation(self, term, result):
        assert term.is_negation == result

    @pytest.mark.parametrize(
        "world, term, operands",
        [
            (world := World(), true_value(world), []),
            (world := World(), false_value(world), []),
            (world := World(), custom_x(1, world), []),
            (world := World(), custom_x(1, world) | custom_x(2, world), [custom_x(1, world), custom_x(2, world)]),
            (world := World(), custom_x(1, world) & custom_x(2, world), [custom_x(1, world), custom_x(2, world)]),
            (world := World(), ~custom_x(1, world), [custom_x(1, world)]),
            (
                world := World(),
                (custom_x(1, world) | custom_x(2, world)) & custom_x(3, world),
                [custom_x(1, world) | custom_x(2, world), custom_x(3, world)],
            ),
        ],
    )
    def test_operands(self, world, term, operands):
        assert [str(op) for op in term.operands] == [str(op) for op in operands]

    @pytest.mark.parametrize(
        "world, term, result",
        [
            (world := World(), world.constant(1, 1), False),
            (world := World(), world.constant(0, 1), False),
            (world := World(), world.bitwise_negate(b_x(1, world)), False),
            (world := World(), world.bitwise_and(b_x(1, world), b_x(2, world)), False),
            (world := World(), world.bitwise_or(world.bitwise_negate(b_x(1, world)), b_x(1, world)), False),
            (world := World(), b_x(1, world), True),
        ],
    )
    def test_is_symbol(self, world, term, result):
        """Check whether the object is a symbol."""
        cond = CustomLogicCondition(term)
        assert cond.is_symbol == result

    @pytest.mark.parametrize(
        "term1, term2, result",
        [
            (b_x(1, World()), b_x(2, World()), False),
            (b_x(1, World()), (world := World()).bitwise_negate(b_x(1, world)), False),
            (b_x(1, World()), (world := World()).bitwise_and(b_x(1, world)), False),
            (b_x(1, World()), (world := World()).bitwise_or(b_x(1, world)), False),
            (
                (world := World()).bitwise_and(b_x(1, world), b_x(2, world), b_x(2, world)),
                (world := World()).bitwise_and(b_x(1, world), b_x(1, world), b_x(2, world)),
                False,
            ),
            (
                (world := World()).bitwise_and(b_x(1, world), world.bitwise_and(b_x(2, world), b_x(3, world))),
                (world := World()).bitwise_and(world.bitwise_and(b_x(1, world), b_x(2, world)), b_x(3, world)),
                False,
            ),
            (
                    (world := World()).bitwise_and(b_x(1, world), b_x(2, world), b_x(3, world)),
                    (world := World()).bitwise_and(b_x(1, world), b_x(3, world), b_x(2, world)),
                    True,
            ),
            (
                (world := World()).bitwise_and(b_x(1, world), b_x(2, world), b_x(2, world)),
                (world := World()).bitwise_and(b_x(1, world), b_x(2, world)),
                False,
            ),
            (
                (world := World()).bitwise_and(b_x(1, world), b_x(2, world)),
                (world := World()).bitwise_and(b_x(1, world), b_x(1, world), b_x(2, world)),
                False,
            ),
            (
                (world := World()).bitwise_and(b_x(1, world), b_x(2, world)),
                (world := World()).bitwise_and(b_x(2, world), b_x(1, world)),
                True,
            ),
            (
                (world := World()).bitwise_and(b_x(1, world), world.bitwise_or(b_x(2, world), b_x(3, world))),
                (world := World()).bitwise_and(world.bitwise_or(b_x(3, world), b_x(2, world)), b_x(1, world)),
                True,
            ),
        ],
    )
    def test_is_equal_to(self, term1, term2, result):
        cond1 = CustomLogicCondition(term1)
        cond2 = CustomLogicCondition(term2)
        assert cond1.is_equal_to(cond2) == result

    @pytest.mark.parametrize(
        "term1, term2, result",
        [
            (custom_variable(World(), "x1", 1), custom_variable(World(), "x2", 1), False),
            (custom_variable(World(), "x1", 1), custom_variable(World(), "x1", 1), True),
            (custom_variable(World(), "x1", 1), (world := World()).bitwise_negate(custom_variable(world, "x1", 1)), False),
            (custom_constant(World(), 1, 1), custom_constant(World(), 1, 1), True),
            (custom_constant(World(), 0, 1), custom_constant(World(), 0, 1), True),
            (custom_constant(World(), 0, 1), custom_constant(World(), 1, 1), False),
            (
                (world := World()).bitwise_and(
                    custom_variable(world, "x1"), custom_variable(world, "x2", 1), custom_variable(world, "x3", 1)
                ),
                (world := World()).bitwise_and(
                    custom_variable(world, "x1", 1), custom_variable(world, "x2", 1), custom_variable(world, "x3", 1)
                ),
                True,
            ),
            (
                (world := World()).bitwise_and(custom_variable(world, "x1", 1), custom_variable(world, "x2", 2)),
                (world := World()).bitwise_and(custom_variable(world, "x2", 1), custom_variable(world, "x1", 1)),
                True,
            ),
            (
                (world := World()).bitwise_and(
                    custom_variable(world, "x1", 1), world.bitwise_or(custom_variable(world, "x2", 1), custom_variable(world, "x3", 1))
                ),
                (world := World()).bitwise_and(
                    world.bitwise_or(custom_variable(world, "x3", 1), custom_variable(world, "x2", 1)), custom_variable(world, "x1", 1)
                ),
                True,
            ),
        ],
    )
    def test_is_equal_to_different_context(self, term1, term2, result):
        cond1 = CustomLogicCondition(term1)
        cond2 = CustomLogicCondition(term2)
        assert cond1.is_equal_to(cond2) == result and cond1.context != cond2.context

    @pytest.mark.parametrize("term, cnf_term", _get_normal_forms("cnf"))
    def test_to_cnf(self, term, cnf_term):
        """Bring condition tag into cnf-form."""
        assert term.to_cnf().is_equal_to(cnf_term)

    @pytest.mark.parametrize("term, dnf_term", _get_normal_forms("dnf"))
    def test_to_dnf(self, term, dnf_term):
        """Bring condition tag into cnf-form."""
        input_term = str(term)
        assert term.to_dnf().is_equal_to(dnf_term) and input_term == str(term)

    @pytest.mark.parametrize(
        "term, simplified",
        [
            (
                custom_x(1, world := World())
                & ~custom_x(2, world)
                & (custom_x(3, world) | ~(custom_x(4, world) & custom_x(2, world)))
                & ~(custom_x(5, world) & custom_x(2, world) & ~custom_x(1, world)),
                custom_x(1, world := World()) & ~custom_x(2, world),
            ),
            (
                custom_x(1, world := World())
                | (custom_x(2, world) & ~custom_x(1, world))
                | (custom_x(3, world) & ~(custom_x(1, world) | custom_x(2, world)))
                | (custom_x(5, world) & custom_x(4, world) & ~custom_x(1, world)),
                CustomLogicCondition.disjunction_of(
                    [custom_x(1, world := World()), custom_x(2, world), custom_x(3, world), (custom_x(5, world) & custom_x(4, world))]
                ),
            ),
            (
                (custom_x(1, world := World()) & ~custom_x(1, world))
                | ~custom_x(2, world)
                | (custom_x(3, world) & (custom_x(4, world) | ~custom_x(4, world)))
                | ~(custom_x(5, world) & custom_x(2, world) & ~custom_x(1, world))
                | (~(custom_x(5, world) & ~custom_x(5, world)) & custom_x(1, world))
                | ~(custom_x(3, world) | ~custom_x(3, world)),
                CustomLogicCondition.disjunction_of(
                    [custom_x(1, world := World()), ~custom_x(5, world), ~custom_x(2, world), custom_x(3, world)]
                ),
            ),
        ],
    )
    def test_simplify(self, term, simplified):
        cond = term.simplify()
        assert cond.is_equal_to(simplified)

    def test_simplify_tmp_variable(self):
        world = World()
        cond = world.bitwise_and(world.variable("x1", 1), world.bitwise_negate(world.variable("x2", 1)))
        log_cond = CustomLogicCondition(cond, tmp=True)
        log_cond.simplify()
        assert log_cond

    @pytest.mark.parametrize(
        "term, result",
        [
            (true_value(World()), []),
            (false_value(World()), []),
            (custom_x(1, world := World()), [custom_x(1, world)]),
            (~custom_x(1, world := World()), [custom_x(1, world)]),
            (
                custom_x(1, world := World())
                & ~custom_x(2, world)
                & (custom_x(3, world) | ~(custom_x(4, world) & custom_x(2, world)))
                & ~(custom_x(5, world) & custom_x(2, world) & ~custom_x(1, world)),
                [custom_x(1, world), custom_x(2, world), custom_x(3, world), custom_x(4, world), custom_x(5, world)],
            ),
        ],
    )
    def test_get_symbols(self, term, result):
        assert [str(symbol) for symbol in term.get_symbols()] == [str(symbol) for symbol in result]

    @pytest.mark.parametrize(
        "term, result",
        [
            (true_value(World()), []),
            (false_value(World()), []),
            (custom_x(1, world := World()), [custom_x(1, world)]),
            (~custom_x(1, world := World()), [~custom_x(1, world)]),
            (custom_x(1, world := World()) | custom_x(2, world), [custom_x(1, world), custom_x(2, world)]),
            (~custom_x(1, world := World()) | custom_x(2, world), [~custom_x(1, world), custom_x(2, world)]),
            (custom_x(1, world := World()) & custom_x(2, world), [custom_x(1, world), custom_x(2, world)]),
            (
                custom_x(1, world := World())
                & ~custom_x(2, world)
                & (custom_x(3, world) | ~(custom_x(4, world) & custom_x(2, world)))
                & ~(custom_x(5, world) & custom_x(2, world) & ~custom_x(1, world)),
                [
                    custom_x(1, world),
                    ~custom_x(2, world),
                    custom_x(3, world),
                    custom_x(4, world),
                    custom_x(2, world),
                    custom_x(5, world),
                    custom_x(2, world),
                    ~custom_x(1, world),
                ],
            ),
        ],
    )
    def test_get_literals(self, term, result):
        assert [str(literal) for literal in term.get_literals()] == [str(literal) for literal in result]

    def test_get_literals_error(self):
        init_world = World()
        term = CustomLogicCondition(
            init_world.bitwise_or(
                init_world.bitwise_and(b_x(1, init_world), init_world.signed_lt(init_world.variable("a", 32), init_world.constant(5, 32))),
                b_x(3, init_world),
            )
        )
        with pytest.raises(AssertionError):
            list(term.get_literals())

    @pytest.mark.parametrize(
        "term, condition, result",
        [
            (true_value(world := World()), custom_x(2, world), true_value(World())),
            (false_value(world := World()), custom_x(2, world), false_value(World())),
            (custom_x(2, world := World()), custom_x(2, world), true_value(World())),
            (custom_x(2, world := World()), custom_x(3, world), custom_x(2, World())),
            (custom_x(1, world := World()) | custom_x(2, world), custom_x(2, world), true_value(World())),
        ],
    )
    def test_substitute_by_true_basics(self, term, condition, result):
        assert term.substitute_by_true(condition).is_equal_to(result)

    @pytest.mark.parametrize(
        "condition, result",
        [
            (
                (custom_x(1, world := World()) | custom_x(2, world) | custom_x(3, world))
                & (custom_x(4, world) | custom_x(5, world))
                & custom_x(6, world)
                & custom_x(7, world),
                true_value(World()),
            ),
            (
                custom_x(6, World()),
                (custom_x(1, world := World()) | custom_x(2, world) | custom_x(3, world))
                & (custom_x(4, world) | custom_x(5, world))
                & custom_x(7, world),
            ),
            (
                custom_x(4, world := World()) | custom_x(5, world),
                (custom_x(1, world := World()) | custom_x(2, world) | custom_x(3, world)) & custom_x(6, world) & custom_x(7, world),
            ),
            (
                custom_x(6, world := World()) & (custom_x(4, world) | custom_x(5, world)),
                (custom_x(1, world := World()) | custom_x(2, world) | custom_x(3, world)) & custom_x(7, world),
            ),
            (
                custom_x(6, world := World()) & custom_x(7, world),
                (custom_x(1, world := World()) | custom_x(2, world) | custom_x(3, world)) & (custom_x(4, world) | custom_x(5, world)),
            ),
            (
                custom_x(1, world := World()) | custom_x(2, world),
                (custom_x(1, world := World()) | custom_x(2, world) | custom_x(3, world))
                & (custom_x(4, world) | custom_x(5, world))
                & custom_x(6, world)
                & custom_x(7, world),
            ),
            (
                (custom_x(1, world := World()) | custom_x(2, world) | custom_x(3, world))
                & (custom_x(4, world) | custom_x(5, world))
                & custom_x(6, world)
                & custom_x(7, world)
                & custom_x(8, world),
                true_value(World()),
            ),
        ],
    )
    def test_substitute_by_true(self, condition, result):
        world = condition.context
        term = (
            (custom_x(1, world) | custom_x(2, world) | custom_x(3, world))
            & (custom_x(4, world) | custom_x(5, world))
            & custom_x(6, world)
            & custom_x(7, world)
        )
        term.substitute_by_true(condition)
        term.simplify()
        assert term.is_equal_to(result.simplify())

    @pytest.mark.parametrize(
        "term, conditions, result",
        [
            (
                custom_x(1, world := World()) & custom_x(2, world),
                [Condition(OperationType.equal, [var_a, constant_5]), Condition(OperationType.less_or_equal_us, [var_a, constant_10])],
                custom_x(1, world),
            ),
            (
                custom_x(1, world) & custom_x(2, world) & ~custom_x(3, world),
                [
                    Condition(OperationType.equal, [var_a, constant_5]),
                    Condition(OperationType.less_or_equal_us, [var_a, constant_10]),
                    Condition(OperationType.equal, [var_b, constant_10]),
                ],
                custom_x(1, world) & ~custom_x(3, world),
            ),
            (
                custom_x(1, world) & custom_x(2, world),
                [Condition(OperationType.less, [var_a, constant_20]), Condition(OperationType.less_or_equal_us, [var_a, constant_10])],
                custom_x(2, world),
            ),
            (
                custom_x(1, world) & ~custom_x(2, world),
                [Condition(OperationType.less, [var_a, constant_20]), Condition(OperationType.greater_us, [var_a, constant_10])],
                ~custom_x(2, world),
            ),
        ],
    )
    def test_remove_redundancy(self, term, conditions, result):
        # TODO --> new symbols
        condition_handler = MockConditionHandler()
        condition_handler._logic_context = term.context
        for cond in conditions:
            condition_handler.add_condition(cond)
        assert term.remove_redundancy(condition_handler).is_equal_to(result)

    def test_remove_redundancy_new_symbol_1(self):
        world = World()
        term = custom_x(1, world) & custom_x(2, world)
        condition_handler = MockConditionHandler()
        condition_handler._logic_context = world
        for cond in [Condition(OperationType.less, [var_a, constant_5]), Condition(OperationType.less_or_equal_us, [var_a, constant_10])]:
            condition_handler.add_condition(cond)
        term.remove_redundancy(condition_handler)
        assert term.is_symbol
        assert condition_handler.get_condition_of(term) == Condition(OperationType.less_or_equal_us, [var_a, constant_4])
        assert condition_handler.get_z3_condition_of(term) == u_lower_eq(custom_variable(world, "a,eax#3"), 4)

    def test_remove_redundancy_new_symbol_2(self):
        world = World()
        term = custom_x(1, world) & custom_x(2, world)
        condition_handler = MockConditionHandler()
        condition_handler._logic_context = world
        expr = BinaryOperation(OperationType.plus, [var_a, constant_5])
        for cond in [Condition(OperationType.less, [expr, constant_5]), Condition(OperationType.less_or_equal_us, [expr, constant_10])]:
            condition_handler.add_condition(cond)
        term.remove_redundancy(condition_handler)
        assert term.is_symbol
        assert condition_handler.get_condition_of(term) == Condition(OperationType.less_or_equal_us, [expr, constant_4])
        assert condition_handler.get_z3_condition_of(term) == u_lower_eq(custom_variable(world), 4)

    @pytest.mark.parametrize(
        "world, term, result",
        [
            (
                world := World(),
                CustomLogicCondition(
                    world.bitwise_or(
                        world.bitwise_and(b_x(1, world)),
                        world.bitwise_negate(b_x(2, world)),
                        world.bitwise_and(b_x(3, world), world.bitwise_or(world.bitwise_negate(b_x(4, world)))),
                        world.bitwise_negate(world.bitwise_and(b_x(5, world), b_x(2, world), world.bitwise_negate(b_x(1, world)))),
                        world.bitwise_and(
                            world.bitwise_negate(world.bitwise_and(b_x(5, world), world.bitwise_negate(b_x(5, world)))),
                            b_x(1, world),
                        ),
                        world.bitwise_negate(world.bitwise_or(b_x(3, world), world.bitwise_negate(b_x(3, world)))),
                    )
                ),
                "(a < 0x1 | b == 0x2 | (c <= 0x3 & d <= 0x4) | !(e >= 0x5 & b != 0x2 & a >= 0x1) | (!(e >= 0x5 & e < 0x5) & a < 0x1) | "
                "!(c <= 0x3 | c > 0x3))",
            ),
            (
                world := World(),
                CustomLogicCondition(
                    world.bitwise_or(
                        world.bitwise_and(b_x(1, world), world.bitwise_negate(b_x(1, world))),
                        world.bitwise_negate(b_x(2, world)),
                        world.bitwise_and(b_x(3, world), world.bitwise_or(b_x(4, world), world.bitwise_negate(b_x(4, world)))),
                        world.bitwise_negate(world.bitwise_and(b_x(5, world), b_x(2, world), world.bitwise_negate(b_x(1, world)))),
                        world.bitwise_and(
                            world.bitwise_negate(world.bitwise_and(b_x(5, world), world.bitwise_negate(b_x(5, world)))),
                            b_x(1, world),
                        ),
                        world.bitwise_negate(world.bitwise_or(b_x(3, world), world.bitwise_negate(b_x(3, world)))),
                    )
                ),
                "((a < 0x1 & a >= 0x1) | b == 0x2 | (c <= 0x3 & (d > 0x4 | d <= 0x4)) | !(e >= 0x5 & b != 0x2 & a >= 0x1) | "
                "(!(e >= 0x5 & e < 0x5) & a < 0x1) | !(c <= 0x3 | c > 0x3))",
            ),
        ],
    )
    def test_rich_string_representation(self, world, term, result):
        condition_map = {
            custom_x(1, world): Condition(OperationType.less, [Variable("a"), Constant(1)]),
            custom_x(2, world): Condition(OperationType.not_equal, [Variable("b"), Constant(2)]),
            custom_x(3, world): Condition(OperationType.less_or_equal, [Variable("c"), Constant(3)]),
            custom_x(4, world): Condition(OperationType.greater, [Variable("d"), Constant(4)]),
            custom_x(5, world): Condition(OperationType.greater_or_equal, [Variable("e"), Constant(5)]),
        }
        assert term.rich_string_representation(condition_map) == result


class TestPseudoCustomLogicCondition:
    @pytest.mark.parametrize(
        "condition, result",
        [
            (Condition(OperationType.equal, [var_a, constant_5]), "(a,eax#3 == 5)"),
            (
                Condition(OperationType.less_or_equal, [BinaryOperation(OperationType.plus, [var_a, constant_5]), constant_5]),
                "(a + 0x5,['eax#3'] s<= 5)",
            ),
            (
                Condition(OperationType.greater_or_equal_us, [BinaryOperation(OperationType.plus, [var_a, var_b]), constant_5]),
                "(a + b,['eax#3', 'edx#5'] u>= 5)",
            ),
        ],
    )
    def test_initialize_from_condition(self, condition, result):
        world = World()
        cond = PseudoCustomLogicCondition.initialize_from_condition(condition, world)
        assert str(cond) == result and world == cond.context

    def test_initialize_from_formula(self):
        pass

    @pytest.mark.parametrize(
        "term, result",
        [
            (
                PseudoCustomLogicCondition(
                    (world := World()).bitwise_negate(world.unsigned_le(custom_variable(world), custom_constant(world, 5)))
                ),
                PseudoCustomLogicCondition((world := World()).unsigned_gt(custom_variable(world), custom_constant(world, 5))),
            ),
            (
                PseudoCustomLogicCondition(
                    (world := World()).bitwise_and(
                        b_x(1, world),
                        world.bitwise_or(b_x(3, world), world.bitwise_negate(world.bitwise_and(b_x(4, world), b_x(2, world)))),
                        world.bitwise_negate(world.bitwise_and(b_x(5, world), b_x(2, world), world.bitwise_negate(b_x(1, world)))),
                    )
                ),
                PseudoCustomLogicCondition(
                    (world := World()).bitwise_and(
                        b_x(1, world),
                        world.bitwise_or(b_x(3, world), world.bitwise_negate(b_x(4, world)), world.bitwise_negate(b_x(2, world))),
                    )
                ),
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
        world = World()
        world_5 = World()
        custom_expression = PseudoCustomLogicCondition._convert_expression(expression, 32, world)
        custom_expression_5 = PseudoCustomLogicCondition._convert_expression(expression, 5, world_5)
        assert str(custom_expression) == result and custom_expression.size == 32
        assert str(custom_expression_5) == result and custom_expression_5.size == 5
