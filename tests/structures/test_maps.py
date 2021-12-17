from collections import defaultdict
from typing import List, Tuple

import pytest
from dewolf.structures.maps import DefMap, UseMap
from dewolf.structures.pseudo.expressions import Constant, Variable
from dewolf.structures.pseudo.instructions import Assignment, Branch, Instruction, Phi
from dewolf.structures.pseudo.operations import BinaryOperation, Condition, OperationType
from dewolf.structures.pseudo.typing import Integer


def define_def_map() -> Tuple[List, DefMap]:
    def_map = DefMap()
    instruction_list = [
        Assignment(Variable("v", Integer.int32_t(), 1), Variable("u", Integer.int32_t())),
        Assignment(Variable("v", Integer.int32_t(), 3), Constant(4)),
        Assignment(Variable("w", Integer.int32_t(), 1), Variable("v", Integer.int32_t(), 3)),
        Assignment(Variable("u", Integer.int32_t()), Constant(2)),
    ]

    for instruction in instruction_list:
        for definition in instruction.definitions:
            def_map._map[definition] = instruction

    return instruction_list, def_map


def test_def_map_contains():
    instruction_list, def_map = define_def_map()

    assert Variable("v", Integer.int32_t(), 1) in def_map
    assert Variable("u", Integer.int32_t()) in def_map
    assert not Variable("v", Integer.int32_t()) in def_map

    for definition in instruction_list[0].definitions:
        if definition in def_map:
            del def_map._map[definition]
    assert not Variable("v", Integer.int32_t(), 1) in def_map


def test_def_map_add():
    instruction_list, def_map = define_def_map()

    def_map.add(Phi(Variable("v", Integer.int32_t(), 4), [Variable("v", Integer.int32_t(), 1), Variable("v", Integer.int32_t(), 2)]))

    assert def_map._map == {
        Variable("v", Integer.int32_t(), 1): instruction_list[0],
        Variable("v", Integer.int32_t(), 3): instruction_list[1],
        Variable("w", Integer.int32_t(), 1): instruction_list[2],
        Variable("u", Integer.int32_t()): instruction_list[3],
        Variable("v", Integer.int32_t(), 4): Phi(
            Variable("v", Integer.int32_t(), 4), [Variable("v", Integer.int32_t(), 1), Variable("v", Integer.int32_t(), 2)]
        ),
    }

    with pytest.raises(ValueError):
        def_map.add(Assignment(Variable("v", Integer.int32_t(), 1), Variable("v", Integer.int32_t(), 0)))


def test_def_map_get():
    instruction_list, def_map = define_def_map()

    assert def_map.get(Variable("v", Integer.int32_t(), 1)) == instruction_list[0]
    assert def_map.get(Variable("v", Integer.int32_t(), 0)) is None
    assert def_map.get(Variable("v", Integer.int32_t())) is None

    def_map.add(Phi(Variable("v", Integer.int32_t(), 4), [Variable("v", Integer.int32_t(), 1), Variable("v", Integer.int32_t(), 2)]))

    assert def_map.get(Variable("v", Integer.int32_t(), 4)) == Phi(
        Variable("v", Integer.int32_t(), 4), [Variable("v", Integer.int32_t(), 1), Variable("v", Integer.int32_t(), 2)]
    )


def test_defined_variables():
    _, def_map = define_def_map()

    assert def_map.defined_variables == {
        Variable("v", Integer.int32_t(), 1),
        Variable("v", Integer.int32_t(), 3),
        Variable("w", Integer.int32_t(), 1),
        Variable("u", Integer.int32_t()),
    }


def define_use_map() -> Tuple[List, UseMap]:
    use_map = UseMap()
    instruction_list = [
        Assignment(Variable("v", Integer.int32_t(), 1), Variable("u", Integer.int32_t())),
        Assignment(Variable("w", Integer.int32_t(), 1), Variable("v", Integer.int32_t(), 3)),
        Phi(
            Variable("u", Integer.int32_t(), 0),
            [Variable("u", Integer.int32_t()), Variable("v", Integer.int32_t(), 3), Variable("v", Integer.int32_t(), 4)],
        ),
        Assignment(
            Variable("u", Integer.int32_t()), BinaryOperation(OperationType.plus, [Variable("v", Integer.int32_t(), 1), Constant(2)])
        ),
        Assignment(
            Variable("v", Integer.int32_t(), 3),
            BinaryOperation(OperationType.plus, [Variable("v", Integer.int32_t(), 1), Variable("v", Integer.int32_t(), 2)]),
        ),
        Branch(Condition(OperationType.greater, [Variable("v", Integer.int32_t(), 1), Variable("w", Integer.int32_t(), 1)], "bool")),
    ]

    for instruction in instruction_list:
        for usage in instruction.requirements:
            use_map._map[usage].add(instruction)

    return instruction_list, use_map


def test_use_map_contains():
    instruction_list, use_map = define_use_map()

    assert Variable("u", Integer.int32_t()) in use_map
    assert Variable("v", Integer.int32_t(), 3) in use_map
    assert Variable("v", Integer.int32_t(), 1) in use_map
    assert not Variable("v", Integer.int32_t()) in use_map


def test_use_map_iter():
    instruction_list, use_map = define_use_map()

    iterated_values = defaultdict(set)
    for used, instructions in use_map:
        assert isinstance(used, Variable) and isinstance(instructions, set)
        for instruction in instructions:
            assert isinstance(instruction, Instruction)
        iterated_values[used] = instructions
    assert iterated_values == use_map._map


def test_use_map_add():
    instruction_list, use_map = define_use_map()

    new_instruction_1 = Assignment(
        Variable("x", Integer.int32_t()), BinaryOperation(OperationType.plus, [Variable("v", Integer.int32_t(), 1), Constant(2)])
    )
    use_map.add(new_instruction_1)
    assert use_map._map == {
        Variable("u", Integer.int32_t()): {instruction_list[0], instruction_list[2]},
        Variable("v", Integer.int32_t(), 3): {instruction_list[1], instruction_list[2]},
        Variable("v", Integer.int32_t(), 4): {instruction_list[2]},
        Variable("v", Integer.int32_t(), 1): {instruction_list[5], instruction_list[4], instruction_list[3], new_instruction_1},
        Variable("v", Integer.int32_t(), 2): {instruction_list[4]},
        Variable("w", Integer.int32_t(), 1): {instruction_list[5]},
    }

    new_instruction_2 = Phi(
        Variable("u", Integer.int32_t(), 0),
        [Variable("u", Integer.int32_t()), Variable("v", Integer.int32_t(), 3), Variable("v", Integer.int32_t(), 4)],
    )
    use_map.add(new_instruction_2)
    assert use_map._map == {
        Variable("u", Integer.int32_t()): {instruction_list[0], instruction_list[2]},
        Variable("v", Integer.int32_t(), 3): {instruction_list[1], instruction_list[2]},
        Variable("v", Integer.int32_t(), 4): {instruction_list[2]},
        Variable("v", Integer.int32_t(), 1): {instruction_list[5], instruction_list[4], instruction_list[3], new_instruction_1},
        Variable("v", Integer.int32_t(), 2): {instruction_list[4]},
        Variable("w", Integer.int32_t(), 1): {instruction_list[5]},
    }


def test_use_map_get():
    instruction_list, use_map = define_use_map()

    assert use_map.get(Variable("v", Integer.int32_t(), 1)) == {instruction_list[5], instruction_list[4], instruction_list[3]}
    assert use_map.get(Variable("v", Integer.int32_t(), 4)) == {instruction_list[2]}
    assert use_map.get(Variable("x", Integer.int32_t())) == set()


def test_used_variables():
    _, use_map = define_use_map()

    assert use_map.used_variables == {
        Variable("u", Integer.int32_t()),
        Variable("v", Integer.int32_t(), 3),
        Variable("v", Integer.int32_t(), 4),
        Variable("v", Integer.int32_t(), 1),
        Variable("v", Integer.int32_t(), 2),
        Variable("w", Integer.int32_t(), 1),
    }
