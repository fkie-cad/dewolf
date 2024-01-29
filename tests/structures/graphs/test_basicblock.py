"""Module implementing tests for the BasicBlock class pseudo instruction container."""

from functools import partial

import pytest
from decompiler.structures.graphs.cfg import BasicBlock
from decompiler.structures.pseudo.expressions import ImportedFunctionSymbol
from decompiler.structures.pseudo.instructions import Assignment, Branch, Call, Comment, IndirectBranch, ListOperation, Phi
from decompiler.structures.pseudo.operations import BinaryOperation, Condition, Constant, OperationType, UnaryOperation, Variable
from decompiler.structures.pseudo.typing import Integer, Pointer

i = [Variable("i", ssa_label=x, vartype=Integer.uint8_t()) for x in range(3)]
b = [Variable("b", ssa_label=x, vartype=Integer.int32_t()) for x in range(2)]
x = Variable("x", vartype=Pointer(Integer.int32_t()), is_aliased=True)


@pytest.fixture
def testblock() -> BasicBlock:
    """Example basicblock used as a fixture for tests."""
    return BasicBlock(
        1337,
        instructions=[
            Phi(i[1].copy(), [i[0].copy(), i[2].copy()]),
            Assignment(
                i[2].copy(),
                UnaryOperation(
                    OperationType.dereference,
                    [BinaryOperation(OperationType.plus, [i[1].copy(), Constant(1, vartype=Integer.uint8_t())])],
                ),
            ),
            Assignment(
                b[0].copy(),
                BinaryOperation(OperationType.plus, [x.copy(), i[1].copy()]),
            ),
            Assignment(b[1].copy(), Call(ImportedFunctionSymbol("foo", -1), [b[0].copy()])),
            IndirectBranch(b[1].copy()),
        ],
    )


def test_basic_functions(testblock: BasicBlock):
    assert testblock.address == testblock.name == 1337
    assert len(testblock) == 5 == len(testblock.instructions)
    assert testblock.variables == {i[0], i[1], i[2], b[0], b[1], x}
    assert testblock.definitions == {i[1], i[2], b[0], b[1]}
    assert testblock.dependencies == {i[0], x}
    assert IndirectBranch(b[1].copy()) in testblock
    copy = testblock.copy()
    assert copy == testblock and id(copy) != id(testblock)
    assert testblock.condition == BasicBlock.ControlFlowType.indirect
    assert not testblock.is_empty()
    assert testblock.get_definitions(i[1]) == [Phi(i[1].copy(), [i[0].copy(), i[2].copy()])]
    assert testblock.get_usages(x) == [
        Assignment(
            b[0].copy(),
            BinaryOperation(OperationType.plus, [x.copy(), i[1].copy()]),
        )
    ]
    assert set(testblock.subexpressions()) == {
        i[0],
        i[1],
        i[2],
        b[0],
        b[1],
        x,
        Constant(1, Integer.uint8_t()),
        ImportedFunctionSymbol("foo", -1),
        BinaryOperation(OperationType.plus, [i[1], Constant(1, Integer.uint8_t())]),
        UnaryOperation(
            OperationType.dereference,
            [BinaryOperation(OperationType.plus, [i[1].copy(), Constant(1, vartype=Integer.uint8_t())])],
        ),
        Assignment(
            i[2].copy(),
            UnaryOperation(
                OperationType.dereference,
                [BinaryOperation(OperationType.plus, [i[1].copy(), Constant(1, vartype=Integer.uint8_t())])],
            ),
        ),
        ListOperation([i[0], i[2]]),
        Phi(i[1].copy(), [i[0].copy(), i[2].copy()]),
        BinaryOperation(OperationType.plus, [x.copy(), i[1].copy()]),
        Assignment(
            b[0].copy(),
            BinaryOperation(OperationType.plus, [x.copy(), i[1].copy()]),
        ),
        Call(ImportedFunctionSymbol("foo", -1), [b[0].copy()]),
        Assignment(b[1].copy(), Call(ImportedFunctionSymbol("foo", -1), [b[0].copy()])),
        IndirectBranch(b[1].copy()),
    }


def test_instruction_management(testblock: BasicBlock):
    instructions = [
        Phi(i[1].copy(), [i[0].copy(), i[2].copy()]),
        Assignment(
            i[2].copy(),
            UnaryOperation(
                OperationType.dereference,
                [BinaryOperation(OperationType.plus, [i[1].copy(), Constant(1, vartype=Integer.uint8_t())])],
            ),
        ),
        Assignment(
            b[0].copy(),
            BinaryOperation(OperationType.plus, [x.copy(), i[1].copy()]),
        ),
        Assignment(b[1].copy(), Call(ImportedFunctionSymbol("foo", -1), [b[0].copy()])),
        IndirectBranch(b[1].copy()),
    ]
    assert testblock.instructions == instructions
    assert list(testblock) == instructions
    assert testblock[0] == instructions[0]
    testblock[0] = Comment("test")
    assert testblock[0] != instructions[0] and testblock[0] == Comment("test")
    testblock.substitute(testblock[0], Comment("foo"))
    assert testblock[0] != instructions[0] and testblock[0] == Comment("foo")


def test_block_representations(testblock: BasicBlock):
    assert str(testblock) == "\n".join(str(instruction) for instruction in testblock)
    assert repr(testblock) == "BasicBlock(0x539, len=5)"


def test_update_function(testblock: BasicBlock):
    testblock.remove_instruction(testblock[0])
    assert testblock.get_definitions(i[1]) == []
    assert testblock.get_usages(i[0]) == []
    assert len(testblock) == len(testblock.instructions) == 4
    assert testblock.definitions == {i[2], b[0], b[1]}
    testblock.add_instruction(Branch(Condition(OperationType.greater, [x, Constant(0, Integer.int32_t())])))
    assert testblock.condition == BasicBlock.ControlFlowType.conditional
    assert testblock.get_usages(x) == [
        Assignment(
            b[0].copy(),
            BinaryOperation(OperationType.plus, [x.copy(), i[1].copy()]),
        ),
        Branch(Condition(OperationType.greater, [x, Constant(0, Integer.int32_t())])),
    ]
    replacement = Variable("z", ssa_label=0, vartype=Integer.int32_t())
    testblock.substitute(b[1].copy(), replacement)
    assert testblock.get_usages(replacement) == [IndirectBranch(replacement.copy())]
    assert testblock.get_definitions(replacement) == [
        Assignment(replacement.copy(), Call(ImportedFunctionSymbol("foo", -1), [b[0].copy()]))
    ]


def test_add_instruction_where_possible():
    """Test the methods add_instruction_where_possible method."""
    block = BasicBlock(0)
    block.add_instruction_where_possible(Assignment(Variable("a"), Variable("x")))
    block.add_instruction_where_possible(Phi(Variable("x"), [Variable("x1"), Variable("x2")]))
    block.add_instruction_where_possible(Phi(Variable("y"), [Variable("x1"), Variable("x")]))
    block.add_instruction_where_possible(Assignment(Variable("d"), Variable("x")))
    block.add_instruction_where_possible(Branch(Condition(OperationType.equal, [Variable("x"), Variable("y")])))
    block.add_instruction_where_possible(Assignment(Variable("c"), Variable("a")))
    assert block.instructions == [
        Phi(Variable("x"), [Variable("x1"), Variable("x2")]),
        Phi(Variable("y"), [Variable("x1"), Variable("x")]),
        Assignment(Variable("d"), Variable("x")),
        Assignment(Variable("a"), Variable("x")),
        Assignment(Variable("c"), Variable("a")),
        Branch(Condition(OperationType.equal, [Variable("x"), Variable("y")])),
    ]


class TestInstructionReplacement:
    var = partial(Variable, vartype="int")
    const = partial(Constant)
    assign = partial(Assignment)

    a = var("a")
    b = var("b")
    c = var("c")

    # Arbitrary instructions
    i1 = assign(a, const(1))
    i2 = assign(b, a)
    i3 = assign(c, const(2))
    i4 = assign(c, a)
    i5 = assign(b, c)
    i6 = assign(a, c)

    @pytest.mark.parametrize("old_instructions, replacee, replacements", [([i1, i2], i3, [i4]), ([], i3, [i1, i2])])
    def test_replace_instruction_raises_error_when_replacee_not_in_instructions(self, old_instructions, replacee, replacements):
        with pytest.raises(ValueError):
            basic_block = BasicBlock(0, instructions=old_instructions)
            basic_block.replace_instruction(replacee, replacements)

    @pytest.mark.parametrize(
        "old_instructions, replacee, replacements, new_instructions",
        [
            ([i1, i2], i2, [i3], [i1, i3]),
            ([i1, i2, i3], i2, [i4, i5], [i1, i4, i5, i3]),
            ([i1, i2, i3, i4], i2, [], [i1, i3, i4]),
        ],
    )
    def test_replace_instruction_with_valid_inputs(self, old_instructions, replacee, replacements, new_instructions):
        basic_block = BasicBlock(0, instructions=old_instructions)
        basic_block.replace_instruction(replacee, replacements)
        assert basic_block.instructions == new_instructions
