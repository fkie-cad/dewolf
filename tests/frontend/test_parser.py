from collections import namedtuple
from typing import Iterator, List

import pytest
from binaryninja import (
    BasicBlockEdge,
    BranchType,
    Function,
    MediumLevelILBasicBlock,
    MediumLevelILInstruction,
    MediumLevelILOperation,
    PossibleValueSet,
    RegisterValueType,
    Type,
    Variable,
    VariableSourceType,
)
from decompiler.frontend.binaryninja.lifter import BinaryninjaLifter
from decompiler.frontend.binaryninja.parser import BinaryninjaParser
from decompiler.structures.graphs.cfg import BasicBlockEdgeCondition
from decompiler.structures.pseudo.expressions import Constant


class MockEdge(BasicBlockEdge):
    """Mock object representing a binaryninja BasicBlockEdge."""

    # Flat mock objects for edge targets
    BasicBlock = namedtuple("BasicBlock", ["index", "source_block"])
    fakeblock = namedtuple("fakeblock", "start")

    def __init__(self, source: int, target: int, _type: BranchType):
        """Generate a mock edge connecting two basic blocks."""
        self.source = self.BasicBlock(index=source, source_block=self.fakeblock(start=source))
        self.target = self.BasicBlock(index=target, source_block=self.fakeblock(start=target))
        self.type = _type


class MockBlock(MediumLevelILBasicBlock):
    """Mock object representing a binaryninja MediumLevelILBasicBlock."""

    def __init__(self, index: int, edges: List[MockEdge], instructions: List[MediumLevelILInstruction] = None):
        """Create a basic block with the given index, instructions and edges."""
        self._index = index
        self._instructions = instructions if instructions else list()
        self._edges = edges

    @property
    def index(self) -> int:
        """Return the index (e.g. index of the first instruction)"""
        return self._index

    @property
    def outgoing_edges(self) -> Iterator[MockEdge]:
        """Ierate all outgoing edges."""
        return iter(self._edges)

    def __iter__(self) -> Iterator[MediumLevelILInstruction]:
        """Iterate all instructions in the BasicBlock."""
        return iter(self._instructions)

    def __getitem__(self, index: int) -> MediumLevelILInstruction:
        """Get the instruction at a specific index."""
        return self._instructions[index]

    def __del__(self):
        """Override binaryninjas deconstructor, freeing c types"""
        pass

    def __len__(self) -> int:
        """Overwrite instruction count to actually count the amount of instructions."""
        return len(self._instructions)


class MockFunction(Function):
    """Mock object representing a binaryninja Function."""

    def __init__(self, blocks: List[MockBlock]):
        """Generate a mock function only based on a list of basic blocks."""
        self._blocks = blocks

    @property
    def medium_level_il(self) -> "MockFunction":
        """Redirect references to the medium level il form of the function to itself."""
        return self

    @property
    def ssa_form(self) -> "MockFunction":
        """Redirect references to the ssa form of the function to itself."""
        return self

    def create_user_var(self, type, value, values):
        return None

    def __iter__(self) -> Iterator[MockBlock]:
        """Iterate all basic blocks in the function."""
        return iter(self._blocks)

    def __del__(self):
        """Override binaryninjas deconstructor, freeing c types"""
        pass


class MockPossibleValues(PossibleValueSet):
    """Mock object representing a possible value set returned by binaryninja."""

    def __init__(self, mapping: dict):
        """Create a new MockPossibleValues for testing purposes only."""
        self._mapping = mapping

    @property
    def type(self):
        """All switch statements should have a lookup table assigned."""
        return RegisterValueType.LookupTableValue

    def create_user_var(self, type, value, values=None):
        return MockVariable(values)


class MockVariable(Variable):
    """Mock object representing a binaryninja Variable."""

    def __init__(self, values, name="var27"):
        """Create a new MockVariable for testing purposes only."""
        self.possible_values = values
        self._type = Type.int(32)
        object.__setattr__(self, "_source_type", VariableSourceType(0))
        object.__setattr__(self, "_function", MockFunction([]))
        self._name = name
        self.type = Type.int(32)

    def name(self) -> str:
        return self._name


class MockSwitch:
    """Mock object representing a switch statement."""

    def __init__(self, mapping):
        """Create a new MockSwitch for testing purposes only."""
        self.__class__ = MediumLevelILInstruction
        self.dest = MockVariable(MockPossibleValues(mapping))
        self._operation = MediumLevelILOperation.MLIL_JUMP
        self.targets = None
        self._function = None


@pytest.fixture
def parser():
    """Since we only got a binaryninja frontend yet, we only test this parser."""
    return BinaryninjaParser(BinaryninjaLifter())


def test_trivial(parser):
    """Function with a single empty basic block."""
    function = MockFunction([MockBlock(0, [])])
    cfg = parser.parse(function)
    assert len(cfg.nodes) == 1
    assert len(list(cfg.instructions)) == 0
    assert len(cfg.edges) == 0


def test_chain(parser):
    """Function with a simple chain of basic blocks."""
    function = MockFunction(
        [
            MockBlock(0, [MockEdge(0, 1, BranchType.UnconditionalBranch)]),
            MockBlock(1, [MockEdge(1, 2, BranchType.UnconditionalBranch)]),
            MockBlock(2, []),
        ]
    )
    cfg = parser.parse(function)
    assert [v.name for v in cfg.nodes] == [0, 1, 2]
    assert [(edge.source.name, edge.sink.name) for edge in cfg.edges] == [(0, 1), (1, 2)]
    assert len(list(cfg.instructions)) == 0
    assert set([edge.condition_type for edge in cfg.edges]) == {BasicBlockEdgeCondition.unconditional}


def test_branch(parser):
    """Function with a single branch."""
    function = MockFunction(
        [
            MockBlock(0, [MockEdge(0, 1, BranchType.TrueBranch), MockEdge(0, 2, BranchType.FalseBranch)]),
            MockBlock(1, [MockEdge(1, 3, BranchType.UnconditionalBranch)]),
            MockBlock(2, [MockEdge(2, 3, BranchType.UnconditionalBranch)]),
            MockBlock(3, []),
        ]
    )
    cfg = parser.parse(function)
    assert [v.name for v in cfg.nodes] == [0, 1, 2, 3]
    assert [(edge.source.address, edge.sink.address) for edge in cfg.edges] == [(0, 1), (0, 2), (1, 3), (2, 3)]
    assert len(list(cfg.instructions)) == 0
    assert [edge.condition_type for edge in cfg.edges] == [BasicBlockEdgeCondition.true, BasicBlockEdgeCondition.false] + [
        BasicBlockEdgeCondition.unconditional
    ] * 2


def test_switch(parser):
    """Function with a switch statement."""
    function = MockFunction(
        [
            MockBlock(
                0,
                [
                    MockEdge(0, 1, BranchType.IndirectBranch),
                    MockEdge(0, 2, BranchType.IndirectBranch),
                    MockEdge(0, 3, BranchType.IndirectBranch),
                ],
                instructions=[MockSwitch({"a": 1, "b": 1, "c": 2, "d": 3})],
            ),
            MockBlock(1, [MockEdge(1, 4, BranchType.UnconditionalBranch)]),
            MockBlock(2, [MockEdge(2, 4, BranchType.UnconditionalBranch)]),
            MockBlock(3, [MockEdge(3, 4, BranchType.UnconditionalBranch)]),
            MockBlock(4, []),
        ]
    )
    cfg = parser.parse(function)
    assert [v.name for v in cfg.nodes] == [0, 1, 2, 3, 4]
    assert [(edge.source.name, edge.sink.name) for edge in cfg.edges] == [(0, 1), (0, 2), (0, 3), (1, 4), (2, 4), (3, 4)]
    assert [getattr(edge, "cases", None) for edge in cfg.edges] == [
        [Constant("a"), Constant("b")],
        [Constant("c")],
        [Constant("d")],
        None,
        None,
        None,
    ]
    assert len(list(cfg.instructions)) == 1


def test_loop(parser):
    """Function with a simple loop and an exit branch."""
    function = MockFunction(
        [
            MockBlock(0, [MockEdge(0, 1, BranchType.UnconditionalBranch)]),
            MockBlock(1, [MockEdge(1, 2, BranchType.UnconditionalBranch)]),
            MockBlock(2, [MockEdge(2, 1, BranchType.TrueBranch), MockEdge(2, 3, BranchType.FalseBranch)]),
            MockBlock(3, []),
        ]
    )
    cfg = parser.parse(function)
    assert [v.name for v in cfg.nodes] == [0, 1, 2, 3]
    assert [(edge.source.address, edge.sink.address) for edge in cfg.edges] == [(0, 1), (1, 2), (2, 1), (2, 3)]
    assert len(list(cfg.instructions)) == 0
