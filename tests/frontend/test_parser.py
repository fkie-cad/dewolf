from collections import namedtuple
from typing import Any, Iterator, List
from unittest.mock import Mock, NonCallableMock

import pytest
from binaryninja import (
    BasicBlockEdge,
    BranchType,
    Function,
    MediumLevelILBasicBlock,
    MediumLevelILConstPtr,
    MediumLevelILInstruction,
    MediumLevelILJumpTo,
    MediumLevelILTailcallSsa,
    PossibleValueSet,
    RegisterValueType,
    Variable,
)
from decompiler.frontend.binaryninja.lifter import BinaryninjaLifter
from decompiler.frontend.binaryninja.parser import BinaryninjaParser
from decompiler.structures.graphs.branches import SwitchCase, UnconditionalEdge
from decompiler.structures.graphs.cfg import BasicBlockEdgeCondition
from decompiler.structures.pseudo.expressions import Constant
from decompiler.util.decoration import DecoratedCFG


class MockEdge:
    """Mock object representing a binaryninja BasicBlockEdge."""

    # Flat mock objects for edge targets
    BasicBlock = namedtuple("BasicBlock", ["index", "source_block"])
    fakeblock = namedtuple("fakeblock", "start")

    def __init__(self, source: int, target: int, _type: BranchType):
        """Generate a mock edge connecting two basic blocks."""
        self.source = self.BasicBlock(index=source, source_block=self.fakeblock(start=source))
        self.target = self.BasicBlock(index=target, source_block=self.fakeblock(start=target))
        self.type = _type


class MockBlock(Mock):
    """Mock object representing a binaryninja MediumLevelILBasicBlock."""

    def __init__(self, index: int, edges: List[MockEdge], instructions: List[MediumLevelILInstruction] = None):
        """Create a basic block with the given index, instructions and edges."""
        super().__init__(spec=MediumLevelILBasicBlock)
        self._index = index
        self._instructions = instructions if instructions else list()
        self._edges = edges
        self.source_block = self

    def _get_child_mock(self, **kw: Any) -> NonCallableMock:
        """Child mocks should not be of type MockBlock."""
        return Mock()._get_child_mock(**kw)

    @property
    def index(self) -> int:
        """Return the index (e.g. index of the first instruction)"""
        return self._index

    @property
    def outgoing_edges(self) -> List[MockEdge]:
        """List all outgoing edges."""
        return list(self._edges)

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


class MockView:
    endianness = 0
    sections = {}
    address_size = 32

    def update_analysis_and_wait(self):
        pass

    def get_tags_at(self, _):
        """Do not lift tags. Needed to lift mock instructions that do not set .function to None"""
        return list()

    def get_data_var_at(self, _):
        """Do not lift constant pointer as data variable."""
        return None

    def get_symbol_at(self, _):
        """Do not lift constant pointer as symbol."""
        return None

    def get_function_at(self, _):
        """Do not lift constant pointer as function."""
        return None


class MockFunction(Function):
    """Mock object representing a binaryninja Function."""

    def __init__(self, blocks: List[MockBlock]):
        """Generate a mock function only based on a list of basic blocks."""
        self._blocks = blocks
        self._view = MockView()
        self._arch = "test"
        self.source_function = self
        self.handle = Mock()

    @property
    def medium_level_il(self) -> "MockFunction":
        """Redirect references to the medium level il form of the function to itself."""
        return self

    @property
    def ssa_form(self) -> "MockFunction":
        """Redirect references to the ssa form of the function to itself."""
        return self

    def __iter__(self) -> Iterator[MockBlock]:
        """Iterate all basic blocks in the function."""
        return iter(self._blocks)

    def __del__(self):
        """Override binaryninjas deconstructor, freeing c types"""
        pass


class MockSwitch(Mock):
    """Mock object representing a switch statement."""

    def __init__(self, mapping):
        """Create a new MockSwitch for testing purposes only."""
        super().__init__(spec=MediumLevelILJumpTo)
        self.ssa_memory_version = 0
        self.function = None  # prevents lifting of tags
        self.dest = Mock(spec=Variable)
        self.dest.possible_values = Mock(spec=PossibleValueSet)
        self.dest.possible_values.type = RegisterValueType.LookupTableValue
        self.dest.possible_values.mapping = mapping


class MockFixedJump(Mock):
    """Mock object representing a constant jump."""

    def __init__(self, address: int):
        """Create new MediumLevelILJumpTo object"""
        super().__init__(spec=MediumLevelILJumpTo)
        self.ssa_memory_version = 0
        self.function = None  # prevents lifting of tags
        self.dest = Mock(spec=MediumLevelILConstPtr)
        self.dest.constant = address
        self.dest.function = MockFunction([])  # need .function.view to lift

class MockTailcall(Mock):
    """Mock object representing a constant jump."""

    def __init__(self, address: int):
        """Create new MediumLevelILJumpTo object"""
        super().__init__(spec=MediumLevelILTailcallSsa)
        self.ssa_memory_version = 0
        self.function = None  # prevents lifting of tags
        self.dest = Mock(spec=MediumLevelILConstPtr)
        self.dest.constant = address
        self.params = []
        self.output = []
        self.dest.function = MockFunction([])  # need .function.view to lift

    def _get_child_mock(self, **kw: Any) -> NonCallableMock:
        """Return Mock as child mock."""
        return Mock(params=[])._get_child_mock(**kw)


@pytest.fixture
def parser():
    """Since we only got a binaryninja frontend yet, we only test this parser."""
    return BinaryninjaParser(BinaryninjaLifter())


def test_trivial(parser):
    """Function with a single empty basic block."""
    function = MockFunction([MockBlock(0, [])])
    cfg, _ = parser.parse(function)
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
    cfg, _ = parser.parse(function)
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
    cfg, _ = parser.parse(function)
    assert [v.name for v in cfg.nodes] == [0, 1, 2, 3]
    assert [(edge.source.address, edge.sink.address) for edge in cfg.edges] == [(0, 1), (0, 2), (1, 3), (2, 3)]
    assert len(list(cfg.instructions)) == 0
    assert [edge.condition_type for edge in cfg.edges] == [BasicBlockEdgeCondition.true, BasicBlockEdgeCondition.false] + [
        BasicBlockEdgeCondition.unconditional
    ] * 2


def test_switch(parser):
    """Function with a switch statement."""
    switch_instr = MockSwitch({"a": 1, "b": 1, "c": 2, "d": 3})
    function = MockFunction(
        [
            MockBlock(
                0,
                [
                    MockEdge(0, 1, BranchType.IndirectBranch),
                    MockEdge(0, 2, BranchType.IndirectBranch),
                    MockEdge(0, 3, BranchType.IndirectBranch),
                ],
                instructions=[switch_instr],
            ),
            MockBlock(1, [MockEdge(1, 4, BranchType.UnconditionalBranch)]),
            MockBlock(2, [MockEdge(2, 4, BranchType.UnconditionalBranch)]),
            MockBlock(3, [MockEdge(3, 4, BranchType.UnconditionalBranch)]),
            MockBlock(4, []),
        ]
    )
    cfg, _ = parser.parse(function)
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
    cfg, _ = parser.parse(function)
    assert [v.name for v in cfg.nodes] == [0, 1, 2, 3]
    assert [(edge.source.address, edge.sink.address) for edge in cfg.edges] == [(0, 1), (1, 2), (2, 1), (2, 3)]
    assert len(list(cfg.instructions)) == 0


def test_convert_indirect_edge_to_unconditional(parser):
    """Unconditional jump to constant address."""
    jmp_instr = MockFixedJump(42)
    function = MockFunction(
        [
            block := MockBlock(0, [MockEdge(0, 42, BranchType.IndirectBranch)], instructions=[jmp_instr]),
            MockBlock(42, []),
        ]
    )
    assert parser._can_convert_single_outedge_to_unconditional(block)
    cfg = parser.parse(function)  # need to mock everything the lifter needs...
    assert [v.name for v in cfg.nodes] == [0, 42]
    cfg_edge = cfg.edges[0]
    assert (cfg_edge.source.address, cfg_edge.sink.address) == (0, 42)
    assert isinstance(cfg_edge, UnconditionalEdge)
    assert len(list(cfg.instructions)) == 0


def test_convert_indirect_edge_to_unconditional_no_valid_edge(parser):
    """Unconditional jump to constant address, but jump addresses do not match."""
    jmp_instr = MockFixedJump(12)
    function = MockFunction(
        [
            block := MockBlock(0, [MockEdge(0, 42, BranchType.IndirectBranch)], instructions=[jmp_instr]),
            MockBlock(42, []),
        ]
    )
    assert not parser._can_convert_single_outedge_to_unconditional(block)
    cfg = parser.parse(function)  # need to mock everything the lifter needs...
    assert [v.name for v in cfg.nodes] == [0, 42]
    cfg_edge = cfg.edges[0]
    assert (cfg_edge.source.address, cfg_edge.sink.address) == (0, 42)
    assert not isinstance(cfg_edge, UnconditionalEdge)
    assert len(list(cfg.instructions)) == 1

def test_tailcall_address_recovery(parser):
    """
    Address of edge.target.source_block.start is not in lookup table.
    """
    jmp_instr = MockSwitch({"a": 42})
    function = MockFunction(
        [
            MockBlock(0, [MockEdge(0, 0, BranchType.IndirectBranch)], instructions=[jmp_instr]),
            MockBlock(1, []),
        ]
    )
    with pytest.raises(KeyError):
        cfg = parser.parse(function)

    # extract address from tailcall in successor
    tailcall = MockTailcall(address=42)
    broken_edge = Mock()
    broken_edge.type = BranchType.IndirectBranch

    function = MockFunction(
        [
            switch_block := MockBlock(0, [broken_edge], instructions=[jmp_instr]),
            tailcall_block := MockBlock(1, [], instructions=[tailcall]),
        ]
    )
    broken_edge.source = switch_block
    broken_edge.target = tailcall_block
    broken_edge.target.source_block.start = 0
    cfg = parser.parse(function)
    v0, v1 = cfg.nodes
    assert isinstance(cfg.get_edge(v0, v1), SwitchCase)
