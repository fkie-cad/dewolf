"""Module defining the various branches between BasicBlocks used in ControlFlowGraphs."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Iterator, List, Optional

from decompiler.structures.graphs.interface import GraphEdgeInterface
from decompiler.structures.pseudo import Branch, Constant, Expression

if TYPE_CHECKING:
    from decompiler.structures.graphs.cfg import BasicBlock


class BasicBlockEdgeCondition(Enum):
    """Enum for different types of basic block edges."""

    unconditional = "unconditional"
    true = "true"
    false = "false"
    indirect = "indirect"
    switch = "switch"


class BasicBlockEdge(GraphEdgeInterface, ABC):
    """Class representing an edge between basic blocks."""

    def __init__(self, source: BasicBlock, sink: BasicBlock):
        """
        Init an new basic block edge based on start, end and type.

        source -- The start of the edge
        sink -- The end of the edge
        """
        self._source = source
        self._sink = sink

    @property
    def source(self) -> BasicBlock:
        """Return the start of the edge."""
        return self._source

    @property
    def sink(self) -> BasicBlock:
        """Return the target of the edge."""
        return self._sink

    def __eq__(self, other):
        """Check if two basic block edges have the same start and end points."""
        return isinstance(other, type(self)) and self.__dict__ == other.__dict__

    def __hash__(self) -> int:
        """Return an unique hash for the given edge."""
        return hash((self.source, self.sink, self.condition_type))

    def __iter__(self) -> Iterator[Expression]:
        """Iterate all subexpressions present in the edge data."""
        yield from []

    def substitute(self, replacee: Expression, repleacement: Expression):
        """Substitute all expression references in the edge matching the given replacee."""
        pass

    @property
    @abstractmethod
    def condition_type(self) -> BasicBlockEdgeCondition:
        """Return the type of the basic block edge (legacy)."""
        pass

    def copy(self, source: Optional[BasicBlock] = None, sink: Optional[BasicBlock] = None) -> BasicBlockEdge:
        """
        Copy the edge, returning a new object.
        source -- (optional) The new source of the copied edge.
        sink -- (optional) The new sink of the copied edge.
        """
        return self.__class__(source if source is not None else self._source, sink if sink is not None else self._sink)


class UnconditionalEdge(BasicBlockEdge):
    """Class representing an unconditional edge between basic blocks."""

    @property
    def condition_type(self) -> BasicBlockEdgeCondition:
        """Unconditional edges are unconditional."""
        return BasicBlockEdgeCondition.unconditional


class ConditionalEdge(BasicBlockEdge):
    """Base class for conditional edges."""

    @property
    def branch_instruction(self) -> Branch:
        """Return the branch instruction of the conditional edge."""
        return self._source.instructions[-1]


class IndirectEdge(ConditionalEdge):
    """Class representing an indirect edge, such as JMP eax."""

    @property
    def expression(self):
        """Return the expression of the indirect branch."""
        return self._source.instructions[-1].expression

    @property
    def condition_type(self) -> BasicBlockEdgeCondition:
        """Indirect edges are indirect."""
        return BasicBlockEdgeCondition.indirect

    def __iter__(self) -> Iterator[Expression]:
        """Yield the expression determining the target of the edge."""
        yield self.expression


class TrueCase(ConditionalEdge):
    """Class representing the true-branch of an condition."""

    @property
    def condition_type(self) -> BasicBlockEdgeCondition:
        """True cases are true."""
        return BasicBlockEdgeCondition.true


class FalseCase(ConditionalEdge):
    """Class representing the false-branch of an condition."""

    @property
    def condition_type(self) -> BasicBlockEdgeCondition:
        """False cases are false."""
        return BasicBlockEdgeCondition.false


class SwitchCase(IndirectEdge):
    """Class representing an edge based on a switch case."""

    def __init__(self, source: BasicBlock, sink: BasicBlock, cases: List[Constant]):
        """Init a new switch edge based on the switched variable and the case values."""
        super(SwitchCase, self).__init__(source, sink)
        self._cases: List[Constant] = cases

    @property
    def cases(self) -> List[Constant]:
        """Return a list of Constants triggering this case."""
        return self._cases

    @cases.setter
    def cases(self, cases: List[Constant]):
        """Set the list of instructions."""
        assert all(isinstance(case, Constant) for case in cases)
        self._cases = cases

    @property
    def condition_type(self) -> BasicBlockEdgeCondition:
        """Switch cases are switch."""
        return BasicBlockEdgeCondition.switch

    def copy(
        self, source: Optional[BasicBlock] = None, sink: Optional[BasicBlock] = None, cases: Optional[List[Constant]] = None
    ) -> SwitchCase:
        """
        Copy the edge, returning a new object.
        source -- (optional) The new source of the copied edge.
        sink -- (optional) The new sink of the copied edge.
        cases -- (optional) The new list of case constants associated.
        """
        return SwitchCase(
            source if source is not None else self._source,
            sink if sink is not None else self._sink,
            cases if cases is not None else [x.copy() for x in self._cases],
        )
