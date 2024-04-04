"""Module implementing basic nodes based on aa given (printable) python object."""

from __future__ import annotations

from typing import Any

from .interface import GraphEdgeInterface, GraphNodeInterface


class BasicNode(GraphNodeInterface):
    """Basic node implementation for testing purposes."""

    def __init__(self, value: Any = None):
        """Initialize an node based on the given Value."""
        self._value = value

    def __str__(self) -> str:
        """Return a string representation of the node."""
        return str(self._value)

    def __repr__(self) -> str:
        """Return a representation for debug purposes."""
        return f"Node({str(self)})"

    def __eq__(self, other) -> bool:
        """Check equality based on the string representation."""
        return isinstance(other, BasicNode) and self._value == other._value

    def __hash__(self) -> int:
        """Return an unique hash value for the node."""
        return hash(self._value)

    def copy(self) -> BasicNode:
        """Return a new object with the same value."""
        return BasicNode(self._value)


class BasicEdge(GraphEdgeInterface):
    """A basic edge implementation for various purposes."""

    def __init__(self, source: GraphNodeInterface, sink: GraphNodeInterface):
        """Init an edge just based on source and sink."""
        self._source: GraphNodeInterface = source
        self._sink: GraphNodeInterface = sink

    @property
    def source(self) -> GraphNodeInterface:
        """Return the source of the edge."""
        return self._source

    @property
    def sink(self) -> GraphNodeInterface:
        """Return the sink of the edge."""
        return self._sink

    def __eq__(self, other) -> bool:
        """Check whether two edges are equal."""
        return other is not None and self.__dict__ == other.__dict__

    def copy(self, source: GraphNodeInterface = None, sink: GraphNodeInterface = None) -> GraphEdgeInterface:
        """
        Copy the edge, returning a new object.
        source -- (optional) The new source of the copied edge.
        sink -- (optional) The new sink of the copied edge.
        """
        return BasicEdge(source if source is not None else self._source, sink if sink is not None else self._sink)

    def __hash__(self) -> int:
        """Return an unique hash value for the node."""
        return hash(
            (
                hash(self._source),
                hash(self._sink),
            )
        )
