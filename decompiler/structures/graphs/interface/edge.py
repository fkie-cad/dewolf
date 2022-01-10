"""Module defining the edge interface linking node objects."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic, Optional, TypeVar

if TYPE_CHECKING:
    from decompiler.structures.graphs.interface import GraphNodeInterface

NODE = TypeVar("NODE", bound="GraphNodeInterface")


class GraphEdgeInterface(ABC, Generic[NODE]):
    """Interface for graph edges."""

    @property
    @abstractmethod
    def source(self) -> NODE:
        """Return the origin of the edge."""

    @property
    @abstractmethod
    def sink(self) -> NODE:
        """Return the target of the edge."""

    @abstractmethod
    def __eq__(self, other) -> bool:
        """Check whether two edges are equal."""

    @abstractmethod
    def copy(self, source: Optional[NODE] = None, sink: Optional[NODE] = None) -> GraphEdgeInterface:
        """
        Copy the edge, returning a new object.
        source -- (optional) The new source of the copied edge.
        sink -- (optional) The new sink of the copied edge.
        """
