"""Module defining the most basic node interface."""
from __future__ import annotations

from abc import ABC, abstractmethod


class GraphNodeInterface(ABC):
    """Basic Interface for graph nodes."""

    @abstractmethod
    def __str__(self) -> str:
        """Return a string representation."""

    @abstractmethod
    def __eq__(self, other) -> bool:
        """Graph nodes should be equal for equal content."""

    @abstractmethod
    def __hash__(self) -> int:
        """Graph nodes should always have an unique hash."""

    @abstractmethod
    def copy(self) -> GraphNodeInterface:
        """Return a copy of the graph node."""
