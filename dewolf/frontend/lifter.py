"""Interface for frontend lifters."""
from abc import ABC, abstractmethod

from dewolf.structures.pseudo import Expression


class Lifter(ABC):
    """Represents a basic lifter emmiting decompiler IR."""

    @abstractmethod
    def lift(self, expression) -> Expression:
        """Lift the given expression to pseudo IR."""
