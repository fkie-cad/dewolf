"""Interface for frontend lifters."""
from abc import ABC, abstractmethod
from typing import Callable, Dict, Type, TypeVar

from decompiler.structures.pseudo import Expression


class Lifter(ABC):
    """Represents a basic lifter emmiting decompiler IR."""

    @abstractmethod
    def lift(self, expression, **kwargs) -> Expression:
        """Lift the given expression to pseudo IR."""


T = TypeVar("T")
V = TypeVar("V")


class ObserverLifter(Lifter):
    """Base class for lifters following the observer-pattern."""

    HANDLERS: Dict[Type[T], Callable[[T], V]] = {}

    def __init__(self):
        self.complex_types = {}

    def lift(self, expression: T, **kwargs) -> V:
        """Lift the given expression based on the registered handlers."""
        handler = self.HANDLERS.get(expression.__class__, self.lift_unknown)
        return handler(expression)

    @abstractmethod
    def lift_unknown(self, expression: T) -> V:
        """Handle an expression when there is no registered handler for it."""

    @property
    @abstractmethod
    def is_omitting_masks(self) -> bool:
        """Indicate whatever bitmasks should be omitted when possible."""


class Handler:
    """Base class for handlers to be registered in an ObserverLifter."""

    HANDLERS: Dict[Type[T], Callable[[T], V]] = {}
    BYTE_SIZE = 8

    def __init__(self, lifter: ObserverLifter):
        self._lifter = lifter
