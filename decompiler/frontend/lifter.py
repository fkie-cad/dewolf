"""Interface for frontend lifters."""
from abc import ABC, abstractmethod
from typing import Type, TypeVar, Callable, Dict

from decompiler.structures.pseudo import Expression


class Lifter(ABC):
    """Represents a basic lifter emmiting decompiler IR."""

    @abstractmethod
    def lift(self, expression, **kwargs) -> Expression:
        """Lift the given expression to pseudo IR."""


T = TypeVar("T")
V = TypeVar("V")


class ObserverLifter(Lifter):

    HANDLERS: Dict[Type[T], Callable[[T], V]] = {}

    def lift(self, expression: T, **kwargs) -> V:
        handler = self.HANDLERS.get(type(expression), self.lift_unknown)
        return handler(expression)

    @abstractmethod
    def lift_unknown(self, expression: T) -> V:
        pass


class Handler:

    HANDLERS: Dict[Type[T], Callable[[T], V]] = {}
    BYTE_SIZE = 8

    def __init__(self, lifter: ObserverLifter):
        self._lifter = lifter
