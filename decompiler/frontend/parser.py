"""Module defining the parser interface."""
from abc import ABC, abstractmethod

from decompiler.structures.graphs.cfg import ControlFlowGraph


class Parser(ABC):
    """Class providing the basic interface for frontend parsers."""

    @abstractmethod
    def parse(self, function) -> ControlFlowGraph:
        """Generate a ControlFlowGraph from the given function object."""
        pass
