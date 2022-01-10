"""Module defining the interface for rooted graphs."""
from abc import ABC, abstractmethod
from typing import Optional

from decompiler.structures.graphs.interface.graph import EDGE, NODE, GraphInterface


class RootedGraphInterface(GraphInterface[NODE, EDGE], ABC):
    """An interface for graph buffering an dominator tree."""

    @property  # type: ignore
    @abstractmethod
    def root(self) -> Optional[NODE]:
        """Return the root of the graph (if any)."""

    @root.setter  # type: ignore
    @abstractmethod
    def root(self, value: NODE):
        """Set the root of the graph."""

    @property
    @abstractmethod
    def dominator_tree(self) -> GraphInterface:
        """Return the dominator tree of the graph."""

    @abstractmethod
    def is_dominating(self, dominator: NODE, dominated: NODE) -> bool:
        """Check whether one node is dominating the other."""

    @abstractmethod
    def find_common_dominator(self, *nodes: NODE) -> Optional[NODE]:
        """Return a common dominator of the given nodes, if any."""
