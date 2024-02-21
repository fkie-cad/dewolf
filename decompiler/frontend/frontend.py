"""Module implementing the interface for different frontends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from decompiler.task import DecompilerTask
from decompiler.util.options import Options


class Frontend(ABC):
    """Interface for frontends to the Decompiler."""

    @classmethod
    @abstractmethod
    def from_raw(cls, data) -> Frontend:
        """
        Generate a frontend instance directly from the raw data.
        This allows to utilize established environments such as binary ninja views.

        data -- The data to be passed to the frontend
        """

    @classmethod
    @abstractmethod
    def from_path(cls, path: str, options: Options) -> Frontend:
        """
        Generate a new frontend with the given sample path.

        path -- The path to a sample whose functions shall be decompiled.
        options -- Options to pass to the frontend
        """

    @abstractmethod
    def lift(self, task: DecompilerTask):
        """Lift function data into task object."""

    @abstractmethod
    def get_all_function_names(self) -> List[str]:
        """Returns the entire list of all function names in the binary. Ignores blacklisted functions and imported functions."""
