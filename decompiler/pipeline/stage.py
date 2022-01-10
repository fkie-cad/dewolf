"""Module implementing the PipelineStage interface."""
from abc import ABC, abstractmethod

from decompiler.task import DecompilerTask


class PipelineStage(ABC):
    """Interface for any pipeline stage."""

    # Pipeline stages which this stage depends on
    dependencies = []

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of the pipeline stage."""
        pass

    @abstractmethod
    def run(self, task: "DecompilerTask"):
        """Run the stage on the given task, transforming its content."""
        pass
