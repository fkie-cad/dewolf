"""Tests for the pipeline system."""
import pytest
from dewolf.pipeline.default import AST_STAGES, CFG_STAGES
from dewolf.pipeline.pipeline import DecompilerPipeline
from dewolf.pipeline.stage import PipelineStage
from dewolf.task import DecompilerTask


class TestPipeline:
    """Class dedicated to run tests for pipeline objects."""

    class EmptyPipeline(DecompilerPipeline):
        """A Mock pipeline without any stages."""

        def __init__(self):
            super().__init__([])

    class EmptyTask(DecompilerTask):
        """An empty task mock object."""

        def __init__(self):
            """Just pass None values."""
            super().__init__(None, None)

        def reset(self):
            """Empty reset function so the fields can be set however."""
            pass

    class MockStage(PipelineStage):
        """Ab mock pipeline stage, doing nothing."""

        name = "mock"

        def __init__(self, name, dependencies):
            """Pass parameters for mock object."""
            self.name = name
            self._dependencies = dependencies

        @property
        def dependencies(self):
            return self._dependencies

        def run(self, task):
            pass

    def test_empty(self):
        """An empty pipeline should always work."""
        empty_pipeline = self.EmptyPipeline()
        empty_pipeline.run(self.EmptyTask())

    def test_default_valid(self):
        """The default pipeline should always be valid."""
        pipeline = DecompilerPipeline.from_strings([stage.__name__ for stage in CFG_STAGES], [stage.__name__ for stage in AST_STAGES])
        pipeline.validate()

    def test_dependencies(self):
        """Check if stage dependencies are correctly enforced."""
        stage_1 = self.MockStage("stage_1", [])
        stage_2 = self.MockStage("stage_2", ["stage_1"])
        # generate an invalid pipeline
        invalid_pipeline = DecompilerPipeline([stage_2, stage_1])
        with pytest.raises(ValueError) as _:
            invalid_pipeline.validate()
        # generate a valid pipeline
        valid_pipeline = DecompilerPipeline([stage_1, stage_2])
        valid_pipeline.validate()
