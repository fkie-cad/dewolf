"""Module containing pipeline definitions for the decompiler."""
from __future__ import annotations

from logging import debug, error, warning
from typing import List

from decompiler.pipeline.controlflowanalysis.restructuring import PatternIndependentRestructuring
from decompiler.pipeline.preprocessing import (
    Coherence,
    CompilerIdiomHandling,
    InsertMissingDefinitions,
    MemPhiConverter,
    PhiFunctionFixer,
    RegisterPairHandling,
    RemoveStackCanary,
    SwitchVariableDetection,
)
from decompiler.pipeline.ssa.outofssatranslation import OutOfSsaTranslation
from decompiler.task import DecompilerTask
from decompiler.util.decoration import DecoratedAST, DecoratedCFG

from .default import AST_STAGES, CFG_STAGES
from .stage import PipelineStage

PREPROCESSING_STAGES = [
    CompilerIdiomHandling,
    RemoveStackCanary,
    RegisterPairHandling,
    Coherence,
    SwitchVariableDetection,
    MemPhiConverter,
    InsertMissingDefinitions,
    PhiFunctionFixer,
]

POSTPROCESSING_STAGES = [OutOfSsaTranslation, PatternIndependentRestructuring]


class DecompilerPipeline:
    """Basic decompiler pipleline interface."""

    def __init__(self, stages: List[PipelineStage]):
        """Generate a new Pipeline based on the given stages"""
        self._stages = stages

    @classmethod
    def from_strings(cls, cfg_stage_names: List[str], ast_stage_names: List[str]) -> DecompilerPipeline:
        """Generate a new pipeline composed of the stages referenced by name."""
        name_to_stage = {stage.name: stage for stage in CFG_STAGES + AST_STAGES}
        stages = PREPROCESSING_STAGES.copy()

        for stage_name in cfg_stage_names:
            if stage := name_to_stage.get(stage_name):
                stages.append(stage)
            else:
                warning(f'Could not find a CFG PipelineStage named "{stage_name}"')

        stages.extend(POSTPROCESSING_STAGES.copy())

        for stage_name in ast_stage_names:
            if stage := name_to_stage.get(stage_name):
                stages.append(stage)
            else:
                warning(f'Could not find a AST PipelineStage named "{stage_name}"')
        return cls(stages)

    @property
    def stages(self) -> List[PipelineStage]:
        return self._stages

    def validate(self):
        """Check if the pipeline stage dependencies are fulfilled."""
        stages_run = []
        for stage in self.stages:
            for dependency in stage.dependencies:
                if dependency not in stages_run:
                    raise ValueError(f"Invalid pipeline: {stage.name} requires {dependency}!")
            stages_run.append(stage.name)

    def run(self, task: DecompilerTask):
        """Run the pipeline on the given graph."""
        output_format = task.options.getstring("logging.stage_output")
        show_all = task.options.getboolean("logging.show_all_stages", fallback=False)
        show_starting_point = task.options.getboolean("logging.show_starting_point", fallback=False)
        showed_stages = task.options.getlist("logging.show_selected", fallback=[])
        print_ascii = output_format == "ascii" or output_format == "ascii_and_tabs"
        show_in_tabs = output_format == "tabs" or output_format == "ascii_and_tabs"

        self.validate()

        if show_starting_point:
            self._show_stage(task, "Starting point", print_ascii, show_in_tabs)

        if task.failed:
            return

        for stage in self.stages:
            debug(f"stage {stage.name}")
            instance = stage()
            try:
                instance.run(task)
                if show_all or stage.name in showed_stages:
                    self._show_stage(task, f"After {stage.name}", print_ascii, show_in_tabs)
            except Exception as e:
                task.fail(origin=stage.name)
                error(f"Failed to decompile {task.name}, error during stage {stage.name}: {e}")
                break

    @staticmethod
    def _show_stage(task: DecompilerTask, stage_name: str, print_ascii: bool, show_in_tabs: bool):
        """Based on the task either an AST or a CFG is shown on the console (ASCII) and/or in BinaryNinja (FlowGraph) tabs."""
        if task.syntax_tree is not None:
            if print_ascii:
                DecoratedAST.print_ascii(task.syntax_tree, f"(AST) {stage_name}")
            if show_in_tabs:
                DecoratedAST.show_flowgraph(task.syntax_tree, f"(AST) {stage_name}")
        elif task.graph is not None:
            if print_ascii:
                DecoratedCFG.print_ascii(task.graph, stage_name)
            if show_in_tabs:
                DecoratedCFG.show_flowgraph(task.graph, stage_name)
