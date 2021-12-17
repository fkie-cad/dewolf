from typing import Optional

from dewolf.pipeline.commons.cast_simplification_functions import simplify_casts_in_instruction
from dewolf.pipeline.stage import PipelineStage
from dewolf.structures.graphs.cfg import ControlFlowGraph
from dewolf.task import DecompilerTask

MAX_REGISTER_SIZE = 64


class RedundantCastsElimination(PipelineStage):
    name = "redundant-casts-elimination"

    def __init__(self):
        self.cfg: Optional[ControlFlowGraph] = None

    def run(self, task: DecompilerTask):
        self.cfg = task.graph
        for instr in self.cfg.instructions:
            simplify_casts_in_instruction(instr)
