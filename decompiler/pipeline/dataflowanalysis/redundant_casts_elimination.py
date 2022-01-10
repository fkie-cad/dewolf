from typing import Optional

from decompiler.pipeline.commons.cast_simplification_functions import simplify_casts_in_instruction
from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.task import DecompilerTask

MAX_REGISTER_SIZE = 64


class RedundantCastsElimination(PipelineStage):
    name = "redundant-casts-elimination"

    def __init__(self):
        self.cfg: Optional[ControlFlowGraph] = None

    def run(self, task: DecompilerTask):
        self.cfg = task.graph
        for instr in self.cfg.instructions:
            simplify_casts_in_instruction(instr)
