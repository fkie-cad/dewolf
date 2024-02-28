"""Module to find and declare function pointer variables"""

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.pseudo.instructions import Assignment, Variable
from decompiler.structures.pseudo.operations import Call
from decompiler.structures.pseudo.typing import FunctionPointer, Pointer
from decompiler.task import DecompilerTask


class FindFunctionPointer(PipelineStage):
    name = "find-function-pointer"

    def run(self, task: DecompilerTask):
        for block in task.graph:
            for expression in block:
                if (
                    isinstance(expression, Assignment)
                    and isinstance(expression.value, Call)
                    and isinstance(expression.value.function, Variable)
                ):
                    expression.value.function._type = Pointer(
                        basetype=FunctionPointer(
                            size=expression.value.function.type.size,
                            return_type=expression.value.function.type,
                            parameters=tuple(expression.value.parameters),
                        ),
                    )
