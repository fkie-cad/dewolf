"""Module to find and declare function pointer variables"""

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.pseudo.instructions import Assignment, Variable
from decompiler.structures.pseudo.operations import Call
from decompiler.structures.pseudo.typing import FunctionTypeDef, Pointer
from decompiler.task import DecompilerTask


class FindFunctionPointer(PipelineStage):
    """Pipeline stage to identify and annotate function pointers in the decompiled code."""

    name = "find-function-pointer"

    def run(self, task: DecompilerTask):
        """
        Run the pipeline stage in the given task, search in all expressions for a
        variable that is called and adjust its type information.
        """
        for block in task.graph:
            for expression in block:
                if (
                    isinstance(expression, Assignment)
                    and isinstance(expression.value, Call)
                    and isinstance(expression.value.function, Variable)
                ):
                    expression.value.function._type = Pointer(
                        basetype=FunctionTypeDef(
                            size=expression.value.function.type.size,
                            return_type=expression.value.function.type,
                            parameters=tuple(expression.value.parameters),
                        ),
                    )
