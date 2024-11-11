"""Module describing tasks to be handled by the decompiler pipleline."""

from dataclasses import dataclass, field
from logging import error
from typing import List, Optional

from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo import Integer
from decompiler.structures.pseudo.complextypes import ComplexTypeMap
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.typing import Type
from decompiler.util.options import Options


# We set eq=False, so that tasks are only equal when they are the very same instance
@dataclass(eq=False)
class DecompilerTask:
    """Represents a task for the decompiler pipeline."""

    name: str
    # We allow fronted specific identifiers here. The fronted should check if it can handle a specific type of identifier
    function_identifier: object
    options: Options = field(default_factory=Options.load_default_options)
    cfg: ControlFlowGraph | None = None
    ast: AbstractSyntaxTree | None = None
    function_return_type: Type = Integer.int32_t()
    function_parameters: List[Variable] = field(default_factory=list)
    complex_types: ComplexTypeMap = field(default_factory=ComplexTypeMap)

    _failure_origin: str | None = field(default=None, init=False)

    # Property for backwards compatibility. Previous code used self._cfg, which is now public.
    @property
    def graph(self):
        return self.cfg

    # Property for backwards compatibility. Previous code used self._ast, which is now public.
    @property
    def syntax_tree(self):
        return self.ast

    def fail(self, origin: str = "", exception: Optional[Exception] = None):
        """Sets the task to be failed by setting the failure origin."""
        if self.failure_origin is not None:
            raise RuntimeError("Tried failing already failed task")

        self._failure_origin = origin
        error(f"Failed to decompile {self.name}, error during stage {origin}: {exception}")

    @property
    def failed(self) -> bool:
        """
        Returns True if an error occurred during decompilation.
        A failed task is a task that did not properly finish and is left in an undefined state.
        Therefore, no valid decompiled code can be generated from it.
        """
        return self._failure_origin is not None

    @property
    def failure_origin(self) -> str | None:
        return self._failure_origin
