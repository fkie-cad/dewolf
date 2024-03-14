"""Module describing tasks to be handled by the decompiler pipleline."""

from dataclasses import dataclass, field
from typing import List

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

    # Properties for backwards compatibility. Previous code used these properties to access self._ast/self._cfg, which are now public.
    graph = property(lambda self: self.cfg, lambda self, v: setattr(self, "cfg", v))
    syntax_tree = property(lambda self: self.ast, lambda self, v: setattr(self, "ast", v))

    def fail(self, origin: str = ""):
        """Sets the task to be failed by setting the failure origin."""
        if self.failure_origin is not None:
            raise RuntimeError("Tried failing already failed task")

        self._failure_origin = origin

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
