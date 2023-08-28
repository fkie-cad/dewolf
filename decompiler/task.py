"""Module describing tasks to be handled by the decompiler pipleline."""
from typing import Dict, List, Optional

from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.complextypes import ComplexTypeMap
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.typing import Integer, Type
from decompiler.util.options import Options


class DecompilerTask:
    """Represents a task for the decompiler pipeline."""

    def __init__(
        self,
        name: str,
        cfg: ControlFlowGraph = None,
        ast: Optional[AbstractSyntaxTree] = None,
        options: Optional[Options] = None,
        function_return_type: Type = Integer(32),
        function_parameters: Optional[List[Variable]] = None,
        complex_types: Optional[ComplexTypeMap] = None
    ):
        """
        Init a new decompiler task.

        :param name -- The name of the function or task
        :param cfg -- The control flow graph of the function
        :param function_return_type -- The type of the return value of the decompiled function
        :param function_parameters -- List of function parameters as Variables
        """
        self._name = name
        self._cfg = cfg
        self._ast = ast
        self._function_return_type = function_return_type
        self._function_parameters = function_parameters if function_parameters else []
        self._options: Options = options if options else Options.load_default_options()
        self._failed = False
        self._failure_origin = None
        self._complex_types = complex_types if complex_types else ComplexTypeMap()

    @property
    def name(self) -> str:
        """Return the name of the task."""
        return self._name

    @property
    def graph(self) -> ControlFlowGraph:
        """Return a graph representing the function control flow."""
        return self._cfg

    @property
    def syntax_tree(self) -> AbstractSyntaxTree:
        """Return a syntax tree representing the function."""
        return self._ast

    @property
    def function_return_type(self) -> Type:
        """Return the type of the variable returned by the function."""
        return self._function_return_type

    @property
    def function_parameters(self) -> List[Variable]:
        """Return a list of parameters usually passed to the function."""
        return self._function_parameters

    @property
    def options(self) -> Options:
        """Options for various pipeline stages of the task."""
        return self._options

    @options.setter
    def options(self, value: Options):
        """Setter function for task options."""
        self._options = value

    @property
    def failed(self) -> bool:
        """Returns True if an error occurred during a decompilation stage.

        A failed tasks will not produce valid decompiled code but an error message will be shown."""
        return self._failed

    def fail(self, origin: str = None):
        """Sets the task to failed and the origin to the name of the stage where failure occurred."""
        self._failed = True
        self._failure_origin = origin

    @property
    def failure_message(self) -> str:
        """Returns the message to be shown for a failed task."""
        msg = f"Failed to decompile"
        if self._failure_origin:
            msg += f" due to error during {self._failure_origin}."
        return msg

    @property
    def complex_types(self) -> ComplexTypeMap:
        """Return complex types present in the function (structs, unions, enums, etc.)."""
        return self._complex_types
