"""Module describing tasks to be handled by the decompiler pipleline."""
from typing import List, Optional

from dewolf.structures.ast.syntaxtree import AbstractSyntaxTree
from dewolf.structures.graphs.cfg import ControlFlowGraph
from dewolf.structures.pseudo.expressions import Variable
from dewolf.structures.pseudo.typing import Integer, Type
from dewolf.util.options import Options


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
