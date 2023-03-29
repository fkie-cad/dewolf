import re
from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Optional

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.ast.ast_nodes import CaseNode, CodeNode, ConditionNode, LoopNode, SwitchNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.pseudo import CustomType, DataflowObject, Float, GlobalVariable, Integer, Pointer, Type, Variable
from decompiler.task import DecompilerTask


def _get_var_counter(var_name: str) -> Optional[str]:
    """Return the counter of a given variable name, if any is present."""
    if counter := re.match(r".*?([0-9]+)$", var_name):
        return counter.group(1)
    return None


def _get_containing_variables(dfo: DataflowObject) -> List[Variable]:
    """Returns a list of variables contained in this dataflow object."""
    variables: List[Variable] = []
    for sub_exp in dfo.subexpressions():
        if isinstance(sub_exp, Variable):
            variables.append(sub_exp)
    return variables


class NamingConvention(str, Enum):
    """Enum for the currently available naming conventions."""
    default = "default"
    system_hungarian = "system_hungarian"


class RenamingScheme(ABC):
    """Base class for different Renaming schemes."""

    def __init__(self, task: DecompilerTask) -> None:
        self._ast: AbstractSyntaxTree = task._ast
        self._variables: List[Variable] = []
        self._loop_vars : List[Variable] = []
        self._params: List[Variable] = task._function_parameters


    def _filter_variables(self, item: Variable) -> bool:
        """Return False if variable is a parameter, renamed loop variable or GlobalVariable, else True"""
        if item in self._params or (item in self._loop_vars and item.name.find("var_") == -1) or isinstance(item, GlobalVariable):
            return False
        return True


    def collectVariableNames(self):
        """Collects all variables and loop variable by iterating over every node in the AST and removing ones which should not be renamed:
            - fkt parameter
            - loop variables which have been renamed by For/WhileLoopRenamer
            - global variables
        """
        for node in self._ast.topological_order():
            if isinstance(node, CodeNode):
                for stmt in node.instructions:
                    self._variables.extend(_get_containing_variables(stmt))
            elif isinstance(node, (ConditionNode, LoopNode)):
                for expr in [self._ast.condition_map[symbol] for symbol in node.condition.get_symbols()]:
                    self._variables.extend(_get_containing_variables(expr))
            elif isinstance(node, (SwitchNode, CaseNode)):
                self._variables.extend(_get_containing_variables(node.expression))     
        
        for node in self._ast.get_loop_nodes_post_order():
            for expr in [self._ast.condition_map[symbol] for symbol in node.condition.get_symbols()]:
                self._loop_vars.extend(_get_containing_variables(expr))
            
        self._variables = list(filter(self._filter_variables, self._variables))  


    @abstractmethod
    def renameVariableNames(self):
        """Abstract method which should rename variables with respect to the used scheme."""
        pass


class HungarianScheme(RenamingScheme):
    """Class which renames variables into hungarian notation."""

    type_prefix = {
        Float: {16: "h", 32: "f", 64: "d", 80: "ld", 128: "q", 256: "o"},
        Integer: {8: "ch", 16: "s", 32: "i", 64: "l", 128: "i128"},
    }


    def __init__(self, task: DecompilerTask) -> None:
        super().__init__(task)
        self._name = VariableNameGeneration.name
        self._var_name: str = task.options.getstring(f"{self._name}.variable_name", fallback="Var")
        self._pointer_base: bool = task.options.getboolean(f"{self._name}.pointer_base", fallback=True)
        self._type_separator: str = task.options.getstring(f"{self._name}.type_separator", fallback="")
        self._counter_separator: str = task.options.getstring(f"{self._name}.counter_separator", fallback="")
    

    def renameVariableNames(self):
        """Rename all collected variables to the hungarian notation."""
        for var in self._variables:
            counter = _get_var_counter(var.name)
            var._name = self._hungarian_notation(var, counter if counter else "")
            

    def _hungarian_notation(self, var: Variable, counter: int) -> str:
        """Return hungarian notation to a given variable."""
        return f"{self._hungarian_prefix(var.type)}{self._type_separator}{self._var_name}{self._counter_separator}{counter}"


    def _hungarian_prefix(self, var_type: Type) -> str:
        """Return hungarian prefix to a given variable type."""
        if isinstance(var_type, Pointer):
            if self._pointer_base:
                return f"{self._hungarian_prefix(var_type.type)}p"
            return "p"
        if isinstance(var_type, CustomType):
            if var_type.is_boolean:
                return "b"
            elif var_type.size == 0:
                return "v"
        if isinstance(var_type, (Integer, Float)):
            sign = "" if var_type.is_signed else "u"
            prefix = self.type_prefix[type(var_type)][var_type.size]
            return f"{sign}{prefix}"


class DefaultScheme(RenamingScheme):
    """Class which renames variables into the default scheme."""

    def __init__(self, task: DecompilerTask) -> None:
        super().__init__(task)


    def renameVariableNames(self):
        # Maybe make the suboptions more generic, so that the default scheme can also be changed by some parameters?
        pass


class VariableNameGeneration(PipelineStage):
    """ 
    Pipelinestage in charge of renaming variables to a configured format.
    Currently only the 'default' or 'hungarian' system are supported.
    """

    name : str = "variable-name-generation"

    def __init__(self):
        self._notation: str = None


    def run(self, task: DecompilerTask):
        """Rename variable names to the given scheme."""
        self._notation = task.options.getstring(f"{self.name}.notation", fallback="default")

        renamer: RenamingScheme = None

        match self._notation:
            case NamingConvention.default:
                renamer = DefaultScheme(task)
            case NamingConvention.system_hungarian:
                renamer = HungarianScheme(task)
            case _:
                return

        renamer.collectVariableNames()
        renamer.renameVariableNames()
