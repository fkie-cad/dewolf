import re
from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Optional, Set

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.pseudo import CustomType, Float, GlobalVariable, Integer, Pointer, Type, Variable
from decompiler.structures.visitors.ast_dataflowobjectvisitor import BaseAstDataflowObjectVisitor
from decompiler.task import DecompilerTask



def _get_var_counter(var_name: str) -> Optional[str]:
    """Return the counter of a given variable name, if any is present."""
    if counter := re.match(r".*?([0-9]+)$", var_name):
        return counter.group(1)
    return None


class VariableCollector(BaseAstDataflowObjectVisitor):
    """Collect all variables in nodes/expressions"""

    def __init__(self):
        self._variables: List[Variable] = []

    def get_variables(self) -> list[Variable]:
        """Get collected variables."""
        return self._variables

    def visit_variable(self, expression: Variable):
        """Add visited variables to list"""
        self._variables.append(expression)


class NamingConvention(str, Enum):
    """Enum for the currently available naming conventions."""

    default = "default"
    system_hungarian = "system_hungarian"


class RenamingScheme(ABC):
    """Base class for different Renaming schemes."""

    def __init__(self, task: DecompilerTask) -> None:
        """Collets all needed variables for renaming + filters which should not be renamed"""
        collector = VariableCollector()
        collector.visit_ast(task._ast)
        self._ast = task._ast
        self._params: List[Variable] = task._function_parameters
        self._variables: Set[Variable] = set(filter(self._filter_variables, collector.get_variables()))
        

    def _filter_variables(self, item: Variable) -> bool:
        """Return False if variable is either a:
            - parameter
            - GlobalVariable
        """
        return not item in self._params and not isinstance(item, GlobalVariable)


    def renameVariables(self):
        """Rename all collected variables with a naming scheme."""
        for var in self._variables:
            self._ast.replace_variable_in_subtree(self._ast.root, var, Variable(self.getVariableName(var), var.type, is_aliased=var.is_aliased, ssa_name=var.ssa_name))


    @abstractmethod
    def getVariableName(self, var: Variable) -> str:
        "Should return a new name of a variable based on the old name and the counter"
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
        self._pointer_base: bool = task.options.getboolean(f"{self._name}.pointer_base", fallback=True)
        self._type_separator: str = task.options.getstring(f"{self._name}.type_separator", fallback="")
        self._counter_separator: str = task.options.getstring(f"{self._name}.counter_separator", fallback="")
        self._variable_counter_dic: dict[Variable, Integer] = {}
        self._counter: Integer = 0
            

    def _get_counter(self, var: Variable) -> Integer:
        """Look up if variable already has a counter, if not assign new one"""
        if var not in self._variable_counter_dic:
            self._variable_counter_dic[var] = self._counter
            self._counter += 1      
        return self._variable_counter_dic[var]


    def _get_name_identifier(self, name: str) -> str:
        """Return identifier for hungarian notation."""
        return "Var"


    def getVariableName(self, var: Variable) -> str:
        """Return hungarian notation to a given variable."""
        return f"{self._hungarian_prefix(var.type)}{self._type_separator}{self._get_name_identifier(var._name)}{self._counter_separator}{self._get_counter(var.name)}"

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
            else:
                return ""
        if isinstance(var_type, (Integer, Float)):
            sign = "u" if isinstance(var_type, Integer) and not var_type.is_signed else ""
            prefix = self.type_prefix[type(var_type)].get(var_type.size, "unk")
            return f"{sign}{prefix}"
        return ""


class VariableNameGeneration(PipelineStage):
    """
    Pipelinestage in charge of renaming variables to a configured format.
    Currently only the 'default' or 'hungarian' system are supported.
    """

    name: str = "variable-name-generation"

    def __init__(self):
        self._notation: str = None

    def run(self, task: DecompilerTask):
        """Rename variable names to the given scheme."""
        self._notation = task.options.getstring(f"{self.name}.notation", fallback="default")
        renamer: RenamingScheme = None

        match self._notation:
            case NamingConvention.system_hungarian:
                renamer = HungarianScheme(task)
            case _: # Implicit default convention, will not rename anything
                return

        renamer.renameVariables()
