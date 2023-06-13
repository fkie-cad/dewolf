import re
from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, List, Optional, Set

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.ast.ast_nodes import ConditionNode, LoopNode
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import Condition, CustomType, DataflowObject, Float, GlobalVariable, Integer, Pointer, Type, Variable
from decompiler.structures.visitors.ast_dataflowobjectvisitor import BaseAstDataflowObjectVisitor
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


class VariableCollector(BaseAstDataflowObjectVisitor):
    """Visit relevant nodes and collect their variables."""

    def __init__(self, cond_map: Dict[LogicCondition, Condition]):
        self._cond_map: Dict[LogicCondition, Condition] = cond_map
        self._loop_vars: list[Variable] = []
        self._variables: list[Variable] = []

    def get_variables(self) -> list[Variable]:
        """Get collected variables."""
        return self._variables

    def get_loop_variables(self) -> list[Variable]:
        """Get collected variables used in loops."""
        return self._loop_vars

    def visit_condition_node(self, node: ConditionNode):
        for expr in [self._cond_map[symbol] for symbol in node.condition.get_symbols()]:
            self._variables.extend(_get_containing_variables(expr))

    def visit_loop_node(self, node: LoopNode):
        for expr in [self._cond_map[symbol] for symbol in node.condition.get_symbols()]:
            self._loop_vars.extend(_get_containing_variables(expr))

    def visit_variable(self, expression: Variable):
        self._variables.append(expression)


class NamingConvention(str, Enum):
    """Enum for the currently available naming conventions."""
    default = "default"
    system_hungarian = "system_hungarian"


class RenamingScheme(ABC):
    """Base class for different Renaming schemes."""

    def __init__(self, task: DecompilerTask) -> None:
        """Collets all needed variables for renaming + filters already renamed + function arguments out"""
        collector = VariableCollector(task._ast.condition_map)
        collector.visit_ast(task._ast)
        self._params: List[Variable] = task._function_parameters
        self._loop_vars : List[Variable] = collector.get_loop_variables()
        self._variables: List[Variable] = list(filter(self._filter_variables, collector.get_variables()))
        

    def _filter_variables(self, item: Variable) -> bool:
        """Return False if variable is either a:
            - parameter
            - renamed loop variable
            - GlobalVariable
        """
        return not item in self._params and not (item in self._loop_vars and item.name.find("var_") == -1) and not isinstance(item, GlobalVariable)


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

    custom_var_names = {
        "tmp_": "Tmp"
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
            if self.alread_renamed(var._name):
                continue
            counter = _get_var_counter(var.name)
            var._name = self._hungarian_notation(var, counter if counter else "")
            

    def _hungarian_notation(self, var: Variable, counter: int) -> str:
        """Return hungarian notation to a given variable."""
        return f"{self._hungarian_prefix(var.type)}{self._type_separator}{self.custom_var_names.get(var._name.rstrip(counter), self._var_name)}{self._counter_separator}{counter}"


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
            sign = "" if var_type.is_signed else "u"
            prefix = self.type_prefix[type(var_type)].get(var_type.size, "unk")
            return f"{sign}{prefix}"
        return ""


    def alread_renamed(self, name) -> bool: 
        """Return true if variable with custom name was already renamed, false otherwise"""
        renamed_keys_words = [key for key in self.custom_var_names.values()] + ["unk", self._var_name]
        return any(keyword in name for keyword in renamed_keys_words)

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

        renamer.renameVariableNames()
