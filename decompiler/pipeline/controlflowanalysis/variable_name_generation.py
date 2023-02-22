import re
from enum import Enum
from typing import List, Optional

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.ast.ast_nodes import CaseNode, CodeNode, ConditionNode, LoopNode, SwitchNode, ForLoopNode, WhileLoopNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.pseudo import CustomType, DataflowObject, Float, Integer, Pointer, Type, Variable, GlobalVariable
from decompiler.task import DecompilerTask


def _get_var_counter(var_name: str) -> Optional[str]:
    if counter := re.match(r".*?([0-9]+)$", var_name):
        return counter.group(1)
    return None


def _get_containing_variables(dfo: DataflowObject) -> List[Variable]:
    """Returns a list of variables contained in this dataflow object"""
    variables: List[Variable] = []

    for sub_exp in dfo.subexpressions():
        if isinstance(sub_exp, Variable):
            variables.append(sub_exp)

    return variables


class NamingConvention(str, Enum):
    default = "default"
    system_hungarian = "system_hungarian"


class VariableNameGeneration(PipelineStage):
    """Pipelinestage in charge of renaming variables to a configured format."""

    name : str = "variable-name-generation"
    type_prefix = {
        Float: {16: "h", 32: "f", 64: "d", 80: "ld", 128: "q", 256: "o"},
        Integer: {8: "ch", 16: "s", 32: "i", 64: "l", 128: "i128"},
    }


    def __init__(self):
        self._ast: Optional[AbstractSyntaxTree] = None
        self._notation: Optional[str] = None
        self._var_name: Optional[str] = None
        self._pointer_base: bool = True
        self._type_separator: str = ""
        self._counter_separator: str = ""
        self._variables: List[Variable] = []
        self._variable_blacklist : List[str] = []


    def run(self, task: DecompilerTask):
        self._ast = task.syntax_tree
        self._notation = task.options.getstring(f"{self.name}.notation", fallback="default")
        self._var_name = task.options.getstring(f"{self.name}.variable_name", fallback="Var")
        self._pointer_base = task.options.getboolean(f"{self.name}.pointer_base", fallback=True)
        self._type_separator = task.options.getstring(f"{self.name}.type_separator", fallback="")
        self._counter_separator = task.options.getstring(f"{self.name}.counter_separator", fallback="")
        self._variable_blacklist = [param.name for param in task.function_parameters]

        if self._notation != NamingConvention.default:
            self._collect()
            self._purge()
            self._rename()


    def _collect(self):
        for node in self._ast.topological_order():
            if isinstance(node, CodeNode):
                for stmt in node.instructions:
                    self._variables.extend(_get_containing_variables(stmt))
            elif isinstance(node, (ConditionNode, LoopNode)):
                for expr in [self._ast.condition_map[symbol] for symbol in node.condition.get_symbols()]:
                    self._variables.extend(_get_containing_variables(expr))
            elif isinstance(node, (SwitchNode, CaseNode)):
                self._variables.extend(_get_containing_variables(node.expression))         


    def _purge(self):
        for node in self._ast.topological_order():
            if isinstance(node, (LoopNode)):
                for expr in [self._ast.condition_map[symbol] for symbol in node.condition.get_symbols()]:
                    y = _get_containing_variables(expr)
                self._variables = [x for x in self._variables if x not in y]
        for var in self._variables:
            if var.name in self._variable_blacklist:
                self._variables.remove(var)
        

    def _rename(self):
        for var in self._variables:
            counter = _get_var_counter(var.name)
            var._name = self._hungarian_notation(var, counter if counter else "")
            

    def _hungarian_notation(self, var: Variable, counter: int) -> str:
        return ("g_" if isinstance(var, GlobalVariable) else "") + f"{self._hungarian_prefix(var.type)}{self._type_separator}{self._var_name}{self._counter_separator}{counter}"


    def _hungarian_prefix(self, var_type: Type) -> str:
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
