import re
from enum import Enum
from typing import List, Optional

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.ast.ast_nodes import CaseNode, CodeNode, ConditionNode, LoopNode, SwitchNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.pseudo import CustomType, DataflowObject, Float, GlobalVariable, Integer, Pointer, Type, Variable
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
    """ 
    Pipelinestage in charge of renaming variables to a configured format.
    Currently only the 'default' or 'hungarian' system are supported.
    """

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
        self._params : List[Variable] = []


    def run(self, task: DecompilerTask):
        self._ast = task.syntax_tree
        self._notation = task.options.getstring(f"{self.name}.notation", fallback="default")
        self._var_name = task.options.getstring(f"{self.name}.variable_name", fallback="Var")
        self._pointer_base = task.options.getboolean(f"{self.name}.pointer_base", fallback=True)
        self._type_separator = task.options.getstring(f"{self.name}.type_separator", fallback="")
        self._counter_separator = task.options.getstring(f"{self.name}.counter_separator", fallback="")
        self._params = task.function_parameters

        if self._notation != NamingConvention.default:
            self._collect()
            self._purge()
            self._rename()


    def _collect(self):
        """Collects all variables by iterating over every node in the AST."""
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
        """Remove variables for renaming if they are:
            - function params 
            - loop variables which have been renamed by For/WhileLoopRenamer
            - global vars with a symbol as a name
        """
        loop_vars : List[Variable] = []
        for node in self._ast.get_loop_nodes_post_order():
            for expr in [self._ast.condition_map[symbol] for symbol in node.condition.get_symbols()]:
                loop_vars.extend(_get_containing_variables(expr))
            
        loop_vars = [var for var in loop_vars if var.name.find("var_") == -1]
        self._variables = [var for var in self._variables if var not in self._params]
        self._variables = [var for var in self._variables if var not in loop_vars]
        self._variables = [var for var in self._variables if not isinstance(var, GlobalVariable)]

    def _rename(self):
        for var in self._variables:
            counter = _get_var_counter(var.name)
            var._name = self._hungarian_notation(var, counter if counter else "")
            

    def _hungarian_notation(self, var: Variable, counter: int) -> str:
        return f"{self._hungarian_prefix(var.type)}{self._type_separator}{self._var_name}{self._counter_separator}{counter}"


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
