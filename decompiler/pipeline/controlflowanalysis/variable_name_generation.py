import logging
import string
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Counter, List

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.pseudo import ArrayType, CustomType, Float, GlobalVariable, Integer, Pointer, Type, Variable
from decompiler.structures.visitors.ast_dataflowobjectvisitor import BaseAstDataflowObjectVisitor
from decompiler.structures.visitors.substitute_visitor import SubstituteVisitor
from decompiler.task import DecompilerTask


class VariableCollector(BaseAstDataflowObjectVisitor):
    """Collect all variables in nodes/expressions"""

    def __init__(self):
        self.variables: list[Variable] = []

    def visit_variable(self, expression: Variable):
        self.variables.append(expression)


class NamingConvention(str, Enum):
    """Enum for the currently available naming conventions."""

    default = "default"
    system_hungarian = "system_hungarian"


@dataclass(frozen=True)
class VariableIdentifier:
    name: str
    ssa_label: int | None


def identifier(var: Variable) -> VariableIdentifier:
    return VariableIdentifier(var.name, var.ssa_label)


class RenamingScheme(ABC):

    @abstractmethod
    def rename_variable(self, variable: Variable) -> Variable | None:
        pass


class NoRenamingScheme(RenamingScheme):
    def rename_variable(self, variable: Variable) -> Variable | None:
        return None


class HungarianScheme(RenamingScheme):
    """Class which renames variables into hungarian notation."""

    type_prefix = {
        Float: {16: "h", 32: "f", 64: "d", 80: "ld", 128: "q", 256: "o"},
        Integer: {8: "ch", 16: "s", 32: "i", 64: "l", 128: "i128"},
    }

    def __init__(self, task: DecompilerTask) -> None:
        self._task = task
        self._var_name: str = task.options.getstring(f"{VariableNameGeneration.name}.variable_name", fallback="var")
        self._pointer_base: bool = task.options.getboolean(f"{VariableNameGeneration.name}.pointer_base", fallback=True)
        self._type_separator: str = task.options.getstring(f"{VariableNameGeneration.name}.type_separator", fallback="")
        self._counter_separator: str = task.options.getstring(f"{VariableNameGeneration.name}.counter_separator", fallback="")

        self._variables = self._get_variables_to_rename()

        counter = Counter[tuple[str, Type]]()
        self._variable_rename_map: dict[VariableIdentifier, str] = {}

        variable_id: VariableIdentifier
        vars: list[Variable]
        for variable_id, vars in self._variables.items():
            # because the way our cfg works, each use site of each variable could theoretically have a different type
            # we just take the first assuming that they are all the same...
            var_type = vars[0].type
            name_identifier = self._get_name_identifier(variable_id.name)

            counter_postfix = f"{self._counter_separator}{counter[(name_identifier, var_type)]}"  # array[0x12] != array[0x13] kriegt aber selben Namen, da Typen unterschiedlich sind
            counter[(name_identifier, var_type)] += 1

            prefix = self._hungarian_prefix(var_type)

            new_name: str
            if prefix is not None:
                new_name = f"{prefix}{self._type_separator}{name_identifier.capitalize()}{counter_postfix}"
            else:
                new_name = f"{name_identifier}{counter_postfix}"

            self._variable_rename_map[variable_id] = new_name

    def rename_variable(self, variable: Variable) -> Variable | None:
        new_name = self._variable_rename_map.get(identifier(variable))
        if new_name is None:
            return None
        else:
            return variable.copy(name=new_name)

    def _get_name_identifier(self, name: str) -> str:
        """Return identifier by purging non alpha chars + capitalize the char afterwards. If string is too short, return generic"""
        if len(name) < 2:
            return self._var_name

        x = string.capwords("".join([c if c.isalnum() else " " for c in name]))
        x = x[0].lower() + x[1:]  # important! We want to be able to choose later if the first letter should be capitalized
        return "".join(filter(str.isalpha, x))

    def _hungarian_prefix(self, var_type: Type) -> str | None:
        """Return hungarian prefix to a given variable type."""
        match var_type:
            case Pointer() | ArrayType():
                if self._pointer_base:
                    pprefix = self._hungarian_prefix(var_type.type)
                    return f"{pprefix}p" if pprefix is not None else "unkp"
                else:
                    return "p"
            case CustomType():
                if var_type.is_boolean:
                    return "b"
                if var_type.size == 0:
                    return "v"
            case Integer() | Float():
                sign = "u" if isinstance(var_type, Integer) and not var_type.is_signed else ""
                prefix = self.type_prefix[type(var_type)].get(var_type.size, "unk")
                return f"{sign}{prefix}"

        return None

    def _get_variables_to_rename(self) -> dict[VariableIdentifier, list[Variable]]:
        collector = VariableCollector()
        collector.visit_ast(self._task.ast)

        def include_variable(item: Variable):
            return item not in self._task.function_parameters and not isinstance(item, GlobalVariable)

        variables: dict[VariableIdentifier, List[Variable]] = defaultdict(list)
        for variable in collector.variables:
            if include_variable(variable):
                variables[identifier(variable)].append(variable)
        return variables


class VariableNameGeneration(PipelineStage):
    """
    Pipelinestage in charge of renaming variables to a configured format.
    Currently only the 'default' or 'hungarian' system are supported.
    """

    name: str = "variable-name-generation"

    def run(self, task: DecompilerTask):
        """Rename variable names to the given scheme."""
        notation = task.options.getstring(f"{self.name}.notation", fallback=NamingConvention.default)

        scheme: RenamingScheme
        match notation:
            case NamingConvention.default:
                scheme = NoRenamingScheme()
            case NamingConvention.system_hungarian:
                scheme = HungarianScheme(task)
            case _:
                logging.warning("Unknown naming convention: %s", notation)
                return

        self._rename_with_scheme(task, scheme)

    @staticmethod
    def _rename_with_scheme(task: DecompilerTask, rename_scheme: RenamingScheme):
        rename_visitor = SubstituteVisitor(lambda o: rename_scheme.rename_variable(o) if isinstance(o, Variable) else None)

        for node in task.ast.nodes:
            for obj in node.get_dataflow_objets(task.ast.condition_map):
                new_obj = rename_visitor.visit(obj)
                if new_obj is not None:
                    # while this should not happen, in theory, there is nothing preventing this case...
                    logging.warning("Variable name renaming couldn't rename %s", new_obj)
