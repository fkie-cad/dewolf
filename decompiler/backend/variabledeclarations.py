"""Module containing the visitors used to generate variable declarations."""
from collections import defaultdict
from typing import Iterable, Iterator, List

from decompiler.backend.cexpressiongenerator import CExpressionGenerator
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.pseudo import (
    DataflowObject,
    Expression,
    ExternConstant,
    ExternFunctionPointer,
    GlobalVariable,
    Operation,
    Pointer,
    Variable,
)
from decompiler.structures.visitors.ast_dataflowobjectvisitor import BaseAstDataflowObjectVisitor
from decompiler.task import DecompilerTask
from decompiler.util.insertion_ordered_set import InsertionOrderedSet
from decompiler.util.serialization.bytes_serializer import convert_bytes


class LocalDeclarationGenerator:
    @staticmethod
    def from_task(task: DecompilerTask):
        vars_per_line = task.options.getint("code-generator.variable_declarations_per_line", fallback=1)

        parameter_names = {p.name for p in task.function_parameters}
        variables = InsertionOrderedSet(LocalDeclarationGenerator._get_variables(task.syntax_tree))

        return "\n".join(LocalDeclarationGenerator.generate(parameter_names, variables, vars_per_line))

    @staticmethod
    def _get_variables(ast: AbstractSyntaxTree) -> Iterator[Variable]:
        for node in ast.nodes:
            for obj in node.get_dataflow_objets(ast.condition_map):
                for expression in obj.subexpressions():
                    if isinstance(expression, Variable):
                        yield expression

    @staticmethod
    def generate(parameter_names: Iterable[str], variables: Iterable[Variable], vars_per_line: int) -> Iterator[str]:
        """Generate a string containing the variable definitions for the visited variables."""

        variable_type_mapping = defaultdict(list)
        for variable in sorted(variables, key=lambda x: str(x)):
            if not isinstance(variable, GlobalVariable) and variable.name not in parameter_names:
                variable_type_mapping[variable.type].append(variable)

        for variable_type, variables in sorted(variable_type_mapping.items(), key=lambda x: str(x)):
            for chunked_variables in LocalDeclarationGenerator._chunks(variables, vars_per_line):
                yield CExpressionGenerator.format_variables_declaration(variable_type, [var.name for var in chunked_variables]) + ";"

    @staticmethod
    def _chunks(lst: List, n: int) -> Iterator[List]:
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(lst), n):
            yield lst[i : i + n]


class GlobalDeclarationGenerator(BaseAstDataflowObjectVisitor):
    @staticmethod
    def from_asts(asts: Iterable[AbstractSyntaxTree]) -> str:
        global_variables, extern_constants = GlobalDeclarationGenerator._get_global_variables_and_constants(asts)
        return "\n".join(GlobalDeclarationGenerator.generate(global_variables.__iter__(), extern_constants))

    @staticmethod
    def _get_global_variables_and_constants(asts: Iterable[AbstractSyntaxTree]) -> tuple[set[GlobalVariable], set[ExternConstant]]:
        global_variables = InsertionOrderedSet()
        extern_constants = InsertionOrderedSet()

        def handle_obj(obj: DataflowObject):
            match obj:
                case GlobalVariable():
                    global_variables.add(obj)
                    if isinstance(obj.initial_value, Expression):
                        handle_obj(obj.initial_value)

                case ExternConstant():
                    extern_constants.add(obj)

        for ast in asts:
            for node in ast.nodes:
                for obj in node.get_dataflow_objets(ast.condition_map):
                    for expression in obj.subexpressions():
                        handle_obj(expression)

        return global_variables, extern_constants

    @staticmethod
    def generate(global_variables: Iterable[GlobalVariable], extern_constants: Iterable[ExternConstant]) -> Iterator[str]:
        """Generate all definitions"""
        for variable in global_variables:
            yield f"extern {variable.type} {variable.name} = {GlobalDeclarationGenerator.get_initial_value(variable)};"
        for constant in sorted(extern_constants, key=lambda x: x.value):
            yield f"extern {constant.type} {constant.value};"

    @staticmethod
    def get_initial_value(variable: GlobalVariable) -> str:
        """Get a string representation of the initial value of the given variable."""
        if isinstance(variable.initial_value, GlobalVariable):
            return variable.initial_value.name
        elif isinstance(variable.initial_value, ExternFunctionPointer):
            return str(variable.initial_value.value)
        if isinstance(variable.initial_value, bytes):
            return str(convert_bytes(variable.initial_value, variable.type))
        if isinstance(operation := variable.initial_value, Operation):
            for requirement in operation.requirements:
                if isinstance(requirement, GlobalVariable):
                    requirement.unsubscript()
        if isinstance(variable.type, Pointer) and isinstance(variable.initial_value, int):
            return hex(variable.initial_value)
        return str(variable.initial_value)
