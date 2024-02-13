"""Module containing the visitors used to generate variable declarations."""

from collections import defaultdict
from typing import Iterable, Iterator, List

from decompiler.backend.cexpressiongenerator import CExpressionGenerator
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.pseudo import (
    Expression,
    GlobalVariable,
    Variable,
    UnaryOperation,
)
from decompiler.structures.visitors.ast_dataflowobjectvisitor import BaseAstDataflowObjectVisitor
from decompiler.task import DecompilerTask
from decompiler.util.insertion_ordered_set import InsertionOrderedSet
from decompiler.backend.cexpressiongenerator import print_global_variable_init


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
    def __init__(self) -> None:
        self._global_vars = InsertionOrderedSet()
        super().__init__()

    @staticmethod
    def _generate_definitions(global_variables: set[GlobalVariable]) -> Iterator[str]:
        """Generate all definitions"""
        for variable in global_variables:
            yield f"extern {variable.type} {variable.name} = {print_global_variable_init(variable)};"

    @staticmethod
    def from_asts(asts: Iterable[AbstractSyntaxTree]) -> str:
        """Generate """
        globals = InsertionOrderedSet()
        for ast in asts:
            globals |= GlobalDeclarationGenerator().visit_ast(ast)
        return "\n".join(GlobalDeclarationGenerator._generate_definitions(globals))

    def visit_ast(self, ast: AbstractSyntaxTree) -> InsertionOrderedSet:
        """Visit ast and return all collected global variables"""
        super().visit_ast(ast)
        return self._global_vars

    def visit_unary_operation(self, operation: UnaryOperation):
        """Visit unary operation"""
        self.visit(operation.operand)

    def visit_global_variable(self, expression: GlobalVariable):
        """Visit the given global variable. Strip SSA label to remove duplicates"""
        self._global_vars.add(expression.copy(ssa_label=0, ssa_name=None))
        if isinstance(expression.initial_value, Expression) and (subexpr := self.visit(expression.initial_value)):
            self._global_vars.add(subexpr)
