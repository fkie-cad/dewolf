"""Module containing the visitors used to generate variable declarations."""

from collections import defaultdict
from typing import Iterable, Iterator, List

from decompiler.backend.cexpressiongenerator import (
    CExpressionGenerator,
    get_data_of_struct_string,
    inline_global_variable,
    is_struct_string,
)
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.pseudo import GlobalVariable, Integer, Variable
from decompiler.structures.pseudo.complextypes import Struct
from decompiler.structures.pseudo.expressions import StructConstant
from decompiler.structures.pseudo.typing import ArrayType, CustomType, Pointer
from decompiler.structures.visitors.ast_dataflowobjectvisitor import BaseAstDataflowObjectVisitor
from decompiler.task import DecompilerTask
from decompiler.util.insertion_ordered_set import InsertionOrderedSet


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
            base = f"extern {'const ' if variable.is_constant else ''}"
            match variable.type:
                case ArrayType():
                    br, bl = "", ""
                    if not variable.type.type in [Integer.char(), CustomType.wchar16(), CustomType.wchar32()]:
                        br, bl = "{", "}"
                    yield f"{base}{variable.type.type} {variable.name}[{hex(variable.type.elements)}] = {br}{CExpressionGenerator().visit(variable.initial_value)}{bl};"
                case Struct():
                    if is_struct_string(variable.type):
                        yield base + f"struct {variable.type.name} {variable.name} = {CExpressionGenerator().visit(get_data_of_struct_string(variable))};"
                        continue
                    string = f"struct {variable.type.name} {variable.name}" + "{\n"
                    for m_type, m_value in zip(variable.type.members.values(), variable.initial_value.value.values()):
                        value = CExpressionGenerator().visit(m_value)
                        string += f"\t.{m_type.name} = {value};\n"
                    string += "}"
                    yield base + string
                case _:
                    yield f"{base}{variable.type} {variable.name} = {CExpressionGenerator().visit(variable.initial_value)};"

    @staticmethod
    def from_asts(asts: Iterable[AbstractSyntaxTree]) -> str:
        """Generate"""
        globals = InsertionOrderedSet()
        for ast in asts:
            globals |= GlobalDeclarationGenerator().visit_ast(ast)
        return "\n".join(GlobalDeclarationGenerator._generate_definitions(globals))

    def visit_ast(self, ast: AbstractSyntaxTree) -> InsertionOrderedSet:
        """Visit ast and return all collected global variables"""
        super().visit_ast(ast)
        return self._global_vars

    def visit_global_variable(self, expr: GlobalVariable):
        """Visit global variables. Only collect ones which will not be inlined by CExprGenerator. Strip SSA label to remove duplicates"""
        if not inline_global_variable(expr):
            self._global_vars.add(expr.copy(ssa_label=0, ssa_name=None))
        if not expr.is_constant or expr.type == Pointer(CustomType.void()):
            self._global_vars.add(expr.copy(ssa_label=0, ssa_name=None))
        if isinstance(expr.initial_value, StructConstant):
            for member_value in expr.initial_value.value.values():
                self.visit(member_value)
