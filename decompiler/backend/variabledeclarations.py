"""Module containing the visitors used to generate variable declarations."""
from collections import defaultdict
from typing import Iterable, Iterator, List, Set

from decompiler.structures.ast.ast_nodes import ForLoopNode, LoopNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Constant,
    ExternConstant,
    ExternFunctionPointer,
    GlobalVariable,
    Operation,
    OperationType,
    UnaryOperation,
    Variable,
)
from decompiler.structures.visitors.ast_dataflowobjectvisitor import BaseAstDataflowObjectVisitor
from decompiler.task import DecompilerTask
from decompiler.util.serialization.bytes_serializer import convert_bytes


class LocalDeclarationGenerator(BaseAstDataflowObjectVisitor):
    """Visits all nodes in the AST and produces the variable declarations."""

    def __init__(self, vars_per_line: int = 1):
        """Initialize a new VariableCollector with an empty set of variables."""
        self._variables: Set[Variable] = set()
        self._vars_per_line: int = vars_per_line

    @classmethod
    def from_task(cls, task: DecompilerTask):
        """Class method for shorthand usage."""
        param_names = list(param.name for param in task.function_parameters)
        generator = cls(task.options.getint("code-generator.variable_declarations_per_line", fallback=1))
        generator.visit_ast(task.syntax_tree)
        return "\n".join(generator.generate(param_names))

    def visit_assignment(self, instruction: Assignment):
        """Remember all defined variables."""
        self._variables.update(instruction.definitions)

    def visit_loop_node(self, node: LoopNode):
        """Visit the given loop node, taking node of the loop declaration."""
        if isinstance(node, ForLoopNode) and isinstance(node.declaration, Assignment):
            if isinstance(node.declaration.destination, Operation):
                self._variables.add(node.declaration.destination[0])
            else:
                self._variables.add(node.declaration.destination)

    def visit_unary_operation(self, unary: UnaryOperation):
        """Visit unary operations to remember all variables those memory location was read."""
        if unary.operation == OperationType.address or unary.operation == OperationType.dereference:
            if isinstance(unary.operand, Variable):
                self._variables.add(unary.operand)
            elif isinstance(unary.operand, BinaryOperation):
                if isinstance(unary.operand.left, Variable):
                    self._variables.add(unary.operand.left)
                else:
                    self.visit(unary.operand.left)

    def generate(self, param_names: list = []) -> Iterator[str]:
        """Generate a string containing the variable definitions for the visited variables."""
        variable_type_mapping = defaultdict(list)
        for variable in sorted(self._variables, key=lambda x: str(x)):
            if not isinstance(variable, GlobalVariable):
                variable_type_mapping[variable.type].append(variable)

        for variable_type, variables in sorted(variable_type_mapping.items(), key=lambda x: str(x)):
            for chunked_variables in self._chunks(variables, self._vars_per_line):
                variable_names = ", ".join([var.name for var in chunked_variables])
                if variable_names in param_names:
                    continue
                yield f"{variable_type} {variable_names};"

    @staticmethod
    def _chunks(lst: List, n: int) -> Iterator[List]:
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(lst), n):
            yield lst[i : i + n]


class GlobalDeclarationGenerator(BaseAstDataflowObjectVisitor):
    """Visits all nodes in the AST and produces the declarations of global variables."""

    def __init__(self):
        """Generate a new declarator with an empty sets of visited globals."""
        self._extern_constants: Set[ExternConstant] = set()
        self._global_variables: Set[GlobalVariable] = set()

    @classmethod
    def from_asts(cls, asts: Iterable[AbstractSyntaxTree]) -> str:
        """Class method for shorthand usage."""
        generator = cls()
        for ast in asts:
            generator.visit_ast(ast)
        return "\n".join(generator.generate())

    def generate(self) -> Iterator[str]:
        """Generate a string containing the variable definitions for the visited variables."""
        for variable in self._global_variables:
            yield f"extern {variable.type} {variable.name} = {self.get_initial_value(variable)};"
        for constant in sorted(self._extern_constants, key=lambda x: x.value):
            yield f"extern {constant.type} {constant.value};"

    def visit_unary_operation(self, unary: UnaryOperation):
        """Visit an unary operation, visiting variable operands and nested operations along the way."""
        if isinstance(unary.operand, UnaryOperation) or isinstance(unary.operand, Variable):
            self.visit(unary.operand)

    def visit_variable(self, expression: Variable):
        """Visit the given variable, remembering all visited global Variables."""
        if isinstance(expression, GlobalVariable):
            self._global_variables.add(expression)
            if isinstance(expression.initial_value, UnaryOperation):
                self.visit(expression.initial_value)

    def visit_constant(self, expression: Constant):
        """Visit the given constant, checking if it has been defined externally."""
        if isinstance(expression, ExternConstant):
            self._extern_constants.add(expression)

    @staticmethod
    def get_initial_value(variable: GlobalVariable) -> str:
        """Get a string representation of the initial value of the given variable."""
        if isinstance(variable.initial_value, GlobalVariable):
            return variable.initial_value.name
        elif isinstance(variable.initial_value, ExternFunctionPointer):
            return str(variable.initial_value.value)
        if isinstance(variable.initial_value, bytes):
            return str(convert_bytes(variable.initial_value, variable.type))
        if isinstance(operation:=variable.initial_value, Operation):
            for requirement in operation.requirements:
                if isinstance(requirement, GlobalVariable):
                    requirement.unsubscript()
        return str(variable.initial_value)
