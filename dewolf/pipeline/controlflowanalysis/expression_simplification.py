"""Module implementing basic simplifications for expressions."""
from typing import Optional

from dewolf.pipeline.stage import PipelineStage
from dewolf.structures.ast.ast_nodes import CodeNode
from dewolf.structures.pseudo.expressions import Constant, DataflowObject, Expression
from dewolf.structures.pseudo.instructions import Instruction
from dewolf.structures.pseudo.operations import BinaryOperation, OperationType, UnaryOperation
from dewolf.structures.pseudo.typing import Integer
from dewolf.task import DecompilerTask


def simplify(expression: DataflowObject, parent: Optional[Instruction] = None):
    """
    Simplifies the given instruction
    a + 0 -> a, a - 0 -> a, 0 - a -> -a, a*0 -> 0, a* 1 -> a, a* -1 -> -a, a / 1 -> a, a / -1 -> -a
    """
    parent = expression if parent is None else parent
    assert isinstance(parent, Instruction), f"The parent {parent} must be an instruction."
    for sub_expr in expression:
        simplify(sub_expr, parent)
    if isinstance(expression, BinaryOperation) and expression.operation in SIMPLIFICATION_FOR:
        SIMPLIFICATION_FOR[expression.operation](expression, parent)


def _simplify_addition(binary_operation: BinaryOperation, instruction: Instruction):
    """
    Simplifies the given addition in the given instruction.

    -> Simplifies a+0, 0+a, a-0 and -0 + a to a
    """
    if any(is_zero_constant(zero := op) for op in binary_operation.operands):
        non_zero = get_other_operand(binary_operation, zero)
        instruction.substitute(binary_operation, non_zero)


def _simplify_multiplication(binary_operation: BinaryOperation, instruction: Instruction):
    """
    Simplifies the given multiplication in the given instruction.

    -> Simplifies a*0, 0*a, a*(-0) and (-0) * a to 0
    -> Simplifies a*1, 1*a to a
    -> Simplifies a*(-1), (-1)*a to -a
    """
    if any(is_zero_constant(zero := op) for op in binary_operation.operands):
        instruction.substitute(binary_operation, zero)
    elif any(is_one_constant(one := op) for op in binary_operation.operands):
        non_one = get_other_operand(binary_operation, one)
        instruction.substitute(binary_operation, non_one)
    elif any(is_minus_one_constant(minus_one := op) for op in binary_operation.operands):
        negated_expression = negate_expression(get_other_operand(binary_operation, minus_one))
        instruction.substitute(binary_operation, negated_expression)


def _simplify_subtraction(binary_operation: BinaryOperation, instruction: Instruction):
    """
    Simplifies the given subtraction in the given instruction.

    -> Simplifies a-0, a-(-0) to a
    -> Simplifies 0-a, -0-a to -a
    """
    if is_zero_constant(binary_operation.operands[1]):
        instruction.substitute(binary_operation, binary_operation.operands[0])
    elif is_zero_constant(binary_operation.operands[0]):
        instruction.substitute(binary_operation, negate_expression(binary_operation.operands[1]))


def _simplify_division(binary_operation: BinaryOperation, instruction: Instruction):
    """
    Simplifies the given division in the given instruction.

    -> Simplifies a/1 to a and a/(-1) to -a
    """
    if is_one_constant(binary_operation.operands[1]):
        instruction.substitute(binary_operation, binary_operation.operands[0])
    elif is_minus_one_constant(binary_operation.operands[1]):
        instruction.substitute(binary_operation, negate_expression(binary_operation.operands[0]))


# This translator maps the operations to their simplification method
SIMPLIFICATION_FOR = {
    OperationType.plus: _simplify_addition,
    OperationType.multiply: _simplify_multiplication,
    OperationType.minus: _simplify_subtraction,
    OperationType.divide: _simplify_division,
}


def is_zero_constant(expression: Expression) -> bool:
    """Checks whether the given expression is 0."""
    return isinstance(expression, Constant) and expression.value == 0


def is_one_constant(expression: Expression) -> bool:
    """Checks whether the given expression is 1."""
    return isinstance(expression, Constant) and expression.value == 1


def is_minus_one_constant(expression: Expression) -> bool:
    """Checks whether the given expression is -1."""
    return isinstance(expression, Constant) and expression.value == -1


def negate_expression(expression: Expression) -> Expression:
    """Negate the given expression and return it."""
    if isinstance(expression, Constant) and expression.value == 0:
        return expression
    if isinstance(expression, UnaryOperation) and expression.operation == OperationType.negate:
        return expression.operand
    if isinstance(expression, Constant) and isinstance(expression.type, Integer) and expression.type.is_signed:
        return Constant(-expression.value, expression.type)
    return UnaryOperation(OperationType.negate, [expression])


def get_other_operand(binary_operation: BinaryOperation, expression: Expression) -> Expression:
    """Returns the operand that is not equal to expression."""
    if binary_operation.operands[0] == expression:
        return binary_operation.operands[1]
    return binary_operation.operands[0]


class ExpressionSimplification(PipelineStage):
    """The ExpressionSimplification makes various simplifications to expressions on the AST, like a + 0 = a."""

    name = "expression-simplification"

    def run(self, task: DecompilerTask):
        """Run the task expression simplification on each instruction of the AST."""
        if task.syntax_tree is None:
            for instruction in task.graph.instructions:
                simplify(instruction)
        else:
            for node in task.syntax_tree.topological_order():
                if not isinstance(node, CodeNode):
                    continue
                for instruction in node.instructions:
                    simplify(instruction)
