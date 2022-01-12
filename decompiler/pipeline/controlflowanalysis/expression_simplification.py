"""Module implementing basic simplifications for expressions."""
from typing import Optional

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.ast.ast_nodes import CodeNode
from decompiler.structures.pseudo.expressions import Constant, Expression
from decompiler.structures.pseudo.instructions import Instruction
from decompiler.structures.pseudo.operations import BinaryOperation, Operation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import Integer
from decompiler.task import DecompilerTask


class ExpressionSimplification(PipelineStage):
    """The ExpressionSimplification makes various simplifications to expressions on the AST, like a + 0 = a."""

    name = "expression-simplification"

    def __init__(self):
        self.HANDLERS = {
            OperationType.plus: self._simplify_addition,
            OperationType.minus: self._simplify_subtraction,
            OperationType.multiply: self._simplify_multiplication,
            OperationType.divide: self._simplify_division,
            OperationType.divide_us: self._simplify_division,
            OperationType.divide_float: self._simplify_division,
            OperationType.dereference: self._simplify_dereference,
        }

    def run(self, task: DecompilerTask):
        """Run the task expression simplification on each instruction of the AST."""
        if task.syntax_tree is None:
            for instruction in task.graph.instructions:
                self.simplify(instruction)
        else:
            for node in task.syntax_tree.topological_order():
                if not isinstance(node, CodeNode):
                    continue
                for instruction in node.instructions:
                    self.simplify(instruction)

    def simplify(self, instruction: Instruction):
        """Simplify all subexpressions of the given instruction recursively."""
        todo = list(instruction)
        while todo and (expression := todo.pop()):
            if self.simplify_expression(expression, instruction):
                todo = list(instruction)
            else:
                todo.extend(expression)

    def simplify_expression(self, expression: Expression, parent: Instruction) -> Optional[Expression]:
        """Simplify the given instruction utilizing the registered OperationType handlers."""
        if isinstance(expression, Operation) and expression.operation in self.HANDLERS:
            if simplified := self.HANDLERS[expression.operation](expression):
                print(f"simplified {parent}. {expression} -> {simplified}")
                parent.substitute(expression, simplified)
                print(f"result: {parent}.")
                return simplified

    def _simplify_addition(self, expression: BinaryOperation) -> Optional[Expression]:
        """
        Simplifies the given addition in the given instruction.

        -> Simplifies a+0, 0+a, a-0 and -0 + a to a
        """
        if any(self.is_zero_constant(zero := op) for op in expression.operands):
            return self.get_other_operand(expression, zero).copy()

    def _simplify_subtraction(self, expression: BinaryOperation) -> Optional[Expression]:
        """
        Simplifies the given subtraction in the given instruction.

        -> Simplifies a-0, a-(-0) to a
        -> Simplifies 0-a, -0-a to -a
        """
        if self.is_zero_constant(expression.operands[1]):
            return expression.operands[0].copy()
        if self.is_zero_constant(expression.operands[0]):
            return self.negate_expression(expression.operands[1])

    def _simplify_multiplication(self, expression: BinaryOperation) -> Optional[Expression]:
        """
        Simplifies the given multiplication in the given instruction.

        -> Simplifies a*0, 0*a, a*(-0) and (-0) * a to 0
        -> Simplifies a*1, 1*a to a
        -> Simplifies a*(-1), (-1)*a to -a
        """
        if any(self.is_zero_constant(zero := op) for op in expression.operands):
            return zero.copy()
        if any(self.is_one_constant(one := op) for op in expression.operands):
            return self.get_other_operand(expression, one).copy()
        if any(self.is_minus_one_constant(minus_one := op) for op in expression.operands):
            return self.negate_expression(self.get_other_operand(expression, minus_one))

    def _simplify_division(self, expression: BinaryOperation) -> Optional[Expression]:
        """
        Simplifies the given division in the given instruction.

        -> Simplifies a/1 to a and a/(-1) to -a
        """
        if self.is_one_constant(expression.operands[1]):
            return expression.operands[0].copy()
        if self.is_minus_one_constant(expression.operands[1]):
            return self.negate_expression(expression.operands[0])

    def _simplify_dereference(self, expression: UnaryOperation) -> Optional[Expression]:
        """
        Simplifies dereference expression with nested address-of expressions.

        -> Simplifies *(&(x)) to x
        """
        if isinstance(expression.operand, UnaryOperation) and expression.operand.operation == OperationType.address:
            return expression.operand.operand.copy()

    @staticmethod
    def is_zero_constant(expression: Expression) -> bool:
        """Checks whether the given expression is 0."""
        return isinstance(expression, Constant) and expression.value == 0

    @staticmethod
    def is_one_constant(expression: Expression) -> bool:
        """Checks whether the given expression is 1."""
        return isinstance(expression, Constant) and expression.value == 1

    @staticmethod
    def is_minus_one_constant(expression: Expression) -> bool:
        """Checks whether the given expression is -1."""
        return isinstance(expression, Constant) and expression.value == -1

    @staticmethod
    def negate_expression(expression: Expression) -> Expression:
        """Negate the given expression and return it."""
        if isinstance(expression, Constant) and expression.value == 0:
            return expression
        if isinstance(expression, UnaryOperation) and expression.operation == OperationType.negate:
            return expression.operand
        if isinstance(expression, Constant) and isinstance(expression.type, Integer) and expression.type.is_signed:
            return Constant(-expression.value, expression.type)
        return UnaryOperation(OperationType.negate, [expression])

    @staticmethod
    def get_other_operand(binary_operation: BinaryOperation, expression: Expression) -> Expression:
        """Returns the operand that is not equal to expression."""
        if binary_operation.operands[0] == expression:
            return binary_operation.operands[1]
        return binary_operation.operands[0]
