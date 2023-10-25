from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import BinaryOperation, Expression, Operation, OperationType, UnaryOperation


class CollapseAddNeg(SimplificationRule):
    """
    Simplifies additions/subtraction with negated expression.

    - `e0 + -(e1) -> e0 - e1`
    - `e0 - -(e1) -> e0 + e1`
    """

    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        if operation.operation not in [OperationType.plus, OperationType.minus]:
            return []
        if not isinstance(operation, BinaryOperation):
            raise TypeError(f"Expected BinaryOperation, got {type(operation)}")

        right = operation.right
        if not isinstance(right, UnaryOperation) or right.operation != OperationType.negate:
            return []

        return [
            (
                operation,
                BinaryOperation(
                    OperationType.minus if operation.operation == OperationType.plus else OperationType.plus,
                    [operation.left, right.operand],
                    operation.type,
                ),
            )
        ]
