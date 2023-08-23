from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Operation, OperationType, UnaryOperation


class CollapseMultNegOne(SimplificationRule):
    """
    Simplifies expressions multiplied with -1.

    `e0 * -1 -> -(e0)`
    """

    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        if operation.operation != OperationType.multiply:
            return []
        if not isinstance(operation, BinaryOperation):
            raise TypeError(f"Expected BinaryOperation, got {type(operation)}")

        right = operation.right
        if not isinstance(right, Constant) or right.value != -1:
            return []

        return [(
            operation,
            UnaryOperation(
                OperationType.negate,
                [operation.left],
                operation.type
            )
        )]
