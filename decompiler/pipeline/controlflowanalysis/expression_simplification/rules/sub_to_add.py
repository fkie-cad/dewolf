from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Operation, OperationType


class SubToAdd(SimplificationRule):
    """
    Replace subtractions with additions.

    `e0 - e1 -> e0 + (e1 * -1)`
    """

    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        if operation.operation != OperationType.minus:
            return []
        if not isinstance(operation, BinaryOperation):
            raise TypeError(f"Expected BinaryOperation, got {type(operation)}")

        mul_op = BinaryOperation(OperationType.multiply, [operation.right, Constant(-1, operation.type)])

        return [(
            operation,
            BinaryOperation(
                OperationType.plus,
                [operation.left, mul_op],
                operation.type
            )
        )]
