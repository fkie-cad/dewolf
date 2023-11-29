from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import BinaryOperation, Expression, Operation, OperationType, UnaryOperation


class SubToAdd(SimplificationRule):
    """
    Replace subtractions with additions.

    `e0 - e1 -> e0 + (-e1)`
    """

    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        if operation.operation != OperationType.minus:
            return []
        if not isinstance(operation, BinaryOperation):
            raise TypeError(f"Expected BinaryOperation, got {type(operation)}")

        neg_op = UnaryOperation(OperationType.negate, [operation.right])

        return [(operation, BinaryOperation(OperationType.plus, [operation.left, neg_op], operation.type))]
