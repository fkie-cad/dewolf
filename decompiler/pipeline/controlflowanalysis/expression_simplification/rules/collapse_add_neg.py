from typing import Optional

from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import BinaryOperation, Expression, Operation, OperationType, UnaryOperation


class CollapseAddNeg(SimplificationRule):
    """
    Simplifies additions/subtraction with negated expression.

    - `e0 + -(e1) -> e0 - e1`
    - `e0 - -(e1) -> e0 + e1`
    - `-(e0) + e1 -> e1 - e0`
    - `-(e0) - e1 -> -(e0 + e1)`
    """

    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        replacement: Optional[Expression] = None
        match operation:
            case BinaryOperation(
                operation=OperationType.plus,
                left=e0,
                right=UnaryOperation(
                    operation=OperationType.negate,
                    operand=e1
                )
            ):
                replacement = BinaryOperation(OperationType.minus, [e0, e1], operation.type)

            case BinaryOperation(
                operation=OperationType.minus,
                left=e0,
                right=UnaryOperation(
                    operation=OperationType.negate,
                    operand=e1
                )
            ):
                replacement = BinaryOperation(OperationType.plus, [e0, e1], operation.type)

            case BinaryOperation(
                operation=OperationType.plus,
                left=UnaryOperation(
                    operation=OperationType.negate,
                    operand=e0
                ),
                right=e1
            ):
                replacement = BinaryOperation(OperationType.minus, [e1, e0], operation.type)

            case BinaryOperation(
                operation=OperationType.minus,
                left=UnaryOperation(
                    operation=OperationType.negate,
                    operand=e0
                ),
                right=e1
            ):
                replacement = UnaryOperation(
                    OperationType.negate,
                    [BinaryOperation(OperationType.plus, [e0, e1], operation.type)]
                )

        if replacement is None:
            return []

        return [(operation, replacement)]
