from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Operation, OperationType


class SimplifyTrivialLogicArithmetic(SimplificationRule):
    """
    Simplifies trivial logic arithmetic.

    - `e || false -> e`
    - `e || true -> true`
    - `e && false -> false`
    - `e && true -> e`
    """

    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        match operation:
            case BinaryOperation(operation=OperationType.logical_or, right=Constant(value=0)):
                return [(operation, operation.left)]
            case BinaryOperation(operation=OperationType.logical_and, right=Constant(value=0)):
                return [(operation, Constant(0, operation.type))]
            case BinaryOperation(operation=OperationType.logical_or, right=Constant(value=value)) if value != 0:
                return [(operation, Constant(1, operation.type))]
            case BinaryOperation(operation=OperationType.logical_and, right=Constant(value=value)) if value != 0:
                return [(operation, operation.left)]
            case _:
                return []
