from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Operation, OperationType, UnaryOperation


class SimplifyTrivialArithmetic(SimplificationRule):
    """
    Simplifies trivial arithmetic:

    - `e + 0 -> e`
    - `e - 0 -> e`
    - `e * 0 -> 0`
    - `e u* 0 -> 0`
    - `e * 1 -> e`
    - `e u* 1 -> e`
    - `e * -1 -> -e`
    - `e u* -1 -> -e`
    - `e / 1 -> e`
    - `e u/ 1 -> e`
    - `e / -1 -> -e`
    """

    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        match operation:
            case BinaryOperation(operation=OperationType.plus | OperationType.minus, right=Constant(value=0)):
                return [(operation, operation.left)]
            case BinaryOperation(
                operation=OperationType.multiply | OperationType.multiply_us | OperationType.divide | OperationType.divide_us,
                right=Constant(value=1),
            ):
                return [(operation, operation.left)]
            case BinaryOperation(operation=OperationType.multiply | OperationType.multiply_us, right=Constant(value=0)):
                return [(operation, Constant(0, operation.type))]
            case BinaryOperation(
                operation=OperationType.multiply | OperationType.multiply_us | OperationType.divide, right=Constant(value=-1)
            ):
                return [(operation, UnaryOperation(OperationType.negate, [operation.left]))]
            case _:
                return []
