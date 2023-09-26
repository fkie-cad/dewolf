from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Operation, OperationType


class SimplifyTrivialBitArithmetic(SimplificationRule):
    """
    Simplifies trivial bit arithmetic:

    - `e | 0 -> e`
    - `e | e -> e`
    - `e & 0 -> 0`
    - `e & e -> e`
    - `e ^ 0 -> e`
    - `e ^ e -> 0`
    """

    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        match operation:
            case BinaryOperation(operation=OperationType.bitwise_or | OperationType.bitwise_xor, right=Constant(value=0)):
                return [(operation, operation.left)]
            case BinaryOperation(operation=OperationType.bitwise_and, right=Constant(value=0)):
                return [(operation, Constant(0, operation.type))]
            case BinaryOperation(operation=OperationType.bitwise_or | OperationType.bitwise_and, left=left, right=right) if left == right:
                return [(operation, operation.left)]
            case BinaryOperation(operation=OperationType.bitwise_xor, left=left, right=right) if left == right:
                return [(operation, Constant(0, operation.type))]
            case _:
                return []
