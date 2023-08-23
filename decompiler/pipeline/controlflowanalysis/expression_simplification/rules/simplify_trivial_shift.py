from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Operation, OperationType


class SimplifyTrivialShift(SimplificationRule):
    """
    Simplifies trivial shift/rotate arithmetic:

    - `e << 0 -> e`
    - `e >> 0 -> e`
    - `e u>> 0 -> e`
    - `e lrot 0 -> e`
    - `e rrot 0 -> e`
    """

    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        match operation:
            case BinaryOperation(
                operation=OperationType.left_shift
                | OperationType.right_shift
                | OperationType.right_shift_us
                | OperationType.left_rotate
                | OperationType.right_rotate,
                right=Constant(value=0),
            ):
                return [(operation, operation.left)]
            case _:
                return []
