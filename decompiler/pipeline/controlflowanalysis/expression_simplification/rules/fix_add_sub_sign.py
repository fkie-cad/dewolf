from decompiler.pipeline.controlflowanalysis.expression_simplification.modification import normalize_int
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Integer, Operation, OperationType


class FixAddSubSign(SimplificationRule):
    """
    Changes add/sub when variable type is signed.

    - `V - a -> E + (-a)` when signed(a) < 0
    - `V + a -> E - (-a)` when signed(a) < 0
    """

    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        if operation.operation not in (OperationType.plus, OperationType.minus):
            return []
        if not isinstance(operation, BinaryOperation):
            raise TypeError(f"Expected BinaryOperation, got {type(operation)}")

        right = operation.right
        if not isinstance(right, Constant):
            return []

        con_type = right.type
        if not isinstance(con_type, Integer):
            return []

        a = normalize_int(right.value, con_type.size, True)
        if a >= 0:
            return []

        neg_a = Constant(
            normalize_int(-a, con_type.size, con_type.signed),
            con_type
        )
        return [(
            operation,
            BinaryOperation(
                OperationType.plus if operation.operation == OperationType.minus else OperationType.minus,
                [operation.left, neg_a]
            )
        )]
