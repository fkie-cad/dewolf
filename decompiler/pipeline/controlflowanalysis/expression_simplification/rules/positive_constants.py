from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Integer, Operation, OperationType
from decompiler.util.integer_util import normalize_int


class PositiveConstants(SimplificationRule):
    """
    Changes add/sub so that the right operand constant is always positive.
    For unsigned arithmetic, choose the operation with the lesser constant (e.g.: V - 4294967293 -> V + 3 for 32 bit ints).

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

        constant_type = right.type
        if not isinstance(constant_type, Integer):
            return []

        signed_normalized_constant = normalize_int(right.value, constant_type.size, True)
        if signed_normalized_constant >= 0:
            return []

        neg_constant = Constant(
            normalize_int(-signed_normalized_constant, constant_type.size, constant_type.signed),
            constant_type
        )
        return [(
            operation,
            BinaryOperation(
                OperationType.plus if operation.operation == OperationType.minus else OperationType.minus,
                [operation.left, neg_constant]
            )
        )]
