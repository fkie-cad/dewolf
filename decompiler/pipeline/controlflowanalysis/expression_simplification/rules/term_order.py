from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Operation
from decompiler.structures.pseudo.operations import COMMUTATIVE_OPERATIONS


class TermOrder(SimplificationRule):
    """
    Swap constants of commutative operations to the right.

    - `c + e -> e + c`
    - `c * e -> e * c`
    - `c & e -> e & c`
    - `c | e -> e | c`
    - `c ^ e -> e ^ c`
    """

    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        if operation.operation not in COMMUTATIVE_OPERATIONS:
            return []
        if not isinstance(operation, BinaryOperation):
            raise ValueError(f"Expected BinaryOperation, got {operation}")

        if isinstance(operation.left, Constant) and not isinstance(operation.right, Constant):
            return [(operation, BinaryOperation(operation.operation, [operation.right, operation.left], operation.type, operation.tags))]
        else:
            return []
