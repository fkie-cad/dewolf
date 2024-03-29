from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import BinaryOperation, Constant, Expression, Operation
from decompiler.structures.pseudo.operations import COMMUTATIVE_OPERATIONS


class TermOrder(SimplificationRule):
    """
    Swap constants of commutative operations to the right.
    This stage is important because other stages expect constants to be on the right side.
    Associativity is not exploited, i.e. nested operations of the same type are not considered.

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
            raise TypeError(f"Expected BinaryOperation, got {type(operation)}")

        if isinstance(operation.left, Constant) and not isinstance(operation.right, Constant):
            return [(operation, BinaryOperation(operation.operation, [operation.right, operation.left], operation.type, operation.tags))]
        else:
            return []
