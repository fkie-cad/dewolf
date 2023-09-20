from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import Expression, Operation, OperationType, UnaryOperation


class SimplifyRedundantReference(SimplificationRule):
    """
    Removes redundant nesting of referencing, immediately followed by referencing.

    `*(&(e0)) -> e0`
    """

    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        match operation:
            case UnaryOperation(
                operation=OperationType.dereference,
                operand=UnaryOperation(operation=OperationType.address, operand=inner_operand)
            ):
                return [(operation, inner_operand)]
            case _:
                return []
