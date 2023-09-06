from decompiler.pipeline.controlflowanalysis.expression_simplification.modification import FOLDABLE_OPERATIONS, constant_fold
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import Constant, Expression, Operation


class CollapseConstants(SimplificationRule):
    """
    Fold operations with only constants as operands:
    """

    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        if not all(isinstance(o, Constant) for o in operation.operands):
            return []
        if operation.operation not in FOLDABLE_OPERATIONS:
            return []

        return [(
            operation,
            constant_fold(operation.operation, operation.operands)
        )]
