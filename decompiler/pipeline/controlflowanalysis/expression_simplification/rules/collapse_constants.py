from decompiler.pipeline.controlflowanalysis.expression_simplification.constant_folding import (
    IncompatibleOperandCount,
    UnsupportedMismatchedSizes,
    UnsupportedOperationType,
    UnsupportedValueType,
    constant_fold,
)
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import MalformedData, SimplificationRule
from decompiler.structures.pseudo import Constant, Expression, Operation


class CollapseConstants(SimplificationRule):
    """
    Fold operations with only constants as operands:
    """

    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        if not operation.operands:
            return []  # Is this even allowed?
        if not all(isinstance(o, Constant) for o in operation.operands):
            return []

        try:
            folded_constant = constant_fold(operation.operation, operation.operands, operation.type)
        except (UnsupportedOperationType, UnsupportedValueType, UnsupportedMismatchedSizes):
            return []
        except IncompatibleOperandCount as e:
            raise MalformedData() from e

        return [(operation, folded_constant)]
