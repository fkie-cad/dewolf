"""Module implementing the ConditionHandler class."""
from functools import partial

from binaryninja import mediumlevelil
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Condition, OperationType


class ConditionHandler(Handler):
    """Handler for mlil conditions."""

    def register(self):
        """Register the handler functions at the parent lifter."""
        self._lifter.HANDLERS.update(
            {
                mediumlevelil.MediumLevelILCmpE: partial(self.lift_condition, operation=OperationType.equal),
                mediumlevelil.MediumLevelILCmpNe: partial(self.lift_condition, operation=OperationType.not_equal),
                mediumlevelil.MediumLevelILCmpSge: partial(self.lift_condition, operation=OperationType.greater_or_equal),
                mediumlevelil.MediumLevelILCmpSgt: partial(self.lift_condition, operation=OperationType.greater),
                mediumlevelil.MediumLevelILCmpSle: partial(self.lift_condition, operation=OperationType.less_or_equal),
                mediumlevelil.MediumLevelILCmpSlt: partial(self.lift_condition, operation=OperationType.less),
                mediumlevelil.MediumLevelILCmpUge: partial(self.lift_condition, operation=OperationType.greater_or_equal_us),
                mediumlevelil.MediumLevelILCmpUgt: partial(self.lift_condition, operation=OperationType.greater_us),
                mediumlevelil.MediumLevelILCmpUle: partial(self.lift_condition, operation=OperationType.less_or_equal_us),
                mediumlevelil.MediumLevelILCmpUlt: partial(self.lift_condition, operation=OperationType.less_us),
                mediumlevelil.MediumLevelILFcmpE: partial(self.lift_condition, operation=OperationType.equal),
                mediumlevelil.MediumLevelILFcmpNe: partial(self.lift_condition, operation=OperationType.not_equal),
                mediumlevelil.MediumLevelILFcmpGe: partial(self.lift_condition, operation=OperationType.greater_or_equal),
                mediumlevelil.MediumLevelILFcmpGt: partial(self.lift_condition, operation=OperationType.greater),
                mediumlevelil.MediumLevelILFcmpLe: partial(self.lift_condition, operation=OperationType.less_or_equal),
                mediumlevelil.MediumLevelILFcmpLt: partial(self.lift_condition, operation=OperationType.less),
                mediumlevelil.MediumLevelILFcmpO: partial(self.lift_condition, operation=OperationType.equal),
                mediumlevelil.MediumLevelILFcmpUo: partial(self.lift_condition, operation=OperationType.equal),
            }
        )

    def lift_condition(self, condition: mediumlevelil.MediumLevelILBinaryBase, operation: OperationType = None, **kwargs) -> Condition:
        """Lift the given conditional to a pseudo operation."""
        return Condition(
            operation, [self._lifter.lift(condition.left, parent=condition), self._lifter.lift(condition.right, parent=condition)]
        )
