"""Module implementing the ConditionHandler class."""
from functools import partial

from binaryninja import mediumlevelil
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Branch, Condition, Constant, IndirectBranch, OperationType, Return


class ConditionHandler(Handler):
    """Handler for mlil conditions and branches,"""

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
                mediumlevelil.MediumLevelILRet: self.lift_return,
                mediumlevelil.MediumLevelILIf: self.lift_branch,
                mediumlevelil.MediumLevelILJump: lambda x: None,
                mediumlevelil.MediumLevelILJumpTo: self.lift_branch_indirect,
                mediumlevelil.MediumLevelILGoto: lambda x: None,
                mediumlevelil.MediumLevelILNoret: lambda x: None,
            }
        )

    def lift_condition(self, condition: mediumlevelil.MediumLevelILBinaryBase, operation: OperationType = None, **kwargs) -> Condition:
        """Lift the given conditional to a pseudo operation."""
        return Condition(
            operation, [self._lifter.lift(condition.left, parent=condition), self._lifter.lift(condition.right, parent=condition)]
        )

    def lift_branch(self, branch: mediumlevelil.MediumLevelILIf, **kwargs) -> Branch:
        """Lift a branch instruction by lifting its condition."""
        condition = self._lifter.lift(branch.condition, parent=branch)
        if not isinstance(condition, Condition):
            condition = Condition(OperationType.not_equal, [condition, Constant(0, condition.type.copy())])
        return Branch(condition)

    def lift_branch_indirect(self, branch: mediumlevelil.MediumLevelILJumpTo, **kwargs) -> IndirectBranch:
        """Lift a non-trivial jump instruction."""
        return IndirectBranch(self._lifter.lift(branch.dest, parent=branch))

    def lift_return(self, ret_op: mediumlevelil.MediumLevelILRet, **kwargs) -> Return:
        """Lift a return instruction."""
        return Return([self._lifter.lift(return_value, parent=ret_op) for return_value in ret_op.src])
