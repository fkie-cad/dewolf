"""Module implementing the ConditionHandler class."""

from binaryninja import mediumlevelil
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Branch, Condition, Constant, IndirectBranch, OperationType, Return


class FlowHandler(Handler):
    """Handler for mlil instructions influencing the control flow."""

    def register(self):
        """Register the handler functions at the parent lifter."""
        self._lifter.HANDLERS.update(
            {
                mediumlevelil.MediumLevelILRet: self.lift_return,
                mediumlevelil.MediumLevelILIf: self.lift_branch,
                mediumlevelil.MediumLevelILJump: lambda x: None,
                mediumlevelil.MediumLevelILJumpTo: self.lift_branch_indirect,
                mediumlevelil.MediumLevelILGoto: lambda x: None,
                mediumlevelil.MediumLevelILNoret: lambda x: None,
            }
        )

    def lift_branch(self, branch: mediumlevelil.MediumLevelILIf, **kwargs) -> Branch:
        """Lift a branch instruction by lifting its condition."""
        condition = self._lifter.lift(branch.condition, parent=branch)
        if not isinstance(condition, Condition):
            condition = Condition(OperationType.not_equal, [condition, Constant(0, condition.type)])
        return Branch(condition)

    def lift_branch_indirect(self, branch: mediumlevelil.MediumLevelILJumpTo, **kwargs) -> IndirectBranch:
        """Lift a non-trivial jump instruction."""
        return IndirectBranch(self._lifter.lift(branch.dest, parent=branch))

    def lift_return(self, ret_op: mediumlevelil.MediumLevelILRet, **kwargs) -> Return:
        """Lift a return instruction."""
        return Return([self._lifter.lift(return_value, parent=ret_op) for return_value in ret_op.src])
