"""Module implementing the ConditionHandler class."""
from functools import partial

from binaryninja import mediumlevelil

from dewolf.frontend.lifter import Handler
from dewolf.structures.pseudo import OperationType, Condition, Branch, Return, IndirectBranch, Constant


class ConditionHandler(Handler):
    """Handler for mlil conditions and branches,"""

    def register(self):
        self._lifter.HANDLERS.update(
            {
                mediumlevelil.MediumLevelILCmp_e: partial(self.lift_condition, operation=OperationType.equal),
                mediumlevelil.MediumLevelILCmp_ne: partial(self.lift_condition, operation=OperationType.not_equal),
                mediumlevelil.MediumLevelILCmp_sge: partial(self.lift_condition, operation=OperationType.greater_or_equal),
                mediumlevelil.MediumLevelILCmp_sgt: partial(self.lift_condition, operation=OperationType.greater),
                mediumlevelil.MediumLevelILCmp_sle: partial(self.lift_condition, operation=OperationType.less_or_equal),
                mediumlevelil.MediumLevelILCmp_slt: partial(self.lift_condition, operation=OperationType.less),
                mediumlevelil.MediumLevelILCmp_uge: partial(self.lift_condition, operation=OperationType.greater_or_equal_us),
                mediumlevelil.MediumLevelILCmp_ugt: partial(self.lift_condition, operation=OperationType.greater_us),
                mediumlevelil.MediumLevelILCmp_ule: partial(self.lift_condition, operation=OperationType.less_or_equal_us),
                mediumlevelil.MediumLevelILCmp_ult: partial(self.lift_condition, operation=OperationType.less_us),
                mediumlevelil.MediumLevelILFcmp_e: partial(self.lift_condition, operation=OperationType.equal),
                mediumlevelil.MediumLevelILFcmp_ne: partial(self.lift_condition, operation=OperationType.not_equal),
                mediumlevelil.MediumLevelILFcmp_ge: partial(self.lift_condition, operation=OperationType.greater_or_equal),
                mediumlevelil.MediumLevelILFcmp_gt: partial(self.lift_condition, operation=OperationType.greater),
                mediumlevelil.MediumLevelILFcmp_le: partial(self.lift_condition, operation=OperationType.less_or_equal),
                mediumlevelil.MediumLevelILFcmp_lt: partial(self.lift_condition, operation=OperationType.less),
                mediumlevelil.MediumLevelILFcmp_o: partial(self.lift_condition, operation=OperationType.equal),
                mediumlevelil.MediumLevelILFcmp_uo: partial(self.lift_condition, operation=OperationType.equal),
                mediumlevelil.MediumLevelILRet: self.lift_return,
                mediumlevelil.MediumLevelILIf: self.lift_branch,
                mediumlevelil.MediumLevelILJump_to: self.lift_branch_indirect,
                mediumlevelil.MediumLevelILGoto: lambda x: None,
                mediumlevelil.MediumLevelILNoret: lambda x: None,
            }
        )

    def lift_condition(self, condition: mediumlevelil.MediumLevelILBinaryBase, operation: OperationType = None) -> Condition:
        """Lift the given constant value."""
        assert operation is not None
        return Condition(operation, [self._lifter.lift(condition.left), self._lifter.lift(condition.right)])

    def lift_branch(self, instruction: mediumlevelil.MediumLevelILIf) -> Branch:
        """Lift a branch instruction.. by lifting its condition."""
        condition = self._lifter.lift(instruction.condition)
        if not isinstance(condition, Condition):
            condition = Condition(OperationType.not_equal, [condition, Constant(0, condition.type.copy())])
        return Branch(condition)

    def lift_branch_indirect(self, instruction: mediumlevelil.MediumLevelILJump_to) -> IndirectBranch:
        """Lift a non-trivial jump instruction."""
        return IndirectBranch(self._lifter.lift(instruction.dest))

    def lift_return(self, instruction: mediumlevelil.MediumLevelILRet) -> Return:
        """Lift a return instruction."""
        return Return([self._lifter.lift(return_value) for return_value in instruction.src])
