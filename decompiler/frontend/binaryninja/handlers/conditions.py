"""Module implementing the ConditionHandler class."""
from binaryninja import mediumlevelil, MediumLevelILOperation

from dewolf.frontend.lifter import Handler
from dewolf.structures.pseudo import OperationType, Condition, Branch, Return, IndirectBranch, Constant


class ConditionHandler(Handler):
    """Handler for mlil conditions and branches,"""

    # Dict mapping mlil instruction to pseudo OperationTypes
    CONDITIONS = {
        MediumLevelILOperation.MLIL_CMP_E: OperationType.equal,
        MediumLevelILOperation.MLIL_CMP_NE: OperationType.not_equal,
        MediumLevelILOperation.MLIL_CMP_SLT: OperationType.less,
        MediumLevelILOperation.MLIL_CMP_ULT: OperationType.less_us,
        MediumLevelILOperation.MLIL_CMP_SLE: OperationType.less_or_equal,
        MediumLevelILOperation.MLIL_CMP_ULE: OperationType.less_or_equal_us,
        MediumLevelILOperation.MLIL_CMP_SGE: OperationType.greater_or_equal,
        MediumLevelILOperation.MLIL_CMP_UGE: OperationType.greater_or_equal_us,
        MediumLevelILOperation.MLIL_CMP_SGT: OperationType.greater,
        MediumLevelILOperation.MLIL_CMP_UGT: OperationType.greater_us,
        MediumLevelILOperation.MLIL_FCMP_E: OperationType.equal,
        MediumLevelILOperation.MLIL_FCMP_NE: OperationType.not_equal,
        MediumLevelILOperation.MLIL_FCMP_GE: OperationType.greater_or_equal,
        MediumLevelILOperation.MLIL_FCMP_GT: OperationType.greater,
        MediumLevelILOperation.MLIL_FCMP_LE: OperationType.less_or_equal,
        MediumLevelILOperation.MLIL_FCMP_LT: OperationType.less,
        MediumLevelILOperation.MLIL_FCMP_O: OperationType.power,
        MediumLevelILOperation.MLIL_FCMP_UO: OperationType.power,
    }

    def register(self):
        self._lifter.HANDLERS.update({
            mediumlevelil.MediumLevelILCmp_e: self.lift_condition,
            mediumlevelil.MediumLevelILCmp_ne: self.lift_condition,
            mediumlevelil.MediumLevelILCmp_sge: self.lift_condition,
            mediumlevelil.MediumLevelILCmp_sgt: self.lift_condition,
            mediumlevelil.MediumLevelILCmp_sle: self.lift_condition,
            mediumlevelil.MediumLevelILCmp_slt: self.lift_condition,
            mediumlevelil.MediumLevelILCmp_uge: self.lift_condition,
            mediumlevelil.MediumLevelILCmp_ugt: self.lift_condition,
            mediumlevelil.MediumLevelILCmp_ule: self.lift_condition,
            mediumlevelil.MediumLevelILCmp_ult: self.lift_condition,
            mediumlevelil.MediumLevelILFcmp_e: self.lift_condition,
            mediumlevelil.MediumLevelILFcmp_ne: self.lift_condition,
            mediumlevelil.MediumLevelILFcmp_ge: self.lift_condition,
            mediumlevelil.MediumLevelILFcmp_gt: self.lift_condition,
            mediumlevelil.MediumLevelILFcmp_le: self.lift_condition,
            mediumlevelil.MediumLevelILFcmp_lt: self.lift_condition,
            mediumlevelil.MediumLevelILFcmp_o: self.lift_condition,
            mediumlevelil.MediumLevelILFcmp_uo: self.lift_condition,
            mediumlevelil.MediumLevelILRet: self.lift_return,
            mediumlevelil.MediumLevelILIf: self.lift_branch,
            mediumlevelil.MediumLevelILJump_to: self.lift_branch_indirect,
            mediumlevelil.MediumLevelILGoto: lambda x: None,
            mediumlevelil.MediumLevelILNoret: lambda x: None,
        })

    def lift_condition(self, condition: mediumlevelil.MediumLevelILBinaryBase) -> Condition:
        """Lift the given constant value."""
        return Condition(
            self.CONDITIONS[condition.operation],
            [self._lifter.lift(condition.left), self._lifter.lift(condition.right)],
        )

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
