from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Optional, Type, TypeVar

from decompiler.structures.logic.custom_logic import CustomLogicCondition, PseudoCustomLogicCondition
from decompiler.structures.logic.interface_decorators import ensure_cnf
from decompiler.structures.logic.logic_interface import ConditionInterface
from decompiler.structures.logic.z3_logic import PseudoZ3LogicCondition, Z3LogicCondition

if TYPE_CHECKING:
    from decompiler.structures.ast.condition_symbol import ConditionHandler

LOGICCLASS = TypeVar("LOGICCLASS", bound="ConditionInterface")
PseudoLOGICCLASS = TypeVar("PseudoLOGICCLASS", bound="PseudoLogicInterface")


def generate_logic_condition_class(base) -> Type[LOGICCLASS]:
    class BLogicCondition(base[LOGICCLASS]):
        @ensure_cnf
        def __init__(self, condition, tmp: bool = False):
            super().__init__(condition, tmp)

        def simplify_to_shortest(self, complexity_bound: int) -> BLogicCondition:
            """Simplify the condition to the shortest one (CNF or DNF)."""
            if self.is_true or self.is_false or self.is_symbol:
                return self

            if self._get_complexity_of_simplification() > complexity_bound:
                return self
            dnf_condition = self.to_dnf()
            if len(self) <= len(dnf_condition):
                return self
            else:
                return dnf_condition

        def _get_complexity_of_simplification(self) -> int:
            """
            Return the complexity of a given formula
             - we use it to decide whether we compute the dnf-form of a formula that is in cnf-form."""
            count = 1
            for arg in self.operands:
                count *= len(arg)
            return count

        @ensure_cnf
        def substitute_by_true(self, condition: BLogicCondition, condition_handler: Optional[ConditionHandler] = None) -> BLogicCondition:
            """
            Substitutes the given condition by true, i.e., changes the condition under the assumption that the given condition fulfilled.

            Example: substituting in the expression (a∨b)∧c the condition (a∨b) by true results in the condition c,
                 and substituting the condition c by true in the condition (a∨b)
            """
            return super().substitute_by_true(condition, condition_handler)

        @ensure_cnf
        def remove_redundancy(self, condition_handler: ConditionHandler) -> BLogicCondition:
            """
            More advanced simplification of conditions.

            - The given formula is simplified using the given dictionary that maps to each symbol a pseudo-condition.
            - This helps, for example for finding switch cases, because it simplifies the condition
              'x1 & x2' if 'x1 = var < 10' and 'x2 = var == 5' to the condition 'x2'.
            """
            return super().remove_redundancy(condition_handler)

    return BLogicCondition


LogicCondition: ConditionInterface = generate_logic_condition_class(Z3LogicCondition)
# LogicCondition = generate_logic_condition_class(CustomLogicCondition)


def generate_pseudo_logic_condition_class(base, log_cond=LogicCondition) -> Type[PseudoLOGICCLASS]:
    class BPseudoLogicCondition(log_cond, base[LOGICCLASS, PseudoLOGICCLASS]):
        pass

    return BPseudoLogicCondition


PseudoLogicCondition = generate_pseudo_logic_condition_class(PseudoZ3LogicCondition)
# PseudoLogicCondition = generate_pseudo_logic_condition_class(PseudoCustomLogicCondition)
