from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Dict, Generic, Iterable, Iterator, List, Sequence, TypeVar

from decompiler.structures.pseudo import Condition

if TYPE_CHECKING:
    from decompiler.structures.ast.condition_symbol import ConditionHandler

CONTEXT = TypeVar("CONTEXT")


class LogicInterface(ABC, Generic[CONTEXT]):
    """Class in charge of implementing generic logic operations."""

    @classmethod
    @abstractmethod
    def generate_new_context(cls):
        """Generate a context for the logic formulas."""

    @property
    @abstractmethod
    def context(self):
        """Return the context of the logic formula"""

    @abstractmethod
    def __and__(self, other: LogicInterface) -> LogicInterface:
        """Logical and of two condition tag interfaces."""

    def __iand__(self, other: LogicInterface) -> LogicInterface:
        """Logical and of self with another condition tag."""
        return self & other

    @abstractmethod
    def __or__(self, other: LogicInterface) -> LogicInterface:
        """Logical or of two condition tag interfaces."""

    def __ior__(self, other: LogicInterface) -> LogicInterface:
        """Logical or of self with another condition tag."""
        return self | other

    @abstractmethod
    def __invert__(self) -> LogicInterface:
        """Logical negate of two condition tag interfaces."""

    @property
    @abstractmethod
    def is_true(self) -> bool:
        """Check whether the tag is the 'true-symbol'."""

    @property
    @abstractmethod
    def is_false(self) -> bool:
        """Check whether the tag is the 'false-symbol'."""

    @property
    @abstractmethod
    def is_disjunction(self) -> bool:
        """Check whether the condition is a disjunction of conditions, i.e. A v B v C."""

    @property
    @abstractmethod
    def is_conjunction(self) -> bool:
        """Check whether the condition is a conjunction of conditions, i.e. A ^ B ^ C."""

    @property
    @abstractmethod
    def is_negation(self) -> bool:
        """Check whether the condition is a negation of conditions, i.e. !A."""


class ConditionInterface(LogicInterface, ABC, Generic[CONTEXT]):
    """Class in charge of handling boolean formulas with symbols."""

    def __eq__(self, other: LogicInterface) -> bool:
        """Check that the string returns the same formula."""
        return hash(self) == hash(other)

    def __hash__(self) -> int:
        return hash((self.__class__, str(self)))

    @abstractmethod
    def copy(self) -> LogicInterface:
        """Copy the logic interface"""

    @classmethod
    @abstractmethod
    def initialize_symbol(cls, name: str, context: CONTEXT) -> ConditionInterface:
        """Create a symbol."""

    @classmethod
    @abstractmethod
    def initialize_true(cls, context: CONTEXT) -> ConditionInterface:
        """Return condition tag that represents True."""

    @classmethod
    @abstractmethod
    def initialize_false(cls, context: CONTEXT) -> ConditionInterface:
        """Return condition tag that represents False."""

    @classmethod
    @abstractmethod
    def disjunction_of(cls, clauses: Sequence[ConditionInterface]) -> ConditionInterface:
        """Creates a disjunction for the list of given clauses."""

    @classmethod
    @abstractmethod
    def conjunction_of(cls, clauses: Sequence[ConditionInterface]) -> ConditionInterface:
        """Creates a conjunction for the list of given clauses."""

    @abstractmethod
    def __str__(self) -> str:
        """Return string representation."""

    def __repr__(self) -> str:
        """Return representation."""
        return str(self)

    def __len__(self) -> int:
        """Returns the length of a formula, which corresponds to its complexity."""
        return sum(1 for _ in self.get_symbols())

    @property
    @abstractmethod
    def operands(self) -> List[ConditionInterface]:
        """Return all operands of the condition."""

    @property
    @abstractmethod
    def is_symbol(self) -> bool:
        """Check whether the object is a symbol."""

    @property
    def is_literal(self) -> bool:
        """Check whether the object is a literal, i.e., a symbol or a negated symbol"""
        if self.is_symbol:
            return True
        return self.is_negation and (~self).is_symbol

    @property
    def is_disjunction_of_literals(self) -> bool:
        """
        Check whether the given condition is a disjunction of literals, i.e., whether it is
            - a symbol,
            - the negation of a symbol or
            - a disjunction of symbols or negation of symbols.
        """
        if self.is_literal:
            return True
        return self.is_disjunction and all(operand.is_literal for operand in self.operands)

    @property
    def is_cnf_form(self) -> bool:
        """Check whether the condition is already in cnf-form."""
        if self.is_true or self.is_false or self.is_disjunction_of_literals:
            return True
        return self.is_conjunction and all(clause.is_disjunction_of_literals for clause in self.operands)

    def is_equivalent_to(self, other: ConditionInterface) -> bool:
        """Check whether the condition is equivalent to the given condition."""
        if self.is_equal_to(other):
            return True
        return self.does_imply(other) and other.does_imply(self)

    @abstractmethod
    def is_equal_to(self, other: ConditionInterface) -> bool:
        """Check whether the conditions are equal, i.e., have the same form except the ordering."""

    def does_imply(self, other: ConditionInterface) -> bool:
        """Check whether the condition implies the given condition."""
        tmp_condition = (~self | other).simplify()
        return tmp_condition.is_true

    def is_complementary_to(self, other: ConditionInterface) -> bool:
        """Check whether the condition is complementary to the given condition, i.e. self == Not(other)."""
        if self.is_true or self.is_false or other.is_true or other.is_false:
            return False
        return self.is_equivalent_to(~other)

    @abstractmethod
    def to_cnf(self) -> None:
        """Bring condition tag into cnf-form."""

    @abstractmethod
    def to_dnf(self) -> LogicInterface:
        """Bring condition tag into dnf-form."""

    @abstractmethod
    def simplify(self) -> ConditionInterface:
        """Simplify the given condition. Make sure that it does not destroy cnf-form."""

    @abstractmethod
    def get_symbols(self) -> Iterator[ConditionInterface]:
        """Return all symbols used by the condition."""

    @abstractmethod
    def get_symbols_as_string(self) -> Iterator[str]:
        """Return all symbols as strings"""

    @abstractmethod
    def get_literals(self) -> Iterator[ConditionInterface]:
        """Return all literals used by the condition."""

    @abstractmethod
    def substitute_by_true(self, condition: ConditionInterface) -> ConditionInterface:
        """
        Substitutes the given condition by true.

        Example: substituting in the expression (a∨b)∧c the condition (a∨c) by true results in the condition c,
             and substituting the condition c by true in the condition (a∨b)
        """

    @abstractmethod
    def remove_redundancy(self, condition_handler: ConditionHandler) -> ConditionInterface:
        """
        More advanced simplification of conditions.

        - The given formula is simplified using the given dictionary that maps to each symbol a pseudo-condition.
        - This helps, for example for finding switch cases, because it simplifies the condition
          'x1 & x2' if 'x1 = var < 10' and 'x2 = var == 5' to the condition 'x2'.
        """

    @classmethod
    @abstractmethod
    def get_logic_condition(cls, real_condition: PseudoLogicInterface, condition_handler: ConditionHandler) -> ConditionInterface:
        """Generate a symbol condition given the real-condition together with the condition handler."""

    @abstractmethod
    def serialize(self) -> str:
        """Serializes a condition as a string"""

    @classmethod
    @abstractmethod
    def deserialize(cls, data: str, context: CONTEXT) -> LogicInterface:
        """Deserialize a condition from a string."""

    @abstractmethod
    def rich_string_representation(self, condition_map: Dict[LogicInterface, Condition]):
        """Replaces each symbol by the condition of the condition map."""

    def get_complexity(self, condition_map: Dict[LogicInterface, Condition]) -> int:
        """Returns the complexity of a logic condition"""
        complexity_sum = 0
        for literal in self.get_literals():
            if literal.is_negation:
                complexity_sum += condition_map[~literal].complexity
            else:
                complexity_sum += condition_map[literal].complexity

        return complexity_sum


class PseudoLogicInterface(ConditionInterface, ABC):
    @classmethod
    @abstractmethod
    def initialize_from_condition(cls, condition: Condition, context: CONTEXT) -> PseudoLogicInterface:
        """Create the simplified condition from the condition of type Condition."""

    @classmethod
    @abstractmethod
    def initialize_from_conditions_or(cls, conditions: List[Condition], context: CONTEXT) -> PseudoLogicInterface:
        """Create the simplified condition from Or(conditions), where each condition is of type Condition."""

    @classmethod
    @abstractmethod
    def initialize_from_formula(
        cls, condition: ConditionInterface, condition_map: Dict[ConditionInterface, PseudoLogicInterface]
    ) -> PseudoLogicInterface:
        """Create the simplified condition from the condition that is a formula of symbols."""
