from __future__ import annotations

import functools
from itertools import product
from typing import TYPE_CHECKING, Dict, Generic, Iterable, Iterator, List, Sequence, TypeVar

from decompiler.structures.logic.logic_interface import ConditionInterface, PseudoLogicInterface
from decompiler.structures.logic.z3_implementations import Z3Implementation
from decompiler.structures.pseudo import Condition
from z3 import And, Bool, BoolRef, BoolVal, Context, Not, Or, Solver, is_and, is_false, is_not, is_or, is_true, substitute

if TYPE_CHECKING:
    from decompiler.structures.ast.condition_symbol import ConditionHandler
LOGICCLASS = TypeVar("LOGICCLASS", bound="Z3LogicCondition")
PseudoLOGICCLASS = TypeVar("PseudoLOGICCLASS", bound="PseudoZ3LogicCondition")


class Z3LogicCondition(ConditionInterface, Generic[LOGICCLASS]):
    """Class in charge of implementing generic logic operations using z3."""

    SIMPLIFICATION_THRESHOLD = 2000
    COMPLEXITY_THRESHOLD = 100000

    def __init__(self, condition: BoolRef, tmp: bool = False):
        self._condition: BoolRef = condition
        self.z3 = Z3Implementation(True, self.SIMPLIFICATION_THRESHOLD, self.COMPLEXITY_THRESHOLD)

    def __str__(self) -> str:
        """Return string representation."""
        return self.z3.string_of(self._condition)

    def copy(self) -> LOGICCLASS:
        """Copy an instance of the Z3ConditionInterface."""
        return self.__class__(self._condition)

    @classmethod
    def generate_new_context(cls) -> Context:
        """Generate a context for z3-conditions."""
        return Context()

    @classmethod
    def initialize_symbol(cls, name: str, context: Context) -> LOGICCLASS:
        """Create a symbol."""
        return cls(Bool(name, ctx=context))

    @classmethod
    def initialize_true(cls, context: Context) -> LOGICCLASS:
        """Return condition tag that represents True."""
        return cls(BoolVal(True, ctx=context))

    @classmethod
    def initialize_false(cls, context: Context) -> LOGICCLASS:
        """Return condition tag that represents False."""
        return cls(BoolVal(False, ctx=context))

    @classmethod
    def disjunction_of(cls, clauses: Sequence[LOGICCLASS]) -> LOGICCLASS:
        """Creates a disjunction for the list of given clauses."""
        return cls(functools.reduce(Or, [clause._condition for clause in clauses]))

    @classmethod
    def conjunction_of(cls, clauses: Sequence[LOGICCLASS]) -> LOGICCLASS:
        """Creates a conjunction for the list of given clauses."""
        return cls(functools.reduce(And, [clause._condition for clause in clauses]))

    def __and__(self, other: LOGICCLASS) -> LOGICCLASS:
        """Logical and of two condition tag interfaces."""
        return self.__class__(And(self._condition, other._condition))

    def __or__(self, other: LOGICCLASS) -> LOGICCLASS:
        """Logical or of two condition tag interfaces."""
        return self.__class__(Or(self._condition, other._condition))

    def __invert__(self) -> LOGICCLASS:
        """Logical negate of two condition tag interfaces."""
        if self.is_negation:
            return self.__class__(self._condition.arg(0))
        return self.__class__(Not(self._condition))

    @property
    def context(self) -> Context:
        """Return context of logic condition."""
        return self._condition.ctx

    @property
    def is_true(self) -> bool:
        """Check whether the tag is the 'true-symbol'."""
        return is_true(self._condition)

    @property
    def is_false(self) -> bool:
        """Check whether the tag is the 'false-symbol'."""
        return is_false(self._condition)

    @property
    def is_disjunction(self) -> bool:
        """Check whether the condition is a disjunction of conditions, i.e. A v B v C."""
        return is_or(self._condition)

    @property
    def is_conjunction(self) -> bool:
        """Check whether the condition is a conjunction of conditions, i.e. A ^ B ^ C."""
        return is_and(self._condition)

    @property
    def is_negation(self) -> bool:
        """Check whether the condition is a negation of conditions, i.e. !A."""
        return is_not(self._condition)

    @property
    def operands(self) -> List[LOGICCLASS]:
        """Return all operands of the condition."""
        return [self.__class__(operand) for operand in self._condition.children()]

    @property
    def is_symbol(self) -> bool:
        """Check whether the object is a symbol."""
        return self.z3.is_symbol(self._condition)

    @property
    def is_literal(self) -> bool:
        """Check whether the object is a literal, i.e., a symbol or a negated symbol"""
        return self.z3.is_literal(self._condition)

    @property
    def is_disjunction_of_literals(self) -> bool:
        """
        Check whether the given condition is a disjunction of literals, i.e., whether it is
            - a symbol,
            - the negation of a symbol or
            - a disjunction of symbols or negation of symbols.
        """
        return self.z3.is_disjunction_of_literals(self._condition)

    @property
    def is_cnf_form(self) -> bool:
        """Check whether the condition is already in cnf-form."""
        return self.z3.is_cnf_form(self._condition)

    def is_equal_to(self, other: LOGICCLASS) -> bool:
        """Check whether the conditions are equal, i.e., have the same from except the ordering."""
        return self.z3.is_equal(self._condition, other._condition)

    def does_imply(self, other: LOGICCLASS) -> bool:
        """Check whether the condition implies the given condition."""
        return self.z3.does_imply(self._condition, other._condition)

    def is_complementary_to(self, other: LOGICCLASS) -> bool:
        """Check whether the condition is complementary to the given condition, i.e. self == Not(other)."""
        if self.is_true or self.is_false or other.is_true or other.is_false:
            return False
        return self.z3.does_imply(self._condition, Not(other._condition)) and self.z3.does_imply(Not(other._condition), self._condition)

    def to_cnf(self) -> LOGICCLASS:
        """Bring condition tag into cnf-form."""
        if self.is_cnf_form:
            return self
        self._condition = self.z3.z3_to_cnf(self._condition)
        return self

    def to_dnf(self) -> LOGICCLASS:
        """Bring condition tag into dnf-form."""
        dnf_form = self.__class__.initialize_true(self.context)
        dnf_form._condition = self.z3.z3_to_dnf(self._condition)
        return dnf_form

    def simplify(self) -> LOGICCLASS:
        """Simplify the given condition. Make sure that it does not destroys cnf-form."""
        self._condition = self.z3.simplify_z3_condition(self._condition)
        return self

    def get_symbols(self) -> Iterator[LOGICCLASS]:
        """Return all symbols used by the condition."""
        for z3_symbol in self.z3.get_symbols(self._condition):
            yield self.__class__(z3_symbol)

    def get_symbols_as_string(self) -> Iterator[str]:
        """Return all symbols as strings"""
        for z3_symbol in self.z3.get_symbols(self._condition):
            yield self.z3.string_of(z3_symbol)

    def get_literals(self) -> Iterator[LOGICCLASS]:
        """Return all literals used by the condition."""
        for z3_literal in self.z3.get_literals(self._condition):
            yield self.__class__(z3_literal)

    def substitute_by_true(self, condition: LOGICCLASS) -> LOGICCLASS:
        """
        Substitutes the given condition by true.

        Example: substituting in the expression (a∨b)∧c the condition (a∨b) by true results in the condition c,
             and substituting the condition c by true in the condition (a∨b)
        """
        if condition.does_imply(self):
            self._condition = BoolVal(True, ctx=condition.context)
            return self
        self.to_cnf()

        if self.is_true or self.is_false or self.is_negation or self.is_symbol:
            return self

        condition_operands: List[LOGICCLASS] = condition.operands
        numb_of_arg_expr: int = len(self.operands) if self.is_conjunction else 1
        numb_of_arg_cond: int = len(condition_operands) if condition.is_conjunction else 1

        if numb_of_arg_expr <= numb_of_arg_cond:
            return self

        expression: BoolRef = self._condition
        subexpressions: List[LOGICCLASS] = [condition] if numb_of_arg_cond == 1 else condition_operands
        for sub_expr_1, sub_expr_2 in product(subexpressions, self.operands):
            if sub_expr_1.is_equivalent_to(sub_expr_2):
                expression = substitute(expression, (sub_expr_2._condition, BoolVal(True, ctx=condition.context)))
        self._condition = expression
        return self

    def remove_redundancy(self, condition_handler: ConditionHandler) -> LOGICCLASS:
        """
        More advanced simplification of conditions.

        - The given formula is simplified using the given dictionary that maps to each symbol a pseudo-condition.
        - This helps, for example for finding switch cases, because it simplifies the condition
          'x1 & x2' if 'x1 = var < 10' and 'x2 = var == 5' to the condition 'x2'.
        """
        if self.is_literal or self.is_true or self.is_false:
            return self
        condition_map = condition_handler.get_z3_condition_map()
        condition: BoolRef = self._condition
        replacement_to_z3 = list()
        replacement_to_symbol = list()
        for symbol in self.get_symbols():
            replacement_to_z3.append((symbol._condition, condition_map[symbol]._condition))
            simplified_cond_neg = self.z3.simplify_z3_condition(Not(condition_map[symbol]._condition), resolve_negations=False)
            replacement_to_symbol.append((condition_map[symbol]._condition, symbol._condition))
            replacement_to_symbol.append((simplified_cond_neg, Not(symbol._condition)))
        condition = substitute(condition, replacement_to_z3)
        condition = self.z3.simplify_z3_condition(condition, resolve_negations=False)
        condition = substitute(condition, replacement_to_symbol)
        condition = self.z3.z3_to_cnf(condition)
        if self.z3.all_literals_contained_in_set(condition, set(symbol for symbol, _ in replacement_to_z3)):
            self._condition = condition
        return self

    def serialize(self) -> str:
        """Serialize the given condition into a SMT2 string representation."""
        solver = Solver(ctx=self.context)
        solver.add(self._condition)
        return str(solver.sexpr())

    @classmethod
    def deserialize(cls, data: str, context: Context) -> LOGICCLASS:
        """Deserialize the given string representing a z3 expression."""
        solver = Solver(ctx=context)
        solver.from_string(data)
        return cls(solver.assertions()[0])

    def rich_string_representation(self, condition_map: Dict[LOGICCLASS, Condition]):
        """Replaces each symbol by the condition of the condition map and print this condition as string."""
        return self.z3.string_of(self._condition, {cond._condition: value for cond, value in condition_map.items()})

    def get_complexity(self, condition_map: Dict[LOGICCLASS, Condition]) -> int:
        """ Returns the complexity of a logic condition"""
        complexity_sum = 0
        for literal in self.get_literals():
            if literal.is_negation: 
                complexity_sum += condition_map[~literal].complexity
            else:
                complexity_sum += condition_map[literal].complexity

        return complexity_sum

class PseudoZ3LogicCondition(PseudoLogicInterface, Z3LogicCondition, Generic[LOGICCLASS, PseudoLOGICCLASS]):
    def __init__(self, condition: BoolRef, tmp: bool = False):
        super().__init__(condition)
        self.z3 = Z3Implementation(False, self.SIMPLIFICATION_THRESHOLD, self.COMPLEXITY_THRESHOLD)

    @classmethod
    def initialize_from_condition(cls, condition: Condition, context: Context) -> PseudoLOGICCLASS:
        """Create the simplified condition from the condition of type Condition."""
        z3_condition = Z3Implementation.get_z3_condition_of(condition, context)
        return cls(z3_condition)

    @classmethod
    def initialize_from_conditions_or(cls, conditions: List[Condition], context: Context) -> PseudoLOGICCLASS:
        or_conditions = []
        for cond in conditions:
            or_conditions.append(Z3Implementation.get_z3_condition_of(cond, context))
        return cls(Or(*or_conditions))

    @classmethod
    def initialize_from_formula(cls, condition: LOGICCLASS, condition_map: Dict[LOGICCLASS, PseudoLOGICCLASS]) -> PseudoLOGICCLASS:
        """Create the simplified condition from the condition that is a formula of symbols."""
        condition.to_cnf()
        if condition.is_true:
            return cls.initialize_true(condition.context)
        if condition.is_false:
            return cls.initialize_false(condition.context)
        if condition.is_literal:
            return cls._get_condition_of_literal(condition, condition_map)
        if condition.is_disjunction:
            return cls._get_condition_of_disjunction(condition, condition_map)

        operands = list()
        for conjunction in condition.operands:
            if conjunction.is_literal:
                operands.append(cls._get_condition_of_literal(conjunction, condition_map)._condition)
            else:
                operands.append(cls._get_condition_of_disjunction(conjunction, condition_map)._condition)

        return cls(And(*operands))

    @classmethod
    def _get_condition_of_disjunction(cls, disjunction: LOGICCLASS, condition_map: Dict[LOGICCLASS, PseudoLOGICCLASS]) -> PseudoLOGICCLASS:
        """Return for a disjunction (Or) the corresponding z3-condition."""
        assert disjunction.is_disjunction, f"The input must be a disjunction, but it is {disjunction}"
        operands = [cls._get_condition_of_literal(operand, condition_map)._condition for operand in disjunction.operands]
        return cls(Or(*operands))

    @staticmethod
    def _get_condition_of_literal(literal: LOGICCLASS, condition_map: Dict[LOGICCLASS, PseudoLOGICCLASS]) -> PseudoLOGICCLASS:
        """Given a literal, i.e., a symbol or a negation of a symbol, return the condition the symbol is mapped to."""
        assert literal.is_literal, f"The input must be a literal, but it is {literal}"
        if literal.is_symbol:
            return condition_map[literal]
        return ~condition_map[~literal]
