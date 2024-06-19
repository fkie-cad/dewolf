# Implementations on z3-level
import logging
from itertools import product
from typing import Dict, Iterator, Optional, Set

from decompiler.structures.pseudo import Condition, Constant, Expression, NotUseableConstant, OperationType, Variable
from z3 import (
    UGE,
    UGT,
    ULE,
    ULT,
    And,
    BitVec,
    BitVecRef,
    BitVecVal,
    Bool,
    BoolRef,
    BoolVal,
    Context,
    Not,
    Or,
    Repeat,
    Tactic,
    is_and,
    is_const,
    is_false,
    is_not,
    is_or,
    is_true,
    simplify,
)


class Z3Implementation:
    OPERATIONS = {
        OperationType.equal: lambda a, b: a == b,
        OperationType.not_equal: lambda a, b: a != b,
        OperationType.less: lambda a, b: a < b,
        OperationType.less_or_equal: lambda a, b: a <= b,
        OperationType.greater: lambda a, b: a > b,
        OperationType.greater_or_equal: lambda a, b: a >= b,
        OperationType.greater_us: UGT,
        OperationType.less_us: ULT,
        OperationType.greater_or_equal_us: UGE,
        OperationType.less_or_equal_us: ULE,
    }

    def __init__(self, resolve_negations: bool, simplification_threshold: int = 2000, complexity_threshold: int = 100000):
        self._resolve_negations = resolve_negations
        self._SIMPLIFICATION_THRESHOLD = simplification_threshold
        self._COMPLEXITY_THRESHOLD = complexity_threshold

    @staticmethod
    def string_of(z3_condition: BoolRef, condition_map: Optional[Dict[Bool, Condition]] = None) -> str:
        """
        Return string representation of the given z3-condition.

        If a condition map is given, then we replace the symbols by the actual conditions in the string representation.
        """
        if condition_map is None:
            condition_map = dict()
        if Z3Implementation.is_symbol(z3_condition):
            if z3_condition in condition_map:
                return str(condition_map[z3_condition])
            return f"{z3_condition}"
        if is_true(z3_condition):
            return "true"
        if is_false(z3_condition):
            return "false"
        if is_not(z3_condition):
            original_condition = z3_condition.arg(0)
            if original_condition in condition_map:
                return str(condition_map[original_condition].negate())
            return f"!{Z3Implementation.string_of(original_condition, condition_map)}"
        operands = z3_condition.children()
        if is_or(z3_condition) or is_and(z3_condition):
            symbol = "|" if is_or(z3_condition) else "&"
            if len(operands) == 1:
                return Z3Implementation.string_of(operands[0], condition_map)
            return "(" + f" {symbol} ".join([f"{Z3Implementation.string_of(operand, condition_map)}" for operand in operands]) + ")"
        return f"{z3_condition}"

    @staticmethod
    def is_symbol(condition: BoolRef):
        """Return true if the given condition is a symbol, i.e., a bool."""
        return is_const(condition) and not is_true(condition) and not is_false(condition)

    @staticmethod
    def is_literal(condition: BoolRef) -> bool:
        """Check whether the given condition is a symbol or a negated symbol."""
        if Z3Implementation.is_symbol(condition):
            return True
        return is_not(condition) and Z3Implementation.is_symbol(condition.arg(0))

    @staticmethod
    def is_disjunction_of_literals(condition: BoolRef) -> bool:
        """
        Check whether the given condition is a disjunction of literals, i.e., whether it is
            - a symbol,
            - the negation of a symbol or
            - a disjunction of symbols or negation of symbols.
        """
        if Z3Implementation.is_literal(condition):
            return True
        return is_or(condition) and all(Z3Implementation.is_literal(literal) for literal in condition.children())

    @staticmethod
    def is_cnf_form(condition: BoolRef) -> bool:
        """Checks whether the given condition is in CNF form"""
        if Z3Implementation.is_disjunction_of_literals(condition):
            return True
        return is_and(condition) and all(Z3Implementation.is_disjunction_of_literals(clause) for clause in condition.children())

    @staticmethod
    def is_equal(term1: BoolRef, term2: BoolRef) -> bool:
        """Check whether two formulas are equal, i.e. have the same form except of the ordering."""
        if (is_true(term1) and is_true(term2)) or (is_false(term1) and is_false(term2)):
            return True
        if str(term1.decl()) != str(term2.decl()) or (is_const(term1) and str(term1) != str(term2)):
            return False
        arguments_term_1 = Z3Implementation._get_operands_of(term1)
        arguments_term_2 = Z3Implementation._get_operands_of(term2)
        if len(arguments_term_1) != len(arguments_term_2):
            return False
        for argument1 in arguments_term_1:
            for argument2 in arguments_term_2:
                if Z3Implementation.is_equal(argument1, argument2):
                    arguments_term_2.remove(argument2)
                    break
            else:
                return False
        return True

    def does_imply(self, condition: BoolRef, other: BoolRef) -> bool:
        tmp_condition = self.simplify_z3_condition(Or(Not(condition), other))
        return is_true(tmp_condition)

    def z3_to_cnf(self, condition: BoolRef) -> BoolRef:
        """Given a z3 formula it returns a z3 formula in CNF form"""
        condition = self.simplify_z3_condition(condition)
        if self.is_cnf_form(condition):
            return condition
        if self._is_disjunction_of_two_cnf_formulas(condition):
            return self._to_cnf_for_disjunction_of_cnf_formulas(condition)

        if is_or(condition):
            if (conjunction := self._get_conjunction_of(condition)) is None:
                return condition
            remaining_condition = [child for child in condition.children() if not child == conjunction]
            return self.simplify_z3_condition(And([self.z3_to_cnf(Or(arg, *remaining_condition)) for arg in conjunction.children()]))
        elif is_and(condition):
            return self.simplify_z3_condition(And([self.z3_to_cnf(child) for child in condition.children()]))
        else:
            return condition

    def z3_to_dnf(self, condition: BoolRef) -> BoolRef:
        """Given a z3 formula it returns a z3 formula in DNF form"""
        condition = self.simplify_z3_condition(condition)
        if is_and(condition):
            disjunction = None
            for child in condition.children():
                if is_or(child):
                    disjunction = child
                    break
            if disjunction is None:
                return condition
            remaining_condition = [child for child in condition.children() if not child == disjunction]
            return self.simplify_z3_condition(Or(*[self.z3_to_dnf(And(arg, *remaining_condition)) for arg in disjunction.children()]))
        elif is_or(condition):
            return self.simplify_z3_condition(Or(*[self.z3_to_dnf(child) for child in condition.children()]))
        else:
            return condition

    def simplify_z3_condition(self, z3_condition: BoolRef, resolve_negations: bool = True) -> BoolRef:
        """
        Simplify the given z3 condition
         - if resolve negation is true, we first remove Not(....)
         - Depending on the complexity of the condition we choose different simplification tactics.
        """
        if self._resolve_negations and resolve_negations:
            z3_condition = self._resolve_negation(z3_condition)
        z3_condition = simplify(z3_condition)
        z3_condition = simplify(Repeat(Tactic("ctx-simplify", ctx=z3_condition.ctx))(z3_condition).as_expr())
        if not self._too_large_to_fully_simplify(z3_condition):
            z3_condition = simplify(Repeat(Tactic("ctx-solver-simplify", ctx=z3_condition.ctx))(z3_condition).as_expr())
        return z3_condition

    @staticmethod
    def get_symbols(condition: BoolRef) -> Iterator[BoolRef]:
        """Return all symbols of the given expression."""
        if Z3Implementation.is_symbol(condition):
            yield condition
        for child in condition.children():
            yield from Z3Implementation.get_symbols(child)

    @staticmethod
    def get_literals(condition: BoolRef) -> Iterator[BoolRef]:
        """Return the literals of the given z3-condition."""
        if Z3Implementation.is_literal(condition):
            yield condition
        elif is_or(condition) or is_and(condition) or is_not(condition):
            for child in condition.children():
                yield from Z3Implementation.get_literals(child)
        else:
            assert is_true(condition) or is_false(condition), f"The condition {condition} does not consist of literals."

    @staticmethod
    def all_literals_are_symbols(condition: BoolRef) -> bool:
        """Check for a cnf-formula whether all literals or their negation are symbols of the given set of literals."""
        if is_true(condition) or is_false(condition):
            return True
        try:
            for _ in Z3Implementation.get_literals(condition):
                pass
            return True
        except AssertionError:
            return False

    @staticmethod
    def get_z3_condition_of(condition: Condition, context: Context) -> BoolRef:
        """
        Convert a given condition a op b into the z3-condition bit_vec_a op bit_vec_b.

        a and b can be any type of Expression. The name of the BitVec or BitVecVal (for Constants) reflects the expression as well as
        the SSA-variable names that occur in the expression.
        """
        if condition.left.type.size != condition.right.type.size:
            logging.info(
                f"The operands of {condition} have different sizes: {condition.left.type.size} & {condition.right.type.size}. Increase the size of the smaller one."
            )
        bit_vec_size = max(condition.left.type.size, condition.right.type.size, 1)
        operand_1: BitVecRef = Z3Implementation.convert_expression(condition.left, bit_vec_size, context)
        operand_2: BitVecRef = Z3Implementation.convert_expression(condition.right, bit_vec_size, context)
        return Z3Implementation.OPERATIONS[condition.operation](operand_1, operand_2)

    @staticmethod
    def convert_expression(expression: Expression, bit_vec_size: Optional[int] = None, context: Optional[Context] = None) -> BitVecRef:
        """Convert the given expression into a z3 bit-vector."""
        if bit_vec_size is None:
            bit_vec_size = expression.type.size
        if isinstance(expression, NotUseableConstant):
            return BitVec(expression.value, bit_vec_size, ctx=context)
        if isinstance(expression, Constant):
            return BitVecVal(expression.value, bit_vec_size, ctx=context)
        elif isinstance(expression, Variable):
            return BitVec(f"{expression},{expression.ssa_name}", bit_vec_size, ctx=context)
        else:
            return BitVec(f"{expression},{[str(var.ssa_name) for var in expression.requirements]}", bit_vec_size, ctx=context)

    @staticmethod
    def _resolve_negation(input_cond: BoolRef):
        """Remove Not(Y) where Y is a logic formula that is not a single symbol or a comparison."""
        if is_not(input_cond):
            argument = input_cond.arg(0)
            if is_true(argument):
                return BoolVal(False, ctx=input_cond.ctx)
            if is_false(argument):
                return BoolVal(True, ctx=input_cond.ctx)
            if is_not(argument):
                return Z3Implementation._resolve_negation(argument.arg(0))
            if is_and(argument):
                return Or(*[Z3Implementation._resolve_negation(Not(child)) for child in argument.children()])
            if is_or(argument):
                return And(*[Z3Implementation._resolve_negation(Not(child)) for child in argument.children()])
            return input_cond
        if is_and(input_cond):
            return And(*[Z3Implementation._resolve_negation(child) for child in input_cond.children()])
        if is_or(input_cond):
            return Or(*[Z3Implementation._resolve_negation(child) for child in input_cond.children()])
        return input_cond

    def _too_large_to_fully_simplify(self, z3_condition: BoolRef) -> bool:
        """Checks whether a z3-formula is too large to apply the tactic `ctx-solver-simplify."""
        if z3_condition.num_args() > self._SIMPLIFICATION_THRESHOLD:
            return True

        complexity = 0
        for term in z3_condition.children():
            complexity += 1 if is_const(term) else term.num_args()
            if complexity > self._SIMPLIFICATION_THRESHOLD:
                return True

        return sum(1 for _ in self.get_symbols(z3_condition)) > self._COMPLEXITY_THRESHOLD

    def _to_cnf_for_disjunction_of_cnf_formulas(self, condition: BoolRef) -> BoolRef:
        """Given a z3 formula that is a disjunction of two cnf-formulas it returns a z3 formula in CNF form"""
        cnf_literals_cond1 = condition.arg(0).children() if is_and(condition.arg(0)) else [condition.arg(0)]
        cnf_literals_cond2 = condition.arg(1).children() if is_and(condition.arg(1)) else [condition.arg(1)]
        cnf_formula = And(
            [self.simplify_z3_condition(Or(term1, term2)) for term1, term2 in product(cnf_literals_cond1, cnf_literals_cond2)]
        )
        if self._too_large_to_fully_simplify(cnf_formula):
            return simplify(cnf_formula)
        return self.simplify_z3_condition(cnf_formula)

    @staticmethod
    def _get_conjunction_of(condition: BoolRef) -> Optional[BoolRef]:
        """If the condition has a conjunction as operand, then we return it, otherwise return None."""
        for child in condition.children():
            if is_and(child):
                return child
        return None

    @staticmethod
    def _is_disjunction_of_two_cnf_formulas(condition: BoolRef) -> bool:
        """We check whether the given condition is a disjunction of two cnf formulas, i.e., whether condition = (CNF) v (CNF)."""
        if not is_or(condition) or not condition.num_args() == 2:
            return False

        for child in condition.children():
            if not (is_and(child) or Z3Implementation.is_disjunction_of_literals(child)):
                return False
            if is_and(child):
                for term in child.children():
                    if not Z3Implementation.is_disjunction_of_literals(term):
                        return False
        return True

    @staticmethod
    def _get_operands_of(term: BoolRef):
        """
        Given a z3 formula, we return all operands.

        However, if an operand is of the same type as the term itwe return its operands instead, i.e.,
        if term= (a v b) ^ (c ^ d) ^ x ^ (y v (x ^ z) ) ^ (u ^ (y v z)) we return the operands [(a v b), c, d, x, y v (x ^ z), u, y v z]
        """
        new_operands = term.children()
        term_operands = []
        while new_operands:
            operand = new_operands.pop()
            if operand.decl() == term.decl():
                new_operands += operand.children()
            else:
                term_operands.append(operand)
        return term_operands
