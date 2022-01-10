from __future__ import annotations

import logging
from itertools import product
from typing import Dict, Generic, Iterator, List, Sequence, TypeVar

import decompiler.structures.pseudo as pseudo
from decompiler.structures.logic.logic_interface import ConditionInterface, PseudoLogicInterface
from simplifier.operations import BitwiseAnd, BitwiseNegate, BitwiseOr
from simplifier.range_simplifier import RangeSimplifier
from simplifier.visitor import ToCnfVisitor
from simplifier.visitor.serialize_visitor import SerializeVisitor
from simplifier.world.nodes import BaseVariable, BitVector, Constant, Operation, TmpVariable, Variable, WorldObject
from simplifier.world.world import World

LOGICCLASS = TypeVar("LOGICCLASS", bound="CustomLogicCondition")
PseudoLOGICCLASS = TypeVar("PseudoLOGICCLASS", bound="PseudoCustomLogicCondition")


class CustomLogicCondition(ConditionInterface, Generic[LOGICCLASS]):
    """Class in charge of implementing generic logic operations using costume logic."""

    def __init__(self, condition: WorldObject, tmp: bool = False):
        if isinstance(condition, Variable):
            self._variable = condition
        else:
            self._variable: BaseVariable = condition.world.new_variable(condition.size, tmp)
            self.context.define(self._variable, condition)

    @classmethod
    def generate_new_context(cls) -> World:
        """Generate a context for z3-conditions."""
        return World()

    @property
    def _condition(self) -> WorldObject:
        if term := self.context.get_definition(self._variable):
            return term
        return self._variable

    def __len__(self) -> int:
        """Returns the length of a formula, which corresponds to its complexity."""
        if isinstance(self._condition, Variable):
            return 1
        count = 0
        for node in self.context.iter_postorder(self._condition):
            if not isinstance(node, Operation):
                continue
            count += sum(1 for op in node.operands if isinstance(op, Variable))
        return count

    def __str__(self) -> str:
        """Return string representation."""
        condition = self._condition
        if isinstance(condition, Constant) and condition.size == 1:
            return "false" if condition.unsigned == 0 else "true"
        return str(condition)

    def copy(self) -> LOGICCLASS:
        """Copy an instance of the Z3ConditionInterface."""
        return self.__class__(self._condition)

    @classmethod
    def initialize_symbol(cls, name: str, context: World) -> LOGICCLASS:
        """Create a symbol."""
        return cls(context.variable(name, 1))

    @classmethod
    def initialize_true(cls, context: World) -> LOGICCLASS:
        """Return condition tag that represents True."""
        return cls(context.constant(1, 1))

    @classmethod
    def initialize_false(cls, context: World) -> LOGICCLASS:
        """Return condition tag that represents False."""
        return cls(context.constant(0, 1))

    @classmethod
    def disjunction_of(cls, clauses: Sequence[LOGICCLASS]) -> LOGICCLASS:
        """Creates a disjunction for the list of given clauses."""
        world = clauses[0].context
        return cls(world.bitwise_or(*(clause._condition for clause in clauses)))

    @classmethod
    def conjunction_of(cls, clauses: Sequence[LOGICCLASS]) -> LOGICCLASS:
        """Creates a conjunction for the list of given clauses."""
        world = clauses[0].context
        return cls(world.bitwise_and(*(clause._condition for clause in clauses)))

    def __and__(self, other: LOGICCLASS) -> LOGICCLASS:
        """Logical and of two condition tag interfaces."""
        return self.__class__(self.context.bitwise_and(self._condition, other._condition))

    def __or__(self, other: LOGICCLASS) -> LOGICCLASS:
        """Logical or of two condition tag interfaces."""
        return self.__class__(self.context.bitwise_or(self._condition, other._condition))

    def __invert__(self) -> LOGICCLASS:
        """Logical negate of two condition tag interfaces."""
        return self.__class__(self._custom_negate(self._condition))

    def _custom_negate(self, condition: WorldObject) -> WorldObject:
        """Negate the given world object."""
        if isinstance(condition, BitwiseNegate):
            return condition.operand
        return self.context.bitwise_negate(condition)

    @property
    def context(self) -> World:
        """Return context of logic condition."""
        return self._variable.world

    @property
    def is_true(self) -> bool:
        """Check whether the tag is the 'true-symbol'."""
        return isinstance(self._condition, Constant) and self._condition.unsigned != 0

    @property
    def is_false(self) -> bool:
        """Check whether the tag is the 'false-symbol'."""
        return isinstance(self._condition, Constant) and self._condition.unsigned == 0

    @property
    def is_disjunction(self) -> bool:
        """Check whether the condition is a disjunction of conditions, i.e. A v B v C."""
        return isinstance(self._condition, BitwiseOr)

    @property
    def is_conjunction(self) -> bool:
        """Check whether the condition is a conjunction of conditions, i.e. A ^ B ^ C."""
        return isinstance(self._condition, BitwiseAnd)

    @property
    def is_negation(self) -> bool:
        """Check whether the condition is a negation of conditions, i.e. !A."""
        return isinstance(self._condition, BitwiseNegate)

    @property
    def operands(self) -> List[LOGICCLASS]:
        """Return all operands of the condition."""
        return self._get_operands()

    def _get_operands(self, tmp: bool = False):
        """Get operands."""
        condition = self._condition
        if isinstance(condition, BitVector):
            return []
        assert isinstance(condition, Operation), f"The condition must be an operation."
        return [self.__class__(operand, tmp) for operand in condition.operands]

    @property
    def is_symbol(self) -> bool:
        """Check whether the object is a symbol."""
        return self._is_symbol(self._condition)  # TODO

    @property
    def is_literal(self) -> bool:
        """Check whether the object is a literal, i.e., a symbol or a negated symbol"""
        return self._is_literal(self._condition)  # TODO

    # @property
    # def is_disjunction_of_literals(self) -> bool:
    #     """
    #     Check whether the given condition is a disjunction of literals, i.e., whether it is
    #         - a symbol,
    #         - the negation of a symbol or
    #         - a disjunction of symbols or negation of symbols.
    #     """
    #     return self.z3.is_disjunction_of_literals(self._condition)

    # @property
    # def is_cnf_form(self) -> bool:
    #     """Check whether the condition is already in cnf-form."""
    #     return self.z3.is_cnf_form(self._condition)

    def is_equal_to(self, other: LOGICCLASS) -> bool:
        """Check whether the conditions are equal, i.e., have the same from except the ordering."""
        return World.compare(self._condition, other._condition)

    def does_imply(self, other: LOGICCLASS) -> bool:
        """Check whether the condition implies the given condition."""
        tmp_condition = self.__class__(self.context.bitwise_or(self._custom_negate(self._condition), other._condition), tmp=True)
        self.context.free_world_condition(tmp_condition._variable)
        tmp_condition._variable.simplify()
        if tmp_condition.is_true:
            self.context.cleanup()
            return True
        return False

    # def is_complementary_to(self, other: LOGICCLASS) -> bool:
    #     """Check whether the condition is complementary to the given condition, i.e. self == Not(other)."""
    #     if self.is_true or self.is_false or other.is_true or other.is_false:
    #         return False
    #     return self.z3.does_imply(self._condition, Not(other._condition)) and self.z3.does_imply(Not(other._condition), self._condition)

    def to_cnf(self) -> LOGICCLASS:
        """Bring condition tag into cnf-form."""
        if self.is_cnf_form:
            return self
        self.context.free_world_condition(self._variable)
        ToCnfVisitor(self._variable)
        return self

    def to_dnf(self) -> LOGICCLASS:
        """Bring condition tag into dnf-form."""
        raise NotImplementedError(f"To DNF is not implemented so far")
        # dnf_form = self.__class__.initialize_true()
        # dnf_form._condition = self.z3.z3_to_dnf(self._condition)
        # return dnf_form

    def simplify(self) -> LOGICCLASS:
        """Simplify the given condition. Make sure that it does not destroys cnf-form."""
        self.context.free_world_condition(self._variable)
        self._variable.simplify()
        tmp_var = False
        if isinstance(self._variable, TmpVariable):
            new_var = self.context.variable(f"Simplify", 1)
            self.context.define(new_var, self._condition)
            tmp_var = True
        RangeSimplifier.simplify(self._condition)
        if tmp_var:
            self._variable = self.context.new_variable(1, tmp=True)
            self.context.substitute(new_var, self._variable)
        return self

    def get_symbols(self) -> Iterator[LOGICCLASS]:
        """Return all symbols used by the condition."""
        for node in self.context.iter_postorder(self._condition):
            if self._is_symbol(node):
                yield self.__class__(node)

    def get_symbols_as_string(self) -> Iterator[str]:
        """Return all symbols as strings"""
        for node in self.context.iter_postorder(self._condition):
            if self._is_symbol(node):
                yield str(node)

    def get_literals(self) -> Iterator[LOGICCLASS]:
        """Return all literals used by the condition."""
        for literal in self._get_literals(self._condition):
            yield self.__class__(literal)

    def substitute_by_true(self, condition: LOGICCLASS) -> LOGICCLASS:
        """
        Substitutes the given condition by true.

        Example: substituting in the expression (a∨b)∧c the condition (a∨b) by true results in the condition c,
             and substituting the condition c by true in the condition (a∨b)
        """
        assert self.context == condition.context, f"The condition must be contained in the same graph."
        if not self.is_true and (self.is_equal_to(condition) or condition.does_imply(self)):
            if self.is_symbol:
                self._variable: BaseVariable = self.context.new_variable(self._condition.size)
                self.context.define(self._variable, self.context.constant(1, 1))
            else:
                self.context.replace(self._condition, self.context.constant(1, 1))
            self.context.cleanup()
            return self
        self.to_cnf()

        if self.is_true or self.is_false or self.is_negation or self.is_symbol:
            return self

        condition_operands: List[WorldObject] = condition._get_operands(tmp=True)
        operands = self._get_operands(tmp=True)
        numb_of_arg_expr: int = len(operands) if self.is_conjunction else 1
        numb_of_arg_cond: int = len(condition_operands) if condition.is_conjunction else 1

        if numb_of_arg_expr <= numb_of_arg_cond:
            self.context.cleanup()
            return self

        subexpressions: List[LOGICCLASS] = [condition] if numb_of_arg_cond == 1 else condition_operands
        for sub_expr_1, sub_expr_2 in product(subexpressions, self.operands):
            if sub_expr_1.is_equivalent_to(sub_expr_2):
                relations = self.context.get_relation(self._condition, sub_expr_2._condition)
                for relation in relations:
                    self.context.remove_operand(self._condition, relation.sink)
        self.context.cleanup()
        return self

    def remove_redundancy(self, condition_map: Dict[LOGICCLASS, PseudoCustomLogicCondition]) -> LOGICCLASS:
        """
        More advanced simplification of conditions.

        - The given formula is simplified using the given dictionary that maps to each symbol a pseudo-condition.
        - This helps, for example for finding switch cases, because it simplifies the condition
          'x1 & x2' if 'x1 = var < 10' and 'x2 = var == 5' to the condition 'x2'.
        """
        if self.is_literal or self.is_true or self.is_false:
            return self
        assert isinstance(self._condition, Operation), "We only remove redundancy for operations"

        copied_condition = PseudoCustomLogicCondition(self._condition)
        self.context.free_world_condition(copied_condition._variable)
        condition_nodes = set(self.context.iter_postorder(copied_condition._variable))

        replacement_dict: Dict[WorldObject, WorldObject] = dict()
        for symbol in self.get_symbols():
            world_symbol = symbol._condition
            parent_operations = [parent for parent in self.context.parent_operation(world_symbol) if parent in condition_nodes]
            for parent in parent_operations:
                for relation in self.context.get_relation(parent, world_symbol):
                    index = relation.index
                    self.context.remove_operand(parent, relation.sink)
                    self.context.add_operand(parent, condition_map[symbol]._condition, index)
                    replacement_dict[condition_map[symbol]._condition] = world_symbol

        self.context.free_world_condition(copied_condition._variable)
        RangeSimplifier.simplify(copied_condition._condition)
        non_logic_operands = {
            node
            for node in self.context.iter_postorder(copied_condition._variable)
            if isinstance(node, Operation) and not isinstance(node, (BitwiseOr, BitwiseAnd, BitwiseNegate))
        }
        for operand in non_logic_operands:
            for condition, symbol in replacement_dict.items():
                if World.compare(condition, operand):
                    self.context.replace(operand, symbol)
                    break
            else:
                self.context.cleanup()
                return self

        self.context.replace(self._condition, copied_condition._condition)
        self.context.cleanup()
        return self

    def serialize(self) -> str:
        """Serialize the given condition into a SMT2 string representation."""
        return self._condition.accept(SerializeVisitor())

    @classmethod
    def deserialize(cls, data: str, context: World) -> LOGICCLASS:
        """Deserialize the given string representing a z3 expression."""
        return CustomLogicCondition(context.from_string(data))

    def rich_string_representation(self, condition_map: Dict[LOGICCLASS, pseudo.Condition]):
        """Replaces each symbol by the condition of the condition map and print this condition as string."""
        return self._rich_string_representation(
            self._condition, {symbol._condition: condition for symbol, condition in condition_map.items()}
        )

    # some world-implementation helpers:

    def _is_symbol(self, condition: WorldObject) -> bool:
        return isinstance(condition, Variable) and condition.size == 1 and self.context.get_definition(condition) is None

    def _is_literal(self, condition: WorldObject) -> bool:
        return self._is_symbol(condition) or (isinstance(condition, BitwiseNegate) and self._is_symbol(condition.operand))

    def _get_literals(self, condition: WorldObject):
        if self._is_literal(condition):
            yield condition
        elif isinstance(condition, (BitwiseOr, BitwiseAnd, BitwiseNegate)):
            for child in condition.operands:
                yield from self._get_literals(child)
        else:
            assert isinstance(condition, Constant) and condition.size == 1, f"The condition {condition} does not consist of literals."

    def _rich_string_representation(self, condition: WorldObject, condition_map: Dict[Variable, pseudo.Condition]):
        if self._is_symbol(condition):
            if condition in condition_map:
                return str(condition_map[condition])
            return f"{condition}"
        if isinstance(condition, Constant) and condition.size == 1:
            return "false" if condition.unsigned == 0 else "true"
        if isinstance(condition, BitwiseNegate):
            original_condition = condition.operand
            if original_condition in condition_map:
                return str(condition_map[original_condition].negate())
            return f"!{self._rich_string_representation(original_condition, condition_map)}"
        if isinstance(condition, (BitwiseOr, BitwiseAnd)):
            operands = condition.operands
            symbol = "|" if isinstance(condition, BitwiseOr) else "&"
            if len(operands) == 1:
                return self._rich_string_representation(operands[0], condition_map)
            return "(" + f" {symbol} ".join([f"{self._rich_string_representation(operand, condition_map)}" for operand in operands]) + ")"
        return f"{condition}"


class PseudoCustomLogicCondition(PseudoLogicInterface, CustomLogicCondition, Generic[LOGICCLASS, PseudoLOGICCLASS]):
    def __init__(self, condition: WorldObject, tmp: bool = False):
        super().__init__(condition, tmp)

    @classmethod
    def initialize_from_condition(cls, condition: pseudo.Condition, context: World) -> PseudoLOGICCLASS:
        """Create the simplified condition from the condition of type Condition."""
        custom_condition = cls._get_custom_condition_of(condition, context)
        return cls(custom_condition)

    @classmethod
    def initialize_from_conditions_or(cls, conditions: List[pseudo.Condition], context: World) -> PseudoLOGICCLASS:
        or_conditions = []
        for cond in conditions:
            or_conditions.append(cls._get_custom_condition_of(cond, context))
        return cls(context.bitwise_or(*or_conditions))

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

        return cls(condition.context.bitwise_and(*operands))

    @classmethod
    def _get_condition_of_disjunction(cls, disjunction: LOGICCLASS, condition_map: Dict[LOGICCLASS, PseudoLOGICCLASS]) -> PseudoLOGICCLASS:
        """Return for a disjunction (Or) the corresponding z3-condition."""
        assert disjunction.is_disjunction, f"The input must be a disjunction, but it is {disjunction}"
        operands = [cls._get_condition_of_literal(operand, condition_map)._condition for operand in disjunction.operands]
        return cls(disjunction.context.bitwise_or(*operands))

    @staticmethod
    def _get_condition_of_literal(literal: LOGICCLASS, condition_map: Dict[LOGICCLASS, PseudoLOGICCLASS]) -> PseudoLOGICCLASS:
        """Given a literal, i.e., a symbol or a negation of a symbol, return the condition the symbol is mapped to."""
        assert literal.is_literal, f"The input must be a literal, but it is {literal}"
        if literal.is_symbol:
            return condition_map[literal]
        return ~condition_map[~literal]

    @staticmethod
    def _get_custom_condition_of(condition: pseudo.Condition, world: World) -> WorldObject:
        """
        Convert a given condition a op b into the custom-condition bit_vec_a op bit_vec_b.

        a and b can be any type of Expression. The name of the bitvector reflects the expression as well as
        the SSA-variable names that occur in the expression.
        """
        if condition.left.type.size != condition.right.type.size:
            logging.warning(
                f"The operands of {condition} have different sizes: {condition.left.type.size} & {condition.right.type.size}. Increase the size of the smaller one."
            )
        bit_vec_size = max(condition.left.type.size, condition.right.type.size, 1)
        operand_1: BitVector = PseudoCustomLogicCondition._convert_expression(condition.left, bit_vec_size, world)
        operand_2: BitVector = PseudoCustomLogicCondition._convert_expression(condition.right, bit_vec_size, world)
        return PseudoCustomLogicCondition.SHORTHAND[condition.operation](world, operand_1, operand_2)

    @staticmethod
    def _convert_expression(expression: pseudo.Expression, bit_vec_size: int, world: World) -> BitVector:
        """Convert the given expression into a z3 bit-vector."""
        if isinstance(expression, pseudo.Constant):
            return Constant(world, expression.value, bit_vec_size)
        elif isinstance(expression, pseudo.Variable):
            return Variable(world, f"{expression},{expression.ssa_name}", bit_vec_size)
        else:
            return Variable(world, f"{expression},{[str(var.ssa_name) for var in expression.requirements]}", bit_vec_size)

    SHORTHAND = {
        pseudo.OperationType.equal: lambda world, a, b: world.bool_equal(a, b),
        pseudo.OperationType.not_equal: lambda world, a, b: world.bool_unequal(a, b),
        pseudo.OperationType.less: lambda world, a, b: world.signed_lt(a, b),
        pseudo.OperationType.less_or_equal: lambda world, a, b: world.signed_le(a, b),
        pseudo.OperationType.greater: lambda world, a, b: world.signed_gt(a, b),
        pseudo.OperationType.greater_or_equal: lambda world, a, b: world.signed_ge(a, b),
        pseudo.OperationType.greater_us: lambda world, a, b: world.unsigned_gt(a, b),
        pseudo.OperationType.less_us: lambda world, a, b: world.unsigned_lt(a, b),
        pseudo.OperationType.greater_or_equal_us: lambda world, a, b: world.unsigned_ge(a, b),
        pseudo.OperationType.less_or_equal_us: lambda world, a, b: world.unsigned_le(a, b),
    }
