from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Set, Tuple

from decompiler.structures.ast.condition_symbol import ConditionHandler
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.logic.z3_implementations import Z3Implementation
from decompiler.structures.pseudo import Condition, Constant, Expression, OperationType, Variable, Z3Converter
from z3 import BoolRef


@dataclass(frozen=True)
class ExpressionUsages:
    """Dataclass that maintain for a condition the used SSA-variables."""

    expression: Expression
    ssa_usages: Tuple[Optional[Variable]]


@dataclass
class ZeroCaseCondition:
    """Possible switch expression together with its zero-case condition."""

    expression: Expression
    ssa_usages: Set[Optional[Variable]]
    z3_condition: BoolRef


@dataclass
class CaseNodeProperties:
    """
    Class for mapping possible expression and constant of a symbol for a switch-case.

    -> symbol: symbol that belongs to the expression and constant
    -> constant: the compared constant
    -> The condition that the new case node should get.
    """

    symbol: LogicCondition
    expression: ExpressionUsages
    constant: Constant
    negation: bool

    def __eq__(self, other) -> bool:
        """
        We want to be able to compare CaseNodeCandidates with AST-nodes, more precisely,
        we want that an CaseNodeCandidate 'case_node' is equal to the AST node 'case_node.node'.
        """
        if isinstance(other, CaseNodeProperties):
            return self.symbol == other.symbol
        return False


class SwitchNodeHandler:
    def __init__(self, condition_handler: ConditionHandler):
        self._condition_handler: ConditionHandler = condition_handler
        self._z3_converter = Z3Converter()
        self._zero_case_of_switch_expression: Dict[ExpressionUsages, ZeroCaseCondition] = dict()
        self._get_zero_cases_for_possible_switch_expressions()
        self._case_node_properties_of_symbol: Dict[LogicCondition, Optional[CaseNodeProperties]] = dict()
        self._initialize_case_node_properties_for_symbols()

    # TODO: Can we add new potential switch-expressions??

    def get_case_node_property_of(self, condition: LogicCondition) -> Optional[CaseNodeProperties]:
        negation = False
        if condition.is_negation:
            condition = condition.operands[0]
            negation = True
        if condition.is_symbol:
            if condition not in self._case_node_properties_of_symbol:
                self._case_node_properties_of_symbol[condition] = self.__get_case_node_property_of_symbol(condition)
            if (
                case_node_property := self._case_node_properties_of_symbol[condition]
            ) is not None and case_node_property.negation == negation:
                return case_node_property
        return None

    def is_potential_switch_case(self, condition: LogicCondition) -> bool:
        """Check whether the given condition is a potential switch case."""
        return self.get_case_node_property_of(condition) is not None

    def get_potential_switch_expression(self, condition: LogicCondition) -> Optional[ExpressionUsages]:
        """Check whether the given condition is a potential switch case."""
        if (case_node_property := self.get_case_node_property_of(condition)) is not None:
            return case_node_property.expression

    def get_potential_switch_constant(self, condition: LogicCondition) -> Optional[Constant]:
        if (case_node_property := self.get_case_node_property_of(condition)) is not None:
            return case_node_property.constant

    def _get_zero_cases_for_possible_switch_expressions(self) -> None:
        """Get all possible switch expressions, i.e., all expression compared with a constant, together with the potential zero case."""
        for symbol in self._condition_handler.get_all_symbols():
            self.__add_switch_expression_and_zero_case_for_symbol(symbol)

    def __add_switch_expression_and_zero_case_for_symbol(self, symbol: LogicCondition) -> None:
        """Add possible switch condition for symbol if comparison of expression with constant."""
        assert symbol.is_symbol, f"Each symbol should be a single Literal, but we have {symbol}"
        non_constants = [op for op in self._condition_handler.get_condition_of(symbol).operands if not isinstance(op, Constant)]
        if len(non_constants) != 1:
            return None
        expression_usage = ExpressionUsages(non_constants[0], tuple(var.ssa_name for var in non_constants[0].requirements))
        if expression_usage not in self._zero_case_of_switch_expression:
            self.__add_switch_expression(expression_usage)

    def __add_switch_expression(self, expression_usage: ExpressionUsages) -> None:
        """Construct the zero case condition and add it to the dictionary."""
        ssa_expression = self.__get_ssa_expression(expression_usage)
        try:
            z3_condition = self._z3_converter.convert(Condition(OperationType.equal, [ssa_expression, Constant(0, ssa_expression.type)]))
        except ValueError:
            return
        self._zero_case_of_switch_expression[expression_usage] = ZeroCaseCondition(
            expression_usage.expression, set(expression_usage.ssa_usages), z3_condition
        )

    def __get_ssa_expression(self, expression_usage: ExpressionUsages) -> Expression:
        """Construct SSA-expression of the given expression."""
        ssa_expression = expression_usage.expression.copy()
        for variable in [var for var in expression_usage.ssa_usages if var is not None]:
            ssa_expression.substitute(variable, variable.ssa_name)
        return ssa_expression

    def _initialize_case_node_properties_for_symbols(self) -> None:
        """Initialize for each symbol the possible switch case properties"""
        for symbol in self._condition_handler.get_all_symbols():
            self._case_node_properties_of_symbol[symbol] = self.__get_case_node_property_of_symbol(symbol)

    def __get_case_node_property_of_symbol(self, symbol: LogicCondition) -> Optional[CaseNodeProperties]:
        """Return CaseNodeProperty of the given symbol, if it exists."""
        condition = self._condition_handler.get_condition_of(symbol)
        if condition.operation not in {OperationType.equal, OperationType.not_equal}:
            return None
        constants: List[Constant] = [operand for operand in condition.operands if isinstance(operand, Constant)]
        expressions: List[Expression] = [operand for operand in condition.operands if not isinstance(operand, Constant)]

        if len(constants) == 1 or len(expressions) == 1:
            expression_usage = ExpressionUsages(expressions[0], tuple(var.ssa_name for var in expressions[0].requirements))
            const: Constant = constants[0]
        elif len(constants) == 0 and (zero_case_condition := self.__check_for_zero_case_condition(condition)):
            expression_usage, const = zero_case_condition
            self._condition_handler.update_z3_condition_of(symbol, Condition(condition.operation, [expression_usage.expression, const]))
        else:
            return None
        return CaseNodeProperties(symbol, expression_usage, const, condition.operation == OperationType.not_equal)

    def __check_for_zero_case_condition(self, condition: Condition) -> Optional[Tuple[ExpressionUsages, Constant]]:
        """
        Check whether the condition belongs to a zero-case of a switch expression.

        If this is the case, we return the switch expression and the zero-constant
        """
        tuple_ssa_usages = tuple(var.ssa_name for var in condition.requirements)
        ssa_usages = set(tuple_ssa_usages)
        ssa_condition = None
        for expression_usage, zero_case_condition in self._zero_case_of_switch_expression.items():
            if zero_case_condition.ssa_usages != ssa_usages:
                continue
            if ssa_condition is None:
                ssa_condition = self.__get_z3_condition(ExpressionUsages(condition, tuple_ssa_usages))
            zero_case_z3_condition = zero_case_condition.z3_condition
            if self.__is_equivalent(ssa_condition, zero_case_z3_condition):
                return expression_usage, Constant(0, expression_usage.expression.type)

    def __get_z3_condition(self, expression_usage: ExpressionUsages) -> BoolRef:
        """Get z3-condition of the expression usage in SSA-form"""
        ssa_condition = self.__get_ssa_expression(expression_usage)
        assert isinstance(ssa_condition, Condition), f"{ssa_condition} must be of type Condition!"
        ssa_condition = ssa_condition.negate() if ssa_condition.operation == OperationType.not_equal else ssa_condition
        z3_condition = self._z3_converter.convert(ssa_condition)
        return z3_condition

    def __is_equivalent(self, cond1: BoolRef, cond2: BoolRef):
        """Check whether the given conditions are equivalent."""
        z3_implementation = Z3Implementation(True)
        if z3_implementation.is_equal(cond1, cond2):
            return True
        return z3_implementation.does_imply(cond1, cond2) and z3_implementation.does_imply(cond2, cond1)
