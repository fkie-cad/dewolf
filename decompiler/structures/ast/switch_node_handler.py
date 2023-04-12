from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Set, Tuple

from z3 import BoolRef

from decompiler.structures.ast.condition_symbol import ConditionHandler
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.logic.z3_implementations import Z3Implementation
from decompiler.structures.pseudo import Condition, Constant, Expression, OperationType, Variable, Z3Converter


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
        self._possible_switch_expressions: Dict[ExpressionUsages, ZeroCaseCondition] = dict()
        self._get_possible_switch_expressions()
        self._switch_expressions_of_symbol: Dict[LogicCondition, CaseNodeProperties] = dict(self._get_initial_switch_cases())

    def _get_possible_switch_expressions(self) -> Iterator[Tuple[ExpressionUsages, ZeroCaseCondition]]:
        """Get all possible switch expressions, i.e., all expression compared with a constant."""
        for symbol in self._condition_handler.get_all_symbols():
            assert symbol.is_symbol, f"Each symbol should be a single Literal, but we have {symbol}"
            condition = self._condition_handler.get_condition_of(symbol)
            non_constants = [operand for operand in condition.operands if not isinstance(operand, Constant)]
            if len(non_constants) != 1:
                continue
            expression, ssa_usages = self.__get_ssa_expression(non_constants[0])
            expression_usage = ExpressionUsages(non_constants[0], tuple(ssa_usages))
            if expression_usage in self._possible_switch_expressions:
                continue
            z3_condition = self._z3_converter.convert(Condition(OperationType.equal, [expression, Constant(0, expression.type)]))
            self._possible_switch_expressions[expression_usage] = ZeroCaseCondition(non_constants[0], set(ssa_usages), z3_condition)

    def __get_ssa_expression(self, expression: Expression) -> ExpressionUsages:
        ssa_expression = expression.copy()
        ssa_usages: List[Optional[Variable]] = []
        for variable in ssa_expression.requirements:
            if variable.ssa_name:
                ssa_expression.substitute(variable, variable.ssa_name)
            ssa_usages.append(variable.ssa_name)
        return ssa_expression, ssa_usages

    def _get_initial_switch_cases(self):
        """Initialize for each symbol the possible switch case properties"""
        for symbol in self._condition_handler.get_all_symbols():
            condition = self._condition_handler.get_condition_of(symbol)
            if condition.operation not in {OperationType.equal, OperationType.not_equal}:
                continue
            if case_properties := self._get_expression_and_constant(condition):
                yield symbol, CaseNodeProperties(
                    symbol, case_properties[0], case_properties[1], condition.operation == OperationType.not_equal
                )

    def _get_expression_and_constant(self, condition: Condition) -> Optional[Tuple[ExpressionUsages, Constant]]:
        """TODO"""
        constant: List[Constant] = [operand for operand in condition.operands if isinstance(operand, Constant)]
        expression: List[Expression] = [operand for operand in condition.operands if not isinstance(operand, Constant)]
        if len(constant) == 1 or len(expression) == 1:
            return ExpressionUsages(expression[0], tuple(var.ssa_name for var in expression[0].requirements)), constant[0]
        if len(constant) == 0:
            return self.__find_switch_expression_of_condition(condition)

    def __find_switch_expression_of_condition(self, condition: Condition) -> Optional[Tuple[ExpressionUsages, Constant]]:
        """TODO"""
        cond1, ssa_usages = None, None
        for expression_usage, zero_case_condition in self._possible_switch_expressions.items():
            if zero_case_condition.ssa_usages != ssa_usages:
                continue
            if cond1 is None:
                cond1, ssa_usages = self.__get_condition(condition)
            cond2 = zero_case_condition.z3_condition
            if self._is_equivalent(cond1, cond2):
                return expression_usage, Constant(0, expression_usage.expression.type)

    def __get_condition(self, condition: Condition):
        ssa_condition, ssa_usages = self.__get_ssa_expression(condition)
        assert isinstance(ssa_condition, Condition), f"{ssa_condition} must be of type Condition!"
        ssa_condition = ssa_condition.negate() if ssa_condition.operation == OperationType.not_equal else ssa_condition
        cond1 = self._z3_converter.convert(ssa_condition)
        return cond1, ssa_usages

    def _is_equivalent(self, cond1: BoolRef, cond2: BoolRef):
        z3_implementation = Z3Implementation(True)
        if z3_implementation.is_equal(cond1, cond2):
            return True
        return z3_implementation.does_imply(cond1, cond2) and z3_implementation.does_imply(cond2, cond1)
