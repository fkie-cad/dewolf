from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union

from decompiler.structures.logic.logic_condition import LogicCondition, PseudoLogicCondition
from decompiler.structures.logic.z3_implementations import Z3Implementation
from decompiler.structures.pseudo import Condition, Constant, Expression, OperationType, Variable, Z3Converter
from z3 import BoolRef


def _is_equivalent(cond1: BoolRef, cond2: BoolRef):
    """Check whether the given conditions are equivalent."""
    z3_implementation = Z3Implementation(True)
    if z3_implementation.is_equal(cond1, cond2):
        return True
    return z3_implementation.does_imply(cond1, cond2) and z3_implementation.does_imply(cond2, cond1)


def _get_ssa_expression(expression_usage: ExpressionUsages) -> Expression:
    """Construct SSA-expression of the given expression."""
    if isinstance(expression_usage.expression, Variable):
        return expression_usage.expression.ssa_name if expression_usage.expression.ssa_name else expression_usage.expression
    ssa_expression = expression_usage.expression.copy()
    for variable in [var for var in ssa_expression.requirements if var.ssa_name]:
        ssa_expression.substitute(variable, variable.ssa_name)
    return ssa_expression


@dataclass(frozen=True)
class ExpressionUsages:
    """Dataclass maintaining for a condition the used SSA-variables."""

    expression: Expression
    ssa_usages: Tuple[Optional[Variable], ...]

    @classmethod
    def from_expression(cls, expression: Expression) -> ExpressionUsages:
        return ExpressionUsages(expression, tuple(var.ssa_name for var in expression.requirements))


@dataclass(frozen=True)
class ZeroCaseCondition:
    """Possible switch expression together with its zero-case condition."""

    expression: Expression
    ssa_usages: Set[Optional[Variable]]
    z3_condition: BoolRef

    def are_equivalent(self, other: Union[ZeroCaseCondition, PotentialZeroCaseCondition]) -> bool:
        return self.ssa_usages == other.ssa_usages and _is_equivalent(self.z3_condition, other.z3_condition)


@dataclass(frozen=True)
class PotentialZeroCaseCondition:
    """Possible zero-case condition with its z3-condition and ssa-usages."""

    expression: Condition
    ssa_usages: Set[Optional[Variable]]
    z3_condition: BoolRef

    def are_equivalent(self, other: Union[ZeroCaseCondition, PotentialZeroCaseCondition]) -> bool:
        return self.ssa_usages == other.ssa_usages and _is_equivalent(self.z3_condition, other.z3_condition)


@dataclass(frozen=True)
class CaseNodeProperties:
    """
    Class for mapping possible expression and constant of a symbol for a switch-case.

    -> symbol: symbol that belongs to the expression and constant
    -> constant: the compared constant
    -> negation: whether the symbol or its negation belongs to a switch-case
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

    def copy(self) -> CaseNodeProperties:
        return CaseNodeProperties(self.symbol, self.expression, self.constant, self.negation)


@dataclass
class ConditionSymbol:
    """Dataclass that maintains for each symbol the according condition and its transition in a z3-condition."""

    _condition: Condition
    _symbol: LogicCondition
    z3_condition: PseudoLogicCondition
    case_node_property: Optional[CaseNodeProperties] = None

    @property
    def condition(self) -> Condition:
        return self._condition

    @property
    def symbol(self) -> LogicCondition:
        return self._symbol

    def __hash__(self) -> int:
        return hash((self.condition, self.symbol))

    def __eq__(self, other):
        """Check whether two condition-symbols are equal."""
        return isinstance(other, ConditionSymbol) and self.condition == other.condition and self.symbol == other.symbol


@dataclass
class SwitchHandler:
    z3_converter: Z3Converter
    zero_case_of_switch_expression: Dict[ExpressionUsages, ZeroCaseCondition]
    potential_zero_cases: Dict[ConditionSymbol, PotentialZeroCaseCondition]

    @classmethod
    def initialize(cls, condition_map: Optional[Dict[LogicCondition, ConditionSymbol]]) -> SwitchHandler:
        handler = cls(Z3Converter(), {}, {})
        if condition_map is None:
            return handler
        for cond_symbol in condition_map.values():
            if cond_symbol.case_node_property is not None:
                handler.have_new_zero_case_for(cond_symbol.case_node_property.expression)
            elif cond_symbol.condition.operation in {OperationType.equal, OperationType.not_equal} and not any(
                isinstance(operand, Constant) for operand in cond_symbol.condition.operands
            ):
                handler.have_new_potential_zero_case_for(cond_symbol)
        return handler

    def have_new_zero_case_for(self, expression_usage: ExpressionUsages) -> bool:
        """Returns whether we added a new zero-case condition for the given expression."""
        return expression_usage not in self.zero_case_of_switch_expression and self._successfully_compute_zero_case_condition_for(
            expression_usage
        )

    def have_new_potential_zero_case_for(self, condition_symbol: ConditionSymbol) -> bool:
        """Returns whether we added a new zero-case condition for the given expression."""
        return self._successfully_compute_potential_zero_case_condition_for(condition_symbol)

    def _successfully_compute_zero_case_condition_for(self, expression_usage: ExpressionUsages) -> bool:
        """Return whether the construction of the zero-case condition was successful and add it to the dictionary."""
        ssa_expression = _get_ssa_expression(expression_usage)
        try:
            z3_condition = self.z3_converter.convert(Condition(OperationType.equal, [ssa_expression, Constant(0, ssa_expression.type)]))
            self.zero_case_of_switch_expression[expression_usage] = ZeroCaseCondition(
                expression_usage.expression, set(expression_usage.ssa_usages), z3_condition
            )
            return True
        except ValueError:
            return False

    def _successfully_compute_potential_zero_case_condition_for(self, condition_symbol: ConditionSymbol) -> bool:
        """Construct the potential zero-case condition."""
        condition = condition_symbol.condition
        expression_usage = ExpressionUsages.from_expression(condition)
        ssa_condition = _get_ssa_expression(expression_usage)
        assert isinstance(ssa_condition, Condition), f"{ssa_condition} must be of type Condition!"
        ssa_condition = ssa_condition.negate() if ssa_condition.operation == OperationType.not_equal else ssa_condition
        try:
            z3_condition = self.z3_converter.convert(ssa_condition)
            self.potential_zero_cases[condition_symbol] = PotentialZeroCaseCondition(
                condition, set(expression_usage.ssa_usages), z3_condition
            )
            return True
        except ValueError:
            return False


class ConditionHandler:
    """Class that handles all the conditions of a transition graph and syntax-forest."""

    def __init__(self, condition_map: Optional[Dict[LogicCondition, ConditionSymbol]] = None):
        """Initialize a new condition handler with a dictionary that maps the symbol to its according ConditionSymbol."""
        self._condition_map: Dict[LogicCondition, ConditionSymbol] = dict() if condition_map is None else condition_map
        self._symbol_counter = 0
        self._logic_context = next(iter(self._condition_map)).context if self._condition_map else LogicCondition.generate_new_context()
        self._switch_handler: SwitchHandler = SwitchHandler.initialize(condition_map)

    def __eq__(self, other) -> bool:
        """Checks whether two condition handlers are equal."""
        return isinstance(other, ConditionHandler) and other._condition_map == self._condition_map

    def __hash__(self) -> int:
        """Returns a hash for the condition map"""
        return hash(self._condition_map)

    def __len__(self) -> int:
        """Returns the number of elements in the condition map."""
        return len(self._condition_map)

    def __iter__(self) -> Iterable[LogicCondition]:
        """Iterate over all symbols"""
        yield from self._condition_map

    @property
    def logic_context(self):
        """Return the utilized logic context."""
        return self._logic_context

    def copy(self) -> ConditionHandler:
        """Return a copy of the condition handler"""
        condition_map = {
            symbol: ConditionSymbol(
                condition_symbol.condition.copy(),
                condition_symbol.symbol,
                condition_symbol.z3_condition,
                condition_symbol.case_node_property.copy(),
            )
            for symbol, condition_symbol in self._condition_map.items()
        }
        return ConditionHandler(condition_map)

    def get_condition_of(self, symbol: LogicCondition) -> Condition:
        """Return the condition to the given symbol"""
        return self._condition_map[symbol].condition

    def get_z3_condition_of(self, symbol: LogicCondition) -> PseudoLogicCondition:
        """Return the z3-condition to the given symbol"""
        return self._condition_map[symbol].z3_condition

    def get_case_node_property_of(self, symbol: LogicCondition) -> CaseNodeProperties:
        """Return the z3-condition to the given symbol"""
        return self._condition_map[symbol].case_node_property

    def get_all_symbols(self) -> Set[LogicCondition]:
        """Return all existing symbols"""
        return set(self._condition_map.keys())

    def get_condition_map(self) -> Dict[LogicCondition, Condition]:
        """Return the condition map that maps symbols to conditions."""
        return dict((symbol, condition_symbol.condition) for symbol, condition_symbol in self._condition_map.items())

    def get_z3_condition_map(self) -> Dict[LogicCondition, PseudoLogicCondition]:
        """Return the z3-condition map that maps symbols to z3-conditions."""
        return dict((symbol, condition_symbol.z3_condition) for symbol, condition_symbol in self._condition_map.items())

    def get_reverse_z3_condition_map(self) -> Dict[PseudoLogicCondition, LogicCondition]:
        """Return the reverse z3-condition map that maps z3-conditions to symbols."""
        return dict((condition_symbol.z3_condition, symbol) for symbol, condition_symbol in self._condition_map.items())

    def get_true_value(self) -> LogicCondition:
        """Return a true value."""
        return LogicCondition.initialize_true(self._logic_context)

    def get_false_value(self) -> LogicCondition:
        """Return a false value."""
        return LogicCondition.initialize_false(self._logic_context)

    def get_literal_and_constant_of(self, condition: LogicCondition) -> Iterable[LogicCondition, Constant]:
        """Get the constant for each literal of the given condition."""
        for literal in condition.get_literals():
            yield literal, self.get_potential_switch_constant_of(literal)

    def get_constants_of(self, condition: LogicCondition) -> Iterable[Constant]:
        """Get the constant for each literal of the given condition."""
        for literal in condition.get_literals():
            yield self.get_potential_switch_constant_of(literal)

    def get_potential_switch_constant_of(self, condition: LogicCondition) -> Optional[Constant]:
        """Check whether the given condition is a potential switch case, and if return the corresponding constant."""
        if (case_node_property := self._get_case_node_property_of(condition)) is not None:
            return case_node_property.constant

    def get_potential_switch_expression_of(self, condition: LogicCondition) -> Optional[ExpressionUsages]:
        """Check whether the given condition is a potential switch case, and if return the corresponding expression."""
        if (case_node_property := self._get_case_node_property_of(condition)) is not None:
            return case_node_property.expression

    def add_condition(self, condition: Condition) -> LogicCondition:
        """Adds a new condition to the condition map and returns the corresponding condition_symbol"""
        z3_condition = PseudoLogicCondition.initialize_from_condition(condition, self._logic_context)
        if symbol := self._condition_already_exists(z3_condition):
            return symbol

        symbol = self._get_next_symbol()
        condition_symbol = ConditionSymbol(condition, symbol, z3_condition)
        self._set_switch_case_property_for_condition(condition_symbol)
        self._condition_map[symbol] = condition_symbol
        return symbol

    def _condition_already_exists(self, z3_condition: PseudoLogicCondition) -> Optional[ConditionSymbol]:
        """Check whether the given condition already exists and returns the corresponding Condition Symbol."""
        for value in self._condition_map.values():
            if value.z3_condition.is_equal_to(z3_condition):
                return value.symbol
            elif value.z3_condition.is_equal_to(~z3_condition):
                return ~value.symbol

    def _get_next_symbol(self) -> LogicCondition:
        """Get the next unused symbol name."""
        self._symbol_counter += 1
        return LogicCondition.initialize_symbol(f"x{self._symbol_counter}", self._logic_context)

    def _set_switch_case_property_for_condition(self, condition_symbol: ConditionSymbol) -> None:
        """Compute the switch-case property."""
        condition: Condition = condition_symbol.condition
        if condition.operation not in {OperationType.equal, OperationType.not_equal}:
            return None
        constants: List[Constant] = [operand for operand in condition.operands if isinstance(operand, Constant)]
        expressions: List[Expression] = [operand for operand in condition.operands if not isinstance(operand, Constant)]

        if len(constants) == 1 and len(expressions) == 1:
            expression_usage = ExpressionUsages.from_expression(expressions[0])
            condition_symbol.case_node_property = CaseNodeProperties(
                condition_symbol.symbol, expression_usage, constants[0], condition.operation == OperationType.not_equal
            )
            self._update_potential_zero_cases_for(expression_usage)
        elif len(constants) == 0:
            if self._switch_handler.have_new_potential_zero_case_for(condition_symbol):
                self._add_zero_case_condition_for(condition_symbol)

    def _update_potential_zero_cases_for(self, expression_usage: ExpressionUsages) -> None:
        """
        Update the Zero-cases for the given expression.

        If the switch handler adds a new zero-case condition, we check whether one of the potential zero-cases matches this zero-case.
        """
        if self._switch_handler.have_new_zero_case_for(expression_usage):
            self._add_missing_zero_cases_for(self._switch_handler.zero_case_of_switch_expression[expression_usage])

    def _add_missing_zero_cases_for(self, zero_case: ZeroCaseCondition) -> None:
        """We check for each potential zero-case whether it matches the given zero-case."""
        found_zero_cases = set()
        for condition_symbol, potential_zero_case in self._switch_handler.potential_zero_cases.items():
            if zero_case.are_equivalent(potential_zero_case):
                self._update_case_property_for(
                    condition_symbol, potential_zero_case, ExpressionUsages.from_expression(zero_case.expression)
                )
                found_zero_cases.add(condition_symbol)
        for zero_case_condition_symbol in found_zero_cases:
            del self._switch_handler.potential_zero_cases[zero_case_condition_symbol]

    def _add_zero_case_condition_for(self, potential_zero_case_condition_symbol: ConditionSymbol) -> None:
        """
        Check whether the condition belongs to a zero-case of a switch expression.

        If this is the case, we return the switch expression and the zero-constant
        """
        potential_zero_case: PotentialZeroCaseCondition = self._switch_handler.potential_zero_cases[potential_zero_case_condition_symbol]
        for expression_usage, zero_case in self._switch_handler.zero_case_of_switch_expression.items():
            if potential_zero_case.are_equivalent(zero_case):
                self._update_case_property_for(potential_zero_case_condition_symbol, potential_zero_case, expression_usage)
                del self._switch_handler.potential_zero_cases[potential_zero_case_condition_symbol]
                return None
        return None

    def _update_case_property_for(
        self, condition_symbol: ConditionSymbol, zero_case: PotentialZeroCaseCondition, expression_usage: ExpressionUsages
    ):
        """
        Update the case_node_property of the given condition-symbol which belongs to the potential zero-case with the given expression.
        """
        condition_symbol.z3_condition = PseudoLogicCondition.initialize_from_condition(
            Condition(
                zero_case.expression.operation,
                [expression_usage.expression, (Constant(0, expression_usage.expression.type))],
            ),
            self._logic_context,
        )
        condition_symbol.case_node_property = CaseNodeProperties(
            condition_symbol.symbol,
            expression_usage,
            Constant(0, expression_usage.expression.type),
            zero_case.expression.operation == OperationType.not_equal,
        )

    def _get_case_node_property_of(self, condition: LogicCondition) -> Optional[CaseNodeProperties]:
        """Return the case-property of a given literal."""
        negation = False
        if condition.is_negation:
            condition = condition.operands[0]
            negation = True
        if condition.is_symbol:
            case_node_property = self.get_case_node_property_of(condition)
            if case_node_property is not None and case_node_property.negation == negation:
                return case_node_property
        return None
