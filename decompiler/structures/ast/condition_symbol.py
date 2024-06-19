from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Set, Tuple, List

from z3 import BoolRef

from decompiler.structures.logic.logic_condition import LogicCondition, PseudoLogicCondition
from decompiler.structures.logic.z3_implementations import Z3Implementation
from decompiler.structures.pseudo import Condition, Constant, Expression, Variable, OperationType, Z3Converter


@dataclass(frozen=True)
class ExpressionUsages:
    """Dataclass maintaining for a condition the used SSA-variables."""

    expression: Expression
    ssa_usages: Tuple[Optional[Variable]]


@dataclass
class ZeroCaseCondition:
    """Possible switch expression together with its zero-case condition."""

    expression: Expression
    ssa_usages: Set[Optional[Variable]]
    z3_condition: BoolRef


@dataclass(frozen=True)
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

    def __eq__(self, other):
        """Check whether two condition-symbols are equal."""
        return (
            isinstance(other, ConditionSymbol)
            and self.condition == other.condition
            and self.symbol == other.symbol
            # and self.z3_condition.is_equivalent_to(other.z3_condition)
        )


@dataclass
class SwitchHandler:
    z3_converter: Z3Converter
    zero_case_of_switch_expression: Dict[ExpressionUsages, ZeroCaseCondition]
    possible_zero_cases: Dict[ConditionSymbol, Tuple[BoolRef, ExpressionUsages]]

    @classmethod
    def initialize(cls, condition_map: Optional[Dict[LogicCondition, ConditionSymbol]]) -> SwitchHandler:
        return SwitchHandler(Z3Converter(), {}, {})


class ConditionHandler:
    """Class that handles all the conditions of a transition graph and syntax-forest."""

    def __init__(self, condition_map: Optional[Dict[LogicCondition, ConditionSymbol]] = None):
        """Initialize a new condition handler with a dictionary that maps the symbol to its according ConditionSymbol."""
        self._condition_map: Dict[LogicCondition, ConditionSymbol] = dict() if condition_map is None else condition_map
        self._symbol_counter = 0
        self._logic_context = next(iter(self._condition_map)).context if self._condition_map else LogicCondition.generate_new_context()
        self._switch_handler: SwitchHandler = SwitchHandler.initialize(condition_map)
        # self._z3_converter: Z3Converter = Z3Converter()
        # self._zero_case_of_switch_expression: Dict[ExpressionUsages, ZeroCaseCondition] = dict()
        # for cond_symbol in condition_map.values():
        #     expression = cond_symbol.case_node_property.expression
        #     if zero_case := self._get_zero_case_condition(expression) is not None:
        #         self._zero_case_of_switch_expression[expression] = zero_case

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

    def get_true_value(self) -> LogicCondition:
        """Return a true value."""
        return LogicCondition.initialize_true(self._logic_context)

    def get_false_value(self) -> LogicCondition:
        """Return a false value."""
        return LogicCondition.initialize_false(self._logic_context)

    def _set_switch_case_property_for_condition(self, condition_symbol: ConditionSymbol) -> None:
        """Compute the switch-case property."""
        condition = condition_symbol.condition
        if condition.operation not in {OperationType.equal, OperationType.not_equal}:
            return None
        constants: List[Constant] = [operand for operand in condition.operands if isinstance(operand, Constant)]
        expressions: List[Expression] = [operand for operand in condition.operands if not isinstance(operand, Constant)]

        if len(constants) == 1 or len(expressions) == 1:
            expression_usage = ExpressionUsages(expressions[0], tuple(var.ssa_name for var in expressions[0].requirements))
            const: Constant = constants[0]
            if (
                expression_usage not in self._switch_handler.zero_case_of_switch_expression
                and (zero_case := self._compute_zero_case_condition_for(expression_usage)) is not None
            ):
                self._switch_handler.zero_case_of_switch_expression[expression_usage] = zero_case
                # TODO: check that potential switch are checked for this expression!
                for possible_zero_case_condition_symbol, values in self._switch_handler.possible_zero_cases.items():
                    # COPY PART!!!
                    if zero_case.ssa_usages != set(values[1].ssa_usages):
                        continue
                    ssa_condition = values[0]
                    zero_case_z3_condition = zero_case.z3_condition
                    if self.__is_equivalent(ssa_condition, zero_case_z3_condition):
                        # update the condition_symbol!!!
                        constant = Constant(0, expression_usage.expression.type)
                        possible_zero_case_condition_symbol.z3_condition = PseudoLogicCondition.initialize_from_condition(
                            Condition(condition.operation, [values[1], constant]), self._logic_context
                        )
                        possible_zero_case_condition_symbol.case_node_property = CaseNodeProperties(
                            possible_zero_case_condition_symbol.symbol,
                            values[1],
                            constant,
                            condition.operation == OperationType.not_equal,  # TODO
                        )
        elif len(constants) == 0:

            tuple_ssa_usages = tuple(var.ssa_name for var in condition.requirements)
            ssa_condition = self.__get_z3_condition(expressions_usage := ExpressionUsages(condition, tuple_ssa_usages))
            if ssa_condition is None:
                return None

            if (
                zero_case_condition := self._get_associated_zero_case_condition_for(ssa_condition, expressions_usage)
            ) is not None:  # TODO: check this function
                expression_usage, const = zero_case_condition
                condition_symbol.z3_condition = PseudoLogicCondition.initialize_from_condition(
                    Condition(condition.operation, [expression_usage.expression, const]), self._logic_context
                )
            else:
                self._switch_handler.possible_zero_cases[condition_symbol] = (ssa_condition, expressions_usage)
                return None
        else:
            return None
        condition_symbol.case_node_property = CaseNodeProperties(
            condition_symbol.symbol, expression_usage, const, condition.operation == OperationType.not_equal
        )

    def _compute_zero_case_condition_for(self, expression_usage: ExpressionUsages) -> Optional[ZeroCaseCondition]:
        """Construct the zero-case condition and add it to the dictionary."""
        ssa_expression = self.__get_ssa_expression(expression_usage)
        try:
            z3_condition = self._switch_handler.z3_converter.convert(
                Condition(OperationType.equal, [ssa_expression, Constant(0, ssa_expression.type)])
            )
        except ValueError:
            return None
        return ZeroCaseCondition(expression_usage.expression, set(expression_usage.ssa_usages), z3_condition)

    def _get_associated_zero_case_condition_for(
        self, ssa_condition: BoolRef, expression_usage: ExpressionUsages
    ) -> Optional[Tuple[ExpressionUsages, Constant]]:
        """
        Check whether the condition belongs to a zero-case of a switch expression.

        If this is the case, we return the switch expression and the zero-constant
        """
        ssa_usages = set(expression_usage.ssa_usages)
        for expression_usage, zero_case_condition in self._switch_handler.zero_case_of_switch_expression.items():
            if zero_case_condition.ssa_usages != ssa_usages:
                continue
            zero_case_z3_condition = zero_case_condition.z3_condition
            if self.__is_equivalent(ssa_condition, zero_case_z3_condition):
                return expression_usage, Constant(0, expression_usage.expression.type)

    def __get_z3_condition(self, expression_usage: ExpressionUsages) -> Optional[BoolRef]:
        """Get z3-condition of the expression usage in SSA-form if there is one"""
        ssa_condition = self.__get_ssa_expression(expression_usage)
        assert isinstance(ssa_condition, Condition), f"{ssa_condition} must be of type Condition!"
        ssa_condition = ssa_condition.negate() if ssa_condition.operation == OperationType.not_equal else ssa_condition
        try:
            return self._switch_handler.z3_converter.convert(ssa_condition)
        except ValueError:
            return None

    @staticmethod
    def __is_equivalent(cond1: BoolRef, cond2: BoolRef):
        """Check whether the given conditions are equivalent."""
        z3_implementation = Z3Implementation(True)
        if z3_implementation.is_equal(cond1, cond2):
            return True
        return z3_implementation.does_imply(cond1, cond2) and z3_implementation.does_imply(cond2, cond1)

    @staticmethod
    def __get_ssa_expression(expression_usage: ExpressionUsages) -> Expression:
        """Construct SSA-expression of the given expression."""
        if isinstance(expression_usage.expression, Variable):
            return expression_usage.expression.ssa_name if expression_usage.expression.ssa_name else expression_usage.expression
        ssa_expression = expression_usage.expression.copy()
        for variable in [var for var in ssa_expression.requirements if var.ssa_name]:
            ssa_expression.substitute(variable, variable.ssa_name)
        return ssa_expression
