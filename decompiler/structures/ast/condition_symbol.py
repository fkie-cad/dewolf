from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Set

from decompiler.structures.logic.logic_condition import LogicCondition, PseudoLogicCondition
from decompiler.structures.pseudo import Condition


@dataclass(frozen=True)
class ConditionSymbol:
    """Dataclass that maintains for each symbol the according condition and its transition in a z3-condition."""

    condition: Condition
    symbol: LogicCondition
    z3_condition: PseudoLogicCondition

    def __eq__(self, other):
        """Check whether two condition-symbols are equal."""
        return (
            isinstance(other, ConditionSymbol)
            and self.condition == other.condition
            and self.symbol == other.symbol
            and self.z3_condition.is_equivalent_to(other.z3_condition)
        )


class ConditionHandler:
    """Class that handles all the conditions of a transition graph and syntax-forest."""

    def __init__(self, condition_map: Optional[Dict[LogicCondition, ConditionSymbol]] = None):
        """Initialize a new condition handler with an dictionary that maps the symbol to its according ConditionSymbol."""
        self._condition_map: Dict[LogicCondition, ConditionSymbol] = dict() if condition_map is None else condition_map
        self._symbol_counter = 0
        self._logic_context = next(iter(self._condition_map)).context if self._condition_map else LogicCondition.generate_new_context()

    def __eq__(self, other) -> bool:
        """Checks whether two condition handlers are equal."""
        return isinstance(other, ConditionHandler) and other._condition_map == self._condition_map

    def __hash__(self) -> int:
        """Returns a hash for the condition map"""
        return hash(self._condition_map)

    def __len__(self) -> int:
        """Returns the number of elements in the condition map."""
        return len(self._condition_map)

    @property
    def logic_context(self):
        """Return the utilized logic context."""
        return self._logic_context

    def copy(self) -> ConditionHandler:
        """Return a copy of the condition handler"""
        condition_map = {
            symbol: ConditionSymbol(condition_symbol.condition.copy(), condition_symbol.symbol, condition_symbol.z3_condition)
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

    def add_condition(self, condition: Condition) -> ConditionSymbol:
        """Adds a new condition to the condition map and returns the corresponding condition_symbol"""
        for value in self._condition_map.values():
            if value.condition == condition:
                return value
            elif value.condition.negate() == condition:
                return ConditionSymbol(condition, ~value.symbol, ~value.z3_condition)

        symbol = self._get_next_symbol()
        z3_condition = PseudoLogicCondition.initialize_from_condition(condition, self._logic_context)
        condition_symbol = ConditionSymbol(condition, symbol, z3_condition)
        self._condition_map[symbol] = condition_symbol
        return condition_symbol

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
