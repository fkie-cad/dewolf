"""Implements translating psuedo instructions into logic statements."""
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Generic, TypeVar, Union

from .expressions import Constant, Expression, Variable
from .instructions import Branch, GenericBranch
from .operations import Condition, Operation, OperationType, UnaryOperation

T = TypeVar("T")


class BaseConverter(ABC, Generic[T]):
    """Interface for converting pseudo expressions to Logic statements"""

    SAT = "sat"
    UNSAT = "unsat"
    UNKNOWN = "unknown"

    def convert(self, expression: Union[Expression, Branch], **kwargs: T) -> T:
        """Convert a given expression or branch into a logic statement of type T."""
        if isinstance(expression, Variable):
            return self._convert_variable(expression)
        if isinstance(expression, Constant) and (isinstance(expression.value, int) or isinstance(expression.value, float)):
            return self._convert_constant(expression)
        if isinstance(expression, Branch):
            return self._convert_branch(expression)
        if isinstance(expression, Condition):
            return self._convert_condition(expression)
        if isinstance(expression, UnaryOperation) and expression.operation == OperationType.dereference:
            return self._convert_variable(Variable(str(expression), expression.type))
        if isinstance(expression, Operation):
            return self._convert_operation(expression)
        raise ValueError(f"Could not convert {expression} into a logic statement.")

    @abstractmethod
    def check(self, *condition: T, timeout: int) -> str:
        """Return a string describing whether the given terms are satisfiable."""

    def is_not_satisfiable(self, *condition: T, timeout: int = 2000) -> bool:
        """Check whether a given set of terms is not satisfiable."""
        return self.check(*condition, timeout=timeout) == BaseConverter.UNSAT

    def is_satisfiable(self, *condition: T, timeout: int = 2000) -> bool:
        """Check whether a given set of terms is satisfiable."""
        return self.check(*condition, timeout=timeout) == BaseConverter.SAT

    @abstractmethod
    def _convert_variable(self, variable: Variable, **kwargs: T) -> T:
        """Represent the given Variable as type T."""

    @abstractmethod
    def _convert_constant(self, constant: Constant, **kwargs: T) -> T:
        """Represent the given constant as type T."""

    @abstractmethod
    def _convert_branch(self, branch: Branch, **kwargs: T) -> T:
        """
        Convert the given branch into type T.

        Condition type Branches can be converted as a BinaryOperation.
        When the condition is a single variable or an expression, the condition becomes a check != 0.
        """

    @abstractmethod
    def _convert_condition(self, condition: Condition, **kwargs: T) -> T:
        """
        Convert the given condition into type T.

        Please note conditions are a special kind of operation returning a boolean value.
        """

    @abstractmethod
    def _convert_operation(self, operation: Operation, **kwargs: T) -> T:
        """
        Convert the given operation into type T.
        """
