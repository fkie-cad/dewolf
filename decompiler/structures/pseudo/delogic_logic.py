"""Implements translating pseudo instructions into delogic statements."""
from __future__ import annotations

from typing import Generic, Union

from simplifier.world.nodes import Operation as WorldOperation
from simplifier.world.nodes import Variable as WorldVariable
from simplifier.world.nodes import WorldObject
from simplifier.world.world import World

from .expressions import Constant, Expression, Variable
from .instructions import Branch
from .logic import BaseConverter
from .operations import Condition, Operation, OperationType


class DelogicConverter(BaseConverter):
    """Class in charge of converting psudo expressions into Logic statements"""

    def __init__(self):
        self._world = World()
        self._var_count = 0

    def convert(self, expression: Union[Expression, Branch], define_expr: bool = False) -> WorldObject:
        """Convert a given expression or branch into a logic statement of type WorldObject."""
        converted_expr = super().convert(expression)
        if define_expr:
            return self.define_expression(converted_expr)
        return converted_expr

    def define_expression(self, expr: WorldObject) -> WorldVariable:
        """Bind an expression to a WorldVariable."""
        var_name = f"delogic_var_{self._var_count}"
        self._var_count += 1
        var = self._world.variable(var_name, expr.size)
        self._world.define(var, expr)
        return var

    def compare(self, a: WorldObject, b: WorldObject):
        """Compare two world objects with each other."""
        return self._world.compare(a, b)

    def false(self) -> WorldObject:
        """Return False in Delogic."""
        return self._world.constant(0, 1)

    def negate(self, expr: WorldObject) -> WorldObject:
        """Negate a given expression."""
        if isinstance(expr, WorldVariable) and (formula := self._world.get_definition(expr)):
            return self._world.bool_negate(formula)
        return self._world.bool_negate(expr)

    def check(self, *condition: WorldObject, timeout: int = 2000) -> str:
        """Return a string describing whether the given terms are satisfiable."""
        simplified_expr = self._full_simplification(condition[0], timeout)
        if self.compare(simplified_expr, self.false()):
            return BaseConverter.UNSAT
        return BaseConverter.SAT

    def _full_simplification(self, condition: WorldObject, timeout: int = 2000) -> WorldObject:
        """Return the full simplification of a condition."""
        result = condition.copy_tree() if isinstance(condition, WorldVariable) else self.define_expression(condition.copy_tree())
        # simplify to fixpoint, stop at timeout so we don't accidentally iterate forever.
        for _ in range(timeout):
            result_copy = self.define_expression(result.copy_tree())
            result.simplify()
            if self.compare(result_copy, result):
                break
        return result

    def _convert_variable(self, variable: Variable, default_size: int = 32) -> WorldObject:
        """Represent the given variable as a WorldObject."""
        return self._world.from_string(f"{variable.name}@{variable.type.size or default_size}")

    def _convert_constant(self, constant: Constant, default_size: int = 32) -> WorldObject:
        """Represent the given constant as a WorldObject."""
        return self._world.from_string(f"{constant.value}@{constant.type.size or default_size}")

    def _convert_branch(self, branch: Branch) -> WorldObject:
        """
        Convert the given branch into a WorldObject.

        Condition type Branches can be converted as a BinaryOperation.
        When the condition is a single variable or an expression, the condition becomes a check != 0.
        """
        if isinstance(branch.condition, Condition):
            return self._convert_condition(branch.condition)
        return self._convert_condition(Condition(OperationType.not_equal, [branch.condition, Constant(0, branch.condition.type)]))

    def _convert_condition(self, condition: Condition) -> WorldObject:
        """
        Convert the given condition into a WorldObject.

        Please note conditions are a special kind of operation returning a boolean value.
        """
        return self._get_operation(condition)

    def _convert_operation(self, operation: Operation) -> WorldObject:
        """
        Convert the given operation into a WorldObject.
        """
        return self._get_operation(operation)

    def _get_operation(self, operation: Operation) -> WorldObject:
        """Convert the given operation into a WorldObject expression utilizing the handler functions."""
        converter = self.OPERATIONS.get(operation.operation, None)
        if not converter:
            raise ValueError(f"Could not convert operation {operation} into World Logic.")
        operands = [self.convert(operand) for operand in operation.operands]

        return converter(self._world, *operands)

    OPERATIONS = {
        OperationType.plus: lambda w, a, b: w.signed_add(a, b),
        OperationType.minus: lambda w, a, b: w.signed_sub(a, b),
        OperationType.multiply: lambda w, a, b: w.signed_mul(a, b),
        OperationType.divide: lambda w, a, b: w.signed_div(a, b),
        OperationType.modulo: lambda w, a, b: w.signed_mod(a, b),
        OperationType.bitwise_xor: lambda w, a, b: w.bitwise_xor(a, b),
        OperationType.bitwise_or: lambda w, a, b: w.bitwise_or(a, b),
        OperationType.bitwise_and: lambda w, a, b: w.bitwise_and(a, b),
        OperationType.left_shift: lambda w, a, b: w.shift_left(a, b),
        OperationType.right_shift: lambda w, a, b: w.shift_right(a, b),
        OperationType.left_rotate: lambda w, a, b: w.rotate_left(a, b),
        OperationType.right_rotate: lambda w, a, b: w.rotate_right(a, b),
        OperationType.equal: lambda w, a, b: w.bool_equal(a, b),
        OperationType.not_equal: lambda w, a, b: w.bool_unequal(a, b),
        OperationType.less: lambda w, a, b: w.signed_lt(a, b),
        OperationType.less_or_equal: lambda w, a, b: w.signed_le(a, b),
        OperationType.greater: lambda w, a, b: w.signed_gt(a, b),
        OperationType.greater_or_equal: lambda w, a, b: w.signed_ge(a, b),
        OperationType.cast: lambda w, a: a,
        OperationType.negate: lambda w, a: w.bitwise_negate(a),
        OperationType.logical_not: lambda w, a: w.bool_negate(a),
        # unsigned operations
        OperationType.divide_us: lambda w, a, b: w.unsigned_div(a, b),
        OperationType.modulo_us: lambda w, a, b: w.unsigned_mod(a, b),
        OperationType.greater_us: lambda w, a, b: w.unsigned_gt(a, b),
        OperationType.less_us: lambda w, a, b: w.unsigned_lt(a, b),
        OperationType.greater_or_equal_us: lambda w, a, b: w.unsigned_ge(a, b),
        OperationType.less_or_equal_us: lambda w, a, b: w.unsigned_le(a, b),
    }
