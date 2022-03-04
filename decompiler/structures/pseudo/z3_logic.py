"""Implements translating psuedo instructions into logic statements."""
from __future__ import annotations

import logging
from typing import Iterator, List, Union

from z3 import (
    UGE,
    UGT,
    ULE,
    ULT,
    And,
    BitVec,
    BitVecRef,
    BitVecVal,
    BoolRef,
    Context,
    ExprRef,
    Extract,
    If,
    Not,
    Or,
    RotateLeft,
    RotateRight,
    Solver,
    UDiv,
    URem,
    Xor,
    ZeroExt,
    is_bool,
    is_bv,
)

from .expressions import Constant, Expression, Variable
from .instructions import Branch
from .logic import BaseConverter
from .operations import Condition, Operation, OperationType


class Z3Converter(BaseConverter):
    """Class in charge of converting pseudo expressions into z3 logic statements."""

    def __init__(self):
        self._context = Context()

    @property
    def context(self) -> Context:
        """Return the current z3 context."""
        return self._context

    def negate(self, expr: BoolRef) -> BitVecRef:
        """Negate a given expression."""
        return Not(expr)

    def _convert_variable(self, variable: Variable) -> BitVecRef:
        """Represent the given Variable as a BitVector in z3."""
        return BitVec(variable.name, variable.type.size if variable.type.size else 32, ctx=self._context)

    def _convert_constant(self, constant: Constant) -> BitVecRef:
        """Represent the given variable as a BitVector (no types)."""
        return BitVecVal(constant.value, constant.type.size if constant.type.size else 32, ctx=self._context)

    def _convert_branch(self, branch: Branch) -> BitVecRef:
        """
        Convert the given branch into z3 logic.

        Condition type Branches can be converted as a BinaryOperation.
        When the condition is a single variable or an expression, the condition becomes a check != 0.
        """
        if isinstance(branch.condition, Condition):
            return self._convert_condition(branch.condition)
        return self._convert_condition(Condition(OperationType.not_equal, [branch.condition, Constant(0, branch.condition.type)]))

    def _convert_condition(self, condition: Condition) -> BitVecRef:
        """
        Convert the given condition into z3 logic.

        Please note conditions are a special kind of operation returning a boolean value.
        """
        _operation = self._get_operation(condition)
        return self._ensure_bool_sort(_operation)

    def _convert_operation(self, operation: Operation) -> BitVecRef:
        """
        Convert the given operation into a z3 logic.

        Operations should always be of BitvecRef type.
        """
        _operation = self._get_operation(operation)
        return self._ensure_bitvec_sort(_operation)

    def _get_operation(self, operation: Operation) -> Union[BoolRef, BitVecRef]:
        """Convert the given operation into a z3 expression utilizing the handler functions."""
        operands = self._ensure_same_sort([self.convert(operand) for operand in operation.operands])
        if isinstance(operands[0], BoolRef) and operation.operation in self.OPERATIONS_BOOLREF:
            converter = self.OPERATIONS_BOOLREF.get(operation.operation, None)
        else:
            converter = self.OPERATIONS.get(operation.operation, None)
        if not converter:
            raise ValueError(f"Could not convert operation {operation} into z3 logic.")
        return converter(*operands)

    def _ensure_same_sort(self, operands: List[ExprRef]) -> List[ExprRef]:
        """
        Complicated function ensuring the given operand list has a common sort.

        Converts bv and bool into each other and tries to even out size differences for bit vectors.
        """
        if any(is_bv(op) for op in operands):
            operands = [self._ensure_bitvec_sort(operand) for operand in operands]
            operands = list(self._ensure_bv_size(operands))
        elif any(is_bool(op) for op in operands):
            operands = [self._ensure_bool_sort(operand) for operand in operands]
        return operands

    def _ensure_bitvec_sort(self, expression: ExprRef) -> BitVecRef:
        """Ensure that the sort of the given expression is BitVec."""
        if is_bv(expression):
            return expression
        if is_bool(expression):
            return If(expression, BitVecVal(1, 1, ctx=self._context), BitVecVal(0, 1, ctx=self._context), ctx=self._context)
        raise ValueError(f"Can not convert {expression}")

    def _ensure_bool_sort(self, expression: ExprRef) -> BitVecRef:
        """Ensure that the sort of the given expression is BitVec."""
        if is_bool(expression):
            return expression
        if is_bv(expression):
            return expression != BitVecVal(1, expression.size(), ctx=self._context)
        raise ValueError(f"Can not convert {expression}")

    def _ensure_bv_size(self, operands: List[BitVecRef]) -> Iterator[BitVecRef]:
        """Ensure all bitvecors given as operands have the same size."""
        desired_size = operands[0].size()
        for operand in operands:
            operand_size = operand.size()
            if operand_size == desired_size:
                yield operand
            else:
                if desired_size > operand_size:
                    yield ZeroExt(desired_size - operand_size, operand)
                else:
                    yield Extract(desired_size - 1, 0, operand)

    def check(self, *condition: BoolRef, timeout: int = 2000) -> str:
        """Return a string describing whether the given terms are satisfiable."""
        solver = Solver(ctx=self._context)
        solver.set("timeout", timeout)
        for term in condition:
            solver.add(term)
        result = repr(solver.check())
        if result == "unknown":
            logging.warning(f"It could be that z3 was not able to check satisfiability for the given terms in {timeout}ms")
            return BaseConverter.UNKNOWN
        elif result == "unsat":
            return BaseConverter.UNSAT
        return BaseConverter.SAT

    LOGIC_OPERATIONS = {
        OperationType.bitwise_or,
        OperationType.bitwise_and,
    }

    OPERATIONS = {
        OperationType.plus: lambda a, b: a + b,
        OperationType.minus: lambda a, b: a - b,
        OperationType.multiply: lambda a, b: a * b,
        OperationType.divide: lambda a, b: a / b,
        OperationType.modulo: lambda a, b: a % b,
        OperationType.bitwise_xor: lambda a, b: a ^ b,
        OperationType.bitwise_or: lambda a, b: a | b,
        OperationType.bitwise_and: lambda a, b: a & b,
        OperationType.left_shift: lambda a, b: a << b,
        OperationType.right_shift: lambda a, b: a >> b,
        OperationType.left_rotate: RotateLeft,
        OperationType.right_rotate: RotateRight,
        OperationType.equal: lambda a, b: a == b,
        OperationType.not_equal: lambda a, b: a != b,
        OperationType.less: lambda a, b: a < b,
        OperationType.less_or_equal: lambda a, b: a <= b,
        OperationType.greater: lambda a, b: a > b,
        OperationType.greater_or_equal: lambda a, b: a >= b,
        OperationType.cast: lambda a: a,
        OperationType.negate: lambda a: -a,
        OperationType.logical_not: lambda a: ~a,
        # unsigned operations
        OperationType.divide_us: UDiv,
        OperationType.modulo_us: URem,
        OperationType.greater_us: UGT,
        OperationType.less_us: ULT,
        OperationType.greater_or_equal_us: UGE,
        OperationType.less_or_equal_us: ULE,
    }

    OPERATIONS_BOOLREF = {
        OperationType.bitwise_and: And,
        OperationType.bitwise_xor: Xor,
        OperationType.bitwise_or: Or,
        OperationType.logical_not: Not,
        OperationType.negate: Not,
    }
