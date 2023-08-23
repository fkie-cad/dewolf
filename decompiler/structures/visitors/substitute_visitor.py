from typing import Callable, Optional, TypeVar, Union

from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Break,
    Call,
    Comment,
    Condition,
    Constant,
    Continue,
    DataflowObject,
    Expression,
    FunctionSymbol,
    GenericBranch,
    ImportedFunctionSymbol,
    IntrinsicSymbol,
    ListOperation,
    MemPhi,
    Operation,
    Phi,
    RegisterPair,
    Return,
    TernaryExpression,
    UnaryOperation,
    UnknownExpression,
    Variable,
)
from decompiler.structures.visitors.interfaces import DataflowObjectVisitorInterface

T = TypeVar("T", bound=DataflowObject)


def _assert_type(obj: DataflowObject, t: type[T]) -> T:
    if not isinstance(obj, t):
        raise TypeError()
    else:
        return obj


class SubstituteVisitor(DataflowObjectVisitorInterface[Optional[DataflowObject]]):

    @classmethod
    def identity(cls, replacee: DataflowObject, replacement: DataflowObject) -> "SubstituteVisitor":
        return SubstituteVisitor(lambda o: replacement if o is replacee else None)

    @classmethod
    def equality(cls, replacee: DataflowObject, replacement: DataflowObject) -> "SubstituteVisitor":
        return SubstituteVisitor(lambda o: replacement if o == replacee else None)

    def __init__(self, mapper: Callable[[DataflowObject], Optional[DataflowObject]]) -> None:
        self._mapper = mapper

    def visit_unknown_expression(self, expr: UnknownExpression) -> Optional[DataflowObject]:
        return self._mapper(expr)

    def visit_constant(self, expr: Constant) -> Optional[DataflowObject]:
        return self._mapper(expr)

    def visit_variable(self, expr: Variable) -> Optional[DataflowObject]:
        return self._mapper(expr)

    def visit_register_pair(self, expr: RegisterPair) -> Optional[DataflowObject]:
        if (low_replacement := expr.low.accept(self)) is not None:
            expr._low = _assert_type(low_replacement, Variable)

        if (high_replacement := expr.high.accept(self)) is not None:
            expr._high = _assert_type(high_replacement, Variable)

        return self._mapper(expr)

    def _visit_operation(self, op: Operation) -> Optional[DataflowObject]:
        op.operands[:] = [op if (repl := op.accept(self)) is None else _assert_type(repl, Expression) for op in op.operands]
        return self._mapper(op)

    def visit_list_operation(self, op: ListOperation) -> Optional[DataflowObject]:
        return self._visit_operation(op)

    def visit_unary_operation(self, op: UnaryOperation) -> Optional[DataflowObject]:
        if op.array_info is not None:
            if (base_replacement := op.array_info.base.accept(self)) is not None:
                op.array_info.base = _assert_type(base_replacement, Variable)
            if (isinstance(op.array_info.index, Variable) and
                    (index_replacement := op.array_info.index.accept(self)) is not None):
                op.array_info.index = _assert_type(index_replacement, Variable)

        return self._visit_operation(op)

    def visit_binary_operation(self, op: BinaryOperation) -> Optional[DataflowObject]:
        return self._visit_operation(op)

    def visit_call(self, op: Call) -> Optional[DataflowObject]:
        if (function_replacement := op.function.accept(self)) is not None:
            op._function = _assert_type(
                function_replacement,
                Union[FunctionSymbol, ImportedFunctionSymbol, IntrinsicSymbol, Variable]
            )

        return self._visit_operation(op)

    def visit_condition(self, op: Condition) -> Optional[DataflowObject]:
        return self._visit_operation(op)

    def visit_ternary_expression(self, op: TernaryExpression) -> Optional[DataflowObject]:
        return self._visit_operation(op)

    def visit_comment(self, instr: Comment) -> Optional[DataflowObject]:
        return self._mapper(instr)

    def visit_assignment(self, instr: Assignment) -> Optional[DataflowObject]:
        if (value_replacement := instr.value.accept(self)) is not None:
            instr._value = _assert_type(value_replacement, Expression)
        if (destination_replacement := instr.destination.accept(self)) is not None:
            instr._destination = _assert_type(destination_replacement, Expression)

        return self._mapper(instr)

    def visit_generic_branch(self, instr: GenericBranch) -> Optional[DataflowObject]:
        if (condition_replacement := instr.condition.accept(self)) is not None:
            instr._condition = _assert_type(condition_replacement, Expression)

        return self._mapper(instr)

    def visit_return(self, instr: Return) -> Optional[DataflowObject]:
        if (values_replacement := instr.values.accept(self)) is not None:
            instr._values = _assert_type(values_replacement, ListOperation)

        return self._mapper(instr)

    def visit_break(self, instr: Break) -> Optional[DataflowObject]:
        return self._mapper(instr)

    def visit_continue(self, instr: Continue) -> Optional[DataflowObject]:
        return self._mapper(instr)

    def visit_phi(self, instr: Phi) -> Optional[DataflowObject]:
        # we ignore the return value here, because replacing instr.value itself would require updating
        # instr.origin_block with information we don't have
        instr.value.accept(self)

        # update instr.origin_block with potential changes from instr.value.accept(self)
        for node, expression in instr.origin_block.items():
            if (replacement := self._mapper(expression)) is not None:
                instr.origin_block[node] = _assert_type(replacement, Union[Variable, Constant])

        if (destination_replacement := instr.destination.accept(self)) is not None:
            instr._destination = _assert_type(destination_replacement, Variable)

        return self._mapper(instr)

    def visit_mem_phi(self, instr: MemPhi) -> Optional[DataflowObject]:
        return None
