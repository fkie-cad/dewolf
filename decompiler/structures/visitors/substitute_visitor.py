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
from decompiler.structures.pseudo.operations import ArrayInfo
from decompiler.structures.visitors.interfaces import DataflowObjectVisitorInterface

T = TypeVar("T", bound=DataflowObject)


def _assert_type(obj: DataflowObject, t: type[T]) -> T:
    if not isinstance(obj, t):
        raise TypeError()
    else:
        return obj


class SubstituteVisitor(DataflowObjectVisitorInterface[Optional[DataflowObject]]):
    """
    A visitor class for performing substitutions in a dataflow tree.

    This class allows you to create instances that can traverse a dataflow graph and perform substitutions
    based on a provided mapping function. The mapping function is applied to each visited node in the graph,
    and if the mapping function returns a non-None value, the node is replaced with the returned value.

    Note:
        - Modifications to the dataflow tree happen in place. Only if the whole node that is being visited is replaced,
          the visit method returns the replacement and not none.
        - Even if a visit method returns a replacement, modifications could have happened to the original dataflow tree.
        - Care should be taken when using this visitor, as substitution can leave the dataflow tree in an invalid state.
          For example a dereference UnaryOperation could be updated without the changes being reflected in its ArrayInfo.
          Same with changes to Phi and its origin_block
    """

    @classmethod
    def identity(cls, replacee: DataflowObject, replacement: DataflowObject) -> "SubstituteVisitor":
        """
        Create a SubstituteVisitor instance for identity-based substitution.

        This class method creates a SubstituteVisitor instance that replaces nodes equal to the 'replacee'
        parameter with the 'replacement' parameter based on identity comparison (is).

        Note:
            While SubstituteVisitor.equality() creates copies of the specified replacement, this one does not!
            Be careful as to not introduce the same dataflow object twice into the dataflow tree.

        :param replacee: The object to be replaced based on identity.
        :param replacement: The object to replace 'replacee' with.
        :return: A SubstituteVisitor instance for identity-based substitution.
        """

        return SubstituteVisitor(lambda o: replacement if o is replacee else None)

    @classmethod
    def equality(cls, replacee: DataflowObject, replacement: DataflowObject) -> "SubstituteVisitor":
        """
        Create a SubstituteVisitor instance for equality-based substitution.

        This class method creates a SubstituteVisitor instance that replaces nodes equal to the 'replacee'
        parameter with the 'replacement' parameter based on equality comparison (==).

        Note:
            This visitor creates copies of the specified replacement when substituting.

        :param replacee: The object to be replaced based on equality.
        :param replacement: The object to replace 'replacee' with.
        :return: A SubstituteVisitor instance for equality-based substitution.
        """

        return SubstituteVisitor(lambda o: replacement.copy() if o == replacee else None)

    def __init__(self, mapper: Callable[[DataflowObject], Optional[DataflowObject]]) -> None:
        """
        Initialize a SubstituteVisitor instance.

        :param mapper: A callable object that takes a DataflowObject as input and returns an Optional[DataflowObject].
        This function is used to determine replacements for visited nodes.
        """

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
        """Base visit function used for all operation related visit functions"""
        for index, operand in enumerate(op.operands):
            if (repl := operand.accept(self)) is not None:
                op.operands[index] = _assert_type(repl, Expression)

        return self._mapper(op)

    def visit_list_operation(self, op: ListOperation) -> Optional[DataflowObject]:
        return self._visit_operation(op)

    def _substitute_array_info(self, array_info: ArrayInfo):
        if (base_replacement := array_info.base.accept(self)) is not None:
            array_info.base = _assert_type(base_replacement, Variable)

        # array_info.index can either be Variable or int. Only try substituting if not int
        if isinstance(array_info.index, Variable):
            if (index_replacement := array_info.index.accept(self)) is not None:
                array_info.index = _assert_type(index_replacement, Variable)

    def visit_unary_operation(self, op: UnaryOperation) -> Optional[DataflowObject]:
        if op.array_info is not None:
            self._substitute_array_info(op.array_info)

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

    def _visit_phi_base(self, instr: Phi, value_type: type[DataflowObject]):
        if (repl := instr.value.accept(self)) is not None:
            # Phi only accepts ListOperation with 'value_type' as valid values
            for operand in _assert_type(repl, ListOperation).operands:
                _assert_type(operand, value_type)

            instr._value = repl

        for node, expression in instr.origin_block.items():
            if (replacement := expression.accept(self)) is not None:
                instr.origin_block[node] = _assert_type(replacement, Union[Variable, Constant])

        if (destination_replacement := instr.destination.accept(self)) is not None:
            instr._destination = _assert_type(destination_replacement, Variable)

        return self._mapper(instr)

    def visit_phi(self, instr: Phi) -> Optional[DataflowObject]:
        return self._visit_phi_base(instr, Union[Variable, Constant])

    def visit_mem_phi(self, instr: MemPhi) -> Optional[DataflowObject]:
        return self._visit_phi_base(instr, Union[Variable])
