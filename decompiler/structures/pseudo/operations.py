"""Module declaring all valid IR operations."""

from __future__ import annotations

import logging
from abc import ABC
from dataclasses import dataclass
from enum import Enum, auto
from itertools import chain, zip_longest
from typing import TYPE_CHECKING, Dict, Iterator, List, Optional, Sequence, Tuple, TypeVar, Union

from decompiler.util.insertion_ordered_set import InsertionOrderedSet

from .expressions import Constant, Expression, IntrinsicSymbol, Symbol, Tag, Variable
from .typing import CustomType, Pointer, Type, UnknownType

T = TypeVar("T")


if TYPE_CHECKING:
    from decompiler.structures.visitors.interfaces import DataflowObjectVisitorInterface


class OperationType(Enum):
    """Enumerator of all operation types."""

    minus = auto()
    minus_with_carry = auto()
    minus_float = auto()
    plus = auto()
    plus_with_carry = auto()
    plus_float = auto()
    negate = auto()
    left_shift = auto()
    right_shift = auto()
    right_shift_us = auto()
    left_rotate = auto()
    right_rotate = auto()
    right_rotate_carry = auto()
    left_rotate_carry = auto()
    multiply = auto()
    multiply_us = auto()
    multiply_float = auto()
    divide = auto()
    divide_us = auto()
    divide_float = auto()
    modulo = auto()
    modulo_us = auto()
    power = auto()
    bitwise_or = auto()
    bitwise_and = auto()
    bitwise_xor = auto()
    bitwise_not = auto()
    logical_or = auto()
    logical_and = auto()
    logical_not = auto()
    equal = auto()
    not_equal = auto()
    less = auto()
    less_us = auto()
    greater = auto()
    greater_us = auto()
    less_or_equal = auto()
    less_or_equal_us = auto()
    greater_or_equal = auto()
    greater_or_equal_us = auto()
    dereference = auto()
    address = auto()
    cast = auto()
    pointer = auto()
    low = auto()
    ternary = auto()
    call = auto()
    field = auto()
    list_op = auto()
    adc = auto()
    member_access = auto()


# For pretty-printing and debug
SHORTHANDS = {
    OperationType.minus: "-",
    OperationType.minus_with_carry: "-",
    OperationType.minus_float: "f-",
    OperationType.plus: "+",
    OperationType.plus_with_carry: "+",
    OperationType.plus_float: "f+",
    OperationType.negate: "-",
    OperationType.left_shift: "<<",
    OperationType.right_shift: ">>",
    OperationType.right_shift_us: "u>>",
    OperationType.left_rotate: "l_rot",
    OperationType.right_rotate: "r_rot",
    OperationType.right_rotate_carry: "r_rot_carry",
    OperationType.left_rotate_carry: "l_rot_carry",
    OperationType.multiply: "*",
    OperationType.multiply_us: "u*",
    OperationType.multiply_float: "f*",
    OperationType.divide: "/",
    OperationType.divide_us: "u/",
    OperationType.divide_float: "f/",
    OperationType.modulo: "%",
    OperationType.modulo_us: "u%",
    OperationType.power: "**",
    OperationType.bitwise_or: "|",
    OperationType.bitwise_and: "&",
    OperationType.bitwise_xor: "^",
    OperationType.bitwise_not: "~",
    OperationType.logical_or: "||",
    OperationType.logical_and: "&&",
    OperationType.logical_not: "!",
    OperationType.equal: "==",
    OperationType.not_equal: "!=",
    OperationType.less: "<",
    OperationType.less_us: "u<",
    OperationType.greater: ">",
    OperationType.greater_us: "u>",
    OperationType.less_or_equal: "<=",
    OperationType.less_or_equal_us: "u<=",
    OperationType.greater_or_equal: ">=",
    OperationType.greater_or_equal_us: "u>=",
    OperationType.dereference: "*",
    OperationType.address: "&",
    OperationType.cast: "cast",
    OperationType.pointer: "point",
    OperationType.low: "low",
    OperationType.ternary: "?",
    OperationType.call: "func",
    OperationType.list_op: "list",
    OperationType.adc: "adc",
    OperationType.member_access: ".",
}

UNSIGNED_OPERATIONS = {
    OperationType.multiply_us,
    OperationType.divide_us,
    OperationType.modulo_us,
    OperationType.less_us,
    OperationType.less_or_equal_us,
    OperationType.greater_us,
    OperationType.greater_or_equal_us,
}

SIGNED_OPERATIONS = {
    OperationType.multiply,
    OperationType.divide,
    OperationType.modulo,
    OperationType.less,
    OperationType.less_or_equal,
    OperationType.greater,
    OperationType.greater_or_equal,
}

COMMUTATIVE_OPERATIONS = {
    OperationType.plus,
    OperationType.multiply,
    OperationType.multiply_us,
    OperationType.bitwise_and,
    OperationType.bitwise_xor,
    OperationType.bitwise_or,
    OperationType.logical_or,
    OperationType.logical_and,
    OperationType.equal,
    OperationType.not_equal,
}

NON_COMPOUNDABLE_OPERATIONS = {
    OperationType.right_rotate,
    OperationType.right_rotate_carry,
    OperationType.left_rotate,
    OperationType.left_rotate_carry,
    OperationType.power,
    OperationType.logical_or,
    OperationType.logical_and,
    OperationType.equal,
    OperationType.not_equal,
}


class Operation(Expression, ABC):
    """Base class for all operations"""

    def __init__(
        self,
        operation: OperationType,
        operands: Sequence[Expression],
        vartype: Type = UnknownType(),
        tags: Optional[Tuple[Tag, ...]] = None,
    ):
        """Initialize an operation."""
        self._operands = list(operands)
        self._operation = operation
        self._type = vartype
        super().__init__(tags)

    def __eq__(self, __value):
        return (
            isinstance(__value, Operation)
            and self._operation == __value._operation
            and self._operands == __value._operands
            and self.type == __value.type
        )

    def __hash__(self):
        return hash((self._operation, tuple(self._operands), self.type))

    def __repr__(self) -> str:
        """Return debug representation of an operation. Used in equality checks"""
        return f"{self.operation.name} [{','.join(map(repr, self._operands))}] {self.type}"

    def __iter__(self) -> Iterator[Expression]:
        """Yield all subexpression nested into the Operation."""
        yield from self._operands

    @property
    def is_signed(self) -> bool:
        """Returns whether the given operation is signed."""
        return self.operation in SIGNED_OPERATIONS

    @property
    def is_unsigned(self) -> bool:
        """Returns whether the given operation is unsigned."""
        return self.operation in UNSIGNED_OPERATIONS

    @property
    def has_sign(self) -> bool:
        """Returns whether the given operation has a sign (signed or unsigned)."""
        return self.operation in SIGNED_OPERATIONS | UNSIGNED_OPERATIONS

    @property
    def complexity(self) -> int:
        """Complexity of an operation is sum of complexities of all operands"""
        return sum([x.complexity for x in self.operands])

    @property
    def operands(self) -> List[Expression]:
        """Return a list of operand expressions."""
        return self._operands

    @property
    def operation(self) -> OperationType:
        """Return the operation type."""
        return self._operation

    @property
    def requirements_iter(self) -> Iterator[Variable]:
        """Operation requires a list of all unique variables required by each of its operands"""
        for operand in self._operands:
            yield from operand.requirements_iter

    def substitute(self, replacee: Expression, replacement: Expression) -> None:
        """Substitutes operand directly if possible, then recursively substitutes replacee in operands"""
        for operand in self._operands:
            operand.substitute(replacee, replacement)
        self._operands = [operand if operand != replacee else replacement for operand in self._operands]

    @property
    def type(self) -> Type:
        """Return the result type of the given expression."""
        if type(self._type) is not UnknownType:
            return self._type
        if operand_types := [operand.type for operand in self.operands]:
            return max(operand_types, key=lambda type: type.size)
        return UnknownType()

    @staticmethod
    def _collect_required_variables(operands: List[Expression]) -> List[Variable]:
        """Create list of all requirements lists of all operands, flatten it, remove duplicates"""
        return list(InsertionOrderedSet(chain(*[op.requirements for op in operands])))


class ListOperation(Operation):
    """Operation-wrapper for list of expressions
    - for phi function arguments
    - for multiple return values of a call
    """

    def __init__(self, operands: Sequence[Expression], tags: Optional[Tuple[Tag, ...]] = None):
        super().__init__(OperationType.list_op, operands, tags=tags)

    def __eq__(self, __value):
        return isinstance(__value, ListOperation) and super().__eq__(__value)

    def __hash__(self):
        return super().__hash__()

    def __str__(self) -> str:
        return ",".join(map(str, self.operands))

    def copy(self) -> ListOperation:
        """Create a copy of a ListOperation by copying all operands."""
        return ListOperation([operand.copy() for operand in self._operands], self.tags)

    def __getitem__(self, item):
        """Allow list access to the operands."""
        return self.operands[item]

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Operation."""
        return visitor.visit_list_operation(self)


@dataclass(unsafe_hash=True)
class ArrayInfo:
    """Class to store array info information for dereference if available
    base: variable storing start address of an array
    index: int or variable for []-access
    confidence:
        true: we know the type of base, and therefore size of its elements
        false: type of base is unknown-size (void*, etc); we still can determine that this is
               array element access from the form of dereference

    *(a + 4), int* a -> a[1] a: base, 1: index, confidence: True
    *(a + 4*i), void* a -> a[i] a: base, i: index, confidence: False
    """

    base: Variable = None
    index: Union[int, Variable] = -1
    confidence: bool = False

    def substitute(self, replacee: Variable, replacement: Variable):
        """Replace Variable used in array access"""
        if self.base == replacee:
            self.base = replacement
        if self.index == replacee:
            self.index = replacement


class UnaryOperation(Operation):
    """Represents an expression with a single operand."""

    def __init__(
        self,
        operation: OperationType,
        operands: List[Expression],
        vartype: Type = UnknownType(),
        writes_memory: Optional[int] = None,
        contraction: bool = False,
        tags: Optional[Tuple[Tag, ...]] = None,
        array_info: Optional[ArrayInfo] = None,
    ):
        """Construct a new unary operation object, combining the fields of the Operation class with the writes_memory field.
        Contraction field specifies if cast operation comes from contraction of register (e.g. eax.al) rather than type extension
        Array info stores array information by dereference if available
        """
        super().__init__(operation, operands, vartype, tags=tags)
        self._writes_memory = writes_memory
        self.contraction = contraction
        self.array_info = array_info

    def __eq__(self, __value):
        return (
            isinstance(__value, UnaryOperation)
            and self.contraction == __value.contraction
            and self.array_info == __value.array_info
            and super().__eq__(__value)
        )

    def __hash__(self):
        return hash((self.contraction, self.array_info, super().__hash__()))

    def __str__(self):
        """Return a string representation of the unary operation"""
        if self.operation == OperationType.cast and self.contraction:
            return f"({int(self.type.size/8)}: ) {self.operand}"
        if self.operation == OperationType.cast:
            return f"({self.type}) {self.operand}"
        return f"{SHORTHANDS[self.operation]}({self.operand})"

    def __repr__(self):
        if self.contraction:
            return f"{super().__repr__()} contract"
        elif self.array_info:
            return f"{super().__repr__()} {self.array_info}"
        return super().__repr__()

    @property
    def operand(self) -> Expression:
        """Return the single operand."""
        return self._operands[0]

    @property
    def complexity(self) -> int:
        """Overwrites complexity property of base class in order to increase the complexity of cast operations."""
        return self.operand.complexity

    @property
    def requirements_iter(self) -> Iterator[Variable]:
        """Return the requirements of the single operand."""
        return self.operand.requirements_iter

    @property
    def writes_memory(self) -> Optional[int]:
        """Return the memory version generated by this assignment, if any."""
        return self._writes_memory

    def substitute(self, replacee: Expression, replacement: Expression) -> None:
        """Substitutes operand directly if possible, then recursively substitutes replacee in operands"""
        if self.array_info is not None and isinstance(replacee, Variable) and isinstance(replacement, Variable):
            self.array_info.substitute(replacee, replacement)
        super().substitute(replacee, replacement)

    def copy(self) -> UnaryOperation:
        """Copy the current UnaryOperation, copying all operands and the type."""
        return UnaryOperation(
            self._operation,
            [operand.copy() for operand in self._operands],
            self._type,
            writes_memory=self._writes_memory,
            contraction=self.contraction,
            array_info=ArrayInfo(self.array_info.base, self.array_info.index, self.array_info.confidence) if self.array_info else None,
        )

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Operation."""
        return visitor.visit_unary_operation(self)


class MemberAccess(UnaryOperation):
    def __init__(
        self,
        offset: int,
        member_name: str,
        operands: List[Expression],
        vartype: Type = UnknownType(),
        writes_memory: Optional[int] = None,
    ):
        super().__init__(OperationType.member_access, operands, vartype, writes_memory=writes_memory)
        self.member_offset = offset
        self.member_name = member_name

    def __eq__(self, __value):
        return isinstance(__value, MemberAccess) and super().__eq__(__value)

    def __hash__(self):
        return super().__hash__()

    def __str__(self):
        # use -> when accessing member via a pointer to a struct: ptrBook->title
        # use . when accessing struct member directly: book.title
        if isinstance(self.struct_variable.type, Pointer):
            return f"{self.struct_variable}->{self.member_name}"
        return f"{self.struct_variable}.{self.member_name}"

    @property
    def struct_variable(self) -> Expression:
        """Variable of complex type, which member is being accessed here."""
        return self.operand

    def substitute(self, replacee: Expression, replacement: Expression) -> None:
        if isinstance(replacee, Variable) and replacee == self.struct_variable and isinstance(replacement, Variable):
            self.operands[:] = [replacement]

    def copy(self) -> MemberAccess:
        """Copy the current UnaryOperation, copying all operands and the type."""
        return MemberAccess(
            self.member_offset,
            self.member_name,
            [operand.copy() for operand in self._operands],
            self._type,
            writes_memory=self.writes_memory,
        )

    def is_read_access(self) -> bool:
        """Read-only member access."""
        return self.writes_memory is None

    def is_write_access(self) -> bool:
        """Member is being accessed for writing."""
        return self.writes_memory is not None


class BinaryOperation(Operation):
    """Class representing operations with two operands."""

    __match_args__ = ("operation", "left", "right")

    def __eq__(self, __value):
        return isinstance(__value, BinaryOperation) and super().__eq__(__value)

    def __hash__(self):
        return super().__hash__()

    def __str__(self) -> str:
        """Return a string representation with infix notation."""
        str_left = f"({self.left})" if isinstance(self.left, Operation) else f"{self.left}"
        str_right = f"({self.right})" if isinstance(self.right, Operation) else f"{self.right}"
        return f"{str_left} {SHORTHANDS[self.operation]} {str_right}"

    @property
    def left(self) -> Expression:
        """Return the left-hand-side operand."""
        return self._operands[0]

    @property
    def right(self) -> Expression:
        """Return the right-hand-side operand."""
        return self._operands[1]

    def copy(self) -> BinaryOperation:
        """Generate a deep copy of the current binary operation."""
        return self.__class__(self._operation, [operand.copy() for operand in self._operands], self._type, self.tags)

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Operation."""
        return visitor.visit_binary_operation(self)


class Call(Operation):
    """Class representing a Call operation"""

    def __init__(
        self,
        function: Expression,
        parameter: List[Expression],
        vartype: Type = UnknownType(),
        writes_memory: Optional[int] = None,
        meta_data: Optional[dict] = None,
        tags: Optional[Tuple[Tag, ...]] = None,
    ):
        """Initialize a new call operation."""
        super().__init__(OperationType.call, parameter, vartype=vartype, tags=tags)
        self._function = function
        self._writes_memory = writes_memory
        self._meta_data = meta_data

    def __eq__(self, __value):
        return isinstance(__value, Call) and self._function == __value._function and self._operands == __value._operands

    def __hash__(self):
        return hash((self._function, tuple(self._operands)))

    def __repr__(self):
        """Return debug representation of a call"""
        if self._meta_data is not None:
            parameter_names = self._meta_data.get("param_names", [])
            operands_repr = map(repr, self._operands)
            operands_with_labels = zip_longest(parameter_names, operands_repr, fillvalue="")
            arguments_str = ",".join(f"{label}{': ' if label else ''}{op}" for label, op in operands_with_labels)
            return f"{self._function_name_string()} {arguments_str}"
        operands_repr = ",".join(map(repr, self._operands))
        return f"{self._function_name_string()} {operands_repr}"

    def __str__(self):
        """Return a string representation of the call."""
        operands = ", ".join(map(str, self._operands))
        return f"{self._function_name_string()}({operands})"

    def __iter__(self) -> Iterator[Expression]:
        """For Call operations, the function expression is also a subexpression."""
        yield self._function
        yield from self._operands

    @property
    def parameters(self) -> List[Expression]:
        """Return the call parameters / operands."""
        return self._operands

    @property
    def meta_data(self) -> Dict[str, List[str]]:
        """Return dictionary of meta data e.g. parameter names of function call signature
        :key - "param_names": list of parameter names
        """
        return self._meta_data

    @property
    def requirements_iter(self) -> Iterator[Variable]:
        yield from self._function.requirements_iter
        yield from super().requirements_iter

    @property
    def function(self) -> Expression:
        """Return the name of the function called."""
        return self._function

    @property
    def writes_memory(self) -> Optional[int]:
        """Return the memory version generated by this assignment, if any."""
        return self._writes_memory

    def copy(self) -> Call:
        """Copy the current Call instruction."""
        return Call(
            self._function,
            [operand.copy() for operand in self._operands],
            self._type,
            self._writes_memory,
            self._meta_data.copy() if self._meta_data is not None else None,
            self.tags,
        )

    def _function_name_string(self) -> str:
        if isinstance(self._function, (Symbol, IntrinsicSymbol)):
            return f"{self._function.name}"
        return f"{self.function}"

    def substitute(self, replacee: Expression, replacement: Expression) -> None:
        if replacee == self._function:
            self._function = replacement
        super().substitute(replacee, replacement)

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Operation."""
        return visitor.visit_call(self)


class Condition(BinaryOperation):
    """Represents a binary operation with boolean result."""

    NEGATIONS = {
        OperationType.not_equal: OperationType.equal,
        OperationType.equal: OperationType.not_equal,
        OperationType.greater: OperationType.less_or_equal,
        OperationType.greater_us: OperationType.less_or_equal_us,
        OperationType.less_or_equal: OperationType.greater,
        OperationType.less_or_equal_us: OperationType.greater_us,
        OperationType.greater_or_equal: OperationType.less,
        OperationType.greater_or_equal_us: OperationType.less_us,
        OperationType.less: OperationType.greater_or_equal,
        OperationType.less_us: OperationType.greater_or_equal_us,
    }

    def __eq__(self, __value):
        v_ = isinstance(__value, Condition) and super().__eq__(__value)
        return v_

    def __hash__(self):
        return super().__hash__()

    @property
    def type(self) -> Type:
        """Conditions always return a boolean value."""
        return CustomType.bool()

    def negate(self) -> "Condition":
        """Return a new Condition instance with inverted condition."""
        try:
            negated_sign = self.NEGATIONS[self.operation]
            return Condition(negated_sign, self.operands)
        except KeyError as e:
            logging.error(f"Operation {self.operation} cannot be negated")
            raise e

    def is_equality_with_constant_check(self) -> bool:
        """Check whether condition is of type expr == const or const == expr"""
        return self.operation == OperationType.equal and any([isinstance(op, Constant) for op in self.operands])

    def is_variable_equality_with_constant_check(self, variable: Variable) -> bool:
        """Check whether condition is of type var == const or const == var"""
        return any([op == variable for op in self.operands]) and self.is_equality_with_constant_check()

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Operation."""
        return visitor.visit_condition(self)


class TernaryExpression(Operation):
    """Class representing inline-if constructs."""

    def __init__(self, condition: Expression, true: Expression, false: Expression, tags: Optional[Tuple[Tag, ...]] = None):
        """Initialize a new inline-if operation."""
        super().__init__(OperationType.ternary, [condition, true, false], true.type, tags=tags)

    def __eq__(self, __value):
        return isinstance(__value, TernaryExpression) and super().__eq__(__value)

    def __hash__(self):
        return super().__hash__()

    def __str__(self) -> str:
        """Returns string representation"""
        return f"{self.condition} ? {self.true} : {self.false}"

    @property
    def condition(self) -> Expression:
        """Return ternary expression condition."""
        return self.operands[0]

    @property
    def true(self) -> Expression:
        """Return true branch of ternary expression."""
        return self.operands[1]

    @property
    def false(self) -> Expression:
        """Return false branch of ternary expression."""
        return self.operands[2]

    def copy(self) -> TernaryExpression:
        """Generate a copy of the TernaryExpression."""
        return TernaryExpression(self.condition.copy(), self.true.copy(), self.false.copy(), self.tags)

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Operation."""
        return visitor.visit_ternary_expression(self)
