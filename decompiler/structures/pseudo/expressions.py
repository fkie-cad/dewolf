"""Module defining the custom IR vocabulary.

TERMINALS: string_constant, numeric_constant, variable
TRANSFORMATION RULES:

data-flow-object <-  expression | instruction

instruction      <-  assignment | branch | return | mem-phi

assignment       <-  expression = expression
branch           <-  if (expression)
return           <-  return expression
mem-phi          <-  helper stuff

expression       <-  operation | variable | constant | unknown

operation        <-  unary | binary | ternary | list | call

unary            <-  op expression
binary           <-  expression op expression
ternary          <-  expression ? expression : expression
list             <-  [expression]
call             <-  {string_constant | variable} ([expression])

unknown          <-  string_constant("error_message")
constant         <-  string_constant | numeric_constant

"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Generic, Iterator, List, Optional, Tuple, TypeVar, Union, final

from ...util.insertion_ordered_set import InsertionOrderedSet
from .complextypes import Enum
from .typing import CustomType, Type, UnknownType

T = TypeVar("T")
DecompiledType = TypeVar("DecompiledType", bound=Type)

if TYPE_CHECKING:
    from decompiler.structures.visitors.interfaces import DataflowObjectVisitorInterface


@dataclass
class Tag:
    """Abstraction class for binaryninja.Tag"""

    name: str
    data: str


class DataflowObject(ABC):
    """Interface for data-flow relevant objects."""

    def __init__(self, tags: Optional[Tuple[Tag, ...]] = None):
        self.tags = tags

    @abstractmethod
    def __iter__(self) -> Iterator[DataflowObject]:
        """Iterate all nested DataflowObjects."""
        pass

    @abstractmethod
    def __str__(self) -> str:
        """Return a string representation of the expression."""
        pass

    @property
    @abstractmethod
    def complexity(self) -> int:
        """Return a value indicating the complexity (length) of the given object."""
        pass

    @property
    def requirements_iter(self) -> Iterator[Variable]:
        """Return an iterator of required variables."""
        return
        yield

    @property
    @final
    def requirements(self) -> List[Variable]:
        """Return a list of unique required variables."""
        return list(InsertionOrderedSet(self.requirements_iter))

    def copy(self):
        """Generate a copy of the object."""
        return self.__class__(self.tags)

    @abstractmethod
    def substitute(self, replacee: Expression, replacement: Expression) -> None:
        """Substitute one Expression with another Expression."""
        pass

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this DataFlowObject."""
        raise NotImplementedError(f"accept not implemented for {type(self)}")

    def subexpressions(self) -> Iterator[DataflowObject]:
        """Yield all subexpressions in a depth-first manner."""
        worklist: List[DataflowObject] = [self]
        while worklist and (head := worklist.pop()):
            yield head
            worklist.extend(head)


class Expression(DataflowObject, ABC, Generic[DecompiledType]):
    """Abstract base class for expression types."""

    def __iter__(self) -> Iterator[Expression]:
        yield from []

    @property
    def complexity(self) -> int:
        """Simple expressions like constants and variables have complexity 1"""
        return 1

    def substitute(self, replacee: Expression, replacement: Expression) -> None:
        """Do nothing: default behavior for simple expressions, like Variables and Constants"""
        pass

    @property
    @abstractmethod
    def type(self) -> DecompiledType:
        """Every expression has to define its type."""
        pass


class UnknownExpression(Expression[UnknownType]):
    """Represents an unknown expression type."""

    def __init__(self, msg: str, tags: Optional[Tuple[Tag, ...]] = None):
        """Initialize the type with some kind of error message."""
        self.msg = msg
        super().__init__(tags)

    def __eq__(self, __value):
        return isinstance(__value, UnknownExpression) and self.msg == __value.msg

    def __hash__(self):
        return hash(self.msg)

    def __str__(self) -> str:
        """Return the error message as string representation."""
        return self.msg

    @property
    def type(self) -> UnknownType:
        """An unknown expression is of unknown type."""
        return UnknownType()

    def copy(self) -> UnknownExpression:
        """Generate a copy of the UnknownExpression with the same message."""
        return UnknownExpression(self.msg, self.tags)

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Expression."""
        return visitor.visit_unknown_expression(self)


class Constant(Expression[DecompiledType]):
    """Represents a constant expression type."""

    ValueType = int | float | str | bytes | Expression | list["ValueType"] | dict[int, "ValueType"]

    def __init__(
        self,
        value: ValueType,
        vartype: DecompiledType = UnknownType(),
        pointee: Optional[Constant] = None,
        tags: Optional[Tuple[Tag, ...]] = None,
    ):
        """Init a new constant expression"""
        self.value = value
        self._type = vartype
        self._pointee = pointee
        super().__init__(tags)

    def __eq__(self, __value):
        return (
            isinstance(__value, Constant)
            and self.value == __value.value
            and self._type == __value._type
            and self._pointee == __value.pointee
        )

    def __hash__(self):
        match self.value:
            case dict() | list():
                value_hash_obj = json.dumps(self.value, sort_keys=True)
            case _:
                value_hash_obj = self.value
        return hash((value_hash_obj, self._type, self._pointee))

    def __repr__(self) -> str:
        value = str(self) if isinstance(self.value, str) else self.value
        if self.pointee:
            return f"{value} type: {self.type}, pointee: {repr(self.pointee)}"
        return f"{value} type: {self.type}"

    def __str__(self) -> str:
        """Return a hex-based string representation for integers, strings are printed with double quotation marks.
        Constants of type Enum are represented as strings (corresponding enumerator identifiers).
        """
        if isinstance(self._type, Enum):
            name = self._type.get_name_by_value(self.value)
            if name is not None:
                return name
            # otherwise, i.e. if value is not found in Enum class, fall through
        if self._type.is_boolean:
            return "true" if self.value else "false"
        if isinstance(self.value, str):
            return f'"{self.value.encode("unicode_escape").decode("utf-8")}"'
        if self._pointee:
            return str(self._pointee)
        if isinstance(self.value, int):
            return f"{hex(self.value)}"
        if hasattr(self.value, "__str__"):
            return str(self.value)
        raise ValueError(f"Unknown constant type {type(self.value)}")

    @property
    def type(self) -> DecompiledType:
        """Return the type of the constant."""
        return self._type

    @property
    def pointee(self) -> Optional[Constant]:
        """Return the value pointed to by this constant, if any."""
        return self._pointee

    def copy(self) -> Constant:
        """Generate a Constant with the same value and type."""
        return Constant(self.value, self._type, self._pointee.copy() if self._pointee else None, self.tags)

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Expression."""
        return visitor.visit_constant(self)


class NotUseableConstant(Constant):
    """Represents a non useable constant like 'inf', 'NaN', or the value of builtin functions as a string"""

    def __init__(self, value: str, tags: Optional[Tuple[Tag, ...]] = None):
        super().__init__(value, CustomType("double", 0), tags=tags)

    def __eq__(self, __value):
        return isinstance(__value, NotUseableConstant) and self.value == __value.value

    def __hash__(self):
        return hash(self.value)

    def __str__(self) -> str:
        """Return a string because NotUseableConstant are string only"""
        return self.value

    def __repr__(self):
        """Return the non usable constant."""
        return f"{self.value} type: not-usable-constant"

    def copy(self) -> NotUseableConstant:
        """Generate an NonUseableConstant with the same value"""
        return NotUseableConstant(self.value)


class Symbol(Constant):
    """Represents a symbol based expression."""

    def __init__(self, name: str, value: Union[int, float], vartype: Type = UnknownType(), tags: Optional[Tuple[Tag, ...]] = None):
        super().__init__(value, vartype, tags=tags)
        self._name = name

    def __eq__(self, __value):
        return isinstance(__value, Symbol) and self._name == __value._name and self.value == __value.value

    def __hash__(self):
        return hash((self._name, self.value))

    @property
    def name(self) -> str:
        return self._name

    @property
    def address(self) -> int:
        return self.value

    def __str__(self):
        return f"{self._name}"

    def __repr__(self):
        if isinstance(self.address, (int, float)):
            return f"symbol '{self.name}' at {hex(self.address)}"
        raise ValueError(f"Unknown symbol type {type(self.value)}")

    def copy(self) -> Symbol:
        return Symbol(self.name, self.value, self._type, self.tags)


class FunctionSymbol(Symbol):
    """Represents a function name"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.can_return = None

    def __eq__(self, __value):
        return isinstance(__value, FunctionSymbol) and super().__eq__(__value)

    def __hash__(self):
        return super().__hash__()

    def copy(self) -> FunctionSymbol:
        return FunctionSymbol(self.name, self.value, self._type, self.tags)


class ImportedFunctionSymbol(FunctionSymbol):
    """Represents an imported function name"""

    def __eq__(self, __value):
        return isinstance(__value, ImportedFunctionSymbol) and super().__eq__(__value)

    def __hash__(self):
        return super().__hash__()

    def copy(self) -> ImportedFunctionSymbol:
        return ImportedFunctionSymbol(self._name, self.value, self._type, self.tags)


class IntrinsicSymbol(FunctionSymbol):
    """Represents a compiler instrinsic"""

    INTRINSIC_ADDRESS = 0xF1FFFFFF

    def __init__(self, name: str):
        super().__init__(name, self.INTRINSIC_ADDRESS)

    def __eq__(self, __value):
        return isinstance(__value, IntrinsicSymbol) and self.name == __value.name

    def __hash__(self):
        return hash(self.name)

    def __repr__(self):
        return f"intrinsic '{self.name}'"

    def copy(self) -> IntrinsicSymbol:
        return IntrinsicSymbol(self.name)


class Variable(Expression[DecompiledType]):
    """Represents a variable based expression."""

    def __init__(
        self,
        name: str,
        vartype: DecompiledType = UnknownType(),
        ssa_label: Optional[int] = None,
        is_aliased: bool = False,
        ssa_name: Optional[Variable] = None,
        tags: Optional[Tuple[Tag, ...]] = None,
    ):
        """Init a new variable based on its name and type."""
        self.is_aliased: bool = is_aliased
        self.ssa_label = ssa_label
        self._name = name
        self._type = vartype
        self.ssa_name = ssa_name
        super().__init__(tags)

    def __eq__(self, __value):
        return (
            isinstance(__value, Variable)
            and self._name == __value._name
            and self.ssa_label == __value.ssa_label
            and self._type == __value._type
            and self.is_aliased == __value.is_aliased
        )

    def __hash__(self):
        return hash((self._name, self.ssa_label, self._type, self.is_aliased))

    def __repr__(self) -> str:
        """Return a debug representation of the variable, which includes all the attributes"""
        return f"{self.name}#{self.ssa_label} (type: {self.type} aliased: {self.is_aliased})"

    def __str__(self) -> str:
        """Return a string representation of the variable."""
        return f"{self._name}" if (label := self.ssa_label) is None else f"{self._name}#{label}"

    @property
    def name(self) -> str:
        """Return the name of the variable."""
        return self._name

    @property
    def requirements_iter(self) -> Iterator["Variable"]:
        """A variable depends on itself"""
        yield self

    @property
    def type(self) -> DecompiledType:
        """Return the variable's type."""
        return self._type

    def unsubscript(self) -> None:
        """Remove the assigned ssa-label."""
        self.ssa_label = None

    def copy(
        self,
        name: str = None,
        vartype: DecompiledType = None,
        ssa_label: Optional[int] = None,
        is_aliased: bool = None,
        ssa_name: Optional[Variable] = None,
        tags: Optional[Tuple[Tag, ...]] = None,
    ) -> Variable:
        """Provide a copy of the current Variable."""
        return self.__class__(
            self._name[:] if name is None else name,
            self._type if vartype is None else vartype,
            self.ssa_label if ssa_label is None else ssa_label,
            self.is_aliased if is_aliased is None else is_aliased,
            self.ssa_name if ssa_name is None else ssa_name,
            self.tags if tags is None else tags,
        )

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Expression."""
        return visitor.visit_variable(self)


class GlobalVariable(Variable):
    """Represents a global variable that comes from MLIL_CONST_PTR.
    MLIL_CONST_PTR represents the following types of pointers:
        - Pointers in .text/.bss/.rodata/.data/symbol table.
        - Function call, and thereby function pointers.
    """

    def __init__(
        self,
        name: str,
        vartype: Type,
        initial_value: Expression,
        ssa_label: int = None,
        is_aliased: bool = True,
        ssa_name: Optional[Variable] = None,
        is_constant: bool = False,
        tags: Optional[Tuple[Tag, ...]] = None,
    ):
        """Init a new global variable. Compared to Variable, it has an additional field initial_value.
        :param initial_value: Can be a number, string or GlobalVariable."""
        super().__init__(name, vartype, ssa_label, is_aliased, ssa_name, tags=tags)
        self.initial_value = initial_value
        self.is_constant = is_constant

    def __eq__(self, __value):
        return isinstance(__value, GlobalVariable) and super().__eq__(__value)

    def __hash__(self):
        return super().__hash__()

    def copy(
        self,
        name: str = None,
        vartype: Type = None,
        initial_value: Expression = None,
        ssa_label: int = None,
        is_aliased: bool = None,
        ssa_name: Optional[Variable] = None,
        is_constant: bool = None,
        tags: Optional[Tuple[Tag, ...]] = None,
    ) -> GlobalVariable:
        """Provide a copy of the current Variable."""

        return self.__class__(
            self._name[:] if name is None else name,
            self._type if vartype is None else vartype,
            self.initial_value.copy() if initial_value is None else initial_value.copy(),
            self.ssa_label if ssa_label is None else ssa_label,
            self.is_aliased if is_aliased is None else is_aliased,
            self.ssa_name if ssa_name is None else ssa_name,
            self.is_constant if is_constant is None else is_constant,
            self.tags if tags is None else tags,
        )

    def __iter__(self) -> Iterator[Expression]:
        yield self.initial_value

    def __str__(self) -> str:
        """Return a string representation of the global variable."""
        return f"{self._name}" if (label := self.ssa_label) is None else f"{self._name}#{label}"

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Expression."""
        return visitor.visit_global_variable(self)


class RegisterPair(Variable):
    """Represents a variable saved in two registers (e.g. eax:edx)."""

    def __init__(self, high: Variable, low: Variable, vartype: Type = UnknownType(), tags: Optional[Tuple[Tag, ...]] = None):
        """Init a new RegisterPair."""
        super().__init__(f"({high}:{low})", vartype, tags=tags)
        self._high = high
        self._low = low
        self._type = vartype

    def __eq__(self, __value):
        return (
            isinstance(__value, RegisterPair) and self._high == __value._high and self._low == __value._low and self._type == __value._type
        )

    def __hash__(self):
        return hash((self._high, self._low, self._type))

    def __repr__(self) -> str:
        """Return debug representation of register pair"""
        return f"{repr(self._high)}:{repr(self._low)} type: {self.type}"

    def __iter__(self) -> Iterator[Variable]:
        """Iterate both components of the register pair."""
        yield self._low
        yield self._high

    @property
    def complexity(self) -> int:
        """Complexity of the register pair is sum of its components' complexities"""
        return self._low.complexity + self._high.complexity

    @property
    def high(self) -> Variable:
        """Return the high part of the pair."""
        return self._high

    @property
    def low(self) -> Variable:
        """Return the low part of the pair."""
        return self._low

    @property
    def requirements_iter(self) -> Iterator[Variable]:
        """Pairs depend on their components and itself in case when being used as a single variable
        e.g. 0: (eax:edx) = 0x666667 * ebx
             1: edx = (eax:edx) - 2
        """
        yield self
        yield self._high
        yield self._low

    @property
    def type(self) -> Type:
        """Return the resulting type of the register pair. (Doubled components' type)"""
        return self._type

    def substitute(self, replacee: Variable, replacement: Variable) -> None:
        """Replace parts of the register pair when invoked"""
        self._low = replacement if replacee == self._low else self._low
        self._high = replacement if replacee == self._high else self._high

    def copy(self) -> RegisterPair:
        """Return a copy of the current register pair."""
        return RegisterPair(self._high.copy(), self._low.copy(), self._type, self.tags)

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Expression."""
        return visitor.visit_register_pair(self)
