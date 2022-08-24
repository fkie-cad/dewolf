"""Module modeling all pseudo code instructions."""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, Generic, Iterator, List, Optional, Sequence, Set, Tuple, TypeVar, Union, final

from .expressions import Constant, DataflowObject, Expression, GlobalVariable, Tag, Variable
from .operations import BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation

E = TypeVar("E", bound=Expression)
F = TypeVar("F", bound=Expression)

T = TypeVar("T")


if TYPE_CHECKING:
    from decompiler.structures.visitors.interfaces import DataflowObjectVisitorInterface


class Instruction(DataflowObject, ABC):
    """Instruction interface class."""

    @abstractmethod
    def __iter__(self) -> Iterator[Expression]:
        """Yield the subexpressions of this instruction."""

    @property
    def definitions(self) -> List[Variable]:
        """Return a list of defined variables."""
        return []

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Instruction."""
        raise NotImplementedError(f"accept not implemented for {type(self)}")


class Comment(Instruction):
    """Class for representing comments."""

    STYLES = {
        "C": ("/*", "*/"),
        "html": ("todo", "todo"),
        "debug": ("##", "##"),
    }
    DEFAULT_STYLE = "C"

    def __init__(self, comment: str, comment_style: str = "C", tags: Optional[Tuple[Tag, ...]] = None):
        """Initialize a new comment

        :parameter comment -- str containing commen without delimiters.
        :parameter comment_style -- str for selecting code style delimiters.
        """
        super().__init__(tags)
        self._comment = comment
        self._comment_style = comment_style
        self._open_comment, self._close_comment = self.STYLES.get(comment_style, self.STYLES[self.DEFAULT_STYLE])

    def __repr__(self) -> str:
        """Return representation of comment."""
        return f"{self._open_comment} {self._comment} {self._close_comment}"

    def __str__(self) -> str:
        """Return string representation of comment."""
        return f"{self._open_comment} {self._comment} {self._close_comment}"

    def __iter__(self) -> Iterator[Expression]:
        """Return empty iterator."""
        return
        yield

    @property
    def complexity(self) -> int:
        """Return 0, since comment should not add complexity."""
        return 0

    @property
    def requirements(self) -> List["Variable"]:
        """Return [] since comment has no requirements."""
        return []

    def copy(self) -> Comment:
        """Return a Comment with same str parameters."""
        return Comment(self._comment, self._comment_style, self.tags)

    def substitute(self, replacee: "Expression", replacement: "Expression") -> None:
        """not implemented"""
        pass

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Instruction."""
        return visitor.visit_comment(self)


class BaseAssignment(Instruction, ABC, Generic[E, F]):
    """Baseclass for Assignments an Relations."""

    def __init__(self, destination: E, value: F, tags: Optional[Tuple[Tag, ...]] = None):
        """Initialize a new assignment operation."""
        super().__init__(tags)
        self._destination = destination
        self._value = value

    def __iter__(self) -> Iterator[Expression]:
        """Yield all subexpressions of the given Assignment."""
        yield self._destination
        yield self._value

    @property
    def complexity(self) -> int:
        return self.value.complexity + self.destination.complexity

    @property
    def definitions(self) -> List[Variable]:
        """Return variables defined by instruction. Call can define more than one variable.
        In case contraction on the left side, its operand is being defined"""
        if isinstance(self._destination, Variable):
            return [self._destination]
        elif isinstance(self._destination, ListOperation) or self._is_contraction(self._destination):
            return self._destination.requirements
        return []

    @property
    def destination(self) -> E:
        """Return the left-hand-side expression."""
        return self._destination

    @property
    def value(self) -> F:
        """Return the right-hand-side expression."""
        return self._value

    @property
    def requirements(self) -> List[Variable]:
        """Return the values necessary for evaluation."""
        if (
            isinstance(self._destination, Variable)
            or isinstance(self._destination, ListOperation)
            or self._is_contraction(self._destination)
        ):
            return self._value.requirements
        return self._destination.requirements + self._value.requirements

    @property
    def writes_memory(self) -> Optional[int]:
        """Return the memory version generated by this assignment, if any."""
        if isinstance(self.value, Call):
            return self.value.writes_memory
        if isinstance(self.destination, UnaryOperation) and self.destination.operation == OperationType.dereference:
            return self.destination.writes_memory
        for variable in self.definitions:
            if variable.is_aliased:
                return variable.ssa_label
        return None


class Assignment(BaseAssignment[Expression, Expression]):
    """Base class for all instructions yielding a result."""

    def __init__(self, destination: Expression, value: Expression, tags: Optional[Tuple[Tag, ...]] = None):
        """Init a new Assignment."""
        super(Assignment, self).__init__(destination, value, tags=tags)

    def __str__(self) -> str:
        """Return a string representation starting with the lhs."""
        if isinstance(self._destination, ListOperation) and not self._destination.operands:
            # call assignments, e.g [] = print("something")
            # we want to print than call only
            return f"{self._value}"
        return f"{self.destination} = {self.value}"

    def __repr__(self) -> str:
        return f"{repr(self._destination)} = {repr(self._value)}"

    def substitute(self, replacee: Expression, replacement: Expression) -> None:
        """Substitutes expressions participating in the assignment with the given replacement expressions"""
        if self._value == replacee:
            self._value = replacement
        else:
            self.value.substitute(replacee, replacement)
        if self._destination == replacee:
            self._destination = replacement
        else:
            self.destination.substitute(replacee, replacement)

    def rename_destination(self, replacee: Variable, replacement: Variable):
        """Substitutes Variables participating on the left-hand-side of an assignment."""
        if isinstance(self.destination, Variable) and self._destination == replacee:
            self._destination = replacement
        elif isinstance(self.destination, ListOperation):
            self.destination.substitute(replacee, replacement)

    def copy(self) -> Assignment:
        """Generate a copy of the assignment, copying both left and right hand side."""
        return Assignment(self._destination.copy(), self._value.copy(), self.tags)

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Instruction."""
        return visitor.visit_assignment(self)

    @staticmethod
    def _is_contraction(expression: E) -> bool:
        """Tests if the given expression is contraction"""
        return isinstance(expression, UnaryOperation) and expression.operation == OperationType.cast and expression.contraction


class Relation(BaseAssignment[Variable, Variable]):
    """Class for aliased assignments that do not have the same value."""

    def __init__(self, destination: Variable, value: Variable, tags: Optional[Tuple[Tag, ...]] = None):
        """Init a new Relation."""
        super(Relation, self).__init__(destination, value, tags=tags)

    def __str__(self) -> str:
        """Return a string representation starting with the lhs."""
        return f"{self.destination} -> {self.value}"

    def __repr__(self) -> str:
        return f"{repr(self._destination)} -> {repr(self._value)}"

    def substitute(self, replacee: Expression, replacement: Expression) -> None:
        """Substitutes expressions participating in the assignment with the given replacement expressions"""
        if isinstance(replacement, Variable) and self._value == replacee and replacement.name == self.value.name:
            self._value = replacement

    def rename(self, replacee: Variable, replacement: Variable):
        """Substitutes Variables participating on the left-hand-side of an assignment."""
        if self._destination == replacee:
            self._destination = replacement
        if self._value == replacee:
            self._value = replacement

    def copy(self) -> Relation:
        """Generate a copy of the assignment, copying both left and right hand side."""
        return Relation(self._destination.copy(), self._value.copy(), self.tags)

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Instruction."""
        pass


class GenericBranch(Instruction, ABC, Generic[E]):
    """Super class for both direct and indirect branch classes"""

    def __init__(self, condition: E, tags: Optional[Tuple[Tag, ...]] = None):
        """Init a new branch instruction."""
        super().__init__(tags)
        self._condition = condition

    @abstractmethod
    def __repr__(self) -> str:
        """Return a debug representation of a branch"""

    def __iter__(self) -> Iterator[E]:
        yield self.condition

    @property
    def complexity(self) -> int:
        """Return the complexity of condition"""
        return self.condition.complexity

    @property
    def requirements(self) -> List[Variable]:
        """Return the conditions dependencies."""
        return self.condition.requirements

    def substitute(self, replacee: Expression, replacement: Expression) -> None:
        """Substitutes condition directly (in case of condition is a variable)
        or recursively if condition is an operation

        -> If self is a Branch, where the Branch condition checks whether the replacee expression is zero or not zero, and the replacement
           expression is a BinaryCondition that compares two expressions, then we replace the Branch condition by (not) replacement.
        """
        if self._condition == replacee:
            self._condition = replacement
        else:
            self._condition.substitute(replacee, replacement)

        if (
            isinstance(self.condition, Condition)
            and self.condition.operation in {OperationType.equal, OperationType.not_equal}
            and any(
                isinstance(new_cond := op, BinaryOperation) and new_cond.operation in Condition.NEGATIONS for op in self.condition.operands
            )
            and any(isinstance(op, Constant) and op.value == 0 for op in self.condition.operands)
        ):
            assert isinstance(new_cond, BinaryOperation)
            if self.condition.operation == OperationType.not_equal:
                self._condition = Condition(new_cond.operation, new_cond.operands, new_cond.type)
            else:
                self._condition = Condition(new_cond.operation, new_cond.operands, new_cond.type).negate()

    @property
    def condition(self) -> E:
        """Return the condition deciding upon the control flow in this Branch."""
        return self._condition

    def copy(self) -> GenericBranch[E]:
        """Copy the branch by generating a new object with a copy of the condition."""
        return self.__class__(self._condition.copy(), self.tags)

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Instruction."""
        return visitor.visit_generic_branch(self)


class Branch(GenericBranch[Condition]):
    """Class representing conditional and unconditional jumps.

    :parameter self.condition - tested condition (e.g. a < b, a != 0, ..)
    """

    def __init__(self, condition: Condition, tags: Optional[Tuple[Tag, ...]] = None):
        """Init a new branch instruction."""
        super(Branch, self).__init__(condition, tags=tags)

    def __repr__(self) -> str:
        """Return a debug representation of a branch"""
        return f"if {repr(self.condition)}"

    def __str__(self) -> str:
        """Return a string representation of a branch.

        conditions constant-, variable- or call-conditions should be surrounded by braces
        """
        return f"if({self.condition})"


class IndirectBranch(GenericBranch[Expression]):
    """Class representing a dynamic branch based on the value of a given variable."""

    def __init__(self, condition: Expression, tags: Optional[Tuple[Tag, ...]] = None):
        """Init a new branch instruction."""
        super(IndirectBranch, self).__init__(condition, tags=tags)

    def __repr__(self) -> str:
        """Return a debug representation of a branch"""
        return f"jmp {repr(self.condition)}"

    def __str__(self) -> str:
        """Return a short string representation."""
        return f"jmp {self.condition}"

    @property
    def expression(self) -> Expression:
        """Return the expression being utilized as an address operand."""
        return self.condition


class Return(Instruction):
    """Class representing a RET instruction."""

    def __init__(self, values, tags: Optional[Tuple[Tag, ...]] = None):
        """Create a new return instruction."""
        super().__init__(tags)
        self._values = ListOperation(values)

    def __repr__(self) -> str:
        return f"return {repr(self._values)}"

    def __str__(self):
        """Return a string representation similar to binaryninja's."""
        return f"return {self._values}"

    def __iter__(self) -> Iterator[Expression]:
        """Yield all returned instructions."""
        yield from self._values

    @property
    def complexity(self) -> int:
        """Returns sum of complexities of all returned values"""
        return self._values.complexity

    @property
    def requirements(self) -> List[Variable]:
        """All returned values are required by the return statement."""
        return self._values.requirements

    @property
    def values(self) -> ListOperation:
        """Return a list of all values returned."""
        return self._values

    def substitute(self, replacee: Expression, replacement: Expression) -> None:
        """Replaces recursively in returned values"""
        self._values.substitute(replacee, replacement)

    def copy(self) -> Return:
        """Generate a copy of the return instruction."""
        return Return(self._values.copy(), self.tags)

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Instruction."""
        return visitor.visit_return(self)


class Break(Instruction):
    def __iter__(self) -> Iterator[Expression]:
        yield from ()

    def __str__(self) -> str:
        return "break"

    @property
    def complexity(self) -> int:
        return 0

    @property
    def requirements(self) -> List[Variable]:
        return []

    @final
    def copy(self) -> Break:
        return Break()

    def substitute(self, replacee: Expression, replacement: Expression) -> None:
        return

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        return visitor.visit_break(self)


class Continue(Instruction):
    def __iter__(self) -> Iterator[Expression]:
        yield from ()

    def __str__(self) -> str:
        return "continue"

    @property
    def complexity(self) -> int:
        return 0

    @property
    def requirements(self) -> List[Variable]:
        return []

    @final
    def copy(self) -> Continue:
        return Continue()

    def substitute(self, replacee: Expression, replacement: Expression) -> None:
        return

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        return visitor.visit_continue(self)


class Phi(Assignment):
    """Base class representing Phi instructions in ssa-form."""

    def __init__(
        self,
        destination: Variable,
        value: Sequence[Union[Constant, Variable]],
        origin_block: Optional[Dict[Any, Optional[Union[Variable, Constant]]]] = None,
        tags: Optional[Tuple[Tag, ...]] = None,
    ):
        """
        :parameter self._origin_block:
        A dict that has as key the predecessor block of the current phi-function and as value the variable
        that is live at this block or the constant that comes over this block.
        Key should be type BasicBlock, but then we have a circular dependency
        """
        self._origin_block = origin_block if origin_block else {}
        super().__init__(destination, ListOperation(value), tags=tags)

    def __repr__(self):
        return f"{repr(self.destination)} = ϕ({repr(self.value)})"

    def __str__(self):
        """Return a string representation of the phi statement."""
        return f"{self.destination} = ϕ({self.value})"

    @property
    def origin_block(self) -> Dict[Any, Optional[Union[Variable, Constant]]]:
        return self._origin_block

    def substitute(self, replacee: Expression, replacement: Expression):
        self._value.substitute(replacee, replacement)
        self.__update_origin_block_on_replacement(replacee, replacement)
        if self.destination == replacee:
            self._destination = replacement

    def update_phi_function(self, variable_of_block: Dict[Any, Optional[Union[Variable, Constant]]]):
        """Initializes self._origin_block dict

        we do not add to origin_block varibles that are not contained in phi-function
        """
        phi_variables = set(self.value.operands)
        for node, variable in variable_of_block.items():
            if variable in phi_variables:
                self._origin_block[node] = variable
            else:
                logging.error(f"Variable or Constant {variable} is not an argument of the Phi function {self}.")

    def remove_from_origin_block(self, vertex):
        """
        Remove Vertex from origin_block
        :param vertex - Vertex:
        """
        if self._origin_block.get(vertex) is not None:
            del self._origin_block[vertex]
        else:
            logging.error(f"Block {vertex} is not a key in Phi.origin_block {self}.")

    def copy(self) -> Phi:
        """Copy the current Phi instruction."""
        return Phi(self._destination.copy(), [x.copy() for x in self._value.operands], self._origin_block.copy(), self.tags)

    def __update_origin_block_on_replacement(self, replacee, replacement):
        for node, expression in self._origin_block.items():
            if expression == replacee:
                self._origin_block[node] = replacement

    def accept(self, visitor: DataflowObjectVisitorInterface[T]) -> T:
        """Invoke the appropriate visitor for this Instruction."""
        return visitor.visit_phi(self)


class MemPhi(Phi):
    """Wrapper class to store information extracted from binja's mem_phi"""

    def __init__(self, destination_var: Variable, source_vars: Sequence[Variable], tags: Optional[Tuple[Tag, ...]] = None):
        super().__init__(destination_var, source_vars, tags=tags)

    def __str__(self) -> str:
        return f"{self.destination} = ϕ({self.value})"

    def __iter__(self) -> Iterator[Expression]:
        """Iterate all subexpressions of the MemPhi expression."""
        yield self._destination
        yield from self._value

    def copy(self) -> MemPhi:
        """Copy the current MemPhi instruction."""
        return MemPhi(self._destination.copy(), [operand.copy() for operand in self.value], self.tags)

    def create_phi_functions_for_variables(self, variables: Set[Variable]) -> List[Phi]:
        """Creates a phi function for each variable using ssa-labels of mem-phi function"""
        return [self._generate_phi_function_for_variable(var) for var in variables]

    def substitute(self, replacee: "Expression", replacement: "Expression") -> None:
        """We do not want substitute capabilities for MemPhi, since we remove it while preprocessing."""
        pass

    def _generate_phi_function_for_variable(self, var: Variable) -> Phi:
        """Given a variable, creates a Phi-Function for it using ssa versions of mem variables"""
        phi_target = var.copy(ssa_label=self.destination.ssa_label, is_aliased=True)
        phi_arguments = []
        for variable in self.value.operands:
            phi_arg = var.copy(ssa_label=variable.ssa_label, is_aliased=True)
            phi_arguments.append(phi_arg)
        return Phi(phi_target, phi_arguments)
