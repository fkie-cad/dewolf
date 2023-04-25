from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Dict, Iterable, List, Literal, Optional, Tuple, TypeVar, Union

from decompiler.structures.ast.condition_symbol import ConditionHandler
from decompiler.structures.ast.reachability_graph import CaseDependencyGraph, SiblingReachability
from decompiler.structures.graphs.interface import GraphNodeInterface
from decompiler.structures.logic.logic_condition import LogicCondition, PseudoLogicCondition
from decompiler.structures.pseudo import Assignment, Break, Condition, Constant, Continue, Expression, Instruction, Return, Variable

if TYPE_CHECKING:
    from decompiler.structures.ast.syntaxgraph import AbstractSyntaxInterface
    from decompiler.structures.visitors.interfaces import ASTVisitorInterface

T = TypeVar("T")


class LoopType(Enum):
    While = "while"
    DoWhile = "do_while"
    For = "for"


class BaseAbstractSyntaxTreeNode(GraphNodeInterface, ABC):
    """
    BaseClass for all AbstractSyntaxTree nodes.
    They all have the following attributes:

    self.reaching_condition: a z3-formula that tells us when we reach this AST node
    self._ast the AbstractSyntaxGraph the AST node is contained in.
    """

    def __init__(self, reaching_condition: LogicCondition, ast: Optional[AbstractSyntaxInterface] = None):
        """
        Init a new AbstractSyntaxTreeNode with a reaching condition and the ast it is contained in.

        Note, the reaching_condition of each node in a syntax tree is True.
        """
        self.reaching_condition: LogicCondition = reaching_condition
        self._ast: AbstractSyntaxInterface = ast

    def __eq__(self, other) -> bool:
        """Compare two AST nodes based on their type and reaching condition."""
        if other is None:
            return False
        return isinstance(other, type(self)) and self.reaching_condition.is_equal_to(other.reaching_condition)

    def __hash__(self) -> int:
        """
        AST nodes should hash the same even then in different graphs and should not change when node properties change,
        so we use their addresses.
        """
        return id(self)

    @abstractmethod
    def __str__(self) -> str:
        """Return a string representation of the ast node."""

    @abstractmethod
    def __repr__(self) -> str:
        """Return a debug representation of the ast node."""

    @property
    def children(self) -> Tuple[AbstractSyntaxTreeNode, ...]:
        """Returns the children of the AST-node."""
        return self._ast.children(self)

    @property
    def parent(self) -> Optional[AbstractSyntaxTreeNode]:
        """Returns the unique parent of the AST-node if it exist."""
        return self._ast.parent(self)

    @abstractmethod
    def accept(self, visitor: ASTVisitorInterface[T]) -> T:
        """Accept method"""


class AbstractSyntaxTreeNode(BaseAbstractSyntaxTreeNode, ABC):
    """BaseClass for all specified AbstractSyntaxTree nodes."""

    @property
    def is_empty(self) -> bool:
        """
        Check whether the subtree at this root is empty.

        - LoopNodes and CaseNodes are never empty because a loop with empty body and a case node without a child are still
          relevant for the program flow
        - CodeNodes are empty if their list of instructions is empty.
        """
        return not self.children or all(child.is_empty for child in self.children)

    @property
    def is_loop_with_empty_body(self) -> bool:
        """Checks whether the given ast-root is a LoopNode with an empty Body."""
        return isinstance(self, LoopNode) and (self.body is None or self.body.is_empty)

    @property
    def is_endless_loop(self) -> bool:
        """Checks whether the given node is an endless loop"""
        return isinstance(self, LoopNode) and self.is_endless

    @property
    def is_empty_code_node(self) -> bool:
        """Checks whether the given node is an empty CodeNode"""
        return isinstance(self, CodeNode) and self.is_empty

    @property
    def is_break_node(self) -> bool:
        """Checks whether the input AST node is a break node, i.e., a code node that has only a Break statement."""
        return isinstance(self, CodeNode) and self.instructions == [Break()]

    @property
    def does_end_with_break(self) -> bool:
        """Checks whether the node ends with a break."""
        return all(end_node.does_end_with_break for end_node in self.get_end_nodes())

    @property
    def does_contain_break(self) -> bool:
        """Checks whether any descendant CodeNode contains a break."""
        return any(code_node.does_end_with_break for code_node in self.get_descendant_code_nodes())

    @property
    def is_break_condition(self) -> bool:
        """Checks that the node is a Condition node with one branch that is a break node."""
        if not isinstance(self, ConditionNode):
            return False
        self.clean()
        return self.false_branch is None and self.true_branch.child.is_break_node

    @property
    def is_code_node_ending_with_break(self) -> bool:
        """Checks whether the node is a CodeNode and ends with a break."""
        return isinstance(self, CodeNode) and self.does_end_with_break

    @property
    def does_end_with_continue(self) -> bool:
        """Checks whether the branch ends with a continue."""
        return all(end_node.does_end_with_continue for end_node in self.get_end_nodes())

    @property
    def is_code_node_ending_with_continue(self) -> bool:
        """Checks whether the node is a CodeNode and ends with a continue."""
        return isinstance(self, CodeNode) and self.does_end_with_continue

    @property
    def does_end_with_return(self) -> bool:
        """Checks whether the branch ends with a return."""
        return all(end_node.does_end_with_return for end_node in self.get_end_nodes())

    @property
    def is_code_node_ending_with_return(self) -> bool:
        """Checks whether the node is a CodeNode and ends with a return."""
        return isinstance(self, CodeNode) and self.does_end_with_return

    def get_end_nodes(self) -> Iterable[Union[CodeNode, SwitchNode, LoopNode, ConditionNode]]:
        """Yields all nodes where the subtree can terminate."""
        for child in self.children:
            yield from child.get_end_nodes()

    def clean(self) -> None:
        """Makes clean ups, depending on the node. This helps to standardize the AST."""
        pass

    def simplify_reaching_condition(self, condition_handler: ConditionHandler):
        """Simplify the reaching condition. If it is false we remove the subtree of this node."""
        if not self.reaching_condition.is_true:
            self.reaching_condition.remove_redundancy(condition_handler)
        if self.reaching_condition.is_false:
            logging.warning(f"The CFG node {self} has reaching condition false, therefore, we remove it.")
            self._ast.remove_subtree(self)

    def replace_variable(self, replacee: Variable, replacement: Variable) -> None:
        """Replaces each occurrence of the given variable replacee by the variable replacement in the given AST-node."""
        pass

    def get_possible_case_candidate_condition(self) -> Optional[LogicCondition]:
        """Returns the reaching condition of a node if it is a possible case node of a switch node."""
        # if not self.reaching_condition.is_true and not self.does_end_with_break:
        if not self.reaching_condition.is_true and not any(
            code_node.does_end_with_break for code_node in self.get_descendant_code_nodes_interrupting_ancestor_loop()
        ):
            return self.reaching_condition
        return None

    def get_descendant_code_nodes(self) -> Iterable[CodeNode]:
        """Returns all code nodes that are descendants of the given node"""
        yield from self._ast.get_code_nodes_post_order(self)

    def get_reachable_code_nodes(self) -> Iterable[CodeNode]:
        """Return all code nodes that are reachable from this node."""
        return self._ast.reachable_code_nodes(self)

    def get_descendant_code_nodes_interrupting_ancestor_loop(self) -> Iterable[CodeNode]:
        for child in self.children:
            yield from child.get_descendant_code_nodes_interrupting_ancestor_loop()

    def get_required_variables(self, condition_map: Optional[Dict[LogicCondition, Condition]] = None) -> Iterable[Variable]:
        """Return all variables that are required in this node."""
        yield from ()

    def get_defined_variables(self, condition_map: Optional[Dict[LogicCondition, Condition]] = None) -> Iterable[Variable]:
        """Return all variables that are defined in this node."""
        yield from ()


class VirtualRootNode(AbstractSyntaxTreeNode):
    """
    A node that is always the root and can be used to point to the root of an AST or the root of the current tree of an abstract forest.
    """

    def __str__(self) -> str:
        """Return a string representation of a RootNode."""
        return "Root"

    def __repr__(self) -> str:
        """Return a debug representation of the ast node."""
        return f"Root({self.reaching_condition})"

    @property
    def children(self) -> Tuple[AbstractSyntaxTreeNode, ...]:
        """Returns the possible child of the node in a List."""
        children = super().children
        assert len(children) <= 1, "A RootNode only one child!"
        return children

    @property
    def child(self) -> AbstractSyntaxTreeNode:
        """Returns the child or None if it does not exist."""
        return self.children[0] if self.children else None

    @property
    def parent(self) -> None:
        """Returns None, because a RootNode has no parent."""
        assert self._ast.parent(self) is None, "A root nodes can not have a parent!"
        return None

    @property
    def is_empty(self) -> bool:
        """The root node is never empty by assumption, because we never want to delete it."""
        return False

    def copy(self) -> VirtualRootNode:
        """Return a copy of the ast node."""
        return VirtualRootNode(self.reaching_condition)

    def accept(self, visitor: ASTVisitorInterface[T]) -> T:
        return visitor.visit_root_node(self)


class SeqNode(AbstractSyntaxTreeNode):
    """
    A sequence node additionally has the attribute self._sorted_nodes, which is a list of all successors of the sequence node in the
    Abstract Syntax Tree. They are ordered in a topological order wrt. the Control Flow Graph nodes they contain as leaves.
    """

    def __init__(self, reaching_condition: LogicCondition, ast: Optional[AbstractSyntaxInterface] = None):
        """Init a new SequenceNode with a reaching condition and the ast it is contained in."""
        super().__init__(reaching_condition, ast)
        self._sorted_children: Tuple[AbstractSyntaxTreeNode, ...] = tuple()

    def __str__(self) -> str:
        """Return a string representation of a SeqNode."""
        return "Sequence"

    def __repr__(self) -> str:
        """Return a debug representation of the ast node."""
        return f"Sequence({self.reaching_condition})\n {len(self._sorted_children)}"

    def copy(self) -> SeqNode:
        """Return a copy of the ast node."""
        return SeqNode(self.reaching_condition)

    @property
    def children(self) -> Tuple[AbstractSyntaxTreeNode, ...]:
        """Return a tuple of all successors in execution order."""
        if not (children := super().children):
            return children
        if set(self._sorted_children) != set(children):
            logging.debug("The sorted tuple of children differs from the actual list of children, so we have to sort them!")
            self.sort_children()
        return self._sorted_children

    def sort_children(self) -> None:
        """Sorts the successors of the sequence node in execution order."""
        reachability_of_children: SiblingReachability = self.get_reachability_of_children()
        sorted_children = reachability_of_children.sorted_nodes()
        if sorted_children is None:
            raise ValueError(f"The children of {self} can not be sorted due to circular reachability")
        self._sorted_children = sorted_children

    def get_end_nodes(self) -> Iterable[Union[CodeNode, SwitchNode, LoopNode, ConditionNode]]:
        """The end-node of the sequence node is the end-node of the last node in the sequence."""
        if children := self.children:
            yield from children[-1].get_end_nodes()

    def clean(self) -> None:
        """
        Standardization for Sequence-Node is to remove a seq-node that only have one child and
        to flatten it if a child is also a sequence node.
        """
        super().clean()
        if len(children := self.children) == 1:
            child = children[0]
            child.reaching_condition &= self.reaching_condition
            self._ast.replace_seq_node_by_single_child(self)
        else:
            self._ast.flatten_sequence_node(self)

    def get_reachability_of_children(self) -> SiblingReachability:
        """Return the sibling reachability of the children of the seq node."""
        return self._ast.get_sibling_reachability_of_children_of(self)

    def get_break_nodes(self) -> Iterable[Union[CodeNode, ConditionNode]]:
        """
        Return all break-node children of the sequence node

        - Code-Nodes containing only a break statement
        - Condition-Nodes having one branch that is a code-node with only a break-statement
        """
        for child in self.children:
            if child.is_break_node or child.is_break_condition:
                yield child

    def accept(self, visitor: ASTVisitorInterface[T]) -> T:
        return visitor.visit_seq_node(self)


class CodeNode(AbstractSyntaxTreeNode):
    """
    A code node additionally has the attributes
        - self.stmts, is the list of Instructions of this node.
    """

    def __init__(self, stmts: List[Instruction], reaching_condition: LogicCondition, ast: Optional[AbstractSyntaxInterface] = None):
        """Init a new CodeNode with a list of instructions, a reaching condition and the ast it is contained in."""
        super().__init__(reaching_condition, ast)
        self.instructions = stmts

    def __hash__(self) -> int:
        """
        AST nodes should hash the same even then in different graphs and should not change when node properties change,
        so we use their addresses.
        """
        return super().__hash__()

    def __eq__(self, other) -> bool:
        """Compare two AST nodes based on their type, reaching condition and statements."""
        return super().__eq__(other) and other.instructions == self.instructions

    def __str__(self) -> str:
        """Return a string representation of a CodeNode."""
        return "\n".join([str(x) for x in self.instructions])

    def __repr__(self) -> str:
        """Return a debug representation of the ast node."""
        return f"Code({self.reaching_condition})\n{str(self)}"

    def copy(self) -> CodeNode:
        """Return a copy of the ast node."""
        return CodeNode(self.instructions.copy(), self.reaching_condition)

    @property
    def children(self) -> Tuple[AbstractSyntaxTreeNode, ...]:
        """A code node has no successors, so we return an empty tuple."""
        assert super().children == (), f"A code node has no children!"
        return ()

    @property
    def is_empty(self) -> bool:
        """A code node is empty if it contains no statements."""
        return not self.instructions

    @property
    def does_end_with_break(self) -> bool:
        """A code node ends with break if the last instruction is a Break Instruction"""
        return len(self.instructions) > 0 and isinstance(self.instructions[-1], Break)

    @property
    def does_contain_break(self) -> bool:
        """Only the last instruction can be an interruption after clean."""
        self.clean()
        return self.does_end_with_break

    @property
    def does_end_with_continue(self) -> bool:
        """A code node ends with break if the last instruction is a Continue Instruction"""
        return len(self.instructions) > 0 and isinstance(self.instructions[-1], Continue)

    @property
    def does_end_with_return(self) -> bool:
        """Only the last instruction can be an interruption after clean."""
        return len(self.instructions) > 0 and isinstance(self.instructions[-1], Return)

    def get_end_nodes(self) -> Iterable[CodeNode]:
        """The end-node of a code node is the code node itself."""
        yield self

    def clean(self) -> None:
        """Standardizing a code node is to removes all instructions that come after an interruption, i.e. Break, Return or Continue."""
        super().clean()
        for idx, instruction in enumerate(self.instructions):
            if isinstance(instruction, (Break, Return, Continue)):
                self.instructions = self.instructions[: idx + 1]
                break

    def insert_instruction_before(self, insertion_instruction: Instruction, existing_instruction: Instruction):
        """
        Insert a single instruction before an existing instruction in this CodeNode.

        :param insertion_instruction: instruction to insert
        :param existing_instruction: instruction before which the insertion_instruction is inserted
        :raises ValueError: Raised if existing_instruction is not contained in the CodeNode
        """
        self.insert_instruction_list_before([insertion_instruction], existing_instruction)

    def insert_instruction_list_before(self, insertion_instructions: Iterable[Instruction], existing_instruction: Instruction):
        """
        Insert instructions before another instruction in this CodeNode.

        :param insertion_instructions: list of instructions to insert
        :param existing_instruction: instruction before which the insertion_instructions are inserted
        :raises ValueError: Raised if anchor_instruction is not contained in this CodeNode
        """
        for idx, instruction in enumerate(self.instructions):
            if id(instruction) == id(existing_instruction):
                self.instructions[idx:idx] = insertion_instructions
                return
        raise ValueError(f"instruction {existing_instruction} not contained in code node {self}")

    def replace_variable(self, replacee: Variable, replacement: Variable) -> None:
        """Replace each variable replacee by the variable replacement in all instructions."""
        for instruction in self.instructions:
            instruction.substitute(replacee, replacement)

    def accept(self, visitor: ASTVisitorInterface[T]) -> T:
        return visitor.visit_code_node(self)

    def get_descendant_code_nodes_interrupting_ancestor_loop(self) -> Iterable[CodeNode]:
        if self.does_end_with_break or self.does_end_with_continue:
            yield self

    def get_required_variables(self, condition_map: Optional[Dict[LogicCondition, Condition]] = None) -> Iterable[Variable]:
        for instruction in self.instructions:
            yield from instruction.requirements

    def get_defined_variables(self, condition_map: Optional[Dict[LogicCondition, Condition]] = None) -> Iterable[Variable]:
        for instruction in self.instructions:
            yield from instruction.definitions


class ConditionNode(AbstractSyntaxTreeNode):
    """
    A conditional node additionally has the attributes
        - self.condition, the z3-condition for the 'if' statement
        - self.true_branch, the AST node that is next, when the condition is true.
        - self.false_branch, the AST node that is next, when the condition is false.
    """

    def __init__(self, condition: LogicCondition, reaching_condition: LogicCondition, ast: Optional[AbstractSyntaxInterface] = None):
        """Init a new ConditionNode with a condition, a reaching condition and the ast it is contained in."""
        super().__init__(reaching_condition, ast)
        self.condition: LogicCondition = condition

    def __hash__(self) -> int:
        """
        AST nodes should hash the same even then in different graphs and should not change when node properties change,
        so we use their addresses.
        """
        return super().__hash__()

    def __eq__(self, other) -> bool:
        """Compare two AST nodes based on their type, reaching condition and condition."""
        return super().__eq__(other) and self.condition.is_equal_to(other.condition)

    def __str__(self) -> str:
        """Return a string representation of a ConditionNode."""
        return f"if ({str(self.condition)})"

    def __repr__(self) -> str:
        """Return a debug representation of the ast node."""
        return (
            f"ConditionNode({self.reaching_condition})\n{str(self)}\n"
            f"TrueNode({type(self.true_branch_child) if self.true_branch_child else None}\n"
            f"FalseNode({type(self.false_branch_child) if self.false_branch_child else None}))"
        )

    def copy(self) -> ConditionNode:
        """Return a copy of the ast node."""
        return ConditionNode(self.condition, self.reaching_condition)

    @property
    def children(self) -> Tuple[Union[TrueNode, FalseNode], ...]:
        """Returns the children of a condition node, which can only be TrueNodes and FalseNodes."""
        children = super().children
        assert all(isinstance(c, (TrueNode, FalseNode)) for c in children), "A condition node has only True- and FalseNode children!"
        return children

    @property
    def true_branch(self) -> Optional[TrueNode]:
        """Return the true-branch of the condition node."""
        true_nodes = [child for child in self.children if isinstance(child, TrueNode)]
        assert len(true_nodes) < 2, f"A condition node can not have more than one True Branch"
        return true_nodes[0] if true_nodes else None

    @property
    def false_branch(self) -> Optional[FalseNode]:
        """Return the false branch of a condition node."""
        false_nodes = [child for child in self.children if isinstance(child, FalseNode)]
        assert len(false_nodes) < 2, f"A condition node can not have more than one False Branch"
        return false_nodes[0] if false_nodes else None

    @property
    def true_branch_child(self) -> Optional[AbstractSyntaxTreeNode]:
        """Return the child of the true-branch"""
        return self.true_branch.child if self.true_branch else None

    @property
    def false_branch_child(self) -> Optional[AbstractSyntaxTreeNode]:
        """Return the child of the false-branch"""
        return self.false_branch.child if self.false_branch else None

    def get_end_nodes(self) -> Iterable[Union[CodeNode, SwitchNode, LoopNode, ConditionNode]]:
        """A Condition node with only one branch is an end-node, otherwise we return the end-nodes of each branch."""
        if self.true_branch_child is not None and self.false_branch_child is not None:
            yield from super().get_end_nodes()
        else:
            yield self

    @property
    def does_end_with_break(self) -> bool:
        """Checks whether the node ends with a break."""
        if self.true_branch_child is not None and self.false_branch_child is not None:
            return super().does_end_with_break
        return False

    @property
    def does_end_with_continue(self) -> bool:
        """Check whether the node ends with a continue."""
        if self.true_branch_child is not None and self.false_branch_child is not None:
            return super().does_end_with_continue
        return False

    @property
    def does_end_with_return(self) -> bool:
        """Check whether the node ends with a return."""
        if self.true_branch_child is not None and self.false_branch_child is not None:
            return super().does_end_with_return
        return False

    def get_possible_case_candidate_condition(self) -> Optional[LogicCondition]:
        """Returns the reaching condition of a node if it is a possible case node of a switch node."""
        self.clean()
        if self.false_branch is None and not any(
            code_node.does_end_with_break for code_node in self.get_descendant_code_nodes_interrupting_ancestor_loop()
        ):
            return self.reaching_condition & self.condition
        return None

    def simplify_reaching_condition(self, condition_handler: ConditionHandler):
        """
        Add the reaching condition to the condition of the condition node if the false-branch does not exist. Otherwise, only simplify it.
        """
        self.clean()
        if self.false_branch is None and not self.reaching_condition.is_true:
            self.condition &= self.reaching_condition
            self.condition.remove_redundancy(condition_handler)
            self.reaching_condition = LogicCondition.initialize_true(self.reaching_condition.context)
        super().simplify_reaching_condition(condition_handler)

    def switch_branches(self):
        """Switch the true-branch and false-branch, this includes negating the condition."""
        self._ast.switch_branches(self)

    def clean(self) -> None:
        """Standardizing a Condition node is to remove empty True/False Branches and to make sure that the true branch always exists."""
        for dead_child in (child for child in self.children if child.child is None):
            self._ast.remove_subtree(dead_child)
        if len(self.children) == 1 and self.true_branch is None:
            self.switch_branches()
        super().clean()

    def replace_variable(self, replacee: Variable, replacement: Variable) -> None:
        """Replace the variable replacee by replacement in the condition."""
        self._ast.substitute_variable_in_condition(self.condition, replacee, replacement)

    def accept(self, visitor: ASTVisitorInterface[T]) -> T:
        return visitor.visit_condition_node(self)

    def get_required_variables(self, condition_map: Optional[Dict[LogicCondition, Condition]] = None) -> Iterable[Variable]:
        if not condition_map:
            return
        for symbol in self.condition.get_symbols():
            if symbol not in condition_map:
                logging.warning("LogicCondition not in condition map.")
                continue
            yield from condition_map[symbol].requirements


class ConditionalNode(AbstractSyntaxTreeNode, ABC):
    """Abstract Base class for nodes with one child, i.e. TrueNodes, FalseNodes and CaseNodes."""

    @property
    def children(self) -> Tuple[AbstractSyntaxTreeNode, ...]:
        """A conditional node has at most one child which we return in a tuple."""
        children = super().children
        assert len(children) <= 1, "A TrueNode, FalseNode and CaseNode have only one child!"
        return children

    @property
    def child(self) -> Optional[AbstractSyntaxTreeNode]:
        """Returns the one possible child of the conditional node."""
        return self.children[0] if self.children else None


class TrueNode(ConditionalNode):
    """A node representing the true-branch of a condition node."""

    def __str__(self) -> str:
        """Return a string representation of a TrueNode."""
        return "TrueNode"

    def __repr__(self) -> str:
        """Return a debug representation of the ast node."""
        return f"TrueNode({self.reaching_condition})\n{type(self.child) if self.child else ''}"

    def copy(self) -> TrueNode:
        """Return a copy of the ast node."""
        return TrueNode(self.reaching_condition)

    @property
    def branch_condition(self) -> LogicCondition:
        """Returns the condition of the branch."""
        assert isinstance(self.parent, ConditionNode), "True and False Nodes must have a ConditionNode as parent!"
        return self.parent.condition

    def accept(self, visitor: ASTVisitorInterface[T]) -> T:
        return visitor.visit_true_node(self)


class FalseNode(ConditionalNode):
    """A node representing the false-branch of a condition node."""

    def __str__(self) -> str:
        """Return a string representation of a FalseNode."""
        return "FalseNode"

    def __repr__(self) -> str:
        """Return a debug representation of the ast node."""
        return f"FalseNode({self.reaching_condition})\n{type(self.child) if self.child else ''}"

    def copy(self) -> FalseNode:
        """Return a copy of the ast node."""
        return FalseNode(self.reaching_condition)

    @property
    def branch_condition(self) -> LogicCondition:
        """Returns the condition of the branch."""
        assert isinstance(self.parent, ConditionNode), "True and False Nodes must have a ConditionNode as parent!"
        return ~self.parent.condition

    def accept(self, visitor: ASTVisitorInterface[T]) -> T:
        return visitor.visit_false_node(self)


class LoopNode(AbstractSyntaxTreeNode, ABC):
    """
    A loop node additionally has the attributes
        - self.condition, the z3-condition for the 'loop' statement.
    """

    def __init__(self, condition: LogicCondition, reaching_condition: LogicCondition, ast: Optional[AbstractSyntaxInterface] = None):
        """Init a new LoopNode with a loop-condition, a reaching condition and the ast it is contained in."""
        super().__init__(reaching_condition, ast)
        self.condition: LogicCondition = condition

    def __hash__(self) -> int:
        """
        AST nodes should hash the same even then in different graphs and should not change when node properties change,
        so we use their addresses.
        """
        return super().__hash__()

    def __eq__(self, other) -> bool:
        """Compare two AST nodes based on their type, reaching condition and loop-condition."""
        return super().__eq__(other) and self.condition.is_equal_to(other.condition)

    def __str__(self) -> str:
        """Return a string representation of a LoopNode."""
        return f"{self.loop_type.value} ({str(self.condition)})"

    def __repr__(self) -> str:
        """Return a debug representation of the ast node."""
        return f"{self.loop_type}({self.reaching_condition})\n{self}\n Body:{type(self.body)}"

    @property
    def children(self) -> Tuple[AbstractSyntaxTreeNode, ...]:
        """Returns the loop-body wrapped in a tuple."""
        children = super().children
        assert len(children) <= 1, "A loop node has at most one child!"
        return children

    @property
    def body(self) -> Optional[AbstractSyntaxTreeNode]:
        """Return the body of the loop"""
        return self.children[0] if self.children else None

    @property
    @abstractmethod
    def loop_type(self) -> LoopType:
        """Return the type of the loop"""
        pass

    @property
    def is_endless(self) -> bool:
        """Check whether the loop is an endless loop"""
        return self.condition.is_true

    @property
    def is_empty(self) -> bool:
        """A loop is never empty because even a loop with empty body is not empty and influences the control flow."""
        return False

    @property
    def does_end_with_break(self) -> bool:
        """Since we never know whether we enter the loop it can not end with break."""
        return False

    @property
    def does_contain_break(self) -> bool:
        """Return False because a break-node could also belong to a nested loop-node."""
        return False

    @property
    def does_end_with_continue(self) -> bool:
        """Since we never know whether we enter the loop it can not end with continue."""
        return False

    @property
    def does_end_with_return(self) -> bool:
        """Since we never know whether we enter the loop it can not end with return."""
        return False

    def get_end_nodes(self) -> Iterable[LoopNode]:
        """A Loop node is an end-node"""
        yield self

    def replace_variable(self, replacee: Variable, replacement: Variable) -> None:
        """Replace the variable replacee by replacement in the loop-condition."""
        self._ast.substitute_variable_in_condition(self.condition, replacee, replacement)

    def accept(self, visitor: ASTVisitorInterface[T]) -> T:
        return visitor.visit_loop_node(self)

    def get_descendant_code_nodes_interrupting_ancestor_loop(self) -> Iterable[CodeNode]:
        yield from []

    def get_required_variables(self, condition_map: Optional[Dict[LogicCondition, Condition]] = None) -> Iterable[Variable]:
        if not condition_map:
            return
        for symbol in self.condition.get_symbols():
            if symbol not in condition_map:
                logging.warning("LogicCondition not in condition map.")
                continue
            yield from condition_map[symbol].requirements


class WhileLoopNode(LoopNode):
    """Class for While Loops."""

    def copy(self) -> WhileLoopNode:
        """Return a copy of the ast node."""
        return WhileLoopNode(self.condition, self.reaching_condition)

    @property
    def loop_type(self) -> LoopType:
        """Return the loop-type."""
        return LoopType.While

    def clean(self) -> None:
        """Standardizing a Loop node is to remove the condition from the body if it is already implied by the loop condition."""
        super().clean()
        body = self.body
        if not self.is_endless and isinstance(body, ConditionNode):
            body.clean()
            if self.condition.does_imply(body.true_branch.branch_condition):
                if body.false_branch:
                    self._ast.remove_subtree(body.false_branch)
                self._ast.replace_condition_node_by_single_branch(body)
            elif body.false_branch and self.condition.does_imply(body.false_branch.branch_condition):
                self._ast.remove_subtree(body.true_branch)
                self._ast.replace_condition_node_by_single_branch(body)


class DoWhileLoopNode(LoopNode):
    """Class for Do-While Loops."""

    def copy(self) -> DoWhileLoopNode:
        """Return a copy of the ast node."""
        return DoWhileLoopNode(self.condition, self.reaching_condition)

    @property
    def loop_type(self) -> LoopType:
        """Return the loop-type."""
        return LoopType.DoWhile


class ForLoopNode(LoopNode):
    """
    A for loop node has the additional attributes
        - self.declaration, the declaration of the loop variable.
        - self.modification, the statement that modifies the loop variable after each iteration.
    """

    def __init__(
        self,
        declaration: Optional[Union[Expression, Assignment]],
        condition: LogicCondition,
        modification: Optional[Assignment],
        reaching_condition: LogicCondition,
        ast: Optional[AbstractSyntaxInterface] = None,
    ):
        """Init a new ForLoopNode with a condition, modification, declaration, a reaching condition and the ast it is contained in."""
        super().__init__(condition, reaching_condition, ast)
        self.declaration = declaration
        self.modification = modification

    def __hash__(self) -> int:
        """
        AST nodes should hash the same even then in different graphs and should not change when node properties change,
        so we use their addresses.
        """
        return super().__hash__()

    def __eq__(self, other) -> bool:
        """Compare two AST nodes based on their type, reaching condition, loop-condition, declaration and modification."""
        return super().__eq__(other) and self.declaration == other.declaration and self.modification == other.modification

    def __str__(self) -> str:
        """Return a string representation of a ForLoopNode."""
        return f"{self.loop_type.value} ({self.declaration}; {str(self.condition)}; {self.modification})"

    def copy(self) -> ForLoopNode:
        """Return a copy of the ast node."""
        return ForLoopNode(self.declaration, self.condition, self.modification, self.reaching_condition)

    @property
    def loop_type(self) -> LoopType:
        """Return the loop type."""
        return LoopType.For

    def replace_variable(self, replacee: Variable, replacement: Variable) -> None:
        """Replace the variable replacee by replacement in the loop-condition, declaration and modification."""
        super().replace_variable(replacee, replacement)
        if self.declaration is not None:
            self.declaration.substitute(replacee, replacement)
        if self.modification is not None:
            self.modification.substitute(replacee, replacement)

    def get_required_variables(self, condition_map: Optional[Dict[LogicCondition, Condition]] = None) -> Iterable[Variable]:
        yield from self.declaration.requirements
        yield from self.modification.requirements
        if not condition_map:
            return
        for symbol in self.condition.get_symbols():
            yield from condition_map[symbol].requirements

    def get_defined_variables(self, condition_map: Optional[Dict[LogicCondition, Condition]] = None) -> Iterable[Variable]:
        if self.declaration and isinstance(self.declaration, Assignment):
            yield from self.declaration.definitions
        yield from self.modification.definitions


class SwitchNode(AbstractSyntaxTreeNode):
    """
    A switch node additionally has the attributes
        - self.expression, the switch expression that decides to which case we switch.
        - self._sorted_cases, a list of Abstract Syntax Tree nodes, one for each case.
    """

    def __init__(self, expression: Expression, reaching_condition: LogicCondition, ast: Optional[AbstractSyntaxInterface] = None):
        """Init a new SwitchNode with the switch expression, a reaching condition and the ast it is contained in."""
        super().__init__(reaching_condition, ast)
        self.expression = expression
        self._sorted_cases: Optional[Tuple[CaseNode]] = None

    def __hash__(self) -> int:
        """
        AST nodes should hash the same even then in different graphs and should not change when node properties change,
        so we use their addresses.
        """
        return super().__hash__()

    def __eq__(self, other) -> bool:
        """Compare two AST nodes based on their type, reaching condition and switch expression."""
        return super().__eq__(other) and self.expression == other.expression

    def __str__(self) -> str:
        """Return a string representation of a SwitchNode."""
        return f"switch ({self.expression})"

    def __repr__(self) -> str:
        """Return a debug representation of the ast node."""
        return f"SwitchNode({self.reaching_condition})\n{str(self)}\n{len(self._sorted_cases)}"

    def copy(self) -> SwitchNode:
        """Return a copy of the ast node."""
        return SwitchNode(self.expression, self.reaching_condition)

    @property
    def children(self) -> Tuple[CaseNode]:
        """Returns the successors of the switch node (case nodes) in execution order."""
        children = super().children
        assert all(isinstance(c, CaseNode) for c in children), "A switch node has only CaseNode children!"
        if self._sorted_cases is None:
            return children
        if set(children) != set(self._sorted_cases):
            logging.debug("The sorted cases are not the same as the children!")
            self.sort_cases()
        return self._sorted_cases

    @property
    def default(self) -> Optional[CaseNode]:
        """Return the default-case if it exists."""
        for child in super().children:
            if child.constant == "default":
                return child
        return None

    @property
    def cases(self) -> Tuple[CaseNode, ...]:
        """Return all case nodes that are not the default node in order."""
        return tuple(child for child in self.children if child.constant != "default")

    @property
    def does_end_with_break(self) -> bool:
        """When construction switch nodes we make sure that they do not contain a break-statement."""
        return False

    @property
    def does_contain_break(self) -> bool:
        """When construction switch nodes we make sure that they do not contain a break-statement."""
        return False

    @property
    def does_end_with_continue(self) -> bool:
        """Since we never know whether we enter the loop it can not end with continue."""
        return False

    @property
    def does_end_with_return(self) -> bool:
        """Since we never know whether we enter the loop it can not end with return."""
        return False

    def sort_cases(self):
        """
        Order the switch cases according to their constant (if possible) and prepend breaks to the cases that do not reach any other case.

        1. Pick Case nodes, where a linear order starts, and whose constant is minimum among the not picked case nodes with this property.
        2. Append break to last node of this order, if it does not end with a return or continue statement.
        """
        default_node = self.default
        case_nodes = tuple(case for case in super().children if case != default_node)
        case_dependency_graph = CaseDependencyGraph(self._ast.get_sibling_reachability_for(case_nodes))
        linear_ordering_starting_at: Dict[CaseNode, List[CaseNode]] = dict(case_dependency_graph.find_partial_order_of_cases())
        sorted_cases = list()
        for case_node in sorted(linear_ordering_starting_at.keys(), key=lambda node: node.constant.value):
            if case_dependency_graph.in_degree(case_node) > 0:
                raise ValueError(f"Every case node, where a order starts, should have in-degree zero.")

            sorted_cases += linear_ordering_starting_at[case_node]
            last_node = linear_ordering_starting_at[case_node][-1]
            if not (last_node.does_end_with_continue or last_node.does_end_with_return):
                last_node.break_case = True
        if default_node:
            sorted_cases.append(default_node)
        self._sorted_cases = tuple(sorted_cases)

    def get_end_nodes(self) -> Iterable[SwitchNode]:
        """A switch node is an end-node"""
        yield self

    def replace_variable(self, replacee: Variable, replacement: Variable) -> None:
        """Replace the variable replacee by replacement in the switch-expression."""
        self.expression.substitute(replacee, replacement)

    def accept(self, visitor: ASTVisitorInterface[T]) -> T:
        return visitor.visit_switch_node(self)

    def get_required_variables(self, condition_map: Optional[Dict[LogicCondition, Condition]] = None) -> Iterable[Variable]:
        yield from self.expression.requirements


class CaseNode(ConditionalNode):
    """
    A case node additionally has the attributes
        - self.expression, the 'switch' expression, i.e., the expression whose value we compare.
        - self.constant, the constant the expression should have for this case.
        - self.break_case, whether the Case ends with a break.
    """

    def __init__(
        self,
        expression: Expression,
        constant: Union[Constant, Literal["default"]],
        reaching_condition: LogicCondition,
        break_case: bool = False,
        ast: Optional[AbstractSyntaxInterface] = None,
    ):
        """Init a new CaseNode with the switch expression, the case-constant, a reaching condition and the ast it is contained in."""
        super().__init__(reaching_condition, ast)
        self.expression = expression
        self.constant = constant
        self.break_case = break_case

    def __hash__(self) -> int:
        """
        AST nodes should hash the same even then in different graphs and should not change when node properties change,
        so we use their addresses.
        """
        return super().__hash__()

    def __eq__(self, other) -> bool:
        """Compare two AST nodes based on their type, reaching condition, switch-expression and constant."""
        return super().__eq__(other) and self.expression == other.expression and self.constant == other.constant

    def __str__(self) -> str:
        """Return a string representation of a CaseNode."""
        if isinstance(self.constant, Constant):
            return f"case {self.constant}:"
        return f"default:"

    def __repr__(self) -> str:
        """Return a debug representation of the ast node."""
        return f"CaseNode({self.reaching_condition})\n {str(self)}"

    def copy(self) -> CaseNode:
        """Return a copy of the ast node."""
        return CaseNode(self.expression, self.constant, self.reaching_condition, self.break_case)

    @property
    def does_end_with_break(self) -> bool:
        """By construction, a case node never ends with break (in case of loop-breaks)."""
        return False

    @property
    def does_contain_break(self) -> bool:
        """By construction, a case node never ends with break (in case of loop-breaks)."""
        return False

    @property
    def is_empty(self) -> bool:
        """Even case nodes with empty code-node are not empty, because they still influence the program flow."""
        return False

    def replace_variable(self, replacee: Variable, replacement: Variable) -> None:
        """Replace the variable replacee by replacement in the switch-expression."""
        self.expression.substitute(replacee, replacement)

    def accept(self, visitor: ASTVisitorInterface[T]) -> T:
        return visitor.visit_case_node(self)

    def get_required_variables(self, condition_map: Optional[Dict[LogicCondition, Condition]] = None) -> Iterable[Variable]:
        yield from self.expression.requirements
