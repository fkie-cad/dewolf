"""Module for visitor ABCs."""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

import decompiler.structures.ast.ast_nodes as ast_nodes
import decompiler.structures.pseudo.expressions as expressions
import decompiler.structures.pseudo.operations as operations
from decompiler.structures.pseudo import instructions

T = TypeVar("T")


class ASTVisitorInterface(ABC, Generic[T]):
    """Interface for all Visitor objects for the Abstract Syntax Tree"""

    def visit(self, node: ast_nodes.AbstractSyntaxTreeNode) -> T:
        """Visit an AST node, dispatching to the correct handler."""
        return node.accept(self)

    @abstractmethod
    def visit_condition_node(self, node: ast_nodes.ConditionNode) -> T:
        """Visit ConditionNode"""

    @abstractmethod
    def visit_loop_node(self, node: ast_nodes.LoopNode) -> T:
        """Visit LoopNode"""

    @abstractmethod
    def visit_switch_node(self, node: ast_nodes.SwitchNode) -> T:
        """Visit SwitchNode"""

    @abstractmethod
    def visit_case_node(self, node: ast_nodes.CaseNode) -> T:
        """Visit CaseNode"""

    @abstractmethod
    def visit_code_node(self, node: ast_nodes.CodeNode) -> T:
        """Visit CodeNode"""

    @abstractmethod
    def visit_seq_node(self, node: ast_nodes.SeqNode) -> T:
        """Visit SeqNode"""

    @abstractmethod
    def visit_true_node(self, node: ast_nodes.TrueNode) -> T:
        """Visit TrueNode"""

    @abstractmethod
    def visit_false_node(self, node: ast_nodes.FalseNode) -> T:
        """Visit FalseNode"""

    @abstractmethod
    def visit_root_node(self, node: ast_nodes.VirtualRootNode) -> T:
        """Visit RootNode"""


class DataflowObjectVisitorInterface(ABC, Generic[T]):
    """Interface for visiting Expressions, Operations and Instructions."""

    def visit(self, expr: expressions.DataflowObject) -> T:
        """Visit an DataflowObject, dispatching to the correct handler."""
        return expr.accept(self)

    @abstractmethod
    def visit_unknown_expression(self, expr: expressions.UnknownExpression):
        """Visit an UnknownExpression"""

    @abstractmethod
    def visit_constant(self, expr: expressions.Constant):
        """Visit a Constant."""

    @abstractmethod
    def visit_variable(self, expr: expressions.Variable):
        """Visit a Variable."""

    @abstractmethod
    def visit_register_pair(self, expr: expressions.RegisterPair):
        """Visit a RegisterPair."""

    """Methods to visit Operations."""

    @abstractmethod
    def visit_list_operation(self, op: operations.ListOperation) -> T:
        """Visit a ListOperation."""

    @abstractmethod
    def visit_unary_operation(self, op: operations.UnaryOperation) -> T:
        """Visit a UnaryOperation."""

    @abstractmethod
    def visit_binary_operation(self, op: operations.BinaryOperation) -> T:
        """Visit a BinaryOperation."""

    @abstractmethod
    def visit_call(self, op: operations.Call) -> T:
        """Visit a Call."""

    @abstractmethod
    def visit_condition(self, op: operations.Condition) -> T:
        """Visit a Condition."""

    @abstractmethod
    def visit_ternary_expression(self, op: operations.TernaryExpression) -> T:
        """Visit a TernaryExpression."""

    """Methods to visit Instructions."""

    @abstractmethod
    def visit_comment(self, instr: instructions.Comment) -> T:
        """Visit a Comment."""

    @abstractmethod
    def visit_assignment(self, instr: instructions.Assignment) -> T:
        """Visit an Assignment."""

    @abstractmethod
    def visit_generic_branch(self, instr: instructions.GenericBranch) -> T:
        """Visit an GenericBranch."""

    @abstractmethod
    def visit_return(self, instr: instructions.Return) -> T:
        """Visit an Return."""

    @abstractmethod
    def visit_break(self, instr: instructions.Break) -> T:
        """Visit a Break."""

    @abstractmethod
    def visit_continue(self, instr: instructions.Continue) -> T:
        """Visit a Continue."""

    @abstractmethod
    def visit_phi(self, instr: instructions.Phi) -> T:
        """Visit an Phi."""

    @abstractmethod
    def visit_mem_phi(self, instr: instructions.MemPhi) -> T:
        """Visit an MemPhi."""
