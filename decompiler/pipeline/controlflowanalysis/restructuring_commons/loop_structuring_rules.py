from abc import ABC, abstractmethod
from typing import Iterable, List, Set

from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CodeNode, ConditionNode, LoopNode, SeqNode, WhileLoopNode
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest


def _has_loop_break_interruptions_in(body: AbstractSyntaxTreeNode) -> bool:
    """Check that there is no break-statement in the given Sequence node."""

    for code_node in _get_code_nodes_interrupting_loop(body):
        if code_node.does_end_with_break:
            return False
    return True


def _has_only_loop_interruptions_in(end_nodes: Set[CodeNode], body: SeqNode) -> bool:
    """
    Check that there is no continue-statement in the loop-body and no break statement except the last child that could
    interrupt the loop node.
    """
    for code_node in _get_code_nodes_interrupting_loop(body):
        if code_node not in end_nodes and (code_node.does_end_with_continue or code_node.does_end_with_break):
            return False
    return True


def _get_code_nodes_interrupting_loop(node: AbstractSyntaxTreeNode) -> Iterable[CodeNode]:
    """
    Return all code nodes that can contain a break or continue statement that would interrupt the closest ancestor loop to the
    given node.
    """
    if isinstance(node, CodeNode):
        yield node
    if not isinstance(node, LoopNode):
        for child in node.children:
            yield from _get_code_nodes_interrupting_loop(child)


class LoopStructuringRule(ABC):
    """Base Class in charge of loop restructuring rules."""

    @staticmethod
    @abstractmethod
    def can_be_applied(loop_node: AbstractSyntaxTreeNode) -> bool:
        """Check whether the restructuring can be applied."""

    def __init__(self, asforest: AbstractSyntaxForest):
        self._asforest: AbstractSyntaxForest = asforest

    @abstractmethod
    def restructure(self):
        """restructures the loop according to the Rule of the Loop-type."""


class WhileLoopRule(LoopStructuringRule):
    """
    Class in charge of restructure an endless loop into a while loop with condition.

    The loop must have the following properties:
        -  endless-loop
        - (loop-body is a sequence node whose first child is a break-condition) or the loop-body itself is a break condition.
    """

    @staticmethod
    def can_be_applied(loop_node: AbstractSyntaxTreeNode):
        """Check whether it fulfills the property for a restructuring as while loop"""
        return loop_node.is_endless_loop and (
            (isinstance(body := loop_node.body, SeqNode) and body.children[0].is_break_condition) or loop_node.body.is_break_condition
        )

    def restructure(self):
        """
        Restructure the endless loop (the current root-node) as a while loop.

        - We first check whether it is a loop whose the body is a break-condition, i.e., we transform it into a while loop with condition
          that has no body.
        - If not, we restructure as a while loop whose condition is the negated break condition of the first node,
          which is a conditional-break.
        """
        loop_node: LoopNode = self._asforest.current_root
        if not isinstance(loop_node, WhileLoopNode):
            self._asforest.substitute_loop_node(
                loop_node,
                loop_node := self._asforest.factory.create_endless_loop_node(),
            )
        loop_body = loop_node.body
        if loop_body.is_break_condition:
            loop_node.condition = ~loop_body.condition
            self._asforest.remove_subtree(loop_body.true_branch)
            self._asforest.remove_empty_nodes(loop_node)
            return
        first_conditional_break: ConditionNode = loop_body.children[0]
        first_conditional_break.clean()
        break_condition = first_conditional_break.condition
        loop_node.condition = ~break_condition
        self._asforest.remove_subtree(first_conditional_break)


class DoWhileLoopRule(LoopStructuringRule):
    """
    Class in charge of restructure an endless loop into a do-while loop with condition.

    The loop must have the following properties:
        -  endless-loop
        - loop-body is a sequence node whose last child is a break-condition
    """

    @staticmethod
    def can_be_applied(loop_node: AbstractSyntaxTreeNode):
        """Check whether it fulfills the property for a restructuring as do-while loop"""
        return loop_node.is_endless_loop and isinstance(body := loop_node.body, SeqNode) and body.children[-1].is_break_condition

    def restructure(self):
        """
        Restructure the endless loop (the current root-node) as a do-while loop.

        - We restructure as a do-while loop whose condition is the negated break condition of the last node, which is a conditional-break.
        """
        loop_node: LoopNode = self._asforest.current_root
        loop_body_nodes = loop_node.body.children
        last_conditional_break = loop_body_nodes[-1]
        last_conditional_break.clean()
        break_condition = last_conditional_break.condition
        new_loop_node = self._asforest.factory.create_do_while_loop_node(~break_condition)
        self._asforest.substitute_loop_node(loop_node, new_loop_node)
        self._asforest.remove_subtree(last_conditional_break)


class NestedDoWhileLoopRule(LoopStructuringRule):
    """
    Class in charge of restructure an endless loop into a nested do-while loop with condition.

    The loop must have the following properties:
        - endless-loop
        - loop-body is a sequence node whose last child is a condition-node with one child
        - No node, except the last child of the sequence, contains a break condition.
    """

    @staticmethod
    def can_be_applied(loop_node: AbstractSyntaxTreeNode):
        """Check whether it fulfills the property for a restructuring as nested dowhile loop"""
        return (
            loop_node.is_endless_loop
            and isinstance(body := loop_node.body, SeqNode)
            and isinstance(condition_node := body.children[-1], ConditionNode)
            and len(condition_node.children) == 1
            and all(_has_loop_break_interruptions_in(child) for child in body.children[:-1])
        )

    def restructure(self):
        """
        Restructure the endless loop (the current root-node) as a nested-do-while loop.

        - We restructure the body to a sequence node whose children are a do-while loop with the old body as child, and the branch of the
        last condition node.
        """
        loop_node: LoopNode = self._asforest.current_root
        loop_body: SeqNode = loop_node.body
        old_loop_children: List[AbstractSyntaxTreeNode] = list(loop_body.children)
        last_node: ConditionNode = old_loop_children[-1]
        last_node.clean()
        new_loop = self._asforest.factory.create_do_while_loop_node(~last_node.condition)
        self._asforest.replace_condition_node_by_single_branch(last_node)
        if len(old_loop_children[:-1]) > 1:
            new_loop_body = self._asforest.add_seq_node_with_reaching_condition_before(
                old_loop_children[:-1], self._asforest.condition_handler.get_true_value()
            )
        else:
            new_loop_body = old_loop_children[0]
        self._asforest.add_loop_node_before(new_loop_body, new_loop)


class SequenceRule(LoopStructuringRule):
    """
    Class in charge of restructure an endless loop into a sequence node.

    The loop must have the following properties:
        - endless-loop
        - loop-body is a sequence node whose last child ends with a break
        - The loop has no other interruption due to continue or break
    """

    @staticmethod
    def can_be_applied(loop_node: AbstractSyntaxTreeNode):
        """Check whether it fulfills the property for a restructuring as a sequence instead of a loop."""
        if not loop_node.is_endless_loop or not isinstance(body := loop_node.body, SeqNode):
            return False
        end_nodes: Set[CodeNode] = set()
        for end_node in body.get_end_nodes():
            if not end_node.is_code_node_ending_with_break:
                return False
            end_nodes.add(end_node)

        return _has_only_loop_interruptions_in(end_nodes, body)

    def restructure(self):
        """
        Restructure the endless loop (the current root-node) as a sequence loop.

        - We restructure the the loop node to a sequence node by removing the loop-node and all break statements of end-nodes.
        """
        loop_node: LoopNode = self._asforest.current_root
        loop_body = loop_node.body
        self._delete_break_statements_for_loop(loop_body)
        self._asforest.remove_current_root()
        self._asforest.remove_root_node(loop_node)
        self._asforest.set_current_root(loop_body)

    def _delete_break_statements_for_loop(self, ast_node: AbstractSyntaxTreeNode):
        """Remove all break statements from the code nodes in the given subtree."""
        for code_node in ast_node.get_end_nodes():
            code_node.clean()
            if code_node.does_end_with_break:
                code_node.instructions = code_node.instructions[:-1]
        self._asforest.clean_up(ast_node)


class ConditionToSequenceRule(LoopStructuringRule):
    """
    Class in charge of restructure an endless loop into a while loop with condition.

    The loop must have the following properties:
        - endless-loop
        - loop-body is a condition node
        - Exactly one of the two branches ends with a break.
    """

    @staticmethod
    def can_be_applied(loop_node: AbstractSyntaxTreeNode):
        """Check whether it fulfills the property for a restructuring as condition to sequence."""
        if not loop_node.is_endless_loop or not isinstance(body := loop_node.body, ConditionNode):
            return False
        break_in_true = body.true_branch.does_contain_break if body.true_branch else False
        break_in_false = body.false_branch.does_contain_break if body.false_branch else False
        if break_in_true ^ break_in_false:
            if break_in_true:
                body.switch_branches()
            return True
        return False

    def restructure(self):
        """
        Restructure the endless loop (the current root-node) as a sequence-node with two children where the first is a again a loop-node.

        - We restructure the the loop node to a sequence node, whose first child is a while-loop, whose condition is the condition of the
        condition-node of the loop body and whose child is the true-branch, and whose second child is the false_branch.
        """
        old_loop_body: ConditionNode = self._asforest.current_root.body
        branch_with_break = old_loop_body.false_branch_child
        new_loop_body = old_loop_body.true_branch_child
        new_loop = self._asforest.factory.create_while_loop_node(old_loop_body.condition)
        self._asforest.extract_branch_from_condition_node(old_loop_body, old_loop_body.false_branch)
        if new_loop_body is None:
            new_loop_body = self._get_new_loop_body(branch_with_break, old_loop_body)
        self._asforest.replace_condition_node_by_single_branch(old_loop_body)
        self._asforest.add_loop_node_before(new_loop_body, new_loop)

    def _get_new_loop_body(self, branch_with_break: AbstractSyntaxTreeNode, condition_node: ConditionNode) -> CodeNode:
        """Return the loop body of the new loop-node we want to insert."""
        new_loop_body = self._asforest.add_code_node()
        for code_node in branch_with_break.get_descendant_code_nodes():
            self._asforest.add_reachability(new_loop_body, code_node)
        self._asforest.substitute_branches_by(new_loop_body, condition_node)
        return new_loop_body
