from typing import Optional, Set

from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.missing_case_finder import (
    MissingCaseFinder,
)
from decompiler.structures.ast.ast_nodes import ConditionNode, SwitchNode
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.pseudo import Constant


class MissingCaseFinderCondition(MissingCaseFinder):
    """
    Class in charge of finding missing case for switch nodes in Condition nodes.

    A condition-node where one branch has a valid switch-case condition and the other is a switch node with the
    same expression, indicates that this branch is a missing case of the switch.
    """

    @classmethod
    def find(cls, asforest: AbstractSyntaxForest):
        """Try to find missing cases that are branches of condition nodes."""
        missing_case_finder = cls(asforest)
        for condition_node in asforest.get_condition_nodes_post_order(asforest.current_root):
            if new_case_constants := missing_case_finder._can_insert_missing_case_node(condition_node):
                missing_case_finder._insert_case_node(
                    condition_node.false_branch_child, new_case_constants, condition_node.true_branch_child
                )
                asforest.replace_condition_node_by_single_branch(condition_node)

    def _can_insert_missing_case_node(self, condition_node: ConditionNode) -> Optional[Set[Constant]]:
        """
        Check whether one of the branches is a possible case node for the other branch that should be a switch node.
        If this is the case, return the case-constants for the new case node.

        -> We have to make sure that there exists a switch node where we can insert it and that it has the correct condition
        -> The case constants can not exist in the switch node where we want to insert the case node.

        :param condition_node: The condition node where we want to find a missing case.
        :return: Return the set of constant for this switch node if it is a missing case and None otherwise.
        """
        if len(condition_node.children) == 1 or not any(isinstance(branch.child, SwitchNode) for branch in condition_node.children):
            return None
        if isinstance(condition_node.false_branch_child, SwitchNode):
            condition_node.switch_branches()

        switch_node: SwitchNode = condition_node.true_branch_child
        possible_case_node = condition_node.false_branch_child
        case_condition = condition_node.false_branch.branch_condition

        if not switch_node.reaching_condition.is_true or possible_case_node._has_descendant_code_node_breaking_ancestor_loop():
            return None

        expression_usage = self._get_const_eq_check_expression_of_disjunction(case_condition)
        if (
            expression_usage is None
            or expression_usage.expression != switch_node.expression
            or expression_usage.ssa_usages != tuple(var.ssa_name for var in switch_node.expression.requirements)
        ):
            return None

        new_case_constants = set(self._get_case_constants_for_condition(case_condition))
        if all(case.constant not in new_case_constants for case in switch_node.cases):
            return new_case_constants
