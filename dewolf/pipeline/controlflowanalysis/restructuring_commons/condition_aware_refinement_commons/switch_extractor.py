from typing import Optional, Union

from dewolf.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.base_class_car import (
    BaseClassConditionAwareRefinement,
)
from dewolf.structures.ast.ast_nodes import ConditionNode, FalseNode, SeqNode, TrueNode
from dewolf.structures.ast.syntaxforest import AbstractSyntaxForest


class SwitchExtractor(BaseClassConditionAwareRefinement):
    """Extract switch nodes from condition nodes if the condition node is irrelevant for the switch node."""

    def __init__(self, asforest: AbstractSyntaxForest):
        """
        self.asforest: The asforst where we try to construct switch nodes
        self.current_cond_node: The condition node which we consider to extract switch nodes.
        """
        self.asforest = asforest
        self._current_cond_node: Optional[ConditionNode] = None
        super().__init__(asforest.condition_handler)

    @classmethod
    def extract(cls, asforest):
        """
        Extract switch nodes from condition nodes, i.e., if a switch node is a branch of a condition node whose condition is redundant for
        the switch node, we extract it from the condition node.
        """
        switch_extractor = cls(asforest)
        for condition_node in asforest.get_condition_nodes_post_order(asforest.current_root):
            switch_extractor._current_cond_node = condition_node
            switch_extractor._extract_switches_from_condition()

    def _extract_switches_from_condition(self) -> None:
        """Extract switch nodes in the true and false branch of the given condition node."""
        if self._current_cond_node.false_branch:
            self._try_to_extract_switch_from_branch(self._current_cond_node.false_branch)
        if self._current_cond_node.true_branch:
            self._try_to_extract_switch_from_branch(self._current_cond_node.true_branch)
        if self._current_cond_node in self.asforest:
            self._current_cond_node.clean()

    def _try_to_extract_switch_from_branch(self, branch: Union[TrueNode, FalseNode]) -> None:
        """
        1. If the given branch of the condition node is a switch node,
           then extract it if the reaching condition is redundant for the switch node.
        2. If the given branch of the condition node is a sequence node whose first or last node is a switch node,
           then extract it if the reaching condition is redundant for the switch node.
        """
        branch_condition = branch.branch_condition
        if self._condition_is_redundant_for_switch_node(branch.child, branch_condition):
            self._extract_switch_node_from_branch(branch)
        elif isinstance(sequence_node := branch.child, SeqNode):
            for switch_node in [sequence_node.children[0], sequence_node.children[-1]]:
                if self._condition_is_redundant_for_switch_node(switch_node, branch_condition):
                    self.asforest.extract_switch_from_condition_sequence(switch_node, self._current_cond_node)

    def _extract_switch_node_from_branch(self, branch: Union[TrueNode, FalseNode]) -> None:
        """
        Extract the switch node from the current condition node.
            1. The current condition node is a condition Node with one child -> replace the ConditionNode by the SwitchNode
            2. The parent of the current condition node is a sequence node -> add the switch node as a new child to this sequence node
            3. The parent of the current condition node is not a sequence node -> replace the ConditionNode by a sequence node with two
               children, one is the old ConditionNode and the other the switch node.

        :param branch: The branch from which we extract the switch node.
        :return: If we introduce a new sequence node, then return this node, otherwise return None.
        """
        if len(self._current_cond_node.children) != 2:
            self.asforest.replace_condition_node_by_single_branch(self._current_cond_node)
        else:
            self.asforest.extract_branch_from_condition_node(self._current_cond_node, branch, False)
