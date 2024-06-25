from typing import Optional, Union

from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.base_class_car import (
    BaseClassConditionAwareRefinement,
)
from decompiler.pipeline.controlflowanalysis.restructuring_options import RestructuringOptions
from decompiler.structures.ast.ast_nodes import ConditionNode, FalseNode, SeqNode, SwitchNode, TrueNode
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.logic.logic_condition import LogicCondition


class SwitchExtractor(BaseClassConditionAwareRefinement):
    """Extract switch nodes from condition nodes if the condition node is irrelevant for the switch node."""

    @classmethod
    def extract(cls, asforest: AbstractSyntaxForest, options: RestructuringOptions):
        """Extract switch nodes from condition nodes, or sequence-nodes with a non-trivial reaching-condition."""
        switch_extractor = cls(asforest, options)
        for switch_node in list(asforest.get_switch_nodes_post_order(asforest.current_root)):
            while switch_extractor._successfully_extracts_switch_nodes(switch_node):
                pass

    def _successfully_extracts_switch_nodes(self, switch_node: SwitchNode) -> bool:
        """
        We extract the given switch-node, if possible, and return whether it was successfully extracted.

        1. If the switch node has a sequence node as parent and is its first or last child
            i) Sequence node has a non-trivial reaching-condition
               --> extract the switch from the sequence node if the reaching-condition is redundant for the switch
           ii) Sequence node has a trivial reaching-condition, and its parent is a branch of a condition node
               --> extract the switch from the condition-node if the branch-condition is redundant for the switch
        2. If the switch node has a branch of a condition-node as parent
               --> extract the switch from the condition node if the branch-condition is redundant for the switch
        """
        switch_parent = switch_node.parent
        if isinstance(switch_parent, SeqNode):
            if not switch_parent.reaching_condition.is_true:
                return self._successfully_extract_switch_from_first_or_last_child_of(switch_parent, switch_parent.reaching_condition)
            elif isinstance(branch := switch_parent.parent, TrueNode | FalseNode):
                return self._successfully_extract_switch_from_first_or_last_child_of(switch_parent, branch.branch_condition)
        elif isinstance(switch_parent, TrueNode | FalseNode) and self._condition_is_redundant_for_switch_node(
            switch_node, switch_parent.branch_condition
        ):
            self._extract_switch_node_from_branch(switch_parent)
            return True
        return False

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
        assert isinstance(condition_node := branch.parent, ConditionNode), "The parent of a true/false-branch must be a condition node!"
        if len(condition_node.children) != 2:
            self.asforest.replace_condition_node_by_single_branch(condition_node)
        else:
            self.asforest.extract_branch_from_condition_node(condition_node, branch, False)

    def _successfully_extract_switch_from_first_or_last_child_of(self, sequence_node: SeqNode, condition: LogicCondition) -> bool:
        """
        Check whether the first or last child of the sequence node is a switch-node for which the given condition is redundant.
        If this is the case, extract the switch-node from the sequence.
        """
        for switch_node in [sequence_node.children[0], sequence_node.children[-1]]:
            if self._condition_is_redundant_for_switch_node(switch_node, condition):
                assert isinstance(switch_node, SwitchNode), f"The node {switch_node} must be a switch-node!"
                self.asforest.extract_switch_from_sequence(switch_node)
                return True
        return False
