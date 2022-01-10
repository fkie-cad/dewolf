"""
Module for Condition Aware Refinement
"""

from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.base_class_car import (
    BaseClassConditionAwareRefinement,
)
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.initial_switch_node_constructer import (
    InitialSwitchNodeConstructor,
)
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.missing_case_finder import (
    MissingCaseFinder,
)
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.switch_extractor import SwitchExtractor
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.logic.logic_condition import LogicCondition


class ConditionAwareRefinement(BaseClassConditionAwareRefinement):
    """Condition Aware Refinement"""

    REFINEMENT_PIPELINE = [
        InitialSwitchNodeConstructor.construct,
        MissingCaseFinder.find_in_condition,
        SwitchExtractor.extract,
        MissingCaseFinder.find_in_sequence,
    ]

    def __init__(self, asforest: AbstractSyntaxForest):
        self.asforest = asforest
        super().__init__(asforest.condition_handler)

    @classmethod
    def refine(cls, asforest: AbstractSyntaxForest):
        condition_aware_refinement = cls(asforest)
        for stage in condition_aware_refinement.REFINEMENT_PIPELINE:
            asforest.clean_up(asforest.current_root)
            stage(asforest)
            condition_aware_refinement._remove_redundant_reaching_condition_from_switch_nodes()
        asforest.clean_up(asforest.current_root)

    def _remove_redundant_reaching_condition_from_switch_nodes(self):
        """Remove the reaching condition from all switch nodes if it is redundant."""
        for switch_node in self.asforest.get_switch_nodes_post_order(self.asforest.current_root):
            if not switch_node.reaching_condition.is_true and self._condition_is_redundant_for_switch_node(
                switch_node, switch_node.reaching_condition
            ):
                switch_node.reaching_condition = self.condition_handler.get_true_value()
