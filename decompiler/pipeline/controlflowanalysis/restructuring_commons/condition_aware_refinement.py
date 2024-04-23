"""
Module for Condition Aware Refinement
"""

from typing import Set

from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.base_class_car import (
    BaseClassConditionAwareRefinement,
)
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.initial_switch_node_constructer import (
    InitialSwitchNodeConstructor,
)
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.missing_case_finder import (
    MissingCaseFinder,
)
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.missing_case_finder_condition import (
    MissingCaseFinderCondition,
)
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.missing_case_finder_sequence import (
    MissingCaseFinderSequence,
)
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.switch_extractor import (
    SwitchExtractor,
)
from decompiler.pipeline.controlflowanalysis.restructuring_options import RestructuringOptions
from decompiler.structures.ast.ast_nodes import SwitchNode
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest


class ConditionAwareRefinement(BaseClassConditionAwareRefinement):
    """Condition Aware Refinement"""

    REFINEMENT_PIPELINE = [
        InitialSwitchNodeConstructor.construct,
        MissingCaseFinderCondition.find,
        SwitchExtractor.extract,
        MissingCaseFinderSequence.find,
    ]

    @classmethod
    def refine(cls, asforest: AbstractSyntaxForest, options: RestructuringOptions) -> Set[SwitchNode]:
        condition_aware_refinement = cls(asforest, options)
        for stage in condition_aware_refinement.REFINEMENT_PIPELINE:
            asforest.clean_up(asforest.current_root)
            condition_aware_refinement.updated_switch_nodes.update(stage(asforest, options))
            condition_aware_refinement._remove_redundant_reaching_condition_from_switch_nodes()
        asforest.clean_up(asforest.current_root)
        return set(switch for switch in condition_aware_refinement.updated_switch_nodes if switch in asforest)

    def _remove_redundant_reaching_condition_from_switch_nodes(self):
        """Remove the reaching condition from all switch nodes if it is redundant."""
        for switch_node in self.asforest.get_switch_nodes_post_order(self.asforest.current_root):
            if not switch_node.reaching_condition.is_true and self._condition_is_redundant_for_switch_node(
                switch_node, switch_node.reaching_condition
            ):
                switch_node.reaching_condition = self.condition_handler.get_true_value()
