from typing import Iterable, List, Set

from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.base_class_car import (
    BaseClassConditionAwareRefinement,
)
from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CaseNode, SwitchNode
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import Constant


class MissingCaseFinder(BaseClassConditionAwareRefinement):
    """
    Base Class in charge of finding missing case for switch nodes.

    A missing case is a sibling of a switch nodes that we did not find during the initial switch construction, that has all the properties
    for a case-node candidate or a condition node which the correct condition, where one branch is a switch-node.
    """

    def _insert_case_node(self, new_case_node: AbstractSyntaxTreeNode, case_constants: Set[Constant], switch_node: SwitchNode) -> None:
        """Insert new case node into switch node with the given set of constants."""
        sorted_case_constants: List[Constant] = list(sorted(case_constants, key=lambda const: const.value))
        new_children = list()

        for position, child in enumerate(switch_node.cases):
            if sorted_case_constants[0].value < child.constant.value and self._can_insert_at_position(position, switch_node):
                remaining_cases = switch_node.cases[position:]
                new_children += self._new_case_nodes_for(new_case_node, switch_node, sorted_case_constants)
                new_children += remaining_cases
                break
            new_children.append(child)
        else:
            new_children += self._new_case_nodes_for(new_case_node, switch_node, sorted_case_constants)
        if default_case := switch_node.default:
            new_children.append(default_case)
        switch_node._sorted_cases = tuple(new_children)

    def _new_case_nodes_for(
        self, new_case_node: AbstractSyntaxTreeNode, switch_node: SwitchNode, sorted_case_constants: List[Constant]
    ) -> List[CaseNode]:
        """Construct Case nodes for the given ast node with the given cases and given variable."""
        new_case_nodes = [
            self.asforest.factory.create_case_node(switch_node.expression, case_constant) for case_constant in sorted_case_constants
        ]
        self.asforest.add_case_nodes_with_one_child(new_case_nodes, switch_node, new_case_node)
        return new_case_nodes

    @staticmethod
    def _can_insert_at_position(position: int, switch_node: SwitchNode) -> bool:
        """Check whether we can insert the Case node at the given position of the given switch node"""
        return (
            position == 0
            or switch_node.cases[position - 1].break_case
            or switch_node.cases[position - 1].does_end_with_return
            or switch_node.cases[position - 1].does_end_with_continue
        )

    def _get_case_constants_for_condition(self, case_condition: LogicCondition) -> Iterable[Constant]:
        """Return all constants for the given condition."""
        assert case_condition.is_disjunction_of_literals, f"The condition {case_condition} can not be the condition of a case node."
        if constant := self._get_constant_compared_with_expression(case_condition):
            yield constant
        else:
            for literal in case_condition.operands:
                yield self._get_constant_compared_with_expression(literal)
