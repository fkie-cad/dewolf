from dataclasses import dataclass
from typing import Generator, Iterable, Iterator, List, Optional, Set, Tuple

from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.base_class_car import (
    CaseNodeCandidate,
)
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.missing_case_finder import (
    MissingCaseFinder,
)
from decompiler.pipeline.controlflowanalysis.restructuring_options import RestructuringOptions
from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CaseNode, FalseNode, SwitchNode, TrueNode
from decompiler.structures.ast.reachability_graph import SiblingReachabilityGraph
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.pseudo import Constant


@dataclass
class IntersectingCaseNodeProperties:
    case_node: CaseNodeCandidate
    case_constants: Set[Constant]
    intersecting_cases: Set[Constant]

    def unique_cases(self) -> Iterator[Constant]:
        for constant in self.case_constants:
            if constant not in self.intersecting_cases:
                yield constant


class MissingCaseFinderIntersectingConstants(MissingCaseFinder):
    def __init__(
        self,
        asforest: AbstractSyntaxForest,
        options: RestructuringOptions,
        switch_node: SwitchNode,
        sibling_reachability: SiblingReachabilityGraph,
    ):
        super().__init__(asforest, options)
        self._switch_node: SwitchNode = switch_node
        self._sibling_reachability_graph: SiblingReachabilityGraph = sibling_reachability

    def insert(self, possible_case: CaseNodeCandidate):
        """
        Insert the possible case node that has intersection constants.

        - If the possible-case node reaches the switch-node, then the content must be inserted before any other code.
          Thus, all constants belonging to the new possible case-node must be contained in the switch-node and are the
          first fallthrough-cases.
        - If the possible-case node is reached by the switch-node, then the content must be after any other code.
          Thus, it must contain all constants from a block of fallthrough-cases. But here, it can contain more.
        - If neither one reaches the other, then it can be inserted anywhere, as long as it can be archived by only
          resorting fallthrough-cases all leading to the same code-execution.
        """
        cases_of_switch_node = {case.constant for case in self._switch_node.children}
        case_constants_for_possible_case_node = set(self._get_case_constants_for_condition(possible_case.condition))
        intersection_cases = {constant for constant in case_constants_for_possible_case_node if constant in cases_of_switch_node}
        possible_case_properties = IntersectingCaseNodeProperties(possible_case, case_constants_for_possible_case_node, intersection_cases)
        if (intersecting_linear_case := self.__get_linear_order_intersection_constants(intersection_cases)) is None:
            return
        compare_node = possible_case.get_head
        if self._sibling_reachability_graph.reaches(compare_node, self._switch_node):
            if not self._add_case_before(intersecting_linear_case, possible_case_properties):
                return
        elif self._sibling_reachability_graph.reaches(self._switch_node, compare_node):
            if not self._add_case_after(intersecting_linear_case, possible_case_properties):
                return
        else:
            if not self._add_case_after(intersecting_linear_case, possible_case_properties) and not self._add_case_before(
                intersecting_linear_case, possible_case_properties
            ):
                return

        self._sibling_reachability_graph.update_when_inserting_new_case_node(compare_node, self._switch_node)
        self.updated_switch_nodes.add(self._switch_node)
        compare_node.clean()

    def _add_case_before(self, intersecting_linear_case: Tuple[CaseNode], possible_case_properties: IntersectingCaseNodeProperties) -> bool:
        """
        Insert the possible case node before the first code that is executed in the given linear-case order, if possible.

        - all case-constants of the new case node must be contained in the linear-case order
        - they all must be contained before any code is executed
        """
        if len(possible_case_properties.intersecting_cases) != len(possible_case_properties.case_constants):
            return False
        new_case_node = self._get_case_node_for_insertion_before(possible_case_properties.intersecting_cases, intersecting_linear_case)
        if new_case_node is None:
            return False
        self._add_case_node_to(new_case_node, possible_case_properties.case_node)
        return True

    def _get_case_node_for_insertion_before(
        self, intersection_cases: Set[Constant], intersecting_linear_case: Tuple[CaseNode]
    ) -> Optional[CaseNode]:
        """
        Return the existing case-node where we want to insert the content of the possible-case node.

        The intersecting cases, must be before any code is executed.
        If insertion is not possible, we return None.
        - intersection_cases: all constants that are contained in the new case-node and the switch-node
        - intersecting_linear_case: The list of case-nodes of the switch ending with a break containing the intersecting nodes.
        """
        common_cases, uncommon_cases = self._split_cases_until_first_code(intersecting_linear_case, intersection_cases)
        if len(common_cases) != len(intersection_cases):
            return None
        self.__resort_cases(common_cases + uncommon_cases, [c.child for c in intersecting_linear_case])
        return common_cases[-1]

    def _add_case_after(self, intersecting_linear_case: Tuple[CaseNode], possible_case_properties: IntersectingCaseNodeProperties) -> bool:
        """
        Insert the possible case node after the last code that is executed in the given linear-case order, if possible.

        - all case-constants of the linear-case order must be contained in the constants of the new case node
        - if the new case-node has more constants, we add more cases, otherwise, we write the contend in the last code-node.
        """
        if len(intersecting_linear_case) != len(possible_case_properties.intersecting_cases):
            return False
        possible_case = possible_case_properties.case_node
        possible_case.update_reaching_condition_for_insertion()
        if len(possible_case_properties.intersecting_cases) == len(possible_case_properties.case_constants):
            new_seq = self.asforest._add_sequence_node_before(intersecting_linear_case[-1].child)
            self.asforest._remove_edge(possible_case.node.parent, possible_case.node)
            self.asforest._add_edge(new_seq, possible_case.node)
        else:
            remaining_cases = list(sorted(possible_case_properties.unique_cases(), key=lambda const: const.value))
            self._new_case_nodes_for(possible_case.node, self._switch_node, remaining_cases)
            intersecting_linear_case[-1].break_case = False
        return True

    def _split_cases_until_first_code(
        self, intersecting_linear_case: Tuple[CaseNode], intersection_cases: Set[Constant]
    ) -> Tuple[List[CaseNode], List[CaseNode]]:
        """Split the intersecting linear case until the first case-node contains code."""
        uncommon_cases: List[CaseNode] = list()
        common_cases: List[CaseNode] = list()
        for case in intersecting_linear_case:
            if case.constant not in intersection_cases:
                uncommon_cases.append(case)
            else:
                common_cases.append(case)
            if not case.child.is_empty_code_node:
                return common_cases, uncommon_cases
        if common_cases or uncommon_cases:
            return common_cases, uncommon_cases

    def __resort_cases(self, new_case_order: List[CaseNode], old_case_children: List[AbstractSyntaxTreeNode]):
        """Resort the cases according to the new order by switching the case-node-children whose reachability is correct."""
        for case_node, new_child in zip(new_case_order, old_case_children):
            self.asforest._remove_edge(case_node, case_node.child)
            self.asforest._add_edge(case_node, new_child)
        self._switch_node.sort_cases()

    def _add_case_node_to(self, new_case_node: CaseNode, possible_case: CaseNodeCandidate):
        """Add the possible case node into the new case node"""
        possible_case.update_reaching_condition_for_insertion()
        self.asforest._remove_edge(possible_case.node.parent, possible_case.node)
        if (empty_child := new_case_node.child).is_empty_code_node:
            self.asforest._add_edge(new_case_node, possible_case.node)
            reachable_from = self.asforest._code_node_reachability_graph.reachable_from(empty_child)
            reaching = self.asforest._code_node_reachability_graph.reaching(empty_child)
            for descendant in possible_case.node.get_descendant_code_nodes():
                self.asforest._code_node_reachability_graph.add_reachability_from((descendant, r) for r in reachable_from)
                self.asforest._code_node_reachability_graph.add_reachability_from((r, descendant) for r in reaching)
            self.asforest._remove_node(empty_child)
        else:
            new_seq = self.asforest._add_sequence_node_before(new_case_node.child)
            self.asforest._add_edge(new_seq, possible_case.node)

    def __get_linear_order_intersection_constants(self, case_constants: Set[Constant]) -> Optional[Tuple[CaseNode]]:
        """
        Get the linear-order of switch-cases that intersect with the given set of constants.

        Only one can have an empty intersection, and it must contain all, otherwise we can not insert the case node.
        """
        idx_break_cases = [
            idx + 1
            for idx, case in enumerate(self._switch_node.cases)
            if case.break_case or case.does_end_with_return or case.does_end_with_continue
        ]
        assert len(self._switch_node.cases) == idx_break_cases[-1], "The last case-node must end with a break, continue or return."
        all_linear_cases = [self._switch_node.cases[i:j] for i, j in zip([0] + idx_break_cases, idx_break_cases)]
        for linear_case in all_linear_cases:
            number_of_case_constant_in_order = sum(case.constant in case_constants for case in linear_case)
            if number_of_case_constant_in_order > 0:
                if number_of_case_constant_in_order != len(case_constants):
                    return None
                else:
                    return linear_case
        return None
