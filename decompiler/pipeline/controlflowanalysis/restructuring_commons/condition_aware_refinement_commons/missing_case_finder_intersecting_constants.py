from typing import List, Optional, Set, Tuple

from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.base_class_car import (
    CaseNodeCandidate,
)
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.missing_case_finder import (
    MissingCaseFinder,
)
from decompiler.structures.ast.ast_nodes import CaseNode, FalseNode, SwitchNode, TrueNode
from decompiler.structures.ast.reachability_graph import SiblingReachabilityGraph
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.pseudo import Constant


class MissingCaseFinderIntersectingConstants(MissingCaseFinder):
    def __init__(self, asforest: AbstractSyntaxForest, switch_node: SwitchNode, sibling_reachability: SiblingReachabilityGraph):
        super().__init__(asforest)
        self._switch_node: SwitchNode = switch_node
        self._sibling_reachability_graph: SiblingReachabilityGraph = sibling_reachability

    def insert(self, possible_case: CaseNodeCandidate):
        cases_of_switch_node = {case.constant for case in self._switch_node.children}
        case_constants_for_possible_case_node = set(self._get_case_constants_for_condition(possible_case.condition))
        intersection = {constant for constant in case_constants_for_possible_case_node if constant in cases_of_switch_node}
        if (intersecting_linear_case := self.__get_linear_order_intersection_constants(intersection)) is None:
            return
        # Insert content before case-node
        compare_node = possible_case.get_head
        if self._sibling_reachability_graph.reaches(compare_node, self._switch_node):
            if len(intersection) != len(case_constants_for_possible_case_node):
                return
            if (new_case_node := self._get_case_node_for_insertion(intersection, intersecting_linear_case)) is None:
                return
            self._add_case_node_to(new_case_node, possible_case)

        # Insert content after case-node
        elif self._sibling_reachability_graph.reaches(self._switch_node, compare_node):
            if len(intersecting_linear_case) != len(intersection):
                return
            possible_case.update_reaching_condition_for_insertion()
            if len(intersection) == len(case_constants_for_possible_case_node):
                new_seq = self.asforest._add_sequence_node_before(intersecting_linear_case[-1].child)
                self.asforest._remove_edge(possible_case.node.parent, possible_case.node)
                self.asforest._add_edge(new_seq, possible_case.node)
            else:
                remaining_cases = list(sorted(case_constants_for_possible_case_node - intersection, key=lambda const: const.value))
                self._new_case_nodes_for(possible_case.node, self._switch_node, remaining_cases)
                intersecting_linear_case[-1].break_case = False
        else:
            # TODO
            return

        self._sibling_reachability_graph.update_when_inserting_new_case_node(compare_node, self._switch_node)
        compare_node.clean()

    def _get_case_node_for_insertion(self, intersection: Set[Constant], intersecting_linear_case: Tuple[CaseNode]) -> Optional[CaseNode]:
        """
        Return the existing case-node where we want to insert the content of the possible-case node.

        If insertion is not possible, we return None.
        """
        uncommon_cases: List[CaseNode] = list()
        common_cases: List[CaseNode] = list()
        for case in intersecting_linear_case:
            if case.constant not in intersection:
                uncommon_cases.append(case)
            else:
                common_cases.append(case)
            if not case.child.is_empty_code_node:
                break
        if len(common_cases) != len(intersection):
            return None
        old_children_order = [c.child for c in intersecting_linear_case]
        for case_node, new_child in zip(common_cases + uncommon_cases, old_children_order):
            self.asforest._remove_edge(case_node, case_node.child)
            self.asforest._add_edge(case_node, new_child)
        self._switch_node.sort_cases()
        return common_cases[-1]

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
