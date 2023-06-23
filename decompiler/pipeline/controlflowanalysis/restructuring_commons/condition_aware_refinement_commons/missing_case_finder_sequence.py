import logging
from collections import defaultdict
from typing import DefaultDict, Dict, Iterable, List, Optional, Set, Tuple, Union

from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.base_class_car import (
    BaseClassConditionAwareRefinement,
    CaseNodeCandidate,
)
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.missing_case_finder import (
    MissingCaseFinder,
)
from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CaseNode, ConditionNode, FalseNode, SeqNode, SwitchNode, TrueNode
from decompiler.structures.ast.reachability_graph import SiblingReachabilityGraph
from decompiler.structures.ast.switch_node_handler import ExpressionUsages
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.logic.logic_condition import LogicCondition, PseudoLogicCondition
from decompiler.structures.pseudo import Condition, Constant, OperationType


class MissingCaseFinderSequence(MissingCaseFinder):
    """
    Class in charge of finding missing case for switch nodes in sequences.

    A missing case is a sibling of a switch nodes that we did not find during the initial switch construction, that has all the properties
    for a case-node candidate.
    """

    def __init__(self, asforest: AbstractSyntaxForest):
        """
        self.asforest: The asforst where we try to construct switch nodes
        self._current_seq_node: The seq_node which we consider to find missing cases.
        self._switch_node_of_expression: a dictionary that maps to each expression the corresponding switch node.
        """
        super().__init__(asforest)
        self._current_seq_node: Optional[SeqNode] = None
        self._switch_node_of_expression: Dict[ExpressionUsages, SwitchNode] = dict()

    @classmethod
    def find(cls, asforest: AbstractSyntaxForest):
        """
        Try to find missing cases that are children of sequence nodes.

        - switch node of interest are switch nodes that have no default case since these are the switches where we can add cases.
        """
        missing_case_finder = cls(asforest)
        for seq_node in asforest.get_sequence_nodes_post_order(asforest.current_root):
            missing_case_finder._current_seq_node = seq_node

            missing_case_finder._initialize_switch_node_of_expression_dictionary()
            if not missing_case_finder._switch_node_of_expression:
                continue

            missing_case_finder._add_missing_cases()
            if seq_node in asforest:
                missing_case_finder._add_default_case()

            if seq_node in asforest:
                seq_node.clean()

    def _initialize_switch_node_of_expression_dictionary(self) -> None:
        """
        Initialize the dictionary self._switch_node_of_expression that maps to each switch-node, that is a child of the
        current sequence node, the tuple consisting of all SSA-versions of the variables that occur in the switch-expression.

        - Combines switch nodes if possible
        - Note, we can only add new cases (also default) if the switch node has no default case so far.
          So we consider only switch nodes that have no default case.
        - The list interesting_switch_nodes contains all switch-nodes, that are children of the current sequence node,
          that have no default case.
        - If there are two Switch nodes with the same switch-expression, then we do no consider them.
        """
        switch_node_of_expression: DefaultDict[ExpressionUsages, List[SwitchNode]] = defaultdict(list)
        for switch_node in [child for child in self._current_seq_node.children if isinstance(child, SwitchNode) and child.default is None]:
            used_variables = tuple(var.ssa_name for var in switch_node.expression.requirements)
            switch_node_of_expression[ExpressionUsages(switch_node.expression, used_variables)].append(switch_node)
        for switch_expression, same_expression_switch_nodes in switch_node_of_expression.items():
            if len(same_expression_switch_nodes) == 1:
                continue
            combinable_switch_nodes = [switch for switch in same_expression_switch_nodes if switch.reaching_condition.is_true]
            if len(combinable_switch_nodes) < 2 or self._repeating_cases(combinable_switch_nodes):
                continue
            if self._can_combine_switch_nodes(combinable_switch_nodes):
                if (switch_node := self.asforest.combine_switch_nodes(combinable_switch_nodes)) is not None:
                    switch_node_of_expression[switch_expression] = [switch_node]

        self._switch_node_of_expression = {
            expression: switch_nodes[0] for expression, switch_nodes in switch_node_of_expression.items() if len(switch_nodes) == 1
        }

    def _can_combine_switch_nodes(self, switch_nodes: List[SwitchNode]) -> bool:
        """
        Check whether we can combine the given switch nodes

        :param switch_nodes: A list of switch nodes we want to combine.
        """
        sibling_reachability = self.asforest.get_sibling_reachability_of_children_of(self._current_seq_node)
        # The switch cases are all different, thus which switch comes first is irrelevant for the switch-nodes, but maybe not for the other children
        sibling_reachability.remove_reachability_between(switch_nodes)
        new_node = self.asforest.factory.create_switch_node(switch_nodes[0].expression)
        sibling_reachability.merge_siblings_to(new_node, switch_nodes)
        return sibling_reachability.sorted_nodes() is not None

    def _add_missing_cases(self) -> None:
        """
        Find missing cases for the switch nodes that are the values of the attribute dictionary _switch_node_of_expression and add them.
        """
        if not (new_case_candidates_for_expression := self._get_case_candidates()):
            return

        sibling_reachability = self.asforest.get_sibling_reachability_of_children_of(self._current_seq_node)
        reachability_graph = SiblingReachabilityGraph(sibling_reachability)
        for expression, possible_new_cases in new_case_candidates_for_expression.items():
            if self._current_seq_node not in self.asforest:
                return
            self._add_new_case_nodes_to_switch_node(expression, possible_new_cases, reachability_graph)

    def _get_case_candidates(self) -> Dict[ExpressionUsages, Set[CaseNodeCandidate]]:
        """
        Check for each child of the current sequence node whether it is a potential case candidate for one of the switch nodes.

        Possible case-candidates are AST nodes whose reaching condition is not true, or branches of condition nodes.
        """
        new_case_candidates_for_expression: DefaultDict[ExpressionUsages, Set[CaseNodeCandidate]] = defaultdict(set)
        for child in self._current_seq_node.children:
            if (
                not child.reaching_condition.is_true
                and not child._has_descendant_code_node_breaking_ancestor_loop()
                and (candidate := self._find_switch_expression_and_case_condition_for(child.reaching_condition))
            ):
                expression, case_condition = candidate
                new_case_candidates_for_expression[expression].add(CaseNodeCandidate(child, expression, case_condition))

            elif isinstance(child, ConditionNode):
                for branch in child.children:
                    if not branch._has_descendant_code_node_breaking_ancestor_loop() and (
                        candidate := self._find_switch_expression_and_case_condition_for(branch.branch_condition)
                    ):
                        expression, case_condition = candidate
                        new_case_candidates_for_expression[expression].add(CaseNodeCandidate(branch.child, expression, case_condition))
        return dict(new_case_candidates_for_expression)

    def _find_switch_expression_and_case_condition_for(
        self, condition: LogicCondition
    ) -> Optional[Tuple[ExpressionUsages, LogicCondition]]:
        """
        Try to find a possible switch-expression and case condition for the given condition.

        - We take the first switch node we find, even if their may be another switch node for this condition.

        :param condition: The reaching condition of the AST node of which we want to know whether it can be a case node of a switch node.
        :return: If we find a switch node, the tuple of switch node and case condition and None otherwise.
        """
        for expression_usage, cond in self._get_constant_equality_check_expressions_and_conditions(condition):
            if expression_usage in self._switch_node_of_expression:
                return expression_usage, cond
        return None

    def _add_new_case_nodes_to_switch_node(
        self,
        expression: ExpressionUsages,
        case_node_candidates: Set[CaseNodeCandidate],
        sibling_reachability_graph: SiblingReachabilityGraph,
    ) -> None:
        """
        Check for each case node whether we can add it to the switch node.
        If it is possible, then add it.
        """
        switch_node = self._switch_node_of_expression[expression]
        cases_of_switch_node: Set[Constant] = {case.constant for case in switch_node.children}
        case_constants_for_node: Dict[AbstractSyntaxTreeNode, Set[Constant]] = dict()
        for possible_case in case_node_candidates:
            if not self._can_insert_case_node(possible_case.node, switch_node, sibling_reachability_graph):
                continue
            case_constants_for_node[possible_case.node] = set(self._get_case_constants_for_condition(possible_case.condition))
            # TODO:
            if intersection := (case_constants_for_node[possible_case.node] & cases_of_switch_node):
                compare_node = possible_case.node if possible_case.node.parent is switch_node.parent else possible_case.node.parent.parent
                intersecting_linear_cases = self.__get_linear_order_intersection_constants(switch_node, intersection)
                if sibling_reachability_graph.reaches(compare_node, switch_node):
                    # Insert content before case-node
                    if len(intersection) < len(case_constants_for_node[possible_case.node]):
                        continue
                    uncommon_cases = list()
                    common_cases = list()
                    for case in intersecting_linear_cases:
                        if case.constant not in intersection:
                            uncommon_cases.append(case)
                        else:
                            common_cases.append(case)
                        if not case.child.is_empty_code_node:
                            break
                    if len(common_cases) != len(intersection):
                        continue
                    old_children_order = [c.child for c in intersecting_linear_cases]
                    for case_node, old_child in zip(common_cases + uncommon_cases, old_children_order):
                        if case_node is common_cases[-1]:
                            if isinstance(possible_case.node.parent, (TrueNode, FalseNode)):
                                possible_case.node.reaching_condition &= possible_case.node.parent.branch_condition
                            possible_case.node.reaching_condition.substitute_by_true(possible_case.condition)
                            self.asforest._remove_edge(possible_case.node.parent, possible_case.node)
                            if old_child.is_empty_code_node:
                                self.asforest._add_edge(case_node, possible_case.node)
                                for descendant in possible_case.node.get_descendant_code_nodes():
                                    self.asforest._code_node_reachability_graph.add_reachability_from(
                                        (descendant, r) for r in self.asforest._code_node_reachability_graph.reachable_from(old_child)
                                    )
                                    self.asforest._code_node_reachability_graph.add_reachability_from(
                                        (r, descendant) for r in self.asforest._code_node_reachability_graph.reaching(old_child)
                                    )
                                    self.asforest._remove_node(old_child)
                            else:
                                new_seq = self.asforest._add_sequence_node_before(old_child)
                                self.asforest._add_edge(new_seq, possible_case.node)
                        else:
                            self.asforest._remove_edge(case_node, case_node.child)
                            self.asforest._add_edge(case_node, old_child)

                if sibling_reachability_graph.reaches(switch_node, compare_node):
                    if len(intersecting_linear_cases) != len(intersection):
                        continue
                    if len(intersection) == len(case_constants_for_node[possible_case.node]):
                        new_seq = self.asforest._add_sequence_node_before(intersecting_linear_cases[-1].child)
                        if isinstance(branch := possible_case.node.parent, (TrueNode, FalseNode)):
                            possible_case.node.reaching_condition &= branch.branch_condition
                        possible_case.node.reaching_condition.substitute_by_true(possible_case.condition)
                        #  TODO: update sibling reachability
                        self.asforest._remove_edge(possible_case.node.parent, possible_case.node)
                        self.asforest._add_edge(new_seq, possible_case.node)
                    else:
                        remaining_cases = list(
                            sorted(case_constants_for_node[possible_case.node] - intersection, key=lambda const: const.value)
                        )
                        self._new_case_nodes_for(possible_case.node, switch_node, remaining_cases)
                        intersecting_linear_cases[-1].break_case = False
                logging.info(f"We will handle in a later Issue how to insert Case nodes whose constant already exists.")
                compare_node.clean()
                # continue
            else:
                if isinstance(possible_case.node.parent, (TrueNode, FalseNode)):
                    possible_case.node.reaching_condition &= possible_case.node.parent.branch_condition
                possible_case.node.reaching_condition.substitute_by_true(possible_case.condition)
                sibling_reachability_graph.update_when_inserting_new_case_node(possible_case.node, switch_node)
                self.asforest._code_node_reachability_graph.remove_reachability_between([possible_case.node, switch_node])
                self._insert_case_node(possible_case.node, case_constants_for_node[possible_case.node], switch_node)
                cases_of_switch_node.update(case_constants_for_node[possible_case.node])
                if self._current_seq_node in self.asforest:
                    self._current_seq_node.clean()

    def __get_linear_order_intersection_constants(self, switch: SwitchNode, case_constants: Set[Constant]) -> Optional[Tuple[CaseNode]]:
        idx_break_cases = [
            idx + 1 for idx, case in enumerate(switch.cases) if case.break_case or case.does_end_with_return or case.does_end_with_continue
        ]
        assert len(switch.cases) == idx_break_cases[-1], "The last case-node must end with a break, continue or return."
        linear_cases = [switch.cases[i:j] for i, j in zip([0] + idx_break_cases, idx_break_cases)]
        for linear_case in linear_cases:
            case_constant_in_order = sum(case.constant in case_constants for case in linear_case)
            if case_constant_in_order > 0:
                if case_constant_in_order != len(case_constants):
                    return None
                else:
                    return linear_case
        return None

    @staticmethod
    def _can_insert_case_node(
        possible_case_node: AbstractSyntaxTreeNode, switch_node: SwitchNode, reachability_graph: SiblingReachabilityGraph
    ) -> bool:
        """
        Check whether we can insert the given ast-node into the switch node.

        -> Possible if inserting does not lead to cycles in the dependency graph
        -> Note, the possible case node is either a child of the same sequence node as the switch node or the branch of a condition node
           that is a child of the same sequence node as the switch node.
        """
        if possible_case_node.parent is switch_node.parent:
            compare_node = possible_case_node
        else:
            compare_node = possible_case_node.parent.parent
        return not (
            reachability_graph.has_path(compare_node, switch_node, no_edge=True)
            or reachability_graph.has_path(switch_node, compare_node, no_edge=True)
        )

    def _add_default_case(self):
        """Try to find a possible default case for each switch node that is a child of the current sequence node."""
        possible_default_cases = self._get_possible_default_cases_candidates(self._current_seq_node.children)
        sibling_reachability = self.asforest.get_sibling_reachability_of_children_of(self._current_seq_node)
        reachability_graph = SiblingReachabilityGraph(sibling_reachability)
        for switch_node in self._switch_node_of_expression.values():
            case_conditions_of_switch: PseudoLogicCondition = PseudoLogicCondition.initialize_from_conditions_or(
                [Condition(OperationType.equal, [switch_node.expression, child.constant]) for child in switch_node.children],
                self.condition_handler.logic_context,
            )
            for default_candidate in possible_default_cases:
                if self._can_insert_default_case(default_candidate, switch_node, reachability_graph, case_conditions_of_switch):
                    self.asforest.add_default_case(default_candidate.node, switch_node)
                    possible_default_cases.remove(default_candidate)
                    reachability_graph.update_when_inserting_new_case_node(default_candidate.node, switch_node)
                    break

    def _get_possible_default_cases_candidates(self, ast_nodes: Tuple[AbstractSyntaxTreeNode]) -> Set[CaseNodeCandidate]:
        """
        Computes for each child of the sequence node, that also has a switch node as child, the possible default candidates.

         -> For Condition Nodes either the true or false branch can be the default case
         -> All other nodes, except switch nodes, are possible default nodes.
        """
        default_case_candidates: Set[CaseNodeCandidate] = set()
        for node in ast_nodes:
            if isinstance(node, ConditionNode):
                reaching_condition_as_z3 = self._convert_to_z3_condition(node.reaching_condition)
                for child in node.children:
                    default_case_candidates.add(self._get_default_candidate_for_branch(child, reaching_condition_as_z3))
            elif not isinstance(node, SwitchNode):
                default_case_candidates.add(CaseNodeCandidate(node, None, self._convert_to_z3_condition(node.reaching_condition)))

        return {node for node in default_case_candidates if not node.condition.is_true}

    def _get_default_candidate_for_branch(
        self, branch: Union[TrueNode, FalseNode], reaching_condition_as_z3: PseudoLogicCondition
    ) -> CaseNodeCandidate:
        """Return the default node candidate for the given branch of the condition node."""
        branch_condition = branch.branch_condition
        return CaseNodeCandidate(
            branch.child, None, reaching_condition_as_z3 & self._convert_to_z3_condition(branch.child.reaching_condition & branch_condition)
        )

    @staticmethod
    def _can_insert_default_case(
        default_candidate: CaseNodeCandidate,
        switch_node: SwitchNode,
        reachability_graph: SiblingReachabilityGraph,
        case_conditions: PseudoLogicCondition,
    ) -> bool:
        """Check whether we can insert the given default case candidate to the given switch node."""
        seq_node_child = (
            default_candidate.node.parent.parent
            if isinstance(default_candidate.node.parent, (TrueNode, FalseNode))
            else default_candidate.node
        )
        if reachability_graph.has_path(seq_node_child, switch_node, no_edge=True) or reachability_graph.has_path(
            switch_node, seq_node_child, no_edge=True
        ):
            return False
        return (case_conditions | default_candidate.condition).is_true and (case_conditions & default_candidate.condition).is_false

    @staticmethod
    def _repeating_cases(combinable_switch_nodes: List[SwitchNode]) -> bool:
        """Check whether all cases occur only once."""
        case_constants: Set[Constant] = set()
        for switch_node in combinable_switch_nodes:
            for case_node in switch_node.cases:
                if case_node.constant in case_constants:
                    return True
                else:
                    case_constants.add(case_node.constant)
        return False
