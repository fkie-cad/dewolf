import logging
from collections import defaultdict
from typing import DefaultDict, Dict, Iterable, List, Optional, Set, Tuple, Union

from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.base_class_car import (
    BaseClassConditionAwareRefinement,
    CaseNodeCandidate,
)
from decompiler.structures.ast.switch_node_handler import ExpressionUsages
from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CaseNode, ConditionNode, FalseNode, SeqNode, SwitchNode, TrueNode
from decompiler.structures.ast.reachability_graph import SiblingReachabilityGraph
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.logic.logic_condition import LogicCondition, PseudoLogicCondition
from decompiler.structures.pseudo import Condition, Constant, OperationType


class MissingCaseFinder(BaseClassConditionAwareRefinement):
    """
    Class in charge of finding missing case for switch nodes.

    A missing case is a sibling of a switch nodes that we did not find during the initial switch construction, that has all the properties
    for a case-node candidate.
    """

    def __init__(self, asforest: AbstractSyntaxForest):
        """
        self.asforest: The asforst where we try to construct switch nodes
        self._current_seq_node: The seq_node which we consider to find missing cases.
        self._switch_node_of_expression: a dictionary that maps to each expression the corresponding switch node.
        """
        self.asforest = asforest
        super().__init__(asforest.condition_handler)
        self._current_seq_node: Optional[SeqNode] = None
        self._switch_node_of_expression: Dict[ExpressionUsages, SwitchNode] = dict()

    @classmethod
    def find_in_sequence(cls, asforest: AbstractSyntaxForest):
        """
        Try to find missing cases that are children of sequence nodes.

        - switch node of interest are switch nodes that have no default case since these are the switches where we can add cases.
        """
        missing_case_finder = cls(asforest)
        for seq_node in asforest.get_sequence_nodes_post_order(asforest.current_root):
            missing_case_finder._current_seq_node = seq_node
            switch_nodes_of_interest = [child for child in seq_node.children if isinstance(child, SwitchNode) and child.default is None]
            if not switch_nodes_of_interest:
                continue

            missing_case_finder._initialize_switch_node_of_expression_dictionary(switch_nodes_of_interest)
            if not missing_case_finder._switch_node_of_expression:
                continue

            missing_case_finder._add_missing_cases()
            if seq_node in asforest:
                missing_case_finder._add_default_case()

            if seq_node in asforest:
                seq_node.clean()

    @classmethod
    def find_in_condition(cls, asforest: AbstractSyntaxForest):
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

        if not self._get_const_eq_check_expression_of_disjunction(case_condition) == switch_node.expression:
            return None

        new_case_constants = set(self._get_case_constants_for_condition(case_condition))
        if all(case.constant not in new_case_constants for case in switch_node.cases):
            return new_case_constants

    def _initialize_switch_node_of_expression_dictionary(self, interesting_switch_nodes: List[SwitchNode]) -> None:
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
        for switch_node in interesting_switch_nodes:
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

    def _find_switch_expression_and_case_condition_for(
        self, condition: LogicCondition
    ) -> Optional[Tuple[ExpressionUsages, LogicCondition]]:
        """
        Try to find a possible switch-expression and case condition for the given condition.

        - We take the first switch node we find, even if their may be another switch node for this condition.

        :param condition: The reaching condition of the AST node of which we want to know whether it can be a case node of a switch node.
        :return: If we find a switch node, the tuple of switch node and case condition and None otherwise.
        """
        for expression, cond in self._get_constant_equality_check_expressions_and_conditions(condition):
            used_variables = tuple(var.ssa_name for var in expression.requirements)
            expression_usage = ExpressionUsages(expression, used_variables)
            if expression_usage in self._switch_node_of_expression:
                return expression_usage, cond
        return None

    def _add_new_case_nodes_to_switch_node(
        self, expression: ExpressionUsages, case_node_candidates: Set[CaseNodeCandidate], reachability_graph: SiblingReachabilityGraph
    ) -> None:
        """
        Check for each case node whether we can add it to the switch node.
        If it is possible, then add it.
        """
        switch_node = self._switch_node_of_expression[expression]
        cases_of_switch_node: Set[Constant] = {case.constant for case in switch_node.children}
        case_constants_for_node: Dict[AbstractSyntaxTreeNode, Set[Constant]] = dict()
        for possible_case in case_node_candidates:
            if not self._can_insert_case_node(possible_case.node, switch_node, reachability_graph):
                continue
            case_constants_for_node[possible_case.node] = set(self._get_case_constants_for_condition(possible_case.condition))
            if intersection := (case_constants_for_node[possible_case.node] & cases_of_switch_node):
                logging.info(f"We will handle in a later Issue how to insert Case nodes whose constant already exists.")
                continue
            else:
                if isinstance(possible_case.node.parent, (TrueNode, FalseNode)):
                    possible_case.node.reaching_condition &= possible_case.node.parent.branch_condition
                possible_case.node.reaching_condition.substitute_by_true(possible_case.condition)
                reachability_graph.update_when_inserting_new_case_node(possible_case.node, switch_node)
                self._insert_case_node(possible_case.node, case_constants_for_node[possible_case.node], switch_node)
                cases_of_switch_node.update(case_constants_for_node[possible_case.node])
                if self._current_seq_node in self.asforest:
                    self._current_seq_node.clean()

    def _get_case_constants_for_condition(self, case_condition: LogicCondition) -> Iterable[Constant]:
        """Return all constants for the given condition."""
        assert case_condition.is_disjunction_of_literals, f"The condition {case_condition} can not be the condition of a case node."
        if condition := self._get_literal_condition(case_condition):
            yield self._get_constant_compared_in_condition(condition)
        else:
            for literal in case_condition.operands:
                condition = self._get_literal_condition(literal)
                yield self._get_constant_compared_in_condition(condition)

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

    def _new_case_nodes_for(
        self, new_case_node: AbstractSyntaxTreeNode, switch_node: SwitchNode, sorted_case_constants: List[Constant]
    ) -> List[CaseNode]:
        """Construct Case nodes for the given ast node with the given cases and given variable."""
        new_case_nodes = [
            self.asforest.factory.create_case_node(switch_node.expression, case_constant) for case_constant in sorted_case_constants
        ]
        self.asforest.add_case_nodes_with_one_child(new_case_nodes, switch_node, new_case_node)
        return new_case_nodes

    def _can_combine_switch_nodes(self, switch_nodes: List[SwitchNode]) -> bool:
        """
        Check whether we can combine the given switch nodes

        :param switch_nodes: A list of switch nodes we want to combine.
        """
        sibling_reachability = self.asforest.get_sibling_reachability_of_children_of(self._current_seq_node)
        new_node = self.asforest.factory.create_switch_node(switch_nodes[0].expression)
        sibling_reachability.merge_siblings_to(new_node, switch_nodes)
        return sibling_reachability.sorted_nodes() is not None

    @staticmethod
    def _can_insert_at_position(position: int, switch_node: SwitchNode) -> bool:
        """Check whether we can insert the Case node at the given position of the given switch node"""
        return (
            position == 0
            or switch_node.cases[position - 1].break_case
            or switch_node.cases[position - 1].does_end_with_return
            or switch_node.cases[position - 1].does_end_with_continue
        )

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
        removed_edges = [edge for edge in [(compare_node, switch_node), (switch_node, compare_node)] if edge in reachability_graph.edges]
        reachability_graph.remove_reachability_from(removed_edges)

        can_insert_case_node = not (
            reachability_graph.has_path(compare_node, switch_node) and reachability_graph.has_path(switch_node, compare_node)
        )
        reachability_graph.add_reachability_from(removed_edges)
        return can_insert_case_node

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
