import operator
from collections import defaultdict
from dataclasses import dataclass
from functools import reduce
from itertools import combinations, permutations, product
from typing import DefaultDict, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.base_class_car import (
    BaseClassConditionAwareRefinement,
    CaseNodeCandidate,
)
from decompiler.pipeline.controlflowanalysis.restructuring_options import RestructuringOptions
from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CaseNode, CodeNode, ConditionNode, SeqNode, SwitchNode, TrueNode
from decompiler.structures.ast.reachability_graph import CaseDependencyGraph, LinearOrderDependency, SiblingReachability
from decompiler.structures.ast.switch_node_handler import ExpressionUsages
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import Constant, Expression
from decompiler.util.insertion_ordered_set import InsertionOrderedSet
from networkx import Graph


@dataclass
class SwitchNodeCandidate:
    """Class for possible Switch nodes."""

    expression: Expression
    cases: InsertionOrderedSet[CaseNodeCandidate]

    def construct_switch_cases(self) -> Iterator[Tuple[CaseNode, AbstractSyntaxTreeNode]]:
        """Construct Switch-case for itself."""
        for case_candidate in self.cases:
            yield case_candidate.construct_case_node(self.expression), case_candidate.node


class SwitchNodeProcessor:
    """Class for processing a possible switch node"""

    def __init__(self, asforest: AbstractSyntaxForest):
        self.asforest: AbstractSyntaxForest = asforest
        self.switch_candidate: Optional[SwitchNodeCandidate] = None
        self._sibling_reachability: Optional[SiblingReachability] = None
        self._switch_cases: Optional[Dict[AbstractSyntaxTreeNode, CaseNodeCandidate]] = None
        self._transitive_closure: Optional[SiblingReachability] = None

    @property
    def sibling_reachability(self) -> SiblingReachability:
        return self._sibling_reachability

    @property
    def transitive_closure(self) -> SiblingReachability:
        if self._transitive_closure is None and self.sibling_reachability is not None:
            self._transitive_closure = self.sibling_reachability.transitive_closure()
        return self._transitive_closure

    @property
    def switch_cases(self) -> Dict[AbstractSyntaxTreeNode, CaseNodeCandidate]:
        if self._switch_cases is None or len(self._switch_cases) != len(self.switch_candidate.cases):
            self._switch_cases = {case.node: case for case in self.switch_candidate.cases}
        return self._switch_cases

    def process(self, possible_switch_node: SwitchNodeCandidate, seq_node: SeqNode) -> bool:
        """
        Process the possible switch node such that we can insert it a switch-node, if possible.

        1. clean-up reachability, i.e., remove reachability between case-nodes that are not reachable from each other due to their condition
        2. remove case-candidates with the exact same constants, leaving the once that are most suitable (consider reachability)
        3. remove too nested cases, i.e., we do not want to insert too many conditions into the switch-cases
        4. Check whether we can place the switch-node and delete cases in order to make it insertable.

        Return whether the candidate is a switch-node.
        """
        self.switch_candidate = possible_switch_node
        self._sibling_reachability = self.asforest.get_sibling_reachability_of_children_of(seq_node)
        self._clean_up_reachability()
        self._remove_too_nested_cases()
        cases_with_same_condition: Dict[LogicCondition, InsertionOrderedSet[CaseNodeCandidate]] = self._get_conditions_with_multiple_cases()
        if cases_with_same_condition or not self._can_place_switch_node():
            self._remove_contradicting_cases(cases_with_same_condition)

        if len(possible_switch_node.cases) <= 1 or not self._can_place_switch_node():
            return False
        return True

    def _clean_up_reachability(self):
        """
        If two possible switch-cases reach each other, but they have no common possible cases, then we can remove the reachability.

        In these cases, the order is irrelevant and if one is executed the other will not be executed.
        """
        for candidate_1, candidate_2 in permutations(self.switch_candidate.cases, 2):
            if self.sibling_reachability.reaches(candidate_1.node, candidate_2.node) and not (
                set(self.asforest.switch_node_handler.get_constants_for(candidate_1.condition))
                & set(self.asforest.switch_node_handler.get_constants_for(candidate_2.condition))
            ):
                self.asforest._code_node_reachability_graph.remove_reachability_between([candidate_1.node, candidate_2.node])
                self.sibling_reachability.remove_reachability_between([candidate_1.node, candidate_2.node])

    def _get_conditions_with_multiple_cases(self) -> Dict[LogicCondition, InsertionOrderedSet[CaseNodeCandidate]]:
        """Return a dictionary mapping the case-conditions of cases with the same condition to these cases."""
        cases_of_condition: DefaultDict[LogicCondition, InsertionOrderedSet[CaseNodeCandidate]] = defaultdict(InsertionOrderedSet)
        for case_candidate in self.switch_candidate.cases:
            cases_of_condition[case_candidate.condition].add(case_candidate)
        return {condition: cases for condition, cases in cases_of_condition.items() if len(cases) > 1}

    def _remove_contradicting_cases(self, cases_with_same_condition: Dict[LogicCondition, InsertionOrderedSet[CaseNodeCandidate]]):
        """Remove switch-cases in order to be able to insert the possible case node."""
        interfering_cases = self._generate_interfering_cases_graph()
        self._remove_duplicated_conditions(cases_with_same_condition, interfering_cases)
        self._get_final_switch_cases(interfering_cases)

    def _generate_interfering_cases_graph(self) -> Graph:
        """
        Generate a graph whose nodes are the possible switch-cases, i.e., CaseNodeCandidates,
        and where there is an edge between two case-nodes if they can not be in the same switch node.
        """
        interfering_cases = Graph()
        interfering_cases.add_nodes_from(self.switch_cases.values())
        for node in self.__get_non_case_nodes():
            before_cases = self._cases_reaching(node)
            after_cases = self._cases_reachable_from(node)
            if before_cases and after_cases:
                interfering_cases.add_edges_from(product(before_cases, after_cases))
        return interfering_cases

    def __get_non_case_nodes(self):
        """Return all nodes not in the given set of cases."""
        for sibling in self.sibling_reachability.nodes:
            if sibling not in self.switch_cases:
                yield sibling

    def _remove_duplicated_conditions(
        self, cases_with_same_condition: Dict[LogicCondition, InsertionOrderedSet[CaseNodeCandidate]], interfering_cases: Graph
    ):
        for condition, same_condition_cases in cases_with_same_condition.items():
            non_interfering_cases = [
                (case1, case2)
                for case1, case2 in combinations(same_condition_cases, 2)
                if not interfering_cases.has_edge(case1.node, case2.node)
            ]
            while non_interfering_cases:
                case1, case2 = non_interfering_cases.pop()
                if case1 not in self.switch_candidate.cases or case2 not in self.switch_candidate.cases:
                    continue
                before_cases1 = self._cases_reaching(case1.node)
                after_cases2 = self._cases_reachable_from(case2.node)
                if len(before_cases1) > len(after_cases2):
                    self._remove_case_candidate(case2, interfering_cases, self._cases_reaching(case2.node), after_cases2)
                else:
                    self._remove_case_candidate(case1, interfering_cases, before_cases1, self._cases_reachable_from(case1.node))

    def _remove_case_candidate(
        self, case: CaseNodeCandidate, interfering_cases: Graph, before_cases: List[CaseNodeCandidate], after_cases: List[CaseNodeCandidate]
    ):
        """Remove the case-candidate as a case for the switch-node candidate"""
        self.switch_candidate.cases.remove(case)
        interfering_cases.add_edges_from(product(before_cases, after_cases))
        interfering_cases.remove_node(case)
        del self._switch_cases[case.node]

    def _cases_reaching(self, node: AbstractSyntaxTreeNode) -> List[CaseNodeCandidate]:
        """Switch Cases reaching the given node."""
        return [
            self.switch_cases[reaching] for reaching in self.transitive_closure.siblings_reaching(node) if reaching in self.switch_cases
        ]

    def _cases_reachable_from(self, node: AbstractSyntaxTreeNode) -> List[CaseNodeCandidate]:
        """Switch Cases reachable from the given node."""
        return [
            self.switch_cases[reachable]
            for reachable in self.transitive_closure.reachable_siblings_of(node)
            if reachable in self.switch_cases
        ]

    def _get_final_switch_cases(self, interfering_cases: Graph):
        """Get the final set of switch-cases, respectively, remove switch-cases untill we can order them."""
        assert len(self.switch_candidate.cases) == len(interfering_cases.nodes) and all(
            node in self.switch_candidate.cases for node in interfering_cases
        )
        degree_map = {node: degree for node, degree in interfering_cases.degree()}
        while interfering_cases:
            case = min(degree_map, key=lambda x: degree_map[x])
            for neighbor in list(interfering_cases.neighbors(case)):
                for n in interfering_cases.neighbors(neighbor):
                    degree_map[n] -= 1
                interfering_cases.remove_node(neighbor)
                del degree_map[neighbor]
                self.switch_candidate.cases.discard(neighbor)

            interfering_cases.remove_node(case)
            del degree_map[case]

    def _remove_too_nested_cases(self) -> None:
        """
        Check whether the cases are too nested. If this is the case, then we remove the cases that cause this problem.

        The sibling reachability tells us which ast-nodes must be reachable from their siblings node.
        If we have case nodes, say c1, c2, c3, c4 and c5 s.t. c1 reaches c3 and c4, c2 reaches c3 and c5 and c3 reaches c4 and c5
        then it is impossible to sort the cases without adding too many additional conditions.
        If they are too nested, then we remove the cases from the SwitchNodeCandidate that cause this problem.
        """
        case_dependency_graph = CaseDependencyGraph(
            self.sibling_reachability, tuple(poss_case.node for poss_case in self.switch_candidate.cases)
        )
        for cross_node in case_dependency_graph.get_too_nested_cases():
            self.switch_candidate.cases.remove(cross_node)

    def _can_place_switch_node(self) -> bool:
        """Check whether we can construct a switch node for the switch node candidate."""
        return self.sibling_reachability.can_group_siblings([case.node for case in self.switch_candidate.cases])


class InitialSwitchNodeConstructor(BaseClassConditionAwareRefinement):
    """Class that constructs switch nodes."""

    @classmethod
    def construct(cls, asforest: AbstractSyntaxForest, options: RestructuringOptions):
        """Constructs initial switch nodes if possible."""
        initial_switch_constructor = cls(asforest, options)
        for cond_node in asforest.get_condition_nodes_post_order(asforest.current_root):
            initial_switch_constructor._extract_case_nodes_from_nested_condition(cond_node)
        for seq_node in asforest.get_sequence_nodes_post_order(asforest.current_root):
            initial_switch_constructor._try_to_construct_initial_switch_node_for(seq_node)

    def _extract_case_nodes_from_nested_condition(self, cond_node: ConditionNode) -> None:
        """
        Extract CaseNodeCandidates from nested if-conditions.

        - Nested if-conditions can belong to a switch, i.e., Condition node whose condition is a '==' or '!=' comparison of a variable v and
          a constant, i.e.,  v == 2 or v != 2
        - The branch with the '!=' condition is
          (i) either a Condition node whose condition is a '==' or '!=' comparison of the same variable v and a different constant, or a
              Code node whose reaching condition is of this form, i.e., v == 1 or v != 1
         (ii) a sequence node whose first and last node is a condition node or code node with the properties described in (i)
        - We extract the conditions into a sequence, such that _try_to_construct_initial_switch_node_for can reconstruct the switch.
        """
        if cond_node.false_branch is None:
            return
        if first_case_candidate_expression := self._get_possible_case_candidate_for_condition_node(cond_node):
            if second_case_candidate := self._second_case_candidate_exists_in_branch(
                cond_node.false_branch_child, first_case_candidate_expression
            ):
                self._extract_conditions_to_obtain_switch(cond_node, second_case_candidate)

    def _get_possible_case_candidate_for_condition_node(self, cond_node: ConditionNode) -> Optional[ExpressionUsages]:
        """
        Check whether one branch condition is a possible switch case

        - Make sure, that the possible switch case is always the true-branch
        - If we find a candidate, return a CaseNodeCandidate containing the branch and the switch expression, else return None.
        """
        possible_expressions: List[Tuple[ExpressionUsages, LogicCondition]] = list(
            self._get_constant_equality_check_expressions_and_conditions(cond_node.condition)
        )
        if not possible_expressions and cond_node.false_branch_child:
            if possible_expressions := list(self._get_constant_equality_check_expressions_and_conditions(~cond_node.condition)):
                cond_node.switch_branches()

        if len(possible_expressions) == 1:
            return possible_expressions[0][0]

    def _second_case_candidate_exists_in_branch(
        self, ast_node: AbstractSyntaxTreeNode, first_case_expression: ExpressionUsages
    ) -> Optional[AbstractSyntaxTreeNode]:
        """
        Check whether a possible case candidate whose expression is equal to first_case_expression, is contained in the given ast_node.

        - The case candidate can either be:
            - the ast-node itself if the reaching condition matches a case-condition
            - the true or false branch if the ast_node is a condition node where the condition or negation matches a case-condition
            - the first or last child, if the node is a Sequence node and it has one of the above conditions.
        """
        candidates = [ast_node]
        if isinstance(ast_node, SeqNode):
            candidates += [ast_node.children[0], ast_node.children[-1]]
        for node in candidates:
            second_case_candidate = self._find_second_case_candidate_in(node)
            if second_case_candidate is not None and second_case_candidate[0] == first_case_expression:
                return second_case_candidate[1]

    def _find_second_case_candidate_in(self, ast_node: AbstractSyntaxTreeNode) -> Optional[Tuple[ExpressionUsages, AbstractSyntaxTreeNode]]:
        """Check whether the ast-node fulfills the properties of the second-case node to extract from nested conditions."""
        if isinstance(ast_node, ConditionNode):
            return self._get_possible_case_candidate_for_condition_node(ast_node), ast_node.true_branch_child
        if case_candidate := self._get_possible_case_candidate_for(ast_node):
            return case_candidate.expression, ast_node

    def _extract_conditions_to_obtain_switch(self, cond_node: ConditionNode, second_case_node: AbstractSyntaxTreeNode) -> None:
        """
        First of all, we extract both branches of the condition node and handle the reaching conditions.
        If a branch contains a sequence node, we propagate the reaching condition to its children. This ensures that
        the sequence node can be cleaned and the possible case candidates are all children of the same sequence node.
        """
        first_case_node = cond_node.true_branch_child
        first_case_node.reaching_condition &= cond_node.condition

        common_condition = LogicCondition.conjunction_of(self.__parent_conditions(second_case_node, cond_node))
        second_case_node.reaching_condition &= common_condition

        default_case_node = None

        if isinstance(second_case_node.parent, TrueNode):
            inner_condition_node = second_case_node.parent.parent
            assert isinstance(inner_condition_node, ConditionNode), "parent of True Branch must be a condition node."
            second_case_node.reaching_condition &= inner_condition_node.condition
            if default_case_node := inner_condition_node.false_branch_child:
                default_case_node.reaching_condition &= LogicCondition.conjunction_of(
                    (common_condition, ~inner_condition_node.condition, ~cond_node.condition)
                )

        cond_node.reaching_condition = self.condition_handler.get_true_value()
        self.asforest.extract_branch_from_condition_node(cond_node, cond_node.true_branch, update_reachability=False)
        new_seq_node = cond_node.parent
        if default_case_node:
            self.asforest._remove_edge(default_case_node.parent, default_case_node)
            self.asforest._add_edge(new_seq_node, default_case_node)
        self.asforest._remove_edge(second_case_node.parent, second_case_node)
        self.asforest._add_edge(new_seq_node, second_case_node)
        self.asforest.clean_up(new_seq_node)

    def _try_to_construct_initial_switch_node_for(self, seq_node: SeqNode) -> None:
        """
        Construct a switch node whose cases are children of the current sequence node.

        1. Find children of the given sequence node that are potential case nodes.
        2. If cases are too nested, i.e., putting them in one switch leads to too many additional conditions,
           then we remove these cases.
        3. If there exists an expression that belongs to at least two possible case candidates, then we construct a switch node.
        4. Then we place the switch node if possible.
        """
        switch_node_processor = SwitchNodeProcessor(self.asforest)
        for possible_switch_node in self._get_possible_switch_nodes_for(seq_node):
            if switch_node_processor.process(possible_switch_node, seq_node) is False:
                continue

            sibling_reachability = self.asforest.get_sibling_reachability_of_children_of(seq_node)
            switch_cases = list(possible_switch_node.construct_switch_cases())
            switch_node = self.asforest.create_switch_node_with(possible_switch_node.expression, switch_cases)
            case_dependency = CaseDependencyGraph.construct_case_dependency_for(self.asforest.children(switch_node), sibling_reachability)
            self._update_reaching_condition_for_case_node_children(switch_node)
            self._add_constants_to_cases(switch_node, case_dependency)
            switch_node.sort_cases()

    def _get_possible_switch_nodes_for(self, seq_node: SeqNode) -> List[SwitchNodeCandidate]:
        """
        Return a list of all possible switch candidates for the given sequence node.

        A switch candidate is a node whose reaching condition (for condition nodes combination of condition and reaching condition)
        is a disjunction of a conjunction of comparisons with the switch-expression and an arbitrary condition, that can be empty.
        """
        switch_candidate_for: Dict[ExpressionUsages, SwitchNodeCandidate] = dict()
        for child in seq_node.children:
            if case_candidate := self._get_possible_case_candidate_for(child):
                if case_candidate.expression in switch_candidate_for:
                    switch_candidate_for[case_candidate.expression].cases.add(case_candidate)
                else:
                    switch_candidate_for[case_candidate.expression] = SwitchNodeCandidate(
                        case_candidate.expression.expression, InsertionOrderedSet([case_candidate])
                    )
        return list(candidate for candidate in switch_candidate_for.values() if len(candidate.cases) > 1)

    def _get_possible_case_candidate_for(self, ast_node: AbstractSyntaxTreeNode) -> Optional[CaseNodeCandidate]:
        """
        Check whether the given node is a possible case candidate for a switch node.

        - If this is the case, then the function returns the switch variable
        - Otherwise, the function returns None.
        - Note: Cases can not end with a loop-break statement
        """
        possible_conditions: List[Tuple[ExpressionUsages, LogicCondition]] = list()
        if (
            possible_case_condition := ast_node.get_possible_case_candidate_condition()
        ) is not None and self._contains_no_violating_loop_break(ast_node):
            possible_conditions = list(self._get_constant_equality_check_expressions_and_conditions(possible_case_condition))

        if len(possible_conditions) == 1:
            expression_usage, condition = possible_conditions[0]
            return CaseNodeCandidate(ast_node, expression_usage, condition)

        return None

    def _update_reaching_condition_for_case_node_children(self, switch_node: SwitchNode):
        """
        Update the reaching condition for each case-node child.

        -> Note part of the reaching conditions is now handled by the case-node constant
        -> For case nodes, where one Branch is None, we also considered the if-condition for a possible case-condition.
           Therefore, we have to consider the if-condition and the reaching condition.
        -> Recall: We modified these Condition nodes such that the false branch is always None.
        """
        for case_node in switch_node.cases:
            assert (
                case_node.reaching_condition.is_disjunction_of_literals
            ), f"The condition of a case node should be a disjunction, but it is {case_node.reaching_condition}!"

            if isinstance(cond_node := case_node.child, ConditionNode) and cond_node.false_branch is None:
                self._update_condition_for(cond_node, case_node)

            case_node.child.reaching_condition = case_node.child.reaching_condition.substitute_by_true(case_node.reaching_condition)

    def _update_condition_for(self, cond_node: ConditionNode, case_node: CaseNode) -> None:
        """
        Update the condition of the given condition node, that is the child of the given case node, i.e. remove the reaching condition
        of the case node from the condition of the condition node.
        """
        remaining_if_condition = cond_node.reaching_condition & cond_node.condition
        if case_node.reaching_condition.does_imply(remaining_if_condition):
            self.asforest.replace_condition_node_by_single_branch(cond_node)
        if remaining_if_condition.is_conjunction:
            for sub_expr in remaining_if_condition.operands:
                if sub_expr.is_equivalent_to(case_node.reaching_condition):
                    cond_node.condition = remaining_if_condition.substitute_by_true(sub_expr)
                    cond_node.reaching_condition = self.condition_handler.get_true_value()
                    break

    def _add_constants_to_cases(self, switch_node: SwitchNode, case_dependency_graph: CaseDependencyGraph):
        """
        Add the constants to the cases of the given switch node and add new case-nodes if necessary.

        1. Construct the case-dependency graph and the linear-order-dependency-graph
        2. For each connected component of the linear-order-dependency-graph we add constant to the cases.
           -> Every connected component of the linear-ordered-dependency-graph has either size one or has at least one cross node.
              A cross node is a node that as in-degree or out-degree at least two.
        """
        linear_ordering_starting_at: Dict[CaseNode, List[CaseNode]] = dict(case_dependency_graph.find_partial_order_of_cases())
        linear_order_dependency_graph = LinearOrderDependency.from_linear_dependency(case_dependency_graph, linear_ordering_starting_at)

        for connected_component in linear_order_dependency_graph.get_weakly_connected_components():
            if len(connected_component) == 1:
                first_node_linear_order = connected_component.pop()
                self._add_constants_for_linear_order_starting_at(
                    first_node_linear_order, linear_ordering_starting_at, linear_order_dependency_graph
                )
            elif cross_nodes := linear_order_dependency_graph.get_cross_nodes_of(connected_component):
                conditions_considered_at: Dict[CaseNode, Dict[Constant, LogicCondition]] = dict()
                for starting_case in list(linear_order_dependency_graph.subgraph(connected_component).topological_order()):
                    considered_conditions = reduce(
                        operator.or_,
                        (conditions_considered_at[pred] for pred in linear_order_dependency_graph.cases_reaching(starting_case)),
                        dict(),
                    )
                    new_start_node = self._add_constants_for_linear_order_starting_at(
                        starting_case, linear_ordering_starting_at, linear_order_dependency_graph, considered_conditions
                    )
                    if starting_case in cross_nodes and starting_case != new_start_node:
                        cross_nodes = [new_start_node if id(n) == id(starting_case) else n for n in cross_nodes]
                    conditions_considered_at[new_start_node] = considered_conditions
                self._get_linear_order_for(cross_nodes, linear_ordering_starting_at, linear_order_dependency_graph)
            else:
                raise ValueError(f"Connected component {connected_component} has more than one vertex but no cross node.")

        self._clean_up_prev_cases(switch_node)
        self._clean_up_reaching_conditions(switch_node)

    def _add_constants_for_linear_order_starting_at(
        self,
        first_node: CaseNode,
        linear_ordering_starting_at: Dict[CaseNode, List[CaseNode]],
        linear_order_dependency_graph: LinearOrderDependency,
        considered_constants: Optional[Dict[Constant, LogicCondition]] = None,
    ) -> CaseNode:
        """
        Add constants for all nodes whose order starts at the given case node, i.e., nodes in linear_order_starting_at[first_node]'.
        We return the CaseNode that is the first node after adding constants for the case nodes.
        """
        linear_order = linear_ordering_starting_at[first_node]
        self._add_constants_to_cases_for(linear_order, considered_constants)
        new_order = self.handle_empty_fallthrough(linear_order)
        if first_node != new_order[0]:
            del linear_ordering_starting_at[first_node]
            linear_order_dependency_graph.substitute_case_node(first_node, new_order[0])
        linear_ordering_starting_at[new_order[0]] = new_order
        return new_order[0]

    def _clean_up_prev_cases(self, switch_node: SwitchNode):
        """
        Some cases have no constant because they have the same reaching condition as the previous case.
        Merge cases with the same reaching condition as the previous cases, setting a correct constant.
        """
        case_dependency_graph = CaseDependencyGraph(self.asforest.get_sibling_reachability_of_children_of(switch_node))
        linear_order_starting_at: Dict[CaseNode, List[CaseNode]] = dict(case_dependency_graph.find_partial_order_of_cases())
        for starting_point, ordered_case_nodes in linear_order_starting_at.items():
            new_ordered_case = list()
            for index, case_node in enumerate(ordered_case_nodes):
                if case_node.constant == Constant("add_to_previous_case"):
                    assert index > 0, f"Can not merge case node {case_node} with another case node!"
                    self.asforest.merge_case_nodes(ordered_case_nodes[index - 1], case_node)
                else:
                    new_ordered_case.append(case_node)
            linear_order_starting_at[starting_point] = new_ordered_case

    def _add_constants_to_cases_for(
        self, linear_order: List[CaseNode], considered_conditions: Optional[Dict[Constant, LogicCondition]] = None
    ) -> None:
        """
        Add for each case node of the given linear order the constant to the case, if it is unique one, i.e., if the case node does not
        belong to two constants and we have to insert another case node.

        1. Update the reaching condition of the case node, i.e., remove the parts that are not needed
           and update the reaching condition of its child.
        2. Add constants to cases:
           a) reaching condition is a literal -> case constants is clear and we add it.
           b) reaching condition is false -> the condition is already fulfilled, so we have to add this case node to the previous case.
           c) reaching condition is Or -> have to split it in multiple cases later. We solve this later.

        :param linear_order: A list of case nodes that must be in this order.
        :param considered_conditions: Set of conditions (literals) that are fulfilled when reaching the first case node of the linear order.
        """
        if considered_conditions is None:
            considered_conditions: Dict[Constant, LogicCondition] = dict()

        for case_node in linear_order:
            self._update_reaching_condition_of(case_node, considered_conditions)

            if case_node.reaching_condition.is_literal:
                case_node.constant = self._get_constant_compared_with_expression(case_node.reaching_condition)
                considered_conditions[case_node.constant] = case_node.reaching_condition
            elif case_node.reaching_condition.is_false:
                case_node.constant = Constant("add_to_previous_case")
            else:
                considered_conditions.update(
                    (c, l) for l, c in self.asforest.switch_node_handler.get_literal_and_constant_for(case_node.reaching_condition)
                )

    def _update_reaching_condition_of(self, case_node: CaseNode, considered_conditions: Dict[Constant, LogicCondition]) -> None:
        """
        Handle the reaching conditions of the case node and its child.

        - Remove the literals from the given case node reaching condition that are also contained in considered_conditions
          -> These conditions are already fulfilled.
        - Save the conditions that are fulfilled and not a literal of the reaching condition of the case node.
          -> The child node is only reached if these are not fulfilled.

        :param case_node: The case node where we want to update the reaching condition.
        :param considered_conditions: The conditions (literals) that are already fulfilled when we reach the given case node.
        """
        constant_of_case_node_literal = {
            const: literal
            for literal, const in self.asforest.switch_node_handler.get_literal_and_constant_for(case_node.reaching_condition)
        }
        exception_condition: LogicCondition = self.condition_handler.get_true_value()

        for constant, literal in considered_conditions.items():
            if constant in constant_of_case_node_literal:
                constant_of_case_node_literal.pop(constant)
            else:
                exception_condition &= ~literal
        case_node.reaching_condition = (
            LogicCondition.disjunction_of(constant_of_case_node_literal.values())
            if constant_of_case_node_literal
            else self.condition_handler.get_false_value()
        )
        if not exception_condition.is_true:
            case_node.child.reaching_condition = case_node.child.reaching_condition & exception_condition

    def handle_empty_fallthrough(self, linear_order: List[CaseNode]) -> List[CaseNode]:
        """
        Given a list of case nodes, that are ordered according to their reachability, we insert new empty case nodes before every case
        node that has a reaching condition that is a disjunction (and therefore not a constant yet) to be able to assign a constant to
        each case node.
        The function returns the new list of case nodes.
        """
        switch_cases = []
        for case in linear_order:
            if case.reaching_condition.is_disjunction:
                new_cases = self.prepend_empty_cases_to_case_with_or_condition(case)
                switch_cases.extend(new_cases)
            else:
                switch_cases.append(case)

        return switch_cases

    def prepend_empty_cases_to_case_with_or_condition(self, case: CaseNode) -> List[CaseNode]:
        """
        Given a case node whose reaching condition is a disjunction of literals, we create one case node for each literal and return
        the list of new case nodes.
        """
        condition_for_constant: Dict[Constant, LogicCondition] = dict()
        for l, c in self.asforest.switch_node_handler.get_literal_and_constant_for(case.reaching_condition):
            if c is None:
                raise ValueError(
                    f"The case node should have a reaching-condition that is a disjunction of literals, but it has the clause {l}."
                )
            else:
                condition_for_constant[c] = l
        sorted_constants: List[Constant] = sorted(condition_for_constant, key=lambda constant: constant.value)
        fallthrough_cases = self.asforest.split_case_node(case, sorted_constants)
        for case in fallthrough_cases:
            case.reaching_condition = condition_for_constant[case.constant]
        return fallthrough_cases

    def _get_linear_order_for(
        self,
        cross_nodes: List[CaseNode],
        linear_ordering_starting_at: Dict[CaseNode, List[CaseNode]],
        linear_order_dependency_graph: LinearOrderDependency,
    ) -> None:
        """
        Order the case nodes that have no clear ordering, i.e. the connected components of the linear-order-dependency graph that have
        cross edges.

        -> Note that every node of a connected component of size at least two in the linear-order-dependency graph every node is either
           a cross node or adjacent to a cross node.

        :param cross_nodes: The cross nodes of the component whose case nodes we want to order.
        :param linear_ordering_starting_at: The dictionary that maps the start point of each unique linear order to the linear-order.
        :param linear_order_dependency_graph: The linear-order-dependency-graph of the current switch node.
        """
        assert len(cross_nodes) <= 2, f"The number of cross nodes can be at most two. We eliminated all other case candidates before!"

        if len(cross_nodes) == 2:
            if linear_order_dependency_graph.has_path(cross_nodes[1], cross_nodes[0]):
                cross_nodes = [cross_nodes[1], cross_nodes[0]]
            assert not linear_order_dependency_graph.cross_nodes_are_too_nested(
                cross_nodes
            ), f"The structure of the component is too nested. We eliminated such structures before."

        # order predecessors cross_nodes[0]
        if case_nodes_to_order := set(linear_order_dependency_graph.cases_reaching(cross_nodes[0])):
            _, last_node_in_current_order = self._order_parallel_cases(case_nodes_to_order, linear_ordering_starting_at)
        else:
            last_node_in_current_order = None

        # Case cross_nodes[0]
        if last_node_in_current_order:
            self.asforest.add_reachability(last_node_in_current_order, cross_nodes[0])
        last_node_in_current_order = linear_ordering_starting_at[cross_nodes[0]][-1]

        # order nodes that are successors of cross_nodes[0] and predecessors of cross_nodes[1] (if 2 cross edges)
        if case_nodes_to_order := set(linear_order_dependency_graph.reachable_cases_of(cross_nodes[0])) - {cross_nodes[-1]}:
            first_node, last_node = self._order_parallel_cases(case_nodes_to_order, linear_ordering_starting_at)
            self.asforest.add_reachability(last_node_in_current_order, first_node)

        if len(cross_nodes) == 1:
            return

        last_node_in_current_order = last_node

        # Case cross_nodes[1]
        self.asforest.add_reachability(last_node_in_current_order, cross_nodes[1])
        last_node_in_current_order = linear_ordering_starting_at[cross_nodes[1]][-1]

        # order successors cross_nodes[1]
        if case_nodes_to_order := set(linear_order_dependency_graph.reachable_cases_of(cross_nodes[1])):
            first_node, _ = self._order_parallel_cases(case_nodes_to_order, linear_ordering_starting_at)
            self.asforest.add_reachability(last_node_in_current_order, first_node)

    def _order_parallel_cases(self, case_nodes: Set[CaseNode], linear_ordering_starting_at) -> Optional[Tuple[CaseNode, CodeNode]]:
        """
        Orders the linear ordered cases that are parallel, i.e., that are independent of each other but all have the same successor or
        predecessor case.

        :param case_nodes: The case nodes that start the parallel linear orders that we want to order.
        :param linear_ordering_starting_at: The dictionary that maps the start point of each unique linear order to the linear-order.
        :return: A tuple, where the first node is the first node of the new order and the second node is the last node of the new order.
        """
        if not case_nodes:
            return None
        sorted_case_nodes = sorted(case_nodes, key=lambda case_node: case_node.constant.value)
        ordered_cases = linear_ordering_starting_at[sorted_case_nodes[0]]
        current_condition = LogicCondition.conjunction_of([~case_node.reaching_condition for case_node in ordered_cases])

        for starting_case_node in sorted_case_nodes[1:]:
            self.asforest.add_reachability(ordered_cases[-1], starting_case_node)
            new_condition: LogicCondition = self.condition_handler.get_true_value()

            for case_node in linear_ordering_starting_at[starting_case_node]:
                self.asforest.create_condition_node_with(current_condition, [case_node.child], [])
                new_condition &= ~case_node.reaching_condition
                ordered_cases.append(case_node)
            current_condition = current_condition & new_condition

        return ordered_cases[0], ordered_cases[-1]

    def _clean_up_reaching_conditions(self, switch_node: SwitchNode) -> None:
        """
        Remove the reaching condition of each case node of the given switch node.

        - After constructing the switch node, we replaced each reaching condition of a case node by a case constant.
        - Every case node should have a literal as reaching condition.
        """
        for case_node in switch_node.cases:
            if case_node.reaching_condition.is_literal:
                case_node.reaching_condition = self.condition_handler.get_true_value()
            elif case_node.reaching_condition.is_false and case_node.constant == Constant("add_to_previous_case"):
                continue
            elif not case_node.reaching_condition.is_true:
                raise ValueError(f"{case_node} should have a literal as reaching condition, but RC = {case_node.reaching_condition}.")

    def __parent_conditions(self, second_case_node: AbstractSyntaxTreeNode, cond_node: ConditionNode):
        yield self.condition_handler.get_true_value()
        current_node = second_case_node
        while (current_node := current_node.parent) != cond_node:
            yield current_node.reaching_condition
