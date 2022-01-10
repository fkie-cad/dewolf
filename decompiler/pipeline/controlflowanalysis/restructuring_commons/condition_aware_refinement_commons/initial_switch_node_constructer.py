from dataclasses import dataclass
from itertools import chain
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.base_class_car import (
    BaseClassConditionAwareRefinement,
    CaseNodeCandidate,
    ExpressionUsages,
)
from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CaseNode, CodeNode, ConditionNode, SeqNode, SwitchNode
from decompiler.structures.ast.reachability_graph import CaseDependencyGraph, LinearOrderDependency, SiblingReachability
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import Condition, Constant, Expression
from networkx import has_path


@dataclass
class SwitchNodeCandidate:
    """Class for possible Switch nodes."""

    expression: Expression
    cases: Set[CaseNodeCandidate]

    def construct_switch_cases(self) -> Iterator[Tuple[CaseNode, AbstractSyntaxTreeNode]]:
        """Construct Switch-case for itself."""
        for case_candidate in self.cases:
            yield (case_candidate.construct_case_node(self.expression), case_candidate.node)


class InitialSwitchNodeConstructor(BaseClassConditionAwareRefinement):
    """Class that constructs switch nodes."""

    def __init__(self, asforest: AbstractSyntaxForest):
        """
        self.asforest: The asforst where we try to construct switch nodes
        """
        self.asforest = asforest
        super().__init__(asforest.condition_handler)

    @classmethod
    def construct(cls, asforest: AbstractSyntaxForest):
        """Constructs initial switch nodes if possible."""
        initial_switch_constructor = cls(asforest)
        for seq_node in asforest.get_sequence_nodes_post_order(asforest.current_root):
            initial_switch_constructor._try_to_construct_initial_switch_node_for(seq_node)

    def _try_to_construct_initial_switch_node_for(self, seq_node: SeqNode) -> None:
        """
        Construct a switch node whose cases are children of the current sequence node.

        1. Find children of the given sequence node that are potential case nodes.
        2. If cases are too nested, i.e., putting them in one switch leads to too many additional conditions,
           then we remove these cases.
        3. If there exists an expression that belongs to at least two possible case candidates, then we construct a switch node.
        4. Then we place the switch node if possible.
        """
        for possible_switch_node in self._get_possible_switch_nodes_for(seq_node):
            sibling_reachability = self.asforest.get_sibling_reachability_of_children_of(seq_node)
            if len(possible_switch_node.cases) > 1:
                self._remove_too_nested_cases(possible_switch_node, sibling_reachability)
            if len(possible_switch_node.cases) > 1 and self._can_place_switch_node(possible_switch_node, sibling_reachability):
                switch_cases = list(possible_switch_node.construct_switch_cases())
                switch_node = self.asforest.create_switch_node_with(possible_switch_node.expression, switch_cases)
                case_dependency = CaseDependencyGraph.construct_case_dependency_for(
                    self.asforest.children(switch_node), sibling_reachability
                )
                self._update_reaching_condition_for_case_node_children(switch_node)
                self._add_constants_to_cases(switch_node, case_dependency)
                switch_node.sort_cases()

    def _get_possible_switch_nodes_for(self, seq_node: SeqNode) -> List[SwitchNodeCandidate]:
        """
        Return a list of all possible switch candidates for the given sequence node.

        A switch candidate is a node whose reaching condition (for condition nodes combination of condition and reaching condition)
        is an disjunction of a conjunction of comparisons with the switch-expression and an arbitrary condition, that can be empty.
        """
        switch_candidate_for: Dict[ExpressionUsages, SwitchNodeCandidate] = dict()
        for child in seq_node.children:
            if case_candidate := self._get_possible_case_candidate_for(child):
                if case_candidate.expression in switch_candidate_for:
                    switch_candidate_for[case_candidate.expression].cases.add(case_candidate)
                else:
                    switch_candidate_for[case_candidate.expression] = SwitchNodeCandidate(
                        case_candidate.expression.expression, {case_candidate}
                    )

        self._remove_case_candidates_with_same_condition(switch_candidate_for.values())
        return list(switch_candidate_for.values())

    def _get_possible_case_candidate_for(self, ast_node: AbstractSyntaxTreeNode) -> Optional[CaseNodeCandidate]:
        """
        Check whether the given node is a possible case candidate for a switch node.

        - If this is the case, then the function returns the switch variable
        - Otherwise, the function returns None.
        - Note: Cases can not end with a loop-break statement
        """
        possible_expressions: List[Tuple[Expression, LogicCondition]] = list()
        if (possible_case_condition := ast_node.get_possible_case_candidate_condition()) is not None:
            possible_expressions = list(self._get_constant_equality_check_expressions_and_conditions(possible_case_condition))

        if len(possible_expressions) == 1:
            expression, condition = possible_expressions[0]
            used_variables = tuple(var.ssa_name for var in expression.requirements)
            return CaseNodeCandidate(ast_node, ExpressionUsages(expression, used_variables), possible_expressions[0][1])

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
                conditions_considered_at: Dict[CaseNode, Set[LogicCondition]] = dict()
                for starting_case in list(linear_order_dependency_graph.subgraph(connected_component).topological_order()):
                    considered_conditions = set(
                        chain(*(conditions_considered_at[pred] for pred in linear_order_dependency_graph.cases_reaching(starting_case)))
                    )
                    new_start_node = self._add_constants_for_linear_order_starting_at(
                        starting_case, linear_ordering_starting_at, linear_order_dependency_graph, considered_conditions
                    )
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
        considered_conditions: Optional[Set[CaseNode]] = None,
    ) -> CaseNode:
        """
        Add constants for all nodes whose order starts at the given case node, i.e., nodes in linear_order_starting_at[first_node]'.
        We return the CaseNode that is the first node after adding constants for the case nodes.
        """
        linear_order = linear_ordering_starting_at[first_node]
        self._add_constants_to_cases_for(linear_order, considered_conditions)
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
        self, linear_order: List[CaseNode], considered_conditions: Optional[Set[LogicCondition]] = None
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
            considered_conditions: Set[LogicCondition] = set()

        for case_node in linear_order:
            self._update_reaching_condition_of(case_node, considered_conditions)

            if case_node.reaching_condition.is_literal:
                condition: Condition = self._get_literal_condition(case_node.reaching_condition)
                case_node.constant = self._get_constant_compared_in_condition(condition)
                considered_conditions.add(case_node.reaching_condition)
            elif case_node.reaching_condition.is_false:
                case_node.constant = Constant("add_to_previous_case")
            else:
                considered_conditions.update(case_node.reaching_condition.operands)

    def _update_reaching_condition_of(self, case_node: CaseNode, considered_conditions: Set[LogicCondition]) -> None:
        """
        Handle the reaching conditions of the case node and its child.

        - Remove the literals from the given case node reaching condition that are also contained in considered_conditions
          -> These conditions are already fulfilled.
        - Save the conditions that are fulfilled and not a literal of the reaching condition of the case node.
          -> The child node is only reached if these are not fulfilled.

        :param case_node: The case node where we want to update the reaching condition.
        :param considered_conditions: The conditions (literals) that are already fulfilled when we reach the given case node.
        """
        literals_of_case_node = set(case_node.reaching_condition.get_literals())
        exception_condition: LogicCondition = self.condition_handler.get_true_value()

        for literal in considered_conditions:
            literal_of_case = self._is_literal_of_current_case_node(literal, literals_of_case_node)
            if literal_of_case is not None:
                literals_of_case_node.remove(literal_of_case)
            else:
                exception_condition &= ~literal
        case_node.reaching_condition = (
            LogicCondition.disjunction_of(literals_of_case_node) if literals_of_case_node else self.condition_handler.get_false_value()
        )
        if not exception_condition.is_true:
            case_node.child.reaching_condition = case_node.child.reaching_condition & exception_condition

    def _is_literal_of_current_case_node(
        self, condition: LogicCondition, literals_of_current_case_node: Set[LogicCondition]
    ) -> Optional[LogicCondition]:
        """
        Check whether the given literal is contained in the set of literals. If this is the case, we return the literal.

        Note, two literals can have different names (be different symbols) but still are the same.
        Therefore we also check whether the z3-conditions are equivalent.

        :param condition: The literal, which is a z3-symbol, of which we want to know whether its condition is in the set of literals.
        :param literals_of_current_case_node: The set of literals, which are all z3-symbols.
        :return: The literals in the given set that is equivalent to the given literal or None if it is not equivalent to any literal.
        """
        if condition in literals_of_current_case_node:
            return condition

        z3_condition = self._z3_condition_of_literal(condition)
        for literal in literals_of_current_case_node:
            if self._z3_condition_of_literal(literal).is_equivalent_to(z3_condition):
                return literal
        return None

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
        Given a case node whose reaching condition is an disjunction of literals, we create one case node for each literal and return
        the list of new case nodes.
        """
        condition_for_constant: Dict[Constant, LogicCondition] = dict()
        for literal in case.reaching_condition.operands:
            if condition := self._get_literal_condition(literal):
                condition_for_constant[self._get_constant_compared_in_condition(condition)] = literal
            else:
                raise ValueError(
                    f"The case node should have a reaching-condition that is a disjunction of literals, but it has the clause {literal}."
                )
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
            if has_path(linear_order_dependency_graph, cross_nodes[1], cross_nodes[0]):
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

    @staticmethod
    def _remove_too_nested_cases(possible_switch_node: SwitchNodeCandidate, sibling_reachability: SiblingReachability) -> None:
        """
        Check whether the cases are too nested. If this is the case, then we remove the cases that cause this problem.

        The sibling reachability tells us which ast-nodes must be reachable from their siblings node.
        If we have case nodes, say c1, c2, c3, c4 and c5 s.t. c1 reaches c3 and c4, c2 reaches c3 and c5 and c3 reaches c4 and c5
        then it is impossible to sort the cases without adding too many additional conditions.
        If they are too nested, then we remove the cases from the SwitchNodeCandidate that cause this problem.
        """
        case_dependency_graph = CaseDependencyGraph(sibling_reachability, tuple(poss_case.node for poss_case in possible_switch_node.cases))
        for cross_node in case_dependency_graph.get_too_nested_cases():
            possible_switch_node.cases.remove(cross_node)

    @staticmethod
    def _can_place_switch_node(switch_node_candidate: SwitchNodeCandidate, sibling_reachability: SiblingReachability) -> bool:
        """
        Check whether we can construct a switch node for the switch node candidate.

        :param switch_node_candidate: The switch node candidate that we want to place.
        :param sibling_reachability: The reachability of all children of the sequence node.
        """
        copy_sibling_reachability = sibling_reachability.copy()
        new_node = SwitchNode(switch_node_candidate.expression, LogicCondition.generate_new_context())
        copy_sibling_reachability.merge_siblings_to(new_node, [case_candidate.node for case_candidate in switch_node_candidate.cases])
        return copy_sibling_reachability.sorted_nodes() is not None

    @staticmethod
    def _remove_case_candidates_with_same_condition(switch_candidates: Iterable[SwitchNodeCandidate]) -> None:
        """
        Remove one of two case candidates if they have the same condition.

        Since they were not combined before, they can not be combined and we do not know which to pick.
        """
        for switch_candidate in switch_candidates:
            considered_conditions = set()
            for case_candidate in list(switch_candidate.cases):
                if case_candidate.condition in considered_conditions:
                    switch_candidate.cases.remove(case_candidate)
                else:
                    considered_conditions.add(case_candidate.condition)

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
