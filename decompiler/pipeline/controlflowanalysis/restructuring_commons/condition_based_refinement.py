"""
Module for Condition Based Refinement
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from typing import List, Tuple, Set, Dict, Optional

from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, SeqNode
from decompiler.structures.ast.reachability_graph import SiblingReachability
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.logic.logic_condition import LogicCondition


@dataclass
class CandidateProperties:
    operands: List[LogicCondition]
    symbols: Set[str]

    @classmethod
    def initialize(cls, node: AbstractSyntaxTreeNode) -> CandidateProperties:
        operands = list(node.reaching_condition.operands) if node.reaching_condition.is_conjunction else [node.reaching_condition.copy()]
        symbols = set(node.reaching_condition.get_symbols_as_string())
        return CandidateProperties(operands, symbols)

    @property
    def number_of_interesting_operands(self) -> int:
        return len(self.operands)


class ConditionCandidates:
    def __init__(self, candidates: List[AbstractSyntaxTreeNode]):
        self._candidates: Dict[AbstractSyntaxTreeNode, CandidateProperties] = {c: CandidateProperties.initialize(c) for c in candidates}
        self._max_subexpression_size: int = max(
            (candidate_property.number_of_interesting_operands for candidate_property in self._candidates.values()), default=0
        )

    def __iter__(self):
        yield from self._candidates.items()

    @property
    def maximum_subexpression_size(self) -> int:
        if len(self._candidates) < 2:
            self._max_subexpression_size = 0
        else:
            all_sizes = [candidate_property.number_of_interesting_operands for candidate_property in self._candidates.values()]
            all_sizes.remove(max(all_sizes))
            self._max_subexpression_size = min(max(all_sizes), self._max_subexpression_size)
        return self._max_subexpression_size

    def get_next_subexpression(self):
        while (current_size := self.maximum_subexpression_size) > 0:
            childrens_to_consider = [c for c, p in self._candidates.items() if p.number_of_interesting_operands >= current_size]
            for child in childrens_to_consider:
                if child not in self._candidates:
                    continue
                if current_size > self.maximum_subexpression_size:
                    break
                if current_size == 1:
                    for operand in self._candidates[child].operands:
                        yield child, operand
                        if child not in self._candidates or current_size > self.maximum_subexpression_size:
                            break
                else:
                    for new_operands in combinations(self._candidates[child].operands, current_size):
                        yield child, LogicCondition.conjunction_of(new_operands)
                        if child not in self._candidates or current_size > self._max_subexpression_size:
                            break
            self._max_subexpression_size -= 1

    # def _get_logical_and_subexpressions_of(self, condition: LogicCondition) -> Iterator[LogicCondition]:
    #     """
    #     Get logical and-subexpressions of the input condition.
    #
    #     We get the following expressions
    #         - If the condition is a Symbol or a Not, the whole condition
    #         - If the condition is an And, every possible combination of its And-arguments
    #         - If the condition is an Or, either the condition if all arguments are Symbols or Not or nothing otherwise.
    #     """
    #     if condition.is_true:
    #         yield from ()
    #     elif condition.is_symbol or condition.is_negation or condition.is_disjunction:
    #         yield condition.copy()
    #     elif condition.is_conjunction:
    #         for sub_expression in self._all_subsets(condition.operands):
    #             if len(sub_expression) == 1:
    #                 yield sub_expression[0]
    #             else:
    #                 yield LogicCondition.conjunction_of(sub_expression)
    #     else:
    #         raise ValueError(f"Received a condition which is not a Symbol, Or, Not, or And: {condition}")
    #
    # @staticmethod
    # def _all_subsets(arguments: List[LogicCondition]) -> Iterator[Tuple[LogicCondition]]:
    #     """
    #     Given a set of elements, in our case z3-expressions, it returns an iterator that contains each combination of the input arguments
    #     as a tuple.
    #
    #     (1,2,3) --> Iterator[(1,2,3) (1,2) (1,3) (1,) (2,) (3,)]
    #     """
    #     return (arg for size in range(len(arguments), 0, -1) for arg in combinations(arguments, size))
    def remove(self, nodes_to_remove: List[AbstractSyntaxTreeNode]):
        for node in nodes_to_remove:
            del self._candidates[node]


class ConditionBasedRefinement:
    """
    Condition Based Refinement
    A high level example is given below to illustrate what this module does.
    Given something like:
    (if(b1∧b2) {...}) (if (¬b1) {...}) (if (¬b1 ∨ ¬b2) {...})

    This can be refined to something like:
    (if (¬b1) {...}) (if (b1∧b2) {...} else {...})
    Because ¬b1 ∨ ¬b2 is equivalent to ¬(b1∧b2) according to De Morgan's law.
    """

    def __init__(self, asforest: AbstractSyntaxForest):
        self.asforest: AbstractSyntaxForest = asforest
        self.root: AbstractSyntaxTreeNode = asforest.current_root

    @classmethod
    def refine(cls, asforest: AbstractSyntaxForest) -> None:
        if not isinstance(asforest.current_root, SeqNode):
            return
        if_refinement = cls(asforest)
        if_refinement._condition_based_refinement()

    def _condition_based_refinement(self) -> None:
        """
        Apply Condition Based Refinement on the root node.
            1. Find nodes with complementary reaching conditions.
            2. Find nodes that have some factors in common.
        """
        assert isinstance(self.root, SeqNode), f"The root node {self.root} should be a sequence node!"
        self._refine_code_nodes_with_complementary_conditions()
        newly_created_sequence_nodes: Set[SeqNode] = {self.root}

        while newly_created_sequence_nodes:
            for seq_node in self.asforest.get_sequence_nodes_topological_order(self.root):
                if seq_node not in newly_created_sequence_nodes:
                    continue
                newly_added_sequence_nodes = self._structure_sequence_node(seq_node)
                newly_created_sequence_nodes.update(newly_added_sequence_nodes)
                newly_created_sequence_nodes.remove(seq_node)

    def _refine_code_nodes_with_complementary_conditions(self) -> None:
        """
        Add Conditional nodes for complementary conditions.

        Group the children of the root node, which is a sequence node, in if-else statements
        """
        sequence_node = self.root
        assert isinstance(sequence_node, SeqNode), f"The root note {self.root} should be a sequence node!"

        processed_to_branch = set()
        sibling_reachability: SiblingReachability = self.asforest.get_sibling_reachability_of_children_of(sequence_node)
        for ast_node_i, ast_node_j in self._get_possible_complementary_nodes(sequence_node):
            if ast_node_i in processed_to_branch or ast_node_j in processed_to_branch:
                continue
            if not ast_node_i.reaching_condition.is_complementary_to(ast_node_j.reaching_condition):
                continue
            if self._can_place_condition_node_with_branches([ast_node_i, ast_node_j], sibling_reachability):
                condition_node = self.asforest.create_condition_node_with(ast_node_i.reaching_condition.copy(), [ast_node_i], [ast_node_j])

                sibling_reachability.merge_siblings_to(condition_node, [ast_node_i, ast_node_j])
                processed_to_branch.update([ast_node_i, ast_node_j])

        sequence_node._sorted_children = sibling_reachability.sorted_nodes()

    @staticmethod
    def _get_possible_complementary_nodes(sequence_node: SeqNode):
        interesting_children = [child for child in sequence_node.children if not child.reaching_condition.is_true]
        return combinations(interesting_children, 2)

    def _structure_sequence_node(self, sequence_node: SeqNode) -> Set[SeqNode]:
        """
        Look for children of the input sequence node that have sub-reaching conditions in common and add Conditional nodes, if possible.

        :param sequence_node: The sequence nodes whose children we want to structure.
        :return: The set of sequence nodes we add during structuring the given sequence node.
        """
        # visited = set()
        newly_created_sequence_nodes: Set[SeqNode] = set()
        sibling_reachability: SiblingReachability = self.asforest.get_sibling_reachability_of_children_of(sequence_node)
        subexpression_of_node = dict()
        condition_candidates = ConditionCandidates([child for child in sequence_node.children if not child.reaching_condition.is_true])
        for child, subexpression in condition_candidates.get_next_subexpression():
            # TODO Also stop if it is the last child with a reaching condition to consider!
            # TODO: only compute "useful" subexpressions!
            # for subexpression in self._get_logical_and_subexpressions_of(child.reaching_condition):
            true_cluster, false_cluster = self._cluster_by_condition(subexpression, condition_candidates)
            all_cluster_nodes = true_cluster + false_cluster

            if len(all_cluster_nodes) < 2:
                continue
            if self._can_place_condition_node_with_branches(all_cluster_nodes, sibling_reachability):
                condition_node = self.asforest.create_condition_node_with(subexpression, true_cluster, false_cluster)
                if len(true_cluster) > 1:
                    newly_created_sequence_nodes.add(condition_node.true_branch_child)
                if len(false_cluster) > 1:
                    newly_created_sequence_nodes.add(condition_node.false_branch_child)
                sibling_reachability.merge_siblings_to(condition_node, all_cluster_nodes)
                sequence_node._sorted_children = sibling_reachability.sorted_nodes()
                # TODO remove nodes from condition candidates!
                condition_candidates.remove(all_cluster_nodes)
                # break

        return newly_created_sequence_nodes

    def _cluster_by_condition(
        self, condition: LogicCondition, condition_candidates: ConditionCandidates
    ) -> Tuple[List[AbstractSyntaxTreeNode], List[AbstractSyntaxTreeNode]]:
        """
        Cluster the nodes in sequence_nodes according to the input condition.

        :param condition: The condition for which we check whether it or its negation is a subexpression of the list of input nodes.
        :param condition_candidates: TODO The sequence node we want to cluster.
        :return: A 2-tuple, where the first list is the set of nodes that have condition as subexpression, the second list is the set of
                 nodes that have the negated condition as subexpression.
        """
        true_children = []
        false_children = []
        symbols_of_condition = set(condition.get_symbols_as_string())
        negated_condition = None

        for node, properties in condition_candidates:
            if symbols_of_condition - properties.symbols:
                continue
            # TODO: we should not check this for the node we currently consider!
            if self._is_subexpression_of_cnf_formula(condition, node.reaching_condition):
                true_children.append(node)
            else:
                negated_condition = self._get_negated_condition_of(condition, negated_condition)
                if self._is_subexpression_of_cnf_formula(negated_condition, node.reaching_condition):
                    false_children.append(node)
        return true_children, false_children

    @staticmethod
    def _get_negated_condition_of(condition: LogicCondition, negated_condition: Optional[LogicCondition]) -> LogicCondition:
        """Negate the given condition and return it if negated condition is None, otherwise return `negated_condition`."""
        if negated_condition is None:
            return ~condition
        return negated_condition

    def _is_subexpression_of_cnf_formula(self, term: LogicCondition, expression: LogicCondition) -> bool:
        """
        Check whether the input term is a conjunction of a subset of clauses of a CNF expression.
        :param term: assumed to be CNF. May contain more than one clause.
        :param expression: no assumptions made.
        Examples:
        term = a∨b, expression = (a∨b)∧c, returns True
        term = a∨b, expression = a∨b∨c, returns False; expression's CNF is (a∨b∨c).
        term = (a∨b)∧c, expression = (a∨b)∧(b∨d)∧c, returns True
        term = ¬(a∨b), expression = ¬a∧¬b∧¬c, returns False; term is not CNF and will not match (although this case should not occur).
        """
        if (is_subexpression := self._preliminary_subexpression_checks(term, expression)) is not None:
            return is_subexpression

        expression_operands = expression.operands
        term_operands = term.operands
        numb_of_arg_expr = len(expression_operands) if expression.is_conjunction else 1
        numb_of_arg_term = len(term_operands) if term.is_conjunction else 1

        if numb_of_arg_expr <= numb_of_arg_term:
            return False

        subexpressions = [term] if numb_of_arg_term == 1 else term_operands
        expression_operands = (expression & term).operands
        return all(self._is_contained_in_logic_conditions(sub_expr, expression_operands) for sub_expr in subexpressions)

    @staticmethod
    def _preliminary_subexpression_checks(term: LogicCondition, expression: LogicCondition) -> Optional[bool]:
        """
        Check whether we can easily decide whether term is a conjunction of a subset of clauses of a CNF expression.

        - if expression is true or false, this is trivially not the case
        - if they are equal, this is the case
        - if expression does not imply term, this is not the case
        - if they are equivalent, this is the case.
        - if expression and term are not equivalent, but expression is still a symbol or negation, then it is not the case.
        """
        if expression.is_true or expression.is_false:
            return False
        if term.is_equal_to(expression):
            return True
        if not expression.does_imply(term):
            return False
        elif term.does_imply(expression):
            return True
        if expression.is_negation or expression.is_symbol:
            return False
        return None

    @staticmethod
    def _is_contained_in_logic_conditions(sub_expression: LogicCondition, logic_conditions: List[LogicCondition]) -> bool:
        """Check whether the given sub_expression is contained in the list of logic conditions"""
        return any(sub_expression.does_imply(condition) for condition in logic_conditions)

    @staticmethod
    def _can_place_condition_node_with_branches(branches: List[AbstractSyntaxTreeNode], sibling_reachability: SiblingReachability) -> bool:
        """
        Check whether we can construct a Condition node for the two given AST nodes that are children of the given sequence nodes.

        :param branches:
        :param sibling_reachability:
        :return:
        """
        return sibling_reachability.can_group_siblings(branches)
