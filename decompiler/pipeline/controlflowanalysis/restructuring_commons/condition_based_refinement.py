"""
Module for Condition Based Refinement
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from itertools import combinations
from typing import DefaultDict, Dict, Iterator, List, Optional, Set, Tuple, Union

from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, SeqNode
from decompiler.structures.ast.reachability_graph import SiblingReachability
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.logic.logic_condition import LogicCondition
from networkx import DiGraph, has_path


@dataclass
class Formula:
    condition: LogicCondition
    ast_node: AbstractSyntaxTreeNode

    def __hash__(self) -> int:
        return id(self)


@dataclass
class Clause:
    condition: LogicCondition
    formula: Formula

    def __hash__(self) -> int:
        return id(self)


@dataclass
class Symbol:
    name: str

    def __hash__(self):
        return hash(self.name)


class ConditionCandidates:
    """A graph implementation handling conditions for the condition-based refinement algorithm."""

    def __init__(self, candidates: List[AbstractSyntaxTreeNode]) -> None:
        self._candidates: Dict[AbstractSyntaxTreeNode, Formula] = {c: Formula(c.reaching_condition, c) for c in candidates}
        self._logic_graph: DiGraph = DiGraph()
        self._formulas_containing_symbol: DefaultDict[Symbol, Set[Formula]] = defaultdict(set)
        self._symbols_of_formula: DefaultDict[Formula, Set[Symbol]] = defaultdict(set)
        self._initialize_logic_graph_and_dictionaries()

    def _initialize_logic_graph_and_dictionaries(self):
        for formula in self._candidates.values():
            self._logic_graph.add_node(formula)
            formula_clauses = list(formula.condition.operands) if formula.condition.is_conjunction else [formula.condition.copy()]
            for logic_clause in formula_clauses:
                self._logic_graph.add_edge(formula, clause := Clause(logic_clause, formula))
                for symbol_name in logic_clause.get_symbols_as_string():
                    self._logic_graph.add_edge(clause, symbol := Symbol(symbol_name))
                    self._formulas_containing_symbol[symbol].add(formula)
                    self._symbols_of_formula[formula].add(symbol)
        self._remove_nodes_from(set(symbol for symbol, formulas in self._formulas_containing_symbol.items() if len(formulas) == 1))

    @property
    def candidates(self) -> Iterator[AbstractSyntaxTreeNode]:
        yield from self._candidates

    @property
    def maximum_subexpression_size(self) -> int:
        if len(self._candidates) < 2:
            return 0
        all_sizes = [self._logic_graph.out_degree(formula) for formula in self._candidates.values()]
        all_sizes.remove(max(all_sizes))
        return max(all_sizes)

    def get_symbols_of(self, node: AbstractSyntaxTreeNode) -> Set[str]:
        return {symbol.name for symbol in self._symbols_of_formula[self._candidates[node]]}

    def get_next_subexpression(self) -> Iterator[Tuple[AbstractSyntaxTreeNode, LogicCondition]]:
        """Consider Candidates in sequence-node order and start with the largest possible subexpression."""
        for ast_node in list(self._candidates):
            if ast_node not in self._candidates:
                continue
            if (max_expr_size := self.maximum_subexpression_size) == 0:
                break
            clauses = self._get_clauses(ast_node)
            current_size = min(len(clauses), max_expr_size)
            while current_size > 0 and ast_node in self._candidates:
                for new_operands in combinations(clauses, current_size):
                    yield ast_node, LogicCondition.conjunction_of(new_operands)
                current_size -= 1

    def remove_nodes(self, nodes_to_remove: List[AbstractSyntaxTreeNode]):
        """Remove the given nodes from the graph."""
        self._remove_nodes_from(set(self._candidates[node] for node in nodes_to_remove))

    def _get_clauses(self, node: AbstractSyntaxTreeNode) -> List[LogicCondition]:
        return [clause.condition for clause in self._logic_graph.successors(self._candidates[node])]

    def _remove_nodes_from(self, removable_nodes: Set[Union[Formula, Clause, Symbol]]):
        while removable_nodes:
            node = removable_nodes.pop()
            match node:
                case Formula():
                    removable_nodes.update(self._remove_formula(node))
                case Clause():
                    removable_nodes.update(self._remove_clause(node))
                case Symbol():
                    removable_nodes.update(self._remove_symbol(node))

    def _remove_formula(self, formula: Formula) -> Iterator[Union[Clause, Symbol]]:
        """Remove the given formula from the graph."""
        yield from self._logic_graph.successors(formula)
        self._logic_graph.remove_node(formula)
        for symbol in self._symbols_of_formula[formula]:
            yield from self._remove_symbol_from_formula(formula, symbol)
        del self._candidates[formula.ast_node]

    def _remove_clause(self, clause: Clause) -> Iterator[Union[Formula, Symbol]]:
        """Remove the given clause from the graph."""
        if clause.formula in self._logic_graph:
            if self._logic_graph.out_degree(clause.formula) == 1:
                yield clause.formula
            else:
                for symbol in (s for s in self._logic_graph.successors(clause) if not has_path(self._logic_graph, clause.formula, s)):
                    self._symbols_of_formula[clause.formula].remove(symbol)
                    yield from self._remove_symbol_from_formula(clause.formula, symbol)
        self._logic_graph.remove_node(clause)

    def _remove_symbol(self, symbol: Symbol) -> Iterator[Clause]:
        """Remove the given symbol from the graph."""
        yield from self._logic_graph.predecessors(symbol)
        for formula in self._formulas_containing_symbol[symbol]:
            self._symbols_of_formula[formula].remove(symbol)
        self._logic_graph.remove_node(symbol)

    def _remove_symbol_from_formula(self, formula: Formula, symbol: Symbol) -> Iterator[Symbol]:
        """
        Update the dictionaries and decides whether we also remove the given symbol, if the symbol is not contained in the given formula.
        """
        self._formulas_containing_symbol[symbol].remove(formula)
        if len(self._formulas_containing_symbol[symbol]) <= 1:
            yield symbol

    # def get_next_subexpression(self) -> Iterator[Tuple[AbstractSyntaxTreeNode, LogicCondition]]:
    #     """Get the next subexpression together with the node it comes from and start with the largest possible subexpression!"""
    #     current_size = self.maximum_subexpression_size
    #     while current_size > 0:
    #         for ast_node in [c for c, p in self._candidates.items() if self._logic_graph.out_degree(p) >= current_size]:
    #             if ast_node not in self._candidates:
    #                 continue
    #             if current_size > self.maximum_subexpression_size:
    #                 break
    #             clauses = self._get_clauses(ast_node)
    #             for new_operands in combinations(clauses, current_size):
    #                 yield ast_node, LogicCondition.conjunction_of(new_operands)
    #                 if ast_node not in self._candidates or current_size > self.maximum_subexpression_size:
    #                     break
    #         current_size = min(self.maximum_subexpression_size, current_size - 1)


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
        newly_created_sequence_nodes: Set[SeqNode] = set()
        sibling_reachability: SiblingReachability = self.asforest.get_sibling_reachability_of_children_of(sequence_node)
        condition_candidates = ConditionCandidates([child for child in sequence_node.children if not child.reaching_condition.is_true])
        for child, subexpression in condition_candidates.get_next_subexpression():
            true_cluster, false_cluster = self._cluster_by_condition(subexpression, child, condition_candidates)
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
                condition_candidates.remove_nodes(all_cluster_nodes)

        return newly_created_sequence_nodes

    def _cluster_by_condition(
        self, sub_expression: LogicCondition, node_with_subexpression: AbstractSyntaxTreeNode, condition_candidates: ConditionCandidates
    ) -> Tuple[List[AbstractSyntaxTreeNode], List[AbstractSyntaxTreeNode]]:
        """
        Cluster the nodes in sequence_nodes according to the input condition.

        :param sub_expression: The condition for which we check whether it or its negation is a subexpression of the list of input nodes.
        :param node_with_subexpression: The node of which the given sub_expression is a sub-expression
        :param condition_candidates: class-object handling all condition candidates.
        :return: A 2-tuple, where the first list is the set of nodes that have condition as subexpression, the second list is the set of
                 nodes that have the negated condition as subexpression.
        """
        true_children = []
        false_children = []
        symbols_of_condition = set(sub_expression.get_symbols_as_string())
        negated_condition = None
        for ast_node in condition_candidates.candidates:
            if symbols_of_condition - condition_candidates.get_symbols_of(ast_node):
                continue
            if ast_node == node_with_subexpression or self._is_subexpression_of_cnf_formula(sub_expression, ast_node.reaching_condition):
                true_children.append(ast_node)
            else:
                negated_condition = self._get_negated_condition_of(sub_expression, negated_condition)
                if self._is_subexpression_of_cnf_formula(negated_condition, ast_node.reaching_condition):
                    false_children.append(ast_node)
        return true_children, false_children

    @staticmethod
    def _get_negated_condition_of(condition: LogicCondition, negated_condition: Optional[LogicCondition]) -> LogicCondition:
        """Negate the given condition and return it if negated condition is None, otherwise return `negated_condition`."""
        if negated_condition is None:
            return ~condition
        return negated_condition

    def _is_subexpression_of_cnf_formula(self, sub_expression: LogicCondition, condition: LogicCondition) -> bool:
        """
        Check whether the input term is a conjunction of a subset of clauses of a CNF expression.
        :param sub_expression: assumed to be CNF. May contain more than one clause.
        :param condition: no assumptions made.
        Examples:
        sub_expression = a∨b, condition = (a∨b)∧c, returns True
        sub_expression = a∨b, condition = a∨b∨c, returns False; expression's CNF is (a∨b∨c).
        sub_expression = (a∨b)∧c, condition = (a∨b)∧(b∨d)∧c, returns True
        sub_expression = ¬(a∨b), condition = ¬a∧¬b∧¬c, returns False; sub_expression is not CNF and will not match (although this case should not occur).
        """
        if (is_subexpression := self._preliminary_subexpression_checks(sub_expression, condition)) is not None:
            return is_subexpression

        condition_operands = condition.operands
        sub_expression_operands = sub_expression.operands
        numb_of_arg_condition = len(condition_operands) if condition.is_conjunction else 1
        numb_of_arg_sub_expression = len(sub_expression_operands) if sub_expression.is_conjunction else 1

        if numb_of_arg_condition <= numb_of_arg_sub_expression:
            return False

        clauses_of_sub_expression = [sub_expression] if numb_of_arg_sub_expression == 1 else sub_expression_operands
        updated_expression_operands = (condition & sub_expression).operands
        if self._first_expression_is_complexer_than_second(updated_expression_operands, condition_operands):
            return False
        if len(updated_expression_operands) < len(condition_operands):
            return True
        return all(self._is_contained_in_logic_conditions(sub_expr, updated_expression_operands) for sub_expr in clauses_of_sub_expression)

    def _first_expression_is_complexer_than_second(self, expression_1: List[LogicCondition], expression_2: List[LogicCondition]):
        """Check whether the clauses belonging to the first-expression are more complex than the clauses of the second expression."""
        return len(expression_1) > len(expression_2) or sum(len(op) for op in expression_1) > sum(len(op) for op in expression_2)

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
