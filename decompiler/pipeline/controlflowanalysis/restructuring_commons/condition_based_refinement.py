"""
Module for Condition Based Refinement
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from itertools import combinations
from typing import DefaultDict, Dict, Iterator, List, Optional, Set, Tuple, Union

from networkx import DiGraph, has_path

from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, SeqNode
from decompiler.structures.ast.reachability_graph import SiblingReachability
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.graphs.interface import GraphNodeInterface, GraphEdgeInterface
from decompiler.structures.graphs.nxgraph import NetworkXGraph
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.util.insertion_ordered_set import InsertionOrderedSet


@dataclass
class Formula:
    condition: LogicCondition
    ast_node: AbstractSyntaxTreeNode

    def __hash__(self) -> int:
        return id(self)

    def __eq__(self, other) -> bool:
        return isinstance(other, Formula) and hash(self) == hash(other)


@dataclass
class Clause:
    condition: LogicCondition
    formula: Formula

    def __hash__(self) -> int:
        return id(self)

    def __eq__(self, other) -> bool:
        return isinstance(other, Clause) and hash(self) == hash(other)


@dataclass
class Symbol:
    name: str

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other) -> bool:
        return isinstance(other, Symbol) and hash(self) == hash(other)


class ConditionCandidates:
    """A graph implementation handling conditions for the condition-based refinement algorithm."""

    def __init__(self, candidates: List[AbstractSyntaxTreeNode]) -> None:
        self._candidates: Dict[AbstractSyntaxTreeNode, Formula] = {c: Formula(c.reaching_condition, c) for c in candidates}
        self._logic_graph: DiGraph = DiGraph()
        self._formulas_containing_symbol: DefaultDict[Symbol, Set[Formula]] = defaultdict(set)
        self._symbols_of_formula: DefaultDict[Formula, Set[Symbol]] = defaultdict(set)
        self._removable_nodes: Set[Union[Formula, Clause, Symbol]] = set()
        self._initialize_logic_graph_and_dictionaries()
        self._clean_up()

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
        self._removable_nodes = set(symbol for symbol, formulas in self._formulas_containing_symbol.items() if len(formulas) == 1)

    @property
    def candidates(self) -> Iterator[AbstractSyntaxTreeNode]:
        yield from self._candidates

    def get_clauses(self, node: AbstractSyntaxTreeNode) -> List[LogicCondition]:
        return [clause.condition for clause in self._logic_graph.successors(self._candidates[node])]

    def get_symbols(self, node: AbstractSyntaxTreeNode) -> Set[str]:
        return {symbol.name for symbol in self._symbols_of_formula[self._candidates[node]]}

    @property
    def maximum_subexpression_size(self) -> int:
        if len(self._candidates) < 2:
            return 0
        all_sizes = [self._logic_graph.out_degree(formula) for formula in self._candidates.values()]
        all_sizes.remove(max(all_sizes))
        return max(all_sizes)

    def get_next_subexpression(self) -> Iterator[Tuple[AbstractSyntaxTreeNode, LogicCondition]]:
        """Consider Candidates in sequence-node order and start with the largest possible subexpression."""
        all_candidates = list(self._candidates)
        for ast_node in all_candidates:
            if ast_node not in self._candidates:
                continue
            if (max_expr_size := self.maximum_subexpression_size) == 0:
                break
            clauses = self.get_clauses(ast_node)
            current_size = min(len(clauses), max_expr_size)
            while current_size > 0 and ast_node in self._candidates:
                if current_size == 1:
                    for operand in clauses:
                        yield ast_node, operand
                else:
                    for new_operands in combinations(clauses, current_size):
                        yield ast_node, LogicCondition.conjunction_of(new_operands)
                current_size -= 1

    def remove_nodes(self, nodes_to_remove: List[AbstractSyntaxTreeNode]):
        """Remove the given nodes from the graph."""
        for node in nodes_to_remove:
            self._remove_formula(self._candidates[node])
        self._clean_up()

    def _clean_up(self):
        while self._removable_nodes:
            node = self._removable_nodes.pop()
            match node:
                case Formula():
                    self._remove_formula(node)
                case Clause():
                    self._remove_clause(node)
                case Symbol():
                    self._remove_symbol(node)

    def _remove_formula(self, formula: Formula):
        """Remove the given formula from the graph."""
        self._removable_nodes.update(self._logic_graph.successors(formula))
        self._logic_graph.remove_node(formula)
        for symbol in self._symbols_of_formula[formula]:
            self._remove_formula_from_formula_containing_symbol(formula, symbol)
        del self._candidates[formula.ast_node]

    def _remove_clause(self, clause: Clause):
        """Remove the given clause from the graph."""
        if clause.formula in self._logic_graph:
            if self._logic_graph.out_degree(clause.formula) == 1:
                self._removable_nodes.add(clause.formula)
            else:
                for symbol in (s for s in self._logic_graph.successors(clause) if not has_path(self._logic_graph, clause.formula, s)):
                    self._symbols_of_formula[clause.formula].remove(symbol)
                    self._remove_formula_from_formula_containing_symbol(clause.formula, symbol)
        self._logic_graph.remove_node(clause)

    def _remove_symbol(self, symbol: Symbol):
        """Remove the given symbol from the graph."""
        self._removable_nodes.update(self._logic_graph.predecessors(symbol))
        for formula in self._formulas_containing_symbol[symbol]:
            self._symbols_of_formula[formula].remove(symbol)
        self._logic_graph.remove_node(symbol)

    def _remove_formula_from_formula_containing_symbol(self, formula: Formula, symbol: Symbol):
        self._formulas_containing_symbol[symbol].remove(formula)
        if len(self._formulas_containing_symbol[symbol]) <= 1:
            self._removable_nodes.add(symbol)


#
#     # def get_next_subexpression(self) -> Iterator[Tuple[AbstractSyntaxTreeNode, LogicCondition]]:
#     #     """Get the next subexpression together with the node it comes from and start with the largest possible subexpression!"""
#     #     TODO: only compute "useful" subexpressions!
#     #     while (current_size := self.maximum_subexpression_size) > 0:
#     #         children_to_consider = [c for c, p in self._candidates.items() if p.number_of_interesting_operands >= current_size]
#     #         for child in children_to_consider:
#     #             if child not in self._candidates:
#     #                 continue
#     #             if current_size > self.maximum_subexpression_size:
#     #                 break
#     #             if current_size == 1:
#     #                 for operand in self._candidates[child].operands:
#     #                     yield child, operand
#     #                     if child not in self._candidates or current_size > self.maximum_subexpression_size:
#     #                         break
#     #             else:
#     #                 for new_operands in combinations(self._candidates[child].operands, current_size):
#     #                     yield child, LogicCondition.conjunction_of(new_operands)
#     #                     if child not in self._candidates or current_size > self._max_subexpression_size:
#     #                         break
#     #         self._max_subexpression_size = current_size - 1


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
        :param condition_candidates: TODO The children of the sequence node we want to cluster and that have a reaching condition.
        :return: A 2-tuple, where the first list is the set of nodes that have condition as subexpression, the second list is the set of
                 nodes that have the negated condition as subexpression.
        """
        true_children = []
        false_children = []
        symbols_of_condition = set(sub_expression.get_symbols_as_string())
        negated_condition = None
        for ast_node in condition_candidates.candidates:
            if symbols_of_condition - condition_candidates.get_symbols(ast_node):
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
        # Not sure whether we not want first the expression and then the term, since we do the same when inserting the condition-node.
        # However, we could compare which operands are removed, and then decide whether this is something we want.
        updated_expression_operands = (expression & term).operands
        if len(updated_expression_operands) > len(expression_operands) or sum(len(op) for op in updated_expression_operands) > sum(
            len(op) for op in expression_operands
        ):
            return False
        if len(updated_expression_operands) < len(expression_operands):
            return True
        return all(self._is_contained_in_logic_conditions(sub_expr, updated_expression_operands) for sub_expr in subexpressions)

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
