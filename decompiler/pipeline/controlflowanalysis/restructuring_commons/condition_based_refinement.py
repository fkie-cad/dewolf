"""
Module for Condition Based Refinement
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import chain, combinations
from typing import Dict, Iterator, List, Optional, Set, Tuple

from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, SeqNode
from decompiler.structures.ast.reachability_graph import SiblingReachability
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.util.insertion_ordered_set import InsertionOrderedSet
from networkx import DiGraph, has_path, subgraph_view


@dataclass(frozen=True, eq=False)
class Formula:
    """
    Dataclass for logic-formulas.
    - setting eq to false implies that two objects are equal and have the same hash iff they are the same object
    """

    condition: LogicCondition
    ast_node: AbstractSyntaxTreeNode

    def clauses(self) -> List[LogicCondition]:
        """
        Returns all clauses of the given formula in cnf-form.

        - formula = (a | b) & (c | d) & e, it returns [a | b, c | d, e] --> here each operand is a new logic-condition
        - formula = a | b | c, it returns [a | b | c] --> to ensure that we get a new logic-condition we copy it in this case.
        """
        return list(self.condition.operands) if self.condition.is_conjunction else [self.condition.copy()]


@dataclass(frozen=True, eq=False)
class Clause:
    """
    Dataclass for logic-clauses.
    - setting eq to false implies that two objects are equal and have the same hash iff they are the same object
    """

    condition: LogicCondition
    formula: Formula


@dataclass(frozen=True, eq=True)
class Symbol:
    """
    Dataclass for logic-symbols.
    - setting eq to true implies that two objects are equal and have the same hash iff their attributes are the same
    """

    name: str


class ConditionCandidates:
    """A graph implementation handling conditions for the condition-based refinement algorithm."""

    def __init__(self, candidates: List[AbstractSyntaxTreeNode]) -> None:
        """
        Init for the condition-candidates.

        param candidates:: list of all AST-nodes that we want to cluster into conditions.

        - _candidates: maps all relevant ast-nodes to their formula (reaching condition)
        - logic_graph: representation of all logic-formulas relevant
        - _formulas_containing_symbol: maps each symbol to all formulas that contain this symbol
        - _symbol_of_formula: maps to each formula all symbols that it contains.
        """
        self._candidates: Dict[AbstractSyntaxTreeNode, Formula] = {c: Formula(c.reaching_condition, c) for c in candidates}
        self._unconsidered_nodes: InsertionOrderedSet[AbstractSyntaxTreeNode] = InsertionOrderedSet()
        self._logic_graph: DiGraph = DiGraph()
        self._initialize_logic_graph()

    def _initialize_logic_graph(self):
        """Initialization of the logic-graph."""
        all_symbols = set()
        for formula in self._candidates.values():
            self._logic_graph.add_node(formula)
            for logic_clause in formula.clauses():
                self._logic_graph.add_edge(formula, clause := Clause(logic_clause, formula))
                for symbol_name in logic_clause.get_symbols_as_string():
                    self._logic_graph.add_edge(clause, symbol := Symbol(symbol_name))
                    self._logic_graph.add_edge(formula, symbol, auxiliary=True)
                    all_symbols.add(symbol)
        self._remove_symbols(set(symbol for symbol in all_symbols if self._symbol_only_in_one_formula(symbol)))

    @property
    def candidates(self) -> Iterator[AbstractSyntaxTreeNode]:
        """Iterates over all candidates considered for grouping into conditions."""
        yield from self._candidates

    @property
    def maximum_subexpression_size(self) -> int:
        """Returns the maximum possible subexpression that is relevant for considering for the clustering."""
        if len(self._candidates) < 2:
            return 0
        all_sizes = [self._formula_graph.out_degree(formula) for formula in self._candidates.values()]
        all_sizes.remove(max(all_sizes))
        return max(all_sizes)

    def get_symbols_of(self, node: AbstractSyntaxTreeNode) -> Set[str]:
        """Return all symbols that are used in the formula of the given ast-node."""
        return {symbol.name for symbol in self._auxiliary_graph.successors(self._candidates[node])}

    def get_next_subexpression(self) -> Iterator[Tuple[AbstractSyntaxTreeNode, LogicCondition]]:
        """Consider Candidates in sequence-node order and start with the largest possible subexpression."""
        self._unconsidered_nodes = InsertionOrderedSet(self._candidates)
        while self._unconsidered_nodes and len(self._candidates) > 1 and ((max_expr_size := self.maximum_subexpression_size) != 0):
            ast_node = self._unconsidered_nodes.pop(0)
            clauses = self._get_clauses(ast_node)
            current_size = min(len(clauses), max_expr_size)
            while current_size > 0 and ast_node in self._candidates:
                for new_operands in combinations(clauses, current_size):
                    yield ast_node, LogicCondition.conjunction_of(new_operands)
                current_size -= 1

    def remove_ast_nodes(self, nodes_to_remove: List[AbstractSyntaxTreeNode]):
        """Remove the given nodes from the graph."""
        # for node in nodes_to_remove:
        self._remove_formulas(set(self._candidates[node] for node in nodes_to_remove))
        # self._remove_nodes_from(set(self._candidates[node] for node in nodes_to_remove))

    @property
    def _auxiliary_graph(self) -> DiGraph:
        def filter_auxiliary_edges(source, sink):
            return self._logic_graph[source][sink].get("auxiliary", False)

        return subgraph_view(self._logic_graph, filter_edge=filter_auxiliary_edges)

    @property
    def _formula_graph(self) -> DiGraph:
        def filter_non_auxiliary_edges(source, sink):
            return self._logic_graph[source][sink].get("auxiliary", False) is False

        return subgraph_view(self._logic_graph, filter_edge=filter_non_auxiliary_edges)

    def _get_clauses(self, node: AbstractSyntaxTreeNode) -> List[LogicCondition]:
        """Return all clauses that are contained in the formula of the given ast-node."""
        return [clause.condition for clause in self._formula_graph.successors(self._candidates[node])]

    def _symbol_only_in_one_formula(self, symbol: Symbol):
        """Checks whether the symbol is only contained in one formula"""
        return self._auxiliary_graph.in_degree(symbol) == 1

    def _remove_formulas(self, removing_formulas: Set[Formula]):
        """
        Remove all formulas from the logic-graph and all nodes that have to be removed afterward.

        1. remove each clause that are contained in one of the formulas
        2. remove each formula from the logic-graph
        3. remove all symbols that are only contained in these formulas and one other formula,
            i.e., these are only contained in one formula after removing this formula.
        """
        symbols_of_formulas: Set[Symbol] = set()
        for formula in removing_formulas:
            self._logic_graph.remove_nodes_from(list(self._formula_graph.successors(formula)))
            symbols_of_formulas.update(self._auxiliary_graph.successors(formula))
            self._remove_formula_node(formula)
        self._remove_symbols(set(symbol for symbol in symbols_of_formulas if self._symbol_only_in_one_formula(symbol)))

    def _remove_formula_node(self, formula: Formula):
        """Remove the formula-node from the logic-graph, including updating the candidates and unconsidered-nodes"""
        self._logic_graph.remove_node(formula)
        del self._candidates[formula.ast_node]
        self._unconsidered_nodes.discard(formula.ast_node)

    def _remove_symbols(self, removing_symbols: Set[Symbol]):
        """
        Remove all symbols from the logic-graph and all nodes that have to be removed afterward.

        1. If we do not have to remove any symbol, we do noting
        2. Remove each symbols from the logic-graph
        3. For each clause that contains at least one of the symbols, we
              i. remove the clause
             ii. for each symbol of the clause, we check whether the symbol is in no other clause of the formula containing this clause
                 - True: remove the auxiliary-edge between the formula and the symbol
                         and add it to the new_single_formula_nodes iff it is one afterward.
                 - False: noting
            iii. If the formula that contains this clause has no children anymore, we remove it.
        4. Remove all symbols that are now only contained in one formula.
        """
        if not removing_symbols:
            return
        clauses_containing_any_symbol = set(chain.from_iterable(self._formula_graph.predecessors(symbol) for symbol in removing_symbols))
        self._logic_graph.remove_nodes_from(removing_symbols)
        new_single_formula_nodes = set()
        for clause in clauses_containing_any_symbol:
            symbols_of_clause = list(self._formula_graph.successors(clause))
            self._logic_graph.remove_node(clause)
            for clause_symbol in (s for s in symbols_of_clause if not has_path(self._formula_graph, clause.formula, s)):
                self._logic_graph.remove_edge(clause.formula, clause_symbol)
                if self._symbol_only_in_one_formula(clause_symbol):
                    new_single_formula_nodes.add(clause_symbol)
            if self._formula_graph.out_degree(clause.formula) == 0:
                self._remove_formula_node(clause.formula)
        self._remove_symbols(new_single_formula_nodes)

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
        """Init an instance of the condition-based refinement."""
        self.asforest: AbstractSyntaxForest = asforest
        self.root: AbstractSyntaxTreeNode = asforest.current_root

    @classmethod
    def refine(cls, asforest: AbstractSyntaxForest) -> None:
        """Apply the condition-based-refinement to the given abstract-syntax-forest."""
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
    def _get_possible_complementary_nodes(sequence_node: SeqNode) -> Iterator[Tuple[AbstractSyntaxTreeNode, AbstractSyntaxTreeNode]]:
        """Get all pairs of siblings that have complementary reaching-conditions."""
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
                condition_candidates.remove_ast_nodes(all_cluster_nodes)

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
