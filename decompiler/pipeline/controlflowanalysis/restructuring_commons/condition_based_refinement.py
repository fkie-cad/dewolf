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
from decompiler.structures.graphs.interface import GraphNodeInterface, GraphEdgeInterface
from decompiler.structures.graphs.nxgraph import NetworkXGraph
from decompiler.structures.logic.logic_condition import LogicCondition


class CandidateNode(GraphNodeInterface):
    def __init__(self, condition: Union[LogicCondition, str]):
        self.node: Union[LogicCondition, str] = condition

    def __str__(self) -> str:
        """Return a string representation."""
        return str(self.node)

    def __eq__(self, other) -> bool:
        """Graph nodes should be equal for equal content."""
        return hash(self) == hash(other)

    def __hash__(self) -> int:
        """Graph nodes should always have a unique hash."""
        return id(self)

    def copy(self) -> CandidateNode:
        """Return a copy of the graph node."""
        return self.__class__(self.node.copy())


class FormulaNode(CandidateNode):
    def __init__(self, condition: LogicCondition):
        super().__init__(condition)


class ClauseNode(CandidateNode):
    def __init__(self, condition: LogicCondition):
        super().__init__(condition)


class SymbolNode(CandidateNode):
    def __init__(self, condition: str):
        super().__init__(condition)

    def __str__(self) -> str:
        return self.node

    def __hash__(self):
        return hash(self.node)

    def copy(self) -> SymbolNode:
        """Return a copy of the graph node."""
        return SymbolNode(self.node)


class CandidateEdge(GraphEdgeInterface):
    def __init__(self, source: CandidateNode, sink: CandidateNode):
        self._source: CandidateNode = source
        self._sink: CandidateNode = sink

    @property
    def source(self) -> CandidateNode:
        """Return the origin of the edge."""
        return self._source

    @property
    def sink(self) -> CandidateNode:
        """Return the target of the edge."""
        return self._sink

    def __eq__(self, other) -> bool:
        """Check whether two edges are equal."""
        return self.source == other.source and self.sink == other.sink

    def copy(self, source: Optional[GraphNodeInterface] = None, sink: Optional[GraphNodeInterface] = None) -> CandidateEdge:
        """
        Copy the edge, returning a new object.
        source -- (optional) The new source of the copied edge.
        sink -- (optional) The new sink of the copied edge.
        """
        return CandidateEdge(source if source is not None else self.source, sink if sink is not None else self.sink)


class ConditionCandidates:
    def __init__(self, candidates: List[AbstractSyntaxTreeNode]):
        self._candidates: Dict[AbstractSyntaxTreeNode, FormulaNode] = {c: FormulaNode(c.reaching_condition) for c in candidates}
        self._condition_graph: NetworkXGraph[CandidateNode, CandidateEdge] = NetworkXGraph[CandidateNode, CandidateEdge]()
        self._formulas_containing_symbol: DefaultDict[SymbolNode, Set[FormulaNode]] = defaultdict(set)
        self._initialize_graph()
        self._max_subexpression_size: int = max(
            (self._condition_graph.get_out_degree(formula_node) for formula_node in self._candidates.values()), default=0
        )

    def _initialize_graph(self) -> None:
        for condition in self._candidates.values():
            self._condition_graph.add_node(condition)
            operands = list(condition.node.operands) if condition.node.is_conjunction else [condition.node.copy()]
            for op in operands:
                self._condition_graph.add_edge(CandidateEdge(condition, op_candidate := ClauseNode(op)))
                for symbol in op.get_symbols_as_string():
                    self._condition_graph.add_edge(CandidateEdge(op_candidate, SymbolNode(symbol)))
                    self._formulas_containing_symbol[SymbolNode(symbol)].add(condition)

        single_symbols = set(symbol for symbol, condition in self._formulas_containing_symbol.items() if len(condition) == 1)
        self._remove_clauses_containing_symbols(single_symbols)

    def _remove_clauses_containing_symbols(self, single_symbols: Set[SymbolNode]):
        while single_symbols:
            symbol = single_symbols.pop()
            if not self._formulas_containing_symbol[symbol]:
                continue
            formula = self._formulas_containing_symbol[symbol].pop()
            clauses: Tuple[ClauseNode] = self._condition_graph.get_predecessors(symbol)  # type: ignore
            self._condition_graph.remove_node(symbol)
            for c in clauses:
                single_symbols.update(self._remove_clause(c, formula))

    def _remove_clause(self, clause: ClauseNode, formula: FormulaNode) -> Iterator[SymbolNode]:
        symbols_in_clause: Tuple[SymbolNode] = self._condition_graph.get_successors(clause)  # type: ignore
        self._condition_graph.remove_node(clause)
        for symbol in symbols_in_clause:
            if not self._condition_graph.has_path(formula, symbol):
                self._formulas_containing_symbol[symbol].remove(formula)
                if len(self._formulas_containing_symbol[symbol]) == 1:
                    yield symbol

    def get_symbols_of(self, node: AbstractSyntaxTreeNode) -> Set[str]:
        return set(n.node for n in self._condition_graph.iter_preorder(self._candidates[node]) if isinstance(n, SymbolNode))

    def get_operands(self, node: AbstractSyntaxTreeNode) -> List[LogicCondition]:
        return [clause.node for clause in self._condition_graph.get_successors(self._candidates[node])]

    @property
    def maximum_subexpression_size(self) -> int:
        if len(self._candidates) < 2:
            self._max_subexpression_size = 0
        else:
            all_sizes = [self._condition_graph.get_out_degree(formula_node) for formula_node in self._candidates.values()]
            all_sizes.remove(max(all_sizes))
            self._max_subexpression_size = min(max(all_sizes), self._max_subexpression_size)
        return self._max_subexpression_size

    # def get_next_subexpression(self) -> Iterator[Tuple[AbstractSyntaxTreeNode, LogicCondition]]:
    #     """Get the next subexpression together with the node it comes from and start with the largest possible subexpression!"""
    #     TODO: only compute "useful" subexpressions!
    #     while (current_size := self.maximum_subexpression_size) > 0:
    #         children_to_consider = [c for c, p in self._candidates.items() if p.number_of_interesting_operands >= current_size]
    #         for child in children_to_consider:
    #             if child not in self._candidates:
    #                 continue
    #             if current_size > self.maximum_subexpression_size:
    #                 break
    #             if current_size == 1:
    #                 for operand in self._candidates[child].operands:
    #                     yield child, operand
    #                     if child not in self._candidates or current_size > self.maximum_subexpression_size:
    #                         break
    #             else:
    #                 for new_operands in combinations(self._candidates[child].operands, current_size):
    #                     yield child, LogicCondition.conjunction_of(new_operands)
    #                     if child not in self._candidates or current_size > self._max_subexpression_size:
    #                         break
    #         self._max_subexpression_size = current_size - 1

    def __iter__(self) -> Iterator[AbstractSyntaxTreeNode]:
        yield from self._candidates.keys()

    def get_next_subexpression(self) -> Iterator[Tuple[AbstractSyntaxTreeNode, LogicCondition]]:
        """Consider nodes in order and start with largest possible."""
        all_candidates = list(self._candidates)
        for child in all_candidates:
            if child not in self._candidates:
                continue
            if (max_expr_size := self.maximum_subexpression_size) == 0:
                break
            clauses = self.get_operands(child)
            current_size = min(len(clauses), max_expr_size)
            while current_size > 0 and child in self._candidates:
                if current_size == 1:
                    for operand in clauses:
                        yield child, operand
                else:
                    for new_operands in combinations(clauses, current_size):
                        yield child, LogicCondition.conjunction_of(new_operands)
                current_size -= 1

    def remove(self, nodes_to_remove: List[AbstractSyntaxTreeNode]):
        for node in nodes_to_remove:
            formula = self._candidates[node]
            new_single_symbols = set()
            for clause in self._condition_graph.get_successors(formula):
                new_single_symbols.update(self._remove_clause(clause, formula))
            self._remove_clauses_containing_symbols(new_single_symbols)
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
                condition_candidates.remove(all_cluster_nodes)

        return newly_created_sequence_nodes

    def _cluster_by_condition(
        self, sub_expression: LogicCondition, node_with_subexpression: AbstractSyntaxTreeNode, condition_candidates: ConditionCandidates
    ) -> Tuple[List[AbstractSyntaxTreeNode], List[AbstractSyntaxTreeNode]]:
        """
        Cluster the nodes in sequence_nodes according to the input condition.

        :param sub_expression: The condition for which we check whether it or its negation is a subexpression of the list of input nodes.
        :param node_with_subexpression: The node of which the given sub_expression is a sub-expression
        :param condition_candidates: The children of the sequence node we want to cluster and that have a reaching condition.
        :return: A 2-tuple, where the first list is the set of nodes that have condition as subexpression, the second list is the set of
                 nodes that have the negated condition as subexpression.
        """
        true_children = []
        false_children = []
        symbols_of_condition = set(sub_expression.get_symbols_as_string())
        negated_condition = None
        for node in condition_candidates:
            if symbols_of_condition - condition_candidates.get_symbols_of(node):
                continue
            if node == node_with_subexpression or self._is_subexpression_of_cnf_formula(sub_expression, node.reaching_condition):
                true_children.append(node)
            else:
                negated_condition = self._get_negated_condition_of(sub_expression, negated_condition)
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
