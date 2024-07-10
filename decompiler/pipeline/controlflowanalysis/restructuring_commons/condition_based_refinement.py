"""
Module for Condition Based Refinement
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import chain, combinations
from typing import Dict, Iterator, List, Literal, Optional, Set, Tuple

from decompiler.pipeline.controlflowanalysis.restructuring_options import CbfNodeOrder, RestructuringOptions
from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, ConditionNode, SeqNode
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

    ast_node: AbstractSyntaxTreeNode

    @property
    def is_if_else_formula(self) -> bool:
        """
        Check whether the condition of the formula belongs to an if-else condition.
        The condition-node can only be grouped if it has not reaching-condition.
        """
        return self.ast_node.reaching_condition.is_true and not self.ast_node.is_single_branch

    @property
    def condition(self) -> LogicCondition:
        """
        Return the condition of the formula.

        If the AST-node of the formula as a reaching-condition that is not true, we return the reaching-condition.
        Otherwise,  the AS-node must be a condition node and we return its condition.
        """
        if self.ast_node.reaching_condition.is_true:
            assert isinstance(self.ast_node, ConditionNode), "The ast-node must be a condition node if the RC is true"
            return self.ast_node.condition
        return self.ast_node.reaching_condition

    def clauses(self) -> List[Clause]:
        """
        Returns all clauses of the given formula in cnf-form.

        - formula = (a | b) & (c | d) & e, it returns [a | b, c | d, e] --> here each operand is a new logic-condition
        - formula = a | b | c, it returns [a | b | c] --> to ensure that we get a new logic-condition we copy it in this case.
        """
        if self.is_if_else_formula:
            return [ClauseFormula(self.ast_node.condition.copy(), self)]
        else:
            clauses = list(self.condition.operands) if self.condition.is_conjunction else [self.condition.copy()]
            return [Clause(c, self) for c in clauses]


@dataclass(frozen=True, eq=False)
class Clause:
    """
    Dataclass for logic-clauses.
    - setting eq to false implies that two objects are equal and have the same hash iff they are the same object
    """

    condition: LogicCondition
    formula: Formula


@dataclass(frozen=True, eq=False)
class ClauseFormula(Clause):
    """
    Dataclass for logic-formula that can not be split into clauses for the grouping.
    - setting eq to false implies that two objects are equal and have the same hash iff they are the same object
    """


@dataclass(frozen=True, eq=True)
class Symbol:
    """
    Dataclass for logic-symbols.
    - setting eq to true implies that two objects are equal and have the same hash iff their attributes are the same
    """

    name: str


class ConditionCandidates:
    """A graph implementation handling conditions for the condition-based refinement algorithm."""

    def __init__(self, sequence_node: SeqNode, sibling_reachability: SiblingReachability, options: RestructuringOptions) -> None:
        """
        Init for the condition-candidates.

        param sequence-node:: The sequence node whose children we want to cluster
        param sibling_reachability: The sibling-reachability of the given sequence-node

        - candidates: maps all relevant ast-nodes to their formula (reaching condition)
        - unconsidered_nodes: a set of all nodes that we still have to consider for grouping into conditions.
        - logic_graph: representation of all logic-formulas relevant
        """
        self.sequence_node: SeqNode = sequence_node
        self.sibling_reachability: SiblingReachability = sibling_reachability
        self._options = options
        self._candidates: Dict[AbstractSyntaxTreeNode, Formula] = {
            child: Formula(child)
            for child in sequence_node.children
            if not child.reaching_condition.is_true or isinstance(child, ConditionNode)
        }
        self._unconsidered_nodes: list[AbstractSyntaxTreeNode] = []
        self._logic_graph: DiGraph = DiGraph()
        self._initialize_logic_graph()

    def _initialize_logic_graph(self) -> None:
        """
        Initialization of the logic-graph.

        - We add one node for each cnf-formula, one node for each clause of each formula, and one node for each symbol that is contained in
          at least one formula.
        - We add an edge between each cnf-formula and all clauses it contains, as well as between all clauses and the symbols it contains.
          Additionally, we add an auxiliary edge between each cnf-formula and all clauses it contains.
        - Finally, we remove all symbols that are only contained in one cnf-formula, since these are irrelevant for grouping the AST-nodes
          into if-else-conditions.
        """
        all_symbols = set()
        for formula in self._candidates.values():
            self._logic_graph.add_node(formula)
            for clause in formula.clauses():
                self._logic_graph.add_edge(formula, clause)
                for symbol_name in clause.condition.get_symbols_as_string():
                    self._logic_graph.add_edge(clause, symbol := Symbol(symbol_name))
                    self._logic_graph.add_edge(formula, symbol, auxiliary=True)
                    all_symbols.add(symbol)
        self._remove_symbols(set(symbol for symbol in all_symbols if self._symbol_only_in_one_formula(symbol)))

    @property
    def candidates(self) -> Iterator[AbstractSyntaxTreeNode]:
        """Iterates over all candidates considered for grouping into conditions."""
        yield from self._candidates

    def get_condition(self, ast_node: AbstractSyntaxTreeNode) -> Tuple[LogicCondition, bool]:
        """Return the condition that is relevant for grouping into branches."""
        return self._candidates[ast_node].condition, self._candidates[ast_node].is_if_else_formula

    def maximum_subexpression_size(self) -> int:
        """Returns the maximum possible subexpression that is relevant to consider for clustering into conditions."""
        if len(self._candidates) < 2:
            return 0
        all_sizes = [self._formula_graph.out_degree(formula) for formula in self._candidates.values()]
        all_sizes.remove(max(all_sizes))
        return max(all_sizes)

    def get_symbol_names_of(self, node: AbstractSyntaxTreeNode) -> Set[str]:
        """Return all symbols that are used in the formula of the given ast-node."""
        if node not in self._candidates:
            return set()
        return {symbol.name for symbol in self._auxiliary_graph.successors(self._candidates[node])}

    def get_next_subexpression(self) -> Iterator[Tuple[AbstractSyntaxTreeNode, LogicCondition]]:
        """Consider Candidates in sequence-node order and start with the largest possible subexpression."""
        match self._options.cbf_node_order:
            case CbfNodeOrder.NONE:
                self._unconsidered_nodes = list(self._candidates)
            case CbfNodeOrder.SMALLEST_FIRST:
                self._unconsidered_nodes = [k for k, v in sorted(self._candidates.items(), key=lambda e: len(e[1].clauses()))]
            case CbfNodeOrder.BIGGEST_FIRST:
                self._unconsidered_nodes = [k for k, v in sorted(self._candidates.items(), key=lambda e: len(e[1].clauses()), reverse=True)]

        while self._unconsidered_nodes and len(self._candidates) > 1 and ((max_expr_size := self.maximum_subexpression_size()) != 0):
            ast_node = self._unconsidered_nodes.pop(0)
            clauses = self._get_clauses(ast_node)
            current_size = min(len(clauses), max_expr_size)
            while current_size > 0 and ast_node in self._candidates:
                for new_operands in combinations(clauses, current_size):
                    yield ast_node, LogicCondition.conjunction_of(new_operands)
                    if ast_node not in self._candidates:
                        break
                current_size -= 1

    def update_properties_for_integrating_second_node_into_first(self, cond_node: ConditionNode, merged_node: AbstractSyntaxTreeNode):
        """
        Update the condition-candidate properties when the merged-node is integrated into the given condition-node.

        - Update the sibling-reachability
        - Add the condition-node if it is new and update it otherwise
        - remove the merged-node from the candidate list.
        """
        self.sibling_reachability.merge_siblings_to(cond_node, [merged_node])
        if cond_node not in self._candidates:
            self._add_ast_node(cond_node)
        else:
            self._update_ast_node(cond_node)
        self._remove_ast_nodes([merged_node])

    def _remove_ast_nodes(self, nodes_to_remove: List[AbstractSyntaxTreeNode]) -> None:
        """Remove formulas associated with the given nodes from the graph."""
        self._remove_formulas(set(self._candidates[node] for node in nodes_to_remove))

    def _add_ast_node(self, condition_node: ConditionNode):
        """Add new node to the logic-graph"""
        formula = Formula(condition_node)
        self._candidates[condition_node] = formula
        self._unconsidered_nodes.append(condition_node)
        self._logic_graph.add_node(formula)
        for clause in formula.clauses():
            self._logic_graph.add_edge(formula, clause)
            for symbol_name in clause.condition.get_symbols_as_string():
                self._logic_graph.add_edge(clause, symbol := Symbol(symbol_name))
                self._logic_graph.add_edge(formula, symbol, auxiliary=True)

    def _update_ast_node(self, ast_node: ConditionNode):
        """
        Update the graph properties for the given condition-node.

        - If it was a single-branch condition node before and is now a condition node with two branches, then we have to update its clauses
        in the logic-graph.
        """
        assert ast_node in self._candidates, "The condition node must be a candidate."
        formula = self._candidates[ast_node]
        if not ast_node.is_single_branch and not all(isinstance(c, ClauseFormula) for c in self._formula_graph.successors(formula)):
            assert len(clauses := formula.clauses()) == 1, "A non-single condition node should have one formula clause!"
            self._logic_graph.remove_nodes_from(list(self._formula_graph.successors(formula)))
            self._logic_graph.add_edge(ast_node, clauses[0])
            for symbol in self._auxiliary_graph.successors(formula):
                self._logic_graph.add_edge(clauses[0], symbol)

    @property
    def _auxiliary_graph(self) -> DiGraph:
        """Return a read-only view of the logic-graph containing only the auxiliary-edges, i.e., the edges between formulas and symbols."""

        def filter_auxiliary_edges(source, sink):
            return self._logic_graph[source][sink].get("auxiliary", False)

        return subgraph_view(self._logic_graph, filter_edge=filter_auxiliary_edges)

    @property
    def _formula_graph(self) -> DiGraph:
        """Return a read-only view of the logic-graph containing only the non-auxiliary-edges, i.e., no edge between formulas and symbols."""

        def filter_non_auxiliary_edges(source, sink):
            return self._logic_graph[source][sink].get("auxiliary", False) is False

        return subgraph_view(self._logic_graph, filter_edge=filter_non_auxiliary_edges)

    def _get_clauses(self, node: AbstractSyntaxTreeNode) -> List[LogicCondition]:
        """Return all clauses that are contained in the formula of the given ast-node."""
        return [clause.condition for clause in self._formula_graph.successors(self._candidates[node])]

    def _symbol_only_in_one_formula(self, symbol: Symbol):
        """Checks whether the symbol is only contained in one formula."""
        return self._auxiliary_graph.in_degree(symbol) == 1

    def _remove_formulas(self, removing_formulas: Set[Formula]):
        """
        Remove all formulas from the logic-graph and all nodes that have to be removed afterward.

        1. Remove each clause contained in one of the given formulas.
        2. Remove each formula from the logic-graph.
        3. Remove all symbols that are only contained in these formulas and one other formula,
            i.e., these are only contained in one formula after removing these formulas.
        """
        symbols_of_formulas: Set[Symbol] = set()
        for formula in removing_formulas:
            self._logic_graph.remove_nodes_from(list(self._formula_graph.successors(formula)))
            symbols_of_formulas.update(self._auxiliary_graph.successors(formula))
            self._remove_formula_node(formula)
        self._remove_symbols(set(symbol for symbol in symbols_of_formulas if self._symbol_only_in_one_formula(symbol)))

    def _remove_formula_node(self, formula: Formula):
        """
        Remove the formula-node from the logic-graph, including updating the candidates and unconsidered-nodes.

        Removing a formula implies that it is irrelevant for grouping the ast-nodes into conditions,
        therefore it is not a candidate anymore, and we do not have to consider it for further grouping
        """
        self._logic_graph.remove_node(formula)
        del self._candidates[formula.ast_node]
        try:
            self._unconsidered_nodes.remove(formula.ast_node)
        except ValueError:
            pass

    def _remove_symbols(self, removing_symbols: Set[Symbol]):
        """
        Remove all symbols from the logic-graph and all nodes that have to be removed afterward.

        1. If we do not have to remove any symbol, we do nothing.
        2. Remove each symbol from the logic-graph.
        3. For each clause that contains at least one of the symbols, we
              i. remove the clause
             ii. for each symbol of the clause, we check whether the symbol is in no other clause of the formula containing this clause
                 - True: remove the auxiliary-edge between the formula and the symbol
                         and add it to the new_single_formula_nodes iff it is one afterward.
                 - False: do nothing.
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

    def __init__(self, asforest: AbstractSyntaxForest, options: RestructuringOptions, root: Optional[AbstractSyntaxTreeNode] = None):
        """Init an instance of the condition-based refinement."""
        self.asforest: AbstractSyntaxForest = asforest
        self.root: AbstractSyntaxTreeNode = asforest.current_root if root is None else root
        self.options = options
        self._condition_candidates: Optional[ConditionCandidates] = None

    @classmethod
    def refine(cls, asforest: AbstractSyntaxForest, options: RestructuringOptions, root: Optional[AbstractSyntaxTreeNode] = None) -> None:
        """Apply the condition-based-refinement to the given abstract-syntax-forest starting at the given root."""
        if root is None:
            root = asforest.current_root
        if not isinstance(root, SeqNode):
            return
        if_refinement = cls(asforest, options, root)
        if_refinement._condition_based_refinement()

    def _condition_based_refinement(self) -> None:
        """
        Apply Condition-Based Refinement on the root node.
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
        self._condition_candidates = ConditionCandidates(sequence_node, sibling_reachability, self.options)
        for child, subexpression in self._condition_candidates.get_next_subexpression():
            newly_created_sequence_nodes.update(self._cluster_by_condition(subexpression, child))

        return newly_created_sequence_nodes

    def _cluster_by_condition(self, sub_expression: LogicCondition, current_node: AbstractSyntaxTreeNode) -> List[SeqNode]:
        """
        Cluster the nodes of the current-sequence node according to the input condition belonging to the given ast-node.

        :param sub_expression: The condition for which we check whether it or its negation is a subexpression of a sequence-node child.
        :param current_node: The node of which the given sub_expression is a sub-expression.
        :return: A list of all new created sequence-nodes that should be considered for a future iteration of the CBR.
        """
        symbols_of_condition = set(sub_expression.get_symbols_as_string())
        negated_condition: Optional[LogicCondition] = None
        for ast_node in [candidate for candidate in self._condition_candidates.candidates if candidate != current_node]:
            if symbols_of_condition - self._condition_candidates.get_symbol_names_of(
                ast_node
            ) or not self._can_place_condition_node_with_branches(
                [current_node, ast_node], self._condition_candidates.sibling_reachability
            ):
                continue
            if self._is_possible_branch(ast_node, sub_expression):
                current_node = self._add_condition_node_if_needed(current_node, sub_expression)
                self._add_node_to_condition(current_node, ast_node, "true")
            elif self._is_possible_branch(ast_node, negated_condition := self._get_negated_condition_of(sub_expression, negated_condition)):
                current_node = self._add_condition_node_if_needed(current_node, sub_expression)
                self._add_node_to_condition(current_node, ast_node, "false")

        if isinstance(current_node, ConditionNode):
            return [branch.child for branch in current_node.children if isinstance(branch.child, SeqNode)]
        return []

    def _is_possible_branch(self, ast_node: AbstractSyntaxTreeNode, sub_expression: LogicCondition) -> bool:
        """
        Check whether the given ast-node is a possible branch for a condition-node where one branch-condition is the given sub-expression.
        """
        condition, is_if_else_node = self._condition_candidates.get_condition(ast_node)
        return (not is_if_else_node and self._is_subexpression_of_cnf_formula(sub_expression, condition)) or (
            is_if_else_node and sub_expression.is_equivalent_to(condition)
        )

    def _add_condition_node_if_needed(self, ast_node: AbstractSyntaxTreeNode, sub_expression: LogicCondition) -> ConditionNode:
        """
        If the given AST-node is not a condition-node whose condition is equal to the sub-expression,
        then we create a condition with the given condition and the ast-node as true-child.
        We return a condition node having the given sub-expression as condition.
        """
        if not isinstance(ast_node, ConditionNode) or not sub_expression.is_equal_to(ast_node.condition):
            tmp = ast_node
            ast_node = self.asforest.create_condition_node_with(sub_expression, [ast_node], [])
            self._condition_candidates.update_properties_for_integrating_second_node_into_first(ast_node, tmp)
        return ast_node

    def _add_node_to_condition(self, condition_node: ConditionNode, ast_node: AbstractSyntaxTreeNode, branch: Literal["true", "false"]):
        """
        Add the given ast-node as a branch to the given condition-node.

        - If the branch is "true" the ast-node will be part of the true-branch of the given condition-node.
        - If the branch is "false" the ast-node will be part of the false-branch of the given condition-node.
        """
        true_cluster, false_cluster = None, None
        if isinstance(ast_node, ConditionNode) and ast_node.reaching_condition.is_true:
            true_cluster = ast_node.true_branch_child
            if ast_node.false_branch:
                false_cluster = ast_node.false_branch_child
            else:
                assert true_cluster.reaching_condition.is_true, "single-branch Conditions should not have a RC at this point."
                true_cluster.reaching_condition = ast_node.true_branch.branch_condition.copy()
                true_expression = condition_node.condition if branch == "true" else ~condition_node.condition
                true_cluster.reaching_condition.substitute_by_true(true_expression)
        else:
            true_cluster = ast_node
            true_expression = condition_node.condition if branch == "true" else ~condition_node.condition
            true_cluster.reaching_condition.substitute_by_true(true_expression)
        if branch == "false":
            true_cluster, false_cluster = false_cluster, true_cluster

        self.asforest.add_branches_to_condition_node(condition_node, true_cluster, false_cluster)
        self._condition_candidates.update_properties_for_integrating_second_node_into_first(condition_node, ast_node)
        self._condition_candidates.sequence_node._sorted_children = self._condition_candidates.sibling_reachability.sorted_nodes()

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
