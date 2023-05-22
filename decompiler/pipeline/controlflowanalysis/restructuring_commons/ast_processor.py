"""Module for AST processing steps."""
import logging
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CodeNode, ConditionNode, FalseNode, SeqNode, TrueNode
from decompiler.structures.ast.reachability_graph import SiblingReachability
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo.instructions import Break
from decompiler.util.insertion_ordered_set import InsertionOrderedSet


class Processor:
    """Base class for processing abstract forests."""

    def __init__(self, asforest: AbstractSyntaxForest):
        self.asforest = asforest

    def _extract_conditional_interruption(self, interruption_type: Callable[[ConditionNode], Optional[AbstractSyntaxTreeNode]]):
        """
        Iterates in post order over all condition nodes. If the condition node has one branch ending with a interruption (break, return or
        continue), then pull out the non-interruption branch of this condition node.
        -> For break nodes we also extract them if both branches end with a break.
        """
        for condition_node in self.asforest.get_condition_nodes_post_order(self.asforest.current_root):
            condition_node.clean()
            if condition_node.false_branch is None:
                continue
            if branch := interruption_type(condition_node):
                self.asforest.extract_branch_from_condition_node(condition_node, branch)
            elif condition_node.does_end_with_break:
                self.asforest.extract_all_breaks_from_condition_node(condition_node)

    def _combine_cascading_breaks(self) -> None:
        """Find and combine cascading break conditions and merge them. But only when the remaining branch is None."""
        for condition_node in self.asforest.get_condition_nodes_post_order(self.asforest.current_root):
            condition_node.clean()
            if condition_node.false_branch_child is None or condition_node.true_branch_child is None:
                continue
            true_branch_break_cond = self._get_break_condition(condition_node.true_branch)
            false_branch_break_cond = self._get_break_condition(condition_node.false_branch)
            if true_branch_break_cond is not None and false_branch_break_cond is not None:
                condition_node.condition = true_branch_break_cond | false_branch_break_cond
                break_node = self.asforest.add_code_node([Break()])
                self.asforest.substitute_branches_by(break_node, condition_node)

    @staticmethod
    def _get_break_condition(branch: Union[TrueNode, FalseNode]) -> Optional[LogicCondition]:
        """checks whether the condition is a break condition, and returns this condition if this is the case."""
        if branch.child.is_break_node:
            return branch.branch_condition
        if branch.child.is_break_condition:
            return branch.branch_condition & branch.child.condition

        return None

    def _extract_conditional_breaks(self) -> None:
        """
        Extracts all conditional breaks, i.e., if a child of a condition node that has one branch ending
        with a break, then pull out the non-return branch of this condition node and if both children of
        a branch end with a break than extract the break after the condition node.
        """
        self._extract_conditional_interruption(self._extract_break_from_conditional_node)

    @staticmethod
    def _extract_break_from_conditional_node(node: ConditionNode) -> Optional[AbstractSyntaxTreeNode]:
        """
        This function checks whether exactly one of the two branches of the given condition node ends with a break.
        If this is the case we return the non-break Branch, otherwise we return None.
        """
        break_in_true_branch = node.true_branch is not None and node.true_branch.does_end_with_break
        break_in_false_branch = node.false_branch is not None and node.false_branch.does_end_with_break

        if break_in_true_branch == break_in_false_branch:
            return None
        return node.false_branch if break_in_true_branch else node.true_branch

    def _combine_break_nodes(self):
        """
        If two children of a sequence node are Condition nodes that have only a break branch,
        then combine these Condition nodes if possible.
        """
        for seq_node in self.asforest.get_sequence_nodes_post_order(self.asforest.current_root):
            break_nodes: List[Union[CodeNode, ConditionNode]] = list(seq_node.get_break_nodes())
            if break_nodes:
                self._partition_conditional_breaks_in_groups_and_combine(seq_node, break_nodes)
                seq_node.clean()

    def _partition_conditional_breaks_in_groups_and_combine(self, seq_node: SeqNode, break_nodes: List[Union[ConditionNode, CodeNode]]):
        """Combines all Conditional break nodes that are not reachable from any other node and that reach node seq_node."""
        reachability_of_seq_node_children: SiblingReachability = seq_node.get_reachability_of_children()
        first_break_nodes: Set[Union[ConditionNode, CodeNode]] = set()
        last_break_nodes: Set[Union[ConditionNode, CodeNode]] = set()

        for break_node in break_nodes:
            if not reachability_of_seq_node_children.siblings_reaching(break_node) - first_break_nodes:
                first_break_nodes.add(break_node)
            elif not reachability_of_seq_node_children.reachable_siblings_of(break_node):
                last_break_nodes.add(break_node)

        children = seq_node.children
        first_break_condition = (self.asforest.combine_break_nodes(seq_node, first_break_nodes),) if first_break_nodes else ()
        last_break_condition = (self.asforest.combine_break_nodes(seq_node, last_break_nodes),) if last_break_nodes else ()
        seq_node._sorted_children = (
            first_break_condition
            + tuple(child for child in children if child not in first_break_nodes | last_break_nodes)
            + last_break_condition
        )

    def _update_condition_for_nodes_reachable_from_break(self):
        """
        Update the reaching condition of all nodes reachable from a break-node in a sequence.

        - Given a sequence node, consider all break-nodes that are not reachable from any other node.
        - These break-nodes can all be at the beginning of the sequence.
        - For all other children of the sequence-node, the negated reaching-condition of the break-conditions must hold
        - If setting the negated-break condition to true, changes the reaching-condition of a child,
          then the break-node must be executed before the child, and we update the reachability.
        """
        for seq_node in self.asforest.get_sequence_nodes_post_order():
            break_nodes: InsertionOrderedSet[Union[CodeNode, ConditionNode]] = InsertionOrderedSet(seq_node.get_break_nodes())
            reachability_of_seq_node_children: SiblingReachability = seq_node.get_reachability_of_children()
            for break_node in break_nodes:
                if reachability_of_seq_node_children.siblings_reaching(break_node):
                    continue
                neg_break_cond = ~self.__get_break_condition(break_node)
                for child in (c for c in seq_node.children if c not in break_nodes):
                    old_cond = child.reaching_condition.copy()
                    child.reaching_condition.substitute_by_true(neg_break_cond, self.asforest.condition_handler)
                    if not old_cond.is_equal_to(child.reaching_condition):
                        self.__update_reachability(break_node, child)

    def __update_reachability(self, break_node: Union[CodeNode, ConditionNode], child: AbstractSyntaxTreeNode):
        """Add reachability of code-nodes such that the break-node must always be executed before the child."""
        break_node: CodeNode = break_node if break_node.is_break_node else break_node.true_branch_child
        for cn in child.get_descendant_code_nodes():
            self.asforest.add_reachability(break_node, cn)

    def __get_break_condition(self, break_node: Union[CodeNode, ConditionNode]) -> LogicCondition:
        """Return the break-condition, i.e., the condition that must be fulfilled to reach the break node."""
        break_condition = break_node.reaching_condition
        if not break_node.is_break_node:
            assert isinstance(break_node, ConditionNode) and break_node.true_branch_child.is_break_node
            break_condition &= break_node.condition & break_node.true_branch_child.reaching_condition
        return break_condition


class AcyclicProcessor(Processor):
    """Class in charge of pre- and post-processing when restructuring acyclic regions"""

    def preprocess_condition_refinement(self) -> None:
        """
        Clean up the given ast by removing empty Code nodes, merging nodes with the same reaching condition, simplifying reaching conditions
        more aggressively and sorting break nodes to the begin resp. end of a sequence node if possible.
        """
        self.asforest.remove_empty_nodes(self.asforest.current_root)
        self._combine_nodes_with_same_reaching_conditions()
        self._simplify_reaching_conditions()
        self.asforest.clean_up(self.asforest.current_root)
        self._combine_break_nodes()
        self._update_condition_for_nodes_reachable_from_break()

    def preprocess_condition_aware_refinement(self):
        """Flatten nested Sequence nodes, removes Sequence nodes with only one child and combines cascading condition nodes, if possible."""
        self.asforest.clean_up(self.asforest.current_root)
        self.asforest.combine_cascading_single_branch_conditions(self.asforest.current_root)

    def postprocess_condition_refinement(self) -> None:
        """
        Handles unresolved reaching conditions, combines break nodes, sorts sequence node children to prefer while loops, extracts conditional
        break and returns and remove empty code nodes from sequence nodes.
        """
        self.asforest.clean_up(self.asforest.current_root)
        self.asforest.resolve_unresolved_reaching_conditions(self.asforest.current_root)
        self.asforest.combine_cascading_single_branch_conditions(self.asforest.current_root)

        self._combine_cascading_breaks()
        self._combine_break_nodes()

        self._extract_conditional_breaks()
        self._extract_conditional_returns()

        self._sort_sequence_node_children_while_over_do_while()

        self.asforest.clean_up(self.asforest.current_root)

    def _simplify_reaching_conditions(self) -> None:
        """
        Simplifies the reaching conditions by removing redundant conditions. It considers the actual conditions to a certain point.

        This helps to remove unnecessary conditions for finding switches.
        """
        for node in self.asforest.post_order(self.asforest.current_root):
            node.simplify_reaching_condition(self.asforest.condition_handler)

    def _combine_nodes_with_same_reaching_conditions(self) -> None:
        """
        Check for every SeqNode whether it has children that have the same reaching condition.
         - If so, put them in one sequence node, and merge, if possible, code nodes.
         - These nodes must be on a path in the cfg.
        """
        for seq_node in self.asforest.get_sequence_nodes_topological_order(self.asforest.current_root):
            if groups := self._group_by_reaching_conditions(seq_node.children):
                self._combine_nodes_of_same_group(groups, seq_node)

    def _group_by_reaching_conditions(self, nodes: Tuple[AbstractSyntaxTreeNode]) -> Dict[LogicCondition, List[AbstractSyntaxTreeNode]]:
        """
        Group AST nodes in the given list of AST nodes into groups that have the same reaching condition.
        These nodes are on the same path in the corresponding cfg.

        :param nodes: The AST nodes that we want to group.
        :return: A dictionary that assigns to a reaching condition the list of AST code nodes with this reaching condition,
                 if it are at least two with the same.
        """
        initial_groups: Dict[LogicCondition, List[AbstractSyntaxTreeNode]] = dict()
        for node in nodes:
            reaching_condition = self._reaching_condition_is_in(node.reaching_condition, initial_groups.keys())
            if reaching_condition is not None:
                initial_groups[reaching_condition].append(node)
            else:
                initial_groups[node.reaching_condition] = [node]
        return {reaching_condition: ast_nodes for reaching_condition, ast_nodes in initial_groups.items() if len(ast_nodes) > 1}

    @staticmethod
    def _reaching_condition_is_in(reaching_condition: LogicCondition, z3_conditions: Iterable[LogicCondition]) -> Optional[LogicCondition]:
        """
        Checks whether the given condition is equivalent to a condition that is contained in the given Iterable.
        If it is contained in the Iterable, we return this condition.
        """
        for condition in z3_conditions:
            if condition.is_equal_to(reaching_condition):
                return condition
        return None

    def _combine_nodes_of_same_group(self, groups: Dict[LogicCondition, List[AbstractSyntaxTreeNode]], seq_node: SeqNode) -> None:
        """
        We combine the AST-nodes of the given seq_node that belong to the same group.
            - Combine CodeNodes of the same group, if possible
            - Add Sequence Node as common parent for all nodes of the same group, if not all nodes are Code Nodes.
        """
        sibling_reachability: SiblingReachability = seq_node.get_reachability_of_children()
        for reaching_condition, group_nodes in groups.items():
            prev_node = group_nodes[0]
            new_group_nodes = [prev_node]
            for ast_node in group_nodes[1:]:
                if not self.__can_merge_nodes(prev_node, ast_node, sibling_reachability):
                    self.__combine_group(new_group_nodes, reaching_condition, sibling_reachability)
                    prev_node = ast_node
                    new_group_nodes = [prev_node]
                    continue

                if isinstance(ast_node, CodeNode) and isinstance(prev_node, CodeNode):
                    self.asforest.merge_code_nodes([prev_node, ast_node])
                    sibling_reachability.remove_sibling(ast_node)
                else:
                    prev_node = ast_node
                    new_group_nodes.append(prev_node)

            self.__combine_group(new_group_nodes, reaching_condition, sibling_reachability)

    @staticmethod
    def __can_merge_nodes(
        prev_node: AbstractSyntaxTreeNode, ast_node: AbstractSyntaxTreeNode, sibling_reachability: SiblingReachability
    ) -> bool:
        """Checks whether we can merge the given ast-nodes ast_node into the node prev_node, based on their sibling reachability."""
        return sibling_reachability.reachable_siblings_of(prev_node) == set(sibling_reachability.reachable_siblings_of(ast_node)) | {
            ast_node
        }

    def __combine_group(
        self,
        new_group_nodes: List[AbstractSyntaxTreeNode],
        reaching_condition: LogicCondition,
        sibling_reachability: SiblingReachability,
    ):
        """
        Group the given nodes to a sequence node with the given reaching condition in the as-forest
        and update the sibling reachability accordingly.
        """
        if len(new_group_nodes) > 1 and not reaching_condition.is_true:
            for node in new_group_nodes:
                node.reaching_condition = self.asforest.condition_handler.get_true_value()
            seq_node = self.asforest.add_seq_node_with_reaching_condition_before(new_group_nodes, reaching_condition)
            sibling_reachability.merge_siblings_to(seq_node, new_group_nodes)

    def _extract_conditional_returns(self) -> None:
        """
        Extracts all conditional returns, i.e., if a child of a condition node that has one branch ending
        with a return, then pull out the non-return branch of this condition node.
        """
        self._extract_conditional_interruption(self._extract_return_from_conditional_node)

    @staticmethod
    def _extract_return_from_conditional_node(node: ConditionNode) -> Optional[AbstractSyntaxTreeNode]:
        """
        This function checks whether one of the two branches of the given condition node ends with a return.

        If exactly one branch ends with a return, then we return the Branch that does not end with the return
        If no branch ends with a return, then we return None
        If both branches end with a return, then we return the one with larger complexity.
        """
        branches_without_return = [branch for branch in node.children if not branch.does_end_with_return]
        if len(branches_without_return) == 1:
            return branches_without_return[0]
        if len(branches_without_return) == 2:
            return None
        return_branches = node.children
        first_branch_complexity = sum(len(cn.instructions) for cn in return_branches[0].get_descendant_code_nodes())
        second_branch_complexity = sum(len(cn.instructions) for cn in return_branches[1].get_descendant_code_nodes())
        if first_branch_complexity <= second_branch_complexity:
            return return_branches[1]
        return return_branches[0]

    def _sort_sequence_node_children_while_over_do_while(self) -> None:
        """
        If the Loop body is a sequence node and the order of the nodes can be changed such that we restructure a while loop
        and not a do-while loop, we change the order.
        """
        current_root = self.asforest.current_root
        if not isinstance(current_root, SeqNode):
            return

        sibling_reachability: SiblingReachability = current_root.get_reachability_of_children()
        for ast_node in self.asforest.current_root.children:
            if ast_node.is_break_condition and not sibling_reachability.siblings_reaching(ast_node):
                current_root._sorted_children = (ast_node,) + tuple(node for node in current_root.children if node != ast_node)
                break


class LoopProcessor(Processor):
    """Class in charge of pre- and post-processing of cyclic regions."""

    def preprocess_loop(self) -> None:
        """
        This function updates the loop ast, by
            - Clean up the AST, this includes removing unnecessary sequence nodes
            - combine cascading break nodes
            - combine Conditions of single branches
            - Pull out breaks from the Body of the LoopNode root for the restructuring
                -> Once if the body is a sequence node
                -> Once if the body is a condition node
            - Combine break nodes
            - Remove a condition from the loop body if it is equal to the loop condition.
            - Remove unnecessary continue statements
            - flatten sequence nodes again.
        """
        if self.asforest.current_root.is_loop_with_empty_body:
            logging.warning(f"The loop node {self.asforest.current_root} has an empty loop body!")
            return

        self.asforest.clean_up(self.asforest.current_root)

        self._combine_cascading_breaks()
        self.asforest.combine_cascading_single_branch_conditions(self.asforest.current_root)

        self._extract_conditional_breaks()
        self._combine_break_nodes()

        self.asforest.clean_up(self.asforest.current_root)
        self._remove_redundant_continue_at_end_of_sequence()

        self.asforest.clean_up(self.asforest.current_root)

    def postprocess_loop(self) -> None:
        """
        1. Clean up the root, i.e., remove unnecessary condition from the loop body.
        2. extract continue branches and removes the redundant once,
        3. remove empty code nodes from sequence nodes.
        """
        self.asforest.current_root.clean()

        self._extract_conditional_continues()
        self._remove_redundant_continues()

        self.asforest.clean_up(self.asforest.current_root)

    def _remove_redundant_continue_at_end_of_sequence(self) -> None:
        """
        If the body of an endless loop is a sequence node that ends with a code-node that ends with a continue,
        then this continue is unnecessary and we remove this continue.
        """
        if (
            self.asforest.current_root.is_endless_loop
            and isinstance(self.asforest.current_root.body, SeqNode)
            and self.asforest.current_root.body.children[-1].is_code_node_ending_with_continue
        ):
            continue_child = self.asforest.current_root.body.children[-1]
            continue_child.instructions = continue_child.instructions[:-1]
            self.asforest.remove_empty_nodes(continue_child)

    def _remove_redundant_continues(self) -> None:
        """Remove the continue statement from all CodeNodes that do not reach any other node."""
        for loop_node in self.asforest.get_loop_nodes_post_order(self.asforest.current_root):
            for end_node in loop_node.body.get_end_nodes():
                if end_node.is_code_node_ending_with_continue:
                    end_node.instructions = end_node.instructions[:-1]

        self.asforest.remove_empty_nodes(self.asforest.current_root)

    def _extract_conditional_continues(self) -> None:
        """
        Extract all conditional continues, i.e., if a child of a condition node that has one branch ending
        with a continue, then pull out the non-continue branch of this condition node.
        """
        self._extract_conditional_interruption(self._extract_continue_from_conditional_node)

    @staticmethod
    def _extract_continue_from_conditional_node(node: ConditionNode) -> Optional[Union[TrueNode, FalseNode]]:
        """
        Check whether any of the branches of the given condition node ends with a continue.
        The goal is to choose the branch that is extracted, in general, we want that the branch that ends with continue is "small".
        - If none ends with continue, we return None
        - If exactly one branch ends with a continue, we return the other branch, if it is not None
        - If both end with continue and none is a code-node, we return the false_branch (arbitrary choice)
        - If both end with continue, but exactly one is a code-node ending with continue, we return the non-code node
        - If both end with continue and both are code-nodes, we return the code-node with more instructions.
        """
        continue_in_true_branch = node.true_branch.does_end_with_continue
        continue_in_false_branch = node.false_branch.does_end_with_continue
        code_continue_in_true_branch = node.true_branch.child.is_code_node_ending_with_continue
        code_continue_in_false_branch = node.false_branch.child.is_code_node_ending_with_continue

        if code_continue_in_false_branch and (
            not code_continue_in_true_branch or len(node.true_branch.child.instructions) > len(node.false_branch.child.instructions)
        ):
            continue_in_true_branch = False

        if continue_in_true_branch:
            return node.false_branch
        elif continue_in_false_branch:
            return node.true_branch
        return None
