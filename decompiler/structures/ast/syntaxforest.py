from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union

from decompiler.structures.ast.ast_nodes import (
    AbstractSyntaxTreeNode,
    CaseNode,
    CodeNode,
    ConditionNode,
    FalseNode,
    LoopNode,
    SeqNode,
    SwitchNode,
    TrueNode,
    VirtualRootNode,
)
from decompiler.structures.ast.condition_symbol import ConditionHandler
from decompiler.structures.ast.syntaxgraph import AbstractSyntaxInterface
from decompiler.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import Break, Condition, Constant, Expression, Instruction, OperationType, Variable


class AbstractSyntaxForest(AbstractSyntaxInterface):
    """Class for a Abstract Syntax Forest which is a union of Abstract Syntax Trees."""

    def __init__(self, condition_handler: ConditionHandler):
        """
        Init a new empty abstract syntax forest.

        condition_handler -- in charge of handling all conditions that are contained in the syntax forest.
        self._current_root -- point to the root of the connected component (syntax tree) that we currently restructure.
        """
        super().__init__(context=condition_handler.logic_context)
        self.condition_handler: ConditionHandler = condition_handler
        self._current_root: VirtualRootNode = self.factory.create_virtual_node()
        self._add_node(self._current_root)

    @property
    def current_root(self) -> Optional[AbstractSyntaxTreeNode]:
        """
        Returns the root of the syntax tree (a connected component of the forest) that we currently restructure.

        - It returns None, if we do not consider a specific component.
        """
        return self._current_root.child

    @classmethod
    def generate_from_code_nodes(cls, code_nodes: List[CodeNode], condition_map: ConditionHandler) -> AbstractSyntaxForest:
        """
        Generate an initial syntax forest from a set of code-nodes.

        -> We use this to start with an asforest that contains all code nodes of a cfg to step by step construct the final AST
        representing the CFG
        """
        asforest = AbstractSyntaxForest(condition_map)
        for node in code_nodes:
            asforest.add_code_node(node)
        return asforest

    def construct_initial_ast_for_region(self, reaching_conditions: Dict[TransitionBlock, LogicCondition]) -> SeqNode:
        """
        Initialize the AST for a region of the AST using dictionaries that map each node of the region to the nodes it reaches in the region
        as well as their reaching condition.

        -> Construct a sequence node whose reaching conditions and reachability is given by the dictionaries.
        -> Recall, the reachability is saved in the code-nodes.
        """
        self._add_node(new_seq_node := self.factory.create_seq_node())
        for node, reaching_condition in reaching_conditions.items():
            node.ast.reaching_condition = reaching_condition
            self._add_edge(new_seq_node, node.ast)

        new_seq_node.sort_children()
        return new_seq_node

    def substitute_variable_in_condition(self, condition: LogicCondition, replacee: Variable, replacement: Variable):
        """Substitute the given variable replacee with the variable replacement in the given condition by updating the condition handler."""
        for symbol in condition.get_symbols():
            self.condition_handler.get_condition_of(symbol).substitute(replacee, replacement)

    # Graph manipulation - extern

    def add_code_node(self, code_node: Optional[Union[CodeNode, List[Instruction]]] = None) -> CodeNode:
        """Add the given CodeNode to the graph resp. a code node containing the given list of Instructions."""
        if code_node is None or isinstance(code_node, list):
            return self._add_code_node(code_node)
        assert isinstance(code_node, CodeNode), f"The given node {code_node} is not a code node!"
        self._add_node(code_node)
        return code_node

    def add_seq_node_with_reaching_condition_before(
        self, nodes: List[AbstractSyntaxTreeNode], reaching_condition: LogicCondition
    ) -> SeqNode:
        """
        Add a sequence node with the given RC before the list of given children, that have the same seq node has parent.

        This is needed, for example, to cluster if-else branches when multiple AST-nodes are part of one of the branches.
        Furthermore, we use it to group nodes with the same reaching condition.
        """
        assert (parent := self.have_same_parent(nodes)) is not None and isinstance(
            parent, SeqNode
        ), "All nodes must have the same seq node has parent!"
        new_seq_node = self._add_sequence_node_before(nodes[0])

        parent._sorted_children = tuple(child for child in parent.children if child not in nodes)
        for node in nodes[1:]:
            self._add_edge(new_seq_node, node)
            self._remove_edge(parent, node)

        new_seq_node._sorted_children = tuple(nodes)
        new_seq_node.reaching_condition = reaching_condition
        new_seq_node.clean()
        return new_seq_node

    def add_loop_node_before(self, node: AbstractSyntaxTreeNode, loop_node: LoopNode) -> None:
        """Add the given loop node before the given AST-node."""
        self._add_node(loop_node)
        parent = node.parent
        if parent is not None:
            if isinstance(parent, SeqNode):
                parent._sorted_children = tuple(loop_node if child is node else child for child in parent.children)
            self._remove_edge(parent, node)
            self._add_edge(parent, loop_node)
        self._add_edge(loop_node, node)

    def add_default_case(self, new_child: AbstractSyntaxTreeNode, switch_node: SwitchNode):
        """Add a default case for the given switch node with the given child."""
        self._add_node(case_node := self.factory.create_case_node(switch_node.expression, "default"))
        cases = switch_node.cases
        new_child.reaching_condition = self.condition_handler.get_true_value()
        parent = new_child.parent
        self._remove_edge(parent, new_child)
        self._add_edges_from(((switch_node, case_node), (case_node, new_child)))
        switch_node._sorted_cases = cases + (case_node,)
        parent.clean()
        switch_node.parent.clean()

    def add_case_nodes_with_one_child(self, new_case_nodes: List[CaseNode], switch_node: SwitchNode, child: AbstractSyntaxTreeNode):
        """
        Add the list of case nodes to the switch.
        All case nodes have an empty child except the last one which has the given child as child.
        """
        self._add_nodes_from(new_case_nodes)
        self._add_edges_from((switch_node, case_node) for case_node in new_case_nodes)
        self._add_edges_from((case_node, self.add_code_node()) for case_node in new_case_nodes[:-1])
        parent = child.parent
        self._remove_edge(parent, child)
        self._add_edge(new_case_nodes[-1], child)
        if not new_case_nodes[-1].does_end_with_continue and not new_case_nodes[-1].does_end_with_return:
            new_case_nodes[-1].break_case = True
        self._code_node_reachability_graph.add_reachability_for_fallthrough_cases(new_case_nodes)

        if isinstance(parent, SeqNode):
            parent._sorted_children = tuple(node for node in parent._sorted_children if node is not child)
            parent.clean()
        else:
            parent.parent.clean()

    def add_reachability(self, reaching_node: AbstractSyntaxTreeNode, reachable_node: AbstractSyntaxTreeNode) -> None:
        """Add reachability between all descendant code nodes of the reaching-node and the reachable_node"""
        descendant_code_node_of_cross_node = reachable_node.get_descendant_code_nodes()
        for descendant_node in reaching_node.get_descendant_code_nodes():
            self._code_node_reachability_graph.add_reachability_from(
                (descendant_node, reachable) for reachable in descendant_code_node_of_cross_node
            )

    def combine_break_nodes(
        self, seq_node: SeqNode, break_nodes: Set[Union[ConditionNode, CodeNode]]
    ) -> Optional[Union[ConditionNode, CodeNode]]:
        """
        Construct a condition node for the given break nodes.

        These break nodes are either CodeNodes which only contain the break-statement (break-node) or ConditionNodes with one branch
        that is a break-node.
        """
        if not break_nodes:
            return None
        if len(break_nodes) == 1:
            return list(break_nodes)[0]

        new_break_node, new_condition = self.__get_break_node_and_condition_for(break_nodes)

        if new_condition.is_true:
            self._add_edge(seq_node, new_break_node)
            return new_break_node

        condition_node = self._add_condition_node_with(new_condition, new_break_node)
        self._add_edge(seq_node, condition_node)

        return condition_node

    def __get_break_node_and_condition_for(self, break_nodes: Set[Union[ConditionNode, CodeNode]]) -> Tuple[CodeNode, LogicCondition]:
        """Merges the given break nodes to one new break node and returns this break node together with its reaching condition."""
        new_condition = self.condition_handler.get_false_value()
        new_break_node = self.add_code_node([Break()])
        for node in break_nodes:
            assert node.is_break_node or node.is_break_condition, f"The node {node} is neither a break node nor a break condition."
            break_condition = (
                node.reaching_condition
                if node.is_break_node
                else node.condition & node.reaching_condition & node.true_branch_child.reaching_condition
            )
            new_condition = new_condition | break_condition
            break_node: CodeNode = node if node.is_break_node else node.true_branch.child
            self._code_node_reachability_graph.contract_code_nodes(new_break_node, break_node)
            self.remove_subtree(node)
        return new_break_node, new_condition

    def extract_branch_from_condition_node(
        self, cond_node: ConditionNode, branch: Union[TrueNode, FalseNode], update_reachability: bool = True
    ):
        """
        Extract the given Branch from the condition node.

        -> Afterwards, the Branch must always be executed after the condition node.
        """
        assert isinstance(cond_node, ConditionNode) and branch in cond_node.children, f"{branch} must be a child of {cond_node}."
        new_seq = self._add_sequence_node_before(cond_node)
        extracted_branch = branch.child
        self._remove_node(branch)
        self._add_edge(new_seq, extracted_branch)
        new_seq._sorted_children = (cond_node, extracted_branch)
        if update_reachability:
            descendants_of_branch = set(extracted_branch.get_descendant_code_nodes())
            for code_node in cond_node.get_descendant_code_nodes():
                self._code_node_reachability_graph.add_reachability_from((code_node, descendant) for descendant in descendants_of_branch)
        cond_node.clean()
        if new_seq.parent is not None:
            new_seq.parent.clean()

    def extract_switch_from_condition_sequence(self, switch_node: SwitchNode, condition_node: ConditionNode):
        """Extract the given switch-node, that is the first or last child of a seq-node Branch from the condition node"""
        seq_node_branch = switch_node.parent
        seq_node_branch_children = seq_node_branch.children
        assert seq_node_branch.parent in condition_node.children, f"{seq_node_branch} must be a branch of {condition_node}"
        new_seq_node = self._add_sequence_node_before(condition_node)
        self._remove_edge(seq_node_branch, switch_node)
        self._add_edge(new_seq_node, switch_node)
        if switch_node is seq_node_branch_children[0]:
            new_seq_node._sorted_children = (new_seq_node, condition_node)
            seq_node_branch._sorted_children = seq_node_branch_children[1:]
        elif switch_node is seq_node_branch_children[-1]:
            new_seq_node._sorted_children = (condition_node, new_seq_node)
            seq_node_branch._sorted_children = seq_node_branch_children[:-1]

        seq_node_branch.clean()
        condition_node.clean()
        if new_seq_node.parent is not None:
            new_seq_node.parent.clean()

    def extract_all_breaks_from_condition_node(self, cond_node: ConditionNode):
        """Remove all break instructions at the end of the condition node and extracts them, i.e., add a break after the condition."""
        for node in cond_node.get_end_nodes():
            assert node.is_code_node_ending_with_break, "Each end node must be a code node ending with break for this transformation."
            node.instructions = node.instructions[:-1]
        self.remove_empty_nodes(cond_node)
        self.add_instructions_after(cond_node, Break())
        cond_node.clean()

    def substitute_branches_by(self, branch: AbstractSyntaxTreeNode, condition_node: ConditionNode):
        """Removes all branches from the given condition node and adds the given branch as true case."""
        assert isinstance(condition_node, ConditionNode), f"{condition_node} must be a condition node."
        descendant_branch_code_nodes = set(branch.get_descendant_code_nodes())
        for code_node in condition_node.get_descendant_code_nodes():
            for new_node in descendant_branch_code_nodes:
                self._code_node_reachability_graph.contract_code_nodes(new_node, code_node)
        if condition_node.false_branch:
            self.remove_subtree(condition_node.false_branch)
        if condition_node.true_branch:
            self._replace_subtree(condition_node.true_branch_child, branch)
        else:
            self._add_node(true_branch := self.factory.create_true_node())
            self._add_edges_from(((condition_node, true_branch), (true_branch, branch)))

    def resolve_unresolved_reaching_conditions(self, root: Optional[AbstractSyntaxTreeNode] = None):
        """Adds condition nodes for all nodes that have a reaching condition that is not True."""
        for node in list(nd for nd in self.post_order(root) if not nd.reaching_condition.is_true):
            parent = node.parent
            new_condition_node = self._add_condition_node_with(node.reaching_condition, node)
            node.reaching_condition = self.condition_handler.get_true_value()
            if parent is not None:
                self._remove_edge(parent, node)
                self._add_edge(parent, new_condition_node)

    def create_condition_node_with(
        self, condition: LogicCondition, true_cases: List[AbstractSyntaxTreeNode], false_cases: List[AbstractSyntaxTreeNode]
    ) -> ConditionNode:
        """
        Creates a condition node with the given condition and a list of ast-nodes for the true and false case.

        -> The nodes in true_cases and false_cases must have the same parent.
        """
        assert (parent := self.have_same_parent(true_cases + false_cases)) is not None, "Branches must have the same parent!"

        true_branch = self.__create_branch_for(true_cases, condition)
        false_branch = self.__create_branch_for(false_cases, ~condition)

        condition_node = self._add_condition_node_with(condition, true_branch, false_branch)
        self._add_edge(parent, condition_node)

        return condition_node

    def __create_branch_for(self, branch_nodes: List[AbstractSyntaxTreeNode], condition: LogicCondition):
        """Creates the node for the branch with the given condition."""
        if len(branch_nodes) == 0:
            return None

        if len(branch_nodes) == 1:
            branch = branch_nodes[0]
        else:
            branch = self.add_seq_node_with_reaching_condition_before(branch_nodes, self.condition_handler.get_true_value())
        for node in branch_nodes:
            node.reaching_condition.substitute_by_true(condition)

        self._remove_edge(branch.parent, branch)
        return branch

    def create_switch_node_with(self, expression: Expression, cases: List[Tuple[CaseNode, AbstractSyntaxTreeNode]]) -> SwitchNode:
        """Create a switch node with the given expression and the given list of case nodes."""
        assert (parent := self.have_same_parent([case[1] for case in cases])) is not None, "All case nodes must have the same parent."
        self._add_node(switch_node := self.factory.create_switch_node(expression))
        self._add_edge(parent, switch_node)
        for case_node, child in cases:
            assert isinstance(case_node, CaseNode), "Each case node must be of type CaseNode!"
            self._add_node(case_node)
            self._remove_edge(parent, child)
            self._add_edges_from(((switch_node, case_node), (case_node, child)))

        return switch_node

    def merge_code_nodes(self, code_nodes: List[CodeNode]):
        """Merge the list of given code nodes into the first code-node of the list."""
        remaining_code_node = code_nodes[0]
        for node in code_nodes[1:]:
            remaining_code_node.instructions.extend(node.instructions)
            self._code_node_reachability_graph.contract_code_nodes(remaining_code_node, node)
            self._remove_node(node)

    def merge_case_nodes(self, case_node: CaseNode, merging_case: CaseNode):
        """Merges the case node merging_case to the given case node."""
        assert self.have_same_parent([case_node, merging_case]), "Case nodes must have the same parent."
        assert merging_case.constant == Constant("add_to_previous_case"), f"Case node {merging_case} has wrong constant for merging."
        case_node_child = case_node.child
        merging_case_child = merging_case.child
        new_seq_node = self._add_sequence_node_before(case_node_child)
        self._remove_node(merging_case)
        self._add_edge(new_seq_node, merging_case_child)
        new_seq_node._sorted_children = (case_node_child, merging_case_child)
        descendant_code_merging_code_nodes = merging_case_child.get_descendant_code_nodes()
        for descendant_code_node in case_node_child.get_descendant_code_nodes():
            self._code_node_reachability_graph.add_reachability_from(
                (descendant_code_node, reachable) for reachable in descendant_code_merging_code_nodes
            )

    def combine_switch_nodes(self, combinable_switch_nodes: List[SwitchNode]) -> SwitchNode:
        """Combine two sibling switch nodes that have the same expression and no overlapping cases."""
        assert (parent := self.have_same_parent(combinable_switch_nodes)) is not None, "All switch nodes must have the same parent."
        assert isinstance(parent, SeqNode), "The parent of all switches must be a Sequence node."
        self._add_node(new_switch_node := self.factory.create_switch_node(combinable_switch_nodes[0].expression))
        self._add_edge(parent, new_switch_node)
        switch_node_cases: Dict[SwitchNode, List[CaseNode]] = dict()
        for switch_node in combinable_switch_nodes:
            switch_node_cases[switch_node] = []
            for case in switch_node.cases:
                self._add_edge(new_switch_node, case)
                switch_node_cases[switch_node].append(case)
            self._remove_node(switch_node)
        try:
            new_switch_node.sort_cases()
        except ValueError:
            for switch_node, cases in switch_node_cases.items():
                self._add_node(switch_node)
                self._add_edges_from((switch_node, case) for case in cases)
                self._add_edge(parent, switch_node)
            self._remove_node(new_switch_node)

        parent.sort_children()
        return new_switch_node if new_switch_node in set(self.nodes) else None

    def combine_cascading_single_branch_conditions(self, root: Optional[AbstractSyntaxTreeNode] = None):
        """
        Combine two nested condition nodes if both have only one branch.

        -> If we call clean on a condition node, the true_branch exists or the condition node has no branches.
        """
        for condition_node in self.get_condition_nodes_post_order(root):
            condition_node.clean()
            if condition_node.false_branch:
                continue

            nested_condition_node = condition_node.true_branch_child
            if isinstance(nested_condition_node, ConditionNode) and nested_condition_node.false_branch is None:
                new_condition = (
                    condition_node.condition
                    & nested_condition_node.condition
                    & condition_node.reaching_condition
                    & nested_condition_node.reaching_condition
                )
                condition_node.condition = new_condition.remove_redundancy(self.condition_handler)
                condition_node.reaching_condition = self.condition_handler.get_true_value()

                self.replace_condition_node_by_single_branch(nested_condition_node)

    def split_case_node(self, case_node: CaseNode, sorted_constants: List[Constant]) -> List[CaseNode]:
        """Given a case node with more than one constant, split it into multiple cases according to the list of sorted constants."""
        fallthrough_cases = list()
        for constant in sorted_constants[:-1]:
            self._add_node(new_case := self.factory.create_case_node(case_node.expression, constant))
            empty_code_node = self.add_code_node()
            self._add_edges_from(((case_node.parent, new_case), (new_case, empty_code_node)))
            fallthrough_cases.append(new_case)
        case_node.constant = sorted_constants[-1]
        case_node.reaching_condition = self.condition_handler.get_true_value()
        fallthrough_cases.append(case_node)
        self._code_node_reachability_graph.add_reachability_for_fallthrough_cases(fallthrough_cases)
        return fallthrough_cases

    def remove_root_node(self, root_node: AbstractSyntaxTreeNode):
        """Removes the node if it has in-degree zero."""
        assert root_node.parent is None, f"{root_node} is not a root, so we can not remove it!"
        self._remove_node(root_node)

    def set_current_root(self, root: AbstractSyntaxTreeNode):
        """Marks a connected component as the current component by setting its root as the current root. There can only be one!"""
        assert self.current_root is None, f"We already have a temporary root, namely {self.current_root}"
        self._add_edge(self._current_root, root)

    def remove_current_root(self):
        """UnMark a connected component as the current component by setting the current root to None."""
        assert self.current_root is not None, "There is no temporary root that can be removed!"
        self._remove_edge(self._current_root, self.current_root)

    def replace_switch_by_conditions(self, switch_node: SwitchNode):
        """Replace the switch node by nested if-else."""
        assert isinstance(switch_node, SwitchNode), "The given node must be a switch node"
        last_condition_node = self.__get_final_else(switch_node)
        for current_case, condition, break_case in self.__reverse_iterate_case_conditions(switch_node):
            if break_case:
                last_condition_node = self.__add_condition_before_nodes(condition, current_case, last_condition_node)
            else:
                self.__handle_fall_through_case(current_case, condition, last_condition_node)
        self._replace_subtree(switch_node, last_condition_node)

    def __get_final_else(self, switch_node: SwitchNode) -> Optional[TransitionBlock]:
        """
        Return the default node child, if it exists.

        -> The default node is the final else of the nested if-else constructed from the switch.
        """
        final_else_case = None
        if default_case := switch_node.default:
            final_else_case = default_case.child
            self._remove_node(default_case)
        return final_else_case

    def __reverse_iterate_case_conditions(self, switch_node: SwitchNode) -> Iterable[Tuple[AbstractSyntaxTreeNode, LogicCondition, bool]]:
        """Iterate over all case nodes in reverse order and yield, child, condition and whether it is a break case."""
        for case_node in reversed(switch_node.cases):
            child = case_node.child
            condition = self.condition_handler.add_condition(Condition(OperationType.equal, [case_node.expression, case_node.constant]))
            self._remove_edge(case_node, child)
            yield child, condition, case_node.break_case

    def __add_condition_before_nodes(
        self, condition: LogicCondition, true_branch: AbstractSyntaxTreeNode, false_branch: Optional[AbstractSyntaxTreeNode] = None
    ) -> ConditionNode:
        """
        Add the given condition before the true_branch and its negation before the false branch.

        -> If the false_branch exists (not None) or the true_branch is not a Condition, then we introduce a condition node with the given branches
        -> Otherwise, we only have a true-branch that is also a condition node. In this case we can add the given condition to the condition node.
        """
        if false_branch is not None or not isinstance(true_branch, ConditionNode):
            return self._add_condition_node_with(condition, true_branch, false_branch)
        true_branch.condition &= condition
        return true_branch

    def __handle_fall_through_case(self, case_node, case_condition, condition_node) -> None:
        """
        Add the new node to the true-branch of the condition node and update the conditions of the fall through cases in this branch.

        -> We visit the case nodes in reverse order
        -> add case_condition to the given condition node and all condition-nodes belonging to fall through cases
        -> Insert a sequence node, if the true-branch is not already a sequence node.
        """
        condition_node.condition |= case_condition
        if case_node.is_empty:
            self.remove_subtree(case_node)
            return
        if not isinstance(true_branch := condition_node.true_branch_child, SeqNode):
            true_branch = self._add_sequence_node_before(true_branch)
        else:
            for child in true_branch.children[:-1]:
                assert isinstance(child, ConditionNode), "All children except the last one must be condition nodes."
                child.condition |= case_condition
        assert isinstance(true_branch, SeqNode), "The true-branch must be a sequence node."
        new_condition_node = self.__add_condition_before_nodes(case_condition, case_node)
        self._add_edge(true_branch, new_condition_node)
        true_branch._sorted_children = (new_condition_node,) + true_branch._sorted_children
