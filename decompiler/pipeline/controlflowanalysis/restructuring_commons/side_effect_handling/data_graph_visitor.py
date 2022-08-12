from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Set

from decompiler.structures.ast.ast_nodes import (
    AbstractSyntaxTreeNode,
    CaseNode,
    CodeNode,
    ConditionNode,
    DoWhileLoopNode,
    FalseNode,
    LoopNode,
    SeqNode,
    SwitchNode,
    TrueNode,
    VirtualRootNode,
)
from decompiler.structures.visitors.interfaces import ASTVisitorInterface


@dataclass
class SubtreeProperty:
    root: AbstractSyntaxTreeNode
    first_node: AbstractSyntaxTreeNode
    last_nodes: Set[AbstractSyntaxTreeNode] = field(default_factory=set)
    continue_nodes: Set[AbstractSyntaxTreeNode] = field(default_factory=set)
    break_nodes: Set[AbstractSyntaxTreeNode] = field(default_factory=set)


class ASTDataGraphVisitor(ASTVisitorInterface):
    def __init__(self):
        super().__init__()
        self._property_dict: Dict[AbstractSyntaxTreeNode, SubtreeProperty] = dict()

    @property
    def property_dict(self) -> Dict[AbstractSyntaxTreeNode, SubtreeProperty]:
        return self._property_dict

    def visit_seq_node(self, node: SeqNode) -> None:
        first_node = self._property_dict[node.children[0]].first_node
        last_nodes = self._property_dict[node.children[-1]].last_nodes
        continue_nodes = set().union(*(self._property_dict[child].continue_nodes for child in node.children))
        break_nodes = set().union(*(self._property_dict[child].break_nodes for child in node.children))
        self._property_dict[node] = SubtreeProperty(node, first_node, last_nodes, continue_nodes, break_nodes)

    def visit_code_node(self, node: CodeNode) -> None:
        first_node = node
        last_nodes = set() if node.does_end_with_break else {node}
        continue_nodes = {node} if node.does_end_with_continue else set()
        break_nodes = {node} if node.does_end_with_break else set()
        self._property_dict[node] = SubtreeProperty(node, first_node, last_nodes, continue_nodes, break_nodes)

    def visit_condition_node(self, node: ConditionNode) -> None:
        first_node = node
        last_nodes = {node} if node.false_branch_child is None else set()
        last_nodes = last_nodes.union(*(self._property_dict[branch.child].last_nodes for branch in node.children))
        continue_nodes = set().union(*(self._property_dict[branch.child].continue_nodes for branch in node.children))
        break_nodes = set().union(*(self._property_dict[branch.child].break_nodes for branch in node.children))
        self._property_dict[node] = SubtreeProperty(node, first_node, last_nodes, continue_nodes, break_nodes)

    def visit_loop_node(self, node: LoopNode) -> None:
        first_node = self._property_dict[node.body].first_node if isinstance(node, DoWhileLoopNode) else node
        last_nodes = set() if node.is_endless_loop else {node}
        last_nodes |= self._property_dict[node.body].break_nodes
        continue_nodes = set()
        break_nodes = set()
        self._property_dict[node] = SubtreeProperty(node, first_node, last_nodes, continue_nodes, break_nodes)

    def visit_switch_node(self, node: SwitchNode) -> None:
        first_node = node
        last_nodes = self._property_dict[node.default].last_nodes if node.default else set()
        last_nodes = last_nodes.union(*(self._property_dict[case].last_nodes for case in node.cases if case.break_case))
        continue_nodes = set().union(*(self._property_dict[case].continue_nodes for case in node.children))
        break_nodes = set()
        self._property_dict[node] = SubtreeProperty(node, first_node, last_nodes, continue_nodes, break_nodes)

    def visit_case_node(self, node: CaseNode) -> None:
        first_node = node
        last_nodes = self._property_dict[node.child].last_nodes
        continue_nodes = self._property_dict[node.child].continue_nodes
        break_nodes = {node} if node.break_case else set()
        self._property_dict[node] = SubtreeProperty(node, first_node, last_nodes, continue_nodes, break_nodes)

    def visit_true_node(self, node: TrueNode) -> None:
        pass

    def visit_false_node(self, node: FalseNode) -> None:
        pass

    def visit_root_node(self, node: VirtualRootNode) -> None:
        pass
