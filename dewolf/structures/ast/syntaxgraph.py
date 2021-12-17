from __future__ import annotations

from abc import ABC
from typing import Callable, Iterable, Iterator, List, Optional, Set, Tuple, TypeVar, Union

from dewolf.structures.ast.ast_node_factory import ASTNodeFactory
from dewolf.structures.ast.ast_nodes import (
    AbstractSyntaxTreeNode,
    CaseNode,
    CodeNode,
    ConditionNode,
    LoopNode,
    SeqNode,
    SwitchNode,
    WhileLoopNode,
)
from dewolf.structures.ast.reachability_graph import ReachabilityGraph, SiblingReachability
from dewolf.structures.logic.logic_condition import LogicCondition
from dewolf.structures.pseudo import Instruction, Variable
from dewolf.util.insertion_ordered_set import InsertionOrderedSet
from networkx import DiGraph

T = TypeVar("T", bound=AbstractSyntaxTreeNode)


class AbstractSyntaxInterface(ABC):
    """Interface for Abstract Syntax Tree structures."""

    def __init__(self, context=None):
        """Init a new abstract syntax graph."""
        self._ast = DiGraph()
        self._code_node_reachability_graph: ReachabilityGraph = ReachabilityGraph()
        context = LogicCondition.generate_new_context() if context is None else context
        self.factory = ASTNodeFactory(context, self)

    def __len__(self) -> int:
        """Return the overall amount of nodes."""
        return self._ast.number_of_nodes()

    def __eq__(self, other: object) -> bool:
        """Check whether the two ast's are equal."""
        # return isinstance(other, AbstractSyntaxInterface) and len(self.get_roots) == len(other.get_roots)
        return hash(other) == hash(self)

    def __iter__(self) -> Iterator[AbstractSyntaxTreeNode]:
        """Iterate all nodes contained in the graph."""
        yield from self._ast.nodes

    def __contains__(self, node: AbstractSyntaxTreeNode):
        """Check if a node is contained in the graph."""
        return node in self._ast.nodes

    def substitute_variable_in_condition(self, condition: LogicCondition, replacee: Variable, replacement: Variable):
        """Substitute the given variable replacee by the variable replacement in the given condition in the graph."""
        raise NotImplementedError("Not implemented!")

    @property
    def nodes(self) -> Tuple[AbstractSyntaxTreeNode, ...]:
        """Return a tuple containing all nodes in the graph."""
        return tuple(self._ast.nodes)

    @property
    def get_roots(self) -> Tuple[AbstractSyntaxTreeNode, ...]:
        """Returns the tuple of roots for all nodes."""
        return tuple(node for node, d in self._ast.in_degree() if not d)

    @property
    def edges(self) -> Tuple[Tuple[AbstractSyntaxTreeNode, AbstractSyntaxTreeNode], ...]:
        """Return a tuple containing all edges of the graph."""
        return tuple(self._ast.edges)

    # Node relations
    def parent(self, node: AbstractSyntaxTreeNode) -> Optional[AbstractSyntaxTreeNode]:
        """Return the parent nodes of the given node."""
        assert node in self, f"Node {node} is not in the AST."
        predecessors = list(self._ast.predecessors(node))
        assert len(predecessors) <= 1, f"In an AST, each node can have at most one predecessor. But {node} has two!"
        return predecessors[0] if predecessors else None

    def children(self, node: AbstractSyntaxTreeNode) -> Tuple[AbstractSyntaxTreeNode, ...]:
        """Return the child nodes of the given node."""
        assert node in self, f"Node {node} is not in the AST."
        return tuple(dict.fromkeys(self._ast.successors(node)))

    # Edges
    def get_in_edges(self, node: AbstractSyntaxTreeNode) -> Optional[Tuple[AbstractSyntaxTreeNode, AbstractSyntaxTreeNode]]:
        """Get all edges targeting the given node."""
        if parent := self.parent(node):
            return (parent, node)
        return None

    def get_out_edges(self, node: AbstractSyntaxTreeNode) -> Tuple[Tuple[AbstractSyntaxTreeNode, AbstractSyntaxTreeNode], ...]:
        """Get all edges starting at the given node."""
        return tuple((node, child) for child in self.children(node))

    # reachability

    def reachable_code_nodes(self, node: AbstractSyntaxTreeNode) -> InsertionOrderedSet[CodeNode]:
        """Returns the set of all code nodes that are reachable from the given AST node."""
        reachable_code_nodes, _ = self._code_node_reachability_graph.get_reachable_and_descendant_code_nodes_of(node)
        return reachable_code_nodes

    def reachable_code_nodes_from(self, code_nodes: InsertionOrderedSet[CodeNode]) -> InsertionOrderedSet[CodeNode]:
        """Returns the set of all code nodes that are reachable from the given set of code nodes."""
        return self._code_node_reachability_graph.get_nodes_reachable_from(code_nodes)

    def get_sibling_reachability_of_children_of(self, ast_node: Union[SeqNode, SwitchNode]) -> SiblingReachability:
        """
        Return the sibling reachability for the children of the given node,
        i.e., a representation that tells us which siblings a child reaches.
        """
        return self.get_sibling_reachability_for(self.children(ast_node))

    def get_sibling_reachability_for(self, ast_nodes: Tuple[AbstractSyntaxTreeNode, ...]) -> SiblingReachability:
        """Return the sibling reachability restricted to the given nodes."""
        return self._code_node_reachability_graph.compute_sibling_reachability_of(ast_nodes)

    # Graph traversal

    def post_order(self, source: AbstractSyntaxTreeNode = None) -> Iterator[AbstractSyntaxTreeNode]:
        """Iterate all nodes in post order starting at the given source, if it is given, else start from all roots."""
        if source:
            yield from self._post_order(source)
        else:
            for root in self.get_roots:
                yield from self._post_order(root)

    def _post_order(self, source: AbstractSyntaxTreeNode) -> Iterator[AbstractSyntaxTreeNode]:
        """Iterate all nodes in post order starting at the given source."""
        if not source:
            return
        for child in source.children:
            yield from self._post_order(source=child)
        yield source

    def pre_order(self, source: Optional[AbstractSyntaxTreeNode] = None) -> Iterator[AbstractSyntaxTreeNode]:
        """Iterate all nodes in pre order starting at the given source, if it is given, else start form all roots."""
        if source:
            yield from self._pre_order(source)
        else:
            for root in self.get_roots:
                yield from self._pre_order(root)

    def _pre_order(self, source: AbstractSyntaxTreeNode) -> Iterator[AbstractSyntaxTreeNode]:
        """Iterate all nodes in pre order starting at the given source."""
        if not source:
            return
        yield source
        for child in source.children:
            yield from self._pre_order(source=child)

    def topological_order(self, source: Optional[AbstractSyntaxTreeNode] = None) -> Iterator[AbstractSyntaxTreeNode]:
        """Iterate all nodes in topological order, if the graph is acyclic."""
        yield from self.pre_order(source)

    def _iter_post_order(self, src: Optional[AbstractSyntaxTreeNode], predicate: Callable[[T], bool]) -> Iterator[T]:
        """Iterate all nodes in post order starting at the given source that fulfill the predicate."""
        for node in self.post_order(src):
            if predicate and predicate(node):
                yield node

    def _iter_topological_order(self, src: Optional[AbstractSyntaxTreeNode], predicate: Callable[[T], bool]) -> Iterator[T]:
        """Iterate all nodes in topological order starting at the given source that fulfill the predicate."""
        for node in self.topological_order(src):
            if predicate and predicate(node):
                yield node

    def get_code_nodes_post_order(self, root: Optional[AbstractSyntaxTreeNode] = None) -> Iterator[CodeNode]:
        """Iterate all nodes in post order that are code nodes."""
        yield from self._iter_post_order(root, lambda x: isinstance(x, CodeNode))

    def get_code_nodes_topological_order(self, root: Optional[AbstractSyntaxTreeNode] = None) -> Iterator[CodeNode]:
        """Iterate all nodes in topological order that are code nodes."""
        yield from self._iter_topological_order(root, lambda x: isinstance(x, CodeNode))

    def get_sequence_nodes_post_order(self, root: Optional[AbstractSyntaxTreeNode] = None) -> Iterator[SeqNode]:
        """Iterate all nodes in post order that are sequence nodes."""
        yield from self._iter_post_order(root, lambda x: isinstance(x, SeqNode))

    def get_sequence_nodes_topological_order(self, root: Optional[AbstractSyntaxTreeNode] = None) -> Iterator[SeqNode]:
        """Iterate all nodes in topological order that are sequence nodes."""
        yield from self._iter_topological_order(root, lambda x: isinstance(x, SeqNode))

    def get_condition_nodes_post_order(self, root: Optional[AbstractSyntaxTreeNode] = None) -> Iterator[ConditionNode]:
        """Iterate all nodes in post order that are condition nodes."""
        yield from self._iter_post_order(root, lambda x: isinstance(x, ConditionNode))

    def get_loop_nodes_post_order(self, root: Optional[AbstractSyntaxTreeNode] = None) -> Iterator[LoopNode]:
        """Iterate all nodes in post order that are loop nodes."""
        yield from self._iter_post_order(root, lambda x: isinstance(x, LoopNode))

    def get_switch_nodes_post_order(self, root: Optional[AbstractSyntaxTreeNode] = None) -> Iterator[SwitchNode]:
        """Iterate all nodes in post order that are switch nodes."""
        yield from self._iter_post_order(root, lambda x: isinstance(x, SwitchNode))

    # Graph manipulation - extern

    def add_endless_loop_with_body(self, body: AbstractSyntaxTreeNode) -> WhileLoopNode:
        """Construct an endless while loop with the given body. The body must be a node of the Abstract Syntax Forest."""
        assert body in self, f"The body {body} is not contained in the AST!"
        assert body.parent is None, f"The body {body} already has a parent!"
        while_loop = self.factory.create_endless_loop_node()
        self._add_node(while_loop)
        self._add_edge(while_loop, body)
        return while_loop

    def substitute_loop_node(self, old_loop_node: LoopNode, new_loop_node: LoopNode):
        """Substitute the loop node by another loop node."""
        assert old_loop_node in self and new_loop_node not in self, f"The old node must be in the AST and the new node node."
        assert isinstance(old_loop_node, LoopNode) and isinstance(new_loop_node, LoopNode), "Both nodes must be loop nodes!"
        self._substitute_node(old_loop_node, new_loop_node)

    def replace_seq_node_by_single_child(self, node: SeqNode):
        """This function replaces the given Sequence Node by its single child in the AST."""
        assert len(node.children) == 1 and isinstance(node, SeqNode), f"This works only for sequence nodes that have only one child!"
        child = node.children[0]
        self._replace_subtree(node, child)

    def flatten_sequence_node(self, seq_node: SeqNode):
        """If a sequence node has a sequence node as child with reaching condition true, then we remove it."""
        sorted_nodes = list()
        for child in seq_node.children:
            if isinstance(child, SeqNode) and child.reaching_condition.is_true:
                sorted_nodes += list(child.children)
                self._add_edges_from((seq_node, succ) for succ in child.children)
                self._remove_node(child)
            else:
                sorted_nodes.append(child)
        seq_node._sorted_children = tuple(sorted_nodes)

    def switch_branches(self, condition_node: ConditionNode):
        """Switch the true branch and false branch. This also changes the condition."""
        if condition_node.is_empty:
            return
        true_branch = condition_node.true_branch
        false_branch = condition_node.false_branch
        true_branch_child = condition_node.true_branch_child
        false_branch_child = condition_node.false_branch_child
        if true_branch_child:
            self._substitute_node(true_branch, self.factory.create_false_node())
        if false_branch_child:
            self._substitute_node(false_branch, self.factory.create_true_node())
        condition_node.condition = ~condition_node.condition

    def add_instructions_after(self, node: AbstractSyntaxTreeNode, *instruction: Instruction) -> AbstractSyntaxTreeNode:
        """
        Add an instruction after the given AST node.
            - If it is a CodeNode, we insert it as final instruction and return this node
            - Otherwise, we insert a sequence node that has node and the new code node has child and return it.

        If we add the instruction to a code-node then we return the code node. Otherwise, we return the parent of the newly added code node.
        """
        if isinstance(node, CodeNode) and node.reaching_condition.is_true:
            node.instructions += list(instruction)
            return node

        new_code_node = self._add_code_node(list(instruction))
        for code_node in node.get_descendant_code_nodes():
            self._code_node_reachability_graph.add_reachability(code_node, new_code_node)
            self._code_node_reachability_graph.add_reachability_from(
                (new_code_node, reaching) for reaching in node.get_reachable_code_nodes()
            )

        new_seq_node = self._add_sequence_node_before(node)
        self._add_edge(new_seq_node, new_code_node)
        new_seq_node._sorted_children = (node, new_code_node)
        if isinstance(parent := new_seq_node.parent, SeqNode):
            parent.clean()
            return parent

        return new_seq_node

    def remove_subtree(self, node: AbstractSyntaxTreeNode):
        """Remove the subtree with the given node as root."""
        for node in self.post_order(node):
            self._remove_node(node)

    def remove_empty_nodes(self, root: Optional[AbstractSyntaxTreeNode] = None):
        """
        Remove all empty nodes that are not needed.
        This includes empty code nodes, and all AST-nodes without children, except CaseNodes and LoopNodes.

        Since we iterate in post-order, each empty node has no child.
        """
        empty_nodes: Set[AbstractSyntaxTreeNode] = set()
        for node in self.post_order(root):
            if isinstance(node, CodeNode) and not node.is_empty_code_node:
                continue
            if all(child in empty_nodes for child in node.children):
                self.__handle_empty_node(node, empty_nodes)
            else:
                self.__remove_empty_children_of(node, empty_nodes)
            if self.parent(node) is None and node in empty_nodes:
                self.remove_subtree(node)

    def __remove_empty_children_of(self, node: AbstractSyntaxTreeNode, empty_nodes: Set[AbstractSyntaxTreeNode]):
        """Removes all children of the given node that are also contained in the given set of nodes."""
        for child in node.children:
            if child in empty_nodes:
                self.remove_subtree(child)

    def __handle_empty_node(self, node: AbstractSyntaxTreeNode, empty_nodes: Set[AbstractSyntaxTreeNode]):
        """
        Handles how we proceed with the given node whose children are all empty.

        -> If it is a CaseNode or LoopNode, then the node is not empty.
           In this case we want the the child resp. body is an empty code node and have to handle the reachability of this code node.
        -> Otherwise, the node itself is also empty.
        """
        if isinstance(node, (CaseNode, LoopNode)):
            child = node.body if isinstance(node, LoopNode) else node.child
            if child.is_empty_code_node:
                return
            new_empty_code_node = self._add_code_node()
            for code_node in node.get_descendant_code_nodes():
                self._code_node_reachability_graph.contract_code_nodes(new_empty_code_node, code_node)
            self._add_edge(node, new_empty_code_node)
            self.remove_subtree(child)
        else:
            empty_nodes.add(node)

    def clean_up(self, root: Optional[AbstractSyntaxTreeNode] = None) -> None:
        """
        Remove empty nodes and call clean for each node, i.e., unifies the abstract syntax forest.

        If a root is given as input and is removed during this procedure, we return the new root of the subtree with this root.
        """
        self.remove_empty_nodes(root)
        for node in self.post_order(root):
            node.clean()

    def replace_condition_node_by_single_branch(self, node: ConditionNode):
        """This function replaces the given AST- condition node by its single child in the AST."""
        assert isinstance(node, ConditionNode), f"This transformation works only for condition nodes!"
        assert len(node.children) == 1, f"This works only if the Condition node has only one child!"
        node.clean()
        self._replace_subtree(node, node.true_branch_child)

    def replace_variable_in_subtree(self, head: AbstractSyntaxTreeNode, replacee: Variable, replacement: Variable):
        for node in self.topological_order(head):
            node.replace_variable(replacee, replacement)

    # Graph manipulation - intern

    def _add_node(self, node: AbstractSyntaxTreeNode):
        """Add a node to the graph. If it is a CodeNode, we also add it to the reachability_graph."""
        node._ast = self
        if isinstance(node, CodeNode):
            self._code_node_reachability_graph.add_code_node(node)
        self._ast.add_node(node)

    def _add_nodes_from(self, nodes: Iterable[AbstractSyntaxTreeNode]):
        """Add multiple nodes to the graph (legacy)."""
        for node in nodes:
            self._add_node(node)

    def _add_edge(self, source: AbstractSyntaxTreeNode, sink: AbstractSyntaxTreeNode):
        """Add a single edge between the given nodes to the graph."""
        assert source in self and sink in self, f"The nodes are not contained in the graph!"
        self._ast.add_edge(source, sink)

    def _add_edges_from(self, edges: Iterable[Tuple[AbstractSyntaxTreeNode, AbstractSyntaxTreeNode]]):
        """Add multiple edges to the graph (legacy)."""
        for edge in edges:
            self._add_edge(*edge)

    def _remove_node(self, node: AbstractSyntaxTreeNode):
        """Remove the node from the graph."""
        if isinstance(node.parent, SeqNode):
            node.parent._sorted_children = tuple(child for child in node.parent._sorted_children if child != node)
        if isinstance(node, CodeNode):
            self._code_node_reachability_graph.remove_code_node(node)
        self._ast.remove_node(node)

    def _remove_nodes_from(self, nodes: Iterable[AbstractSyntaxTreeNode]):
        """Remove all nodes from the given iterator."""
        for node in nodes:
            self._remove_node(node)

    def _remove_edge(self, source: AbstractSyntaxTreeNode, sink: AbstractSyntaxTreeNode):
        """Remove the given edge from the graph."""
        self._ast.remove_edge(source, sink)

    def _remove_edges_from(self, edges: Iterable[Tuple[AbstractSyntaxTreeNode, AbstractSyntaxTreeNode]]):
        """Remove all nodes in the given tuple from the graph."""
        for edge in edges:
            self._remove_edge(*edge)

    def _add_code_node(self, instructions: Optional[List[Instruction]] = None) -> CodeNode:
        """Add an CodeNode with the given list of instructions to the abstract syntax forest."""
        instructions = instructions if instructions else []
        code_node = self.factory.create_code_node(instructions)
        self._add_node(code_node)
        return code_node

    def _add_condition_node_with(
        self,
        condition: LogicCondition,
        true_branch: Optional[AbstractSyntaxTreeNode] = None,
        false_branch: Optional[AbstractSyntaxTreeNode] = None,
    ) -> ConditionNode:
        """Add a condition node with the given parameters to the syntax forest and return it."""
        condition_node = self.factory.create_condition_node(condition)
        self._add_node(condition_node)
        if true_branch is not None:
            true_node = self.factory.create_true_node()
            self._add_node(true_node)
            self._add_edges_from(((condition_node, true_node), (true_node, true_branch)))
        if false_branch is not None:
            false_node = self.factory.create_false_node()
            self._add_node(false_node)
            self._add_edges_from(((condition_node, false_node), (false_node, false_branch)))

        return condition_node

    def _substitute_node(self, replacee: AbstractSyntaxTreeNode, replacement: AbstractSyntaxTreeNode):
        """Substitute the node replacee by the node replacement. Make sure that the substitution is valid!!!"""
        parent = replacee.parent
        children = replacee.children
        self._add_node(replacement)
        if parent is not None:
            self._add_edge(parent, replacement)
        for child in children:
            self._add_edge(replacement, child)
        if isinstance(parent, SeqNode):
            parent._sorted_children = tuple(replacement if child == replacee else child for child in parent._sorted_children)

        self._remove_node(replacee)

    def _replace_subtree(self, replacee_root: AbstractSyntaxTreeNode, replacement_root: AbstractSyntaxTreeNode):
        """Replaces the subtree with root replacee_root by the subtree with root replacement_root"""
        if replacement_root in self and replacement_root.parent:
            self._remove_edge(replacement_root.parent, replacement_root)
        self._add_node(replacement_root)
        parent = replacee_root.parent
        if isinstance(parent, SeqNode):
            parent._sorted_children = tuple(replacement_root if nd == replacee_root else nd for nd in parent.children)
        self.remove_subtree(replacee_root)
        if parent:
            self._add_edge(parent, replacement_root)

    def _add_sequence_node_before(self, node: AbstractSyntaxTreeNode) -> SeqNode:
        """Introduce a sequence node before the given node."""
        new_seq = self.factory.create_seq_node()
        self._add_node(new_seq)
        parent = node.parent
        if parent is not None:
            if isinstance(parent, SeqNode):
                parent._sorted_children = tuple(new_seq if child == node else child for child in parent._sorted_children)
            self._remove_edge(parent, node)
            self._add_edge(parent, new_seq)
        self._add_edge(new_seq, node)
        return new_seq

    def have_same_parent(self, ast_nodes: Iterable[AbstractSyntaxTreeNode]) -> Optional[AbstractSyntaxTreeNode]:
        """Check whether the given set of nodes have the same parent."""
        parents = set(node.parent for node in ast_nodes)
        return parents.pop() if len(parents) == 1 else None
