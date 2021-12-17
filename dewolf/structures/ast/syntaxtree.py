from __future__ import annotations

from typing import Dict, Iterator, Optional, Tuple

from dewolf.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CodeNode, ForLoopNode, VirtualRootNode, WhileLoopNode
from dewolf.structures.ast.syntaxforest import AbstractSyntaxForest
from dewolf.structures.ast.syntaxgraph import AbstractSyntaxInterface
from dewolf.structures.logic.logic_condition import LogicCondition
from dewolf.structures.pseudo import Condition, Variable


class AbstractSyntaxTree(AbstractSyntaxInterface):
    """Class representing an Abstract Syntax Tree."""

    def __init__(self, root: AbstractSyntaxTreeNode, condition_map: Dict[LogicCondition, Condition]):
        """
        Init a new empty abstract syntax tree.

        root -- optional the root of the AST
        condition_map -- in charge of handling all conditions that are contained in the syntax forest.

        self._root -- root node that points to the root of the ast.

        In a syntax tree each AST-node has reaching condition True.
        """
        super().__init__(context=root.reaching_condition.context)
        self.condition_map: Dict[LogicCondition, Condition] = condition_map
        self._root: VirtualRootNode = self.factory.create_virtual_node()
        self._add_node(self._root)
        self._add_node(root)
        self._add_edge(self._root, root)

    @property
    def get_roots(self) -> Tuple[AbstractSyntaxTreeNode, ...]:
        """Checks that the only root of the AST is the node self._root and returns its unique child in a tuple."""
        assert super().get_roots == (self._root,), f"A syntax tree can have only one root!"
        return (self.root,)

    @property
    def root(self) -> Optional[AbstractSyntaxTreeNode]:
        """Return the root node of the ast."""
        return self._root.child

    @classmethod
    def from_asforest(cls, asforest: AbstractSyntaxForest, root: AbstractSyntaxTreeNode) -> AbstractSyntaxTree:
        """Construct an AST from an abstract syntax forest. This forest should only have one root."""
        ast_nodes = list(asforest.topological_order(root))
        ast_edges = list(e for e in asforest.edges if not isinstance(e[0], VirtualRootNode))
        ast = cls(root, asforest.condition_handler.get_condition_map())
        ast._add_nodes_from(ast_nodes)
        ast._add_edges_from(ast_edges)
        ast.clean_up(ast.root)
        return ast

    def substitute_variable_in_condition(self, condition: LogicCondition, replacee: Variable, replacement: Variable):
        """Substitute the given variable replacee with the variable replacement in the given condition by updating the condition map."""
        for symbol in condition.get_symbols():
            self.condition_map[symbol].substitute(replacee, replacement)

    # Iterations
    def get_while_loop_nodes_topological_order(self, root: Optional[AbstractSyntaxTreeNode] = None) -> Iterator[WhileLoopNode]:
        """Iterate all nodes in topological order that are while loop nodes."""
        root = self.root if root is None else root
        yield from self._iter_topological_order(root, lambda x: isinstance(x, WhileLoopNode))

    def get_for_loop_nodes_topological_order(self, root: Optional[AbstractSyntaxTreeNode] = None) -> Iterator[ForLoopNode]:
        """Iterate all nodes in topological order that are for loop nodes."""
        root = self.root if root is None else root
        yield from self._iter_topological_order(root, lambda x: isinstance(x, ForLoopNode))

    def get_reachable_nodes_pre_order(self, source: AbstractSyntaxTreeNode) -> Iterator[AbstractSyntaxTreeNode]:
        iterator = self.pre_order()
        current_node = next(iterator)
        while current_node is not source:
            current_node = next(iterator)
        yield source
        yield from iterator

    def get_code_nodes_topological_order(self, root: Optional[AbstractSyntaxTreeNode] = None) -> Iterator[CodeNode]:
        """Iterate all nodes in topological order that are code nodes."""
        root = self.root if root is None else root
        yield from self._iter_topological_order(root, lambda x: isinstance(x, CodeNode))

    # Graph manipulation - intern
    def _remove_node(self, node: AbstractSyntaxTreeNode):
        """Remove the node from the graph."""
        assert node != self._root, "It is not allowed to remove the root node!"
        super()._remove_node(node)
