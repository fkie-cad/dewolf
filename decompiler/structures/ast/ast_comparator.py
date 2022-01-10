from typing import Dict, NewType, Optional, Tuple

from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, ConditionNode
from decompiler.structures.ast.syntaxgraph import AbstractSyntaxInterface

Color = NewType("Color", int)


class ASTComparator:
    """Class that handles the coloring of one or multiple graphs representing a world."""

    def __init__(self):
        """Generate a new type of class GraphColoringGenerator."""
        self._color_of_node: Dict[AbstractSyntaxTreeNode, Color] = dict()

    @classmethod
    def compare(cls, ast_forest_1: AbstractSyntaxInterface, ast_forest_2: AbstractSyntaxInterface) -> bool:
        """Compares whether two ASTs are the same"""
        if id(ast_forest_1) == id(ast_forest_2):
            return True
        ast_forest_1.clean_up()
        ast_forest_2.clean_up()
        if type(ast_forest_1) != type(ast_forest_2) and set(ast_forest_1.get_roots) != set(ast_forest_2.get_roots):
            return False

        graph_coloring_generator = cls()
        graph_coloring_generator.color_as_forest(ast_forest_1)
        graph_coloring_generator.color_as_forest(ast_forest_2)
        ast_forest_1_roots = {graph_coloring_generator.color_of_node(root) for root in ast_forest_1.get_roots}
        ast_forest_2_roots = {graph_coloring_generator.color_of_node(root) for root in ast_forest_2.get_roots}

        return ast_forest_1_roots == ast_forest_2_roots

    def color_of_node(self, node: AbstractSyntaxTreeNode) -> Optional[Color]:
        """Return color of the given node."""
        return self._color_of_node.get(node)

    def color_as_forest(self, as_forest: AbstractSyntaxInterface) -> None:
        """Color the head node and returns its color."""
        for node in as_forest.post_order():
            self._color_of_node[node] = self._compute_color_of(node)

    def _get_children_classes(self, node: AbstractSyntaxTreeNode) -> Tuple[Color, ...]:
        """Return tuple of classes of the operands."""
        if isinstance(node, ConditionNode) and node.false_branch is not None:
            if self._color_of_node[node.true_branch_child] > self._color_of_node[node.false_branch_child]:
                node.switch_branches()
                self._color_of_node[node.true_branch] = self._compute_color_of(node.true_branch)
                self._color_of_node[node.false_branch] = self._compute_color_of(node.false_branch)
            return self._color_of_node[node.true_branch], self._color_of_node[node.false_branch]
        return tuple(self._color_of_node[child] for child in node.children)

    def _compute_color_of(self, node: AbstractSyntaxTreeNode) -> Color:
        """Compute color of the node."""
        children: Tuple[Color, ...] = self._get_children_classes(node)
        identifier = f"{node}, {children}"
        return Color(hash(identifier))
