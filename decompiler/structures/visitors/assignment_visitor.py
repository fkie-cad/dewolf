from typing import List

from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CodeNode, ForLoopNode, LoopNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.pseudo import Assignment
from decompiler.structures.visitors.ast_dataflowobjectvisitor import BaseAstDataflowObjectVisitor


class AssignmentVisitor(BaseAstDataflowObjectVisitor):
    """Visits all variable assignments in the AST and produces a list"""

    def __init__(self):
        """Create a new assignment visitor collecting all visited assignments."""
        self.assignments: List[Assignment] = list()

    @classmethod
    def from_ast(cls, ast: AbstractSyntaxTree, head: AbstractSyntaxTreeNode = None) -> List[Assignment]:
        """Return all assignments in the given AST, if given starting at the node else at the root."""
        visitor = cls()
        for node in ast.pre_order(head):
            visitor.visit(node)
        return visitor.assignments

    def visit_loop_node(self, node: LoopNode):
        """Visit the given LoopNode, if it is a ForLoopNode take declaration and modification."""
        if isinstance(node, ForLoopNode):
            if isinstance(node.declaration, Assignment):
                self.assignments.append(node.declaration)
            self.assignments.append(node.modification)

    def visit_code_node(self, node: CodeNode):
        """Visit the given CodeNode, remembering all Assignment instructions."""
        for stmt in node.instructions:
            if isinstance(stmt, Assignment):
                self.assignments.append(stmt)
