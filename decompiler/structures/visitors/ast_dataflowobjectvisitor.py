from abc import ABC
from typing import List

from decompiler.structures.ast.ast_nodes import (
    CaseNode,
    CodeNode,
    ConditionNode,
    FalseNode,
    ForLoopNode,
    LoopNode,
    SeqNode,
    SwitchNode,
    TrueNode,
    VirtualRootNode,
)
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.pseudo.expressions import Constant, DataflowObject, RegisterPair, UnknownExpression, Variable
from decompiler.structures.pseudo.instructions import Assignment, Break, Comment, Continue, GenericBranch, MemPhi, Phi, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, TernaryExpression, UnaryOperation
from decompiler.structures.visitors.interfaces import ASTVisitorInterface, DataflowObjectVisitorInterface


class AstDataflowObjectVisitor(ASTVisitorInterface, DataflowObjectVisitorInterface, ABC):
    def visit_ast(self, ast: AbstractSyntaxTree):
        """Visit the ast, calling visit methods for all DataflowObjects."""
        for condition in ast.condition_map.values():
            self.visit_subexpressions(condition)
        for node in ast.nodes:
            self.visit(node)

    def visit_subexpressions(self, df_object: DataflowObject):
        """Visit all subexpressions of the given DataflowObject."""
        unvisited_objects: List[DataflowObject] = [df_object]
        while unvisited_objects and (head := unvisited_objects.pop()):
            self.visit(head)
            unvisited_objects.extend(head)

    def visit_code_node(self, node: CodeNode):
        """Visit all DataflowObjects in the CodeNode."""
        for instruction in node.instructions:
            self.visit_subexpressions(instruction)

    def visit_condition_node(self, node: ConditionNode):
        """Visit all DataflowObjects in the ConditionNode."""
        pass

    def visit_root_node(self, node: VirtualRootNode):
        """Visit all DataflowObjects in the VirtualRootNode."""
        pass

    def visit_seq_node(self, node: SeqNode):
        """Visit all DataflowObjects in the SeqNode."""
        pass

    def visit_switch_node(self, node: SwitchNode):
        """Visit all DataflowObjects in the SwitchNode."""
        self.visit(node.expression)

    def visit_case_node(self, node: CaseNode):
        """Visit all DataflowObjects in the CaseNode."""
        self.visit_subexpressions(node.expression)
        if isinstance(node.constant, Constant):
            self.visit(node.constant)

    def visit_loop_node(self, node: LoopNode):
        """Visit all DataflowObjects in the LoopNode."""
        if isinstance(node, ForLoopNode):
            self.visit_subexpressions(node.declaration)
            self.visit_subexpressions(node.modification)

    def visit_true_node(self, node: TrueNode):
        """Visit all DataflowObjects in the TrueNode."""
        pass

    def visit_false_node(self, node: FalseNode):
        """Visit all DataflowObjects in the FalseNode."""
        pass


class BaseAstDataflowObjectVisitor(AstDataflowObjectVisitor):
    """Base implementation of the DataflowObject visitor for ASTs without function."""

    def visit_unknown_expression(self, expression: UnknownExpression):
        pass

    def visit_constant(self, expression: Constant):
        pass

    def visit_variable(self, expression: Variable):
        pass

    def visit_global_variable(self, expression: Variable):
        pass

    def visit_register_pair(self, expression: RegisterPair):
        pass

    def visit_list_operation(self, operation: ListOperation):
        pass

    def visit_unary_operation(self, operation: UnaryOperation):
        pass

    def visit_binary_operation(self, operation: BinaryOperation):
        pass

    def visit_ternary_expression(self, operation: TernaryExpression):
        pass

    def visit_call(self, operation: Call):
        pass

    def visit_condition(self, operation: Condition):
        pass

    def visit_comment(self, instruction: Comment):
        pass

    def visit_assignment(self, instruction: Assignment):
        pass

    def visit_generic_branch(self, instruction: GenericBranch):
        pass

    def visit_return(self, instruction: Return):
        pass

    def visit_break(self, instruction: Break):
        pass

    def visit_continue(self, instruction: Continue):
        pass

    def visit_phi(self, instruction: Phi):
        pass

    def visit_mem_phi(self, instruction: MemPhi):
        pass
