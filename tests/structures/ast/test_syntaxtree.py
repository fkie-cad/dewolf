""" Tests for the AbstractSyntaxTree base class."""
import pytest
from decompiler.structures.ast.ast_nodes import CodeNode, SeqNode, VirtualRootNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree

# Fixtures for example ASTs
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import Assignment, Condition, Constant, OperationType, Return, Variable

new_context = LogicCondition.generate_new_context()


@pytest.fixture
def empty_node():
    """An empty CodeNode."""
    return CodeNode(stmts=[], reaching_condition=LogicCondition.initialize_true(new_context))


@pytest.fixture
def ast_single():
    """AST only containing an empty CodeNode."""
    return AbstractSyntaxTree(
        root=CodeNode(stmts=[], reaching_condition=LogicCondition.initialize_true(LogicCondition.generate_new_context())),
        condition_map=dict(),
    )


def test_create_empty_ast():
    """Create an empty AST -> empty SeqNode"""
    ast = AbstractSyntaxTree(root=SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context())), condition_map=dict())
    assert (
        len(ast) == 2 and set(ast.nodes) == {ast._root, ast.root} and isinstance(ast._root, VirtualRootNode) and ast.condition_map == dict()
    )


def test_create_ast_with_root():
    ast = AbstractSyntaxTree(
        root=CodeNode([], reaching_condition=LogicCondition.initialize_true(LogicCondition.generate_new_context())), condition_map=dict()
    )
    assert len(ast) == 2 and set(ast.nodes) == {ast._root, ast.root} and ast.root.is_empty_code_node and ast.condition_map == dict()


class TestIterators:
    """Test iterating over abstract syntax trees."""

    def test_reachable_nodes_pre_order(self):
        context = LogicCondition.generate_new_context()
        condition_a = LogicCondition.initialize_symbol("a", context)
        condition_map = {condition_a: Condition(OperationType.less, [Variable("a"), Variable("b")])}

        ast = AbstractSyntaxTree(root := SeqNode(LogicCondition.initialize_true(context)), condition_map)

        code_node_1 = ast._add_code_node([Assignment(Variable("a"), Constant(0)), Assignment(Variable("b"), Constant(1))])

        condition_node_true = ast._add_code_node([Assignment(Variable("a"), Constant(0))])
        condition_node_false = ast._add_code_node([Assignment(Variable("a"), Constant(1))])
        condition_node = ast._add_condition_node_with(condition_a, condition_node_true, condition_node_false)

        code_node_2 = ast._add_code_node([Return([Variable("a")])])

        ast._add_edges_from([(root, code_node_1), (root, condition_node), (root, code_node_2)])

        assert list(ast.get_reachable_nodes_pre_order(root)) == list(ast.pre_order())
        assert list(ast.get_reachable_nodes_pre_order(code_node_1)) == [
            code_node_1,
            condition_node,
            condition_node.true_branch,
            condition_node_true,
            condition_node.false_branch,
            condition_node_false,
            code_node_2,
        ]
        assert list(ast.get_reachable_nodes_pre_order(condition_node)) == [
            condition_node,
            condition_node.true_branch,
            condition_node_true,
            condition_node.false_branch,
            condition_node_false,
            code_node_2,
        ]
        assert list(ast.get_reachable_nodes_pre_order(condition_node_true)) == [
            condition_node_true,
            condition_node.false_branch,
            condition_node_false,
            code_node_2,
        ]
        assert list(ast.get_reachable_nodes_pre_order(condition_node_false)) == [condition_node_false, code_node_2]
        assert list(ast.get_reachable_nodes_pre_order(code_node_2)) == [code_node_2]
