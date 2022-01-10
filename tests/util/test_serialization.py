from typing import Union

import pytest
from decompiler.structures.ast.ast_nodes import (
    AbstractSyntaxTreeNode,
    CaseNode,
    CodeNode,
    ConditionNode,
    DoWhileLoopNode,
    FalseNode,
    ForLoopNode,
    SeqNode,
    SwitchNode,
    TrueNode,
    WhileLoopNode,
)
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Assignment, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Condition, OperationType
from decompiler.structures.pseudo.typing import Integer, Type
from decompiler.util.serialization.ast_serializer import AstNodeSerializer, AstSerializer


def var(name: str, _type: Type = Integer.int32_t()) -> Variable:
    return Variable(name, _type)


def const(value: Union[int, str], _type: Type = Integer.int32_t()) -> Constant:
    return Constant(value, _type)


new_context = LogicCondition.generate_new_context()


def true_value(context=new_context) -> LogicCondition:
    return LogicCondition.initialize_true(context)


def false_value(context=new_context) -> LogicCondition:
    return LogicCondition.initialize_false(context)


def logic_cond(name: str, context=new_context) -> LogicCondition:
    return LogicCondition.initialize_symbol(name, context)


class TestAstNodeSerialization:
    """Test if ast nodes are serialized and deserialized correctly."""

    @staticmethod
    def save_and_load(node: AbstractSyntaxTreeNode):
        serializer = AstNodeSerializer()
        data = serializer.serialize(node)
        return serializer.deserialize(data)

    @pytest.mark.parametrize(
        "node",
        [SeqNode(true_value(LogicCondition.generate_new_context())), SeqNode(logic_cond("x1", LogicCondition.generate_new_context()))],
    )
    def test_sequence_node(self, node: SeqNode):
        AbstractSyntaxTree(root=node, condition_map={})  # SeqNodes need to be part of an AST in order to get its children
        result = self.save_and_load(node)
        assert node == result

    @pytest.mark.parametrize(
        "context, node",
        [
            (context := LogicCondition.generate_new_context(), CodeNode([], true_value(context))),
            (context := LogicCondition.generate_new_context(), CodeNode([], false_value(context))),
            (context := LogicCondition.generate_new_context(), CodeNode([Assignment(var("a"), const(1))], true_value(context))),
        ],
    )
    def test_code_node(self, context, node: CodeNode):
        assert node == self.save_and_load(node)

    @pytest.mark.parametrize(
        "node",
        [
            ConditionNode(logic_cond("x1"), true_value()),
            ConditionNode(true_value(), true_value()),
            ConditionNode(false_value(), true_value()),
        ],
    )
    def test_condition_node(self, node: ConditionNode):
        assert node == self.save_and_load(node)

    @pytest.mark.parametrize("node", [TrueNode(true_value()), TrueNode(false_value())])
    def test_true_node(self, node: TrueNode):
        assert node == self.save_and_load(node)

    @pytest.mark.parametrize("node", [FalseNode(true_value()), FalseNode(false_value())])
    def test_false_node(self, node: FalseNode):
        assert node == self.save_and_load(node)

    @pytest.mark.parametrize("node", [WhileLoopNode(logic_cond("x1"), true_value()), WhileLoopNode(logic_cond("x1"), false_value())])
    def test_while_loop_node(self, node: WhileLoopNode):
        assert node == self.save_and_load(node)

    @pytest.mark.parametrize("node", [DoWhileLoopNode(logic_cond("x1"), true_value()), DoWhileLoopNode(logic_cond("x1"), false_value())])
    def test_do_while_loop_node(self, node: DoWhileLoopNode):
        assert node == self.save_and_load(node)

    @pytest.mark.parametrize(
        "node",
        [
            ForLoopNode(
                Assignment(var("i"), const(0)),
                logic_cond("x1"),
                Assignment(var("i"), BinaryOperation(OperationType.plus, [var("i"), const(1)])),
                true_value(),
            ),
            ForLoopNode(
                Assignment(var("i"), const(0)),
                logic_cond("x1"),
                Assignment(var("i"), BinaryOperation(OperationType.plus, [var("i"), const(1)])),
                false_value(),
            ),
        ],
    )
    def test_for_loop_node(self, node: ForLoopNode):
        assert node == self.save_and_load(node)

    @pytest.mark.parametrize(
        "node", [SwitchNode(var("a"), true_value()), SwitchNode(const(1), true_value()), SwitchNode(var("a"), false_value())]
    )
    def test_switch_node(self, node: SwitchNode):
        """SwitchNodes need to be part of an AST in order to get its children"""
        AbstractSyntaxTree(root=node, condition_map={})
        assert node == self.save_and_load(node)

    @pytest.mark.parametrize("node", [CaseNode(var("a"), const(0), true_value()), CaseNode(var("a"), const(0), false_value())])
    def test_case_node(self, node: CaseNode):
        assert node == self.save_and_load(node)


class TestAstSerialization:
    """Test if abstract syntax trees are serialized and deserialized correctly."""

    @pytest.fixture
    def sequence_ast(self) -> AbstractSyntaxTree:
        """AST with single CodeNode child."""
        context = LogicCondition.generate_new_context()
        root = SeqNode(true_value(context))
        ast = AbstractSyntaxTree(root, {})
        code_node = ast._add_code_node([Assignment(var("c"), const(5)), Return([var("c")])])
        ast._add_edge(root, code_node)
        return ast

    @pytest.fixture
    def sequence_ast_order(self) -> AbstractSyntaxTree:
        """AST with two CodeNodes as children in which the order matters."""
        root = SeqNode(true_value(LogicCondition.generate_new_context()))
        ast = AbstractSyntaxTree(root, {})
        cn_1 = ast._add_code_node([Assignment(var("c"), const(5))])
        cn_2 = ast._add_code_node([Assignment(var("c"), BinaryOperation(OperationType.plus, [var("c"), const(5)])), Return([var("c")])])
        ast._add_edge(root, cn_1)
        ast._add_edge(root, cn_2)
        ast._code_node_reachability_graph.add_reachability(cn_1, cn_2)
        return ast

    @pytest.fixture
    def endless_loop_ast(self) -> AbstractSyntaxTree:
        """AST with CodeNode and EndlessLoopNode with CodeNode body."""
        root = SeqNode(true_value(LogicCondition.generate_new_context()))
        ast = AbstractSyntaxTree(root, {})
        child_1 = ast._add_code_node([Assignment(var("c"), const(5))])
        loop_body = ast._add_code_node([Assignment(var("c"), BinaryOperation(OperationType.plus, [var("c"), const(5)]))])
        child_2 = ast.add_endless_loop_with_body(loop_body)
        ast._add_edges_from(((root, child_1), (root, child_2)))
        ast._code_node_reachability_graph.add_reachability(child_1, loop_body)
        return ast

    @pytest.fixture
    def for_loop_ast(self) -> AbstractSyntaxTree:
        """AST with CodeNode and ForLoopNode with CodeNode body."""
        context = LogicCondition.generate_new_context()
        root = SeqNode(true_value(context))
        ast = AbstractSyntaxTree(root, {logic_cond("x1", context): Condition(OperationType.less_or_equal, [var("i"), const(5)])})
        child_1 = ast._add_code_node([Assignment(var("c"), const(5))])
        child_2 = ast.factory.create_for_loop_node(
            declaration=Assignment(var("i"), const(0)),
            modification=Assignment(var("i"), BinaryOperation(OperationType.plus, [var("i"), const(1)])),
            condition=logic_cond("x1"),
        )
        body = ast._add_code_node([Assignment(var("c"), BinaryOperation(OperationType.plus, [var("c"), var("i")]))])
        ast._add_nodes_from((child_2, body))
        ast._add_edges_from(((root, child_1), (root, child_2), (child_2, body)))
        ast._code_node_reachability_graph.add_reachability(child_1, body)
        return ast

    @pytest.fixture
    def nested_loop_ast(self) -> AbstractSyntaxTree:
        """AST with nested EndlessLoopNodes."""
        context = LogicCondition.generate_new_context()
        root = SeqNode(true_value(context))
        ast = AbstractSyntaxTree(root, {logic_cond("x1", context): Condition(OperationType.equal, [var("x"), const(5)])})
        child_1 = ast._add_code_node([Assignment(var("c"), const(5))])
        nested_loop_body = ast._add_code_node([Assignment(var("c"), BinaryOperation(OperationType.plus, [var("c"), const(5)]))])
        nested_loop = ast.factory.create_while_loop_node(condition=~logic_cond("x1", context))
        ast._add_node(nested_loop)
        child_2 = ast.add_endless_loop_with_body(nested_loop)
        ast._add_edges_from(((root, child_1), (root, child_2), (nested_loop, nested_loop_body)))
        ast._code_node_reachability_graph.add_reachability(child_1, nested_loop_body)
        return ast

    @pytest.fixture
    def switch_ast(self) -> AbstractSyntaxTree:
        """AST with SwitchNode."""
        ast = AbstractSyntaxTree(switch := SwitchNode(var("a"), true_value(LogicCondition.generate_new_context())), {})

        # switch and cases
        case_1 = ast.factory.create_case_node(var("a"), const(0))
        case_code_1 = ast._add_code_node([Return([const(0)])])
        case_2 = ast.factory.create_case_node(var("a"), const(1))
        case_code_2 = ast._add_code_node([Return([const(1)])])
        switch._sorted_cases = (case_1, case_2)

        # add nodes and edges to AST
        ast._add_nodes_from([switch, case_1, case_2])
        ast._add_edges_from(
            [
                (switch, case_1),
                (switch, case_2),
                (case_1, case_code_1),
                (case_2, case_code_2),
            ]
        )
        ast._code_node_reachability_graph.add_reachability_from([(case_code_1, case_code_2)])
        return ast

    @pytest.fixture
    def switch_default_ast(self) -> AbstractSyntaxTree:
        """AST with SwitchNode with default case."""
        ast = AbstractSyntaxTree(switch := SwitchNode(var("a"), true_value(LogicCondition.generate_new_context())), {})

        # switch and cases
        case_1 = ast.factory.create_case_node(var("a"), const(0))
        case_code_1 = ast._add_code_node([Return([const(0)])])
        case_2 = ast.factory.create_case_node(var("a"), const(1))
        case_code_2 = ast._add_code_node([Return([const(1)])])
        case_3 = ast.factory.create_case_node(var("a"), "default")
        case_code_3 = ast._add_code_node([Return([const("DEFAULT")])])
        switch._sorted_cases = (case_1, case_2, case_3)

        # add nodes and edges to AST
        ast._add_nodes_from([switch, case_1, case_2, case_3])
        ast._add_edges_from(
            [(switch, case_1), (switch, case_2), (switch, case_3), (case_1, case_code_1), (case_2, case_code_2), (case_3, case_code_3)]
        )
        ast._code_node_reachability_graph.add_reachability_from([(case_code_1, case_code_2), (case_code_2, case_code_3)])
        return ast

    @pytest.fixture
    def if_else_ast(self) -> AbstractSyntaxTree:
        """AST with ConditionNode."""
        context = LogicCondition.generate_new_context()
        root = SeqNode(true_value(context))
        ast = AbstractSyntaxTree(root, {logic_cond("x1", context): Condition(OperationType.less, [var("c"), const(5)])})
        true_seq_node = ast.factory.create_seq_node()
        ast._add_node(true_seq_node)
        code_node = ast._add_code_node([Assignment(var("c"), const(5)), Return(var("c"))])
        false_code_node = ast._add_code_node([Return([const(0)])])
        condition_node = ast._add_condition_node_with(condition=logic_cond("x1"), true_branch=true_seq_node, false_branch=false_code_node)
        ast._add_edges_from(((root, condition_node), (true_seq_node, code_node)))
        return ast

    @staticmethod
    def save_and_load(ast: AbstractSyntaxTree) -> AbstractSyntaxTree:
        """Serializes AST and returns deserialized AST."""
        ast_serializer = AstSerializer()
        return ast_serializer.deserialize(ast_serializer.serialize(ast))

    @pytest.mark.parametrize(
        "fixture",
        [
            "sequence_ast",
            "sequence_ast_order",
            "if_else_ast",
            "endless_loop_ast",
            "for_loop_ast",
            "nested_loop_ast",
            "switch_ast",
            "switch_default_ast",
        ],
    )
    def test_ast_equal_before_and_after_serialization(self, fixture, request):
        """Tests if AST's have same properties before and after serialization/deserialization."""
        ast_in: AbstractSyntaxTree = request.getfixturevalue(fixture)
        ast_out: AbstractSyntaxTree = self.save_and_load(ast_in)

        # check that roots are equal
        assert ast_in.root == ast_out.root

        # check that every node is de-/serialized
        assert sorted(ast_in.nodes, key=lambda x: str(x)) == sorted(ast_out.nodes, key=lambda x: str(x))

        # check that every edge is de-/serialized
        assert sorted(ast_in.edges, key=lambda x: str(x)) == sorted(ast_out.edges, key=lambda x: str(x))

        # check condition maps are equal
        assert ast_in.condition_map == ast_out.condition_map

        # check CodeNode reachability graphs are equal
        assert ast_in._code_node_reachability_graph.nodes == ast_out._code_node_reachability_graph.nodes
        assert list(ast_in._code_node_reachability_graph.edges) == list(ast_out._code_node_reachability_graph.edges)

        # check that all CodeNodes are contained in the code node reachability graph
        assert [cn for cn in ast_out.get_code_nodes_post_order()] == [cn for cn in ast_out._code_node_reachability_graph.nodes]
