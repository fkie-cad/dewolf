from typing import List, Union

import pytest
from dewolf.structures.ast.ast_nodes import SeqNode, SwitchNode
from dewolf.structures.ast.syntaxtree import AbstractSyntaxTree
from dewolf.structures.logic.logic_condition import LogicCondition
from dewolf.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Break,
    Call,
    Comment,
    Condition,
    Constant,
    Continue,
    Expression,
    GenericBranch,
    Instruction,
    Integer,
    ListOperation,
    MemPhi,
    Operation,
    OperationType,
    Phi,
    Return,
    TernaryExpression,
    Type,
    UnaryOperation,
    UnknownExpression,
    Variable,
)
from dewolf.structures.visitors.assignment_visitor import AssignmentVisitor
from dewolf.structures.visitors.ast_dataflowobjectvisitor import BaseAstDataflowObjectVisitor


def var(name: str, _type: Type = Integer.int32_t()) -> Variable:
    return Variable(name, _type)


def const(value: Union[int, str], _type: Type = Integer.int32_t()) -> Constant:
    return Constant(value, _type)


class TestAssignmentVisitor:
    """Check if AssignmentVisitor works as expected."""

    @pytest.fixture
    def code_node_ast(self) -> AbstractSyntaxTree:
        """AST with two CodeNodes."""
        root = SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context()))
        ast = AbstractSyntaxTree(root, {})
        cn_1 = ast._add_code_node([Assignment(var("c"), const(5))])
        cn_2 = ast._add_code_node([Assignment(var("c"), BinaryOperation(OperationType.plus, [var("c"), const(5)])), Return([var("c")])])
        ast._add_edge(root, cn_1)
        ast._add_edge(root, cn_2)
        ast._code_node_reachability_graph.add_reachability(cn_1, cn_2)
        return ast

    @pytest.fixture
    def for_loop_ast(self) -> AbstractSyntaxTree:
        """AST with CodeNode and ForLoopNode with CodeNode body."""
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(
            root, {LogicCondition.initialize_symbol("x1", context): Condition(OperationType.less_or_equal, [var("i"), const(5)])}
        )
        child_1 = ast._add_code_node([Assignment(var("c"), const(5))])
        child_2 = ast.factory.create_for_loop_node(
            declaration=Assignment(var("i"), const(0)),
            modification=Assignment(var("i"), BinaryOperation(OperationType.plus, [var("i"), const(1)])),
            condition=LogicCondition.initialize_symbol("x1", context),
        )
        body = ast._add_code_node([Assignment(var("c"), BinaryOperation(OperationType.plus, [var("c"), var("i")]))])
        ast._add_nodes_from((child_2, body))
        ast._add_edges_from(((root, child_1), (root, child_2), (child_2, body)))
        ast._code_node_reachability_graph.add_reachability(child_1, body)
        return ast

    # Tests

    def test_code_node_ast(self, code_node_ast: AbstractSyntaxTree):
        assert AssignmentVisitor.from_ast(code_node_ast) == [
            Assignment(var("c"), const(5)),
            Assignment(var("c"), BinaryOperation(OperationType.plus, [var("c"), const(5)])),
        ]
        assert AssignmentVisitor.from_ast(code_node_ast, code_node_ast.nodes[-1]) == [
            Assignment(var("c"), BinaryOperation(OperationType.plus, [var("c"), const(5)])),
        ]

    def test_for_loop_ast(self, for_loop_ast: AbstractSyntaxTree):
        assert AssignmentVisitor.from_ast(for_loop_ast) == [
            Assignment(var("c"), const(5)),
            Assignment(var("i"), const(0)),
            Assignment(var("i"), BinaryOperation(OperationType.plus, [var("i"), const(1)])),
            Assignment(var("c"), BinaryOperation(OperationType.plus, [var("c"), var("i")])),
        ]
        assert AssignmentVisitor.from_ast(for_loop_ast, for_loop_ast.nodes[-1]) == [
            Assignment(var("i"), const(0)),
            Assignment(var("i"), BinaryOperation(OperationType.plus, [var("i"), const(1)])),
            Assignment(var("c"), BinaryOperation(OperationType.plus, [var("c"), var("i")])),
        ]


class TestDataflowObjectVisitor:
    """Check if DataflowObjectVisitor works as expected"""

    class ConcreteAstDataflowObjectVisitor(BaseAstDataflowObjectVisitor):
        """Concrete implementation of BaseAstDataflowObjectVisitor interface."""

        def __init__(self):
            self.visited_instructions: List[Instruction] = []
            self.visited_operations: List[Operation] = []
            self.visited_expressions: List[Expression] = []

        """Visitors for instructions."""

        def visit_assignment(self, instruction: Assignment):
            self.visited_instructions.append(instruction)

        def visit_comment(self, instruction: Comment):
            self.visited_instructions.append(instruction)

        def visit_phi(self, instruction: Phi):
            self.visited_instructions.append(instruction)

        def visit_continue(self, instruction: Continue):
            self.visited_instructions.append(instruction)

        def visit_return(self, instruction: Return):
            self.visited_instructions.append(instruction)

        def visit_break(self, instruction: Break):
            self.visited_instructions.append(instruction)

        def visit_mem_phi(self, instruction: MemPhi):
            self.visited_instructions.append(instruction)

        def visit_generic_branch(self, instruction: GenericBranch):
            self.visited_instructions.append(instruction)

        """Visitors for operations"""

        def visit_call(self, operation: Call):
            self.visited_operations.append(operation)

        def visit_ternary_expression(self, operation: TernaryExpression):
            self.visited_operations.append(operation)

        def visit_binary_operation(self, operation: BinaryOperation):
            self.visited_operations.append(operation)

        def visit_unary_operation(self, operation: UnaryOperation):
            self.visited_operations.append(operation)

        def visit_condition(self, operation: Condition):
            self.visited_operations.append(operation)

        def visit_list_operation(self, operation: ListOperation):
            self.visited_operations.append(operation)

        """Visitors for expressions"""

        def visit_constant(self, expression: Constant):
            self.visited_expressions.append(expression)

        def visit_variable(self, expression: Variable):
            self.visited_expressions.append(expression)

        def visit_unknown_expression(self, expression: UnknownExpression):
            self.visited_expressions.append(expression)

    # FIXTURES

    @pytest.fixture
    def code_ast(self) -> AbstractSyntaxTree:
        """AST with two CodeNodes."""
        root = SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context()))
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
        root = SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context()))
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
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(
            root, {LogicCondition.initialize_symbol("x1", context): Condition(OperationType.less_or_equal, [var("i"), const(5)])}
        )
        child_1 = ast._add_code_node([Assignment(var("c"), const(5))])
        child_2 = ast.factory.create_for_loop_node(
            declaration=Assignment(var("i"), const(0)),
            modification=Assignment(var("i"), BinaryOperation(OperationType.plus, [var("i"), const(1)])),
            condition=LogicCondition.initialize_symbol("x1", context),
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
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(
            root, {LogicCondition.initialize_symbol("x1", context): Condition(OperationType.equal, [var("x"), const(5)])}
        )
        child_1 = ast._add_code_node([Assignment(var("c"), const(5))])
        nested_loop_body = ast._add_code_node([Assignment(var("c"), BinaryOperation(OperationType.plus, [var("c"), const(5)]))])
        nested_loop = ast.factory.create_while_loop_node(condition=~LogicCondition.initialize_symbol("x1", context))
        ast._add_node(nested_loop)
        child_2 = ast.add_endless_loop_with_body(nested_loop)
        ast._add_edges_from(((root, child_1), (root, child_2), (nested_loop, nested_loop_body)))
        ast._code_node_reachability_graph.add_reachability(child_1, nested_loop_body)
        return ast

    @pytest.fixture
    def switch_ast(self) -> AbstractSyntaxTree:
        """AST with SwitchNode."""
        root_switch_node = SwitchNode(
            expression=var("a"), reaching_condition=LogicCondition.initialize_true(LogicCondition.generate_new_context())
        )
        ast = AbstractSyntaxTree(root_switch_node, {})
        case_1 = ast.factory.create_case_node(expression=var("a"), constant=const(1))
        case_child_1 = ast._add_code_node([Assignment(var("c"), const(5)), Return([var("c")])])
        case_2 = ast.factory.create_case_node(expression=var("a"), constant=const(2))
        case_child_2 = ast._add_code_node([Return([var("b")])])
        ast._add_nodes_from((case_1, case_2))
        ast._add_edges_from(((root_switch_node, case_1), (root_switch_node, case_2), (case_1, case_child_1), (case_2, case_child_2)))
        ast._code_node_reachability_graph.add_reachability(case_child_1, case_child_2)
        root_switch_node._sorted_cases = (case_1, case_2)
        return ast

    @pytest.fixture
    def switch_default_ast(self) -> AbstractSyntaxTree:
        """AST with SwitchNode and default case."""
        root_switch_node = SwitchNode(
            expression=var("a"), reaching_condition=LogicCondition.initialize_true(LogicCondition.generate_new_context())
        )
        ast = AbstractSyntaxTree(root_switch_node, {})
        case_1 = ast.factory.create_case_node(expression=var("a"), constant=const(0))
        case_child_1 = ast._add_code_node([Assignment(var("c"), const(5)), Return([var("c")])])
        case_2 = ast.factory.create_case_node(expression=var("a"), constant=const(1))
        case_child_2 = ast._add_code_node([Return([var("b")])])
        default_case = ast.factory.create_case_node(expression=var("a"), constant="default")
        default_child = ast._add_code_node([Return([const(5)])])
        ast._add_nodes_from((case_1, case_2, default_case))
        ast._add_edges_from(
            (
                (root_switch_node, case_1),
                (root_switch_node, case_2),
                (root_switch_node, default_case),
                (case_1, case_child_1),
                (case_2, case_child_2),
                (default_case, default_child),
            )
        )
        ast._code_node_reachability_graph.add_reachability_from(((case_child_1, case_child_2), (case_child_2, default_child)))
        root_switch_node._sorted_cases = (case_1, case_2, default_case)
        return ast

    @pytest.fixture
    def if_else_ast(self) -> AbstractSyntaxTree:
        """AST with ConditionNode."""
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(
            root, {LogicCondition.initialize_symbol("x1", context): Condition(OperationType.less, [var("c"), const(5)])}
        )
        true_seq_node = ast.factory.create_seq_node()
        ast._add_node(true_seq_node)
        code_node = ast._add_code_node([Assignment(var("c"), const(5)), Return(var("c"))])
        false_code_node = ast._add_code_node([Return([const(0)])])
        condition_node = ast._add_condition_node_with(
            condition=LogicCondition.initialize_symbol("x1", context), true_branch=true_seq_node, false_branch=false_code_node
        )
        ast._add_edges_from(((root, condition_node), (true_seq_node, code_node)))
        return ast

    # TESTS

    def test_code_ast(self, code_ast: AbstractSyntaxTree):
        visitor = self.ConcreteAstDataflowObjectVisitor()
        visitor.visit_ast(code_ast)
        assert visitor.visited_instructions == [
            Assignment(var("c"), const(5)),
            Assignment(var("c"), BinaryOperation(OperationType.plus, [var("c"), const(5)])),
            Return([var("c")]),
        ]
        assert visitor.visited_operations == [BinaryOperation(OperationType.plus, [var("c"), const(5)])]
        assert visitor.visited_expressions == [const(5), var("c"), const(5), var("c"), var("c"), var("c")]

    def test_endless_loop_ast(self, endless_loop_ast: AbstractSyntaxTree):
        visitor = self.ConcreteAstDataflowObjectVisitor()
        visitor.visit_ast(endless_loop_ast)
        assert visitor.visited_instructions == [
            Assignment(var("c"), const(5)),
            Assignment(var("c"), BinaryOperation(OperationType.plus, [var("c"), const(5)])),
        ]
        assert visitor.visited_operations == [BinaryOperation(OperationType.plus, [var("c"), const(5)])]
        assert visitor.visited_expressions == [const(5), var("c"), const(5), var("c"), var("c")]

    def test_for_loop_ast(self, for_loop_ast: AbstractSyntaxTree):
        visitor = self.ConcreteAstDataflowObjectVisitor()
        visitor.visit_ast(for_loop_ast)
        assert visitor.visited_instructions == [
            Assignment(var("c"), const(5)),
            Assignment(var("c"), BinaryOperation(OperationType.plus, [var("c"), var("i")])),
            Assignment(var("i"), const(0)),
            Assignment(var("i"), BinaryOperation(OperationType.plus, [var("i"), const(1)])),
        ]
        assert visitor.visited_operations == [
            Condition(OperationType.less_or_equal, [var("i"), const(5)]),
            BinaryOperation(OperationType.plus, [var("c"), var("i")]),
            BinaryOperation(OperationType.plus, [var("i"), const(1)]),
        ]
        assert visitor.visited_expressions == [
            const(5),
            var("i"),
            const(5),
            var("c"),
            var("i"),
            var("c"),
            var("c"),
            const(0),
            var("i"),
            const(1),
            var("i"),
            var("i"),
        ]

    def test_nested_loop_ast(self, nested_loop_ast: AbstractSyntaxTree):
        visitor = self.ConcreteAstDataflowObjectVisitor()
        visitor.visit_ast(nested_loop_ast)
        assert visitor.visited_instructions == [
            Assignment(var("c"), const(5)),
            Assignment(var("c"), BinaryOperation(OperationType.plus, [var("c"), const(5)])),
        ]
        assert visitor.visited_operations == [
            Condition(OperationType.equal, [var("x"), const(5)]),
            BinaryOperation(OperationType.plus, [var("c"), const(5)]),
        ]
        assert visitor.visited_expressions == [const(5), var("x"), const(5), var("c"), const(5), var("c"), var("c")]

    def test_switch_ast(self, switch_ast: AbstractSyntaxTree):
        visitor = self.ConcreteAstDataflowObjectVisitor()
        visitor.visit_ast(switch_ast)
        assert visitor.visited_instructions == [Assignment(var("c"), const(5)), Return([var("c")]), Return([var("b")])]
        assert visitor.visited_operations == []
        assert visitor.visited_expressions == [var("a"), const(5), var("c"), var("c"), var("b"), var("a"), const(1), var("a"), const(2)]

    def test_switch_default_ast(self, switch_default_ast: AbstractSyntaxTree):
        visitor = self.ConcreteAstDataflowObjectVisitor()
        visitor.visit_ast(switch_default_ast)
        assert visitor.visited_instructions == [Assignment(var("c"), const(5)), Return([var("c")]), Return([var("b")]), Return([const(5)])]
        assert visitor.visited_operations == []
        assert visitor.visited_expressions == [
            var("a"),
            const(5),
            var("c"),
            var("c"),
            var("b"),
            const(5),
            var("a"),
            const(0),
            var("a"),
            const(1),
            var("a"),
        ]

    def test_if_else_ast(self, if_else_ast: AbstractSyntaxTree):
        visitor = self.ConcreteAstDataflowObjectVisitor()
        visitor.visit_ast(if_else_ast)
        assert visitor.visited_instructions == [Assignment(var("c"), const(5)), Return(var("c")), Return([const(0)])]
        assert visitor.visited_operations == [Condition(OperationType.less, [var("c"), const(5)])]
        assert visitor.visited_expressions == [const(5), var("c"), const(5), var("c"), const(0)]
