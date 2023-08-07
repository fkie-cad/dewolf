import pytest
from decompiler.pipeline.controlflowanalysis.loop_name_generator import ForLoopVariableRenamer, WhileLoopVariableRenamer
from decompiler.structures.ast.ast_nodes import ForLoopNode, SeqNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Call,
    Condition,
    Constant,
    ImportedFunctionSymbol,
    ListOperation,
    OperationType,
    Variable,
)
from decompiler.structures.pseudo.operations import OperationType

# Test For/WhileLoop Renamer

def logic_cond(name: str, context) -> LogicCondition:
    return LogicCondition.initialize_symbol(name, context)

@pytest.fixture
def ast_call_for_loop() -> AbstractSyntaxTree:
    """
    a = 5;
    while(b = foo; b <= 5; b++){
        a++;
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value),
        condition_map={logic_cond("x1", context): Condition(OperationType.less_or_equal, [Variable("b"), Constant(5)])},
    )
    code_node = ast._add_code_node(
        instructions=[
            Assignment(Variable("a"), Constant(5)),
        ]
    )
    loop_node = ast.factory.create_for_loop_node(Assignment(ListOperation([Variable("b")]), Call(ImportedFunctionSymbol("foo", 0), [])), logic_cond("x1", context), Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)])))
    loop_node_body = ast._add_code_node(
        [
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Variable("1")])),
        ]
    )
    ast._add_node(loop_node)
    ast._add_edges_from(((root, code_node), (root, loop_node), (loop_node, loop_node_body)))
    ast._code_node_reachability_graph.add_reachability(code_node, loop_node_body)
    root._sorted_children = (code_node, loop_node)
    return ast


def test_declaration_listop(ast_call_for_loop):
    """Test renaming with ListOperation as Declaration"""
    ForLoopVariableRenamer(ast_call_for_loop, ["i"]).rename()
    for node in ast_call_for_loop:
        if isinstance(node, ForLoopNode):
            assert node.declaration.destination.operands[0].name == "i"
    

def test_for_loop_variable_generation():
    renamer = ForLoopVariableRenamer(
        AbstractSyntaxTree(SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context())), {}),
        ["i", "j", "k", "l", "m", "n"]
    )
    assert [renamer._get_variable_name() for _ in range(14)] == [
        "i",
        "j",
        "k",
        "l",
        "m",
        "n",
        "i1",
        "j1",
        "k1",
        "l1",
        "m1",
        "n1",
        "i2",
        "j2",
    ]


def test_while_loop_variable_generation():
    renamer = WhileLoopVariableRenamer(
        AbstractSyntaxTree(SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context())), {})
    )
    assert [renamer._get_variable_name() for _ in range(5)] == ["counter", "counter1", "counter2", "counter3", "counter4"]
