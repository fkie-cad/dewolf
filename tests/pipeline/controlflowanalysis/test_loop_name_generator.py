from typing import List

import pytest
from decompiler.pipeline.controlflowanalysis.loop_name_generator import ForLoopVariableRenamer, LoopNameGenerator, WhileLoopVariableRenamer
from decompiler.pipeline.controlflowanalysis.loop_utility_methods import _initialization_reaches_loop_node
from decompiler.pipeline.controlflowanalysis.readability_based_refinement import ReadabilityBasedRefinement
from decompiler.structures.ast.ast_nodes import CaseNode, CodeNode, ConditionNode, ForLoopNode, SeqNode, SwitchNode, WhileLoopNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Break,
    Call,
    Condition,
    Constant,
    ImportedFunctionSymbol,
    ListOperation,
    Variable,
)
from decompiler.structures.pseudo.operations import ArrayInfo, OperationType, UnaryOperation
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

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
    loop_node = ast.factory.create_for_loop_node(
        Assignment(ListOperation([Variable("b")]), Call(ImportedFunctionSymbol("foo", 0), [])),
        logic_cond("x1", context),
        Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)])),
    )
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
        ["i", "j", "k", "l", "m", "n"],
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


# Test Readabilitybasedrefinement + LoopNameGenerator together


def _generate_options(
    empty_loops: bool = False,
    hide_decl: bool = False,
    rename_for: bool = True,
    rename_while: bool = True,
    max_condition: int = 100,
    max_modification: int = 100,
    force_for_loops: bool = False,
    blacklist: List[str] = [],
) -> Options:
    options = Options()
    options.set("readability-based-refinement.keep_empty_for_loops", empty_loops)
    options.set("readability-based-refinement.hide_non_initializing_declaration", hide_decl)
    options.set("readability-based-refinement.max_condition_complexity_for_loop_recovery", max_condition)
    options.set("readability-based-refinement.max_modification_complexity_for_loop_recovery", max_modification)
    options.set("readability-based-refinement.force_for_loops", force_for_loops)
    options.set("readability-based-refinement.forbidden_condition_types_in_simple_for_loops", blacklist)
    if rename_for:
        names = ["i", "j", "k", "l", "m", "n"]
        options.set("loop-name-generator.for_loop_variable_names", names)
    options.set("loop-name-generator.rename_while_loop_variables", rename_while)
    return options


@pytest.fixture
def ast_array_access_for_loop() -> AbstractSyntaxTree:
    """
    for (var_0 = 0; var_0 < 10; var_0 = var_0 + 1) {
        *(var_1 + var_0) = var_0;
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value),
        condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("var_0"), Constant(10)])},
    )
    declaration = Assignment(Variable("var_0"), Constant(0))
    condition = logic_cond("x1", context)
    modification = Assignment(Variable("var_0"), BinaryOperation(OperationType.plus, [Variable("var_0"), Constant(1)]))
    for_loop = ast.factory.create_for_loop_node(declaration, condition, modification)
    array_info = ArrayInfo(Variable("var_1"), Variable("var_0"))
    array_access_unary_operation = UnaryOperation(
        OperationType.dereference, [BinaryOperation(OperationType.plus, [Variable("var_1"), Variable("var_0")])], array_info=array_info
    )
    for_loop_body = ast._add_code_node([Assignment(array_access_unary_operation, Variable("var_0"))])
    ast._add_node(for_loop)
    ast._add_edges_from([(root, for_loop), (for_loop, for_loop_body)])
    return ast


@pytest.fixture
def ast_while_true() -> AbstractSyntaxTree:
    """
    a = 0;
    b = 0;
    while(true){
        a = a + 1;
        b = b + 1;
    }
    """
    true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(root := SeqNode(true_value), {})
    code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0)), Assignment(Variable("b"), Constant(0))])
    loop_node_body = ast._add_code_node(
        [
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)])),
            Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)])),
        ]
    )
    loop_node = ast.add_endless_loop_with_body(loop_node_body)
    ast._add_edges_from(((root, code_node), (root, loop_node)))
    return ast


@pytest.fixture
def ast_single_instruction_while() -> AbstractSyntaxTree:
    """
    a = 0;
    while (a < 10) {
        a = a + 1;
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value), condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)])}
    )
    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0))])
    while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
    while_loop_body = ast._add_code_node([Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)]))])
    ast._add_node(while_loop)
    ast._add_edges_from([(root, init_code_node), (root, while_loop), (while_loop, while_loop_body)])
    return ast


@pytest.fixture
def ast_replaceable_while() -> AbstractSyntaxTree:
    """
    a = 0;
    while (x < 10) {
        printf("counter: %d", x);
        a = a + 1;
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value), condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)])}
    )

    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0))])

    while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
    while_loop_body = ast._add_code_node(
        [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("counter: %d\n"), Variable("a")])),
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)])),
        ]
    )

    ast._add_node(while_loop)
    ast._add_edges_from([(root, init_code_node), (root, while_loop), (while_loop, while_loop_body)])
    root._sorted_children = (init_code_node, while_loop)
    return ast


@pytest.fixture
def ast_replaceable_while_usage() -> AbstractSyntaxTree:
    """
    a = 0;
    while (a < 10) {
        printf("counter: %d", a);
        a = a + 1;
    }
    printf("final counter: %d", a);
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value), condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)])}
    )

    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0))])

    while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
    while_loop_body = ast._add_code_node(
        [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("counter: %d\n"), Variable("a")])),
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)])),
        ]
    )

    exit_code_node = ast._add_code_node(
        [Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("final counter: %d"), Variable("a")]))]
    )

    ast._add_node(while_loop)
    ast._add_edges_from([(root, init_code_node), (root, while_loop), (root, exit_code_node), (while_loop, while_loop_body)])
    return ast


@pytest.fixture
def ast_replaceable_while_reinit_usage() -> AbstractSyntaxTree:
    """
    a = 0;
    while (a < 10) {
        printf("counter: %d", a);
        a = a + 1;
    }
    a = 50;
    printf("50 = %d", a);
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value), condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)])}
    )

    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0))])

    while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
    while_loop_body = ast._add_code_node(
        [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("counter: %d\n"), Variable("a")])),
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)])),
        ]
    )

    exit_code_node = ast._add_code_node(
        [
            Assignment(Variable("a"), Constant(50)),
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("final counter: %d"), Variable("a")])),
        ]
    )

    ast._add_node(while_loop)
    ast._add_edges_from([(root, init_code_node), (root, while_loop), (root, exit_code_node), (while_loop, while_loop_body)])
    return ast


@pytest.fixture
def ast_replaceable_while_compound_usage() -> AbstractSyntaxTree:
    """
    a = 0;
    while (a < 10) {
        printf("counter: %d", a);
        a = a + 1;
    }
    a = a + 50;
    printf("50 = %d", a);
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value), condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)])}
    )

    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0))])

    while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
    while_loop_body = ast._add_code_node(
        [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("counter: %d\n"), Variable("a")])),
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)])),
        ]
    )

    exit_code_node = ast._add_code_node(
        [
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(50)])),
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("final counter: %d"), Variable("a")])),
        ]
    )

    ast._add_node(while_loop)
    ast._add_edges_from([(root, init_code_node), (root, while_loop), (root, exit_code_node), (while_loop, while_loop_body)])
    return ast


@pytest.fixture
def ast_endless_while_init_outside() -> AbstractSyntaxTree:
    """
    a = 0;
    while (true) {
        while (a < 5) {
            printf("%d\n", a);
            a = a + 1;
        }
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value), condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(2)])}
    )

    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0))])

    inner_while = ast.factory.create_while_loop_node(logic_cond("x1", context))
    ast._add_node(inner_while)
    endless_loop = ast.add_endless_loop_with_body(inner_while)

    inner_while_body = ast._add_code_node(
        [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("%d\n"), Variable("a")])),
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)])),
        ]
    )

    ast._add_edges_from([(root, init_code_node), (root, endless_loop), (endless_loop, inner_while), (inner_while, inner_while_body)])
    return ast


@pytest.fixture
def ast_nested_while() -> AbstractSyntaxTree:
    """
    a = 0;
    while (a < 1) {
        b = 0;
        while (b < 1) {
            b = b + 1;
        }
        a = a + 1;
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value),
        condition_map={
            logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(5)]),
            logic_cond("x2", context): Condition(OperationType.less, [Variable("b"), Constant(5)]),
        },
    )

    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0))])

    outer_while = ast.factory.create_while_loop_node(logic_cond("x1", context))
    outer_while_body = ast.factory.create_seq_node()
    outer_while_init = ast._add_code_node([Assignment(Variable("b"), Constant(0))])
    outer_while_exit = ast._add_code_node([Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)]))])

    inner_while = ast.factory.create_while_loop_node(logic_cond("x2", context))
    inner_while_body = ast._add_code_node([Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)]))])

    ast._add_nodes_from((outer_while, outer_while_body, inner_while))
    ast._add_edges_from(
        [
            (root, init_code_node),
            (root, outer_while),
            (outer_while, outer_while_body),
            (outer_while_body, outer_while_init),
            (outer_while_body, inner_while),
            (outer_while_body, outer_while_exit),
            (inner_while, inner_while_body),
        ]
    )
    return ast


@pytest.fixture
def ast_call_init() -> AbstractSyntaxTree:
    """
    a = 5;
    b = foo();
    while(b <= 5){
        a = a + b;
        b = b + 1;
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
            Assignment(ListOperation([Variable("b")]), Call(ImportedFunctionSymbol("foo", 0), [])),
        ]
    )
    loop_node = ast.factory.create_while_loop_node(condition=logic_cond("x1", context))
    loop_node_body = ast._add_code_node(
        [
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Variable("b")])),
            Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)])),
        ]
    )
    ast._add_node(loop_node)
    ast._add_edges_from(((root, code_node), (root, loop_node), (loop_node, loop_node_body)))
    ast._code_node_reachability_graph.add_reachability(code_node, loop_node_body)
    root._sorted_children = (code_node, loop_node)
    return ast


@pytest.fixture
def ast_redundant_init() -> AbstractSyntaxTree:
    """
    b = 0;
    a = 5;
    b = 2;

    while(b <= 5){
        a = a + b;
        b = b + 1;
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value), condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("b"), Constant(5)])}
    )
    code_node = ast._add_code_node(
        instructions=[
            Assignment(Variable("b"), Constant(0)),
            Assignment(Variable("a"), Constant(5)),
            Assignment(Variable("b"), Constant(2)),
        ]
    )
    loop_node = ast.factory.create_while_loop_node(condition=logic_cond("x1", context))
    loop_node_body = ast._add_code_node(
        [
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Variable("b")])),
            Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)])),
        ]
    )
    ast._add_node(loop_node)
    ast._add_edges_from(((root, code_node), (root, loop_node), (loop_node, loop_node_body)))
    ast._code_node_reachability_graph.add_reachability(code_node, loop_node_body)
    root._sorted_children = (code_node, loop_node)
    return ast


@pytest.fixture
def ast_reinit_in_condition_true() -> AbstractSyntaxTree:
    """
    int x = 1;
    int i = 0;

    if (x == 1) {
        i = 1;
    }

    while (i < 10) {
        x = x * 2;
        i = i + 1;
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value),
        condition_map={
            logic_cond("a", context): Condition(OperationType.less, [Variable("i"), Constant(10)]),
            logic_cond("b", context): Condition(OperationType.equal, [Variable("x"), Constant(1)]),
        },
    )
    code_node = ast._add_code_node(instructions=[Assignment(Variable("x"), Constant(1)), Assignment(Variable("i"), Constant(0))])
    code_node_true = ast._add_code_node([Assignment(Variable("i"), Constant(1))])
    condition_node = ast._add_condition_node_with(logic_cond("b", context), code_node_true)
    loop_node = ast.factory.create_while_loop_node(condition=logic_cond("a", context))
    loop_node_body = ast._add_code_node(
        [
            Assignment(Variable("x"), BinaryOperation(OperationType.multiply, [Variable("x"), Constant(2)])),
            Assignment(Variable("i"), BinaryOperation(OperationType.plus, [Variable("i"), Constant(1)])),
        ]
    )
    ast._add_nodes_from((condition_node, loop_node))
    ast._add_edges_from(((root, code_node), (root, condition_node), (root, loop_node), (loop_node, loop_node_body)))
    ast._code_node_reachability_graph.add_reachability(code_node, loop_node_body)
    root._sorted_children = (code_node, loop_node)
    return ast


@pytest.fixture
def ast_usage_in_condition() -> AbstractSyntaxTree:
    """
    int a = 1;
    int b = 0;

    if (b == 1) {
        a = 1;
    }

    while (b < 10) {
        a = a * 2;
        b = b + 1;
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value),
        condition_map={
            logic_cond("x1", context): Condition(OperationType.less, [Variable("b"), Constant(10)]),
            logic_cond("x2", context): Condition(OperationType.equal, [Variable("b"), Constant(1)]),
        },
    )
    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(1)), Assignment(Variable("b"), Constant(0))])
    code_node_true = ast._add_code_node([Assignment(Variable("a"), Constant(1))])
    condition_node = ast._add_condition_node_with(logic_cond("x2", context), code_node_true)
    loop_node = ast.factory.create_while_loop_node(condition=logic_cond("x1", context))
    loop_node_body = ast._add_code_node(
        [
            Assignment(Variable("a"), BinaryOperation(OperationType.multiply, [Variable("a"), Constant(2)])),
            Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)])),
        ]
    )
    ast._add_node(loop_node)
    ast._add_edges_from(((root, init_code_node), (root, condition_node), (root, loop_node), (loop_node, loop_node_body)))
    ast._code_node_reachability_graph.add_reachability(init_code_node, loop_node_body)
    root._sorted_children = (init_code_node, loop_node)
    return ast


@pytest.fixture
def ast_sequenced_while_loops() -> AbstractSyntaxTree:
    """
    a = 0;
    b = 0;

    while (a < 5) {
        printf("%d\n", a);
        a++;
    }

    while (b < 5) {
        printf("%d\n", b);
        b++;
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value),
        condition_map={
            logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(5)]),
            logic_cond("x2", context): Condition(OperationType.less, [Variable("b"), Constant(5)]),
        },
    )

    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0)), Assignment(Variable("b"), Constant(0))])

    while_loop_1 = ast.factory.create_while_loop_node(logic_cond("x1", context))
    while_loop_1_body = ast._add_code_node(
        [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("%d\n"), Variable("a")])),
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)])),
        ]
    )

    while_loop_2 = ast.factory.create_while_loop_node(logic_cond("x2", context))
    while_loop_2_body = ast._add_code_node(
        [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("%d\n"), Variable("b")])),
            Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)])),
        ]
    )

    ast._add_nodes_from((while_loop_1, while_loop_2))
    ast._add_edges_from(
        (
            (root, init_code_node),
            (root, while_loop_1),
            (root, while_loop_2),
            (while_loop_1, while_loop_1_body),
            (while_loop_2, while_loop_2_body),
        )
    )
    return ast


@pytest.fixture
def ast_switch_as_loop_body() -> AbstractSyntaxTree:
    """
    This while-loop should not be replaced with a for-loop because we don't know wich value 'a' has.

    Code of AST:
    a = 5;
    b = 0;
    while(b <= 5){
        switch(a) {
            case 0:
                a = a + b:
                break;
            case 1:
                b = b + 1;
                break;
        }
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value),
        condition_map={logic_cond("a", context): Condition(OperationType.less_or_equal, [Variable("b"), Constant(5)])},
    )
    code_node = ast._add_code_node([Assignment(Variable("a"), Constant(5)), Assignment(Variable("b"), Constant(0))])
    loop_node = ast.factory.create_while_loop_node(condition=logic_cond("a", context))
    root._sorted_children = (code_node, loop_node)
    loop_body_switch = ast.factory.create_switch_node(Variable("a"))
    loop_body_case_1 = ast.factory.create_case_node(Variable("a"), Constant(0), break_case=True)
    code_node_case_1 = ast._add_code_node([Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Variable("b")]))])
    loop_body_case_2 = ast.factory.create_case_node(Variable("a"), Constant(1), break_case=True)
    code_node_case_2 = ast._add_code_node(
        [
            Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)])),
        ]
    )
    ast._add_nodes_from((code_node, loop_node, loop_body_switch, loop_body_case_1, loop_body_case_2))
    ast._add_edges_from(
        (
            (root, code_node),
            (root, loop_node),
            (loop_node, loop_body_switch),
            (loop_body_switch, loop_body_case_1),
            (loop_body_switch, loop_body_case_2),
            (loop_body_case_1, code_node_case_1),
            (loop_body_case_2, code_node_case_2),
        )
    )
    ast._code_node_reachability_graph.add_reachability_from(((code_node, code_node_case_1), (code_node, code_node_case_2)))
    return ast


@pytest.fixture
def ast_switch_as_loop_body_increment() -> AbstractSyntaxTree:
    """
    This loop should be replaced with a for-loop because b has no usages after last definition, is in condition and is initialized
    before loop without any usages in between.

    Code of AST:
    a = 5;
    b = 0;
    while(b <= 5){
        switch(a) {
            case 0:
                a = a + b:
                break;
            case 1:
                b = b + 1;
                break;
        }
        b = b + 1;
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value), condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("b"), Constant(5)])}
    )

    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(5)), Assignment(Variable("b"), Constant(0))])

    while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
    while_loop_seq = ast.factory.create_seq_node()

    switch_node = ast.factory.create_switch_node(Variable("a"))
    case_1 = ast.factory.create_case_node(Variable("a"), Constant(0), break_case=True)
    case_1_code = ast._add_code_node([Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Variable("b")]))])
    case_2 = ast.factory.create_case_node(Variable("a"), Constant(0), break_case=True)
    case_2_code = ast._add_code_node([Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)]))])

    increment_code = ast._add_code_node([Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)]))])

    ast._add_nodes_from((while_loop, while_loop_seq, switch_node, case_1, case_2))
    ast._add_edges_from(
        [
            (root, init_code_node),
            (root, while_loop),
            (while_loop, while_loop_seq),
            (while_loop_seq, switch_node),
            (while_loop_seq, increment_code),
            (switch_node, case_1),
            (switch_node, case_2),
            (case_1, case_1_code),
            (case_2, case_2_code),
        ]
    )
    return ast


@pytest.fixture
def ast_init_in_switch() -> AbstractSyntaxTree:
    """
    a = 5;
    b = 0;
    switch(a){
        case 0:
            a = b;
    }
    while(b <= (5 + a)){
        a = a + b;
        b = b + 1;
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value),
        condition_map={
            logic_cond("x1", context): Condition(
                OperationType.less_or_equal,
                [Variable("b"), BinaryOperation(OperationType.plus, [Constant(5), Variable("a")])],
            )
        },
    )
    init_code_node = ast._add_code_node(instructions=[Assignment(Variable("a"), Constant(5)), Assignment(Variable("b"), Constant(0))])
    switch_node = ast.factory.create_switch_node(Variable("a"))
    loop_node = ast.factory.create_while_loop_node(condition=logic_cond("x1", context))
    case_node = ast.factory.create_case_node(Variable("a"), Constant(0))
    case_child = ast._add_code_node([Assignment(Variable("a"), Variable("b"))])
    loop_body = ast.factory.create_seq_node()
    loop_body_child = ast._add_code_node(
        [
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Variable("b")])),
            Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)])),
        ]
    )
    ast._add_nodes_from((switch_node, loop_node, loop_body, case_node))
    ast._add_edges_from(
        (
            (root, init_code_node),
            (root, switch_node),
            (switch_node, case_node),
            (case_node, case_child),
            (root, loop_node),
            (loop_node, loop_body),
            (loop_body, loop_body_child),
        )
    )
    ast._code_node_reachability_graph.add_reachability_from([(case_child, loop_body_child)])
    root._sorted_children = (init_code_node, switch_node, loop_node)
    loop_body._sorted_children = (loop_body_child,)
    switch_node._sorted_cases = (case_node,)
    return ast


@pytest.fixture
def ast_while_in_else() -> AbstractSyntaxTree:
    """
    while (true) {
        if (b < 2) {
            break;
        } else {
            a = 0;
            while (a < 5) {
                printf("%d\n", a);
                a = a + 1;
            }
        }
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value),
        condition_map={
            logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(2)]),
            logic_cond("x2", context): Condition(OperationType.less, [Variable("b"), Constant(2)]),
        },
    )

    inner_while = ast.factory.create_while_loop_node(logic_cond("x1", context))
    ast._add_node(inner_while)

    true_branch_child = ast._add_code_node([Break()])
    inner_seq = ast.factory.create_seq_node()
    ast._add_node(inner_seq)
    condition_node = ast._add_condition_node_with(logic_cond("x2", context), true_branch_child, inner_seq)

    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0))])

    endless_loop = ast.add_endless_loop_with_body(condition_node)

    inner_while_body = ast._add_code_node(
        [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("%d\n"), Variable("a")])),
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)])),
        ]
    )

    ast._add_edges_from(
        [
            (root, endless_loop),
            (endless_loop, condition_node),
            (inner_seq, init_code_node),
            (inner_seq, inner_while),
            (inner_while, inner_while_body),
        ]
    )
    return ast


@pytest.fixture
def ast_continuation_is_not_first_var() -> AbstractSyntaxTree:
    """
    a = 0;
    b = 0;
    while (a < b) {
        printf("%d\n", a);
        b = b + 1;
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value),
        condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Variable("b")])},
    )

    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0)), Assignment(Variable("b"), Constant(0))])

    while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
    while_loop_body = ast._add_code_node(
        [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("%d\n"), Variable("a")])),
            Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)])),
        ]
    )

    ast._add_node(while_loop)
    ast._add_edges_from([(root, init_code_node), (root, while_loop), (while_loop, while_loop_body)])
    root._sorted_children = (init_code_node, while_loop)
    return ast


@pytest.fixture
def ast_initialization_in_condition() -> AbstractSyntaxTree:
    """
    if(b < 10 ){
        a = 5;
    while (x < 10) {
        printf("counter: %d", a);
        a = a + 1;
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value),
        condition_map={
            logic_cond("x0", context): Condition(OperationType.less, [Variable("b"), Constant(10)]),
            logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)]),
        },
    )

    true_branch = ast._add_code_node([Assignment(Variable("a"), Constant(5))])
    if_condition = ast._add_condition_node_with(logic_cond("x0", context), true_branch)
    while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
    while_loop_body = ast._add_code_node(
        [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("counter: %d\n"), Variable("a")])),
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)])),
        ]
    )

    ast._add_node(while_loop)
    ast._add_edges_from([(root, if_condition), (root, while_loop), (while_loop, while_loop_body)])
    root._sorted_children = (if_condition, while_loop)
    return ast


@pytest.fixture
def ast_initialization_in_condition_sequence() -> AbstractSyntaxTree:
    """
    if(b < 10 ){
        if(c < 10){
            b = 5;
        }
        a = 5;
    while (x < 10) {
        printf("counter: %d", a);
        a = a + 1;
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value),
        condition_map={
            logic_cond("x0", context): Condition(OperationType.less, [Variable("b"), Constant(10)]),
            logic_cond("x1", context): Condition(OperationType.less, [Variable("c"), Constant(10)]),
            logic_cond("x2", context): Condition(OperationType.less, [Variable("a"), Constant(10)]),
        },
    )

    true_branch_c = ast._add_code_node([Assignment(Variable("b"), Constant(5))])
    code_node = ast._add_code_node([Assignment(Variable("a"), Constant(5))])
    if_condition_c = ast._add_condition_node_with(logic_cond("x1", context), true_branch_c)
    ast._add_node(true_branch_b := ast.factory.create_seq_node())
    if_condition_b = ast._add_condition_node_with(logic_cond("x1", context), true_branch_b)
    while_loop = ast.factory.create_while_loop_node(logic_cond("x2", context))
    while_loop_body = ast._add_code_node(
        [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("counter: %d\n"), Variable("a")])),
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)])),
        ]
    )

    ast._add_node(while_loop)
    ast._add_edges_from(
        [
            (root, if_condition_b),
            (root, while_loop),
            (while_loop, while_loop_body),
            (true_branch_b, if_condition_c),
            (true_branch_b, code_node),
        ]
    )
    true_branch_b._sorted_children = (if_condition_c, code_node)
    root._sorted_children = (if_condition_b, while_loop)
    return ast


class TestReadabilityBasedRefinementAndLoopNameGenerator:
    """Test Readability functionality with all its substages."""

    @staticmethod
    def run_rbr(ast: AbstractSyntaxTree, options: Options = _generate_options()):
        task = DecompilerTask(name="func", function_identifier="", cfg=None, ast=ast, options=options)
        ReadabilityBasedRefinement().run(task)
        LoopNameGenerator().run(task)

    def test_no_replacement(self, ast_while_true):
        self.run_rbr(ast_while_true)
        assert all(not isinstance(node, ForLoopNode) for node in ast_while_true.topological_order())

    def test_simple_replacement(self, ast_replaceable_while):
        self.run_rbr(ast_replaceable_while)

        assert ast_replaceable_while.condition_map == {
            logic_cond("x1", LogicCondition.generate_new_context()): Condition(OperationType.less, [Variable("i"), Constant(10)])
        }

        loop_node = ast_replaceable_while.root
        assert isinstance(loop_node, ForLoopNode)
        assert loop_node.declaration == Assignment(Variable("i"), Constant(0))
        assert loop_node.modification == Assignment(Variable("i"), BinaryOperation(OperationType.plus, [Variable("i"), Constant(1)]))

        loop_body = loop_node.body
        assert isinstance(loop_body, CodeNode)
        assert loop_body.instructions == [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("counter: %d\n"), Variable("i")])),
        ]

    def test_with_usage(self, ast_replaceable_while_usage):
        self.run_rbr(ast_replaceable_while_usage)

        for_loop = ast_replaceable_while_usage.root.children[0]
        assert isinstance(for_loop, ForLoopNode)
        assert for_loop.declaration == Assignment(Variable("i"), Constant(0))

        copy_instr_node = ast_replaceable_while_usage.root.children[1]
        assert isinstance(copy_instr_node, CodeNode)
        assert copy_instr_node.instructions == [Assignment(Variable("a"), Variable("i"))]

    def test_with_usage_redefinition(self, ast_replaceable_while_reinit_usage):
        self.run_rbr(ast_replaceable_while_reinit_usage)

        for_loop = ast_replaceable_while_reinit_usage.root.children[0]
        assert isinstance(for_loop, ForLoopNode)
        assert for_loop.declaration == Assignment(Variable("i"), Constant(0))
        assert for_loop.modification == Assignment(Variable("i"), BinaryOperation(OperationType.plus, [Variable("i"), Constant(1)]))

        exit_code_node = ast_replaceable_while_reinit_usage.root.children[1]
        assert isinstance(exit_code_node, CodeNode)
        assert exit_code_node.instructions == [
            Assignment(Variable("a"), Constant(50)),
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("final counter: %d"), Variable("a")])),
        ]

    def test_with_usage_redefenition_2(self, ast_replaceable_while_compound_usage):
        self.run_rbr(ast_replaceable_while_compound_usage)

        for_loop = ast_replaceable_while_compound_usage.root.children[0]
        assert isinstance(for_loop, ForLoopNode)
        assert for_loop.declaration == Assignment(Variable("i"), Constant(0))
        assert for_loop.modification == Assignment(Variable("i"), BinaryOperation(OperationType.plus, [Variable("i"), Constant(1)]))

        copy_instr_node = ast_replaceable_while_compound_usage.root.children[1]
        assert isinstance(copy_instr_node, CodeNode)
        assert copy_instr_node.instructions == [Assignment(Variable("a"), Variable("i"))]

    def test_continuation_is_not_first_var(self, ast_continuation_is_not_first_var):
        self.run_rbr(ast_continuation_is_not_first_var)

        init_code_node = ast_continuation_is_not_first_var.root.children[0]
        assert isinstance(init_code_node, CodeNode)
        assert init_code_node.instructions == [Assignment(Variable("a"), Constant(0))]

        loop_node = ast_continuation_is_not_first_var.root.children[1]
        assert isinstance(loop_node, ForLoopNode)
        assert loop_node.declaration == Assignment(Variable("i"), Constant(0))
        assert loop_node.modification == Assignment(Variable("i"), BinaryOperation(OperationType.plus, [Variable("i"), Constant(1)]))

        loop_node_body = loop_node.body
        assert isinstance(loop_node_body, CodeNode)
        assert loop_node_body.instructions == [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("%d\n"), Variable("a")]))
        ]

    def test_init_with_call(self, ast_call_init):
        self.run_rbr(ast_call_init, _generate_options(rename_for=True))

        code_node = ast_call_init.root.children[0]
        assert isinstance(code_node, CodeNode)
        assert code_node.instructions == [Assignment(Variable("a"), Constant(5))]

        for_loop_node = ast_call_init.root.children[1]
        assert isinstance(for_loop_node, ForLoopNode)
        assert for_loop_node.declaration == Assignment(Variable("i"), Call(ImportedFunctionSymbol("foo", 0), []))
        assert for_loop_node.modification == Assignment(Variable("i"), BinaryOperation(OperationType.plus, [Variable("i"), Constant(1)]))

        loop_node_body = for_loop_node.body
        assert isinstance(loop_node_body, CodeNode)
        assert loop_node_body.instructions == [
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Variable("i")]))
        ]

        assert for_loop_node.condition == logic_cond("x1", context := LogicCondition.generate_new_context())
        assert ast_call_init.condition_map == {
            logic_cond("x1", context): Condition(OperationType.less_or_equal, [Variable("i"), Constant(5)])
        }

    def test_double_init(self, ast_redundant_init):
        self.run_rbr(ast_redundant_init)

        code_node = ast_redundant_init.root.children[0]
        assert isinstance(code_node, CodeNode)
        assert code_node.instructions == [
            Assignment(Variable("b"), Constant(0)),
            Assignment(Variable("a"), Constant(5)),
            Assignment(Variable("b"), Constant(2)),
        ]

        for_loop_node = ast_redundant_init.root.children[1]
        assert isinstance(for_loop_node, ForLoopNode)
        assert for_loop_node.declaration == Variable("b")
        assert for_loop_node.modification == Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)]))

        loop_node_body = for_loop_node.body
        assert isinstance(loop_node_body, CodeNode)
        assert loop_node_body.instructions == [
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Variable("b")])),
        ]

        assert for_loop_node.condition == logic_cond("x1", context := LogicCondition.generate_new_context())
        assert ast_redundant_init.condition_map == {logic_cond("x1", context): Condition(OperationType.less, [Variable("b"), Constant(5)])}

    def test_double_init_condition_node(self, ast_reinit_in_condition_true):
        self.run_rbr(ast_reinit_in_condition_true)

    def test_init_in_switch(self, ast_init_in_switch):
        self.run_rbr(ast_init_in_switch)

        init_code_node = ast_init_in_switch.root.children[0]
        assert isinstance(init_code_node, CodeNode)
        assert init_code_node.instructions == [Assignment(Variable("a"), Constant(5)), Assignment(Variable("b"), Constant(0))]

        loop_node = ast_init_in_switch.root.children[2]
        assert isinstance(loop_node, ForLoopNode)
        assert loop_node.declaration == Variable("b")
        assert loop_node.modification == Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)]))

        loop_node_body = loop_node.body
        assert isinstance(loop_node_body, CodeNode)
        assert loop_node_body.instructions == [
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Variable("b")]))
        ]

    def test_usage_in_condition(self, ast_usage_in_condition):
        self.run_rbr(ast_usage_in_condition)

        code_node = ast_usage_in_condition.root.children[0]
        assert isinstance(code_node, CodeNode)
        assert code_node.instructions == [Assignment(Variable("a"), Constant(1)), Assignment(Variable("b"), Constant(0))]

        condition_node = ast_usage_in_condition.root.children[1]
        assert isinstance(condition_node, ConditionNode)
        assert condition_node.condition == logic_cond("x2", context := LogicCondition.generate_new_context())

        loop_node = ast_usage_in_condition.root.children[2]
        assert isinstance(loop_node, ForLoopNode)
        assert loop_node.declaration == Variable("b")
        assert loop_node.condition == logic_cond("x1", context)
        assert loop_node.modification == Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)]))

        loop_body = loop_node.body
        assert isinstance(loop_body, CodeNode)
        assert loop_body.instructions == [Assignment(Variable("a"), BinaryOperation(OperationType.multiply, [Variable("a"), Constant(2)]))]

    def test_while_in_else(self, ast_while_in_else):
        self.run_rbr(ast_while_in_else)

        endless_loop = ast_while_in_else.root
        assert isinstance(endless_loop, WhileLoopNode)

        condition_node = endless_loop.body
        assert isinstance(condition_node, ConditionNode)

        loop_node = condition_node.false_branch_child
        assert isinstance(loop_node, ForLoopNode)
        assert loop_node.declaration == Assignment(Variable("i"), Constant(0))
        assert loop_node.modification == Assignment(Variable("i"), BinaryOperation(OperationType.plus, [Variable("i"), Constant(1)]))

        loop_node_body = loop_node.body
        assert isinstance(loop_node_body, CodeNode)
        assert loop_node_body.instructions == [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("%d\n"), Variable("i")]))
        ]

    def test_nested_while(self, ast_nested_while):
        self.run_rbr(ast_nested_while, _generate_options(empty_loops=True))

        outer_loop = ast_nested_while.root
        assert isinstance(outer_loop, ForLoopNode)
        assert outer_loop.declaration == Assignment(Variable("i"), Constant(0))
        assert ast_nested_while.condition_map[outer_loop.condition] == Condition(OperationType.less, [Variable("i"), Constant(5)])
        assert outer_loop.modification == Assignment(Variable("i"), BinaryOperation(OperationType.plus, [Variable("i"), Constant(1)]))

        inner_loop = outer_loop.children[0]
        assert isinstance(inner_loop, ForLoopNode)
        assert inner_loop.declaration == Assignment(Variable("j"), Constant(0))
        assert ast_nested_while.condition_map[inner_loop.condition] == Condition(OperationType.less, [Variable("j"), Constant(5)])
        assert inner_loop.modification == Assignment(Variable("j"), BinaryOperation(OperationType.plus, [Variable("j"), Constant(1)]))

    def test_nested_while_loop(self, ast_endless_while_init_outside):
        self.run_rbr(ast_endless_while_init_outside)

        endless_loop = ast_endless_while_init_outside.root.children[1]
        assert isinstance(endless_loop, WhileLoopNode)

        for_loop = endless_loop.body
        assert isinstance(for_loop, ForLoopNode)
        assert for_loop.declaration == Variable("a")

    def test_sequenced_loops(self, ast_sequenced_while_loops):
        self.run_rbr(ast_sequenced_while_loops)

        loop_1 = ast_sequenced_while_loops.root.children[0]
        assert isinstance(loop_1, ForLoopNode)
        assert loop_1.declaration == Assignment(Variable("i"), Constant(0))
        assert loop_1.modification == Assignment(Variable("i"), BinaryOperation(OperationType.plus, [Variable("i"), Constant(1)]))

        loop_1_body = loop_1.body
        assert isinstance(loop_1_body, CodeNode)
        assert loop_1_body.instructions == [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("%d\n"), Variable("i")])),
        ]

        loop_2 = ast_sequenced_while_loops.root.children[1]
        assert isinstance(loop_2, ForLoopNode)
        assert loop_2.declaration == Assignment(Variable("j"), Constant(0))
        assert loop_2.modification == Assignment(Variable("j"), BinaryOperation(OperationType.plus, [Variable("j"), Constant(1)]))

        loop_2_body = loop_2.body
        assert isinstance(loop_2_body, CodeNode)
        assert loop_2_body.instructions == [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("%d\n"), Variable("j")])),
        ]

    def test_switch_as_loop_body(self, ast_switch_as_loop_body):
        self.run_rbr(ast_switch_as_loop_body)

        assert all(not isinstance(node, ForLoopNode) for node in ast_switch_as_loop_body.topological_order())

        init_code_node = ast_switch_as_loop_body.root.children[0]
        assert isinstance(init_code_node, CodeNode)
        assert init_code_node.instructions == [Assignment(Variable("a"), Constant(5)), Assignment(Variable("counter"), Constant(0))]

        while_node = ast_switch_as_loop_body.root.children[1]
        assert isinstance(while_node, WhileLoopNode)

        switch_node = while_node.body
        assert isinstance(switch_node, SwitchNode)

        case_1_body = switch_node.children[0].child
        assert isinstance(case_1_body, CodeNode)
        assert case_1_body.instructions == [
            Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Variable("counter")]))
        ]

        case_2_body = switch_node.children[1].child
        assert isinstance(case_2_body, CodeNode)
        assert case_2_body.instructions == [
            Assignment(Variable("counter"), BinaryOperation(OperationType.plus, [Variable("counter"), Constant(1)]))
        ]

    def test_switch_as_loop_with_increment(self, ast_switch_as_loop_body_increment):
        self.run_rbr(ast_switch_as_loop_body_increment)

        init_code_node = ast_switch_as_loop_body_increment.root.children[0]
        assert isinstance(init_code_node, CodeNode)
        assert init_code_node.instructions == [Assignment(Variable("a"), Constant(5))]

        loop_node = ast_switch_as_loop_body_increment.root.children[1]
        assert isinstance(loop_node, ForLoopNode)
        assert loop_node.declaration == Assignment(Variable("i"), Constant(0))
        assert loop_node.modification == Assignment(Variable("i"), BinaryOperation(OperationType.plus, [Variable("i"), Constant(1)]))

        switch_node = loop_node.body
        assert isinstance(switch_node, SwitchNode)

        case_1 = switch_node.children[0]
        assert isinstance(case_1, CaseNode)

        case_1_body = case_1.child
        assert isinstance(case_1_body, CodeNode)
        assert case_1_body.instructions == [Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Variable("i")]))]

        case_2 = switch_node.children[1]
        assert isinstance(case_2, CaseNode)

        case_2_body = case_2.child
        assert isinstance(case_2_body, CodeNode)
        assert case_2_body.instructions == [Assignment(Variable("i"), BinaryOperation(OperationType.plus, [Variable("i"), Constant(1)]))]

        assert ast_switch_as_loop_body_increment.condition_map == {
            logic_cond("x1", LogicCondition.generate_new_context()): Condition(OperationType.less, [Variable("i"), Constant(5)])
        }

    def test_rename_unary_operation_updates_array_info(self, ast_array_access_for_loop):
        """Test if UnaryOperation.ArrayInfo gets updated on renaming"""
        self.run_rbr(ast_array_access_for_loop, _generate_options(rename_for=True))

        def find_unary_op(ast):
            """look for UnaryOperation in AST"""
            for node in ast.get_code_nodes_topological_order():
                for instr in node.instructions:
                    for unary_op in instr:
                        if isinstance(unary_op, UnaryOperation):
                            return unary_op
            return None

        unary_operation = find_unary_op(ast_array_access_for_loop)
        if not isinstance(unary_operation, UnaryOperation):
            assert False, "Did not find UnaryOperation in AST (expect it for array access)"
        assert unary_operation.array_info is not None
        assert unary_operation.array_info.base in unary_operation.requirements
        assert unary_operation.array_info.index in unary_operation.requirements

    def test_no_for_loop_renaming(self, ast_replaceable_while):
        self.run_rbr(ast_replaceable_while, _generate_options(rename_for=False))

        assert ast_replaceable_while.condition_map == {
            logic_cond("x1", LogicCondition.generate_new_context()): Condition(OperationType.less, [Variable("a"), Constant(10)])
        }

        loop_node = ast_replaceable_while.root
        assert isinstance(loop_node, ForLoopNode)
        assert loop_node.declaration == Assignment(Variable("a"), Constant(0))
        assert loop_node.modification == Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)]))

        loop_body = loop_node.body
        assert isinstance(loop_body, CodeNode)
        assert loop_body.instructions == [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("counter: %d\n"), Variable("a")])),
        ]

    def test_init_may_not_reach_loop_1(self, ast_initialization_in_condition):
        assert (
            _initialization_reaches_loop_node(
                ast_initialization_in_condition.root.children[0].true_branch_child, ast_initialization_in_condition.root.children[1]
            )
            is False
        )

        self.run_rbr(ast_initialization_in_condition, _generate_options())
        assert any(
            isinstance(for_loop := loop, ForLoopNode) for loop in ast_initialization_in_condition.get_for_loop_nodes_topological_order()
        )
        assert for_loop.declaration == Variable("a")

    def test_init_may_not_reach_loop_2(self, ast_initialization_in_condition_sequence):
        assert (
            _initialization_reaches_loop_node(
                ast_initialization_in_condition_sequence.root.children[0].true_branch_child.children[1],
                ast_initialization_in_condition_sequence.root.children[1],
            )
            is False
        )

        self.run_rbr(ast_initialization_in_condition_sequence, _generate_options())
        assert any(
            isinstance(for_loop := loop, ForLoopNode)
            for loop in ast_initialization_in_condition_sequence.get_for_loop_nodes_topological_order()
        )
        assert for_loop.declaration == Variable("a")

    @pytest.mark.parametrize("keep_empty_for_loops", [True, False])
    def test_keep_empty_for_loop(self, keep_empty_for_loops: bool, ast_single_instruction_while):
        self.run_rbr(ast_single_instruction_while, _generate_options(keep_empty_for_loops))

        if keep_empty_for_loops:
            assert isinstance(ast_single_instruction_while.root, ForLoopNode)
        else:
            assert isinstance(ast_single_instruction_while.root.children[1], WhileLoopNode)
