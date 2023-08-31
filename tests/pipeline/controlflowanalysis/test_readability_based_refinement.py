from typing import List

import pytest
from decompiler.pipeline.controlflowanalysis.loop_utility_methods import (
    _find_continuation_instruction,
    _has_deep_requirement,
    _initialization_reaches_loop_node,
)
from decompiler.pipeline.controlflowanalysis.readability_based_refinement import ReadabilityBasedRefinement
from decompiler.structures.ast.ast_nodes import ConditionNode, ForLoopNode, SeqNode, WhileLoopNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Break,
    Call,
    Condition,
    Constant,
    Continue,
    ImportedFunctionSymbol,
    ListOperation,
    OperationType,
    Variable,
)
from decompiler.structures.pseudo.operations import OperationType
from decompiler.task import DecompilerTask
from decompiler.util.options import Options


def logic_cond(name: str, context) -> LogicCondition:
    return LogicCondition.initialize_symbol(name, context)


def _generate_options(empty_loops: bool = False, hide_decl: bool = False, max_condition: int = 100, max_modification: int = 100, \
    force_for_loops: bool = False, blacklist : List[str] = []) -> Options:
    options = Options()
    options.set("readability-based-refinement.keep_empty_for_loops", empty_loops)
    options.set("readability-based-refinement.hide_non_initializing_declaration", hide_decl)
    options.set("readability-based-refinement.max_condition_complexity_for_loop_recovery", max_condition)
    options.set("readability-based-refinement.max_modification_complexity_for_loop_recovery", max_modification)
    options.set("readability-based-refinement.force_for_loops", force_for_loops)
    options.set("readability-based-refinement.forbidden_condition_types_in_simple_for_loops", blacklist)
    return options


@pytest.fixture
def ast_innerWhile_simple_condition_complexity() -> AbstractSyntaxTree:
    """
    a = 0;
    while (a < 1) {
        b = 0;
        c = 0;
        d = 0;
        while (b < 1 && c < 1 && d < 1){
            b = b + 1;
            c = c + 1;
            d = d + 1;
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
            logic_cond("x3", context): Condition(OperationType.less, [Variable("c"), Constant(5)]),
            logic_cond("x4", context): Condition(OperationType.less, [Variable("d"), Constant(5)]),
        },
    )

    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0))])

    outer_while = ast.factory.create_while_loop_node(logic_cond("x1", context))
    outer_while_body = ast.factory.create_seq_node()
    outer_while_init = ast._add_code_node([Assignment(Variable("b"), Constant(0)), Assignment(Variable("c"), Constant(0))
    , Assignment(Variable("d"), Constant(0))])
    outer_while_exit = ast._add_code_node([Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)]))])

    inner_while = ast.factory.create_while_loop_node(logic_cond("x2", context) & logic_cond("x3", context) & logic_cond("x4", context))
    inner_while_body = ast._add_code_node([Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)])),
    Assignment(Variable("c"), BinaryOperation(OperationType.plus, [Variable("c"), Constant(1)])), 
    Assignment(Variable("d"), BinaryOperation(OperationType.plus, [Variable("d"), Constant(1)]))])

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


def generate_ast_with_modification_complexity(complexity : int) -> AbstractSyntaxTree:
    """
    a = 0;
    while (a < 10) {
        a = (a + (...)) + 1; // i times (+1)
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value), condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)])}
    )
    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0))])
    while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
    increment = BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)])
    for _ in range(complexity):
        increment = BinaryOperation(OperationType.plus, [increment, Constant(1)])
    while_loop_body = ast._add_code_node([Assignment(Variable("a"), increment)])
    ast._add_node(while_loop)
    ast._add_edges_from([(root, init_code_node), (root, while_loop), (while_loop, while_loop_body)])
    return ast


def generate_ast_with_condition_type(op : OperationType) -> AbstractSyntaxTree:
    """
    a = 0;
    while (a <op> 10) {
        a = a + 1;
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value), condition_map={logic_cond("x1", context): Condition(op, [Variable("a"), Constant(10)])}
    )
    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0))])
    while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
    while_loop_body = ast._add_code_node([Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)]))])
    ast._add_node(while_loop)
    ast._add_edges_from([(root, init_code_node), (root, while_loop), (while_loop, while_loop_body)])
    return ast


@pytest.fixture
def ast_guarded_do_while_if() -> AbstractSyntaxTree:
    """
    if(a < 10){
        do{
            a++;
        }while(a < 10)
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value), condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)])}
    )
    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0))])
    cond_node = ast.factory.create_condition_node(logic_cond("x1", context))
    true_branch = ast.factory.create_true_node()
    do_while_loop = ast.factory.create_do_while_loop_node(logic_cond("x1", context))
    do_while_loop_body = ast._add_code_node([Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)]))])
    ast._add_node(cond_node)
    ast._add_node(true_branch)
    ast._add_node(do_while_loop)
    ast._add_edges_from([(root, init_code_node), (root, cond_node), (cond_node, true_branch), (true_branch, do_while_loop), (do_while_loop, do_while_loop_body)])
    return ast
    

@pytest.fixture
def ast_guarded_do_while_else() -> AbstractSyntaxTree:
    """
    if(a >= 10){

    }else{
        do{
            a++;
        }while(a < 10)
    }
    """
    true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(
        root := SeqNode(true_value), condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)])}
    )
    init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0))])
    cond_node = ast.factory.create_condition_node(~logic_cond("x1", context))
    false_branch = ast.factory.create_false_node()
    do_while_loop = ast.factory.create_do_while_loop_node(logic_cond("x1", context))
    do_while_loop_body = ast._add_code_node([Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)]))])
    ast._add_node(cond_node)
    ast._add_node(false_branch)
    ast._add_node(do_while_loop)
    ast._add_edges_from([(root, init_code_node), (root, cond_node), (cond_node, false_branch), (false_branch, do_while_loop), (do_while_loop, do_while_loop_body)])
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


class TestForLoopRecovery:
    """ Test options for for-loop recovery """
    @staticmethod
    def run_rbr(ast: AbstractSyntaxTree, options: Options = _generate_options()):
        ReadabilityBasedRefinement().run(DecompilerTask("func", cfg=None, ast=ast, options=options))

    def test_max_condition_complexity(self, ast_innerWhile_simple_condition_complexity):
        self.run_rbr(ast_innerWhile_simple_condition_complexity, _generate_options(max_condition=2))

        for loop_node in list(ast_innerWhile_simple_condition_complexity.get_loop_nodes_post_order()):
            if loop_node.condition.get_complexity(ast_innerWhile_simple_condition_complexity.condition_map) <= 2:
                assert isinstance(loop_node, ForLoopNode)
            else:
                assert isinstance(loop_node, WhileLoopNode)


    @pytest.mark.parametrize("modification_nesting", [1, 2])
    def test_max_modification_complexity(self, modification_nesting):
        ast = generate_ast_with_modification_complexity(modification_nesting)
        max_modi_complexity = 4
        self.run_rbr(ast, _generate_options(empty_loops=True, max_modification=max_modi_complexity))

        for loop_node in list(ast.get_loop_nodes_post_order()):
            if isinstance(loop_node, ForLoopNode):
                assert loop_node.modification.complexity <= max_modi_complexity
            else:
                assert isinstance(loop_node, WhileLoopNode)
                for condition_variable in loop_node.get_required_variables(ast.condition_map):
                    instruction = _find_continuation_instruction(ast, loop_node, condition_variable)
                    assert instruction is not None 
                    assert instruction.instruction.complexity > max_modi_complexity
    

    @pytest.mark.parametrize("operation", [OperationType.equal, OperationType.not_equal ,OperationType.less_or_equal, OperationType.less])
    def test_for_loop_recovery_blacklist(self, operation):
        ast = generate_ast_with_condition_type(operation)
        forbidden_conditon_types = ["not_equal", "equal"]
        self.run_rbr(ast, _generate_options(empty_loops=True, blacklist=forbidden_conditon_types))

        for loop_node in list(ast.get_loop_nodes_post_order()):
            if ast.condition_map[loop_node.condition].operation.name in forbidden_conditon_types:
                assert isinstance(loop_node, WhileLoopNode)
            else:
                assert isinstance(loop_node, ForLoopNode)


class TestGuardedDoWhile:
    @staticmethod
    def run_rbr(ast: AbstractSyntaxTree, options: Options = _generate_options()):
        ReadabilityBasedRefinement().run(DecompilerTask("func", cfg=None, ast=ast, options=options))

    def test_guarded_do_while_if(self, ast_guarded_do_while_if):
        self.run_rbr(ast_guarded_do_while_if, _generate_options())

        for _ in ast_guarded_do_while_if.get_condition_nodes_post_order():
            assert False, "There should be no condition node"

        for loop_node in ast_guarded_do_while_if.get_loop_nodes_post_order():
            assert isinstance(loop_node, WhileLoopNode)

    def test_guarded_do_while_else(self, ast_guarded_do_while_else):
        self.run_rbr(ast_guarded_do_while_else, _generate_options())

        for _ in ast_guarded_do_while_else.get_condition_nodes_post_order():
            assert False, "There should be no condition node"

        for loop_node in ast_guarded_do_while_else.get_loop_nodes_post_order():
            assert isinstance(loop_node, WhileLoopNode)


class TestReadabilityUtils:
    def test_find_continuation_instruction_1(self):
        """
        Should not find any valid continuation instruction because last sequence child has requirement 'a'.

        while (a < 10) {
            a = a + 1;

            if (b < 2) {
                break;
            } else {
                break;
            }

            b = a + 1;
        }
        """
        true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(
            root := SeqNode(true_value),
            condition_map={
                logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)]),
                logic_cond("x2", context): Condition(OperationType.less, [Variable("b"), Constant(2)]),
            },
        )

        while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
        while_loop_seq = ast.factory.create_seq_node()

        seq_1 = ast._add_code_node([Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)]))])

        condition_node_true = ast._add_code_node([Break()])
        condition_node_false = ast._add_code_node([Break()])
        seq_2 = ast._add_condition_node_with(logic_cond("x2", context), condition_node_true, condition_node_false)

        seq_3 = ast._add_code_node([Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)]))])

        ast._add_nodes_from((while_loop, while_loop_seq, seq_2))
        ast._add_edges_from(
            [(root, while_loop), (while_loop, while_loop_seq), (while_loop_seq, seq_1), (while_loop_seq, seq_2), (while_loop_seq, seq_3)]
        )

        assert _find_continuation_instruction(ast, while_loop, Variable("a")) is None

    def test_find_continuation_instruction_2(self):
        """
        Should identify 'a = a + 1' as continuation instruction.

        while (a < 10) {
            a = a + 1;

            if (b < 2) {
                break;
            } else {
                break;
            }

            b = b + 1;
        }
        """
        true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(
            root := SeqNode(true_value),
            condition_map={
                logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)]),
                logic_cond("x2", context): Condition(OperationType.less, [Variable("b"), Constant(2)]),
            },
        )

        while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
        while_loop_seq = ast.factory.create_seq_node()

        seq_1 = ast._add_code_node([Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)]))])

        condition_node_true = ast._add_code_node([Break()])
        condition_node_false = ast._add_code_node([Break()])
        seq_2 = ast._add_condition_node_with(logic_cond("x2", context), condition_node_true, condition_node_false)

        seq_3 = ast._add_code_node([Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)]))])

        ast._add_nodes_from((while_loop, while_loop_seq, seq_2))
        ast._add_edges_from(
            [(root, while_loop), (while_loop, while_loop_seq), (while_loop_seq, seq_1), (while_loop_seq, seq_2), (while_loop_seq, seq_3)]
        )

        assert _find_continuation_instruction(ast, while_loop, Variable("a")).instruction == seq_1.instructions[0]

    def test_find_continuation_instruction_3(self):
        """
        Should not find a valid continuation instruction because condition node has requirement 'a'.

        while (a < 10) {
            a = a + 1;

            if (a < 2) {
                break;
            } else {
                break;
            }

            b = b + 1;
        }
        """
        true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(
            root := SeqNode(true_value),
            condition_map={
                logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)]),
                logic_cond("x2", context): Condition(OperationType.less, [Variable("a"), Constant(2)]),
            },
        )

        while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
        while_loop_seq = ast.factory.create_seq_node()

        seq_1 = ast._add_code_node([Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)]))])

        condition_node_true = ast._add_code_node([Break()])
        condition_node_false = ast._add_code_node([Break()])
        seq_2 = ast._add_condition_node_with(logic_cond("x2", context), condition_node_true, condition_node_false)

        seq_3 = ast._add_code_node([Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)]))])

        while_loop_seq._sorted_children = (seq_1, seq_2, seq_3)

        ast._add_nodes_from((while_loop, while_loop_seq, seq_2))
        ast._add_edges_from(
            [(root, while_loop), (while_loop, while_loop_seq), (while_loop_seq, seq_1), (while_loop_seq, seq_2), (while_loop_seq, seq_3)]
        )

        assert _find_continuation_instruction(ast, while_loop, Variable("a")) is None

    def test_find_continuation_instruction_4(self):
        """
        Should not find any continuation instruction because condition nodes true child has requirement 'a'.

        while (a < 10) {
            a = a + 1;

            if (b < 2) {
                b = a + 1;
            } else {
                break;
            }

            b = b + 1;
        }
        """
        true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(
            root := SeqNode(true_value),
            condition_map={
                logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)]),
                logic_cond("x2", context): Condition(OperationType.less, [Variable("b"), Constant(2)]),
            },
        )

        while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
        while_loop_seq = ast.factory.create_seq_node()

        seq_1 = ast._add_code_node([Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)]))])

        condition_node_true = ast._add_code_node(
            [Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)]))]
        )
        condition_node_false = ast._add_code_node([Break()])
        seq_2 = ast._add_condition_node_with(logic_cond("x2", context), condition_node_true, condition_node_false)

        seq_3 = ast._add_code_node([Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)]))])

        while_loop_seq._sorted_children = (seq_1, seq_2, seq_3)

        ast._add_nodes_from((while_loop, while_loop_seq, seq_2))
        ast._add_edges_from(
            [(root, while_loop), (while_loop, while_loop_seq), (while_loop_seq, seq_1), (while_loop_seq, seq_2), (while_loop_seq, seq_3)]
        )

        assert _find_continuation_instruction(ast, while_loop, Variable("a")) is None

    def test_find_continuation_instruction_5(self):
        """
        Should not find any continuation instruction because condition nodes true child has requirement 'a' in switch.

        while (a < 10) {
            a = a + 1;

            if (b < 2) {
                switch(a) {
                    case 0:
                    break;
                }
            } else {
                break;
            }

            b = b + 1;
        }
        """
        true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(
            root := SeqNode(true_value),
            condition_map={
                logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)]),
                logic_cond("x2", context): Condition(OperationType.less, [Variable("b"), Constant(2)]),
            },
        )

        while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
        while_loop_seq = ast.factory.create_seq_node()

        seq_1 = ast._add_code_node([Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)]))])

        condition_node_true = ast.factory.create_switch_node(Variable("a"))
        case_node = ast.factory.create_case_node(Variable("a"), Constant(1))
        ast._add_nodes_from((condition_node_true, case_node))

        condition_node_false = ast._add_code_node([Break()])
        seq_2 = ast._add_condition_node_with(logic_cond("x2", context), condition_node_true, condition_node_false)

        seq_3 = ast._add_code_node([Assignment(Variable("b"), BinaryOperation(OperationType.plus, [Variable("b"), Constant(1)]))])

        while_loop_seq._sorted_children = (seq_1, seq_2, seq_3)

        ast._add_nodes_from((while_loop, while_loop_seq, seq_2))
        ast._add_edges_from(
            [
                (root, while_loop),
                (while_loop, while_loop_seq),
                (while_loop_seq, seq_1),
                (while_loop_seq, seq_2),
                (while_loop_seq, seq_3),
                (condition_node_true, case_node),
            ]
        )

        assert _find_continuation_instruction(ast, while_loop, Variable("a")) is None

    def test_find_continuation_instruction_6(self):
        """
        Should identify 'a = a + 1' as value continuation instruction.

        a = 0;
        while (a < 10) {
            printf("counter: %d", a);
            a = a + 1;
        }
        """
        true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(
            root := SeqNode(true_value),
            condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)])},
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

        assert _find_continuation_instruction(ast, while_loop, Variable("a")).instruction == while_loop_body.instructions[1]

    def test_find_continuation_instruction_7(self):
        """
        Should not identify 'a = a + 1' as value continuation instruction because it is used in the following instruction.

        a = 0;
        while (a < 10) {
            a = a + 1;
            printf("counter: %d", a);
        }
        """
        true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(
            root := SeqNode(true_value),
            condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)])},
        )

        init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0))])

        while_loop = ast.factory.create_while_loop_node(logic_cond("x1", context))
        while_loop_body = ast._add_code_node(
            [
                Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)])),
                Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("counter: %d\n"), Variable("a")])),
            ]
        )

        ast._add_node(while_loop)
        ast._add_edges_from([(root, init_code_node), (root, while_loop), (while_loop, while_loop_body)])

        assert _find_continuation_instruction(ast, while_loop, Variable("a")) is None

    def test_has_deep_requirements_1(self):
        """
        Code of AST:
        if (x < 10) {
            if (x == 0) {
                x = a;
            }
        }
        """
        true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
        condition_map = {
            logic_cond("x1", context): Condition(OperationType.less, [Variable("x"), Constant(10)]),
            logic_cond("x2", context): Condition(OperationType.equal, [Variable("x"), Constant(0)]),
        }

        ast = AbstractSyntaxTree(root := SeqNode(true_value), condition_map=condition_map)

        inner_code_node = ast._add_code_node([Assignment(Variable("x"), Variable("a"))])
        inner_condition_node = ast._add_condition_node_with(logic_cond("x2", context), inner_code_node, None)
        outer_condition_node = ast._add_condition_node_with(logic_cond("x1", context), inner_condition_node, None)

        ast._add_edges_from([(root, outer_condition_node)])

        assert _has_deep_requirement(condition_map, outer_condition_node, Variable("a")) is True

    def test_has_deep_requirements_2(self):
        """
        Code of AST:
        if (x < 10) {
            if (x == 0) {
                a = x;
            }
        }
        """
        true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
        condition_map = {
            logic_cond("x1", context): Condition(OperationType.less, [Variable("x"), Constant(10)]),
            logic_cond("x2", context): Condition(OperationType.equal, [Variable("x"), Constant(0)]),
        }

        ast = AbstractSyntaxTree(root := SeqNode(true_value), condition_map=condition_map)

        inner_code_node = ast._add_code_node([Assignment(Variable("a"), Variable("x"))])
        inner_condition_node = ast._add_condition_node_with(logic_cond("x2", context), inner_code_node, None)
        outer_condition_node = ast._add_condition_node_with(logic_cond("x1", context), inner_condition_node, None)

        ast._add_edges_from([(root, outer_condition_node)])

        assert _has_deep_requirement(condition_map, outer_condition_node, Variable("a")) is False

    def test_has_deep_requirements_3(self):
        """
        Code of AST:
        if (x < 10) {
            if (a == 0) {
                x = 0;
            }
        }
        """
        true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
        condition_map = {
            logic_cond("x1", context): Condition(OperationType.less, [Variable("x"), Constant(10)]),
            logic_cond("x2", context): Condition(OperationType.equal, [Variable("a"), Constant(0)]),
        }

        ast = AbstractSyntaxTree(root := SeqNode(true_value), condition_map=condition_map)

        inner_code_node = ast._add_code_node([Assignment(Variable("x"), Constant(0))])
        inner_condition_node = ast._add_condition_node_with(logic_cond("x2", context), inner_code_node, None)
        outer_condition_node = ast._add_condition_node_with(logic_cond("x1", context), inner_condition_node, None)

        ast._add_edges_from([(root, outer_condition_node)])

        assert _has_deep_requirement(condition_map, outer_condition_node, Variable("a")) is True

    def test_separated_by_loop_node_1(self):
        """
        Code of AST:
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
            root := SeqNode(true_value),
            condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(2)])},
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

        assert _initialization_reaches_loop_node(init_code_node, inner_while) is False

    def test_separated_by_loop_node_2(self):
        """
        a = 0;
        while (a < 10) {
            printf("counter: %d", a);
            a = a + 1;
        }
        """
        true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(
            root := SeqNode(true_value),
            condition_map={logic_cond("x1", context): Condition(OperationType.less, [Variable("a"), Constant(10)])},
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

        assert _initialization_reaches_loop_node(init_code_node, while_loop) is True

    def test_separated_by_loop_node_3(self):
        """
        Code of AST:
        a = 0;
        while (true) {
            if (b < 2) {
                break;
            } else {
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

        init_code_node = ast._add_code_node([Assignment(Variable("a"), Constant(0))])

        inner_while = ast.factory.create_while_loop_node(logic_cond("x1", context))
        ast._add_node(inner_while)

        true_branch_child = ast._add_code_node([Break()])
        condition_node = ast._add_condition_node_with(logic_cond("x2", context), true_branch_child, inner_while)

        endless_loop = ast.add_endless_loop_with_body(condition_node)

        inner_while_body = ast._add_code_node(
            [
                Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("%d\n"), Variable("a")])),
                Assignment(Variable("a"), BinaryOperation(OperationType.plus, [Variable("a"), Constant(1)])),
            ]
        )

        ast._add_edges_from([(root, init_code_node), (root, endless_loop), (endless_loop, condition_node), (inner_while, inner_while_body)])

        assert _initialization_reaches_loop_node(init_code_node, inner_while) is False

    def test_separated_by_loop_node_4(self, ast_while_in_else):
        init_code_node = ast_while_in_else.root

        endless_loop = ast_while_in_else.root.children[0]
        assert isinstance(endless_loop, WhileLoopNode)
        condition_node = endless_loop.body
        assert isinstance(condition_node, ConditionNode)
        inner_while = condition_node.false_branch_child

        assert _initialization_reaches_loop_node(init_code_node, inner_while) is False
