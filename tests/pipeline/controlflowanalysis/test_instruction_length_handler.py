from typing import List, Union

import pytest
from decompiler.pipeline.controlflowanalysis.instruction_length_handler import InstructionLengthHandler
from decompiler.structures.ast.ast_nodes import CodeNode, SeqNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Call,
    Constant,
    CustomType,
    Float,
    FunctionSymbol,
    Instruction,
    Integer,
    ListOperation,
    OperationType,
    Pointer,
    Return,
    Type,
    UnaryOperation,
    Variable,
)
from decompiler.structures.pseudo.operations import ArrayInfo, Condition
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

PIPELINE_NAME = InstructionLengthHandler.name

INT_8 = Integer.int8_t()
INT_32 = Integer.int32_t()
INT_64 = Integer.int64_t()
FLOAT = Float.float()
CHAR = Integer.char()
VOID = CustomType.void()


def var(name: str, var_type: Type = INT_32) -> Variable:
    return Variable(name, vartype=var_type)


def const(value: Union[int, float, str], var_type: Type = INT_32) -> Constant:
    return Constant(value, var_type)


op_y_z = BinaryOperation(OperationType.plus, [var("y"), var("z")])
op_v_w = BinaryOperation(OperationType.plus, [var("v"), var("w")])
op_x_y_z = BinaryOperation(OperationType.plus, [var("x"), op_y_z.copy()])
op_u_v_w = BinaryOperation(OperationType.plus, [var("u"), op_v_w.copy()])
op_6 = BinaryOperation(OperationType.left_shift, [op_x_y_z.copy(), op_u_v_w.copy()])
op_6_2 = BinaryOperation(OperationType.right_shift, [op_u_v_w.copy(), op_x_y_z.copy()])
op_a_b = BinaryOperation(OperationType.minus, [var("a"), var("b")])
op_c_d = BinaryOperation(OperationType.minus, [var("c"), var("d")])
op_4 = BinaryOperation(OperationType.minus, [op_a_b.copy(), op_c_d.copy()])
op_array_access = BinaryOperation(OperationType.plus, [const(1), BinaryOperation(OperationType.minus, [const(10), const(1)])])


def _generate_options(call: int = 10, assignment: int = 10, ret: int = 10) -> Options:
    options = Options.load_default_options()
    options.set(f"{PIPELINE_NAME}.max_assignment_complexity", assignment)
    options.set(f"{PIPELINE_NAME}.max_call_complexity", call)
    options.set(f"{PIPELINE_NAME}.max_return_complexity", ret)
    return options


def _run_ilh(ast: AbstractSyntaxTree, options: Options = _generate_options()):
    InstructionLengthHandler().run(DecompilerTask(name="test_function", function_identifier="", ast=ast, options=options))


class TestCodeNode:
    @pytest.mark.parametrize(
        "threshold, expected",
        [
            (6, [Assignment(var("a"), op_6.copy())]),
            (
                5,
                [
                    Assignment(var("tmp_0"), op_x_y_z.copy()),
                    Assignment(var("a"), BinaryOperation(OperationType.left_shift, [var("tmp_0"), op_u_v_w.copy()])),
                ],
            ),
            (
                4,
                [
                    Assignment(var("tmp_0"), op_x_y_z.copy()),
                    Assignment(var("a"), BinaryOperation(OperationType.left_shift, [var("tmp_0"), op_u_v_w.copy()])),
                ],
            ),
            (
                3,
                [
                    Assignment(var("tmp_0"), op_x_y_z.copy()),
                    Assignment(var("tmp_1"), op_u_v_w.copy()),
                    Assignment(var("a"), BinaryOperation(OperationType.left_shift, [var("tmp_0"), var("tmp_1")])),
                ],
            ),
            (
                2,
                [
                    Assignment(var("tmp_2"), op_y_z.copy()),
                    Assignment(var("tmp_0"), BinaryOperation(OperationType.plus, [var("x"), var("tmp_2")])),
                    Assignment(var("tmp_3"), op_v_w.copy()),
                    Assignment(var("tmp_1"), BinaryOperation(OperationType.plus, [var("u"), var("tmp_3")])),
                    Assignment(var("a"), BinaryOperation(OperationType.left_shift, [var("tmp_0"), var("tmp_1")])),
                ],
            ),
        ],
    )
    def test_assignment(self, threshold: int, expected: List[Instruction]):
        """
        Test assignment simplification for different thresholds.
        CodeNode instruction: a = (x + (y + z)) << (u + (v + w))
        """
        true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(CodeNode([Assignment(var("a"), op_6.copy())], true_value), condition_map={})
        _run_ilh(ast, _generate_options(assignment=threshold))
        assert ast.root.instructions == expected

    @pytest.mark.parametrize(
        "instruction, ret_complx, assign_complx, expected",
        [
            (Return([op_6.copy()]), 6, 4, [Return([op_6.copy()])]),
            (
                Return([op_6.copy()]),
                5,
                4,
                [
                    Assignment(var("tmp_0"), op_x_y_z.copy()),
                    Return([BinaryOperation(OperationType.left_shift, [var("tmp_0"), op_u_v_w.copy()])]),
                ],
            ),
            (Return([op_6.copy(), op_6_2.copy()]), 11, 11, [Assignment(var("tmp_0"), op_6.copy()), Return([var("tmp_0"), op_6_2.copy()])]),
            (
                Return([op_6.copy(), op_4.copy()]),
                4,
                10,
                [Assignment(var("tmp_0"), op_6.copy()), Assignment(var("tmp_1"), op_4.copy()), Return([var("tmp_0"), var("tmp_1")])],
            ),
            (
                Return([op_x_y_z.copy(), op_u_v_w.copy()]),
                1,
                20,
                [
                    Assignment(var("tmp_0"), op_x_y_z.copy()),
                    Assignment(var("tmp_1"), op_u_v_w.copy()),
                    Return([var("tmp_0"), var("tmp_1")]),
                ],
            ),
        ],
    )
    def test_return(self, instruction: Instruction, ret_complx: int, assign_complx: int, expected: List[Instruction]):
        """Test return statement simplification for different thresholds."""
        true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(CodeNode(stmts := [instruction], true_value), condition_map={})
        _run_ilh(ast, _generate_options(ret=ret_complx, assignment=assign_complx))
        assert stmts == expected

    @pytest.mark.parametrize(
        "call_complx, assign_complx, expected",
        [
            (6, 20, [Assignment(var("a"), Call(FunctionSymbol("foo", 0), [op_6.copy()]))]),
            (
                5,
                3,
                [
                    Assignment(var("tmp_0"), op_x_y_z.copy()),
                    Assignment(
                        var("a"),
                        Call(FunctionSymbol("foo", 0), [BinaryOperation(OperationType.left_shift, [var("tmp_0"), op_u_v_w.copy()])]),
                    ),
                ],
            ),
            (
                5,
                20,
                [
                    Assignment(var("tmp_0"), op_x_y_z.copy()),
                    Assignment(
                        var("a"),
                        Call(FunctionSymbol("foo", 0), [BinaryOperation(OperationType.left_shift, [var("tmp_0"), op_u_v_w.copy()])]),
                    ),
                ],
            ),
            (
                3,
                4,
                [
                    Assignment(var("tmp_0"), op_x_y_z.copy()),
                    Assignment(var("tmp_1"), op_u_v_w.copy()),
                    Assignment(
                        var("a"),
                        Call(FunctionSymbol("foo", 0), [BinaryOperation(OperationType.left_shift, [var("tmp_0"), var("tmp_1")])]),
                    ),
                ],
            ),
            (
                2,
                6,
                [
                    Assignment(var("tmp_0"), op_x_y_z.copy()),
                    Assignment(var("tmp_1"), op_u_v_w.copy()),
                    Assignment(
                        var("a"),
                        Call(FunctionSymbol("foo", 0), [BinaryOperation(OperationType.left_shift, [var("tmp_0"), var("tmp_1")])]),
                    ),
                ],
            ),
            (
                2,
                5,
                [
                    Assignment(var("tmp_0"), op_x_y_z.copy()),
                    Assignment(var("tmp_1"), op_u_v_w.copy()),
                    Assignment(
                        var("a"),
                        Call(FunctionSymbol("foo", 0), [BinaryOperation(OperationType.left_shift, [var("tmp_0"), var("tmp_1")])]),
                    ),
                ],
            ),
            (
                1,
                5,
                [
                    Assignment(var("tmp_1"), op_x_y_z.copy()),
                    Assignment(var("tmp_0"), BinaryOperation(OperationType.left_shift, [var("tmp_1"), op_u_v_w.copy()])),
                    Assignment(var("a"), Call(FunctionSymbol("foo", 0), [var("tmp_0")])),
                ],
            ),
        ],
    )
    def test_call_1_param(self, call_complx: int, assign_complx: int, expected: List[Instruction]):
        true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(
            CodeNode(stmts := [Assignment(var("a"), Call(FunctionSymbol("foo", 0), [op_6.copy()]))], true_value), condition_map={}
        )
        _run_ilh(ast, _generate_options(assignment=assign_complx, call=call_complx))
        assert stmts == expected

    @pytest.mark.parametrize(
        "call_complexity, expected",
        [
            (10, [Assignment(var("a"), Call(FunctionSymbol("foo", 0), [op_6.copy(), op_4.copy()]))]),
            (
                9,
                [
                    Assignment(var("tmp_0"), op_6.copy()),
                    Assignment(var("a"), Call(FunctionSymbol("foo", 0), [var("tmp_0"), op_4.copy()])),
                ],
            ),
            (
                5,
                [
                    Assignment(var("tmp_0"), op_6.copy()),
                    Assignment(var("a"), Call(FunctionSymbol("foo", 0), [var("tmp_0"), op_4.copy()])),
                ],
            ),
            (
                4,
                [
                    Assignment(var("tmp_0"), op_6.copy()),
                    Assignment(var("tmp_1"), op_4.copy()),
                    Assignment(var("a"), Call(FunctionSymbol("foo", 0), [var("tmp_0"), var("tmp_1")])),
                ],
            ),
        ],
    )
    def test_call_2_param(self, call_complexity: int, expected: List[Instruction]):
        true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(
            CodeNode(stmts := [Assignment(var("a"), Call(FunctionSymbol("foo", 0), parameter=[op_6.copy(), op_4.copy()]))], true_value),
            condition_map={},
        )
        _run_ilh(ast, _generate_options(call=call_complexity, assignment=20))
        assert stmts == expected

    @pytest.mark.parametrize(
        "instructions, threshold, expected",
        [
            (
                [Assignment(var("a"), UnaryOperation(OperationType.dereference, [op_4.copy()]))],
                4,
                [Assignment(var("a"), UnaryOperation(OperationType.dereference, [op_4.copy()]))],
            ),
            (
                [Assignment(var("a"), UnaryOperation(OperationType.dereference, [op_4.copy()]))],
                3,
                [
                    Assignment(var("tmp_0"), op_a_b.copy()),
                    Assignment(
                        var("a"),
                        UnaryOperation(OperationType.dereference, [BinaryOperation(OperationType.minus, [var("tmp_0"), op_c_d.copy()])]),
                    ),
                ],
            ),
            (
                [Assignment(var("ch", CHAR), UnaryOperation(OperationType.cast, [op_4.copy()], vartype=CHAR))],
                3,
                [
                    Assignment(var("tmp_0"), op_a_b.copy()),
                    Assignment(
                        var("ch", CHAR),
                        UnaryOperation(
                            OperationType.cast, [BinaryOperation(OperationType.minus, [var("tmp_0"), op_c_d.copy()])], vartype=CHAR
                        ),
                    ),
                ],
            ),
            (
                [Assignment(var("ch", CHAR), UnaryOperation(OperationType.cast, [op_4.copy()], vartype=CHAR))],
                2,
                [
                    Assignment(var("tmp_0"), op_a_b.copy()),
                    Assignment(var("tmp_1"), op_c_d.copy()),
                    Assignment(
                        var("ch", CHAR),
                        UnaryOperation(
                            OperationType.cast, [BinaryOperation(OperationType.minus, [var("tmp_0"), var("tmp_1")])], vartype=CHAR
                        ),
                    ),
                ],
            ),
            (
                [
                    Assignment(
                        var("a"),
                        BinaryOperation(OperationType.plus, [op_6.copy(), UnaryOperation(OperationType.dereference, [op_4.copy()])]),
                    )
                ],
                4,
                [
                    Assignment(var("tmp_2"), op_x_y_z.copy()),
                    Assignment(var("tmp_0"), BinaryOperation(OperationType.left_shift, [var("tmp_2"), op_u_v_w.copy()])),
                    Assignment(var("tmp_1"), UnaryOperation(OperationType.dereference, [op_4.copy()])),
                    Assignment(
                        var("a"),
                        BinaryOperation(OperationType.plus, [var("tmp_0"), var("tmp_1")]),
                    ),
                ],
            ),
            (
                [
                    Assignment(
                        var("a"),
                        BinaryOperation(OperationType.plus, [op_6.copy(), UnaryOperation(OperationType.dereference, [op_4.copy()])]),
                    )
                ],
                3,
                [
                    Assignment(var("tmp_2"), op_x_y_z.copy()),
                    Assignment(var("tmp_3"), op_u_v_w.copy()),
                    Assignment(var("tmp_0"), BinaryOperation(OperationType.left_shift, [var("tmp_2"), var("tmp_3")])),
                    Assignment(var("tmp_4"), op_a_b.copy()),
                    Assignment(
                        var("tmp_1"),
                        UnaryOperation(OperationType.dereference, [BinaryOperation(OperationType.minus, [var("tmp_4"), op_c_d.copy()])]),
                    ),
                    Assignment(
                        var("a"),
                        BinaryOperation(OperationType.plus, [var("tmp_0"), var("tmp_1")]),
                    ),
                ],
            ),
            (
                [
                    Assignment(
                        var("a"),
                        BinaryOperation(OperationType.plus, [op_6.copy(), UnaryOperation(OperationType.dereference, [op_4.copy()])]),
                    )
                ],
                2,
                [
                    Assignment(var("tmp_4"), op_y_z.copy()),
                    Assignment(var("tmp_2"), BinaryOperation(OperationType.plus, [var("x"), var("tmp_4")])),
                    Assignment(var("tmp_5"), op_v_w.copy()),
                    Assignment(var("tmp_3"), BinaryOperation(OperationType.plus, [var("u"), var("tmp_5")])),
                    Assignment(var("tmp_0"), BinaryOperation(OperationType.left_shift, [var("tmp_2"), var("tmp_3")])),
                    Assignment(var("tmp_6"), op_a_b.copy()),
                    Assignment(var("tmp_7"), op_c_d.copy()),
                    Assignment(
                        var("tmp_1"),
                        UnaryOperation(OperationType.dereference, [BinaryOperation(OperationType.minus, [var("tmp_6"), var("tmp_7")])]),
                    ),
                    Assignment(var("a"), BinaryOperation(OperationType.plus, [var("tmp_0"), var("tmp_1")])),
                ],
            ),
        ],
    )
    def test_unary_operation(self, instructions: List[Instruction], threshold: int, expected: List[Instruction]):
        true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(CodeNode(stmts := instructions, true_value), condition_map={})
        _run_ilh(ast, _generate_options(assignment=threshold))
        assert stmts == expected

    @pytest.mark.parametrize(
        "assignment, expected",
        [
            (
                Assignment(
                    var("a"),
                    BinaryOperation(
                        OperationType.plus, [const(1), BinaryOperation(OperationType.plus, [var("ch", CHAR), var("ch", CHAR)])]
                    ),
                ),
                CHAR,
            ),
            (
                Assignment(
                    var("a"),
                    BinaryOperation(
                        OperationType.plus, [const(1), BinaryOperation(OperationType.plus, [var("a_f", FLOAT), var("b_f", FLOAT)])]
                    ),
                ),
                FLOAT,
            ),
            (
                Assignment(
                    var("a"),
                    BinaryOperation(
                        OperationType.plus, [const(1), BinaryOperation(OperationType.plus, [var("e", INT_64), var("f", INT_64)])]
                    ),
                ),
                INT_64,
            ),
        ],
    )
    def test_tmp_var_type(self, assignment: Assignment, expected: Type):
        true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(CodeNode(stmts := [assignment], true_value), {})
        _run_ilh(ast, _generate_options(assignment=2))
        assert isinstance(tmp_assignment := stmts[0], Assignment)
        assert tmp_assignment.destination.type == expected

    def test_ignore_array_access(self):
        array_access = UnaryOperation(
            OperationType.dereference,
            [
                BinaryOperation(
                    OperationType.plus,
                    [
                        base := Variable("arr", Pointer(INT_32), 0, False, ssa_name=Variable("arr", Pointer(INT_32), 0)),
                        index := op_array_access.copy(),
                    ],
                )
            ],
            vartype=INT_32,
            writes_memory=None,
            contraction=False,
            array_info=ArrayInfo(base, index, True),
        )
        true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(CodeNode([array_assignment := Assignment(var("a"), array_access.copy())], true_value), {})
        _run_ilh(ast, _generate_options(assignment=2))
        assert array_assignment == Assignment(var("a"), array_access.copy())

    def test_ignore_lhs(self):
        true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(
            code_node := CodeNode(
                [
                    Assignment(
                        ListOperation([var("a"), var("b"), var("c")]),
                        Call(
                            FunctionSymbol("foo", 0),
                            [var("x"), var("y"), var("z"), BinaryOperation(OperationType.plus, [var("x"), var("y")])],
                        ),
                    )
                ],
                true_value,
            ),
            {},
        )
        _run_ilh(ast, _generate_options(assignment=2, call=2))
        assert code_node.instructions == [
            Assignment(var("tmp_0"), BinaryOperation(OperationType.plus, [var("x"), var("y")])),
            Assignment(
                ListOperation([var("a"), var("b"), var("c")]),
                Call(FunctionSymbol("foo", 0), [var("x"), var("y"), var("z"), var("tmp_0")]),
            ),
        ]

    def test_unsimplifieable(self):
        true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(
            code_node := CodeNode(
                [Assignment(ListOperation([]), Call(FunctionSymbol("foo", 0), [var("x"), var("y"), var("z"), var("u")]))], true_value
            ),
            {},
        )

        _run_ilh(ast, _generate_options(assignment=2, call=1))

        assert code_node.instructions == [
            Assignment(ListOperation([]), Call(FunctionSymbol("foo", 0), [var("x"), var("y"), var("z"), var("u")])),
        ]

    def test_multiple_instructions_single_code_node(self):
        """
        Test that instructions are identified and replaced correctly when placed between other instructions.

        Assignment-threshold: 4
        1. op_a = a + b
        2. op_b = (c + (d + e)) << (f - g)
        3. op_c = (h * 2) / (i + (j + k))
        4. op_d = (l + m) - n

        Should result in:
        1. op_a = a + b

        2. var_0 = (c + (d + e))
           op_b = var_0 << (f - g)

        3. var_1 = (i + (j + k))
           op_c = (h * 2) / var_1

        4. op_d = (l + m) - n
        """
        instr_1 = Assignment(var("op_a"), BinaryOperation(OperationType.plus, [var("a"), var("b")]))
        instr_2 = Assignment(
            var("op_b"),
            BinaryOperation(
                OperationType.left_shift,
                [
                    BinaryOperation(OperationType.plus, [var("c"), BinaryOperation(OperationType.plus, [var("d"), var("e")])]),
                    BinaryOperation(OperationType.minus, [var("f"), var("g")]),
                ],
            ),
        )
        instr_3 = Assignment(
            var("op_c"),
            BinaryOperation(
                OperationType.divide,
                [
                    BinaryOperation(OperationType.multiply, [var("h"), const(2)]),
                    BinaryOperation(OperationType.plus, [var("i"), BinaryOperation(OperationType.plus, [var("j"), var("k")])]),
                ],
            ),
        )
        instr_4 = Assignment(
            var("op_d"), BinaryOperation(OperationType.minus, [BinaryOperation(OperationType.plus, [var("l"), var("m")]), var("n")])
        )
        true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
        ast = AbstractSyntaxTree(CodeNode([instr_1.copy(), instr_2.copy(), instr_3.copy(), instr_4.copy()], true_value), condition_map={})

        _run_ilh(ast, _generate_options(assignment=4))

        assert ast.root.instructions == [
            instr_1.copy(),
            Assignment(
                var("tmp_0"), BinaryOperation(OperationType.plus, [var("c"), BinaryOperation(OperationType.plus, [var("d"), var("e")])])
            ),
            Assignment(
                var("op_b"),
                BinaryOperation(OperationType.left_shift, [var("tmp_0"), BinaryOperation(OperationType.minus, [var("f"), var("g")])]),
            ),
            Assignment(
                var("tmp_1"), BinaryOperation(OperationType.plus, [var("i"), BinaryOperation(OperationType.plus, [var("j"), var("k")])])
            ),
            Assignment(
                var("op_c"),
                BinaryOperation(OperationType.divide, [BinaryOperation(OperationType.multiply, [var("h"), const(2)]), var("tmp_1")]),
            ),
            instr_4.copy(),
        ]

    def test_complex_syntax_tree(self):
        """
        Code for AST:
        a = rand();
        b = rand();
        c = rand();
        d = rand();

        if (a < 10) {
            b = a;
        } else {
            b = (a + 10) / (b - (2 + a));
        }

        switch(c) {
            case 0:
                c = (a + b) / (d - (a * 2));
                break;
            case 1:
                c = 0;
                break;
            default:
                c = (a + b) / (b - (a * 2));
        }
        """
        true_value = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
        condition_node_condition = LogicCondition.initialize_symbol("a", context)

        ast = AbstractSyntaxTree(
            root := SeqNode(true_value), condition_map={condition_node_condition: Condition(OperationType.less, [var("a"), const(10)])}
        )

        init_code_node = ast._add_code_node(
            [
                Assignment(ListOperation([var("a")]), Call(FunctionSymbol("rand", 0), [])),
                Assignment(ListOperation([var("b")]), Call(FunctionSymbol("rand", 0), [])),
                Assignment(ListOperation([var("c")]), Call(FunctionSymbol("rand", 0), [])),
                Assignment(ListOperation([var("d")]), Call(FunctionSymbol("rand", 0), [])),
            ]
        )

        condition_node_true = ast._add_code_node([Assignment(var("b"), var("a"))])
        condition_node_false = ast._add_code_node(
            [
                Assignment(
                    var("b"),
                    BinaryOperation(
                        OperationType.divide,
                        [
                            BinaryOperation(OperationType.plus, [var("a"), var("b")]),
                            BinaryOperation(OperationType.minus, [var("b"), BinaryOperation(OperationType.multiply, [var("a"), const(2)])]),
                        ],
                    ),
                )
            ]
        )
        condition_node = ast._add_condition_node_with(condition_node_condition, condition_node_true, condition_node_false)

        switch_node = ast.factory.create_switch_node(var("c"))
        case_0_node = ast.factory.create_case_node(var("c"), const(0), break_case=True)
        case_0_node_child = ast._add_code_node(
            [
                Assignment(
                    var("c"),
                    BinaryOperation(
                        OperationType.divide,
                        [
                            BinaryOperation(OperationType.plus, [var("a"), var("b")]),
                            BinaryOperation(OperationType.minus, [var("d"), BinaryOperation(OperationType.multiply, [var("a"), const(2)])]),
                        ],
                    ),
                )
            ]
        )
        case_1_node = ast.factory.create_case_node(var("c"), const(1), break_case=True)
        case_1_node_child = ast._add_code_node([Assignment(var("c"), const(0))])
        case_default_node = ast.factory.create_case_node(var("c"), "default")
        case_default_node_child = ast._add_code_node(
            [
                Assignment(
                    var("b"),
                    BinaryOperation(
                        OperationType.divide,
                        [
                            BinaryOperation(OperationType.plus, [var("a"), var("b")]),
                            BinaryOperation(OperationType.minus, [var("b"), BinaryOperation(OperationType.multiply, [var("a"), const(2)])]),
                        ],
                    ),
                )
            ]
        )
        ast._add_nodes_from([switch_node, case_0_node, case_1_node, case_default_node])
        ast._add_edges_from(
            [
                (root, init_code_node),
                (root, condition_node),
                (root, switch_node),
                (switch_node, case_0_node),
                (case_0_node, case_0_node_child),
                (switch_node, case_1_node),
                (case_1_node, case_1_node_child),
                (switch_node, case_default_node),
                (case_default_node, case_default_node_child),
            ]
        )

        ast._code_node_reachability_graph.add_reachability_from(
            [
                (init_code_node, condition_node_true),
                (init_code_node, condition_node_false),
                (init_code_node, condition_node_true),
                (init_code_node, condition_node_false),
            ]
        )

        root._sorted_children = (init_code_node, condition_node, switch_node)

        _run_ilh(ast, _generate_options(assignment=4))

        assert condition_node_false.instructions == [
            Assignment(
                var("tmp_0"),
                BinaryOperation(OperationType.minus, [var("b"), BinaryOperation(OperationType.multiply, [var("a"), const(2)])]),
            ),
            Assignment(
                var("b"), BinaryOperation(OperationType.divide, [BinaryOperation(OperationType.plus, [var("a"), var("b")]), var("tmp_0")])
            ),
        ]

        assert case_0_node_child.instructions == [
            Assignment(
                var("tmp_1"),
                BinaryOperation(OperationType.minus, [var("d"), BinaryOperation(OperationType.multiply, [var("a"), const(2)])]),
            ),
            Assignment(
                var("c"), BinaryOperation(OperationType.divide, [BinaryOperation(OperationType.plus, [var("a"), var("b")]), var("tmp_1")])
            ),
        ]

        assert case_default_node_child.instructions == [
            Assignment(
                var("tmp_2"),
                BinaryOperation(OperationType.minus, [var("b"), BinaryOperation(OperationType.multiply, [var("a"), const(2)])]),
            ),
            Assignment(
                var("b"), BinaryOperation(OperationType.divide, [BinaryOperation(OperationType.plus, [var("a"), var("b")]), var("tmp_2")])
            ),
        ]
