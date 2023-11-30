from io import StringIO

import pytest
from binaryninja import HighlightStandardColor
from decompiler.structures.ast.ast_nodes import SeqNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo.expressions import Constant, FunctionSymbol, ImportedFunctionSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Phi, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, OperationType
from decompiler.structures.pseudo.typing import Integer
from decompiler.util.decoration import ASTYLE_INSTALLED, GRAPH_EASY_INSTALLED, DecoratedAST, DecoratedCFG, DecoratedCode
from decompiler.util.to_dot_converter import ToDotConverter


class TestDecoratedCFG:
    @pytest.fixture
    def simple_graph(self):
        """
        +------------------+
        |        0.        |
        | a#0 = 0x2        |
        | b#0 = foo(a#0)   |
        | if(a#0 < b#0)    | -+
        +------------------+  |
          |                   |
          |                   |
          v                   |
        +------------------+  |
        |        1.        |  |
        | b#2 = a#0 - b#0  |  |
        +------------------+  |
          |                   |
          |                   |
          v                   |
        +------------------+  |
        |        2.        |  |
        | b#1 = ϕ(b#0,b#2) |  |
        | return b#1       | <+
        +------------------+
        """
        cfg = ControlFlowGraph()
        cfg.add_nodes_from(
            [
                start := BasicBlock(
                    0,
                    instructions=[
                        Assignment(Variable("a", Integer.int32_t(), ssa_label=0), Constant(2, Integer.int8_t())),
                        Assignment(
                            Variable("b", Integer.int64_t(), ssa_label=0),
                            Call(FunctionSymbol("foo", 0x42), [Variable("a", Integer.int32_t(), ssa_label=0)]),
                        ),
                        Branch(
                            Condition(
                                OperationType.less,
                                [Variable("a", Integer.int32_t(), ssa_label=0), Variable("b", Integer.int64_t(), ssa_label=0)],
                            )
                        ),
                    ],
                ),
                true := BasicBlock(
                    1,
                    instructions=[
                        Assignment(
                            Variable("b", Integer.int64_t(), ssa_label=2),
                            BinaryOperation(
                                OperationType.minus,
                                [Variable("a", Integer.int32_t(), ssa_label=0), Variable("b", Integer.int64_t(), ssa_label=0)],
                            ),
                        )
                    ],
                ),
                end := BasicBlock(
                    2,
                    instructions=[
                        Phi(
                            Variable("b", Integer.int64_t(), ssa_label=1),
                            [Variable("b", Integer.int64_t(), ssa_label=0), Variable("b", Integer.int64_t(), ssa_label=2)],
                        ),
                        Return([Variable("b", Integer.int64_t(), ssa_label=1)]),
                    ],
                ),
            ]
        )
        cfg.add_edges_from([TrueCase(start, true), FalseCase(start, end), UnconditionalEdge(true, end)])
        return cfg

    @pytest.fixture()
    def graph_with_string(self):
        cfg = ControlFlowGraph()
        cfg.add_nodes_from(
            [
                start := BasicBlock(
                    0,
                    instructions=[
                        Assignment(Variable("a", Integer.int32_t(), ssa_label=0), Constant(2, Integer.int8_t())),
                        Assignment(
                            Variable("b", Integer.int64_t(), ssa_label=0),
                            Call(FunctionSymbol("foo", 0x42), [Variable("a", Integer.int32_t(), ssa_label=0)]),
                        ),
                        Branch(
                            Condition(
                                OperationType.less,
                                [Variable("a", Integer.int32_t(), ssa_label=0), Variable("b", Integer.int64_t(), ssa_label=0)],
                            )
                        ),
                    ],
                ),
                true := BasicBlock(
                    1,
                    instructions=[
                        Assignment(
                            Variable("b", Integer.int64_t(), ssa_label=2),
                            BinaryOperation(
                                OperationType.minus,
                                [Variable("a", Integer.int32_t(), ssa_label=0), Variable("b", Integer.int64_t(), ssa_label=0)],
                            ),
                        )
                    ],
                ),
                end := BasicBlock(
                    2,
                    instructions=[
                        Phi(
                            Variable("b", Integer.int64_t(), ssa_label=1),
                            [Variable("b", Integer.int64_t(), ssa_label=0), Variable("b", Integer.int64_t(), ssa_label=2)],
                        ),
                        Assignment(
                            ListOperation([]),
                            Call(
                                ImportedFunctionSymbol("printf", 0),
                                [Constant("The result is : %i"), Variable("b", Integer.int64_t(), ssa_label=1)],
                            ),
                        ),
                        Return([Variable("b", Integer.int64_t(), ssa_label=1)]),
                    ],
                ),
            ]
        )
        cfg.add_edges_from([TrueCase(start, true), FalseCase(start, end), UnconditionalEdge(true, end)])
        return cfg

    @pytest.mark.usefixtures("simple_graph")
    @pytest.mark.skipif(not GRAPH_EASY_INSTALLED, reason="requires graph-easy")
    def test_does_return_anything_at_all(self, simple_graph):
        decorated = DecoratedCFG.from_cfg(simple_graph)
        assert decorated.export_ascii()

    @pytest.mark.usefixtures("graph_with_string")
    @pytest.mark.skipif(not GRAPH_EASY_INSTALLED, reason="requires graph-easy")
    def test_does_print_ascii(self, graph_with_string):
        decorated = DecoratedCFG.from_cfg(graph_with_string)
        assert decorated.export_ascii().splitlines() == [
            "+-----------------------------------+",
            "|                0.                 |",
            "|             a#0 = 0x2             |",
            "|          b#0 = foo(a#0)           |",
            "|           if(a#0 < b#0)           | -+",
            "+-----------------------------------+  |",
            "  |                                    |",
            "  |                                    |",
            "  v                                    |",
            "+-----------------------------------+  |",
            "|                1.                 |  |",
            "|          b#2 = a#0 - b#0          |  |",
            "+-----------------------------------+  |",
            "  |                                    |",
            "  |                                    |",
            "  v                                    |",
            "+-----------------------------------+  |",
            "|                2.                 |  |",
            "|         b#1 = ϕ(b#0,b#2)          |  |",
            '| printf("The result is : %i", b#1) |  |',
            "|            return b#1             | <+",
            "+-----------------------------------+",
        ]

    @pytest.mark.usefixtures("simple_graph")
    @pytest.mark.skipif(not GRAPH_EASY_INSTALLED, reason="requires graph-easy")
    def test_does_decorate_graph_correctly(self, simple_graph):
        decorated = DecoratedCFG.from_cfg(simple_graph)
        assert decorated.graph.nodes[0] == {"color": "blue", "shape": "box", "label": "0.\na#0 = 0x2\nb#0 = foo(a#0)\nif(a#0 < b#0)"}
        assert decorated.graph.nodes[1] == {"color": "blue", "shape": "box", "label": "1.\nb#2 = a#0 - b#0"}
        assert decorated.graph.nodes[2] == {"color": "blue", "shape": "box", "label": "2.\nb#1 = ϕ(b#0,b#2)\nreturn b#1"}

    def test_convert_to_dot(self, simple_graph):
        decorated = DecoratedCFG.from_cfg(simple_graph)
        dot_converter = ToDotConverter(decorated.graph)
        content = dot_converter._create_dot()
        assert (
            content
            == """strict digraph  {
0 [shape="box", color="blue", label="0.\\na#0 = 0x2\\nb#0 = foo(a#0)\\nif(a#0 < b#0)"]; 
1 [shape="box", color="blue", label="1.\\nb#2 = a#0 - b#0"]; 
2 [shape="box", color="blue", label="2.\\nb#1 = ϕ(b#0,b#2)\\nreturn b#1"]; 
0 -> 1 [color="darkgreen"]; 
0 -> 2 [color="darkred"]; 
1 -> 2 [color="blue"]; 
}"""
        )

    def test_convert_to_dot_with_string(self, graph_with_string):
        decorated = DecoratedCFG.from_cfg(graph_with_string)
        dot_converter = ToDotConverter(decorated.graph)
        content = dot_converter._create_dot()
        assert (
            content
            == """strict digraph  {
0 [shape="box", color="blue", label="0.\\na#0 = 0x2\\nb#0 = foo(a#0)\\nif(a#0 < b#0)"]; 
1 [shape="box", color="blue", label="1.\\nb#2 = a#0 - b#0"]; 
2 [shape="box", color="blue", label="2.\\nb#1 = ϕ(b#0,b#2)\\nprintf(\\"The result is : %i\\", b#1)\\nreturn b#1"]; 
0 -> 1 [color="darkgreen"]; 
0 -> 2 [color="darkred"]; 
1 -> 2 [color="blue"]; 
}"""
        )


class TestDecoratedAST:
    @pytest.fixture
    def ast_condition(self):
        variable_c = Variable("c", Integer(32, signed=True))
        constant_0 = Constant(0, Integer(32, signed=True))
        constant_5 = Constant(5, Integer(32, signed=True))
        root = SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context()))
        ast = AbstractSyntaxTree(root, {})
        true_seq_node = ast.factory.create_seq_node()
        ast._add_node(true_seq_node)
        true_branch = ast._add_code_node([Assignment(variable_c, constant_5), Return([variable_c])])
        false_seq_node = ast.factory.create_seq_node()
        ast._add_node(false_seq_node)
        false_branch = ast._add_code_node([Return([constant_0])])
        condition_node = ast._add_condition_node_with(
            condition=LogicCondition.initialize_true(ast.factory.logic_context), true_branch=true_seq_node, false_branch=false_seq_node
        )
        ast._add_edges_from(((root, condition_node), (true_seq_node, true_branch), (false_seq_node, false_branch)))

        return ast

    @pytest.fixture
    def ast_for_loop(self):
        variable_c = Variable("c", Integer(32, signed=True))
        variable_i = Variable("i", Integer(32, signed=True))
        variable_x = Variable("x", Integer(32, signed=True))
        constant_0 = Constant(0, Integer(32, signed=True))
        constant_5 = Constant(5, Integer(32, signed=True))
        constant_10 = Constant(10, Integer(32, signed=True))
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(
            root, {LogicCondition.initialize_symbol("x1", context): Condition(OperationType.less, [variable_x, constant_5])}
        )
        loop = ast.factory.create_for_loop_node(
            declaration=Assignment(variable_i, constant_0),
            condition=LogicCondition.initialize_symbol("x1", ast.factory.logic_context),
            modification=Assignment(variable_i, constant_10),
        )
        ast._add_node(loop)
        loop_body = ast._add_code_node([Assignment(variable_c, constant_5)])
        ast._add_edges_from(((root, loop), (loop, loop_body)))
        return ast

    @pytest.fixture
    def ast_while_loop(self):
        variable_c = Variable("c", Integer(32, signed=True))
        variable_x = Variable("x", Integer(32, signed=True))
        constant_5 = Constant(5, Integer(32, signed=True))
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(
            root, {LogicCondition.initialize_symbol("x1", context): Condition(OperationType.less, [variable_x, constant_5])}
        )
        loop = ast.factory.create_while_loop_node(condition=LogicCondition.initialize_symbol("x1", ast.factory.logic_context))
        ast._add_node(loop)
        loop_body = ast._add_code_node([Assignment(variable_c, constant_5)])
        ast._add_edges_from(((root, loop), (loop, loop_body)))
        return ast

    @pytest.fixture
    def ast_switch(self):
        switch_expression = Constant(41)
        constant_m1 = Constant(-1, Integer(32, signed=True))
        constant_0 = Constant(0, Integer(32, signed=True))
        constant_1 = Constant(1, Integer(32, signed=True))
        constant_41 = Constant(41, Integer(32, signed=True))
        root = SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context()))
        ast = AbstractSyntaxTree(root, {})
        switch_node = ast.factory.create_switch_node(expression=switch_expression)
        case_1 = ast.factory.create_case_node(expression=switch_expression, constant=constant_0)
        case_1_child = ast._add_code_node([Return([constant_0])])
        case_2 = ast.factory.create_case_node(expression=switch_expression, constant=constant_1)
        case_2_child = ast._add_code_node([Return([constant_1])])
        case_3 = ast.factory.create_case_node(expression=switch_expression, constant=constant_41)
        case_3_child = ast._add_code_node([Return([constant_41])])
        default_case = ast.factory.create_case_node(expression=switch_expression, constant="default")
        default_case_child = ast._add_code_node([Return([constant_m1])])
        ast._add_nodes_from((switch_node, case_1, case_2, case_3, default_case))
        ast._add_edges_from(
            (
                (root, switch_node),
                (switch_node, case_1),
                (switch_node, case_2),
                (switch_node, case_3),
                (switch_node, default_case),
                (case_1, case_1_child),
                (case_2, case_2_child),
                (case_3, case_3_child),
                (default_case, default_case_child),
            )
        )
        switch_node._sorted_cases = (case_1, case_2, case_3, default_case)
        return ast

    # Ascii representation tests

    @pytest.mark.usefixtures("ast_condition")
    @pytest.mark.skipif(not GRAPH_EASY_INSTALLED, reason="requires graph-easy")
    def test_ascii_condition(self, ast_condition):
        assert DecoratedAST.from_ast(ast_condition).export_ascii().splitlines() == [
            "                     +------------------+",
            "                     |    0. SeqNode    |",
            "                     |                  |",
            "                     |     Sequence     |",
            "                     +------------------+",
            "                       |",
            "                       |",
            "                       v",
            "+-------------+      +------------------+",
            "| 4. SeqNode  |      | 1. ConditionNode |",
            "|             |  F   |                  |",
            "|  Sequence   | <--- |    if (true)     |",
            "+-------------+      +------------------+",
            "  |                    |",
            "  |                    | T",
            "  v                    v",
            "+-------------+      +------------------+",
            "| 5. CodeNode |      |    2. SeqNode    |",
            "|             |      |                  |",
            "| return 0x0  |      |     Sequence     |",
            "+-------------+      +------------------+",
            "                       |",
            "                       |",
            "                       v",
            "                     +------------------+",
            "                     |   3. CodeNode    |",
            "                     |                  |",
            "                     |     c = 0x5      |",
            "                     |     return c     |",
            "                     +------------------+",
        ]

    @pytest.mark.usefixtures("ast_for_loop")
    @pytest.mark.skipif(not GRAPH_EASY_INSTALLED, reason="requires graph-easy")
    def test_ascii_for_loop(self, ast_for_loop):
        assert DecoratedAST.from_ast(ast_for_loop).export_ascii().splitlines() == [
            "+---------------------------------+",
            "|           0. SeqNode            |",
            "|                                 |",
            "|            Sequence             |",
            "+---------------------------------+",
            "  |",
            "  |",
            "  v",
            "+---------------------------------+",
            "|         1. ForLoopNode          |",
            "|                                 |",
            "| for (i = 0x0; x < 0x5; i = 0xa) |",
            "+---------------------------------+",
            "  |",
            "  |",
            "  v",
            "+---------------------------------+",
            "|           2. CodeNode           |",
            "|                                 |",
            "|             c = 0x5             |",
            "+---------------------------------+",
        ]

    @pytest.mark.usefixtures("ast_while_loop")
    @pytest.mark.skipif(not GRAPH_EASY_INSTALLED, reason="requires graph-easy")
    def test_ascii_while_loop(self, ast_while_loop):
        assert DecoratedAST.from_ast(ast_while_loop).export_ascii().splitlines() == [
            "+------------------+",
            "|    0. SeqNode    |",
            "|                  |",
            "|     Sequence     |",
            "+------------------+",
            "  |",
            "  |",
            "  v",
            "+------------------+",
            "| 1. WhileLoopNode |",
            "|                  |",
            "| while (x < 0x5)  |",
            "+------------------+",
            "  |",
            "  |",
            "  v",
            "+------------------+",
            "|   2. CodeNode    |",
            "|                  |",
            "|     c = 0x5      |",
            "+------------------+",
        ]

    @pytest.mark.usefixtures("ast_switch")
    @pytest.mark.skipif(not GRAPH_EASY_INSTALLED, reason="requires graph-easy")
    def test_ascii_switch(self, ast_switch):
        assert DecoratedAST.from_ast(ast_switch).export_ascii().splitlines() == [
            "                    +-------------+",
            "                    | 0. SeqNode  |",
            "                    |             |",
            "                    |  Sequence   |",
            "                    +-------------+",
            "                      |",
            "                      |",
            "                      v",
            "+-------------+     +----------------------------+     +-------------+",
            "| 6. CaseNode |     |       1. SwitchNode        |     | 8. CaseNode |",
            "|             |     |                            |     |             |",
            "| case 0x29:  | <-- |       switch (0x29)        | --> |  default:   |",
            "+-------------+     +----------------------------+     +-------------+",
            "  |                   |              |                   |",
            "  |                   |              |                   |",
            "  v                   v              v                   v",
            "+-------------+     +-------------++-------------+     +-------------+",
            "| 7. CodeNode |     | 2. CaseNode || 4. CaseNode |     | 9. CodeNode |",
            "|             |     |             ||             |     |             |",
            "| return 0x29 |     |  case 0x0:  ||  case 0x1:  |     | return -0x1 |",
            "+-------------+     +-------------++-------------+     +-------------+",
            "                      |              |",
            "                      |              |",
            "                      v              v",
            "                    +-------------++-------------+",
            "                    | 3. CodeNode || 5. CodeNode |",
            "                    |             ||             |",
            "                    | return 0x0  || return 0x1  |",
            "                    +-------------++-------------+",
        ]

    # dot representation tests

    @pytest.mark.usefixtures("ast_condition")
    def test_dotviz_output(self, ast_condition):
        decorated = DecoratedAST.from_ast(ast_condition)

        with StringIO() as stringIo:
            decorated._write_dot(stringIo)
            data = stringIo.getvalue()

        assert all(
            [
                x in data
                for x in [
                    r"strict digraph  {",
                    r'[style="filled", fillcolor="#e6f5c9", label="0. SeqNode\n\nSequence"];',
                    r'[style="filled", fillcolor="#e6f5c9", label="1. ConditionNode\n\nif (true)"]',
                    r'[style="filled", fillcolor="#e6f5c9", label="2. SeqNode\n\nSequence"];',
                    r'[style="filled", fillcolor="#fff2ae", label="3. CodeNode\n\nc = 0x5\nreturn c"];',
                    r'[style="filled", fillcolor="#e6f5c9", label="4. SeqNode\n\nSequence"];',
                    r'[style="filled", fillcolor="#fff2ae", label="5. CodeNode\n\nreturn 0x0"];',
                ]
            ]
        )

    # graph representation tests

    @pytest.mark.usefixtures("ast_condition")
    def test_does_decorate_graph_correctly(self, ast_condition):
        decorated = DecoratedAST.from_ast(ast_condition)._graph
        assert [x[1] for x in decorated.nodes(data=True)] == [
            {
                "style": "filled",
                "fillcolor": "#e6f5c9",
                "highlight": HighlightStandardColor.GreenHighlightColor,
                "label": "0. SeqNode\n\nSequence",
            },
            {
                "style": "filled",
                "fillcolor": "#e6f5c9",
                "highlight": HighlightStandardColor.RedHighlightColor,
                "label": "1. ConditionNode\n\nif (true)",
            },
            {
                "style": "filled",
                "fillcolor": "#e6f5c9",
                "highlight": HighlightStandardColor.GreenHighlightColor,
                "label": "2. SeqNode\n\nSequence",
            },
            {"style": "filled", "fillcolor": "#fff2ae", "label": "3. CodeNode\n\nc = 0x5\nreturn c"},
            {
                "style": "filled",
                "fillcolor": "#e6f5c9",
                "highlight": HighlightStandardColor.GreenHighlightColor,
                "label": "4. SeqNode\n\nSequence",
            },
            {"style": "filled", "fillcolor": "#fff2ae", "label": "5. CodeNode\n\nreturn 0x0"},
        ]

    # FlowGraph representation tests

    @pytest.mark.usefixtures("ast_for_loop")
    def test_flow_graph_for_loop(self, ast_for_loop):
        graph = DecoratedAST().from_ast(ast_for_loop)._generate_flowgraph()
        expected = [
            ["0. SeqNode"],
            [""],
            ["Sequence"],
            ["1. ForLoopNode"],
            [""],
            ["for (i = 0x0; x < 0x5; i = 0xa)"],
            ["2. CodeNode"],
            [""],
            ["c = 0x5"],
        ]
        assert str([line.tokens for node in graph.nodes for line in node.lines]) == str(expected)

    @pytest.mark.usefixtures("ast_while_loop")
    def test_flow_graph_while_loop(self, ast_while_loop):
        graph = DecoratedAST().from_ast(ast_while_loop)._generate_flowgraph()
        expected = [["0. SeqNode"], [""], ["Sequence"], ["1. WhileLoopNode"], [""], ["while (x < 0x5)"], ["2. CodeNode"], [""], ["c = 0x5"]]
        assert str([line.tokens for node in graph.nodes for line in node.lines]) == str(expected)

    @pytest.mark.usefixtures("ast_switch")
    def test_flow_graph_switch(self, ast_switch):
        graph = DecoratedAST.from_ast(ast_switch)._generate_flowgraph()
        assert str([line.tokens for node in graph.nodes for line in node.lines]) == str(
            [
                ["0. SeqNode"],
                [""],
                ["Sequence"],
                ["1. SwitchNode"],
                [""],
                ["switch (0x29)"],
                ["2. CaseNode"],
                [""],
                ["case 0x0:"],
                ["3. CodeNode"],
                [""],
                ["return 0x0"],
                ["4. CaseNode"],
                [""],
                ["case 0x1:"],
                ["5. CodeNode"],
                [""],
                ["return 0x1"],
                ["6. CaseNode"],
                [""],
                ["case 0x29:"],
                ["7. CodeNode"],
                [""],
                ["return 0x29"],
                ["8. CaseNode"],
                [""],
                ["default:"],
                ["9. CodeNode"],
                [""],
                ["return -0x1"],
            ]
        )

    def test_convert_to_dot_if(self, ast_condition):
        """Test that convert to dot can if"""
        decorated = DecoratedAST.from_ast(ast_condition)
        dot_converter = ToDotConverter(decorated.graph)
        content = dot_converter._create_dot()
        assert (
            content
            == """strict digraph  {
0 [style="filled", fillcolor="#e6f5c9", label="0. SeqNode\\n\\nSequence"]; 
1 [style="filled", fillcolor="#e6f5c9", label="1. ConditionNode\\n\\nif (true)"]; 
2 [style="filled", fillcolor="#e6f5c9", label="2. SeqNode\\n\\nSequence"]; 
3 [style="filled", fillcolor="#fff2ae", label="3. CodeNode\\n\\nc = 0x5\\nreturn c"]; 
4 [style="filled", fillcolor="#e6f5c9", label="4. SeqNode\\n\\nSequence"]; 
5 [style="filled", fillcolor="#fff2ae", label="5. CodeNode\\n\\nreturn 0x0"]; 
0 -> 1 []; 
1 -> 2 [label="T", color="#228B22"]; 
1 -> 4 [label="F", color="#c2261f"]; 
2 -> 3 []; 
4 -> 5 []; 
}"""
        )

    def test_convert_to_dot_switch(self, ast_switch):
        """Test that convert to dot can handle switch"""
        decorated = DecoratedAST.from_ast(ast_switch)
        dot_converter = ToDotConverter(decorated.graph)
        content = dot_converter._create_dot()
        assert (
            content
            == """strict digraph  {
0 [style="filled", fillcolor="#e6f5c9", label="0. SeqNode\\n\\nSequence"]; 
1 [style="filled", fillcolor="#fdcdac", label="1. SwitchNode\\n\\nswitch (0x29)"]; 
2 [style="filled", fillcolor="#e6f5c9", label="2. CaseNode\\n\\ncase 0x0:"]; 
3 [style="filled", fillcolor="#fff2ae", label="3. CodeNode\\n\\nreturn 0x0"]; 
4 [style="filled", fillcolor="#e6f5c9", label="4. CaseNode\\n\\ncase 0x1:"]; 
5 [style="filled", fillcolor="#fff2ae", label="5. CodeNode\\n\\nreturn 0x1"]; 
6 [style="filled", fillcolor="#e6f5c9", label="6. CaseNode\\n\\ncase 0x29:"]; 
7 [style="filled", fillcolor="#fff2ae", label="7. CodeNode\\n\\nreturn 0x29"]; 
8 [style="filled", fillcolor="#e6f5c9", label="8. CaseNode\\n\\ndefault:"]; 
9 [style="filled", fillcolor="#fff2ae", label="9. CodeNode\\n\\nreturn -0x1"]; 
0 -> 1 []; 
1 -> 2 []; 
1 -> 4 []; 
1 -> 6 []; 
1 -> 8 []; 
2 -> 3 []; 
4 -> 5 []; 
6 -> 7 []; 
8 -> 9 []; 
}"""
        )


class TestDecoratedCode:
    @pytest.fixture
    def simple_code(self):
        return """#import <stdio.h>\nint main(int argv, char** argc){print("Hallo, Welt!");}"""

    @pytest.mark.usefixtures("simple_code")
    def test_does_return_anything_at_all(self, simple_code):
        decorated = DecoratedCode(simple_code)
        assert decorated.export_ascii()

    @pytest.mark.usefixtures("simple_code")
    @pytest.mark.skipif(not ASTYLE_INSTALLED, reason="requires astyle")
    def test_does_reformat_code(self, simple_code):
        """Check if code formatting works properly."""
        decorated = DecoratedCode(simple_code)
        decorated.reformat()
        assert decorated.code == "#import <stdio.h>\n" "int main(int argv, char** argc) {\n" '    print("Hallo, Welt!");\n' "}"

    @pytest.mark.usefixtures("simple_code")
    def test_does_pygmentize(self, simple_code):
        """We had a recent version change in pygmetize, so we try to test for both versions."""
        decorated = DecoratedCode(simple_code)
        assert decorated.export_ascii().count("\x1b") > 0

    @pytest.mark.usefixtures("simple_code")
    def test_does_html_output(self, simple_code):
        """Check whether html output returns anything."""
        decorated = DecoratedCode(simple_code)
        html_code = decorated.export_html()
        assert len(html_code) > 100
        assert r"\*" not in html_code
