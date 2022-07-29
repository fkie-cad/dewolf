from pathlib import Path
from typing import List, Union

import pytest
from decompiler.backend.codegenerator import CodeGenerator
from decompiler.structures.ast.ast_nodes import CaseNode, CodeNode, ConditionNode, ForLoopNode, SeqNode, SwitchNode, WhileLoopNode
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Break,
    Call,
    Condition,
    Constant,
    Continue,
    CustomType,
    Float,
    FunctionSymbol,
    ImportedFunctionSymbol,
    Integer,
    ListOperation,
    OperationType,
    Pointer,
    Return,
    Type,
    UnaryOperation,
    Variable,
)
from decompiler.task import DecompilerTask
from decompiler.util.c_to_ast import C2ASTConverter


def var(name: str, vartype: Type = Integer.int32_t()) -> Variable:
    return Variable(name, vartype)


def const(value: Union[int, float, str], vartype: Type = Integer.int32_t()) -> Constant:
    return Constant(value, vartype)


class TestC2ASTConverter:
    """Test that ASTGenerator produces valid/correct ASTs"""

    @staticmethod
    def run_converter(code: Union[Path, str], function_name: str) -> DecompilerTask:
        return C2ASTConverter().from_code(code, function_name)

    @pytest.mark.parametrize(
        "code, expected",
        [
            ("short main() {}", Integer.int16_t()),
            ("int main() {}", Integer.int32_t()),
            ("float main() {}", Float.float()),
            ("void main() {}", CustomType.void()),
            ("void* main() {}", Pointer(CustomType.void())),
            ("long double main() {}", Float(128)),
        ],
    )
    def test_function_return_type(self, code: str, expected: Type):
        decompiler_task = self.run_converter(code, "main")
        assert decompiler_task.function_return_type == expected

    @pytest.mark.parametrize(
        "code, expected",
        [
            ("int main() {}", []),
            ("int main(int a) {}", [var("a")]),
            ("int main(float a) {}", [var("a", Float.float())]),
            ("int main(char a) {}", [var("a", Integer.char())]),
            ("int main(int a, char b) {}", [var("a"), var("b", Integer.char())]),
        ],
    )
    def test_parameters(self, code: str, expected: List[Variable]):
        decompiler_task = self.run_converter(code, "main")
        assert decompiler_task.function_parameters == expected

    @pytest.mark.parametrize(
        "code, expected",
        [
            ("int main(int a) { a++; }", Assignment(var("a"), BinaryOperation(OperationType.plus, [var("a"), const(1)]))),
            ("int main(int a) { a--; }", Assignment(var("a"), BinaryOperation(OperationType.minus, [var("a"), const(1)]))),
            ("int main(int a) { a += 1; }", Assignment(var("a"), BinaryOperation(OperationType.plus, [var("a"), const(1)]))),
            ("int main(int a) { a -= 1; }", Assignment(var("a"), BinaryOperation(OperationType.minus, [var("a"), const(1)]))),
            ("int main(int a) { a += 2; }", Assignment(var("a"), BinaryOperation(OperationType.plus, [var("a"), const(2)]))),
            ("int main(int a) { a -= 2; }", Assignment(var("a"), BinaryOperation(OperationType.minus, [var("a"), const(2)]))),
            ("int main(int a) { a /= 2; }", Assignment(var("a"), BinaryOperation(OperationType.divide, [var("a"), const(2)]))),
            ("int main(int a) { a *= 2; }", Assignment(var("a"), BinaryOperation(OperationType.multiply, [var("a"), const(2)]))),
        ],
    )
    def test_compound(self, code: str, expected: Assignment):
        decompiler_task = self.run_converter(code, "main")
        code_node = decompiler_task.syntax_tree.root
        assert isinstance(code_node, CodeNode)
        assert code_node.instructions == [expected]

    @pytest.mark.parametrize(
        "code, expected",
        [
            ("int main() { return; }", Return([])),
            ("int main() { return 0; }", Return([const(0)])),
            ('int main() { return "foo"; }', Return([const("foo", Pointer(Integer.char()))])),
            ("int main() { return foo(); }", Return([Call(FunctionSymbol("foo", 0), [])])),
        ],
    )
    def test_return(self, code: str, expected: Return):
        decompiler_task = self.run_converter(code, "main")
        code_node = decompiler_task.syntax_tree.root
        assert isinstance(code_node, CodeNode)
        assert code_node.instructions == [expected]

    def test_function_call(self):
        code = r"""int main(int a) { a = foo(a); }"""
        decompiler_task = self.run_converter(code, "main")
        code_node = decompiler_task.syntax_tree.root
        assert isinstance(code_node, CodeNode)
        assert code_node.instructions == [Assignment(ListOperation([var("a")]), Call(ImportedFunctionSymbol("foo", 0), [var("a")]))]

    def test_types(self):
        code = r"""
            /* Test recognition of different parameter types. */ 
            int test1(char x, short y, int z, int *pointer) {
              int a = x;
              int b = y;
              return a + b + z + *pointer;
            }
        """
        decompiler_task = self.run_converter(code, "test1")
        ast = decompiler_task.syntax_tree
        assert ast is not None
        code_node = ast.root
        assert isinstance(code_node, CodeNode)
        assert code_node.instructions == [
            Assignment(var("a"), var("x", Integer.char())),
            Assignment(var("b"), var("y", Integer.int16_t())),
            Return(
                [
                    BinaryOperation(
                        OperationType.plus,
                        [
                            BinaryOperation(OperationType.plus, [BinaryOperation(OperationType.plus, [var("a"), var("b")]), var("z")]),
                            UnaryOperation(OperationType.dereference, [var("pointer", Pointer(Integer.int32_t()))]),
                        ],
                    )
                ]
            ),
        ]

    def test_code_node_grouping(self):
        code = r"""
            int main(int a, int b) {
                int c = a;
                a = b;
                b = c;
                if (a < b) {
                    printf("b is %d", b);
                    return b;
                }
                return a;
            }
        """
        decompiler_task = self.run_converter(code, "main")

        # check if an AST was generated
        ast = decompiler_task.syntax_tree
        assert ast is not None

        # child 0: code node
        code_node = ast.root.children[0]
        assert isinstance(code_node, CodeNode)
        assert code_node.instructions == [Assignment(var("c"), var("a")), Assignment(var("a"), var("b")), Assignment(var("b"), var("c"))]

        # child 1: condition node
        condition_node = ast.root.children[1]
        assert isinstance(condition_node, ConditionNode)
        assert ast.condition_map[condition_node.condition] == Condition(OperationType.less, [var("a"), var("b")])

        # child 1.1: code node
        code_node_1 = condition_node.true_branch_child
        assert isinstance(code_node_1, CodeNode)
        assert code_node_1.instructions == [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [const("b is %d", Pointer(Integer.char())), var("b")])),
            Return([var("b")]),
        ]

    def test_pointer(self):
        code = r"""
            int main() {
                int zahl = 7;
                int *zeiger;
                zeiger = &zahl;
                printf("Zeiger-Wert: %d\n", *zeiger);
            }
        """
        decompiler_task = self.run_converter(code, "main")

        ast = decompiler_task.syntax_tree
        assert ast is not None

        code_node = ast.root
        assert isinstance(code_node, CodeNode)

        assert code_node.instructions == [
            Assignment(var("zahl"), const(7)),
            Assignment(var("zeiger", Pointer(Integer.int32_t())), UnaryOperation(OperationType.address, [var("zahl")])),
            Assignment(
                ListOperation([]),
                Call(
                    ImportedFunctionSymbol("printf", 0),
                    [
                        const("Zeiger-Wert: %d\\n", Pointer(Integer.char())),
                        UnaryOperation(OperationType.dereference, [var("zeiger", Pointer(Integer.int32_t()))]),
                    ],
                ),
            ),
        ]

    def test_for_loop_1(self):
        code = r"""
            int main() {
                for (int i = 0; i < 10; i++) {
                    printf("i is %d\n", i);
                }
            }
        """
        decompiler_task = self.run_converter(code, "main")
        ast = decompiler_task.syntax_tree
        assert ast is not None

        loop_node = ast.root
        assert isinstance(loop_node, ForLoopNode)

        condition_map = ast.condition_map
        assert condition_map[loop_node.condition] == Condition(OperationType.less, [var("i"), const(10)])
        assert loop_node.declaration == Assignment(var("i"), const(0))
        assert loop_node.modification == Assignment(var("i"), BinaryOperation(OperationType.plus, [var("i"), const(1)]))

        code_node = loop_node.children[0]
        assert isinstance(code_node, CodeNode)
        assert code_node.instructions == [
            Assignment(
                ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [const("i is %d\\n", Pointer(Integer.char())), var("i")])
            ),
        ]

    def test_for_loop_with_break(self):
        code = r"""
            int main() {
                for (int i = 0; i < 10; i++) {
                    break;
                }
            }
        """
        decompiler_task = self.run_converter(code, "main")
        ast = decompiler_task.syntax_tree
        assert ast is not None

        loop_node = ast.root
        assert isinstance(loop_node, ForLoopNode)

        condition_map = ast.condition_map
        assert condition_map[loop_node.condition] == Condition(OperationType.less, [var("i"), const(10)])
        assert loop_node.declaration == Assignment(var("i"), const(0))
        assert loop_node.modification == Assignment(var("i"), BinaryOperation(OperationType.plus, [var("i"), const(1)]))

        code_node = loop_node.children[0]
        assert isinstance(code_node, CodeNode)
        assert code_node.instructions == [Break()]

    def test_for_loop_with_continue(self):
        code = r"""
            int main() {
                for (int i = 0; i < 10; i++) {
                    continue;
                }
            }
        """
        decompiler_task = self.run_converter(code, "main")
        ast = decompiler_task.syntax_tree
        assert ast is not None

        loop_node = ast.root
        assert isinstance(loop_node, ForLoopNode)

        condition_map = ast.condition_map
        assert condition_map[loop_node.condition] == Condition(OperationType.less, [var("i"), const(10)])
        assert loop_node.declaration == Assignment(var("i"), const(0))
        assert loop_node.modification == Assignment(var("i"), BinaryOperation(OperationType.plus, [var("i"), const(1)]))

        code_node = loop_node.children[0]
        assert isinstance(code_node, CodeNode)
        assert code_node.instructions == [Continue()]

    def test_while_loop(self):
        code = r"""
            int main() {
                int i = 0;
                while(i < 20) {
                    printf("current i is: %d\n", i);
                    i = i + 1;
                }
            }
        """
        decompiler_task = self.run_converter(code, "main")
        ast = decompiler_task.syntax_tree
        assert ast is not None

        seq_node = ast.root
        assert isinstance(seq_node, SeqNode)

        init_code_node = seq_node.children[0]
        assert isinstance(init_code_node, CodeNode)
        assert init_code_node.instructions == [Assignment(var("i"), const(0))]

        while_loop = seq_node.children[1]
        assert isinstance(while_loop, WhileLoopNode)
        assert ast.condition_map[while_loop.condition] == Condition(OperationType.less, [var("i"), const(20)])

        inner_code_node = while_loop.children[0]
        assert isinstance(inner_code_node, CodeNode)
        assert inner_code_node.instructions == [
            Assignment(
                ListOperation([]),
                Call(ImportedFunctionSymbol("printf", 0), [const("current i is: %d\\n", Pointer(Integer.char())), var("i")]),
            ),
            Assignment(var("i"), BinaryOperation(OperationType.plus, [var("i"), const(1)])),
        ]

    def test_switch_node(self):
        code = r"""
            int main(int var_1) {
                switch(var_1) {
                    case 0:
                        printf("var_1 is %d", 1);
                        break;
                }
            }
        """
        decompiler_task = self.run_converter(code, "main")
        ast = decompiler_task.syntax_tree
        assert ast is not None

        switch_node = ast.root
        assert isinstance(switch_node, SwitchNode)
        assert switch_node.expression == var("var_1")

        case_0_node = switch_node.cases[0]
        assert isinstance(case_0_node, CaseNode)
        assert case_0_node.constant == const(0)
        assert case_0_node.break_case is True

        case_0_code_node = case_0_node.child
        assert isinstance(case_0_code_node, CodeNode)
        assert case_0_code_node.instructions == [
            Assignment(
                ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [const("var_1 is %d", Pointer(Integer.char())), const(1)])
            )
        ]

    def test_switch_node_1(self):
        code = r"""
            int main(int var_1) {
                switch(var_1) {
                    case 0:
                        if (var_1 == 0) {
                            printf("var_1 is 0");
                        }
                        break;
                }
            }
        """
        decompiler_task = self.run_converter(code, "main")
        ast = decompiler_task.syntax_tree
        assert ast is not None

        switch_node = ast.root
        assert isinstance(switch_node, SwitchNode)
        assert switch_node.expression == var("var_1")

        case_node = switch_node.children[0]
        assert isinstance(case_node, CaseNode)
        assert case_node.expression == var("var_1")
        assert case_node.constant == const(0)
        assert case_node.break_case is True

        case_cond_node = case_node.child
        assert isinstance(case_cond_node, ConditionNode)
        assert ast.condition_map[case_cond_node.condition] == Condition(OperationType.equal, [var("var_1"), const(0)])

        cond_code_node = case_cond_node.true_branch_child
        assert isinstance(cond_code_node, CodeNode)
        assert cond_code_node.instructions == [
            Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [const("var_1 is 0", Pointer(Integer.char()))]))
        ]

    def test_switch_node_default(self):
        code = r"""
            int main(int var_1) {
                switch(var_1) {
                    case 0:
                        if (var_1 == 0) {
                            printf("a is grater: %d", var_1);
                        }
                        break;
                    default:
                        return 0;
                }
            }
        """
        decompiler_task = self.run_converter(code, "main")
        ast = decompiler_task.syntax_tree
        assert ast is not None

        switch_node = ast.root
        assert isinstance(switch_node, SwitchNode)
        assert switch_node.expression == var("var_1")

        case_0_node = switch_node.children[0]
        assert isinstance(case_0_node, CaseNode)
        assert case_0_node.constant == const(0)
        assert case_0_node.break_case is True

        default_node = switch_node.children[1]
        assert isinstance(default_node, CaseNode)
        assert default_node.constant == "default"

        default_code_node = default_node.child
        assert isinstance(default_code_node, CodeNode)
        assert default_code_node.instructions == [Return([const(0)])]

    # def test_arrays(self):
    #     code = r"""
    #     int main() {
    #         int numbers[10];
    #         numbers[2] = 1;
    #         return numbers[0];
    #     }
    #     """
    #     decompiler_task = self.run_converter(code, "main", debug=True)
    #     ast = decompiler_task.syntax_tree
    #     assert ast is not None
    #
    #     code_node = ast.root
    #     assert isinstance(code_node, CodeNode)

    # def test_arrays_2(self):
    #     code = r"""
    #     int *generate() {
    #         int numbers[10];
    #         numbers[2] = 1;
    #         return numbers[0];
    #     }
    #
    #     int main() {
    #         int *numbers = generate();
    #         for(int i = 0; i < 10; i++) {
    #             printf("Number is: %d\n", numbers[i]);
    #         }
    #
    #         return 0;
    #     }
    #     """
    #
    #     task = self.run_converter(code, "main", debug=True)
    #
    #     ast = task.syntax_tree
    #     assert ast is not None
    #
    #     seq_node = ast.root
    #     assert isinstance(seq_node, SeqNode)
    #
    #     code_node = seq_node.children[0]
    #     assert isinstance(code_node, CodeNode)

    def test_negate_vs_logical_not(self):
        code = r"""
            int main(int a) {
                if (!a) {
                    a = -a;
                }
            }
        """
        task = self.run_converter(code, "main")

        ast = task.syntax_tree
        assert ast is not None

        condition_node = ast.root
        assert isinstance(condition_node, ConditionNode)
        assert ast.condition_map.get(condition_node.condition) == UnaryOperation(OperationType.logical_not, [var("a")])

        code_node = condition_node.true_branch_child
        assert isinstance(code_node, CodeNode)
        assert code_node.instructions == [Assignment(var("a"), UnaryOperation(OperationType.negate, [var("a")]))]

    def test_input_output(self):
        input_code = """
            int main(int a, int b) {
                if (a == b) {
                    return 0;
                } else {
                    return 1;
                }
            }
        """

        decompiler_task = self.run_converter(input_code, "main")
        output_code = CodeGenerator().generate_function(decompiler_task)
        assert "".join(input_code.split()) == "".join(output_code.split())

    def test_imported_vs_function_symbol(self):
        code = r"""
            int getNum() {
                return 41;
            }

            int main() {
                printf("Number is: %d", getNum());
                return 0;
            }
        """

        decompiler_task = self.run_converter(code, "main")
        ast = decompiler_task.syntax_tree
        assert ast is not None

        code_node = ast.root
        assert isinstance(code_node, CodeNode)

        assert code_node.instructions == [
            Assignment(
                ListOperation([]),
                Call(
                    ImportedFunctionSymbol("printf", 0),
                    [
                        Constant("Number is: %d", Pointer(Integer.char())),
                        Assignment(ListOperation([]), Call(FunctionSymbol("getNum", 0), [])),
                    ],
                ),
            ),
            Return([Constant(0, Integer.int32_t())]),
        ]
