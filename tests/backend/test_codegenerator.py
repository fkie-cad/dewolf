import re
from typing import Dict, List, Optional

import decompiler.structures.pseudo.instructions as instructions
import decompiler.structures.pseudo.operations as operations
import pytest
from decompiler.backend.cexpressiongenerator import CExpressionGenerator
from decompiler.backend.codegenerator import CodeGenerator
from decompiler.backend.codevisitor import CodeVisitor
from decompiler.backend.variabledeclarations import GlobalDeclarationGenerator, LocalDeclarationGenerator
from decompiler.structures.ast.ast_nodes import CodeNode, SeqNode, SwitchNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import FunctionTypeDef
from decompiler.structures.pseudo.expressions import (
    Constant,
    DataflowObject,
    ExternConstant,
    ExternFunctionPointer,
    FunctionSymbol,
    GlobalVariable,
    ImportedFunctionSymbol,
    Variable,
)
from decompiler.structures.pseudo.instructions import Assignment, Comment, Return
from decompiler.structures.pseudo.operations import (
    ArrayInfo,
    BinaryOperation,
    Call,
    Condition,
    ListOperation,
    MemberAccess,
    OperationType,
    UnaryOperation,
)
from decompiler.structures.pseudo.typing import CustomType, Float, Integer, Pointer, Type
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

void = CustomType.void()
bool1 = CustomType.bool()
int8 = Integer.int8_t()
int32 = Integer.int32_t()
uint32 = Integer.uint32_t()
int64 = Integer.int64_t()
uint64 = Integer.uint64_t()
float32 = Float.float()


def x1_symbol(context=None):
    context = LogicCondition.generate_new_context() if context is None else context
    return LogicCondition.initialize_symbol("x1", context)


def x2_symbol(context=None):
    context = LogicCondition.generate_new_context() if context is None else context
    return LogicCondition.initialize_symbol("x2", context)


def true_condition(context=None):
    context = LogicCondition.generate_new_context() if context is None else context
    return LogicCondition.initialize_true(context)


def logic_cond(name: str, context) -> LogicCondition:
    return LogicCondition.initialize_symbol(name, context)


var_a = Variable("a", int32)
var_b = Variable("b", int32)
var_c = Variable("c", int32)
var_i = Variable("i", int32)
var_x = Variable("x", int32)
var_y = Variable("y", int32)
var_z = Variable("z", int32)
var_x_f = Variable("x_f", float32)
var_y_f = Variable("y_f", float32)
var_x_u = Variable("x_u", uint32)
var_y_u = Variable("y_u", uint32)
var_p = Variable("p", Pointer(int32))
var_fun_p = Variable("p", Pointer(FunctionTypeDef(0, int32, (int32,))))
var_fun_p0 = Variable("p0", Pointer(FunctionTypeDef(0, int32, (int32,))))

const_0 = Constant(0, int32)
const_1 = Constant(1, int32)
const_2 = Constant(2, int32)
const_3 = Constant(3, int32)
const_5 = Constant(5, int32)


def _generate_options(
    max_complx: int = 100,
    compounding: bool = True,
    increment_int: bool = True,
    increment_float: bool = True,
    byte_format: str = "char",
    byte_format_hint: str = "none",
    int_repr_scope: int = 256,
    twos_complement: bool = True,
    array_detection: bool = False,
    var_declarations_per_line: int = 1,
    preferred_true_branch: str = "smallest",
):
    options = Options()
    options.set("code-generator.max_complexity", max_complx)
    options.set("code-generator.use_compound_assignment", compounding)
    options.set("code-generator.use_increment_int", increment_int)
    options.set("code-generator.use_increment_float", increment_float)
    options.set("code-generator.byte_format", byte_format)
    options.set("code-generator.byte_format_hint", byte_format_hint)
    options.set("code-generator.int_representation_scope", int_repr_scope)
    options.set("code-generator.negative_hex_as_twos_complement", twos_complement)
    options.set("code-generator.aggressive_array_detection", array_detection)
    options.set("code-generator.variable_declarations_per_line", var_declarations_per_line)
    options.set("code-generator.preferred_true_branch", preferred_true_branch)
    return options


class TestCodeGeneration:
    @staticmethod
    def _task(ast: AbstractSyntaxTree, params: List[DataflowObject] = None, return_type: Type = int32, options: Optional[Options] = None):
        if not params:
            params = []
        if not options:
            options = _generate_options(compounding=False)
        return DecompilerTask(
            name="test_function",
            function_identifier="",
            ast=ast,
            options=options,
            function_parameters=params,
            function_return_type=return_type,
        )

    @staticmethod
    def _regex_matches(regex: str, task: DecompilerTask):
        source_code = CodeGenerator().generate([task]).replace("\n", "")
        return re.match(regex, re.sub(r"\s+", " ", source_code)) is not None

    def test_init(self):
        assert CodeGenerator()

    def test_function_with_comment(self):
        root = SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context()))

        ast = AbstractSyntaxTree(root, {})
        code_node = ast._add_code_node([Comment("test_comment", comment_style="debug")])
        ast._add_edge(root, code_node)
        assert self._regex_matches(r"^\s*void\s*test_function\(\s*\){\s*## test_comment ##\s*}\s*$", self._task(ast, return_type=void))

    def test_empty_function(self):
        root = SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context()))
        ast = AbstractSyntaxTree(root, {})
        code_node = ast._add_code_node([])
        ast._add_edge(root, code_node)
        assert self._regex_matches(r"^\s*void\s*test_function\(\s*\){\s*}\s*$", self._task(ast, return_type=void))

    def test_empty_function_one_parameter(self):
        root = SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context()))
        ast = AbstractSyntaxTree(root, {})
        code_node = ast._add_code_node([])
        ast._add_edge(root, code_node)
        assert self._regex_matches(r"^\s*int +test_function\(\s*int +a\s*\){\s*}\s*$", self._task(ast, params=[var_a.copy()]))

    def test_empty_function_two_parameters(self):
        root = SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context()))
        ast = AbstractSyntaxTree(root, {})
        code_node = ast._add_code_node([])
        ast._add_edge(root, code_node)
        assert self._regex_matches(
            r"^\s*int +test_function\(\s*int +a\s*,\s*int +b\s*\){\s*}\s*$", self._task(ast, params=[var_a.copy(), var_b.copy()])
        )

    def test_empty_function_two_function_parameters(self):
        root = SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context()))
        ast = AbstractSyntaxTree(root, {})
        code_node = ast._add_code_node([])
        ast._add_edge(root, code_node)
        assert self._regex_matches(
            r"^\s*int +test_function\(\s*int +\(\*\s*p\)\(int\)\s*,\s*int +\(\*\s*p0\)\(int\)\s*\){\s*}\s*$",
            self._task(ast, params=[var_fun_p.copy(), var_fun_p0.copy()]),
        )

    def test_function_with_instruction(self):
        root = SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context()))
        ast = AbstractSyntaxTree(root, {})
        code_node = ast._add_code_node([instructions.Return([const_1.copy()])])
        ast._add_edge(root, code_node)
        assert self._regex_matches(
            r"^\s*int +test_function\(\s*int +a\s*,\s*int +b\s*\){\s*return\s*1\s*;\s*}\s*$",
            self._task(ast, params=[var_a.copy(), var_b.copy()]),
        )

    def test_function_non_compoundable_operations_print_correctly(self):
        root = SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context()))
        ast = AbstractSyntaxTree(root, {})
        code_node = ast._add_code_node(
            [
                instructions.Assignment(
                    var_c.copy(), operations.BinaryOperation(operations.OperationType.right_rotate, [var_c.copy(), const_5.copy()])
                )
            ]
        )
        ast._add_edge(root, code_node)

        regex = r"^%int +test_function\(%int +a%,%int +b%\)%{%int%c;%c%=%\(%\(%c%>>%5%\)%\|%\(c%<<%\(%32%-%5%\)%\)%\)%;%}%$"
        assert self._regex_matches(regex.replace("%", "\\s*"), self._task(ast, params=[var_a.copy(), var_b.copy()]))

    def test_function_with_sequence(self):
        root = SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context()))
        ast = AbstractSyntaxTree(root, {})
        code_node = ast._add_code_node([instructions.Assignment(var_c.copy(), const_5.copy()), instructions.Return([var_c.copy()])])
        ast._add_edge(root, code_node)

        assert self._regex_matches(
            r"^%int +test_function\(%int +a%,%int +b%\){%int%c;%c%=%5%;%return%c%;%}%$".replace("%", "\\s*"),
            self._task(ast, params=[var_a.copy(), var_b.copy()]),
        )

    def test_function_with_only_if(self):
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(root, {x1_symbol(context): Condition(OperationType.less, [var_c.copy(), const_5.copy()])})
        seq_node = ast.factory.create_seq_node()
        ast._add_node(seq_node)
        code_node = ast._add_code_node([instructions.Assignment(var_c.copy(), const_5.copy()), instructions.Return([var_c.copy()])])
        condition_node = ast._add_condition_node_with(condition=x1_symbol(ast.factory.logic_context), true_branch=seq_node)
        ast._add_edges_from(((root, condition_node), (seq_node, code_node)))

        assert self._regex_matches(
            r"^%int +test_function\(%int +a%,%int +b%\)%{%int%c;%if%\(%c%<%5%\)%{%c%=%5%;%return%c%;%}%}%$".replace("%", "\\s*"),
            self._task(ast, params=[var_a.copy(), var_b.copy()]),
        )

    def test_function_with_true_condition(self):
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(root, {x1_symbol(context): Condition(OperationType.less, [var_c.copy(), const_5.copy()])})
        seq_node = ast.factory.create_seq_node()
        ast._add_node(seq_node)
        code_node = ast._add_code_node([instructions.Assignment(var_c.copy(), const_5.copy()), instructions.Return([var_c.copy()])])
        condition_node = ast._add_condition_node_with(condition=true_condition(ast.factory.logic_context), true_branch=seq_node)
        ast._add_edges_from(((root, condition_node), (seq_node, code_node)))
        assert self._regex_matches(
            r"^%int +test_function\(%int +a%,%int +b%\)%{%int%c;%if%\(%true%\)%{%c%=%5%;%return%c%;%}%}%$".replace("%", "\\s*"),
            self._task(ast, params=[var_a.copy(), var_b.copy()]),
        )

    def test_function_with_ifelse(self):
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(root, {x1_symbol(context): Condition(OperationType.less, [var_c.copy(), const_5.copy()])})
        true_seq_node = ast.factory.create_seq_node()
        ast._add_node(true_seq_node)
        code_node = ast._add_code_node([instructions.Assignment(var_c.copy(), const_5.copy()), instructions.Return([var_c.copy()])])
        false_code_node = ast._add_code_node([instructions.Return([const_0.copy()])])
        condition_node = ast._add_condition_node_with(
            condition=x1_symbol(ast.factory.logic_context), true_branch=true_seq_node, false_branch=false_code_node
        )
        ast._add_edges_from(((root, condition_node), (true_seq_node, code_node)))

        assert self._regex_matches(
            r"^%int +test_function\(%int +a%,%int +b%\)%{%int%c;%if%\(%c%<%5%\)%{%c%=%5%;%return%c%;%}%else%{%return%0%;%}%}%$".replace(
                "%", "\\s*"
            ),
            self._task(ast, params=[var_a.copy(), var_b.copy()], options=_generate_options(preferred_true_branch="none")),
        )

    def test_function_with_ifelseif(self):
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(
            root,
            {
                x1_symbol(context): Condition(OperationType.less, [var_a, const_3]),
                x2_symbol(context): Condition(OperationType.less, [var_a, const_5]),
            },
        )

        x2_true_node = ast._add_code_node([instructions.Return([const_1])])
        x2_false_node = ast._add_code_node([instructions.Return([const_2])])
        x1_true_node = ast._add_code_node([instructions.Return([const_0])])
        x1_false_node = ast._add_condition_node_with(
            condition=x2_symbol(ast.factory.logic_context), true_branch=x2_true_node, false_branch=x2_false_node
        )
        condition_node = ast._add_condition_node_with(
            condition=x1_symbol(ast.factory.logic_context), true_branch=x1_true_node, false_branch=x1_false_node
        )

        ast._add_edges_from([(root, condition_node)])

        assert self._regex_matches(
            r"^%int +test_function\(%int +a%,%int +b%\)%{%if%\(%a%<%3%\)%{%return%0%;%}%else +if%\(%a%<%5%\)%{%return%1%;%}%else%{%return%2%;%}%}%$".replace(
                "%", "\\s*"
            ),
            self._task(ast, params=[var_a.copy(), var_b.copy()]),
        )

    def test_function_with_ifelseif_prioritize_elseif_over_length(self):
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(
            root,
            {
                x1_symbol(context): Condition(OperationType.less, [var_a, const_3]),
                x2_symbol(context): Condition(OperationType.less, [var_a, const_5]),
            },
        )

        x2_true_node = ast._add_code_node([instructions.Return([const_1])])
        x2_false_node = ast._add_code_node([instructions.Return([const_2])])
        x1_true_node = ast._add_code_node([instructions.Return([const_0])])
        x1_false_node = ast._add_condition_node_with(
            condition=x2_symbol(ast.factory.logic_context), true_branch=x2_true_node, false_branch=x2_false_node
        )
        condition_node = ast._add_condition_node_with(
            condition=x1_symbol(ast.factory.logic_context), true_branch=x1_true_node, false_branch=x1_false_node
        )

        ast._add_edges_from([(root, condition_node)])

        assert self._regex_matches(
            r"^%int +test_function\(%int +a%,%int +b%\)%{%if%\(%a%<%3%\)%{%return%0%;%}%else +if%\(%a%<%5%\)%{%return%1%;%}%else%{%return%2%;%}%}%$".replace(
                "%", "\\s*"
            ),
            self._task(ast, params=[var_a.copy(), var_b.copy()], options=_generate_options(preferred_true_branch="largest")),
        )

    def test_function_with_ifelseif_swapped_because_elseif(self):
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(
            root,
            {
                x1_symbol(context): Condition(OperationType.greater_or_equal, [var_a, const_3]),
                x2_symbol(context): Condition(OperationType.less, [var_a, const_5]),
            },
        )

        x2_true_node = ast._add_code_node([instructions.Return([const_1])])
        x2_false_node = ast._add_code_node([instructions.Return([const_2])])
        x1_true_node = ast._add_condition_node_with(
            condition=x2_symbol(ast.factory.logic_context), true_branch=x2_true_node, false_branch=x2_false_node
        )
        x1_false_node = ast._add_code_node([instructions.Comment("Long comment to pad branch length..."), instructions.Return([const_0])])
        condition_node = ast._add_condition_node_with(
            condition=x1_symbol(ast.factory.logic_context), true_branch=x1_true_node, false_branch=x1_false_node
        )

        ast._add_edges_from([(root, condition_node)])

        assert self._regex_matches(
            r"^%int +test_function\(%int +a%,%int +b%\)%{%if%\(%a%<%3%\)%{%\/\*%Long comment to pad branch length...%\*\/%return%0%;%}%else +if%\(%a%<%5%\)%{%return%1%;%}%else%{%return%2%;%}%}%$".replace(
                "%", "\\s*"
            ),
            self._task(ast, params=[var_a.copy(), var_b.copy()]),
        )

    def test_function_with_ifelseif_swapped_because_length(self):
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(
            root,
            {x1_symbol(context): Condition(OperationType.greater_or_equal, [var_a, const_3])},
        )

        x1_true_node = ast._add_code_node([instructions.Comment("Long comment to pad branch length..."), instructions.Return([const_1])])
        x1_false_node = ast._add_code_node([instructions.Return([const_0])])
        condition_node = ast._add_condition_node_with(
            condition=x1_symbol(ast.factory.logic_context), true_branch=x1_true_node, false_branch=x1_false_node
        )

        ast._add_edges_from([(root, condition_node)])

        assert self._regex_matches(
            r"^%int +test_function\(%int +a%,%int +b%\)%{%if%\(%a%<%3%\)%{%return%0%;%}%else%{%\/\*%Long comment to pad branch length...%\*\/%return%1%;%}%}%$".replace(
                "%", "\\s*"
            ),
            self._task(ast, params=[var_a.copy(), var_b.copy()]),
        )

    def test_function_with_switch(self):
        root_switch_node = SwitchNode(
            expression=var_a.copy(), reaching_condition=LogicCondition.initialize_true(LogicCondition.generate_new_context())
        )
        ast = AbstractSyntaxTree(root_switch_node, {})
        case_1 = ast.factory.create_case_node(expression=var_a.copy(), constant=const_1.copy())
        case_child_1 = ast._add_code_node([instructions.Assignment(var_c.copy(), const_5.copy()), instructions.Return([var_c.copy()])])
        case_2 = ast.factory.create_case_node(expression=var_a.copy(), constant=const_2.copy())
        case_child_2 = ast._add_code_node([instructions.Return([var_b.copy()])])
        ast._add_nodes_from((case_1, case_2))
        ast._add_edges_from(((root_switch_node, case_1), (root_switch_node, case_2), (case_1, case_child_1), (case_2, case_child_2)))
        ast._code_node_reachability_graph.add_reachability(case_child_1, case_child_2)
        root_switch_node._sorted_cases = (case_1, case_2)

        regex = r"^%int +test_function\(%int +a%,%int +b%\)%{%int%c;%switch%\(%a%\)%{%case%1%:%c%=%5%;%return%c%;%case%2%:%return%b%;%}%}%$"
        assert self._regex_matches(regex.replace("%", "\\s*"), self._task(ast, params=[var_a.copy(), var_b.copy()]))

    def test_function_with_switch_default(self):
        root_switch_node = SwitchNode(
            expression=var_a.copy(), reaching_condition=LogicCondition.initialize_true(LogicCondition.generate_new_context())
        )
        ast = AbstractSyntaxTree(root_switch_node, {})
        case_1 = ast.factory.create_case_node(expression=var_a.copy(), constant=const_0.copy())
        case_child_1 = ast._add_code_node([instructions.Assignment(var_c.copy(), const_5.copy()), instructions.Return([var_c.copy()])])
        case_2 = ast.factory.create_case_node(expression=var_a.copy(), constant=const_1.copy())
        case_child_2 = ast._add_code_node([instructions.Return([var_b.copy()])])
        default_case = ast.factory.create_case_node(expression=var_a.copy(), constant="default")
        default_child = ast._add_code_node([instructions.Return([const_5.copy()])])
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

        regex = (
            r"^%int +test_function\(%int +a%,%int +b%\)%"
            r"{%int%c;%switch%\(%a%\)%{%case%0%:%c%=%5%;%return%c%;%case%1%:%return%b%;%default%:%return%5%;%}%}%$"
        )
        assert self._regex_matches(regex.replace("%", "\\s*"), self._task(ast, params=[var_a.copy(), var_b.copy()]))

    def test_function_with_endless_loop(self):
        root = SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context()))
        ast = AbstractSyntaxTree(root, {})
        child_1 = ast._add_code_node([instructions.Assignment(var_c.copy(), const_5.copy())])
        loop_body = ast._add_code_node(
            [
                instructions.Assignment(
                    var_c.copy(), operations.BinaryOperation(operations.OperationType.plus, [var_c.copy(), const_5.copy()])
                )
            ]
        )
        child_2 = ast.add_endless_loop_with_body(loop_body)
        ast._add_edges_from(((root, child_1), (root, child_2)))
        ast._code_node_reachability_graph.add_reachability(child_1, loop_body)

        assert self._regex_matches(
            r"^%void +test_function\(%int +a%,%int +b%\)%{%int%c;%c%=%5%;%while%\(%true%\)%{%c%=%c%\+%5%;%}%}%$".replace("%", "\\s*"),
            self._task(ast, params=[var_a.copy(), var_b.copy()], return_type=void),
        )

    def test_function_with_while_condition_loop(self):
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(root, {x1_symbol(context): Condition(OperationType.equal, [var_x.copy(), const_5.copy()])})
        child_1 = ast._add_code_node([instructions.Assignment(var_c.copy(), const_5.copy())])
        child_2 = ast.factory.create_while_loop_node(condition=x1_symbol(ast.factory.logic_context))
        body = ast._add_code_node(
            [
                instructions.Assignment(
                    var_c.copy(), operations.BinaryOperation(operations.OperationType.plus, [var_c.copy(), const_5.copy()])
                )
            ]
        )
        ast._add_nodes_from((child_2, body))
        ast._add_edges_from(((root, child_1), (root, child_2), (child_2, body)))
        ast._code_node_reachability_graph.add_reachability(child_1, body)

        regex = r"^%void +test_function\(%int +a%,%int +b%\)%{%int%c;%int%x;%c%=%5%;%while%\(%x%==%5%\)%{%c%=%c%\+%5%;%}%}%$"
        assert self._regex_matches(regex.replace("%", "\\s*"), self._task(ast, params=[var_a.copy(), var_b.copy()], return_type=void))

    def test_function_with_do_while_condition_loop(self):
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(root, {x1_symbol(context): Condition(OperationType.equal, [var_x.copy(), const_5.copy()])})
        child_1 = ast._add_code_node([instructions.Assignment(var_c.copy(), const_5.copy())])
        child_2 = ast.factory.create_do_while_loop_node(condition=x1_symbol(ast.factory.logic_context))
        body = ast._add_code_node(
            [instructions.Assignment(var_c.copy(), BinaryOperation(OperationType.plus, [var_c.copy(), const_5.copy()]))]
        )
        ast._add_nodes_from((child_2, body))
        ast._add_edges_from(((root, child_1), (root, child_2), (child_2, body)))
        ast._code_node_reachability_graph.add_reachability(child_1, body)

        assert self._regex_matches(
            r"^%void +test_function\(%int +a%,%int +b%\)%{%int%c;%int%x;%c%=%5%;%do%{%c%=%c%\+%5%;%}%while%\(%x%==%5%\);%}%$".replace(
                "%", "\\s*"
            ),
            self._task(ast, params=[var_a.copy(), var_b.copy()], return_type=void),
        )

    def test_function_with_for_loop(self):
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(root, {x1_symbol(context): Condition(OperationType.less_or_equal, [var_i.copy(), const_5.copy()])})
        child_1 = ast._add_code_node([instructions.Assignment(var_c.copy(), const_5.copy())])
        child_2 = ast.factory.create_for_loop_node(
            declaration=instructions.Assignment(var_i.copy(), const_0.copy()),
            modification=instructions.Assignment(
                var_i.copy(), operations.BinaryOperation(operations.OperationType.plus, [var_i.copy(), const_1.copy()])
            ),
            condition=x1_symbol(ast.factory.logic_context),
        )
        body = ast._add_code_node(
            [instructions.Assignment(var_c.copy(), operations.BinaryOperation(operations.OperationType.plus, [var_c.copy(), var_i.copy()]))]
        )
        ast._add_nodes_from((child_2, body))
        ast._add_edges_from(((root, child_1), (root, child_2), (child_2, body)))
        ast._code_node_reachability_graph.add_reachability(child_1, body)

        regex = (
            r"^%void +test_function\(%int +a%,%int +b%\)%{%int%c;%int%i;%c%=%5%;"
            r"%for%\(%i%=%0%;%i%<=%5%;%i%=%i%\+%1%\)%{%c%=%c%\+%i%;%}%}%$"
        )
        assert self._regex_matches(regex.replace("%", "\\s*"), self._task(ast, params=[var_a.copy(), var_b.copy()], return_type=void))

    def test_function_nested_loop(self):
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(
            root, {x1_symbol(context): operations.Condition(operations.OperationType.equal, [var_x.copy(), const_5.copy()])}
        )
        child_1 = ast._add_code_node([instructions.Assignment(var_c.copy(), const_5.copy())])
        nested_loop_body = ast._add_code_node(
            [
                instructions.Assignment(
                    var_c.copy(), operations.BinaryOperation(operations.OperationType.plus, [var_c.copy(), const_5.copy()])
                )
            ]
        )
        nested_loop = ast.factory.create_while_loop_node(condition=~x1_symbol(ast.factory.logic_context))
        ast._add_node(nested_loop)
        child_2 = ast.add_endless_loop_with_body(nested_loop)
        ast._add_edges_from(((root, child_1), (root, child_2), (nested_loop, nested_loop_body)))
        ast._code_node_reachability_graph.add_reachability(child_1, nested_loop_body)

        regex = (
            r"^%void +test_function\(%int +a%,%int +b%\)%{%int%c;%int%x;%c%=%5%;%"
            r"while%\(%true%\)%{%while%\(%x%!=%5%\)%{%c%=%c%\+%5%;%}%}%}%$"
        )
        assert self._regex_matches(regex.replace("%", r"\s*"), self._task(ast, params=[var_a.copy(), var_b.copy()], return_type=void))

    def test_varvisitor_condition_as_var(self):
        context = LogicCondition.generate_new_context()
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(root, {x1_symbol(context): var_c.copy()})
        true_branch = ast._add_code_node([instructions.Return([var_c.copy()])])
        condition_node = ast._add_condition_node_with(condition=x1_symbol(ast.factory.logic_context), true_branch=true_branch)
        ast._add_edge(root, condition_node)

        assert self._regex_matches(
            r"^%bool +test_function\(%\)%{%int%c;%if%\(%c%\)%{return%c%;%}%}%$".replace("%", "\\s*"), self._task(ast, return_type=bool1)
        )

    @pytest.mark.parametrize(
        "context, condition, condition_map, expected",
        [
            (context := LogicCondition.generate_new_context(), x1_symbol(context), {x1_symbol(context): Variable("v", bool1)}, r"v"),
            (
                context := LogicCondition.generate_new_context(),
                x1_symbol(context) | x2_symbol(context),
                {
                    x1_symbol(context): Condition(OperationType.equal, [var_x.copy(), const_5.copy()]),
                    x2_symbol(context): Condition(OperationType.equal, [var_y.copy(), const_3.copy()]),
                },
                r"\(%x%==%5%\)%||%\(%y%==%3%\)",
            ),
            (
                context := LogicCondition.generate_new_context(),
                x1_symbol(context) & x2_symbol(context),
                {
                    x1_symbol(context): Condition(OperationType.equal, [var_x.copy(), const_5.copy()]),
                    x2_symbol(context): Condition(OperationType.equal, [var_y.copy(), const_3.copy()]),
                },
                r"\(%x%==%5%\)%&&%\(%y%==%3%\)",
            ),
            (
                context := LogicCondition.generate_new_context(),
                ~x1_symbol(context),
                {x1_symbol(context): Condition(OperationType.equal, [var_x.copy(), const_5.copy()])},
                r"%x%!=%5%",
            ),
            (context := LogicCondition.generate_new_context(), ~x1_symbol(context), {x1_symbol(context): Variable("v", bool1)}, r"!\(v\)"),
        ],
    )
    def test_branch_condition(self, context, condition: LogicCondition, condition_map: Dict[LogicCondition, Condition], expected: str):
        root = SeqNode(LogicCondition.initialize_true(context))
        ast = AbstractSyntaxTree(root, condition_map)
        true_node = ast._add_code_node([Return([const_0.copy()])])
        condition_node = ast._add_condition_node_with(condition, true_node)
        ast._add_edge(root, condition_node)
        root.sort_children()

        regex = r"^%int +test_function\(\)%{(?s).*if%\(%COND_STR%\)%{%return%0%;%}%}%$"
        assert self._regex_matches(regex.replace("COND_STR", expected).replace("%", "\\s*"), self._task(ast))

    def test_loop_declaration_ListOp(self):
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
        source_code = CodeGenerator().generate([self._task(ast)]).replace("\n", "")
        assert source_code.find("for (b = foo();") != -1


class TestExpression:
    @staticmethod
    def _visit_code(dfo: DataflowObject, options: Options = _generate_options()) -> str:
        return CodeVisitor(DecompilerTask(name="test", function_identifier="", options=options)).visit(dfo)

    @pytest.mark.parametrize(
        "expr, result",
        [
            (BinaryOperation(OperationType.plus, (var_x.copy(), var_y.copy())), "x + y"),
            (BinaryOperation(OperationType.minus, (var_x.copy(), var_y.copy())), "x - y"),
            (BinaryOperation(OperationType.multiply, (var_x.copy(), var_y.copy())), "x * y"),
            (BinaryOperation(OperationType.divide, (var_x.copy(), var_y.copy())), "x / y"),
            (BinaryOperation(OperationType.divide_us, (var_x_u.copy(), var_y_u.copy())), "x_u / y_u"),
            (BinaryOperation(OperationType.modulo, (var_x.copy(), var_y.copy())), "x % y"),
            (BinaryOperation(OperationType.modulo_us, (var_x_u.copy(), var_y_u.copy())), "x_u % y_u"),
        ],
    )
    def test_binop_arithmetic(self, expr, result):
        """Test binary operations that are arithmetic are generated correctly."""
        expr_print = CExpressionGenerator()
        assert expr_print.visit(expr) == result

    @pytest.mark.parametrize(
        "expr, result",
        [
            (BinaryOperation(OperationType.less, (var_x.copy(), var_y.copy())), "x < y"),
            (BinaryOperation(OperationType.less_us, (var_x_u.copy(), var_y_u.copy())), "x_u < y_u"),
            (BinaryOperation(OperationType.greater, (var_x.copy(), var_y.copy())), "x > y"),
            (BinaryOperation(OperationType.greater_us, (var_x_u.copy(), var_y_u.copy())), "x_u > y_u"),
            (BinaryOperation(OperationType.less_or_equal, (var_x.copy(), var_y.copy())), "x <= y"),
            (BinaryOperation(OperationType.less_or_equal_us, (var_x_u.copy(), var_y_u.copy())), "x_u <= y_u"),
            (BinaryOperation(OperationType.greater_or_equal, (var_x.copy(), var_y.copy())), "x >= y"),
            (BinaryOperation(OperationType.greater_or_equal_us, (var_x_u.copy(), var_y_u.copy())), "x_u >= y_u"),
            (BinaryOperation(OperationType.equal, (var_x.copy(), var_y.copy())), "x == y"),
            (BinaryOperation(OperationType.not_equal, (var_x_u.copy(), var_y_u.copy())), "x_u != y_u"),
        ],
    )
    def test_binop_comparison(self, expr, result):
        """Test binary operations that are comparisons are generated correctly."""
        expr_print = CExpressionGenerator()
        assert expr_print.visit(expr) == result

    @pytest.mark.parametrize(
        "expr, result",
        [
            (BinaryOperation(OperationType.bitwise_or, (var_x, var_y)), "x | y"),
            (BinaryOperation(OperationType.bitwise_and, (var_x, var_y)), "x & y"),
            (BinaryOperation(OperationType.bitwise_xor, (var_x, var_y)), "x ^ y"),
        ],
    )
    def test_binop_logical(self, expr, result):
        """Test binary operations that are logical operations are generated correctly."""
        expr_print = CExpressionGenerator()
        assert expr_print.visit(expr) == result

    @pytest.mark.parametrize(
        "expr, result",
        [
            (UnaryOperation(OperationType.negate, (var_x,)), "-x"),
            (UnaryOperation(OperationType.logical_not, (var_x,)), "!x"),
            (UnaryOperation(OperationType.dereference, (var_p,)), "*p"),
            (UnaryOperation(OperationType.address, (var_x,)), "&x"),
        ],
    )
    def test_unaryop(self, expr, result):
        """Test unary operations are generated correctly."""
        expr_print = CExpressionGenerator()
        assert expr_print.visit(expr) == result

    @pytest.mark.parametrize(
        "input_expr, expected",
        [
            (UnaryOperation(OperationType.cast, [var_x_u.copy()], vartype=int32), "(int)x_u"),
            (UnaryOperation(OperationType.cast, [var_x.copy()], vartype=int32), "x"),
            (UnaryOperation(OperationType.cast, [const_1.copy()], vartype=int32), "1"),
            (UnaryOperation(OperationType.cast, [Constant(1, uint32)], vartype=int32), "1"),
            (UnaryOperation(OperationType.cast, [Constant(1, int64)], vartype=int32), "1"),
            (UnaryOperation(OperationType.cast, [const_1.copy()], vartype=uint32), "1U"),
            (UnaryOperation(OperationType.cast, [const_1.copy()], vartype=int64), "1L"),
            (UnaryOperation(OperationType.cast, [const_1.copy()], vartype=uint64), "1UL"),
            (UnaryOperation(OperationType.cast, [Constant(-1, int32)], vartype=uint32), "(unsigned int)-1"),
        ],
    )
    def test_unaryop_cast_simplify(self, input_expr, expected):
        """Test that operations are simplified. Assume that multiple-casts have been simplified due to cast simplification."""
        expr_print = CExpressionGenerator()
        assert expr_print.visit(input_expr) == expected

    @pytest.mark.parametrize(
        "operation, result",
        [
            (
                UnaryOperation(
                    OperationType.dereference,
                    [
                        BinaryOperation(
                            OperationType.plus,
                            [
                                var_b := Variable("b", vartype=Pointer(Integer.int32_t()), ssa_name=(b0 := Variable("b", ssa_label=0))),
                                Constant(12),
                            ],
                        )
                    ],
                    array_info=ArrayInfo(b0, 3, True),
                ),
                "b[3]",
            ),
            (
                UnaryOperation(
                    OperationType.dereference,
                    [
                        BinaryOperation(
                            OperationType.plus,
                            [
                                Variable("b", vartype=Pointer(Integer.int32_t()), ssa_name=(b0 := Variable("b", ssa_label=0))),
                                Constant(12),
                            ],
                        )
                    ],
                    array_info=ArrayInfo(b0, 3, False),
                ),
                "*(b + 0xc)/*b[3]*/",
            ),
            (
                UnaryOperation(
                    OperationType.dereference,
                    [
                        BinaryOperation(
                            OperationType.plus,
                            [
                                d := Variable("d", vartype=Pointer(int32), ssa_name=(d0 := Variable("d", ssa_label=0))),
                                BinaryOperation(
                                    OperationType.multiply,
                                    [i := Variable("i", int32, ssa_name=(var0 := Variable("var", ssa_label=0))), Constant(4)],
                                ),
                            ],
                        )
                    ],
                    array_info=ArrayInfo(d, i, True),
                ),
                "d[i]",
            ),
            (
                UnaryOperation(
                    OperationType.dereference,
                    [
                        BinaryOperation(
                            OperationType.plus,
                            [
                                d := Variable("d", vartype=Pointer(int32), ssa_name=(d0 := Variable("d", ssa_label=0))),
                                BinaryOperation(
                                    OperationType.multiply,
                                    [i := Variable("i", int32, ssa_name=(var0 := Variable("var", ssa_label=0))), Constant(4)],
                                ),
                            ],
                        )
                    ],
                    array_info=ArrayInfo(d, i, False),
                ),
                "*(d + i * 0x4)/*d[i]*/",
            ),
        ],
    )
    def test_array_element_access_default(self, operation, result):
        assert self._visit_code(operation, _generate_options(array_detection=False)) == result

    @pytest.mark.parametrize(
        "operation, result",
        [
            (
                UnaryOperation(
                    OperationType.dereference,
                    [
                        BinaryOperation(
                            OperationType.plus,
                            [
                                Variable("b", vartype=Pointer(Integer.int32_t()), ssa_name=(b0 := Variable("b", ssa_label=0))),
                                Constant(12),
                            ],
                        )
                    ],
                    array_info=ArrayInfo(b0, 3, False),
                ),
                "b[3]",
            ),
            (
                UnaryOperation(
                    OperationType.dereference,
                    [
                        BinaryOperation(
                            OperationType.plus,
                            [
                                d := Variable("d", vartype=Pointer(int32), ssa_name=(d0 := Variable("d", ssa_label=0))),
                                BinaryOperation(
                                    OperationType.multiply,
                                    [i := Variable("i", int32, ssa_name=(var0 := Variable("var", ssa_label=0))), Constant(4)],
                                ),
                            ],
                        )
                    ],
                    array_info=ArrayInfo(d, i, False),
                ),
                "d[i]",
            ),
        ],
    )
    def test_array_element_access_aggressive(self, operation, result):
        assert self._visit_code(operation, _generate_options(array_detection=True)) == result

    @pytest.mark.parametrize(
        "operation, result",
        [
            (
                MemberAccess(operands=[Variable("a", Integer.int32_t())], member_name="x", offset=0, vartype=Integer.int32_t()),
                "a.x",
            ),
            (
                MemberAccess(
                    operands=[
                        MemberAccess(operands=[Variable("a", Integer.int32_t())], member_name="x", offset=0, vartype=Integer.int32_t())
                    ],
                    member_name="z",
                    offset=0,
                    vartype=Integer.int32_t(),
                ),
                "a.x.z",
            ),
            (
                MemberAccess(operands=[Variable("ptr", Pointer(Integer.int32_t()))], member_name="x", offset=0, vartype=Integer.int32_t()),
                "ptr->x",
            ),
            (
                MemberAccess(
                    operands=[
                        MemberAccess(
                            operands=[Variable("ptr", Pointer(Integer.int32_t()))], member_name="x", offset=0, vartype=Integer.int32_t()
                        )
                    ],
                    member_name="z",
                    offset=0,
                    vartype=Pointer(Integer.int32_t()),
                ),
                "ptr->x.z",
            ),
            (
                MemberAccess(
                    operands=[
                        MemberAccess(
                            operands=[Variable("ptr", Pointer(Integer.int32_t()))],
                            member_name="x",
                            offset=0,
                            vartype=Pointer(Integer.int32_t()),
                        )
                    ],
                    member_name="z",
                    offset=0,
                    vartype=Pointer(Pointer(Integer.int32_t())),
                ),
                "ptr->x->z",
            ),
            (
                MemberAccess(
                    operands=[
                        MemberAccess(
                            operands=[
                                MemberAccess(
                                    operands=[Variable("ptr", Pointer(Integer.int32_t()))],
                                    member_name="x",
                                    offset=0,
                                    vartype=Pointer(Integer.int32_t()),
                                )
                            ],
                            member_name="z",
                            offset=0,
                            vartype=Pointer(Pointer(Integer.int32_t())),
                        )
                    ],
                    member_name="w",
                    offset=8,
                    vartype=Pointer(Pointer(Pointer(Integer.int32_t()))),
                ),
                "ptr->x->z->w",
            ),
            (
                MemberAccess(
                    offset=0,
                    member_name="x",
                    operands=[
                        BinaryOperation(
                            OperationType.plus,
                            [Variable("ptr", Pointer(Integer.int32_t())), Constant(1, Integer.int32_t())],
                            Pointer(Integer.int32_t()),
                        )
                    ],
                    vartype=Integer.int32_t(),
                ),
                "(ptr + 1)->x",
            ),
        ],
    )
    def test_member_access(self, operation, result):
        assert self._visit_code(operation) == result

    @pytest.mark.parametrize(
        "expr, result",
        [
            (Assignment(ListOperation([]), Call(FunctionSymbol("foo", 0), [])), "foo()"),
            (Assignment(ListOperation([]), Call(FunctionSymbol("foo", 0), [var_x.copy()])), "foo(x)"),
            (
                Assignment(
                    ListOperation([]),
                    Call(FunctionSymbol("foo", 0), [var_x.copy(), BinaryOperation(OperationType.plus, (var_x.copy(), var_y.copy()))]),
                ),
                "foo(x, x + y)",
            ),
            (
                Assignment(ListOperation([]), Call(FunctionSymbol("foo", 0), [var_x.copy()], meta_data={"param_names": ["param1"]})),
                "foo(/* param1 */ x)",
            ),
            (
                Assignment(
                    ListOperation([]),
                    Call(
                        FunctionSymbol("foo", 0),
                        [var_x.copy(), var_y.copy(), var_z.copy()],
                        meta_data={"param_names": ["param1", "param2"]},
                    ),
                ),
                "foo(/* param1 */ x, /* param2 */ y, z)",
            ),
            (Assignment(ListOperation([]), Call(UnaryOperation(OperationType.dereference, [var_x]), [])), "(*x)()"),
        ],
    )
    def test_call(self, expr, result):
        """Test function calls are generated correctly."""
        expr_print = CExpressionGenerator()
        assert expr_print.visit(expr) == result

    @pytest.mark.parametrize(
        "expr, byte_format, byte_format_hint, result",
        [
            (Constant(65, Integer.int8_t()), "char", "char", "'A' /*'A'*/"),
            (Constant(65, Integer.int8_t()), "char", "hex", "'A' /*0x41*/"),
            (Constant(65, Integer.int8_t()), "char", "dec", "'A' /*65*/"),
            (Constant(65, Integer.int8_t()), "char", "false", "'A'"),
            (Constant(65, Integer.int8_t()), "hex", "char", "0x41 /*'A'*/"),
            (Constant(65, Integer.int8_t()), "hex", "hex", "0x41 /*0x41*/"),
            (Constant(65, Integer.int8_t()), "hex", "dec", "0x41 /*65*/"),
            (Constant(65, Integer.int8_t()), "hex", "false", "0x41"),
            (Constant(65, Integer.int8_t()), "dec", "char", "65 /*'A'*/"),
            (Constant(65, Integer.int8_t()), "dec", "hex", "65 /*0x41*/"),
            (Constant(65, Integer.int8_t()), "dec", "dec", "65 /*65*/"),
            (Constant(65, Integer.int8_t()), "dec", "false", "65"),
            (Constant(65, Integer.uint8_t()), "char", "char", "'A' /*'A'*/"),
            (Constant(65, Integer.uint8_t()), "char", "hex", "'A' /*0x41*/"),
            (Constant(65, Integer.uint8_t()), "char", "dec", "'A' /*65*/"),
            (Constant(65, Integer.uint8_t()), "char", "false", "'A'"),
            (Constant(65, Integer.uint8_t()), "hex", "char", "0x41 /*'A'*/"),
            (Constant(65, Integer.uint8_t()), "hex", "hex", "0x41 /*0x41*/"),
            (Constant(65, Integer.uint8_t()), "hex", "dec", "0x41 /*65*/"),
            (Constant(65, Integer.uint8_t()), "hex", "false", "0x41"),
            (Constant(65, Integer.uint8_t()), "dec", "char", "65 /*'A'*/"),
            (Constant(65, Integer.uint8_t()), "dec", "hex", "65 /*0x41*/"),
            (Constant(65, Integer.uint8_t()), "dec", "dec", "65 /*65*/"),
            (Constant(65, Integer.uint8_t()), "dec", "false", "65"),
            (Constant(100, Integer.int32_t()), "char", "char", "100"),
            (Constant(100, Integer.uint32_t()), "char", "char", "100U"),
            (Constant(0xFFFFFFFF, Integer.int32_t()), "char", "char", "-1"),
            (Constant(0xFFFFFFFF, Integer.int32_t()), "hex", "hex", "-1"),
            (Constant(0x8000000000000000, Integer.int64_t()), "char", "false", "0x8000000000000000"),
            (Constant(0x8000000000000000, Integer.int64_t()), "hex", "false", "0x8000000000000000"),
            (Constant(0x8000000000000000, Integer.int64_t()), "dec", "false", "0x8000000000000000"),
            (Constant(0x80000000, Integer.int32_t()), "char", "false", "0x80000000"),
            (Constant(0x80000000, Integer.int32_t()), "hex", "false", "0x80000000"),
            (Constant(0x80000000, Integer.int32_t()), "dec", "false", "0x80000000"),
            (Constant(60, Integer.int32_t()), "char", "dec", "60"),
            (Constant(60, Integer.char()), "char", "dec", "'<' /*60*/"),
            (Constant(0xFFFFFFFF, Integer.uint32_t()), "", "", "0xffffffff"),
            (Constant(24, Integer.int32_t()), "", "", "24"),
            (Constant(24, Integer.uint32_t()), "", "", "24U"),
            (Constant(0x7FFFFFFFFFFFFFFF, Integer.uint64_t()), "", "", "0x7fffffffffffffff"),
            (Constant(-1, Integer.int32_t()), "", "", "-1"),
            (Constant(1, Integer.uint32_t()), "", "", "1U"),
            (Constant(1, Integer.int64_t()), "", "", "1L"),
            (Constant(1, Integer.uint64_t()), "", "", "1UL"),
            (Constant(0x0, Pointer(Integer.int32_t())), "", "", "0x0"),
            (Constant(0xFFFF1234, Pointer(Integer.int32_t())), "", "", "0xffff1234"),
            (Constant(-1, Integer.uint32_t()), "", "", "0xffffffff"),
            (Constant(-24, Integer.uint64_t()), "", "", "0xffffffffffffffe8"),
        ],
    )
    def test_byte_format(self, expr, byte_format, byte_format_hint, result):
        assert (
            self._visit_code(expr, _generate_options(byte_format=byte_format, byte_format_hint=byte_format_hint, int_repr_scope=256))
            == result
        )

    def test_unary_bracketing(self):
        """Test child of unary operation is bracketed properly when it is compound"""
        expr_print = CExpressionGenerator()
        assert (
            expr_print.visit(
                UnaryOperation(
                    OperationType.dereference,
                    [
                        BinaryOperation(
                            OperationType.plus,
                            [Variable("x", Pointer(Integer.int32_t())), Variable("y", Integer.int32_t())],
                            Pointer(Integer.int32_t()),
                        )
                    ],
                    Integer.int32_t(),
                )
            )
            == "*(x + y)"
        )

    def test_binary_bracketing(self):
        """Test children of binary operation is bracketed properly when it is compound"""
        expr_print = CExpressionGenerator()
        assert (
            expr_print.visit(
                BinaryOperation(
                    OperationType.multiply,
                    [
                        BinaryOperation(
                            OperationType.plus, [Variable("x", Integer.int32_t()), Variable("y", Integer.int32_t())], Integer.int32_t()
                        ),
                        BinaryOperation(
                            OperationType.right_shift,
                            [Variable("x", Integer.int32_t()), Variable("y", Integer.int32_t())],
                            Integer.int32_t(),
                        ),
                    ],
                    Integer.int32_t(),
                )
            )
            == "(x + y) * (x >> y)"
        )

    def test_return_instruction(self):
        """Test return instruction is generated properly"""
        expr_print = CExpressionGenerator()
        assert (
            expr_print.visit(
                Return(
                    [
                        BinaryOperation(
                            OperationType.plus, [Variable("x", Integer.int32_t()), Variable("y", Integer.int32_t())], Integer.int32_t()
                        )
                    ]
                )
            )
            == "return x + y"
        )

    def test_assignment_instruction(self):
        """Test assignment instruction is generated properly"""
        expr_print = CExpressionGenerator()
        assert (
            expr_print.visit(
                Assignment(
                    Variable("x", Integer.int32_t()),
                    BinaryOperation(
                        OperationType.plus, [Variable("x", Integer.int32_t()), Variable("y", Integer.int32_t())], Integer.int32_t()
                    ),
                )
            )
            == "x = x + y"
        )

    @pytest.mark.parametrize(
        "expr, result",
        [
            (
                Assignment(var_x_f.copy().copy(), BinaryOperation(OperationType.plus, [var_x_f.copy().copy(), var_y_f.copy().copy()])),
                "x_f += y_f",
            ),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.minus, [var_x_f.copy(), var_y_f.copy()])), "x_f -= y_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.multiply, [var_x_f.copy(), var_y_f.copy()])), "x_f *= y_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.divide, [var_x_f.copy(), var_y_f.copy()])), "x_f /= y_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.modulo, [var_x_f.copy(), var_y_f.copy()])), "x_f %= y_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.plus, [var_x_f.copy(), Constant(2.0, float32)])), "x_f += 2.0"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.plus, [var_x_f.copy(), Constant(-2.0, float32)])), "x_f += -2.0"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.minus, [var_x_f.copy(), Constant(2.0, float32)])), "x_f -= 2.0"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.minus, [var_x_f.copy(), Constant(-2.0, float32)])), "x_f -= -2.0"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.left_shift, [var_x_f.copy(), var_y_f.copy()])), "x_f <<= y_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.right_shift, [var_x_f.copy(), var_y_f.copy()])), "x_f >>= y_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.bitwise_and, [var_x_f.copy(), var_y_f.copy()])), "x_f &= y_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.bitwise_or, [var_x_f.copy(), var_y_f.copy()])), "x_f |= y_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.bitwise_xor, [var_x_f.copy(), var_y_f.copy()])), "x_f ^= y_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.plus, [var_y_f.copy(), var_x_f.copy()])), "x_f += y_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.minus, [var_y_f.copy(), var_x_f.copy()])), "x_f = y_f - x_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.multiply, [var_y_f.copy(), var_x_f.copy()])), "x_f *= y_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.divide, [var_y_f.copy(), var_x_f.copy()])), "x_f = y_f / x_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.modulo, [var_y_f.copy(), var_x_f.copy()])), "x_f = y_f % x_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.plus, [Constant(2.0, float32), var_x_f.copy()])), "x_f += 2.0"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.plus, [Constant(-2.0, float32), var_x_f.copy()])), "x_f += -2.0"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.minus, [Constant(2.0, float32), var_x_f.copy()])), "x_f = 2.0 - x_f"),
            (
                Assignment(var_x_f.copy(), BinaryOperation(OperationType.minus, [Constant(-2.0, float32), var_x_f.copy()])),
                "x_f = -2.0 - x_f",
            ),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.left_shift, [var_y_f.copy(), var_x_f.copy()])), "x_f = y_f << x_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.right_shift, [var_y_f.copy(), var_x_f.copy()])), "x_f = y_f >> x_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.bitwise_and, [var_y_f.copy(), var_x_f.copy()])), "x_f &= y_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.bitwise_or, [var_y_f.copy(), var_x_f.copy()])), "x_f |= y_f"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.bitwise_xor, [var_y_f.copy(), var_x_f.copy()])), "x_f ^= y_f"),
        ],
    )
    def test_compound_float(self, expr, result):
        """Test compound assignment instruction is generated properly"""
        assert self._visit_code(expr, _generate_options(compounding=True))

    @pytest.mark.parametrize(
        "expr, result",
        [
            (Assignment(var_x, BinaryOperation(OperationType.plus, [var_x, var_y])), "x += y"),
            (Assignment(var_x, BinaryOperation(OperationType.minus, [var_x, var_y])), "x -= y"),
            (Assignment(var_x, BinaryOperation(OperationType.multiply, [var_x, var_y])), "x *= y"),
            (Assignment(var_x, BinaryOperation(OperationType.divide, [var_x, var_y])), "x /= y"),
            (Assignment(var_x, BinaryOperation(OperationType.modulo, [var_x, var_y])), "x %= y"),
            (Assignment(var_x, BinaryOperation(OperationType.plus, [var_x, Constant(2, int32)])), "x += 2"),
            (Assignment(var_x, BinaryOperation(OperationType.plus, [var_x, Constant(-2, int32)])), "x += -2"),
            (Assignment(var_x, BinaryOperation(OperationType.minus, [var_x, Constant(2, int32)])), "x -= 2"),
            (Assignment(var_x, BinaryOperation(OperationType.minus, [var_x, Constant(-2, int32)])), "x -= -2"),
            (Assignment(var_x, BinaryOperation(OperationType.left_shift, [var_x, var_y])), "x <<= y"),
            (Assignment(var_x, BinaryOperation(OperationType.right_shift, [var_x, var_y])), "x >>= y"),
            (Assignment(var_x, BinaryOperation(OperationType.bitwise_and, [var_x, var_y])), "x &= y"),
            (Assignment(var_x, BinaryOperation(OperationType.bitwise_or, [var_x, var_y])), "x |= y"),
            (Assignment(var_x, BinaryOperation(OperationType.bitwise_xor, [var_x, var_y])), "x ^= y"),
            (Assignment(var_x, BinaryOperation(OperationType.plus, [var_y, var_x])), "x += y"),
            (Assignment(var_x, BinaryOperation(OperationType.minus, [var_y, var_x])), "x = y - x"),
            (Assignment(var_x, BinaryOperation(OperationType.multiply, [var_y, var_x])), "x *= y"),
            (Assignment(var_x, BinaryOperation(OperationType.divide, [var_y, var_x])), "x = y / x"),
            (Assignment(var_x, BinaryOperation(OperationType.modulo, [var_y, var_x])), "x = y % x"),
            (Assignment(var_x, BinaryOperation(OperationType.plus, [Constant(2, int32), var_x])), "x += 2"),
            (Assignment(var_x, BinaryOperation(OperationType.plus, [Constant(-2, int32), var_x])), "x += -2"),
            (Assignment(var_x, BinaryOperation(OperationType.minus, [Constant(2, int32), var_x])), "x = 2 - x"),
            (Assignment(var_x, BinaryOperation(OperationType.minus, [Constant(-2, int32), var_x])), "x = -2 - x"),
            (Assignment(var_x, BinaryOperation(OperationType.left_shift, [var_y, var_x])), "x = y << x"),
            (Assignment(var_x, BinaryOperation(OperationType.right_shift, [var_y, var_x])), "x = y >> x"),
            (Assignment(var_x, BinaryOperation(OperationType.bitwise_and, [var_y, var_x])), "x &= y"),
            (Assignment(var_x, BinaryOperation(OperationType.bitwise_or, [var_y, var_x])), "x |= y"),
            (Assignment(var_x, BinaryOperation(OperationType.bitwise_xor, [var_y, var_x])), "x ^= y"),
        ],
    )
    def test_compound_integer(self, expr, result):
        assert self._visit_code(expr, _generate_options(compounding=True))

    @pytest.mark.parametrize(
        "expr, result",
        [
            (Assignment(var_x.copy().copy(), BinaryOperation(OperationType.plus, [var_x.copy().copy(), Constant(1, int32)])), "x++"),
            (Assignment(var_x.copy().copy(), BinaryOperation(OperationType.minus, [var_x.copy(), Constant(1, int32)])), "x--"),
            (Assignment(var_x.copy(), BinaryOperation(OperationType.plus, [var_x.copy(), Constant(-1, int32)])), "x--"),
            (Assignment(var_x.copy(), BinaryOperation(OperationType.minus, [var_x.copy(), Constant(-1, int32)])), "x++"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.plus, [var_x_f.copy(), Constant(1.0, float32)])), "x_f += 1.0"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.minus, [var_x_f.copy(), Constant(1.0, float32)])), "x_f -= 1.0"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.plus, [var_x_f.copy(), Constant(-1.0, float32)])), "x_f += -1.0"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.minus, [var_x_f.copy(), Constant(-1.0, float32)])), "x_f -= -1.0"),
        ],
    )
    def test_compound_increment_int(self, expr, result):
        """Test compound assignment instruction is generated properly"""
        assert self._visit_code(expr, _generate_options(compounding=True, increment_int=True, increment_float=False)) == result

    @pytest.mark.parametrize(
        "expr, result",
        [
            (Assignment(var_x, BinaryOperation(OperationType.plus, [var_x, Constant(1, int32)])), "x += 1"),
            (Assignment(var_x, BinaryOperation(OperationType.minus, [var_x, Constant(1, int32)])), "x -= 1"),
            (Assignment(var_x, BinaryOperation(OperationType.plus, [var_x, Constant(-1, int32)])), "x += -1"),
            (Assignment(var_x, BinaryOperation(OperationType.minus, [var_x, Constant(-1, int32)])), "x -= -1"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.plus, [var_x_f.copy(), Constant(1.0, float32)])), "x_f++"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.minus, [var_x_f.copy(), Constant(1.0, float32)])), "x_f--"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.plus, [var_x_f.copy(), Constant(-1.0, float32)])), "x_f--"),
            (Assignment(var_x_f.copy(), BinaryOperation(OperationType.minus, [var_x_f.copy(), Constant(-1.0, float32)])), "x_f++"),
        ],
    )
    def test_compound_increment_float(self, expr, result):
        """Test compound assignment instruction is generated properly"""
        assert self._visit_code(expr, _generate_options(compounding=True, increment_int=False, increment_float=True)) == result

    @pytest.mark.parametrize(
        "expr, result",
        [
            (
                Assignment(var_x, BinaryOperation(OperationType.plus, [var_x, BinaryOperation(OperationType.plus, [var_y, var_z])])),
                "x += y + z",
            ),
            (
                Assignment(var_x, BinaryOperation(OperationType.minus, [var_x, BinaryOperation(OperationType.plus, [var_y, var_z])])),
                "x -= y + z",
            ),
            (
                Assignment(var_x, BinaryOperation(OperationType.minus, [BinaryOperation(OperationType.plus, [var_y, var_z]), var_x])),
                "x = y + z - x",
            ),
            (
                Assignment(var_x, BinaryOperation(OperationType.plus, [BinaryOperation(OperationType.minus, [var_y, var_z]), var_x])),
                "x += y - z",
            ),
        ],
    )
    def test_compound_nested_operations(self, expr, result):
        """Test compound nested operations"""
        assert self._visit_code(expr, _generate_options(compounding=True)) == result

    @pytest.mark.parametrize(
        "constant, bounds, result",
        [
            (Constant(-1, int32), 0, "0xffffffff"),
            (Constant(0xA, int8), 256, "10"),
            (Constant(0xFF, int32), 255, "255"),
            (Constant(0xFF, int32), 0, "0xff"),
            (Constant(-1, int8), 0, "0xff"),
            (Constant(0, int32), 0, "0x0"),
            (Constant(0x0, int32), 0, "0x0"),
            (Constant(0x0, int32), 1, "0"),
            (Constant(0x1, int32), 0, "0x1"),
            (Constant(0x1, int32), 2, "1"),
            (Constant(0x1, int32), 1, "1"),
            (Constant(0x2, int32), 1, "0x2"),
            (Constant(0x1111111, int32), 0, "0x1111111"),
            (Constant(0x1111111, int32), 500, "0x1111111"),
            (Constant(0x1111111, int32), 17895698, "17895697"),
            (Constant(0x8000000000000000, int64), 9223372036854775808, "-9223372036854775808"),
            (Constant(0x8000000000000000, int64), 256, "0x8000000000000000"),
            (Constant(0xFF, int8), 256, "-1"),
            (Constant(0xFF, int8), 0, "0xff"),
            (Constant(0.5, float32), 0, "0.5"),
            (Constant(-0.5, float32), 0, "-0.5"),
            (Constant(10.5, float32), 10, "10.5"),
            (Constant("foo"), 0, '"foo"'),
        ],
    )
    def test_integer_representation(self, constant: Constant, bounds: int, result: str):
        assert self._visit_code(constant, _generate_options(int_repr_scope=bounds, twos_complement=True)) == result

    @pytest.mark.parametrize(
        "expr, expected",
        [
            (Constant(0, Pointer(Integer.char()), Constant('foo "bar"', Integer.char())), '"foo \\"bar\\""'),
            (Constant('foo "bar"'), '"foo \\"bar\\""'),
            (Constant('foo "bar"\r'), '"foo \\"bar\\"\\r"'),
            (Constant('foo "bar"'), '"foo \\"bar\\""'),
        ],
    )
    def test_escaped_string_constant(self, expr, expected):
        assert self._visit_code(expr) == expected


class TestLocalDeclarationGenerator:
    @pytest.mark.parametrize(
        ["vars_per_line", "variables", "expected"],
        [
            (1, [var_x.copy(), var_y.copy()], "int x;\nint y;"),
            (2, [var_x.copy(), var_y.copy()], "int x, y;"),
            (2, [var_x.copy()], "int x;"),
            (2, [var_x.copy(), var_y.copy(), var_z.copy()], "int x, y;\nint z;"),
            (1, [var_x.copy(), var_y.copy(), var_x_f.copy(), var_y_f.copy()], "float x_f;\nfloat y_f;\nint x;\nint y;"),
            (2, [var_x.copy(), var_y.copy(), var_x_f.copy(), var_y_f.copy()], "float x_f, y_f;\nint x, y;"),
            (1, [var_x.copy(), var_y.copy(), var_p.copy()], "int x;\nint y;\nint * p;"),
            (1, [var_x.copy(), var_y.copy(), var_fun_p.copy()], "int x;\nint y;\nint (* p)(int);"),
            (2, [var_x.copy(), var_y.copy(), var_fun_p.copy(), var_fun_p0.copy()], "int x, y;\nint (* p)(int), (* p0)(int);"),
        ],
    )
    def test_variable_declaration(self, vars_per_line: int, variables: List[Variable], expected: str):
        """Ensure variables are generated according to 'variable_declarations_per_line' option."""
        options = _generate_options(var_declarations_per_line=vars_per_line)
        ast = AbstractSyntaxTree(
            CodeNode(
                [Assignment(var, const_1.copy()) for var in variables],
                LogicCondition.initialize_true(LogicCondition.generate_new_context()),
            ),
            {},
        )
        assert LocalDeclarationGenerator.from_task(DecompilerTask(name="", function_identifier="", ast=ast, options=options)) == expected


class TestGlobalVisitor:
    @pytest.mark.parametrize(
        "op",
        [
            ListOperation([Variable("var_5"), GlobalVariable("test")]),
            Call(ExternFunctionPointer("function_pointer_name"), [Constant(15), ExternConstant("boo")]),
            BinaryOperation(OperationType.plus, [GlobalVariable("var_global"), ExternConstant("var_extern")]),
        ],
    )
    def test_operation(self, op):
        """Ensure that GlobalVariable and ExternConstant are generated for global printing"""
        ast = AbstractSyntaxTree(
            CodeNode(
                [Assignment(var_a, op)],
                LogicCondition.initialize_true(LogicCondition.generate_new_context()),
            ),
            {},
        )

        assert len(GlobalDeclarationGenerator.from_asts([ast])) != 0

    def test_nested_global_variable(self):
        """Ensure that GlobalVariableVisitor can visit global variables nested within a global variable"""

        var1 = ExternFunctionPointer("ExternFunction")
        var2 = GlobalVariable("var_glob1", initial_value=var1)
        var3 = GlobalVariable("var_glob2", initial_value=var2)
        var4 = GlobalVariable("var_glob3", initial_value=var3)

        ast = AbstractSyntaxTree(
            CodeNode(
                [Assignment(var_a, var4)],
                LogicCondition.initialize_true(LogicCondition.generate_new_context()),
            ),
            {},
        )

        global_variables, _ = GlobalDeclarationGenerator._get_global_variables_and_constants([ast])
        assert len(global_variables) == 3
