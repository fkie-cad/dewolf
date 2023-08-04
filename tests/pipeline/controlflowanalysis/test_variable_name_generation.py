import pytest
from decompiler.backend.codegenerator import CodeGenerator
from decompiler.pipeline.controlflowanalysis import VariableNameGeneration
from decompiler.pipeline.controlflowanalysis.readability_based_refinement import ForLoopVariableRenamer, WhileLoopVariableRenamer
from decompiler.structures.ast.ast_nodes import CodeNode, ForLoopNode, SeqNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Call,
    Condition,
    Constant,
    CustomType,
    Float,
    ImportedFunctionSymbol,
    Integer,
    ListOperation,
    OperationType,
    Pointer,
    Variable,
)
from decompiler.structures.pseudo.operations import OperationType
from decompiler.task import DecompilerTask
from decompiler.util.decoration import DecoratedCode
from decompiler.util.options import Options

PIPELINE_NAME = VariableNameGeneration.name

I8 = Integer.int8_t()
I16 = Integer.int16_t()
I32 = Integer.int32_t()
I64 = Integer.int64_t()
I128 = Integer.int128_t()
UI8 = Integer.uint8_t()
UI16 = Integer.uint16_t()
UI32 = Integer.uint32_t()
UI64 = Integer.uint64_t()
UI128 = Integer.uint128_t()
HALF = Float(16)
FLOAT = Float.float()
DOUBLE = Float.double()
LONG_DOUBLE = Float(80)
QUADRUPLE = Float(128)
OCTUPLE = Float(256)
BOOL = CustomType.bool()
VOID = CustomType.void()

ALL_TYPES = [I8, I16, I32, I64, I128, UI8, UI16, UI32, UI64, UI128, HALF, FLOAT, DOUBLE, LONG_DOUBLE, QUADRUPLE, OCTUPLE, BOOL, VOID]
EXPECTED_BASE_NAMES = ["chVar0", "sVar1", "iVar2", "lVar3", "i128Var4", "uchVar5", "usVar6", "uiVar7", "ulVar8", "ui128Var9", "hVar10",
                    "fVar11", "dVar12", "ldVar13", "qVar14", "oVar15", "bVar16", "vVar17"]
EXPECTED_POINTER_NAMES = ["chpVar0", "spVar1", "ipVar2", "lpVar3", "i128pVar4", "uchpVar5", "uspVar6", "uipVar7", "ulpVar8", "ui128pVar9",
                            "hpVar10", "fpVar11", "dpVar12", "ldpVar13", "qpVar14", "opVar15", "bpVar16", "vpVar17"]


def _generate_options(notation: str = "system_hungarian", pointer_base: bool = True, type_sep: str = "", counter_sep: str = "") -> Options:
    options = Options()
    options.set(f"{PIPELINE_NAME}.notation", notation)
    options.set(f"{PIPELINE_NAME}.pointer_base", pointer_base)
    options.set(f"{PIPELINE_NAME}.type_separator", type_sep)
    options.set(f"{PIPELINE_NAME}.counter_separator", counter_sep)
    options.set(f"{PIPELINE_NAME}.rename_while_loop_variables", True)
    options.set(f"{PIPELINE_NAME}.for_loop_variable_names", ["i", "j", "k", "l", "m", "n"])
    options.set(f"code-generator.max_complexity", 100)
    options.set("code-generator.use_increment_int", False)
    options.set("code-generator.use_increment_float", False)
    options.set("code-generator.use_compound_assignment", True)
    return options


def _run_vng(ast: AbstractSyntaxTree, options: Options = _generate_options()):
    task = DecompilerTask("variable_name_generation", None, ast, options, VOID)
    VariableNameGeneration().run(task)
    DecoratedCode.print_code(CodeGenerator().generate([task]))


def test_default_notation_1():
    true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(CodeNode(Assignment(var := Variable("var_0", I32), Constant(0)), true_value), {})
    _run_vng(ast, _generate_options(notation="default"))
    assert var.name == "var_0"


@pytest.mark.parametrize(
    "variable, name",
    [
        (Variable("var_" + str(i), typ), EXPECTED_BASE_NAMES[i]) for i, typ in enumerate(ALL_TYPES)
    ] +
    [
        (Variable("var_" + str(i), Pointer(typ)), EXPECTED_POINTER_NAMES[i]) for i, typ in enumerate(ALL_TYPES)
    ]
    ,
)
def test_hungarian_notation(variable, name):
    node = CodeNode([Assignment(variable, Constant(42))], LogicCondition.initialize_true(LogicCondition.generate_new_context()))
    ast = AbstractSyntaxTree(node, {})
    _run_vng(ast)
    for instr in node.instructions:
        assert instr.destination.name == name


@pytest.mark.parametrize("type_sep, counter_sep", [("", ""), ("_", "_")])
def test_hungarian_notation_separators(type_sep: str, counter_sep: str):
    node = CodeNode(Assignment(Variable("var_0", I32), Constant(0)), LogicCondition.initialize_true(LogicCondition.generate_new_context()))
    ast = AbstractSyntaxTree(node, {})
    _run_vng(ast, _generate_options(type_sep=type_sep, counter_sep=counter_sep))
    for instr in node.instructions:
        assert instr.destination.name == f"i{type_sep}Var{counter_sep}0"


def test_custom_type():
    node = CodeNode(Assignment(Variable("var_0", CustomType("size_t", 64)), Constant(0)), LogicCondition.initialize_true(LogicCondition.generate_new_context()))
    ast = AbstractSyntaxTree(node, {})
    _run_vng(ast, _generate_options())
    for instr in node.instructions:
        assert instr.destination.name == "Var0"


def test_bninja_invalid_type():
    node = CodeNode(Assignment(Variable("var_0", Integer(104, True)), Constant(0)), LogicCondition.initialize_true(LogicCondition.generate_new_context()))
    ast = AbstractSyntaxTree(node, {})
    _run_vng(ast, _generate_options())
    for instr in node.instructions:
        assert instr.destination.name == "unkVar0"


def test_tmp_variable():
    true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    node = CodeNode(Assignment(Variable("tmp_42", Float(64)), Constant(0)), true_value)
    ast = AbstractSyntaxTree(node, {})
    _run_vng(ast, _generate_options())
    for instr in node.instructions:
        assert instr.destination.name == "dTmp42"


def test_same_variable():
    """Variables can be copies of the same one. The renamer should only rename a variable once. (More times would destroy the actual name)"""
    var1 = Variable("tmp_42", Float(64))
    node = CodeNode([
        Assignment(var1, Constant(0)),
        Assignment(var1, Constant(0))], LogicCondition.initialize_true(LogicCondition.generate_new_context()))
    ast = AbstractSyntaxTree(node, {})
    _run_vng(ast, _generate_options())
    for instr in node.instructions:
        assert instr.destination.name == "dTmp42"

# ForLoop/WhileLoopRenamer

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
