import pytest
from decompiler.backend.codegenerator import CodeGenerator
from decompiler.pipeline.controlflowanalysis import VariableNameGeneration
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree, CodeNode
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import Assignment, Constant, CustomType, Float, Integer, Pointer, Variable
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
EXPECTED_BASE_NAMES = [
    "chVar0",
    "sVar0",
    "iVar0",
    "lVar0",
    "i128Var0",
    "uchVar0",
    "usVar0",
    "uiVar0",
    "ulVar0",
    "ui128Var0",
    "hVar0",
    "fVar0",
    "dVar0",
    "ldVar0",
    "qVar0",
    "oVar0",
    "bVar0",
    "vVar0",
]
EXPECTED_POINTER_NAMES = [
    "chpVar0",
    "spVar0",
    "ipVar0",
    "lpVar0",
    "i128pVar0",
    "uchpVar0",
    "uspVar0",
    "uipVar0",
    "ulpVar0",
    "ui128pVar0",
    "hpVar0",
    "fpVar0",
    "dpVar0",
    "ldpVar0",
    "qpVar0",
    "opVar0",
    "bpVar0",
    "vpVar0",
]


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
    task = DecompilerTask(
        name="variable_name_generation", function_identifier="", cfg=None, ast=ast, options=options, function_return_type=VOID
    )
    VariableNameGeneration().run(task)
    DecoratedCode.print_code(CodeGenerator().generate([task]))


def test_default_notation_1():
    true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(CodeNode([assignment := Assignment(Variable("var_0", I32), Constant(0))], true_value), {})
    _run_vng(ast, _generate_options(notation="default"))
    assert assignment.destination.name == "var_0"


@pytest.mark.parametrize(
    "variable, name",
    [(Variable("var_" + str(i), typ), EXPECTED_BASE_NAMES[i]) for i, typ in enumerate(ALL_TYPES)]
    + [(Variable("var_" + str(i), Pointer(typ)), EXPECTED_POINTER_NAMES[i]) for i, typ in enumerate(ALL_TYPES)],
)
def test_hungarian_notation(variable, name):
    true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(CodeNode([assignment := Assignment(variable, Constant(42))], true_value), {})
    _run_vng(ast)
    assert assignment.destination.name == name


@pytest.mark.parametrize("type_sep, counter_sep", [("", ""), ("_", "_"), ("", "_"), ("_", "")])
def test_hungarian_notation_separators(type_sep: str, counter_sep: str):
    true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(CodeNode([assignment := Assignment(Variable("var_0", I32), Constant(0))], true_value), {})
    _run_vng(ast, _generate_options(type_sep=type_sep, counter_sep=counter_sep))
    assert assignment.destination.name == f"i{type_sep}Var{counter_sep}0"


def test_custom_type():
    true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(CodeNode([assignment := Assignment(Variable("var_0", CustomType("size_t", 64)), Constant(0))], true_value), {})
    _run_vng(ast, _generate_options())
    assert assignment.destination.name == "unkVar0"


def test_bninja_invalid_type():
    true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    ast = AbstractSyntaxTree(CodeNode([assignment := Assignment(Variable("var_0", Integer(104, True)), Constant(0))], true_value), {})
    _run_vng(ast, _generate_options())
    assert assignment.destination.name == "unkVar0"


def test_same_variable():
    """Variables can be copies of the same one. The renamer should only rename a variable once. (More times would destroy the actual name)"""
    var1 = Variable("tmp_42", Float(64))
    node = CodeNode(
        [Assignment(var1, Constant(0)), Assignment(var1, Constant(0))],
        LogicCondition.initialize_true(LogicCondition.generate_new_context()),
    )
    ast = AbstractSyntaxTree(node, {})
    _run_vng(ast, _generate_options())
    assert node.instructions[0].destination.name == "dTmp0"
    assert node.instructions[1].destination.name == "dTmp0"


def test_same_variable_idx():
    """Variables with the same counter should not be renamed into the same thing"""
    var1 = Variable("x_1", Integer.int32_t())
    var2 = Variable("y_1", Integer.int32_t())
    node = CodeNode(
        [Assignment(var1, Constant(0)), Assignment(var2, Constant(0))],
        LogicCondition.initialize_true(LogicCondition.generate_new_context()),
    )
    ast = AbstractSyntaxTree(node, {})
    _run_vng(ast, _generate_options())
    assert node.instructions[0].destination.name != node.instructions[1].destination.name


def test_different_custom_names_0():
    node = CodeNode(
        [
            Assignment(Variable("tmp_42", Float(64)), Constant(0)),
            Assignment(Variable("entry_", Float(64)), Constant(0)),
            Assignment(Variable("exit_", Float(64)), Constant(0)),
        ],
        LogicCondition.initialize_true(LogicCondition.generate_new_context()),
    )
    ast = AbstractSyntaxTree(node, {})
    _run_vng(ast, _generate_options())
    assert node.instructions[0].destination.name == "dTmp0"
    assert node.instructions[1].destination.name == "dEntry0"
    assert node.instructions[2].destination.name == "dExit0"


def test_different_custom_names_1():
    node = CodeNode(
        [Assignment(Variable("loop_break", Float(64)), Constant(0))], LogicCondition.initialize_true(LogicCondition.generate_new_context())
    )
    ast = AbstractSyntaxTree(node, {})
    _run_vng(ast, _generate_options())
    assert node.instructions[0].destination.name == "dLoopbreak0"
